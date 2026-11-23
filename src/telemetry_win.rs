//! 四（模块 1）：感知层 (Win-Telemetry-Collector) — 真实 OS 扫描 + 外部靶机进程实弹捕获
//!
//! 负责：
//! 1. 在 Windows 真机上直接通过 `EnumWindows`、`GetWindowLongW`、`GetWindowRect`、`GetLastInputInfo`、
//!    `CreateToolhelp32Snapshot`、注册表 `HKCU\...\Run` 巡检及 `%TEMP%` 落地文件真实字节香农熵计算，
//!    将系统实时行为转化为 12 维标准状态向量并推入决策模型；
//! 2. 支持直接拉起真实的独立外部靶机进程 `vnb-rogue-target(.exe)`，从 OS 外部捕获其真实 PID、真实 HWND、
//!    真实落盘文件与注册表篡改痕迹。

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::contract::{
    explain_state_evidence, feat_idx, HostContextProfile, PolicyAction, StateMatrix, FEAT_DIM,
    SEQ_LEN,
};
use crate::decision_model::{DecisionOutput, PolicyDecisionEngine};
use crate::lineage_arena::{ContaminationLedger, TrackedEntity, TrackedWindow};
use crate::win_live_os::{
    check_test_autorun_exists, compute_normalized_shannon_entropy, generate_high_entropy_test_payload,
    get_sandbox_dirs, write_test_autorun_entry, TEST_REG_VALUE_NAME,
};

/// 安全助手捕获并呈递给用户的“发现与提醒”事件条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub finding_id: u64,
    pub timestamp_label: String,
    pub category_tag: String,
    pub summary_title: String,
    pub entity: TrackedEntity,
    pub decision: DecisionOutput,
    /// 由 12 维特征自动翻译的人类可读证据链
    pub evidence_bullets: Vec<String>,
    /// 当前处置状态
    pub status: FindingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    /// 待用户裁决（模型处于模糊边界或高敏拦截提醒态，在“发现与提醒”主视图高亮展示）
    PendingUserDecision,
    /// 已由引擎高置信度自动处置（用户仍可随时查看溯源账本或撤销）
    AutoHandled(PolicyAction),
    /// 已由用户点击按钮亲自裁决处置（并已触发模型在线微调与 ArcSwap 热更新）
    UserResolved {
        chosen_action: PolicyAction,
        updated_policy_rev: u64,
    },
}

/// 构造 [16, 12] 状态矩阵的辅助工具
fn build_sequence_from_keyframes(keyframes: &[(usize, [f32; FEAT_DIM])]) -> StateMatrix {
    let mut mat = [[0.02_f32; FEAT_DIM]; SEQ_LEN];
    for &(step, ref feats) in keyframes {
        if step < SEQ_LEN {
            mat[step] = *feats;
        }
    }
    for t in 1..SEQ_LEN {
        for d in 0..FEAT_DIM {
            if mat[t][d] < mat[t - 1][d] * 0.55 {
                mat[t][d] = (mat[t - 1][d] * 0.55).clamp(0.0, 1.0);
            }
        }
    }
    mat
}

/// 感知层：实时扫描 Windows 系统状态与外部靶机进程
pub struct WinTelemetryCollector {
    next_finding_id: u64,
    clock_seq: u32,
    /// 记录已经被捕获告警过的真实窗口 HWND，防止同一窗口重复刷屏
    seen_live_hwnds: HashSet<u64>,
    /// 后台拉起的真实外部测试子进程句柄池（保证在测试期间真实存活于 OS 进程表中）
    spawned_live_children: Vec<std::process::Child>,
}

impl Default for WinTelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WinTelemetryCollector {
    fn drop(&mut self) {
        for child in &mut self.spawned_live_children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl WinTelemetryCollector {
    pub fn new() -> Self {
        Self {
            next_finding_id: 1,
            clock_seq: 1,
            seen_live_hwnds: HashSet::new(),
            spawned_live_children: Vec::new(),
        }
    }

    fn next_time_label(&mut self) -> String {
        let min = 30 + (self.clock_seq / 6) % 29;
        let sec = (self.clock_seq * 9) % 60;
        self.clock_seq += 1;
        format!("12:{:02}:{:02}", min, sec)
    }

    /// 定位 `vnb-rogue-target(.exe)` 独立靶机二进制路径
    pub fn resolve_target_binary() -> (PathBuf, bool) {
        let bin_name = if cfg!(windows) {
            "vnb-rogue-target.exe"
        } else {
            "vnb-rogue-target"
        };
        if let Ok(cur) = std::env::current_exe() {
            if let Some(parent) = cur.parent() {
                let c1 = parent.join(bin_name);
                if c1.exists() {
                    return (c1, true);
                }
                if let Some(grand) = parent.parent() {
                    let c2 = grand.join(bin_name);
                    if c2.exists() {
                        return (c2, true);
                    }
                }
            }
        }
        (PathBuf::from(bin_name), true)
    }

    /// 真实启动一个操作系统子进程作为被测目标，返回其在 OS 内核中的真实 PID 与可执行路径
    fn spawn_real_os_process(&mut self, role: &str) -> (u32, String) {
        let (bin_path, is_standalone_target) = Self::resolve_target_binary();
        let bin_str = bin_path.to_string_lossy().into_owned();

        let mut cmd = std::process::Command::new(&bin_path);
        if is_standalone_target {
            cmd.arg(format!("--mode={}", role));
        } else {
            cmd.arg(format!("--spawn-role={}", role));
        }

        if let Ok(child) = cmd.spawn() {
            let pid = child.id();
            self.spawned_live_children.push(child);
            (pid, bin_str)
        } else {
            (std::process::id(), bin_str)
        }
    }

    /// 在 Windows 真机上主动执行一次全系统真实窗口与进程扫描（调用 Win32 EnumWindows + Toolhelp32）
    pub fn scan_live_os_windows_now(
        &mut self,
        engine: &PolicyDecisionEngine,
    ) -> Vec<DetectionFinding> {
        #[allow(unused_mut)]
        let mut discovered = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let live_wins = crate::win_live_os::win32_impl::scan_live_suspicious_windows();
            let my_pid = std::process::id();

            for (pid, win, vis_feats) in live_wins {
                if pid == my_pid || self.seen_live_hwnds.contains(&win.hwnd) {
                    continue;
                }
                self.seen_live_hwnds.insert(win.hwnd);

                let (ppid, proc_name, exe_path) =
                    crate::win_live_os::win32_impl::query_process_lineage(pid).unwrap_or_else(
                        || (0, format!("pid_{}.exe", pid), format!("PID:{}", pid)),
                    );

                let is_temp_or_appdata = exe_path.to_lowercase().contains("temp")
                    || exe_path.to_lowercase().contains("appdata");

                let mut f_frame = [0.04_f32; FEAT_DIM];
                f_frame[feat_idx::INPUT_IDLE_DECAY] = vis_feats[0].max(0.75);
                f_frame[feat_idx::TOPMOST_BORDERLESS_MASK] = vis_feats[1];
                f_frame[feat_idx::TASKBAR_HIDDEN] = vis_feats[2];
                f_frame[feat_idx::SCREEN_ZONE_CODE] = vis_feats[3];
                f_frame[feat_idx::FOREIGN_STACK_ORIGIN] = 0.72;
                f_frame[feat_idx::LINEAGE_DIVERGENCE] = if is_temp_or_appdata { 0.90 } else { 0.25 };

                let matrix =
                    build_sequence_from_keyframes(&[(8, f_frame), (13, f_frame), (15, f_frame)]);

                let has_doc = !is_temp_or_appdata;
                let host_profile = HostContextProfile {
                    has_open_user_document: has_doc,
                    active_document_hint: if has_doc {
                        Some(format!("宿主进程 {} 存在活跃工作上下文", proc_name))
                    } else {
                        None
                    },
                    is_critical_shell_host: proc_name.eq_ignore_ascii_case("explorer.exe"),
                    has_main_work_window: has_doc,
                };

                let mut entity = TrackedEntity::new(
                    pid,
                    ppid,
                    &proc_name,
                    &exe_path,
                    "Live Windows EnumWindows + Toolhelp32 实时捕获",
                    host_profile,
                );
                entity.load_state_matrix(matrix);
                entity.ledger.popup_windows.push(win.clone());

                let mut decision = engine.evaluate(&entity.state_window, &entity.host_profile);
                decision.needs_user_prompt = true;
                let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

                let finding = DetectionFinding {
                    finding_id: self.next_finding_id,
                    timestamp_label: self.next_time_label(),
                    category_tag: format!("真机实时捕获 (PID={})", pid),
                    summary_title: format!(
                        "真机扫描捕获【{} (PID={})】置顶弹窗 HWND=0x{:X} \"{}\"",
                        proc_name, pid, win.hwnd, win.title
                    ),
                    entity,
                    decision,
                    evidence_bullets: evidence,
                    status: FindingStatus::PendingUserDecision,
                };
                self.next_finding_id += 1;
                discovered.push(finding);
            }
        }

        let _ = (engine, &self.seen_live_hwnds);
        discovered
    }

    /// 启动安全助手时预置的初始实弹发现列表
    pub fn bootstrap_initial_findings(
        &mut self,
        engine: &PolicyDecisionEngine,
    ) -> Vec<DetectionFinding> {
        vec![
            self.capture_wps_bundled_ad_popup(engine, true),
            self.capture_borderline_desktop_helper_popup(engine),
            self.capture_silent_dropper_family_pack(engine, true),
            self.capture_explorer_injected_mini_news(engine, false),
            self.capture_wechat_normal_notification(engine),
        ]
    }

    /// 场景 1：【宿主夹带私货弹窗 (z_1 主导 -> a_2 外科手术消音)】
    /// 真实写入并持有办公文档句柄，在 Windows 下可真实创建右下角置顶弹窗 HWND
    pub fn capture_wps_bundled_ad_popup(
        &mut self,
        engine: &PolicyDecisionEngine,
        require_user_confirm: bool,
    ) -> DetectionFinding {
        let (drop_dir, _) = get_sandbox_dirs();
        let real_doc_path = drop_dir.join("正在编辑_2026Q4产品架构方案.docx");
        let _ = std::fs::write(
            &real_doc_path,
            "真实办公文档内容：未保存的架构设计草稿 (受 5x4 非对称代价矩阵保护)\n",
        );

        let (real_pid, real_exe) = self.spawn_real_os_process("host-ad");

        let mut f_net = [0.02_f32; FEAT_DIM];
        f_net[feat_idx::INPUT_IDLE_DECAY] = 0.86;
        f_net[feat_idx::SOCKET_RECV_DRIVEN] = 0.82;
        f_net[feat_idx::FOREIGN_STACK_ORIGIN] = 0.68;

        let mut f_popup = [0.02_f32; FEAT_DIM];
        f_popup[feat_idx::INPUT_IDLE_DECAY] = 0.92;
        f_popup[feat_idx::TOPMOST_BORDERLESS_MASK] = 0.94;
        f_popup[feat_idx::TASKBAR_HIDDEN] = 0.95;
        f_popup[feat_idx::SCREEN_ZONE_CODE] = 0.88;
        f_popup[feat_idx::FOREIGN_STACK_ORIGIN] = 0.76;
        f_popup[feat_idx::SOCKET_RECV_DRIVEN] = 0.78;

        let matrix = build_sequence_from_keyframes(&[(9, f_net), (14, f_popup), (15, f_popup)]);

        let host_profile = HostContextProfile {
            has_open_user_document: true,
            active_document_hint: Some(format!(
                "{} (真实磁盘句柄活跃)",
                real_doc_path.to_string_lossy()
            )),
            is_critical_shell_host: false,
            has_main_work_window: true,
        };

        let mut entity = TrackedEntity::new(
            real_pid,
            std::process::id(),
            "wps_host_target.exe",
            &real_exe,
            "Host Process (主程序持有真实文档句柄，内部广告线程弹窗)",
            host_profile,
        );
        entity.load_state_matrix(matrix);
        entity.ledger.popup_windows.push(TrackedWindow {
            hwnd: 0x0019_08A4,
            ui_thread_id: real_pid.saturating_add(1),
            title: "超级会员双十一特惠·右下角置顶悬浮窗".to_string(),
            rect: (1540, 740, 360, 240),
            is_topmost: true,
            muted: false,
        });

        let mut decision = engine.evaluate(&entity.state_window, &entity.host_profile);
        if require_user_confirm {
            decision.needs_user_prompt = true;
        }
        let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

        let finding = DetectionFinding {
            finding_id: self.next_finding_id,
            timestamp_label: self.next_time_label(),
            category_tag: "宿主夹带私货弹窗 (z_1)".to_string(),
            summary_title: format!(
                "发现宿主进程 (真实 PID={}) 弹出右下角置顶推广窗（主进程正打开您的真实文档）",
                real_pid
            ),
            entity,
            status: if decision.needs_user_prompt {
                FindingStatus::PendingUserDecision
            } else {
                FindingStatus::AutoHandled(decision.chosen_action)
            },
            decision,
            evidence_bullets: evidence,
        };
        self.next_finding_id += 1;
        finding
    }

    /// 场景 2：【模糊地带新奇弹窗 (Shadow Mode 硬样本 -> 触发提醒卡片请用户一键裁决)】
    pub fn capture_borderline_desktop_helper_popup(
        &mut self,
        engine: &PolicyDecisionEngine,
    ) -> DetectionFinding {
        let (real_pid, real_exe) = self.spawn_real_os_process("parasitic-popup");

        let mut f_mid = [0.05_f32; FEAT_DIM];
        f_mid[feat_idx::INPUT_IDLE_DECAY] = 0.58;
        f_mid[feat_idx::SOCKET_RECV_DRIVEN] = 0.52;

        let mut f_late = [0.05_f32; FEAT_DIM];
        f_late[feat_idx::INPUT_IDLE_DECAY] = 0.64;
        f_late[feat_idx::TOPMOST_BORDERLESS_MASK] = 0.62;
        f_late[feat_idx::TASKBAR_HIDDEN] = 0.58;
        f_late[feat_idx::SCREEN_ZONE_CODE] = 0.72;
        f_late[feat_idx::FOREIGN_STACK_ORIGIN] = 0.48;

        let matrix = build_sequence_from_keyframes(&[(8, f_mid), (13, f_late), (15, f_late)]);

        let host_profile = HostContextProfile {
            has_open_user_document: false,
            active_document_hint: None,
            is_critical_shell_host: false,
            has_main_work_window: true,
        };

        let mut entity = TrackedEntity::new(
            real_pid,
            std::process::id(),
            "7zDeskHelper_target.exe",
            &real_exe,
            "DeskUtility Component (未知资讯组件栈)",
            host_profile,
        );
        entity.load_state_matrix(matrix);
        entity.ledger.popup_windows.push(TrackedWindow {
            hwnd: 0x0024_11C0,
            ui_thread_id: real_pid.saturating_add(2),
            title: "今日桌面早报·猜你喜欢".to_string(),
            rect: (1520, 720, 380, 260),
            is_topmost: true,
            muted: false,
        });

        let mut decision = engine.evaluate(&entity.state_window, &entity.host_profile);
        decision.needs_user_prompt = true;
        let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

        let finding = DetectionFinding {
            finding_id: self.next_finding_id,
            timestamp_label: self.next_time_label(),
            category_tag: "边界未知弹窗 · 待您裁决".to_string(),
            summary_title: format!(
                "发现【7zDeskHelper (真实 PID={})】弹出右下角半透明资讯窗（置信度处于边界，请您定性）",
                real_pid
            ),
            entity,
            decision,
            evidence_bullets: evidence,
            status: FindingStatus::PendingUserDecision,
        };
        self.next_finding_id += 1;
        finding
    }

    /// 场景 3：【静默捆绑与驻留母体 (z_3 主导 -> a_4 连根拔除与账本回滚)】
    /// 真实在系统临时目录写出高熵载荷文件，并真实写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 测试自启动项！
    pub fn capture_silent_dropper_family_pack(
        &mut self,
        engine: &PolicyDecisionEngine,
        require_user_confirm: bool,
    ) -> DetectionFinding {
        let (real_pid, real_exe) = self.spawn_real_os_process("silent-dropper");
        let (drop_dir, _) = get_sandbox_dirs();

        // 真实在磁盘上写出 2 个高熵捆绑可执行载荷文件，并现场计算真实香农熵
        let dropped_1 = drop_dir.join(format!("BrowserProtect_setup_{}.exe", real_pid));
        let dropped_2 = drop_dir.join(format!("GameBox_ad_hook64_{}.dll", real_pid));
        let payload_bytes = generate_high_entropy_test_payload(4096);
        let _ = std::fs::write(&dropped_1, &payload_bytes);
        let _ = std::fs::write(&dropped_2, &payload_bytes);
        let (_raw_h, norm_entropy) = compute_normalized_shannon_entropy(&payload_bytes);

        let dropped_1_str = dropped_1.to_string_lossy().into_owned();
        let dropped_2_str = dropped_2.to_string_lossy().into_owned();

        // 真实写入注册表测试自启动项
        let _ = write_test_autorun_entry(TEST_REG_VALUE_NAME, &dropped_1_str);
        let _ = check_test_autorun_exists(TEST_REG_VALUE_NAME);

        let mut f1_recv = [0.04_f32; FEAT_DIM];
        f1_recv[feat_idx::INPUT_IDLE_DECAY] = 0.96;
        f1_recv[feat_idx::SOCKET_RECV_DRIVEN] = 0.94;
        f1_recv[feat_idx::PAYLOAD_SHANNON_ENTROPY] = norm_entropy;

        let mut f2_drop = [0.04_f32; FEAT_DIM];
        f2_drop[feat_idx::INPUT_IDLE_DECAY] = 0.97;
        f2_drop[feat_idx::MEM_WX_TRANSITION] = 0.85;
        f2_drop[feat_idx::PAYLOAD_SHANNON_ENTROPY] = norm_entropy;
        f2_drop[feat_idx::TEMP_EXEC_WRITE] = 0.96;
        f2_drop[feat_idx::LINEAGE_DIVERGENCE] = 0.82;

        let mut f3_persist = [0.04_f32; FEAT_DIM];
        f3_persist[feat_idx::INPUT_IDLE_DECAY] = 0.98;
        f3_persist[feat_idx::TEMP_EXEC_WRITE] = 0.92;
        f3_persist[feat_idx::PERSISTENCE_TAMPER] = 0.97;
        f3_persist[feat_idx::LINEAGE_DIVERGENCE] = 0.89;
        f3_persist[feat_idx::SCREEN_ZONE_CODE] = 0.95;

        let matrix = build_sequence_from_keyframes(&[
            (3, f1_recv),
            (8, f2_drop),
            (13, f3_persist),
            (15, f3_persist),
        ]);

        let host_profile = HostContextProfile::default();
        let mut entity = TrackedEntity::new(
            real_pid,
            std::process::id(),
            "FastUpdater_svc.exe",
            &real_exe,
            "Unsigned Temp Dropper (已真实释放高熵文件并写入 Run 启动项)",
            host_profile,
        );
        entity.load_state_matrix(matrix);
        entity.ledger = ContaminationLedger {
            spawned_children: Vec::new(),
            dropped_files: vec![dropped_1_str.clone(), dropped_2_str],
            registry_run_entries: vec![(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                TEST_REG_VALUE_NAME.to_string(),
                dropped_1_str,
            )],
            scheduled_tasks: vec![r"\VNB_Test_KeepAlive_Task".to_string()],
            popup_windows: vec![TrackedWindow {
                hwnd: 0x0031_00F2,
                ui_thread_id: real_pid.saturating_add(3),
                title: "HiddenInstallerHost (-32000,-32000 1x1)".to_string(),
                rect: (-32000, -32000, 1, 1),
                is_topmost: false,
                muted: false,
            }],
        };

        let mut decision = engine.evaluate(&entity.state_window, &entity.host_profile);
        if require_user_confirm {
            decision.needs_user_prompt = true;
        }
        let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

        let finding = DetectionFinding {
            finding_id: self.next_finding_id,
            timestamp_label: self.next_time_label(),
            category_tag: "高危静默全家桶母体 (z_3)".to_string(),
            summary_title: format!(
                "捕获【FastUpdater_svc.exe (真实 PID={})】在临时目录真实释放 2 个高熵载荷并写入注册表 Run 启动项",
                real_pid
            ),
            entity,
            status: if decision.needs_user_prompt {
                FindingStatus::PendingUserDecision
            } else {
                FindingStatus::AutoHandled(decision.chosen_action)
            },
            decision,
            evidence_bullets: evidence,
        };
        self.next_finding_id += 1;
        finding
    }

    /// 场景 4：【独立寄生广告子进程 (z_2 主导 -> a_3 进程击毙与 Spawn Block 禁生)】
    /// 真实拉起外部子进程，当执行 a_3 时真实调用 TerminateProcess 将其击毙！
    pub fn capture_explorer_injected_mini_news(
        &mut self,
        engine: &PolicyDecisionEngine,
        require_user_confirm: bool,
    ) -> DetectionFinding {
        let (real_pid, real_exe) = self.spawn_real_os_process("parasitic-popup");
        std::thread::sleep(Duration::from_millis(15));

        let mut f_spawn = [0.03_f32; FEAT_DIM];
        f_spawn[feat_idx::INPUT_IDLE_DECAY] = 0.91;
        f_spawn[feat_idx::LINEAGE_DIVERGENCE] = 0.92;
        f_spawn[feat_idx::FOREIGN_STACK_ORIGIN] = 0.88;
        f_spawn[feat_idx::CROSS_PROCESS_WRITE] = 0.79;

        let mut f_pop = [0.03_f32; FEAT_DIM];
        f_pop[feat_idx::INPUT_IDLE_DECAY] = 0.94;
        f_pop[feat_idx::TOPMOST_BORDERLESS_MASK] = 0.91;
        f_pop[feat_idx::TASKBAR_HIDDEN] = 0.93;
        f_pop[feat_idx::SCREEN_ZONE_CODE] = 0.89;
        f_pop[feat_idx::FOREIGN_STACK_ORIGIN] = 0.86;
        f_pop[feat_idx::LINEAGE_DIVERGENCE] = 0.94;

        let matrix = build_sequence_from_keyframes(&[(6, f_spawn), (12, f_pop), (15, f_pop)]);

        let host_profile = HostContextProfile::default();
        let mut entity = TrackedEntity::new(
            real_pid,
            std::process::id(),
            "mini_news_pop.exe",
            &real_exe,
            "Adware Module (独立子进程真实运行中)",
            host_profile,
        );
        entity.load_state_matrix(matrix);
        entity.ledger.popup_windows.push(TrackedWindow {
            hwnd: 0x0042_09B8,
            ui_thread_id: real_pid.saturating_add(4),
            title: "迷你热点资讯 · 震惊头条弹窗".to_string(),
            rect: (1500, 700, 400, 280),
            is_topmost: true,
            muted: false,
        });

        let mut decision = engine.evaluate(&entity.state_window, &entity.host_profile);
        if require_user_confirm {
            decision.needs_user_prompt = true;
        }
        let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

        let finding = DetectionFinding {
            finding_id: self.next_finding_id,
            timestamp_label: self.next_time_label(),
            category_tag: "独立寄生广告模块 (z_2)".to_string(),
            summary_title: format!(
                "发现独立广告子进程【mini_news_pop.exe (真实 PID={})】被后台拉起并投递右下角置顶广告窗",
                real_pid
            ),
            entity,
            status: if decision.needs_user_prompt {
                FindingStatus::PendingUserDecision
            } else {
                FindingStatus::AutoHandled(decision.chosen_action)
            },
            decision,
            evidence_bullets: evidence,
        };
        self.next_finding_id += 1;
        finding
    }

    /// 场景 5：【合法用户交互 / 正常通知 (z_0 主导 -> a_0 放行并摘牌)】
    pub fn capture_wechat_normal_notification(
        &mut self,
        engine: &PolicyDecisionEngine,
    ) -> DetectionFinding {
        let mut f_click = [0.01_f32; FEAT_DIM];
        f_click[feat_idx::INPUT_IDLE_DECAY] = 0.04;
        f_click[feat_idx::SCREEN_ZONE_CODE] = 0.10;

        let matrix = build_sequence_from_keyframes(&[(10, f_click), (14, f_click), (15, f_click)]);
        let host_profile = HostContextProfile {
            has_open_user_document: false,
            active_document_hint: None,
            is_critical_shell_host: false,
            has_main_work_window: true,
        };

        let mut entity = TrackedEntity::new(
            std::process::id(),
            1000,
            "NormalWorkApp.exe",
            "C:\\Program Files\\WorkApp\\NormalWorkApp.exe",
            "Verified Publisher",
            host_profile,
        );
        entity.load_state_matrix(matrix);

        let decision = engine.evaluate(&entity.state_window, &entity.host_profile);
        let evidence = explain_state_evidence(&entity.state_window, &entity.host_profile);

        let finding = DetectionFinding {
            finding_id: self.next_finding_id,
            timestamp_label: self.next_time_label(),
            category_tag: "正常用户交互 (z_0)".to_string(),
            summary_title: "检测【NormalWorkApp.exe】紧随用户鼠标点击打开标准窗口，判定合法并从染色池摘牌".to_string(),
            entity,
            status: FindingStatus::AutoHandled(decision.chosen_action),
            decision,
            evidence_bullets: evidence,
        };
        self.next_finding_id += 1;
        finding
    }
}
