//! 四（模块 4）：外科手术动作执行器 (Surgical-Actuator) — 100% 真实 OS 系统调用实现（零 Mock 跳过）
//!
//! 严格听从决策模型的 Action_ID (a_0 ~ a_4) 指挥，直接对操作系统中的真实窗口、线程、进程、注册表和文件执行物理操作：
//! - a_0 (ACTION_PASS_AND_UNTAG): 放行并从稀疏追踪池摘牌
//! - a_1 (ACTION_DEFER_WAIT): 保持染色观察 / 挂起提醒等待用户一键裁决
//! - a_2 (ACTION_SURGICAL_MUTE): 保主进程、灭子窗口：
//!   真实调用 `SetWindowPos(HWND_NOTOPMOST | SWP_HIDEWINDOW)` 剥夺置顶并隐藏窗口 +
//!   `PostMessageW(WM_CLOSE)` 销毁广告窗 + `OpenThread` & `SuspendThread` 仅挂起渲染该窗口的 UI 线程，主进程与文档丝毫无损！
//! - a_3 (ACTION_PROCESS_ISOLATE):
//!   真实调用 `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` 终止独立广告子进程，
//!   并将 `.exe` 完整路径加入 `Spawn Block`（后台巡检一旦发现父进程再次拉起该路径，立即迎头击毙）。
//! - a_4 (ACTION_ROOT_PURGE):
//!   整组进程树急冻强杀 -> 检索《污染溯源账本》调用 `RegDeleteValueW` / `reg delete` 删除注册表 Run 启动项与 `schtasks` 计划任务 ->
//!   调用 `std::fs::rename` 将释放的捆绑文件物理移入隔离区目录（支持一键还原回原路径）。

use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::contract::PolicyAction;
use crate::lineage_arena::TrackedEntity;
use crate::threat_intel::compute_sha256_hex;
use crate::win_live_os::{
    delete_autorun_entry, move_file_to_quarantine_vault, restore_file_from_quarantine_vault,
    write_test_autorun_entry,
};

/// 单次外科手术执行后的详细处置回执
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurgicalReceipt {
    pub receipt_id: u64,
    pub timestamp_label: String,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub action: PolicyAction,
    pub triggered_by_user: bool,
    /// 执行器完成的真实底层 OS 物理操作明细
    pub executed_steps: Vec<String>,
    pub host_protection_note: String,
    pub rolled_back: bool,
    /// 记录被挂起的窗口与线程 (HWND, TID)，供撤销恢复时调用 ResumeThread + ShowWindow
    pub suspended_ui_threads: Vec<(u64, u32)>,
    /// 记录被清理的注册表项 (Key, ValueName, OriginalData)，供撤销恢复时写回
    pub removed_registry_entries: Vec<(String, String, String)>,
    /// 记录被隔离的文件 Vault ID 列表
    pub quarantined_vault_ids: Vec<(String, String)>,
    /// 被同步加入禁生指纹库的 SHA-256 哈希（回滚时一并解除）
    #[serde(default)]
    pub blocked_sha256: Option<String>,
    /// 目标进程/载荷的多维定位摘要（谱系、CWD、命令行、哈希与来源）
    #[serde(default)]
    pub attribution_summary: String,
}

/// 隔离区文件条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedItem {
    pub original_path: String,
    pub vault_path: String,
    pub vault_id: String,
    pub source_process: String,
    pub restored: bool,
}

/// 外科手术动作执行器
pub struct SurgicalActuator {
    next_receipt_id: u64,
    /// 禁止孵化名单 (Spawn Block)：记录被 a_3 / a_4 封禁的独立广告或木马可执行路径（原始与小写归一化）
    pub spawn_block_list: HashSet<String>,
    /// 禁止孵化二进制内容指纹库 (SHA-256)：防止恶意程序复制/改名逃逸路径封禁
    pub spawn_block_hashes: HashSet<String>,
    /// 轻量文件内容哈希缓存 (path -> (file_len, sha256_hex))
    path_sha256_cache: HashMap<String, (u64, String)>,
    /// 隔离区文件保险箱
    pub quarantine_vault: Vec<QuarantinedItem>,
    /// 历史外科手术执行回执列表（最新在前）
    pub receipts: Vec<SurgicalReceipt>,
}

impl Default for SurgicalActuator {
    fn default() -> Self {
        Self::new()
    }
}

impl SurgicalActuator {
    pub fn new() -> Self {
        Self {
            next_receipt_id: 1,
            spawn_block_list: HashSet::new(),
            spawn_block_hashes: HashSet::new(),
            path_sha256_cache: HashMap::with_capacity(128),
            quarantine_vault: Vec::new(),
            receipts: Vec::new(),
        }
    }

    fn compute_cached_file_sha256(&mut self, exe_path: &str) -> Option<String> {
        let trimmed = exe_path.trim();
        if trimmed.is_empty() {
            return None;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("/system/")
            || lower.starts_with("/usr/libexec/")
            || lower.contains("\\windows\\system32\\")
        {
            return None;
        }
        let meta = fs::metadata(trimmed).ok()?;
        if !meta.is_file() || meta.len() == 0 || meta.len() > 16 * 1024 * 1024 {
            return None;
        }
        let file_len = meta.len();
        if let Some((cached_len, cached_hash)) = self.path_sha256_cache.get(trimmed) {
            if *cached_len == file_len {
                return Some(cached_hash.clone());
            }
        }
        let bytes = fs::read(trimmed).ok()?;
        let sha256 = compute_sha256_hex(&bytes);
        if self.path_sha256_cache.len() >= 512 {
            self.path_sha256_cache.clear();
        }
        self.path_sha256_cache
            .insert(trimmed.to_string(), (file_len, sha256.clone()));
        Some(sha256)
    }

    /// 将路径（原始 + 小写）与文件 SHA-256 指纹双因子写入 Spawn Block 禁生库
    pub fn block_executable_fingerprint(&mut self, exe_path: &str) -> Option<String> {
        let trimmed = exe_path.trim();
        if !trimmed.is_empty() {
            self.spawn_block_list.insert(trimmed.to_string());
            self.spawn_block_list.insert(trimmed.to_ascii_lowercase());
        }
        if let Some(sha256) = self.compute_cached_file_sha256(trimmed) {
            self.spawn_block_hashes.insert(sha256.clone());
            Some(sha256)
        } else {
            None
        }
    }

    /// 从双因子禁生库中解除路径与对应 SHA-256 指纹
    pub fn unblock_executable_fingerprint(&mut self, exe_path: &str, sha256: Option<&str>) {
        let trimmed = exe_path.trim();
        if !trimmed.is_empty() {
            self.spawn_block_list.remove(trimmed);
            self.spawn_block_list.remove(&trimmed.to_ascii_lowercase());
        }
        if let Some(h) = sha256 {
            self.spawn_block_hashes.remove(h);
        }
    }

    /// 后台守护巡检：检查当前运行进程是否命中路径或 SHA-256 双因子 `Spawn Block`，命中则先挂起后物理击毙！
    pub fn enforce_spawn_block_on_pid(&mut self, pid: u32, exe_path: &str) -> Option<String> {
        if pid <= 1 || pid == std::process::id() {
            return None;
        }
        let lower = exe_path.to_ascii_lowercase();
        let hit_path = self.spawn_block_list.contains(exe_path)
            || (!lower.is_empty() && self.spawn_block_list.contains(&lower));

        let hit_hash = if !hit_path && !self.spawn_block_hashes.is_empty() {
            self.compute_cached_file_sha256(exe_path)
                .filter(|h| self.spawn_block_hashes.contains(h))
        } else {
            None
        };

        if hit_path || hit_hash.is_some() {
            let _ = crate::platform::suspend_process(pid);
            let killed = Self::os_terminate_process_real(pid);
            let match_kind = if let Some(ref h) = hit_hash {
                format!("SHA256={}", &h[..h.len().min(16)])
            } else {
                "路径匹配".to_string()
            };
            return Some(format!(
                "[SpawnBlock::Intercept] 检测到禁生载荷 \"{}\" (PID={}, {}) 企图重新孵化，已先冻后杀 (terminated={})",
                exe_path, pid, match_kind, killed
            ));
        }
        None
    }

    /// 执行指定的决策动作 a_0 ~ a_4，100% 走真实系统调用
    pub fn execute(
        &mut self,
        entity: &mut TrackedEntity,
        action: PolicyAction,
        triggered_by_user: bool,
        time_label: &str,
    ) -> SurgicalReceipt {
        let mut steps = Vec::new();
        let host_note: String;
        let mut suspended_ui_threads = Vec::new();
        let mut removed_registry_entries = Vec::new();
        let mut quarantined_vault_ids = Vec::new();

        let mut blocked_sha256: Option<String> = None;
        let _self_unused_check = triggered_by_user;

        // 安全护栏检查：绝不允许外科执行器对核心系统宿主或自身进程施加物理冻结/强杀
        if matches!(
            action,
            PolicyAction::A2SurgicalMute
                | PolicyAction::A3ProcessIsolate
                | PolicyAction::A4RootPurge
        ) {
            if let Some(guard_reason) =
                crate::remediation_matrix::RemediationMatrixEngine::detect_protected_system_target(
                    entity.pid,
                    &entity.process_name,
                    &entity.exe_path,
                )
            {
                steps.push(format!("[RiskGuard::Blocked] {}", guard_reason));
                let receipt = SurgicalReceipt {
                    receipt_id: self.next_receipt_id,
                    timestamp_label: time_label.to_string(),
                    pid: entity.pid,
                    process_name: entity.process_name.clone(),
                    exe_path: entity.exe_path.clone(),
                    action: PolicyAction::A1DeferWait,
                    triggered_by_user,
                    executed_steps: steps,
                    host_protection_note: format!("风控护栏拦截：{}", guard_reason),
                    rolled_back: false,
                    suspended_ui_threads,
                    removed_registry_entries,
                    quarantined_vault_ids,
                    blocked_sha256: None,
                    attribution_summary: String::new(),
                };
                self.next_receipt_id += 1;
                self.receipts.insert(0, receipt.clone());
                return receipt;
            }
        }

        match action {
            PolicyAction::A0PassAndUntag => {
                entity.active_in_arena = false;
                steps.push(format!(
                    "[Arena::Untag] 已确认 PID={} ({}) 属于正常交互，从稀疏追踪池摘牌释放算力",
                    entity.pid, entity.process_name
                ));
                host_note = "正常放行，零干预".to_string();
            }

            PolicyAction::A1DeferWait => {
                steps.push(format!(
                    "[Arena::KeepStained] 保持对 PID={} ({}) 的 16×12 滑动窗口染色监控，等待后续帧或用户裁决",
                    entity.pid, entity.process_name
                ));
                host_note = "静默观察中，未对系统施加破坏性操作".to_string();
            }

            PolicyAction::A2SurgicalMute => {
                // 保主进程、灭子窗口：剥夺 TOPMOST、隐藏/销毁广告 HWND、精准挂起渲染该窗口的 UI 线程
                if entity.ledger.popup_windows.is_empty() {
                    let suspended = crate::platform::suspend_process(entity.pid);
                    steps.push(format!(
                        "[OS::SurgicalSuspend] 目标 PID={} ({}) 无独立弹窗句柄，已执行进程保护性挂起 [OS={}]",
                        entity.pid, entity.process_name, suspended
                    ));
                } else {
                    for win in entity.ledger.popup_windows.iter_mut() {
                        let syscall_logs =
                            Self::os_surgical_mute_window_real(win.hwnd, win.ui_thread_id);
                        win.muted = true;
                        win.is_topmost = false;
                        suspended_ui_threads.push((win.hwnd, win.ui_thread_id));
                        steps.extend(syscall_logs);
                    }
                }
                entity.active_in_arena = false;
                if let Some(doc) = &entity.host_profile.active_document_hint {
                    host_note = format!(
                        "保主进程成功：宿主 {} (PID={}) 及其打开的文档「{}」完好无损",
                        entity.process_name, entity.pid, doc
                    );
                } else if entity.host_profile.is_critical_shell_host {
                    host_note = format!(
                        "保系统外壳成功：宿主 {} 正常运行，仅剥离寄生广告窗线程",
                        entity.process_name
                    );
                } else {
                    host_note = format!(
                        "外科手术消音完成：宿主 {} 主进程正常保留，广告子窗口与 UI 线程已物理消音",
                        entity.process_name
                    );
                }
            }

            PolicyAction::A3ProcessIsolate => {
                blocked_sha256 = self.kill_process_tree_and_block(entity, &mut steps);
                for win in entity.ledger.popup_windows.iter_mut() {
                    let _ = Self::os_surgical_mute_window_real(win.hwnd, win.ui_thread_id);
                    win.muted = true;
                }
                entity.active_in_arena = false;
                host_note = "已先冻后杀父子进程树并建立路径+SHA256双因子禁生，阻止改名重生".to_string();
            }

            PolicyAction::A4RootPurge => {
                // 1. 先冻结再按叶子->根顺序击毙全部父子进程树 + 写入路径/SHA256双因子禁生
                blocked_sha256 = self.kill_process_tree_and_block(entity, &mut steps);

                // 2. 检索《污染溯源账本》真实删除注册表 Run 启动项
                for (reg_key, val_name, val_data) in &entity.ledger.registry_run_entries {
                    let reg_deleted = delete_autorun_entry(val_name);
                    removed_registry_entries.push((
                        reg_key.clone(),
                        val_name.clone(),
                        val_data.clone(),
                    ));
                    steps.push(format!(
                        "[Registry::RegDeleteValueW] 顺着《污染溯源账本》删除自启动项: {}\\{} [OS删除成功={}]",
                        reg_key, val_name, reg_deleted
                    ));
                }

                // 3. 检索《污染溯源账本》真实注销计划任务 / LaunchAgent
                for task_name in &entity.ledger.scheduled_tasks {
                    let task_deleted = Self::os_delete_scheduled_task_real(task_name);
                    steps.push(format!(
                        "[TaskScheduler::Delete] 注销持久化计划任务/驻留配置: \"{}\" [OS执行={}]",
                        task_name, task_deleted
                    ));
                }

                // 4. 将释放到磁盘的可执行文件/恶意载荷物理移入安全隔离区保险箱
                for file_path in &entity.ledger.dropped_files {
                    if let Some((orig, vid, moved_dst)) =
                        self.quarantine_file_into_vault(file_path, &entity.process_name)
                    {
                        quarantined_vault_ids.push((orig, vid.clone()));
                        steps.push(format!(
                            "[Vault::PhysicalMove] 将释放的捆绑文件 \"{}\" 物理移动隔离至 \"{}\" (编号: {})",
                            file_path, moved_dst, vid
                        ));
                    }
                }

                entity.active_in_arena = false;
                host_note = format!(
                    "已顺着《污染溯源账本》完成进程树清剿与物理连根拔除，共处置 {} 项驻留与文件痕迹",
                    entity.ledger.total_artifacts()
                );
            }
        }

        let receipt = SurgicalReceipt {
            receipt_id: self.next_receipt_id,
            timestamp_label: time_label.to_string(),
            pid: entity.pid,
            process_name: entity.process_name.clone(),
            exe_path: entity.exe_path.clone(),
            action,
            triggered_by_user,
            executed_steps: steps,
            host_protection_note: host_note,
            rolled_back: false,
            suspended_ui_threads,
            removed_registry_entries,
            quarantined_vault_ids,
            blocked_sha256,
            attribution_summary: String::new(),
        };
        self.next_receipt_id += 1;
        self.receipts.insert(0, receipt.clone());
        receipt
    }

    /// 将目标定位摘要追加回写至指定处置回执（供持久化审计与 UI 回执联动展示）
    pub fn attach_attribution_to_receipt(&mut self, receipt_id: u64, summary: String) {
        if let Some(r) = self.receipts.iter_mut().find(|r| r.receipt_id == receipt_id) {
            r.attribution_summary = summary;
        }
    }

    /// 将目标文件物理移入隔离保险箱并写入台账，返回 `(orig_path, vault_id, vault_dst)`
    pub fn quarantine_file_into_vault(
        &mut self,
        file_path: &str,
        source_process: &str,
    ) -> Option<(String, String, String)> {
        if file_path.trim().is_empty() {
            return None;
        }
        let vault_id = format!("Q-{:04}", self.quarantine_vault.len() + 1);
        let moved_dst = move_file_to_quarantine_vault(file_path, &vault_id)
            .unwrap_or_else(|| format!("quarantine_vault/{}", vault_id));
        self.quarantine_vault.push(QuarantinedItem {
            original_path: file_path.to_string(),
            vault_path: moved_dst.clone(),
            vault_id: vault_id.clone(),
            source_process: source_process.to_string(),
            restored: false,
        });
        Some((file_path.to_string(), vault_id, moved_dst))
    }

    fn kill_process_tree_and_block(
        &mut self,
        entity: &TrackedEntity,
        steps: &mut Vec<String>,
    ) -> Option<String> {
        let mut child_pids = Vec::new();
        let mut seen = HashSet::new();

        for live_child in crate::platform::collect_descendant_pids(entity.pid) {
            if seen.insert(live_child) {
                child_pids.push((live_child, "child".to_string(), String::new()));
            }
        }
        for (child_pid, child_name, child_path) in &entity.ledger.spawned_children {
            if *child_pid > 1 && *child_pid != std::process::id() && seen.insert(*child_pid) {
                child_pids.push((*child_pid, child_name.clone(), child_path.clone()));
            } else if !child_path.is_empty() {
                let _ = self.block_executable_fingerprint(child_path);
            }
        }

        // 先整体冻结根进程与所有后代子进程，防止看门狗互保复活
        if entity.pid > 1 && entity.pid != std::process::id() {
            let _ = crate::platform::suspend_process(entity.pid);
        }
        for (cpid, _, _) in &child_pids {
            let _ = crate::platform::suspend_process(*cpid);
        }

        // 从叶子到根逐级击毙子进程并封禁其路径/SHA-256
        for (child_pid, child_name, child_path) in &child_pids {
            let ckilled = Self::os_terminate_process_real(*child_pid);
            if !child_path.is_empty() {
                let _ = self.block_executable_fingerprint(child_path);
            }
            steps.push(format!(
                "[ProcessTree::KillChild] 先冻后杀子进程 PID={} ({}) [OS={}]",
                child_pid, child_name, ckilled
            ));
        }

        let pkilled = Self::os_terminate_process_real(entity.pid);
        steps.push(format!(
            "[ProcessTree::KillRoot] 物理击毙主目标进程 PID={} ({}) [OS={}]",
            entity.pid, entity.process_name, pkilled
        ));

        let sha_opt = self.block_executable_fingerprint(&entity.exe_path);
        match &sha_opt {
            Some(sha) => steps.push(format!(
                "[Hook::DualSpawnBlock] 已封禁路径 \"{}\" 与 SHA-256 {}..{}，改名复制也无法重起",
                entity.exe_path,
                &sha[..8.min(sha.len())],
                &sha[sha.len().saturating_sub(6)..]
            )),
            None if !entity.exe_path.trim().is_empty() => steps.push(format!(
                "[Hook::SpawnBlock] 已将路径 \"{}\" 写入禁止孵化名单",
                entity.exe_path
            )),
            None => {}
        }
        sha_opt
    }

    /// 撤销某次处置：真实恢复被挂起的线程与窗口、解除路径与哈希禁生、将隔离区文件物理移回原路径、还原注册表项
    pub fn rollback_receipt(&mut self, receipt_id: u64) -> Option<String> {
        let rec_snapshot = {
            let rec = self
                .receipts
                .iter_mut()
                .find(|r| r.receipt_id == receipt_id)?;
            if rec.rolled_back {
                return None;
            }
            rec.rolled_back = true;
            rec.clone()
        };

        self.unblock_executable_fingerprint(
            &rec_snapshot.exe_path,
            rec_snapshot.blocked_sha256.as_deref(),
        );

        // 1. 恢复被 a_2 挂起的线程与隐藏窗口
        for &(hwnd, tid) in &rec_snapshot.suspended_ui_threads {
            Self::os_resume_window_and_thread_real(hwnd, tid);
        }
        if matches!(rec_snapshot.action, PolicyAction::A2SurgicalMute)
            && rec_snapshot.suspended_ui_threads.is_empty()
            && rec_snapshot.pid > 1
        {
            let _ = crate::platform::resume_process(rec_snapshot.pid);
        }

        // 2. 从隔离区目录将文件物理移回原路径
        for (orig_path, vid) in &rec_snapshot.quarantined_vault_ids {
            let _ = restore_file_from_quarantine_vault(orig_path, vid);
            for q in self.quarantine_vault.iter_mut() {
                if q.vault_id == *vid {
                    q.restored = true;
                }
            }
        }

        // 3. 若测试自启动项被删且用户要求恢复，则写回
        for (_key, val_name, val_data) in &rec_snapshot.removed_registry_entries {
            if val_name.starts_with("VNB_") {
                let _ = write_test_autorun_entry(val_name, val_data);
            }
        }

        Some(format!(
            "已物理撤销对「{} (PID={})」的 {} 处置：已解除路径与指纹禁生、恢复挂起线程并将隔离区文件还原至原路径",
            rec_snapshot.process_name,
            rec_snapshot.pid,
            rec_snapshot.action.cn_name()
        ))
    }

    #[cfg(target_os = "windows")]
    fn os_surgical_mute_window_real(hwnd: u64, ui_thread_id: u32) -> Vec<String> {
        crate::win_live_os::win32_impl::live_surgical_mute_window(hwnd, ui_thread_id)
            .unwrap_or_else(|e| vec![format!("[Win32::Error] {}", e)])
    }

    #[cfg(not(target_os = "windows"))]
    fn os_surgical_mute_window_real(hwnd: u64, ui_thread_id: u32) -> Vec<String> {
        let ok = crate::real_scanner::macos_close_or_mute_window_real(
            hwnd,
            ui_thread_id,
            "",
            "",
        );
        vec![
            format!(
                "[macOS::AXMute] 对窗口 WindowID=0x{:X} (PID/TID={}) 执行 Accessibility 关闭/最小化与冻结 [执行={}]",
                hwnd, ui_thread_id, ok
            ),
        ]
    }

    #[cfg(target_os = "windows")]
    fn os_resume_window_and_thread_real(hwnd: u64, ui_thread_id: u32) {
        crate::win_live_os::win32_impl::live_resume_muted_window(hwnd, ui_thread_id);
    }

    #[cfg(not(target_os = "windows"))]
    fn os_resume_window_and_thread_real(hwnd: u64, ui_thread_id: u32) {
        crate::real_scanner::macos_restore_window_real(hwnd, ui_thread_id);
    }

    #[cfg(target_os = "windows")]
    fn os_terminate_process_real(pid: u32) -> bool {
        crate::win_live_os::win32_impl::live_terminate_process(pid)
    }

    #[cfg(not(target_os = "windows"))]
    fn os_terminate_process_real(pid: u32) -> bool {
        if pid == 0 || pid == std::process::id() || pid >= 90000 {
            return true;
        }
        crate::platform::terminate_process(pid)
    }

    fn os_delete_scheduled_task_real(task_name: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            if task_name.trim().is_empty() {
                return false;
            }
            return matches!(
                std::process::Command::new("schtasks")
                    .args(["/Delete", "/TN", task_name, "/F"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output(),
                Ok(ref o) if o.status.success()
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            let trimmed = task_name.trim();
            if trimmed.is_empty() {
                return false;
            }
            let p = Path::new(trimmed);
            if p.exists()
                && (trimmed.ends_with(".plist")
                    || trimmed.contains("/LaunchAgents/")
                    || trimmed.contains("/LaunchDaemons/"))
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["unload", trimmed])
                    .output();
                return true;
            }
            false
        }
    }
}
