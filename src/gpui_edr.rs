//! 基于 Zed GPUI (Metal 4 硬件加速) 的高密度响应式本地 EDR × 9006 自动分析与自动决策工作台 (`src/gpui_edr.rs`)
//!
//! 解决四大核心工程要求：
//! 1. 自动决策判断 (`auto_execute_security_decisions`)：对 9006 协同识别为正常开发组件的对象自动加白放行 (A0)，对权限过宽凭据自动加固 (0600)，对高危暴露面自动锁定并置顶。
//! 2. 全域自动四阶分析 (`run_collaborative_triage_all` + 后台定时巡检)：启动及后台周期自动完成 ① 本地探针 ➔ ② 9006 System-1 ➔ ③ 9006 大模型 ➔ ④ 9006 Agent 深度取证 (`lsof` + `otool`)，无需人工逐行点击。
//! 3. 窗口缩放 100% 随动 (`relative(...)` + `flex_1()` + `min_w(0)` + `min_h(0)`)：移除固定死宽，左右分栏、多列表格列宽、底部实时日志流随窗口宽高实时弹性伸缩。
//! 4. 高密度零空间浪费布局：紧凑内边距 (`p_2` / `py_1`)、五列全宽对齐数据表、单行水平键值详情、右侧底部自适应填满的历史审计流。

use std::time::Duration;

use gpui::{
    actions, div, prelude::*, px, relative, rgb, size, App, Application, AsyncApp, Bounds,
    Context, KeyBinding, SharedString, Timer, WeakEntity, Window, WindowBounds, WindowOptions,
};

use crate::contract::PolicyAction;
use crate::edr_engine::{
    DecisionCallMode, HardenVulnsJobInputs, LlmSecurityVerdict, LocalEdrEngine, ReasoningCallMode,
    ReasoningJobInputs, ThreatSeverity,
};

actions!(vnb_edr_gpui, [Quit]);

// 商业终端安全深色视觉规范常量 (Ardot Dark Hierarchy + Semantic CTAs)
const BG_CANVAS: u32 = 0x0b0c0e;
const BG_PANEL: u32 = 0x111317;
const BG_CARD: u32 = 0x14171c;
const BG_CARD_SELECTED: u32 = 0x1c2028;
const BG_HEADER_ROW: u32 = 0x161920;
const BG_BTN: u32 = 0x1e222a;
const BG_BTN_ACTIVE: u32 = 0x2b313d;

const BORDER_SUBTLE: u32 = 0x22262f;
const BORDER_SELECTED: u32 = 0x475569;

const TEXT_PRIMARY: u32 = 0xf1f5f9;
const TEXT_SECONDARY: u32 = 0x94a3b8;
const TEXT_MUTED: u32 = 0x64748b;
const TEXT_BRIGHT: u32 = 0xffffff;

const DOT_RED: u32 = 0xef4444;
const DOT_AMBER: u32 = 0xf59e0b;
const DOT_GREEN: u32 = 0x10b981;

const BTN_DANGER_BG: u32 = 0xdc2626;
const BTN_DANGER_BORDER: u32 = 0xf87171;
const BTN_PRIMARY_BG: u32 = 0x2563eb;
const BTN_PRIMARY_BORDER: u32 = 0x60a5fa;
const BTN_INFO_BG: u32 = 0x172554;
const BTN_INFO_TEXT: u32 = 0x93c5fd;
const BTN_TRUST_BG: u32 = 0x0f2922;
const BTN_TRUST_BORDER: u32 = 0x10b981;
const BTN_TRUST_TEXT: u32 = 0x34d399;
const BTN_WARN_BG: u32 = 0x451a03;
const BTN_WARN_BORDER: u32 = 0xf59e0b;
const BTN_WARN_TEXT: u32 = 0xfbbf24;
const ACCENT_BLUE: u32 = 0x3b82f6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdrWorkbenchTab {
    AlertsCenter,
    AdBlockCleanupView,
    FirewallIpsView,
    ThreatIntelView,
    ProcessLineageView,
    PersistenceGuardView,
    NetworkC2View,
    FimAndVaultView,
    HistoryLogView,
    ModelConfigView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelSubTab {
    ReportsAndInvestigate,
    IntelFeedsConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallIpsSubTab {
    Rules,
    IpsEvents,
    PayloadDrills,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdBlockSubTab {
    DesktopPopups,
    ArtifactsCleanup,
    DomainShield,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFilterMode {
    AllDecisions,
    PendingManualConfirm,
    AutoDecidedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigEditField {
    DecisionEndpoint,
    ReasoningEndpoint,
    ReasoningModelName,
    ReasoningApiKey,
    SimpleCliCommand,
    CustomSystemPrompt,
    IntelQueryTarget,
    IntelFeedName,
    IntelFeedEndpoint,
    IntelFeedApiKey,
}

pub struct EdrGpuiWorkbench {
    pub edr: LocalEdrEngine,
    pub active_tab: EdrWorkbenchTab,
    pub ad_sub_tab: AdBlockSubTab,
    pub fw_sub_tab: FirewallIpsSubTab,
    pub intel_sub_tab: ThreatIntelSubTab,
    pub alert_filter: AlertFilterMode,
    pub selected_alert_idx: usize,
    pub selected_ad_win_idx: usize,
    pub selected_ad_cand_idx: usize,
    pub selected_ad_conn_idx: usize,
    pub selected_fw_rule_idx: usize,
    pub selected_ips_event_idx: usize,
    pub selected_intel_report_idx: usize,
    pub selected_intel_feed_idx: usize,
    pub selected_proc_idx: usize,
    pub selected_persist_idx: usize,
    pub selected_sock_idx: usize,
    pub selected_fim_idx: usize,
    pub selected_history_idx: usize,
    pub history_category_filter: Option<String>,
    pub hot_reload_ticks: u64,
    pub active_config_field: Option<ConfigEditField>,
    pub intel_query_input: String,
    pub intel_feed_name_input: String,
    pub intel_feed_url_input: String,
    pub intel_feed_key_input: String,
    pub show_topbar_drawer: bool,
    pub show_alerts_pipeline_info: bool,
    pub show_ad_detail_drawer: bool,
    pub show_fw_detail_drawer: bool,
    pub show_intel_detail_drawer: bool,
    pub show_model_dec_card: bool,
    pub show_model_reas_card: bool,
    pub show_model_manual_card: bool,
    pub show_right_model_bar: bool,
    pub show_right_evidence_details: bool,
    pub show_right_playbook_details: bool,
    pub show_right_object_meta: bool,
    pub show_live_log_drawer: bool,
    pub show_advanced_remediation: bool,
    pub locator_status_note: Option<String>,
    pub expanded_row_key: Option<String>,
    pub scan_in_flight: bool,
    pub scan_gen: u64,
    pub forensic_in_flight: Option<String>,
    pub forensic_gen: u64,
    pub intel_in_flight: Option<String>,
    pub reasoning_in_flight: Option<String>,
    pub reasoning_gen: u64,
    pub harden_in_flight: bool,
    pub focus_handle: gpui::FocusHandle,
}

impl EdrGpuiWorkbench {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let edr = LocalEdrEngine::new_ui_shell();
        let focus_handle = cx.focus_handle();
        let exe_path = std::env::current_exe().ok();
        let dylib_path = crate::platform::app_install_root().join("lib/libvnb_edr_gpui.dylib");
        let startup_mtime = exe_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        let startup_dylib_mtime = std::fs::metadata(&dylib_path)
            .ok()
            .and_then(|m| m.modified().ok());

        // 后台仅执行 0.005ms 的二进制/动态库修改时间检查（支持更新 libvnb_edr_gpui.dylib 后平滑热重启），
        // 绝不在后台定时轮询 lsof 或自动调用 27B 推理模型，保证客户端空闲时 0% CPU/GPU 占用与毫秒级点击响应！
        cx.spawn(move |_this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let cx = cx.clone();
            async move {
                loop {
                    Timer::after(Duration::from_secs(4)).await;
                    let mut changed = false;
                    if let (Some(ref path), Some(init_t)) = (&exe_path, startup_mtime) {
                        if let Ok(meta) = std::fs::metadata(path) {
                            if let Ok(cur_t) = meta.modified() {
                                if cur_t > init_t {
                                    changed = true;
                                }
                            }
                        }
                    }
                    if let Some(init_dt) = startup_dylib_mtime {
                        if let Ok(meta) = std::fs::metadata(&dylib_path) {
                            if let Ok(cur_dt) = meta.modified() {
                                if cur_dt > init_dt {
                                    changed = true;
                                }
                            }
                        }
                    }
                    if changed {
                        if let Some(ref path) = exe_path {
                            let _ = std::process::Command::new(path).spawn();
                            let _ = cx.update(|app| app.quit());
                            break;
                        }
                    }
                }
            }
        })
        .detach();

        let first_feed_name = edr
            .threat_intel
            .feeds
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let first_feed_url = edr
            .threat_intel
            .feeds
            .first()
            .map(|f| f.endpoint_url.clone())
            .unwrap_or_default();
        let first_feed_key = edr
            .threat_intel
            .feeds
            .first()
            .map(|f| f.api_key.clone())
            .unwrap_or_default();

        let mut this = Self {
            edr,
            active_tab: EdrWorkbenchTab::AlertsCenter,
            ad_sub_tab: AdBlockSubTab::DesktopPopups,
            fw_sub_tab: FirewallIpsSubTab::Rules,
            intel_sub_tab: ThreatIntelSubTab::ReportsAndInvestigate,
            alert_filter: AlertFilterMode::AllDecisions,
            selected_alert_idx: 0,
            selected_ad_win_idx: 0,
            selected_ad_cand_idx: 0,
            selected_ad_conn_idx: 0,
            selected_fw_rule_idx: 0,
            selected_ips_event_idx: 0,
            selected_intel_report_idx: 0,
            selected_intel_feed_idx: 0,
            selected_proc_idx: 0,
            selected_persist_idx: 0,
            selected_sock_idx: 0,
            selected_fim_idx: 0,
            selected_history_idx: 0,
            history_category_filter: None,
            hot_reload_ticks: 1,
            active_config_field: Some(ConfigEditField::ReasoningEndpoint),
            intel_query_input: "198.51.100.44:4444".to_string(),
            intel_feed_name_input: first_feed_name,
            intel_feed_url_input: first_feed_url,
            intel_feed_key_input: first_feed_key,
            show_topbar_drawer: false,
            show_alerts_pipeline_info: false,
            show_ad_detail_drawer: false,
            show_fw_detail_drawer: false,
            show_intel_detail_drawer: false,
            show_model_dec_card: true,
            show_model_reas_card: true,
            show_model_manual_card: false,
            show_right_model_bar: false,
            show_right_evidence_details: false,
            show_right_playbook_details: false,
            show_right_object_meta: true,
            show_live_log_drawer: false,
            show_advanced_remediation: false,
            locator_status_note: None,
            expanded_row_key: None,
            scan_in_flight: false,
            scan_gen: 0,
            forensic_in_flight: None,
            forensic_gen: 0,
            intel_in_flight: None,
            reasoning_in_flight: None,
            reasoning_gen: 0,
            harden_in_flight: false,
            focus_handle,
        };
        this.spawn_telemetry_scan_task(true, cx);
        this
    }

    /// 异步启动后台全量遥测巡检与 9006 探测（彻底脱离 UI 主线程，冷启动 <80ms 首帧直出）
    fn spawn_telemetry_scan_task(&mut self, force_full: bool, cx: &mut Context<Self>) {
        self.scan_gen = self.scan_gen.wrapping_add(1);
        let my_gen = self.scan_gen;
        self.scan_in_flight = true;
        let req = self.edr.prepare_background_scan(force_full);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = LocalEdrEngine::execute_background_scan_offline(req);
            let _ = tx.send(res);
        });
        cx.spawn(move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    match rx.try_recv() {
                        Ok(res) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                this.edr.commit_background_scan(res);
                                this.hot_reload_ticks = this.hot_reload_ticks.wrapping_add(1);
                                this.selected_alert_idx = this
                                    .selected_alert_idx
                                    .min(this.edr.alerts.len().saturating_sub(1));
                                this.selected_proc_idx = this
                                    .selected_proc_idx
                                    .min(this.edr.live_processes.len().saturating_sub(1));
                                this.selected_persist_idx = this
                                    .selected_persist_idx
                                    .min(this.edr.persistence_entries.len().saturating_sub(1));
                                this.selected_sock_idx = this
                                    .selected_sock_idx
                                    .min(this.edr.active_sockets.len().saturating_sub(1));
                                this.selected_fim_idx = this
                                    .selected_fim_idx
                                    .min(this.edr.fim_records.len().saturating_sub(1));
                                if this.scan_gen == my_gen {
                                    this.scan_in_flight = false;
                                }
                                cx.notify();
                            });
                            break;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            Timer::after(Duration::from_millis(20)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                if this.scan_gen == my_gen {
                                    this.scan_in_flight = false;
                                }
                                cx.notify();
                            });
                            break;
                        }
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// 异步启动 6 维现场深度取证（缓存命中瞬间返回；否则移交后台 OS 线程并发执行，支持切换目标时抢占旧任务）
    fn spawn_forensic_task(
        &mut self,
        cache_key: String,
        pid: u32,
        proc_name: String,
        exe_path: String,
        summary_hint: String,
        cx: &mut Context<Self>,
    ) {
        self.show_right_evidence_details = true;
        if self
            .edr
            .check_forensic_cache(&cache_key, pid, &exe_path)
            .is_some()
        {
            let _ = self.edr.run_deep_forensic_collaboration(
                &cache_key,
                pid,
                &proc_name,
                &exe_path,
                &summary_hint,
            );
            self.forensic_gen = self.forensic_gen.wrapping_add(1);
            self.forensic_in_flight = None;
            cx.notify();
            return;
        }
        self.forensic_gen = self.forensic_gen.wrapping_add(1);
        let my_gen = self.forensic_gen;
        let label = format!("正在对 {} (PID={}) 并行采集句柄/二进制/存证...", proc_name, pid);
        self.forensic_in_flight = Some(label);
        let job = self.edr.prepare_forensic_job(
            &cache_key,
            pid,
            &proc_name,
            &exe_path,
            &summary_hint,
        );
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = LocalEdrEngine::execute_forensic_job_offline(job);
            let _ = tx.send(res);
        });
        cx.spawn(move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    match rx.try_recv() {
                        Ok(bundle) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                let _ = this.edr.commit_forensic_bundle(bundle);
                                if this.forensic_gen == my_gen {
                                    this.forensic_in_flight = None;
                                }
                                cx.notify();
                            });
                            break;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            Timer::after(Duration::from_millis(16)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                if this.forensic_gen == my_gen {
                                    this.forensic_in_flight = None;
                                }
                                cx.notify();
                            });
                            break;
                        }
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// 异步执行协同推演 / 模型自检（彻底脱离 GPUI 主线程，避免等待 27B/HTTP 阻塞界面）
    fn spawn_reasoning_task(
        &mut self,
        job: ReasoningJobInputs,
        label: String,
        cx: &mut Context<Self>,
    ) {
        self.reasoning_gen = self.reasoning_gen.wrapping_add(1);
        let my_gen = self.reasoning_gen;
        self.reasoning_in_flight = Some(label);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = LocalEdrEngine::execute_reasoning_job_offline(job);
            let _ = tx.send(out);
        });
        cx.spawn(move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    match rx.try_recv() {
                        Ok(out) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                let _ = this.edr.commit_reasoning_job_output(out);
                                if this.reasoning_gen == my_gen {
                                    this.reasoning_in_flight = None;
                                }
                                cx.notify();
                            });
                            break;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            Timer::after(Duration::from_millis(16)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                if this.reasoning_gen == my_gen {
                                    this.reasoning_in_flight = None;
                                }
                                cx.notify();
                            });
                            break;
                        }
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// 异步批量加固暴露面并并行完成待处理告警取证
    fn spawn_harden_vulns_task(&mut self, cx: &mut Context<Self>) {
        if self.harden_in_flight {
            return;
        }
        self.harden_in_flight = true;
        let job: HardenVulnsJobInputs = self.edr.prepare_harden_vulns_job();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = LocalEdrEngine::execute_harden_vulns_offline(job);
            let _ = tx.send(out);
        });
        cx.spawn(move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    match rx.try_recv() {
                        Ok(out) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                let _ = this.edr.commit_harden_vulns_result(out);
                                this.harden_in_flight = false;
                                cx.notify();
                            });
                            break;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            Timer::after(Duration::from_millis(16)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                this.harden_in_flight = false;
                                cx.notify();
                            });
                            break;
                        }
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// 异步启动网络攻击指纹 + 代码基因 + 多情报库并行联查（绝不在 UI 主线程阻塞等 HTTP）
    fn spawn_intel_investigation(
        &mut self,
        query: String,
        drill_kind: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if self.intel_in_flight.is_some() {
            return;
        }
        let label = if let Some(ref dk) = drill_kind {
            format!("正在并行执行演练与多情报库联查 [{}]...", dk)
        } else {
            format!("正在并行联查指纹+基因与多情报源: {}...", query)
        };
        self.intel_in_flight = Some(label);
        let job = self
            .edr
            .prepare_threat_intel_job(&query, drill_kind.as_deref());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = crate::threat_intel::ThreatIntelEngine::execute_job_offline(job);
            let _ = tx.send(out);
        });
        cx.spawn(move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let mut cx = cx.clone();
            async move {
                loop {
                    match rx.try_recv() {
                        Ok(out) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                let _ = this.edr.commit_threat_intel_job(out);
                                this.selected_intel_report_idx = 0;
                                this.intel_in_flight = None;
                                cx.notify();
                            });
                            break;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            Timer::after(Duration::from_millis(16)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = this.update(&mut cx, |this, cx| {
                                this.intel_in_flight = None;
                                cx.notify();
                            });
                            break;
                        }
                    }
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn read_system_clipboard() -> String {
        crate::platform::read_clipboard_text()
    }

    fn get_config_field_mut(&mut self, field: ConfigEditField) -> &mut String {
        match field {
            ConfigEditField::DecisionEndpoint => &mut self.edr.model_config.decision_endpoint,
            ConfigEditField::ReasoningEndpoint => &mut self.edr.model_config.reasoning_endpoint,
            ConfigEditField::ReasoningModelName => &mut self.edr.model_config.reasoning_model_name,
            ConfigEditField::ReasoningApiKey => &mut self.edr.model_config.reasoning_api_key,
            ConfigEditField::SimpleCliCommand => &mut self.edr.model_config.simple_cli_command,
            ConfigEditField::CustomSystemPrompt => &mut self.edr.model_config.custom_system_prompt,
            ConfigEditField::IntelQueryTarget => &mut self.intel_query_input,
            ConfigEditField::IntelFeedName => &mut self.intel_feed_name_input,
            ConfigEditField::IntelFeedEndpoint => &mut self.intel_feed_url_input,
            ConfigEditField::IntelFeedApiKey => &mut self.intel_feed_key_input,
        }
    }

    fn handle_config_key_down(&mut self, event: &gpui::KeyDownEvent, cx: &mut Context<Self>) {
        let Some(field) = self.active_config_field else {
            return;
        };
        let key = event.keystroke.key.as_str();
        let modifiers = &event.keystroke.modifiers;

        if modifiers.platform && key.eq_ignore_ascii_case("v") {
            let clip = Self::read_system_clipboard();
            if !clip.is_empty() {
                let target = self.get_config_field_mut(field);
                target.push_str(&clip);
                if field == ConfigEditField::ReasoningModelName {
                    self.edr.preferred_llm_model =
                        self.edr.model_config.reasoning_model_name.clone();
                }
                self.edr.save_model_config();
                cx.notify();
            }
            return;
        }

        match key {
            "backspace" => {
                let target = self.get_config_field_mut(field);
                target.pop();
                if field == ConfigEditField::ReasoningModelName {
                    self.edr.preferred_llm_model =
                        self.edr.model_config.reasoning_model_name.clone();
                }
                self.edr.save_model_config();
                cx.notify();
            }
            "enter" | "escape" => {
                self.edr.save_model_config();
                cx.notify();
            }
            "space" => {
                let target = self.get_config_field_mut(field);
                target.push(' ');
                self.edr.save_model_config();
                cx.notify();
            }
            _ => {
                if !modifiers.platform && !modifiers.control && !modifiers.alt {
                    if let Some(ref kc) = event.keystroke.key_char {
                        let target = self.get_config_field_mut(field);
                        target.push_str(kc);
                    } else if key.chars().count() == 1 {
                        let ch = key.chars().next().unwrap();
                        let ch_out = if modifiers.shift {
                            ch.to_ascii_uppercase()
                        } else {
                            ch
                        };
                        let target = self.get_config_field_mut(field);
                        target.push(ch_out);
                    }
                    if field == ConfigEditField::ReasoningModelName {
                        self.edr.preferred_llm_model =
                            self.edr.model_config.reasoning_model_name.clone();
                    }
                    self.edr.save_model_config();
                    cx.notify();
                }
            }
        }
    }

    fn severity_dot_color(sev: ThreatSeverity) -> u32 {
        match sev {
            ThreatSeverity::Critical | ThreatSeverity::High => DOT_RED,
            ThreatSeverity::Medium | ThreatSeverity::Low => DOT_AMBER,
            ThreatSeverity::Safe => DOT_GREEN,
        }
    }

    fn status_dot(hex: u32) -> gpui::Div {
        div()
            .w(px(7.0))
            .h(px(7.0))
            .flex_shrink_0()
            .rounded_full()
            .bg(rgb(hex))
    }

    fn clean_commercial_text(raw: &str) -> String {
        let mut s = raw
            .replace("9006-system1+binary-act · ", "")
            .replace("local-sza+binary-act · ", "")
            .replace("9006-system1+binary-act", "智能安全引擎")
            .replace("local-sza+binary-act", "本地安全引擎")
            .replace("[9006-System1] ", "")
            .replace("[Local-SZA] ", "")
            .replace("自动核验：", "")
            .replace(" (a_0)", "")
            .replace(" (a_1)", "")
            .replace(" (a_2)", "")
            .replace(" (a_3)", "")
            .replace(" (a_4)", "")
            .replace("（建议人工复核）", "");
        s = s.trim().trim_start_matches('·').trim().to_string();
        if s.is_empty() {
            "安全分析完成".to_string()
        } else {
            s
        }
    }

    fn policy_action_commercial_label(action: PolicyAction) -> &'static str {
        match action {
            PolicyAction::A0PassAndUntag => "信任放行",
            PolicyAction::A1DeferWait => "暂缓观察",
            PolicyAction::A2SurgicalMute => "冻结隔离弹窗",
            PolicyAction::A3ProcessIsolate => "隔离并终止进程",
            PolicyAction::A4RootPurge => "彻底清除并隔离",
        }
    }

    /// 紧凑型单行水平键值行（高对比商业信息排版，支持随窗口宽度自适应截断）
    fn kv_inline_row(label: &str, value: &str) -> gpui::Div {
        div()
            .flex()
            .flex_row()
            .items_center()
            .w_full()
            .min_w(px(0.0))
            .gap_2()
            .py(px(3.5))
            .border_b_1()
            .border_color(rgb(0x1b2029))
            .child(
                div()
                    .w(px(76.0))
                    .flex_shrink_0()
                    .text_size(px(11.0))
                    .text_color(rgb(TEXT_SECONDARY))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(px(11.5))
                    .text_color(rgb(TEXT_PRIMARY))
                    .child(value.to_string()),
            )
    }

    fn toggle_expand_row(&mut self, key: String) {
        if self.expanded_row_key.as_deref() == Some(key.as_str()) {
            self.expanded_row_key = None;
        } else {
            self.expanded_row_key = Some(key);
        }
    }

    fn disclosure_chip(
        id: impl Into<SharedString>,
        label: &str,
        expanded: bool,
    ) -> gpui::Stateful<gpui::Div> {
        div()
            .id(id.into())
            .flex_shrink_0()
            .px_2()
            .py(px(2.5))
            .rounded_sm()
            .cursor_pointer()
            .bg(if expanded {
                rgb(BTN_INFO_BG)
            } else {
                rgb(BG_BTN)
            })
            .border_1()
            .border_color(if expanded {
                rgb(BTN_PRIMARY_BORDER)
            } else {
                rgb(BORDER_SUBTLE)
            })
            .text_size(px(10.5))
            .text_color(if expanded {
                rgb(BTN_INFO_TEXT)
            } else {
                rgb(TEXT_SECONDARY)
            })
            .child(format!("{} {}", label, if expanded { "▾" } else { "▸" }))
    }

    fn row_expand_btn(id: impl Into<SharedString>, expanded: bool) -> gpui::Stateful<gpui::Div> {
        div()
            .id(id.into())
            .px_1p5()
            .py(px(1.5))
            .flex()
            .items_center()
            .justify_center()
            .flex_shrink_0()
            .rounded_sm()
            .cursor_pointer()
            .bg(if expanded {
                rgb(BTN_PRIMARY_BG)
            } else {
                rgb(BTN_INFO_BG)
            })
            .border_1()
            .border_color(if expanded {
                rgb(BTN_PRIMARY_BORDER)
            } else {
                rgb(0x1e3a8a)
            })
            .text_size(px(10.0))
            .text_color(if expanded {
                rgb(TEXT_BRIGHT)
            } else {
                rgb(BTN_INFO_TEXT)
            })
            .child(if expanded { "收起 ▾" } else { "详情 ▸" })
    }

    fn render_target_locator_card(
        &self,
        loc: &crate::edr_engine::TargetAttributionLocator,
        signer: &str,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let (preview_l1, preview_l2) = loc.compact_two_lines();
        let copy_report = loc.to_clipboard_report();
        let reveal_path = loc.reveal_path.clone();
        let has_reveal = !reveal_path.trim().is_empty();
        let header_title = if loc.pid > 0 {
            format!("详细信息 · {} (PID {})", loc.target_label, loc.pid)
        } else {
            format!("详细信息 · {}", loc.target_label)
        };

        let mut kv_rows: Vec<(&'static str, String)> = Vec::new();
        let mut push_kv = |k: &'static str, v: &str| {
            let trimmed = v.trim();
            if !trimmed.is_empty() && trimmed != "-" {
                kv_rows.push((k, trimmed.to_string()));
            }
        };
        if loc.pid > 0 {
            push_kv("签名/PID", &format!("{} (PID {} / PPID {})", signer, loc.pid, loc.ppid));
        } else {
            push_kv("来源签名", signer);
        }
        push_kv("程序路径", &loc.exe_path);
        push_kv("工作目录", &loc.cwd);
        push_kv("启动命令", &loc.cmdline);
        push_kv("父进程链", &loc.ancestry_chain);
        if !loc.network_endpoints.is_empty() {
            push_kv("网络端点", &loc.network_endpoints.join(" | "));
        }
        push_kv("入口/配置", &loc.entry_script_or_config);
        if loc.config_path != loc.entry_script_or_config {
            push_kv("配置文件", &loc.config_path);
        }
        push_kv("服务单元", &loc.service_unit);
        push_kv("用户终端", &loc.user_and_tty);
        push_kv("文件属主", &loc.file_owner);
        push_kv("来源追踪", &loc.provenance_hint);
        push_kv("SHA-256", &loc.sha256_hex);
        if !loc.injected_modules.is_empty() {
            push_kv("注入模块", &loc.injected_modules.join(", "));
        }
        if !loc.holder_processes.is_empty() {
            push_kv("占用进程", &loc.holder_processes.join(", "));
        }
        push_kv("窗口句柄", &loc.window_summary);

        let mut expanded_box = div()
            .flex()
            .flex_col()
            .w_full()
            .min_w(px(0.0))
            .p_2()
            .rounded_sm()
            .bg(rgb(BG_PANEL))
            .border_1()
            .border_color(rgb(BORDER_SUBTLE))
            .gap(px(2.0));
        for (k, v) in kv_rows {
            expanded_box = expanded_box.child(Self::kv_inline_row(k, &v));
        }

        div()
            .id("right-target-locator-card")
            .flex()
            .flex_col()
            .w_full()
            .min_w(px(0.0))
            .flex_shrink_0()
            .p_2()
            .rounded_sm()
            .bg(rgb(BG_CARD))
            .border_1()
            .border_color(rgb(0x2b3648))
            .gap(px(5.0))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .w_full()
                    .min_w(px(0.0))
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_1()
                            .min_w(px(0.0))
                            .gap_1p5()
                            .child(Self::status_dot(ACCENT_BLUE))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(12.0))
                                    .text_color(rgb(TEXT_BRIGHT))
                                    .child(header_title),
                            ),
                    )
                    .child(
                        div()
                            .id("btn-copy-locator")
                            .px_2()
                            .py(px(2.0))
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(BTN_INFO_BG))
                            .border_1()
                            .border_color(rgb(BTN_PRIMARY_BORDER))
                            .text_size(px(10.5))
                            .text_color(rgb(BTN_INFO_TEXT))
                            .child("复制信息")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let ok = crate::platform::write_clipboard_text(&copy_report);
                                this.locator_status_note = Some(if ok {
                                    "✓ 已复制完整溯源定位信息至剪贴板".to_string()
                                } else {
                                    "剪贴板写入未就绪".to_string()
                                });
                                cx.notify();
                            })),
                    )
                    .children(has_reveal.then(|| {
                        let rev = reveal_path.clone();
                        div()
                            .id("btn-reveal-locator")
                            .px_2()
                            .py(px(2.0))
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(BTN_INFO_BG))
                            .border_1()
                            .border_color(rgb(BTN_PRIMARY_BORDER))
                            .text_size(px(10.5))
                            .text_color(rgb(BTN_INFO_TEXT))
                            .child("打开目录")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let ok = crate::platform::reveal_in_file_manager(
                                    std::path::Path::new(&rev),
                                );
                                this.locator_status_note = Some(if ok {
                                    format!("已在文件管理器定位: {}", rev)
                                } else {
                                    format!("路径不存在或不可访问: {}", rev)
                                });
                                cx.notify();
                            }))
                    }))
                    .child(
                        Self::disclosure_chip(
                            "btn-right-obj-meta",
                            "完整字段",
                            self.show_right_object_meta,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_right_object_meta = !this.show_right_object_meta;
                            cx.notify();
                        })),
                    ),
            )
            .child(
                div()
                    .w_full()
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(px(11.0))
                    .text_color(rgb(TEXT_PRIMARY))
                    .child(preview_l1),
            )
            .child(
                div()
                    .w_full()
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(px(10.5))
                    .text_color(rgb(TEXT_SECONDARY))
                    .child(preview_l2),
            )
            .children(self.locator_status_note.as_ref().map(|note| {
                div()
                    .w_full()
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(px(10.5))
                    .text_color(rgb(DOT_GREEN))
                    .child(note.clone())
            }))
            .children(self.show_right_object_meta.then_some(expanded_box))
    }

    fn inline_row_drawer(items: &[(&str, &str)]) -> gpui::Div {
        let mut box_div = div()
            .flex()
            .flex_col()
            .w_full()
            .min_w(px(0.0))
            .px_2p5()
            .py(px(6.0))
            .rounded_sm()
            .bg(rgb(0x0f141c))
            .border_l_2()
            .border_color(rgb(ACCENT_BLUE))
            .gap(px(2.5));
        for (k, v) in items {
            box_div = box_div.child(Self::kv_inline_row(k, v));
        }
        box_div
    }

    /// 底部可折叠实时日志抽屉：默认收起为 30px 摘要条，点击「展开日志 ▴」按需展开滚动日志面板
    fn render_bottom_live_log_drawer(&self, cx: &mut Context<Self>) -> gpui::Stateful<gpui::Div> {
        let log_count = self.edr.history_records.len();
        let expanded = self.show_live_log_drawer;
        let latest_preview = if let Some(rec) = self.edr.history_records.first() {
            format!(
                "[{}] {} · {}",
                rec.timestamp,
                rec.target_name,
                Self::clean_commercial_text(&rec.summary)
            )
        } else if self.scan_in_flight {
            "正在后台执行系统安全巡检，日志将实时更新...".to_string()
        } else {
            "系统运行平稳，暂无新增安全事件".to_string()
        };

        div()
            .id("bottom-live-log-dock")
            .flex()
            .flex_col()
            .w_full()
            .min_w(px(0.0))
            .flex_shrink_0()
            .bg(rgb(BG_PANEL))
            .border_t_1()
            .border_color(rgb(BORDER_SUBTLE))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .w_full()
                    .min_w(px(0.0))
                    .px_3()
                    .py(px(5.0))
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_1()
                            .min_w(px(0.0))
                            .gap_2()
                            .child(Self::status_dot(if self.scan_in_flight {
                                DOT_AMBER
                            } else {
                                DOT_GREEN
                            }))
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(format!("实时日志 ({})", log_count)),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child(latest_preview),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_shrink_0()
                            .gap_1p5()
                            .child(
                                div()
                                    .id("btn-toggle-live-log-drawer")
                                    .px_2()
                                    .py(px(2.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if expanded {
                                        rgb(BTN_PRIMARY_BG)
                                    } else {
                                        rgb(BTN_INFO_BG)
                                    })
                                    .border_1()
                                    .border_color(if expanded {
                                        rgb(BTN_PRIMARY_BORDER)
                                    } else {
                                        rgb(0x1e3a8a)
                                    })
                                    .text_size(px(10.5))
                                    .text_color(if expanded {
                                        rgb(TEXT_BRIGHT)
                                    } else {
                                        rgb(BTN_INFO_TEXT)
                                    })
                                    .child(if expanded { "收起日志 ▾" } else { "展开日志 ▴" })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_live_log_drawer = !this.show_live_log_drawer;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("btn-jump-history-tab")
                                    .px_2()
                                    .py(px(2.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("全部日志 ➔")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.active_tab = EdrWorkbenchTab::HistoryLogView;
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .children(expanded.then(|| {
                div()
                    .id("bottom-live-log-scroll")
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .h(px(180.0))
                    .px_3()
                    .py_1p5()
                    .bg(rgb(BG_CANVAS))
                    .border_t_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1()
                    .overflow_scroll()
                    .children(self.edr.history_records.iter().take(50).enumerate().map(
                        |(idx, rec)| {
                            let dot_hex = match rec.category.as_str() {
                                "告警发现" => DOT_RED,
                                "大模型会诊" | "9006深度取证" => DOT_AMBER,
                                _ => DOT_GREEN,
                            };
                            div()
                                .id(SharedString::from(format!("dock-hist-{}", rec.seq_id)))
                                .flex()
                                .flex_row()
                                .items_center()
                                .w_full()
                                .min_w(px(0.0))
                                .px_2()
                                .py(px(3.5))
                                .rounded_sm()
                                .cursor_pointer()
                                .bg(rgb(BG_CARD))
                                .border_1()
                                .border_color(rgb(BORDER_SUBTLE))
                                .gap_2()
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.active_tab = EdrWorkbenchTab::HistoryLogView;
                                    this.selected_history_idx = idx;
                                    cx.notify();
                                }))
                                .child(Self::status_dot(dot_hex))
                                .child(
                                    div()
                                        .w(px(56.0))
                                        .flex_shrink_0()
                                        .text_size(px(10.5))
                                        .text_color(rgb(TEXT_MUTED))
                                        .child(rec.timestamp.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(90.0))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_size(px(11.0))
                                        .text_color(rgb(TEXT_PRIMARY))
                                        .child(rec.target_name.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(84.0))
                                        .flex_shrink_0()
                                        .truncate()
                                        .text_size(px(10.5))
                                        .text_color(rgb(TEXT_SECONDARY))
                                        .child(rec.category.clone()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.0))
                                        .truncate()
                                        .text_size(px(11.0))
                                        .text_color(rgb(TEXT_SECONDARY))
                                        .child(Self::clean_commercial_text(&rec.summary)),
                                )
                        },
                    ))
            }))
    }

    /// 紧凑表格列头生成辅助
    fn table_header_bar(cols: &[(&str, f32)], action_col_label: &str) -> gpui::Div {
        let mut row = div()
            .flex()
            .flex_row()
            .items_center()
            .w_full()
            .min_w(px(0.0))
            .px_2()
            .py_1()
            .rounded_sm()
            .bg(rgb(BG_HEADER_ROW))
            .border_1()
            .border_color(rgb(BORDER_SUBTLE))
            .gap_2();

        for (title, ratio) in cols {
            row = row.child(
                div()
                    .w(relative(*ratio))
                    .min_w(px(0.0))
                    .truncate()
                    .text_size(px(11.0))
                    .text_color(rgb(TEXT_MUTED))
                    .child((*title).to_string()),
            );
        }

        row.child(
            div()
                .w(px(124.0))
                .flex_shrink_0()
                .text_size(px(11.0))
                .text_color(rgb(TEXT_MUTED))
                .child(action_col_label.to_string()),
        )
    }
}

impl Render for EdrGpuiWorkbench {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let unresolved_alerts = self
            .edr
            .alerts
            .iter()
            .filter(|a| !a.auto_mitigated)
            .count();
        let auto_passed_alerts = self.edr.alerts.iter().filter(|a| a.auto_mitigated).count();
        let total_alerts = self.edr.alerts.len();
        let wildcard_sockets = self
            .edr
            .active_sockets
            .iter()
            .filter(|s| s.is_wildcard_exposed || s.is_c2_suspicious)
            .count();

        let daemon_installed = self.edr.daemon_agent_installed;
        let auto_defense_on = self.edr.active_defense_enabled;
        let local_9006_online = self.edr.local_9006.online;
        let auto_analyzed_cnt = self.edr.auto_analyzed_count.max(self.edr.llm_verdict_cache.len());
        let auto_decided_cnt = self.edr.auto_decided_count.max(auto_passed_alerts);

        div()
            .id("edr-root-workbench")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(|this, ev, _, cx| {
                this.handle_config_key_down(ev, cx);
            }))
            .flex()
            .flex_col()
            .size_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_hidden()
            .bg(rgb(BG_CANVAS))
            .text_color(rgb(TEXT_PRIMARY))
            .text_size(px(12.5))
            // ==================== 1. 商业级单行顶栏 + 可按需展开安全概览抽屉 ====================
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .flex_shrink_0()
                    .bg(rgb(BG_PANEL))
                    .border_b_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .min_w(px(0.0))
                            .px_3()
                            .py(px(6.0))
                            .gap_2()
                            // 左侧：品牌名 + 商业精简导航标签页
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_shrink_0()
                                            .gap_1p5()
                                            .pr_1()
                                            .child(Self::status_dot(if self.scan_in_flight {
                                                DOT_AMBER
                                            } else if unresolved_alerts > 0 {
                                                DOT_RED
                                            } else {
                                                DOT_GREEN
                                            }))
                                            .child(
                                                div()
                                                    .text_size(px(13.0))
                                                    .text_color(rgb(TEXT_BRIGHT))
                                                    .child("VNB 终端安全"),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_wrap()
                                            .gap_1()
                                            .children(
                                                [
                                                    (
                                                        EdrWorkbenchTab::AlertsCenter,
                                                        format!("风险告警 ({})", unresolved_alerts),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::AdBlockCleanupView,
                                                        format!(
                                                            "弹窗拦截 ({})",
                                                            self.edr
                                                                .desktop_windows
                                                                .iter()
                                                                .filter(|w| w.is_ad_popup_candidate)
                                                                .count()
                                                                + self.edr.ad_blocker.pending_cleanup_count()
                                                                + self.edr.ad_blocker.ad_connections.len()
                                                        ),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::FirewallIpsView,
                                                        format!(
                                                            "防火墙 ({})",
                                                            self.edr.firewall_ips.active_rules_count()
                                                        ),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::ThreatIntelView,
                                                        format!(
                                                            "威胁调查 ({})",
                                                            self.edr.threat_intel.reports.len()
                                                        ),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::ProcessLineageView,
                                                        format!("运行进程 ({})", self.edr.live_processes.len()),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::PersistenceGuardView,
                                                        format!("启动项 ({})", self.edr.persistence_entries.len()),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::NetworkC2View,
                                                        format!("网络连接 ({})", self.edr.active_sockets.len()),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::FimAndVaultView,
                                                        format!("敏感文件 ({})", self.edr.fim_records.len()),
                                                    ),
                                                    (
                                                        EdrWorkbenchTab::HistoryLogView,
                                                        format!("安全日志 ({})", self.edr.history_records.len()),
                                                    ),
                                                    (EdrWorkbenchTab::ModelConfigView, "设置".to_string()),
                                                ]
                                                .into_iter()
                                                .enumerate()
                                                .map(|(idx, (tab, label))| {
                                                    let is_active = self.active_tab == tab;
                                                    div()
                                                        .id(SharedString::from(format!("nav-tab-{}", idx)))
                                                        .px_2()
                                                        .py(px(3.5))
                                                        .rounded_sm()
                                                        .cursor_pointer()
                                                        .bg(if is_active {
                                                            rgb(BTN_INFO_BG)
                                                        } else {
                                                            rgb(BG_CARD)
                                                        })
                                                        .border_1()
                                                        .border_color(if is_active {
                                                            rgb(BTN_PRIMARY_BORDER)
                                                        } else {
                                                            rgb(BORDER_SUBTLE)
                                                        })
                                                        .text_size(px(11.0))
                                                        .text_color(if is_active {
                                                            rgb(TEXT_BRIGHT)
                                                        } else {
                                                            rgb(TEXT_SECONDARY)
                                                        })
                                                        .child(label)
                                                        .on_click(cx.listener(move |this, _, _, cx| {
                                                            this.active_tab = tab;
                                                            cx.notify();
                                                        }))
                                                }),
                                            ),
                                    ),
                            )
                            // 右侧：防护状态胶囊 + 核心控制与显眼「立即巡检」CTA
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap_1()
                                    .child(
                                        div()
                                            .id("btn-topbar-drawer-toggle")
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .gap_1p5()
                                            .px_2()
                                            .py(px(3.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if self.show_topbar_drawer {
                                                rgb(BTN_INFO_BG)
                                            } else {
                                                rgb(BG_CARD)
                                            })
                                            .border_1()
                                            .border_color(if self.show_topbar_drawer {
                                                rgb(BTN_PRIMARY_BORDER)
                                            } else {
                                                rgb(BORDER_SUBTLE)
                                            })
                                            .child(Self::status_dot(if self.scan_in_flight {
                                                DOT_AMBER
                                            } else if unresolved_alerts > 0 {
                                                DOT_AMBER
                                            } else {
                                                DOT_GREEN
                                            }))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(format!(
                                                        "{} {}",
                                                        if self.scan_in_flight {
                                                            "正在巡检"
                                                        } else if unresolved_alerts > 0 {
                                                            "发现风险"
                                                        } else {
                                                            "防护概览"
                                                        },
                                                        if self.show_topbar_drawer { "▾" } else { "▸" }
                                                    )),
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.show_topbar_drawer = !this.show_topbar_drawer;
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-auto-decision-toggle")
                                            .px_2()
                                            .py(px(3.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if auto_defense_on {
                                                rgb(BTN_TRUST_BG)
                                            } else {
                                                rgb(BG_BTN)
                                            })
                                            .border_1()
                                            .border_color(if auto_defense_on {
                                                rgb(BTN_TRUST_BORDER)
                                            } else {
                                                rgb(BORDER_SUBTLE)
                                            })
                                            .text_size(px(11.0))
                                            .text_color(if auto_defense_on {
                                                rgb(BTN_TRUST_TEXT)
                                            } else {
                                                rgb(TEXT_SECONDARY)
                                            })
                                            .child(if auto_defense_on {
                                                "主动防御:开"
                                            } else {
                                                "主动防御:关"
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.active_defense_enabled =
                                                    !this.edr.active_defense_enabled;
                                                if this.edr.active_defense_enabled {
                                                    this.edr.auto_execute_security_decisions();
                                                }
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-daemon-toggle")
                                            .px_2()
                                            .py(px(3.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if daemon_installed {
                                                rgb(BG_BTN_ACTIVE)
                                            } else {
                                                rgb(BG_BTN)
                                            })
                                            .border_1()
                                            .border_color(if daemon_installed {
                                                rgb(BORDER_SELECTED)
                                            } else {
                                                rgb(BORDER_SUBTLE)
                                            })
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(if daemon_installed {
                                                "后台守护:开"
                                            } else {
                                                "后台守护:关"
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.toggle_edr_launch_agent_daemon();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-refresh-scan")
                                            .px_2p5()
                                            .py(px(3.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if self.scan_in_flight {
                                                rgb(BTN_WARN_BG)
                                            } else {
                                                rgb(BTN_PRIMARY_BG)
                                            })
                                            .border_1()
                                            .border_color(if self.scan_in_flight {
                                                rgb(BTN_WARN_BORDER)
                                            } else {
                                                rgb(BTN_PRIMARY_BORDER)
                                            })
                                            .text_size(px(11.0))
                                            .text_color(if self.scan_in_flight {
                                                rgb(BTN_WARN_TEXT)
                                            } else {
                                                rgb(TEXT_BRIGHT)
                                            })
                                            .child(if self.scan_in_flight {
                                                "巡检中..."
                                            } else {
                                                "立即巡检"
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.spawn_telemetry_scan_task(true, cx);
                                            })),
                                    ),
                            ),
                    )
                    // 顶栏二次展开抽屉：简洁运维概览 + 一键加固暴露
                    .children(self.show_topbar_drawer.then(|| {
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .min_w(px(0.0))
                            .px_3()
                            .py(px(5.0))
                            .bg(rgb(BG_HEADER_ROW))
                            .border_t_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child(format!(
                                        "安全概览：进程 {} · 启动项 {} · 网络 {} (暴露 {}) · 智能研判 {} · 已处置 {} · 协同引擎：{}",
                                        self.edr.live_processes.len(),
                                        self.edr.persistence_entries.len(),
                                        self.edr.active_sockets.len(),
                                        wildcard_sockets,
                                        auto_analyzed_cnt,
                                        auto_decided_cnt,
                                        if local_9006_online { "在线协同" } else { "本地防护" }
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .id("btn-harden-all-vulns")
                                            .px_2p5()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BTN_PRIMARY_BG))
                                            .border_1()
                                            .border_color(rgb(BTN_PRIMARY_BORDER))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_BRIGHT))
                                            .child(if self.harden_in_flight {
                                                "修复加固中..."
                                            } else {
                                                "一键加固暴露"
                                            })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.spawn_harden_vulns_task(cx);
                                            })),
                                    )
                                    .child(
                                        Self::disclosure_chip("btn-topbar-collapse", "收起", true)
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.show_topbar_drawer = false;
                                                cx.notify();
                                            })),
                                    ),
                            )
                    })),
            )
            // ==================== 2. 主体自适应双栏（100% 随窗口缩放弹性伸缩） ====================
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .overflow_hidden()
                    // 左侧：主功能列表区
                    .child(
                        div()
                            .id("edr-left-table-pane")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w(px(0.0))
                            .h_full()
                            .min_h(px(0.0))
                            .p_2()
                            .gap_1p5()
                            .overflow_hidden()
                            .child(match self.active_tab {
                                EdrWorkbenchTab::AlertsCenter => {
                                    self.render_auto_decision_table(total_alerts, cx)
                                }
                                EdrWorkbenchTab::AdBlockCleanupView => {
                                    self.render_ad_block_and_cleanup_view(cx)
                                }
                                EdrWorkbenchTab::FirewallIpsView => {
                                    self.render_firewall_ips_view(cx)
                                }
                                EdrWorkbenchTab::ThreatIntelView => {
                                    self.render_threat_intel_view(cx)
                                }
                                EdrWorkbenchTab::ProcessLineageView => {
                                    self.render_process_table(cx)
                                }
                                EdrWorkbenchTab::PersistenceGuardView => {
                                    self.render_persistence_table(cx)
                                }
                                EdrWorkbenchTab::NetworkC2View => self.render_network_table(cx),
                                EdrWorkbenchTab::FimAndVaultView => self.render_fim_table(cx),
                                EdrWorkbenchTab::HistoryLogView => self.render_history_table(cx),
                                EdrWorkbenchTab::ModelConfigView => {
                                    self.render_model_config_and_collab_view(cx)
                                }
                            }),
                    )
                    // 右侧：安全处置、详细信息与智能研判面板
                    .child(self.render_right_inspector_panel(cx)),
            )
            // ==================== 3. 底部可折叠实时日志条（默认收起，点击按需展开） ====================
            .child(self.render_bottom_live_log_drawer(cx))
    }
}

impl EdrGpuiWorkbench {
    // ========================================================================
    // 1. 自动分析与自动裁决主表（五列全宽自适应，无中间留白）
    // ========================================================================
    fn render_auto_decision_table(
        &self,
        total_alerts: usize,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let pending_count = self
            .edr
            .alerts
            .iter()
            .filter(|a| !a.auto_mitigated)
            .count();
        let auto_done_count = self
            .edr
            .alerts
            .iter()
            .filter(|a| a.auto_mitigated)
            .count();

        let filtered: Vec<(usize, &crate::edr_engine::EdrAlertFinding)> = self
            .edr
            .alerts
            .iter()
            .enumerate()
            .filter(|(_, a)| match self.alert_filter {
                AlertFilterMode::AllDecisions => true,
                AlertFilterMode::PendingManualConfirm => !a.auto_mitigated,
                AlertFilterMode::AutoDecidedOnly => a.auto_mitigated,
            })
            .collect();

        let expanded_key = self.expanded_row_key.clone();

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1p5()
            .overflow_hidden()
            // 顶部：极简标题 + 可二次展开流水线摘要 + 过滤胶囊
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .flex_shrink_0()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .min_w(px(0.0))
                            .px_2()
                            .py_1()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(if self.scan_in_flight && total_alerts == 0 {
                                                "风险告警与安全处置 · 正在扫描系统环境...".to_string()
                                            } else {
                                                format!(
                                                    "风险告警与安全处置 · 待处理 {} 项 · 已处置 {} 项",
                                                    pending_count, auto_done_count
                                                )
                                            }),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-alerts-pipeline-toggle",
                                            "防护说明",
                                            self.show_alerts_pipeline_info,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_alerts_pipeline_info =
                                                !this.show_alerts_pipeline_info;
                                            cx.notify();
                                        })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap_1()
                                    .children(
                                        [
                                            (
                                                AlertFilterMode::AllDecisions,
                                                format!("全部 ({})", total_alerts),
                                            ),
                                            (
                                                AlertFilterMode::PendingManualConfirm,
                                                format!("待处理 ({})", pending_count),
                                            ),
                                            (
                                                AlertFilterMode::AutoDecidedOnly,
                                                format!("已处置 ({})", auto_done_count),
                                            ),
                                        ]
                                        .into_iter()
                                        .enumerate()
                                        .map(|(i, (mode, label))| {
                                            let is_act = self.alert_filter == mode;
                                            div()
                                                .id(SharedString::from(format!("alert-flt-{}", i)))
                                                .px_2()
                                                .py(px(2.5))
                                                .rounded_sm()
                                                .cursor_pointer()
                                                .bg(if is_act {
                                                    rgb(BTN_INFO_BG)
                                                } else {
                                                    rgb(BG_BTN)
                                                })
                                                .border_1()
                                                .border_color(if is_act {
                                                    rgb(BTN_PRIMARY_BORDER)
                                                } else {
                                                    rgb(BORDER_SUBTLE)
                                                })
                                                .text_size(px(11.0))
                                                .text_color(if is_act {
                                                    rgb(TEXT_BRIGHT)
                                                } else {
                                                    rgb(TEXT_SECONDARY)
                                                })
                                                .child(label)
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.alert_filter = mode;
                                                    this.selected_alert_idx = 0;
                                                    cx.notify();
                                                }))
                                        }),
                                    ),
                            ),
                    )
                    .children(self.show_alerts_pipeline_info.then(|| {
                        div()
                            .w_full()
                            .px_2()
                            .py(px(4.5))
                            .border_t_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .bg(rgb(BG_PANEL))
                            .text_size(px(11.0))
                            .text_color(rgb(TEXT_SECONDARY))
                            .child(format!(
                                "实时防护已检测 {} 项事件：已自动放行或拦截 {} 项，{} 项建议核实处理。点击行内「详情 ▸」或右侧「详细信息」可查看完整路径、父进程链与溯源位置。",
                                total_alerts, auto_done_count, pending_count
                            ))
                    })),
            )
            // 商业精简五列表头
            .child(Self::table_header_bar(
                &[
                    ("风险对象", 0.22),
                    ("风险类型与特征", 0.28),
                    ("安全研判建议", 0.30),
                    ("状态", 0.20),
                ],
                "处置操作",
            ))
            // 自适应滚动数据行区域 (`flex_1().min_h(0)`)
            .child(
                div()
                    .id("alerts-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(filtered.into_iter().map(|(idx, alert)| {
                        let is_selected = self.selected_alert_idx == idx;
                        let is_benign_dev = alert
                            .llm_verdict
                            .as_ref()
                            .map(|v| v.is_benign_dev_tool)
                            .unwrap_or(false);
                        let dot_hex = if alert.auto_mitigated {
                            DOT_GREEN
                        } else if is_benign_dev {
                            DOT_AMBER
                        } else {
                            Self::severity_dot_color(alert.severity)
                        };
                        let alert_id = alert.alert_id;
                        let row_key = format!("alert:{}", alert_id);
                        let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                        let row_key_click = row_key.clone();
                        let auto_analysis_text = alert
                            .llm_verdict
                            .as_ref()
                            .map(|v| Self::clean_commercial_text(&v.conclusion))
                            .unwrap_or_else(|| "正在执行智能安全分析...".to_string());
                        let status_text = if alert.auto_mitigated {
                            if alert.mitigation_summary.contains("隔离")
                                || alert.mitigation_summary.contains("终止")
                                || alert.mitigation_summary.contains("清除")
                            {
                                "已隔离处置".to_string()
                            } else {
                                "已信任放行".to_string()
                            }
                        } else if is_benign_dev {
                            "建议人工确认".to_string()
                        } else {
                            match alert.severity {
                                ThreatSeverity::Critical | ThreatSeverity::High => {
                                    "高危 · 待处置".to_string()
                                }
                                _ => "风险 · 待处置".to_string(),
                            }
                        };
                        let verdict_detail = alert
                            .llm_verdict
                            .as_ref()
                            .map(|v| {
                                format!(
                                    "{} | {}",
                                    Self::clean_commercial_text(&v.reason),
                                    Self::clean_commercial_text(&v.advice)
                                )
                            })
                            .unwrap_or_else(|| {
                                Self::clean_commercial_text(&alert.mitigation_summary)
                            });

                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .px_2()
                            .py(px(5.5))
                            .rounded_sm()
                            .bg(if is_selected {
                                rgb(BG_CARD_SELECTED)
                            } else {
                                rgb(BG_CARD)
                            })
                            .border_1()
                            .border_color(if is_selected {
                                rgb(ACCENT_BLUE)
                            } else {
                                rgb(BORDER_SUBTLE)
                            })
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!("row-alert-{}", alert_id)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .cursor_pointer()
                                    .gap_2()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_alert_idx = idx;
                                        cx.notify();
                                    }))
                                    // 列 1 (22%): 「详情 ▸」显眼胶囊 + 状态点 + 进程名 + PID
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w(relative(0.22))
                                            .min_w(px(0.0))
                                            .gap_1p5()
                                            .child(
                                                Self::row_expand_btn(
                                                    format!("exp-alert-{}", alert_id),
                                                    is_exp,
                                                )
                                                .on_click(cx.listener(
                                                    move |this, _, _, cx| {
                                                        this.selected_alert_idx = idx;
                                                        this.toggle_expand_row(
                                                            row_key_click.clone(),
                                                        );
                                                        cx.notify();
                                                    },
                                                )),
                                            )
                                            .child(Self::status_dot(dot_hex))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(12.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "{} ({})",
                                                        alert.process_name, alert.pid
                                                    )),
                                            ),
                                    )
                                    // 列 2 (28%): 风险类型与特征
                                    .child(
                                        div()
                                            .w(relative(0.28))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(Self::clean_commercial_text(&alert.short_summary)),
                                    )
                                    // 列 3 (30%): 安全研判建议
                                    .child(
                                        div()
                                            .w(relative(0.30))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(auto_analysis_text),
                                    )
                                    // 列 4 (20%): 商业清晰状态标签
                                    .child(
                                        div()
                                            .w(relative(0.20))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(if alert.auto_mitigated {
                                                rgb(DOT_GREEN)
                                            } else if is_benign_dev {
                                                rgb(DOT_AMBER)
                                            } else {
                                                rgb(BTN_DANGER_BORDER)
                                            })
                                            .child(status_text),
                                    )
                                    // 列 5 (固定 124px): 显眼红绿语义处置按钮区
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_end()
                                            .w(px(124.0))
                                            .flex_shrink_0()
                                            .gap_1()
                                            .child(if !alert.auto_mitigated {
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "trust-{}",
                                                        alert_id
                                                    )))
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BTN_TRUST_BG))
                                                    .border_1()
                                                    .border_color(rgb(BTN_TRUST_BORDER))
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(BTN_TRUST_TEXT))
                                                    .child("放行")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.execute_alert_remediation(
                                                            alert_id,
                                                            PolicyAction::A0PassAndUntag,
                                                        );
                                                        cx.notify();
                                                    }))
                                            } else {
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "auto-ok-{}",
                                                        alert_id
                                                    )))
                                                    .px_1p5()
                                                    .py(px(2.0))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(DOT_GREEN))
                                                    .child("✓ 已处理")
                                            })
                                            .child(
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "kill-{}",
                                                        alert_id
                                                    )))
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(if alert.auto_mitigated {
                                                        rgb(BG_BTN)
                                                    } else {
                                                        rgb(BTN_DANGER_BG)
                                                    })
                                                    .border_1()
                                                    .border_color(if alert.auto_mitigated {
                                                        rgb(BORDER_SUBTLE)
                                                    } else {
                                                        rgb(BTN_DANGER_BORDER)
                                                    })
                                                    .text_size(px(11.0))
                                                    .text_color(if alert.auto_mitigated {
                                                        rgb(TEXT_SECONDARY)
                                                    } else {
                                                        rgb(TEXT_BRIGHT)
                                                    })
                                                    .child("处置")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.execute_alert_remediation(
                                                            alert_id,
                                                            PolicyAction::A3ProcessIsolate,
                                                        );
                                                        cx.notify();
                                                    })),
                                            ),
                                    ),
                            )
                            .children(is_exp.then(|| {
                                let loc_identity = format!(
                                    "{} | {}",
                                    if alert.ancestry_chain.is_empty() {
                                        format!("PPID={}", alert.ppid)
                                    } else {
                                        alert.ancestry_chain.clone()
                                    },
                                    if alert.user_and_tty.is_empty() {
                                        "-"
                                    } else {
                                        alert.user_and_tty.as_str()
                                    }
                                );
                                let loc_cwd_entry = format!(
                                    "CWD={} | 入口/配置={} | 服务={}",
                                    if alert.cwd.is_empty() { "-" } else { alert.cwd.as_str() },
                                    if alert.entry_script_or_config.is_empty() {
                                        "-"
                                    } else {
                                        alert.entry_script_or_config.as_str()
                                    },
                                    if alert.service_unit.is_empty() {
                                        "-"
                                    } else {
                                        alert.service_unit.as_str()
                                    }
                                );
                                let loc_prov = format!(
                                    "SHA256={} | 来源={}",
                                    if alert.sha256_hex.is_empty() {
                                        "-"
                                    } else {
                                        alert.sha256_hex.as_str()
                                    },
                                    if alert.provenance_hint.is_empty() {
                                        "-"
                                    } else {
                                        alert.provenance_hint.as_str()
                                    }
                                );
                                let loc_extra = [
                                    (!alert.remote_endpoints.is_empty())
                                        .then(|| format!("网络=[{}]", alert.remote_endpoints.join(" | "))),
                                    (!alert.injected_modules.is_empty())
                                        .then(|| format!("注入=[{}]", alert.injected_modules.join(", "))),
                                    (!alert.holder_processes.is_empty())
                                        .then(|| format!("占用=[{}]", alert.holder_processes.join(", "))),
                                    (!alert.window_summary.is_empty())
                                        .then(|| format!("窗口=[{}]", alert.window_summary)),
                                ]
                                .into_iter()
                                .flatten()
                                .collect::<Vec<_>>()
                                .join(" · ");
                                Self::inline_row_drawer(&[
                                    ("谱系 / 身份", &loc_identity),
                                    ("工作目录 / 入口", &loc_cwd_entry),
                                    ("程序路径", &alert.exe_path),
                                    ("指纹与来源", &loc_prov),
                                    (
                                        "网络/模块/句柄",
                                        if loc_extra.is_empty() { "-" } else { &loc_extra },
                                    ),
                                    ("触发特征", &alert.short_summary),
                                    ("推理建议", &verdict_detail),
                                    ("当前状态", &alert.mitigation_summary),
                                ])
                            }))
                    })),
            )
    }

    // ========================================================================
    // 2. 实时进程谱系多列表（已自动预分析，随窗口宽度 100% 随动）
    // ========================================================================
    fn render_process_table(&self, cx: &mut Context<Self>) -> gpui::Div {
        let expanded_key = self.expanded_row_key.clone();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1()
            .overflow_hidden()
            .child(Self::table_header_bar(
                &[
                    ("进程 / PID", 0.18),
                    ("签名 / 父进程", 0.22),
                    ("程序路径", 0.30),
                    ("分析结论", 0.30),
                ],
                "操作",
            ))
            .child(
                div()
                    .id("proc-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(
                        self.edr
                            .live_processes
                            .iter()
                            .take(100)
                            .enumerate()
                            .map(|(idx, p)| {
                                let is_selected = self.selected_proc_idx == idx;
                                let dot_hex = Self::severity_dot_color(p.severity);
                                let pid = p.pid;
                                let row_key = format!("proc:{}:{}", pid, idx);
                                let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                                let row_key_click = row_key.clone();
                                let key = format!("REAL_PROC:{}:{}", p.pid, p.exe_path);
                                let auto_verdict = self
                                    .edr
                                    .llm_verdict_cache
                                    .get(&key)
                                    .map(|v| Self::clean_commercial_text(&v.conclusion))
                                    .unwrap_or_else(|| Self::clean_commercial_text(&p.status_note));
                                let signer_info = format!("{} · 父:{}", p.code_signer, p.parent_comm);

                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(5.0))
                                    .rounded_sm()
                                    .bg(if is_selected {
                                        rgb(BG_CARD_SELECTED)
                                    } else {
                                        rgb(BG_CARD)
                                    })
                                    .border_1()
                                    .border_color(if is_selected {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .gap_1()
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("row-proc-{}", pid)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .cursor_pointer()
                                            .gap_2()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.selected_proc_idx = idx;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .w(relative(0.18))
                                                    .min_w(px(0.0))
                                                    .gap_1()
                                                    .child(
                                                        Self::row_expand_btn(
                                                            format!("exp-proc-{}", idx),
                                                            is_exp,
                                                        )
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.selected_proc_idx = idx;
                                                                this.toggle_expand_row(
                                                                    row_key_click.clone(),
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                    )
                                                    .child(Self::status_dot(dot_hex))
                                                    .child(
                                                        div()
                                                            .flex_1()
                                                            .min_w(px(0.0))
                                                            .truncate()
                                                            .text_size(px(12.0))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child(format!("{} ({})", p.comm, pid)),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.22))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(signer_info.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.30))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(p.exe_path.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.30))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(auto_verdict),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .justify_end()
                                                    .w(px(124.0))
                                                    .flex_shrink_0()
                                                    .gap_1()
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "forensic-proc-{}",
                                                                pid
                                                            )))
                                                            .px_2()
                                                            .py(px(2.5))
                                                            .rounded_sm()
                                                            .cursor_pointer()
                                                            .bg(rgb(BTN_INFO_BG))
                                                            .border_1()
                                                            .border_color(rgb(BTN_PRIMARY_BORDER))
                                                            .text_size(px(11.0))
                                                            .text_color(rgb(BTN_INFO_TEXT))
                                                            .child(if self.forensic_in_flight.is_some() {
                                                                "取证中"
                                                            } else {
                                                                "深度取证"
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.selected_proc_idx = idx;
                                                                    if let Some(pr) = this
                                                                        .edr
                                                                        .live_processes
                                                                        .get(idx)
                                                                        .cloned()
                                                                    {
                                                                        let k = format!(
                                                                            "REAL_PROC:{}:{}",
                                                                            pr.pid, pr.exe_path
                                                                        );
                                                                        this.spawn_forensic_task(
                                                                            k,
                                                                            pr.pid,
                                                                            pr.comm,
                                                                            pr.exe_path,
                                                                            pr.status_note,
                                                                            cx,
                                                                        );
                                                                    } else {
                                                                        this.show_right_evidence_details =
                                                                            true;
                                                                        cx.notify();
                                                                    }
                                                                },
                                                            )),
                                                    ),
                                            ),
                                    )
                                    .children(is_exp.then(|| {
                                        let proc_chain = if p.ancestry_chain.is_empty() {
                                            format!("{} (PPID={})", p.parent_comm, p.ppid)
                                        } else {
                                            p.ancestry_chain.clone()
                                        };
                                        let proc_cwd_entry = format!(
                                            "CWD={} | 入口={} | 用户={} {}",
                                            if p.cwd.is_empty() { "-" } else { p.cwd.as_str() },
                                            if p.entry_script.is_empty() {
                                                "-"
                                            } else {
                                                p.entry_script.as_str()
                                            },
                                            p.username,
                                            p.elapsed_time
                                        );
                                        let proc_hash_mod = format!(
                                            "SHA256={} | 注入模块={}",
                                            if p.binary_sha256.is_empty() {
                                                "-"
                                            } else {
                                                p.binary_sha256.as_str()
                                            },
                                            if p.injected_modules.is_empty() {
                                                "-".to_string()
                                            } else {
                                                p.injected_modules.join(", ")
                                            }
                                        );
                                        Self::inline_row_drawer(&[
                                            ("多跳谱系", &proc_chain),
                                            ("工作目录 / 入口", &proc_cwd_entry),
                                            ("程序路径", &p.exe_path),
                                            ("命令行", &p.cmdline),
                                            ("指纹与注入", &proc_hash_mod),
                                            ("签名与父进程", &signer_info),
                                            ("状态说明", &p.status_note),
                                        ])
                                    }))
                            }),
                    ),
            )
    }

    // ========================================================================
    // 3. 自启动驻留项多列表（已自动预分析，随窗口宽度 100% 随动）
    // ========================================================================
    fn render_persistence_table(&self, cx: &mut Context<Self>) -> gpui::Div {
        let expanded_key = self.expanded_row_key.clone();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1()
            .overflow_hidden()
            .child(Self::table_header_bar(
                &[
                    ("服务标识", 0.24),
                    ("签名 / 类型", 0.20),
                    ("程序路径", 0.30),
                    ("分析结论", 0.26),
                ],
                "操作",
            ))
            .child(
                div()
                    .id("persist-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(
                        self.edr
                            .persistence_entries
                            .iter()
                            .enumerate()
                            .map(|(idx, entry)| {
                                let is_selected = self.selected_persist_idx == idx;
                                let dot_hex = if entry.is_suspicious {
                                    DOT_AMBER
                                } else {
                                    DOT_GREEN
                                };
                                let row_key = format!("persist:{}", idx);
                                let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                                let row_key_click = row_key.clone();
                                let cfg_path = entry.config_path.clone();
                                let key = format!("PERSIST:{}", entry.config_path);
                                let auto_tag = self
                                    .edr
                                    .llm_verdict_cache
                                    .get(&key)
                                    .map(|v| Self::clean_commercial_text(&v.conclusion))
                                    .unwrap_or_else(|| Self::clean_commercial_text(&entry.risk_reason));

                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(5.0))
                                    .rounded_sm()
                                    .bg(if is_selected {
                                        rgb(BG_CARD_SELECTED)
                                    } else {
                                        rgb(BG_CARD)
                                    })
                                    .border_1()
                                    .border_color(if is_selected {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .gap_1()
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("row-pers-{}", idx)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .cursor_pointer()
                                            .gap_2()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.selected_persist_idx = idx;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .w(relative(0.24))
                                                    .min_w(px(0.0))
                                                    .gap_1()
                                                    .child(
                                                        Self::row_expand_btn(
                                                            format!("exp-pers-{}", idx),
                                                            is_exp,
                                                        )
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.selected_persist_idx = idx;
                                                                this.toggle_expand_row(
                                                                    row_key_click.clone(),
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                    )
                                                    .child(Self::status_dot(dot_hex))
                                                    .child(
                                                        div()
                                                            .flex_1()
                                                            .min_w(px(0.0))
                                                            .truncate()
                                                            .text_size(px(12.0))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child(entry.label.clone()),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.20))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(format!(
                                                        "{} · {}",
                                                        entry.code_signer, entry.kind
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.30))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(entry.target_exec.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.26))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(auto_tag),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .justify_end()
                                                    .w(px(124.0))
                                                    .flex_shrink_0()
                                                    .child(
                                                        if !entry.unloaded && entry.kind.contains("Launch")
                                                        {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "unload-btn-{}",
                                                                    idx
                                                                )))
                                                                .px_2()
                                                                .py(px(2.5))
                                                                .rounded_sm()
                                                                .cursor_pointer()
                                                                .bg(rgb(BTN_WARN_BG))
                                                                .border_1()
                                                                .border_color(rgb(BTN_WARN_BORDER))
                                                                .text_size(px(11.0))
                                                                .text_color(rgb(BTN_WARN_TEXT))
                                                                .child("禁用停止")
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        let _ = this
                                                                            .edr
                                                                            .unload_persistence_agent(
                                                                                &cfg_path,
                                                                            );
                                                                        this.edr
                                                                            .sync_decision_to_9006_memory(
                                                                                &cfg_path,
                                                                                "LAUNCHCTL_UNLOAD",
                                                                            );
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                        } else {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "unload-done-{}",
                                                                    idx
                                                                )))
                                                                .text_size(px(11.0))
                                                                .text_color(rgb(TEXT_MUTED))
                                                                .child(if entry.unloaded {
                                                                    "已停止"
                                                                } else {
                                                                    "自动放行"
                                                                })
                                                        },
                                                    ),
                                            ),
                                    )
                                    .children(is_exp.then(|| {
                                        let runtime_info = match entry.active_pid {
                                            Some(pid) => format!(
                                                "运行中 PID={} ({}) | 签名={}",
                                                pid, entry.active_process_name, entry.code_signer
                                            ),
                                            None => format!("未运行 · 签名={}", entry.code_signer),
                                        };
                                        let prov_info = format!(
                                            "属主={} | 来源={} | SHA256={}",
                                            if entry.file_owner.is_empty() {
                                                "-"
                                            } else {
                                                entry.file_owner.as_str()
                                            },
                                            if entry.provenance_hint.is_empty() {
                                                "-"
                                            } else {
                                                entry.provenance_hint.as_str()
                                            },
                                            if entry.target_sha256.is_empty() {
                                                "-"
                                            } else {
                                                entry.target_sha256.as_str()
                                            }
                                        );
                                        Self::inline_row_drawer(&[
                                            ("配置文件", &entry.config_path),
                                            ("指向程序", &entry.target_exec),
                                            ("触发命令", &entry.raw_trigger_line),
                                            ("运行实例", &runtime_info),
                                            ("属主与来源", &prov_info),
                                            ("参数摘要", &entry.args_summary),
                                            ("风险说明", &entry.risk_reason),
                                        ])
                                    }))
                            }),
                    ),
            )
    }

    // ========================================================================
    // 4. 端口暴露与活跃连接多列表（已自动预分析，随窗口宽度 100% 随动）
    // ========================================================================
    fn render_network_table(&self, cx: &mut Context<Self>) -> gpui::Div {
        let expanded_key = self.expanded_row_key.clone();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1()
            .overflow_hidden()
            .child(Self::table_header_bar(
                &[
                    ("进程 / PID", 0.18),
                    ("本地 ➔ 远端", 0.24),
                    ("风险特征", 0.28),
                    ("分析结论", 0.30),
                ],
                "操作",
            ))
            .child(
                div()
                    .id("net-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(
                        self.edr
                            .active_sockets
                            .iter()
                            .take(100)
                            .enumerate()
                            .map(|(idx, s)| {
                                let is_selected = self.selected_sock_idx == idx;
                                let dot_hex = if s.local_port == 6379 && s.is_wildcard_exposed {
                                    DOT_RED
                                } else if s.is_wildcard_exposed || s.is_c2_suspicious {
                                    DOT_AMBER
                                } else {
                                    DOT_GREEN
                                };
                                let pid = s.pid;
                                let row_key = format!("sock:{}", idx);
                                let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                                let row_key_click = row_key.clone();
                                let ep = s.local_endpoint.clone();
                                let pname_for_fix = s.process_name.clone();
                                let path = s.exe_path.clone();
                                let path_for_fix = s.exe_path.clone();
                                let reason_for_fix = s.c2_reason.clone();
                                let key = format!("SOCK:{}:{}", s.pid, s.local_endpoint);
                                let auto_tag = self
                                    .edr
                                    .llm_verdict_cache
                                    .get(&key)
                                    .map(|v| Self::clean_commercial_text(&v.conclusion))
                                    .unwrap_or_else(|| "正常连接".to_string());
                                let ep_pair = format!("{} -> {} ({})", s.local_endpoint, s.remote_endpoint, s.state);

                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(5.0))
                                    .rounded_sm()
                                    .bg(if is_selected {
                                        rgb(BG_CARD_SELECTED)
                                    } else {
                                        rgb(BG_CARD)
                                    })
                                    .border_1()
                                    .border_color(if is_selected {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .gap_1()
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("row-sock-{}", idx)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .cursor_pointer()
                                            .gap_2()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.selected_sock_idx = idx;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .w(relative(0.18))
                                                    .min_w(px(0.0))
                                                    .gap_1()
                                                    .child(
                                                        Self::row_expand_btn(
                                                            format!("exp-sock-{}", idx),
                                                            is_exp,
                                                        )
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.selected_sock_idx = idx;
                                                                this.toggle_expand_row(
                                                                    row_key_click.clone(),
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                    )
                                                    .child(Self::status_dot(dot_hex))
                                                    .child(
                                                        div()
                                                            .flex_1()
                                                            .min_w(px(0.0))
                                                            .truncate()
                                                            .text_size(px(12.0))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child(format!("{} ({})", s.process_name, pid)),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.24))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(format!(
                                                        "{} -> {}",
                                                        s.local_endpoint, s.remote_endpoint
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.28))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(s.c2_reason.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.30))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(auto_tag),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .justify_end()
                                                    .w(px(124.0))
                                                    .flex_shrink_0()
                                                    .gap_1()
                                                    .child(if s.is_wildcard_exposed || s.is_c2_suspicious {
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "fix-sock-{}",
                                                                idx
                                                            )))
                                                            .px_2()
                                                            .py(px(2.5))
                                                            .rounded_sm()
                                                            .cursor_pointer()
                                                            .bg(rgb(BTN_PRIMARY_BG))
                                                            .border_1()
                                                            .border_color(rgb(BTN_PRIMARY_BORDER))
                                                            .text_size(px(11.0))
                                                            .text_color(rgb(TEXT_BRIGHT))
                                                            .child("加固")
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    let _ = this
                                                                        .edr
                                                                        .execute_port_vulnerability_remediation(
                                                                            pid,
                                                                            &pname_for_fix,
                                                                            &path_for_fix,
                                                                            &reason_for_fix,
                                                                        );
                                                                    cx.notify();
                                                                },
                                                            ))
                                                    } else {
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "ok-sock-{}",
                                                                idx
                                                            )))
                                                            .text_size(px(11.0))
                                                            .text_color(rgb(DOT_GREEN))
                                                            .child("✓ 正常")
                                                    })
                                                    .child(if s.is_wildcard_exposed || s.is_c2_suspicious {
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "kill-sock-{}",
                                                                idx
                                                            )))
                                                            .px_2()
                                                            .py(px(2.5))
                                                            .rounded_sm()
                                                            .cursor_pointer()
                                                            .bg(rgb(BTN_DANGER_BG))
                                                            .border_1()
                                                            .border_color(rgb(BTN_DANGER_BORDER))
                                                            .text_size(px(11.0))
                                                            .text_color(rgb(TEXT_BRIGHT))
                                                            .child("阻断")
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    let _ = crate::platform::terminate_process(pid);
                                                                    let _ = this.edr.block_c2_socket(
                                                                        pid, &ep, &path,
                                                                    );
                                                                    this.edr.sync_decision_to_9006_memory(
                                                                        &ep,
                                                                        "KILL_SOCK",
                                                                    );
                                                                    this.spawn_telemetry_scan_task(true, cx);
                                                                },
                                                            ))
                                                    } else {
                                                        div()
                                                            .id(SharedString::from(format!(
                                                                "noop-sock-{}",
                                                                idx
                                                            )))
                                                            .w(px(1.0))
                                                    }),
                                            ),
                                    )
                                    .children(is_exp.then(|| {
                                        let sock_cwd_cfg = format!(
                                            "CWD={} | 配置/脚本={}",
                                            if s.proc_cwd.is_empty() {
                                                "-"
                                            } else {
                                                s.proc_cwd.as_str()
                                            },
                                            if s.config_path_hint.is_empty() {
                                                "-"
                                            } else {
                                                s.config_path_hint.as_str()
                                            }
                                        );
                                        let sock_parent_svc = format!(
                                            "谱系={} | 服务单元={}",
                                            if s.parent_summary.is_empty() {
                                                "-"
                                            } else {
                                                s.parent_summary.as_str()
                                            },
                                            if s.service_unit.is_empty() {
                                                "-"
                                            } else {
                                                s.service_unit.as_str()
                                            }
                                        );
                                        let sock_scope_dom = if s.remote_domain_hint.is_empty() {
                                            s.ip_scope_hint.clone()
                                        } else {
                                            format!("{} · {}", s.ip_scope_hint, s.remote_domain_hint)
                                        };
                                        Self::inline_row_drawer(&[
                                            ("进程路径", &s.exe_path),
                                            ("完整命令", &s.proc_cmdline),
                                            ("工作目录 / 配置", &sock_cwd_cfg),
                                            ("谱系 / 服务", &sock_parent_svc),
                                            ("端点状态", &ep_pair),
                                            ("网段 / 情报", &sock_scope_dom),
                                            ("风险详情", &s.c2_reason),
                                        ])
                                    }))
                            }),
                    ),
            )
    }

    // ========================================================================
    // 4.5 主机防火墙与入侵防御 (Host Firewall & IPS) 多视角控制面板
    // ========================================================================
    fn render_firewall_ips_view(&self, cx: &mut Context<Self>) -> gpui::Div {
        use crate::firewall_ips::{FirewallAction, IpsSeverity};

        let fw = &self.edr.firewall_ips;
        let expanded_key = self.expanded_row_key.clone();
        let ips_prevent = fw.mode.is_prevent();
        let active_rules = fw.active_rules_count();
        let auto_ips_rules = fw.auto_ips_rules_count();
        let events_cnt = fw.ips_events.len();

        let body: gpui::Div = match self.fw_sub_tab {
            FirewallIpsSubTab::Rules => div()
                .flex()
                .flex_col()
                .flex_1()
                .w_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .gap_1()
                .overflow_hidden()
                .child(Self::table_header_bar(
                    &[
                        ("规则 ID / 策略名称", 0.30),
                        ("方向 · 协议", 0.14),
                        ("目标 IP / 端口", 0.24),
                        ("动作 · 命中计数", 0.32),
                    ],
                    "操作",
                ))
                .child(
                    div()
                        .id("fw-rules-scroll")
                        .flex()
                        .flex_col()
                        .flex_1()
                        .w_full()
                        .min_w(px(0.0))
                        .min_h(px(0.0))
                        .gap_1()
                        .overflow_scroll()
                        .children(fw.rules.iter().enumerate().map(|(idx, r)| {
                            let is_selected = self.selected_fw_rule_idx == idx;
                            let dot_hex = if !r.enabled {
                                TEXT_MUTED
                            } else if r.action == FirewallAction::Allow {
                                DOT_GREEN
                            } else if r.auto_generated_by_ips {
                                DOT_RED
                            } else {
                                DOT_AMBER
                            };
                            let row_key = format!("fw-rule:{}", idx);
                            let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                            let row_key_click = row_key.clone();
                            let rid_toggle = r.rule_id.clone();
                            let rid_del = r.rule_id.clone();
                            let target_str = if r.port > 0 {
                                format!("{}:{}", r.remote_ip, r.port)
                            } else {
                                format!("{}:*", r.remote_ip)
                            };
                            let action_str = format!(
                                "{} · 命中 {} 次{}",
                                r.action.label(),
                                r.hit_count,
                                if r.auto_generated_by_ips { " [IPS自动]" } else { "" }
                            );

                            div()
                                .flex()
                                .flex_col()
                                .w_full()
                                .min_w(px(0.0))
                                .px_2()
                                .py(px(5.0))
                                .rounded_sm()
                                .bg(if is_selected {
                                    rgb(BG_CARD_SELECTED)
                                } else {
                                    rgb(BG_CARD)
                                })
                                .border_1()
                                .border_color(if is_selected {
                                    rgb(BORDER_SELECTED)
                                } else {
                                    rgb(BORDER_SUBTLE)
                                })
                                .gap_1()
                                .child(
                                    div()
                                        .id(SharedString::from(format!("row-fw-rule-{}", idx)))
                                        .flex()
                                        .flex_row()
                                        .items_center()
                                        .w_full()
                                        .min_w(px(0.0))
                                        .cursor_pointer()
                                        .gap_2()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.selected_fw_rule_idx = idx;
                                            cx.notify();
                                        }))
                                        .child(
                                            div()
                                                .flex()
                                                .flex_row()
                                                .items_center()
                                                .w(relative(0.30))
                                                .min_w(px(0.0))
                                                .gap_1()
                                                .child(
                                                    Self::row_expand_btn(
                                                        format!("exp-fw-rule-{}", idx),
                                                        is_exp,
                                                    )
                                                    .on_click(cx.listener(
                                                        move |this, _, _, cx| {
                                                            this.selected_fw_rule_idx = idx;
                                                            this.toggle_expand_row(
                                                                row_key_click.clone(),
                                                            );
                                                            cx.notify();
                                                        },
                                                    )),
                                                )
                                                .child(Self::status_dot(dot_hex))
                                                .child(
                                                    div()
                                                        .flex_1()
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(12.0))
                                                        .text_color(rgb(TEXT_PRIMARY))
                                                        .child(format!("{} · {}", r.rule_id, r.name)),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .w(relative(0.14))
                                                .min_w(px(0.0))
                                                .truncate()
                                                .text_size(px(11.0))
                                                .text_color(rgb(TEXT_SECONDARY))
                                                .child(format!(
                                                    "{} · {}",
                                                    r.direction.code(),
                                                    r.protocol.label()
                                                )),
                                        )
                                        .child(
                                            div()
                                                .w(relative(0.24))
                                                .min_w(px(0.0))
                                                .truncate()
                                                .text_size(px(11.5))
                                                .text_color(rgb(TEXT_SECONDARY))
                                                .child(target_str),
                                        )
                                        .child(
                                            div()
                                                .w(relative(0.32))
                                                .min_w(px(0.0))
                                                .truncate()
                                                .text_size(px(11.0))
                                                .text_color(if r.enabled {
                                                    rgb(TEXT_PRIMARY)
                                                } else {
                                                    rgb(TEXT_MUTED)
                                                })
                                                .child(action_str),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .flex_row()
                                                .items_center()
                                                .justify_end()
                                                .w(px(124.0))
                                                .flex_shrink_0()
                                                .gap_1()
                                                .child(
                                                    div()
                                                        .id(SharedString::from(format!(
                                                            "tog-fw-rule-{}",
                                                            idx
                                                        )))
                                                        .px_1p5()
                                                        .py(px(2.0))
                                                        .rounded_sm()
                                                        .cursor_pointer()
                                                        .bg(if r.enabled {
                                                            rgb(BG_BTN_ACTIVE)
                                                        } else {
                                                            rgb(BG_BTN)
                                                        })
                                                        .border_1()
                                                        .border_color(if r.enabled {
                                                            rgb(BORDER_SELECTED)
                                                        } else {
                                                            rgb(BORDER_SUBTLE)
                                                        })
                                                        .text_size(px(10.5))
                                                        .text_color(rgb(TEXT_PRIMARY))
                                                        .child(if r.enabled { "暂停" } else { "启用" })
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                let _ = this
                                                                    .edr
                                                                    .toggle_firewall_rule(
                                                                        &rid_toggle,
                                                                    );
                                                                cx.notify();
                                                            },
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .id(SharedString::from(format!(
                                                            "del-fw-rule-{}",
                                                            idx
                                                        )))
                                                        .px_1p5()
                                                        .py(px(2.0))
                                                        .rounded_sm()
                                                        .cursor_pointer()
                                                        .bg(rgb(BG_BTN))
                                                        .border_1()
                                                        .border_color(rgb(BORDER_SUBTLE))
                                                        .text_size(px(10.5))
                                                        .text_color(rgb(TEXT_SECONDARY))
                                                        .child("删除")
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                let _ = this
                                                                    .edr
                                                                    .remove_firewall_rule(
                                                                        &rid_del,
                                                                    );
                                                                cx.notify();
                                                            },
                                                        )),
                                                ),
                                        ),
                                )
                                .children(is_exp.then(|| {
                                    Self::inline_row_drawer(&[
                                        ("创建时间", &r.created_at),
                                        ("匹配进程", &r.process_name),
                                        ("策略原因", &r.reason),
                                    ])
                                }))
                        })),
                ),
            FirewallIpsSubTab::IpsEvents => div()
                .flex()
                .flex_col()
                .flex_1()
                .w_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .gap_1()
                .overflow_hidden()
                .child(Self::table_header_bar(
                    &[
                        ("事件 ID / 签名特征", 0.28),
                        ("进程 · 远端目标", 0.24),
                        ("T5B8 状态字 · 残差", 0.20),
                        ("IPS 处置结论", 0.28),
                    ],
                    "操作",
                ))
                .child(
                    div()
                        .id("ips-events-scroll")
                        .flex()
                        .flex_col()
                        .flex_1()
                        .w_full()
                        .min_w(px(0.0))
                        .min_h(px(0.0))
                        .gap_1()
                        .overflow_scroll()
                        .children(if fw.ips_events.is_empty() {
                            vec![div()
                                .p_4()
                                .rounded_sm()
                                .bg(rgb(BG_CARD))
                                .border_1()
                                .border_color(rgb(BORDER_SUBTLE))
                                .text_size(px(12.0))
                                .text_color(rgb(TEXT_SECONDARY))
                                .child("暂无 IPS 入侵拦截事件：宿主网络干净，可点击上方“攻防演练”验证实时包检测与自动封堵联动。")
                                .into_any_element()]
                        } else {
                            fw.ips_events
                                .iter()
                                .enumerate()
                                .map(|(idx, ev)| {
                                    let is_selected = self.selected_ips_event_idx == idx;
                                    let dot_hex = match ev.severity {
                                        IpsSeverity::Critical | IpsSeverity::High => DOT_RED,
                                        IpsSeverity::Medium => DOT_AMBER,
                                        IpsSeverity::Low => DOT_GREEN,
                                    };
                                    let row_key = format!("ips-ev:{}", idx);
                                    let is_exp =
                                        expanded_key.as_deref() == Some(row_key.as_str());
                                    let row_key_click = row_key.clone();
                                    let unblock_ip = ev.remote_ip.clone();
                                    let can_unblock =
                                        ev.auto_blocked && ev.remote_ip != "*" && !ev.remote_ip.is_empty();

                                    div()
                                        .flex()
                                        .flex_col()
                                        .w_full()
                                        .min_w(px(0.0))
                                        .px_2()
                                        .py(px(5.0))
                                        .rounded_sm()
                                        .bg(if is_selected {
                                            rgb(BG_CARD_SELECTED)
                                        } else {
                                            rgb(BG_CARD)
                                        })
                                        .border_1()
                                        .border_color(if is_selected {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        })
                                        .gap_1()
                                        .child(
                                            div()
                                                .id(SharedString::from(format!(
                                                    "row-ips-ev-{}",
                                                    idx
                                                )))
                                                .flex()
                                                .flex_row()
                                                .items_center()
                                                .w_full()
                                                .min_w(px(0.0))
                                                .cursor_pointer()
                                                .gap_2()
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.selected_ips_event_idx = idx;
                                                    cx.notify();
                                                }))
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_row()
                                                        .items_center()
                                                        .w(relative(0.28))
                                                        .min_w(px(0.0))
                                                        .gap_1()
                                                        .child(
                                                            Self::row_expand_btn(
                                                                format!("exp-ips-ev-{}", idx),
                                                                is_exp,
                                                            )
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.selected_ips_event_idx =
                                                                        idx;
                                                                    this.toggle_expand_row(
                                                                        row_key_click.clone(),
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                        )
                                                        .child(Self::status_dot(dot_hex))
                                                        .child(
                                                            div()
                                                                .flex_1()
                                                                .min_w(px(0.0))
                                                                .truncate()
                                                                .text_size(px(12.0))
                                                                .text_color(rgb(TEXT_PRIMARY))
                                                                .child(format!(
                                                                    "[{}] {}",
                                                                    ev.severity.label(),
                                                                    ev.signature_name
                                                                )),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.24))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.5))
                                                        .text_color(rgb(TEXT_SECONDARY))
                                                        .child(format!(
                                                            "{} -> {}",
                                                            ev.process_name, ev.dst_or_remote
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.20))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.0))
                                                        .text_color(rgb(TEXT_MUTED))
                                                        .child(format!(
                                                            "{} · T5={} (Δ={:.2})",
                                                            ev.t5b8_hex,
                                                            ev.t5_regime,
                                                            ev.t5b8_recon_error
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.28))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.0))
                                                        .text_color(rgb(TEXT_PRIMARY))
                                                        .child(if ev.auto_blocked {
                                                            format!(
                                                                "已阻断 ({})",
                                                                ev.linked_rule_id
                                                                    .as_deref()
                                                                    .unwrap_or("FW")
                                                            )
                                                        } else {
                                                            "仅审计告警".to_string()
                                                        }),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_row()
                                                        .items_center()
                                                        .justify_end()
                                                        .w(px(124.0))
                                                        .flex_shrink_0()
                                                        .child(if can_unblock {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "unblock-ips-{}",
                                                                    idx
                                                                )))
                                                                .px_2()
                                                                .py(px(2.0))
                                                                .rounded_sm()
                                                                .cursor_pointer()
                                                                .bg(rgb(BG_BTN))
                                                                .border_1()
                                                                .border_color(rgb(BORDER_SUBTLE))
                                                                .text_size(px(10.5))
                                                                .text_color(rgb(TEXT_PRIMARY))
                                                                .child("加白解封")
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        let _ = this
                                                                            .edr
                                                                            .allowlist_firewall_ip(
                                                                                &unblock_ip,
                                                                            );
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                        } else {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "ips-ok-{}",
                                                                    idx
                                                                )))
                                                                .text_size(px(11.0))
                                                                .text_color(rgb(TEXT_MUTED))
                                                                .child(ev.timestamp.clone())
                                                        }),
                                                ),
                                        )
                                        .children(is_exp.then(|| {
                                            Self::inline_row_drawer(&[
                                                ("载荷样本", &ev.payload_preview),
                                                ("处置说明", &ev.remediation_note),
                                                ("类别/签名", &format!("{} ({})", ev.category.label(), ev.signature_id)),
                                            ])
                                        }))
                                        .into_any_element()
                                })
                                .collect()
                        }),
                ),
            FirewallIpsSubTab::PayloadDrills => {
                let drills = [
                    (
                        "revshell",
                        "演练 1：反弹 Shell 隧道 (/dev/tcp/198.51.100.44:4444)",
                        "验证 IPS-SIG-1001 识别与自动下发 FW-IPS 阻断规则",
                    ),
                    (
                        "shellcode",
                        "演练 2：NOP Sled + x86_64 Syscall 内存注入包",
                        "验证 T5B8 + IPS-SIG-1002 识别二进制 Shellcode 并封堵外联 IP",
                    ),
                    (
                        "redis_rce",
                        "演练 3：Redis 未授权 RCE 写入 Crontab 载荷",
                        "验证 IPS-SIG-1003 拦截高危 6379 服务远程命令执行",
                    ),
                    (
                        "sqli_jndi",
                        "演练 4：Log4j JNDI + SQLi 复合注入请求",
                        "验证 HTTP 漏洞利用载荷识别与策略自动联动",
                    ),
                    (
                        "benign",
                        "演练 5：正常 127.0.0.1:9006 JSON API 请求（防误杀回归）",
                        "验证信任放行规则 FW-ALLOW-LOCAL-9006 零误拦",
                    ),
                ];
                let quick_ports: [(u16, &str); 4] = [
                    (6379, "封堵 Redis 6379"),
                    (445, "封堵 SMB 445"),
                    (3389, "封堵 RDP 3389"),
                    (1337, "封堵 C2 1337"),
                ];
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .overflow_hidden()
                    .child(
                        div()
                            .id("fw-drills-scroll")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .w_full()
                            .min_w(px(0.0))
                            .min_h(px(0.0))
                            .gap_2()
                            .overflow_scroll()
                    .child(
                        div()
                            .p_2()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .flex()
                            .flex_col()
                            .gap_1p5()
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("IPS + T5B8 载荷检测离线安全演练（不对外发包，即时生成规则并可回滚）"),
                            )
                            .children(drills.into_iter().enumerate().map(|(i, (kind, title, desc))| {
                                let k = kind.to_string();
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .gap_2()
                                    .p_1p5()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(title),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(desc),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("btn-ips-drill-{}", i)))
                                            .px_2p5()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(BORDER_SELECTED))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("执行探测")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let _ = this.edr.run_ips_drill_probe(&k);
                                                this.selected_ips_event_idx = 0;
                                                cx.notify();
                                            })),
                                    )
                            })),
                    )
                    .child(
                        div()
                            .p_2()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("快捷端口防火墙规则追加"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .flex_wrap()
                                    .gap_1p5()
                                    .children(quick_ports.into_iter().enumerate().map(|(i, (port, label))| {
                                        div()
                                            .id(SharedString::from(format!("btn-fw-qport-{}", i)))
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(label)
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let _ = this.edr.add_firewall_block_rule(
                                                    &format!("快捷端口封堵 TCP/{}", port),
                                                    crate::firewall_ips::FirewallDirection::Inbound,
                                                    "*",
                                                    port,
                                                    "管理员控制台一键端口屏蔽",
                                                );
                                                cx.notify();
                                            }))
                                    })),
                            ),
                    ),
                )
            }
        };

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1p5()
            .overflow_hidden()
            // 顶部高密控制行：子视图切换 + IPS模式 + 一键端口加固 + OS内核同步 + 内核明细二次展开
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .w_full()
                    .flex_wrap()
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_1()
                            .children(
                                [
                                    (FirewallIpsSubTab::Rules, format!("规则 ({})", active_rules)),
                                    (FirewallIpsSubTab::IpsEvents, format!("IPS拦截 ({})", events_cnt)),
                                    (FirewallIpsSubTab::PayloadDrills, "攻防演练".to_string()),
                                ]
                                .into_iter()
                                .enumerate()
                                .map(|(i, (sub, label))| {
                                    let active = self.fw_sub_tab == sub;
                                    div()
                                        .id(SharedString::from(format!("fw-subtab-{}", i)))
                                        .px_2()
                                        .py(px(3.0))
                                        .rounded_sm()
                                        .cursor_pointer()
                                        .bg(if active { rgb(BG_BTN_ACTIVE) } else { rgb(BG_CARD) })
                                        .border_1()
                                        .border_color(if active {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        })
                                        .text_size(px(11.0))
                                        .text_color(if active {
                                            rgb(TEXT_PRIMARY)
                                        } else {
                                            rgb(TEXT_SECONDARY)
                                        })
                                        .child(label)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.fw_sub_tab = sub;
                                            cx.notify();
                                        }))
                                }),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_1()
                            .child(
                                div()
                                    .id("btn-fw-toggle-ips-mode")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if ips_prevent { rgb(BG_BTN_ACTIVE) } else { rgb(BG_BTN) })
                                    .border_1()
                                    .border_color(if ips_prevent {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(if ips_prevent {
                                        "IPS: 自动阻断"
                                    } else {
                                        "IPS: 仅检测"
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let _ = this.edr.toggle_ips_mode();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("btn-fw-harden-ports")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("封堵高危端口")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let _ = this.edr.harden_firewall_high_risk_ports();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("btn-fw-stage-sync")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("导出规则")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let _ = this.edr.sync_os_firewall_now(false);
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Self::disclosure_chip(
                                    "btn-fw-detail-drawer",
                                    "内核状态",
                                    self.show_fw_detail_drawer,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.show_fw_detail_drawer = !this.show_fw_detail_drawer;
                                    cx.notify();
                                })),
                            ),
                    ),
            )
            // 二次展开：OS 内核防火墙状态、统计与提权同步按钮
            .children(self.show_fw_detail_drawer.then(|| {
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(format!(
                                        "{} | {}",
                                        fw.os_status.backend_name, fw.os_status.stealth_or_profile
                                    )),
                            )
                            .child(
                                div()
                                    .id("btn-fw-kernel-apply")
                                    .px_2()
                                    .py(px(2.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN_ACTIVE))
                                    .border_1()
                                    .border_color(rgb(BORDER_SELECTED))
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("提权应用至 OS 内核")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        let _ = this.edr.sync_os_firewall_now(true);
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(10.5))
                            .text_color(rgb(TEXT_MUTED))
                            .child(format!(
                                "IPS自动规则={} · 已检测包={} · 已阻断={} · 状态: {}",
                                auto_ips_rules,
                                fw.total_packets_inspected,
                                fw.total_packets_blocked,
                                fw.last_sync_message
                            )),
                    )
            }))
            .child(body)
    }

    // ========================================================================
    // 4.8 网络攻击指纹、代码基因调查与多情报库联动面板
    // ========================================================================
    fn render_threat_intel_view(&self, cx: &mut Context<Self>) -> gpui::Div {
        let ti = &self.edr.threat_intel;
        let expanded_key = self.expanded_row_key.clone();
        let enabled_feeds = ti.enabled_feeds_count();
        let reports_cnt = ti.reports.len();

        let body: gpui::Div = match self.intel_sub_tab {
            ThreatIntelSubTab::ReportsAndInvestigate => div()
                .flex()
                .flex_col()
                .flex_1()
                .w_full()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .gap_1p5()
                .overflow_hidden()
                // 调查输入栏与快速采样演练按钮
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .w_full()
                        .p_2()
                        .rounded_sm()
                        .bg(rgb(BG_CARD))
                        .border_1()
                        .border_color(rgb(BORDER_SUBTLE))
                        .gap_1p5()
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .items_center()
                                .gap_1p5()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.0))
                                        .child(self.render_editable_input_row(
                                            "intel-target",
                                            "调查目标 (IP/路径/Hash)",
                                            ConfigEditField::IntelQueryTarget,
                                            &self.intel_query_input,
                                            "输入 IP:Port、文件路径或 SHA-256",
                                            cx,
                                        )),
                                )
                                .child(
                                    div()
                                        .id("btn-run-intel-investigate")
                                        .px_2p5()
                                        .py(px(4.0))
                                        .rounded_sm()
                                        .cursor_pointer()
                                        .bg(rgb(BG_BTN_ACTIVE))
                                        .border_1()
                                        .border_color(rgb(BORDER_SELECTED))
                                        .text_size(px(11.0))
                                        .text_color(rgb(TEXT_PRIMARY))
                                        .child(if self.intel_in_flight.is_some() {
                                            "联查中..."
                                        } else {
                                            "指纹+基因联查"
                                        })
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            let q = this.intel_query_input.clone();
                                            this.spawn_intel_investigation(q, None, cx);
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .flex_wrap()
                                .items_center()
                                .gap_1()
                                .children(
                                    [
                                        ("live", "调查当前可疑外联/进程"),
                                        ("revshell_loader", "演练：反弹Shell+注入基因"),
                                        ("redis_rce_cred", "演练：Redis-RCE+窃密基因"),
                                        ("self_exe_clean", "自检：本程序二进制DNA基线"),
                                    ]
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, (dk, lbl))| {
                                        let k = dk.to_string();
                                        div()
                                            .id(SharedString::from(format!("btn-intel-drill-{}", i)))
                                            .px_2()
                                            .py(px(2.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(lbl)
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.spawn_intel_investigation(
                                                    String::new(),
                                                    Some(k.clone()),
                                                    cx,
                                                );
                                            }))
                                    }),
                                ),
                        )
                        .children(self.intel_in_flight.as_ref().map(|msg| {
                            div()
                                .px_2()
                                .py(px(3.0))
                                .rounded_sm()
                                .bg(rgb(BG_CARD_SELECTED))
                                .border_1()
                                .border_color(rgb(BORDER_SELECTED))
                                .text_size(px(10.5))
                                .text_color(rgb(DOT_AMBER))
                                .child(msg.clone())
                        })),
                )
                .child(Self::table_header_bar(
                    &[
                        ("报告ID / 目标与评判", 0.24),
                        ("网络攻击指纹 (T5B8/协议族)", 0.24),
                        ("代码基因 DNA (SimHash/家族)", 0.28),
                        ("情报联查 (命中/库)", 0.24),
                    ],
                    "联动",
                ))
                .child(
                    div()
                        .id("intel-reports-scroll")
                        .flex()
                        .flex_col()
                        .flex_1()
                        .w_full()
                        .min_w(px(0.0))
                        .min_h(px(0.0))
                        .gap_1()
                        .overflow_scroll()
                        .children(if ti.reports.is_empty() {
                            vec![div()
                                .p_4()
                                .rounded_sm()
                                .bg(rgb(BG_CARD))
                                .border_1()
                                .border_color(rgb(BORDER_SUBTLE))
                                .text_size(px(12.0))
                                .text_color(rgb(TEXT_SECONDARY))
                                .child("尚未生成调查报告：可在上方输入 IP/文件/Hash 并点击“指纹+基因联查”，或运行内置样本探针。")
                                .into_any_element()]
                        } else {
                            ti.reports
                                .iter()
                                .enumerate()
                                .map(|(idx, rep)| {
                                    let is_selected = self.selected_intel_report_idx == idx;
                                    let dot_hex = if rep.fused_threat_score >= 70.0 {
                                        DOT_RED
                                    } else if rep.fused_threat_score >= 45.0 {
                                        DOT_AMBER
                                    } else {
                                        DOT_GREEN
                                    };
                                    let row_key = format!("intel-rep:{}", idx);
                                    let is_exp =
                                        expanded_key.as_deref() == Some(row_key.as_str());
                                    let row_key_click = row_key.clone();
                                    let rid_block = rep.report_id.clone();
                                    let sha_short: String =
                                        rep.code_gene.file_sha256.chars().take(16).collect();
                                    let genes_joined = rep.code_gene.extracted_api_genes.join(" · ");
                                    let feeds_detail = rep
                                        .feed_matches
                                        .iter()
                                        .map(|m| {
                                            format!(
                                                "{}[{} {:.0}%]",
                                                m.feed_name,
                                                m.status,
                                                m.confidence * 100.0
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join(" | ");

                                    div()
                                        .flex()
                                        .flex_col()
                                        .w_full()
                                        .min_w(px(0.0))
                                        .px_2()
                                        .py(px(5.0))
                                        .rounded_sm()
                                        .bg(if is_selected {
                                            rgb(BG_CARD_SELECTED)
                                        } else {
                                            rgb(BG_CARD)
                                        })
                                        .border_1()
                                        .border_color(if is_selected {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        })
                                        .gap_1()
                                        .child(
                                            div()
                                                .id(SharedString::from(format!(
                                                    "row-intel-rep-{}",
                                                    idx
                                                )))
                                                .flex()
                                                .flex_row()
                                                .items_center()
                                                .w_full()
                                                .min_w(px(0.0))
                                                .cursor_pointer()
                                                .gap_2()
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.selected_intel_report_idx = idx;
                                                    cx.notify();
                                                }))
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_row()
                                                        .items_center()
                                                        .w(relative(0.24))
                                                        .min_w(px(0.0))
                                                        .gap_1()
                                                        .child(
                                                            Self::row_expand_btn(
                                                                format!("exp-intel-rep-{}", idx),
                                                                is_exp,
                                                            )
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.selected_intel_report_idx =
                                                                        idx;
                                                                    this.toggle_expand_row(
                                                                        row_key_click.clone(),
                                                                    );
                                                                    cx.notify();
                                                                },
                                                            )),
                                                        )
                                                        .child(Self::status_dot(dot_hex))
                                                        .child(
                                                            div()
                                                                .flex_1()
                                                                .min_w(px(0.0))
                                                                .truncate()
                                                                .text_size(px(12.0))
                                                                .text_color(rgb(TEXT_PRIMARY))
                                                                .child(format!(
                                                                    "{} · {:.0}分 [{}]",
                                                                    rep.query_input,
                                                                    rep.fused_threat_score,
                                                                    rep.verdict_level
                                                                )),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.24))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.0))
                                                        .text_color(rgb(TEXT_SECONDARY))
                                                        .child(format!(
                                                            "{} · {}",
                                                            rep.network_fp.t5b8_hex,
                                                            rep.network_fp.protocol_family
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.28))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.0))
                                                        .text_color(rgb(TEXT_SECONDARY))
                                                        .child(format!(
                                                            "{} · {} ({:.0}%)",
                                                            rep.code_gene.gene_id,
                                                            rep.code_gene.closest_gene_family,
                                                            rep.code_gene.gene_similarity_pct
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .w(relative(0.24))
                                                        .min_w(px(0.0))
                                                        .truncate()
                                                        .text_size(px(11.0))
                                                        .text_color(rgb(TEXT_PRIMARY))
                                                        .child(format!(
                                                            "命中 {}/{} 个情报库",
                                                            rep.feeds_hit_count,
                                                            rep.feeds_queried_count
                                                        )),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_row()
                                                        .items_center()
                                                        .justify_end()
                                                        .w(px(124.0))
                                                        .flex_shrink_0()
                                                        .child(if rep.linked_mitigation_done {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "intel-done-{}",
                                                                    idx
                                                                )))
                                                                .text_size(px(11.0))
                                                                .text_color(rgb(DOT_GREEN))
                                                                .child("已封堵入库")
                                                        } else {
                                                            div()
                                                                .id(SharedString::from(format!(
                                                                    "intel-blk-{}",
                                                                    idx
                                                                )))
                                                                .px_2()
                                                                .py(px(2.0))
                                                                .rounded_sm()
                                                                .cursor_pointer()
                                                                .bg(rgb(BG_BTN_ACTIVE))
                                                                .border_1()
                                                                .border_color(rgb(BORDER_SELECTED))
                                                                .text_size(px(10.5))
                                                                .text_color(rgb(TEXT_PRIMARY))
                                                                .child("封堵入库")
                                                                .on_click(cx.listener(
                                                                    move |this, _, _, cx| {
                                                                        let _ = this
                                                                            .edr
                                                                            .block_from_investigation_report(
                                                                                &rid_block,
                                                                            );
                                                                        cx.notify();
                                                                    },
                                                                ))
                                                        }),
                                                ),
                                        )
                                        .children(is_exp.then(|| {
                                            Self::inline_row_drawer(&[
                                                ("代码基因", &format!("SimHash={} | SHA256={}... | API=[{}]", rep.code_gene.gene_simhash_64, sha_short, genes_joined)),
                                                ("网络指纹", &format!("{} | {}", rep.network_fp.ja3_behavior_tag, rep.network_fp.matched_attack_markers.join(" ; "))),
                                                ("多库联动", &feeds_detail),
                                            ])
                                        }))
                                        .into_any_element()
                                })
                                .collect()
                        }),
                ),
            ThreatIntelSubTab::IntelFeedsConfig => {
                let selected_fid = ti
                    .feeds
                    .get(self.selected_intel_feed_idx)
                    .or_else(|| ti.feeds.first())
                    .map(|f| f.feed_id.clone())
                    .unwrap_or_default();

                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1p5()
                    .overflow_hidden()
                    // 情报接口编辑与新增自定义库卡片
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .p_2()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .gap_1()
                            .child(self.render_editable_input_row(
                                "feed-name",
                                "情报库名称",
                                ConfigEditField::IntelFeedName,
                                &self.intel_feed_name_input,
                                "例如 My-Private-TIP",
                                cx,
                            ))
                            .child(self.render_editable_input_row(
                                "feed-url",
                                "API 接口地址",
                                ConfigEditField::IntelFeedEndpoint,
                                &self.intel_feed_url_input,
                                "https://... 或 http://127.0.0.1:...",
                                cx,
                            ))
                            .child(self.render_editable_input_row(
                                "feed-key",
                                "API Key / 令牌",
                                ConfigEditField::IntelFeedApiKey,
                                &self.intel_feed_key_input,
                                "留空则无认证头或跳过公网调用",
                                cx,
                            ))
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .id("btn-feed-save")
                                            .px_2p5()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(BORDER_SELECTED))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("保存选中情报库")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let url = this.intel_feed_url_input.clone();
                                                let key = this.intel_feed_key_input.clone();
                                                let _ = this.edr.update_intel_feed_config(
                                                    &selected_fid,
                                                    &url,
                                                    &key,
                                                    None,
                                                );
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-feed-add-custom")
                                            .px_2p5()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("新增为自定义情报源")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let name = this.intel_feed_name_input.clone();
                                                let url = this.intel_feed_url_input.clone();
                                                let key = this.intel_feed_key_input.clone();
                                                let _ = this.edr.add_custom_intel_feed(
                                                    &name,
                                                    &url,
                                                    "Authorization",
                                                    &key,
                                                );
                                                this.selected_intel_feed_idx =
                                                    this.edr.threat_intel.feeds.len().saturating_sub(1);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-feed-reset-defaults")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child("恢复默认情报接口")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.reset_default_intel_feeds();
                                                this.selected_intel_feed_idx = 0;
                                                if let Some(f) = this.edr.threat_intel.feeds.first() {
                                                    this.intel_feed_name_input = f.name.clone();
                                                    this.intel_feed_url_input = f.endpoint_url.clone();
                                                    this.intel_feed_key_input = f.api_key.clone();
                                                }
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    )
                    .child(Self::table_header_bar(
                        &[
                            ("情报库名称 / 类型", 0.28),
                            ("接口 URL", 0.34),
                            ("联查统计 / 状态", 0.38),
                        ],
                        "操作",
                    ))
                    .child(
                        div()
                            .id("intel-feeds-scroll")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .w_full()
                            .min_w(px(0.0))
                            .min_h(px(0.0))
                            .gap_1()
                            .overflow_scroll()
                            .children(ti.feeds.iter().enumerate().map(|(idx, f)| {
                                let is_selected = self.selected_intel_feed_idx == idx;
                                let dot_hex = if !f.enabled {
                                    TEXT_MUTED
                                } else if f.total_hits > 0 {
                                    DOT_AMBER
                                } else {
                                    DOT_GREEN
                                };
                                let fid_tog = f.feed_id.clone();
                                let fid_del = f.feed_id.clone();
                                let fname_cp = f.name.clone();
                                let furl_cp = f.endpoint_url.clone();
                                let fkey_cp = f.api_key.clone();

                                div()
                                    .id(SharedString::from(format!("row-feed-{}", idx)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(5.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if is_selected {
                                        rgb(BG_CARD_SELECTED)
                                    } else {
                                        rgb(BG_CARD)
                                    })
                                    .border_1()
                                    .border_color(if is_selected {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .gap_2()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_intel_feed_idx = idx;
                                        this.intel_feed_name_input = fname_cp.clone();
                                        this.intel_feed_url_input = furl_cp.clone();
                                        this.intel_feed_key_input = fkey_cp.clone();
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w(relative(0.28))
                                            .min_w(px(0.0))
                                            .gap_1()
                                            .child(Self::status_dot(dot_hex))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(12.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!("{} [{}]", f.name, f.kind.label())),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.34))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(f.endpoint_url.clone()),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.38))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(if f.enabled {
                                                rgb(TEXT_PRIMARY)
                                            } else {
                                                rgb(TEXT_MUTED)
                                            })
                                            .child(format!(
                                                "权重{:.2} · 查{}次/中{}次 · {}",
                                                f.weight, f.total_queries, f.total_hits, f.last_status
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_end()
                                            .w(px(124.0))
                                            .flex_shrink_0()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "tog-feed-{}",
                                                        idx
                                                    )))
                                                    .px_1p5()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(if f.enabled {
                                                        rgb(BG_BTN_ACTIVE)
                                                    } else {
                                                        rgb(BG_BTN)
                                                    })
                                                    .border_1()
                                                    .border_color(if f.enabled {
                                                        rgb(BORDER_SELECTED)
                                                    } else {
                                                        rgb(BORDER_SUBTLE)
                                                    })
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(if f.enabled { "停用" } else { "启用" })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.toggle_intel_feed(&fid_tog);
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(if f.is_builtin_default {
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "def-feed-{}",
                                                        idx
                                                    )))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child("默认")
                                            } else {
                                                div()
                                                    .id(SharedString::from(format!(
                                                        "del-feed-{}",
                                                        idx
                                                    )))
                                                    .px_1p5()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SUBTLE))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child("删除")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.remove_intel_feed(&fid_del);
                                                        cx.notify();
                                                    }))
                                            }),
                                    )
                            })),
                    )
            }
        };

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1p5()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .w_full()
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap_1()
                            .children(
                                [
                                    (
                                        ThreatIntelSubTab::ReportsAndInvestigate,
                                        format!("指纹与代码基因调查 ({})", reports_cnt),
                                    ),
                                    (
                                        ThreatIntelSubTab::IntelFeedsConfig,
                                        format!("多情报库配置 ({}/{})", enabled_feeds, ti.feeds.len()),
                                    ),
                                ]
                                .into_iter()
                                .enumerate()
                                .map(|(i, (sub, label))| {
                                    let active = self.intel_sub_tab == sub;
                                    div()
                                        .id(SharedString::from(format!("intel-subtab-{}", i)))
                                        .px_2()
                                        .py(px(3.0))
                                        .rounded_sm()
                                        .cursor_pointer()
                                        .bg(if active { rgb(BG_BTN_ACTIVE) } else { rgb(BG_CARD) })
                                        .border_1()
                                        .border_color(if active {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        })
                                        .text_size(px(11.0))
                                        .text_color(if active {
                                            rgb(TEXT_PRIMARY)
                                        } else {
                                            rgb(TEXT_SECONDARY)
                                        })
                                        .child(label)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.intel_sub_tab = sub;
                                            cx.notify();
                                        }))
                                }),
                            ),
                    )
                    .child(
                        Self::disclosure_chip(
                            "btn-intel-detail-drawer",
                            "情报状态",
                            self.show_intel_detail_drawer,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_intel_detail_drawer = !this.show_intel_detail_drawer;
                            cx.notify();
                        })),
                    ),
            )
            .children(self.show_intel_detail_drawer.then(|| {
                div()
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .text_size(px(11.0))
                    .text_color(rgb(TEXT_SECONDARY))
                    .child(format!(
                        "已启用情报源={}/{} · 本地恶意IOC条目={} · 最新状态: {}",
                        enabled_feeds,
                        ti.feeds.len(),
                        ti.custom_malicious_iocs.len(),
                        ti.last_status_message
                    ))
            }))
            .child(body)
    }

    // ========================================================================
    // 5. 敏感凭据与权限多列表（已自动预分析并自动加固，随窗口宽度 100% 随动）
    // ========================================================================
    fn render_fim_table(&self, cx: &mut Context<Self>) -> gpui::Div {
        let expanded_key = self.expanded_row_key.clone();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1()
            .overflow_hidden()
            .child(Self::table_header_bar(
                &[
                    ("凭据", 0.18),
                    ("文件路径", 0.34),
                    ("权限 / 基线", 0.22),
                    ("状态", 0.26),
                ],
                "操作",
            ))
            .child(
                div()
                    .id("fim-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(self.edr.fim_records.iter().enumerate().map(|(idx, f)| {
                        let is_selected = self.selected_fim_idx == idx;
                        let dot_hex = if f.is_alert { DOT_AMBER } else { DOT_GREEN };
                        let row_key = format!("fim:{}", idx);
                        let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                        let row_key_click = row_key.clone();
                        let fpath = f.path.clone();
                        let key = format!("FIM:{}", f.path);
                        let auto_tag = self
                            .edr
                            .llm_verdict_cache
                            .get(&key)
                            .map(|v| v.collaboration_tag.clone())
                            .unwrap_or_else(|| f.status.clone());
                        let baseline_detail = format!(
                            "Unix {} · Hash {} · 香农熵 {:.2}",
                            f.unix_mode_octal, f.current_hash_hex, f.shannon_entropy
                        );

                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .px_2()
                            .py(px(5.0))
                            .rounded_sm()
                            .bg(if is_selected {
                                rgb(BG_CARD_SELECTED)
                            } else {
                                rgb(BG_CARD)
                            })
                            .border_1()
                            .border_color(if is_selected {
                                rgb(BORDER_SELECTED)
                            } else {
                                rgb(BORDER_SUBTLE)
                            })
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!("row-fim-{}", idx)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .cursor_pointer()
                                    .gap_2()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_fim_idx = idx;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w(relative(0.18))
                                            .min_w(px(0.0))
                                            .gap_1()
                                            .child(
                                                Self::row_expand_btn(
                                                    format!("exp-fim-{}", idx),
                                                    is_exp,
                                                )
                                                .on_click(cx.listener(
                                                    move |this, _, _, cx| {
                                                        this.selected_fim_idx = idx;
                                                        this.toggle_expand_row(
                                                            row_key_click.clone(),
                                                        );
                                                        cx.notify();
                                                    },
                                                )),
                                            )
                                            .child(Self::status_dot(dot_hex))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(12.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(
                                                        f.category
                                                            .trim_start_matches("FIM · ")
                                                            .to_string(),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.34))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(f.path.clone()),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.22))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child(format!(
                                                "权限 {} · {}",
                                                f.unix_mode_octal, f.current_hash_hex
                                            )),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.26))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(auto_tag),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_end()
                                            .w(px(124.0))
                                            .flex_shrink_0()
                                            .child(if f.is_alert && !f.quarantined {
                                                div()
                                                    .id(SharedString::from(format!("fix-fim-{}", idx)))
                                                    .px_2()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SUBTLE))
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child("修复权限")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ =
                                                            this.edr.remediate_fim_or_quarantine(&fpath);
                                                        this.edr.sync_decision_to_9006_memory(
                                                            &fpath,
                                                            "CHMOD_0600",
                                                        );
                                                        cx.notify();
                                                    }))
                                            } else {
                                                div()
                                                    .id(SharedString::from(format!("ok-fim-{}", idx)))
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child("基线完好")
                                            }),
                                    ),
                            )
                            .children(is_exp.then(|| {
                                let fim_owner_sha = format!(
                                    "属主={} | SHA256={}",
                                    if f.file_owner.is_empty() {
                                        "-"
                                    } else {
                                        f.file_owner.as_str()
                                    },
                                    if f.sha256_hex.is_empty() {
                                        "-"
                                    } else {
                                        f.sha256_hex.as_str()
                                    }
                                );
                                let fim_holders = if f.holder_processes.is_empty() {
                                    "无活跃占用进程".to_string()
                                } else {
                                    f.holder_processes.join(", ")
                                };
                                Self::inline_row_drawer(&[
                                    ("文件全路径", &f.path),
                                    ("属主与 SHA256", &fim_owner_sha),
                                    ("来源 / 隔离", &f.provenance_hint),
                                    ("占用进程句柄", &fim_holders),
                                    ("基线指标", &baseline_detail),
                                    ("当前结论", &f.status),
                                ])
                            }))
                    })),
            )
    }

    // ========================================================================
    // 6. 持久化历史日志多列表（跨重启 `edr_history.jsonl`，100% 随窗口宽度随动）
    // ========================================================================
    fn render_history_table(&self, cx: &mut Context<Self>) -> gpui::Div {
        let expanded_key = self.expanded_row_key.clone();
        let filtered: Vec<(usize, &crate::edr_engine::EdrHistoryRecord)> = self
            .edr
            .history_records
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                self.history_category_filter
                    .as_ref()
                    .map(|cat| &r.category == cat)
                    .unwrap_or(true)
            })
            .collect();

        let categories = ["大模型会诊", "9006深度取证", "处置动作", "告警发现", "系统巡检"];

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1p5()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .w_full()
                    .min_w(px(0.0))
                    .flex_shrink_0()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_wrap()
                            .gap_1()
                            .child(
                                div()
                                    .id("hist-flt-all")
                                    .px_2()
                                    .py(px(2.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if self.history_category_filter.is_none() {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .text_size(px(11.0))
                                    .text_color(if self.history_category_filter.is_none() {
                                        rgb(TEXT_PRIMARY)
                                    } else {
                                        rgb(TEXT_SECONDARY)
                                    })
                                    .child(format!(
                                        "全部 ({})",
                                        self.edr.history_records.len()
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.history_category_filter = None;
                                        this.selected_history_idx = 0;
                                        cx.notify();
                                    })),
                            )
                            .children(categories.into_iter().enumerate().map(|(i, cat)| {
                                let is_act =
                                    self.history_category_filter.as_deref() == Some(cat);
                                let cnt = self
                                    .edr
                                    .history_records
                                    .iter()
                                    .filter(|r| r.category == cat)
                                    .count();
                                let cat_str = cat.to_string();
                                div()
                                    .id(SharedString::from(format!("hist-flt-{}", i)))
                                    .px_2()
                                    .py(px(2.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if is_act {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .text_size(px(11.0))
                                    .text_color(if is_act {
                                        rgb(TEXT_PRIMARY)
                                    } else {
                                        rgb(TEXT_SECONDARY)
                                    })
                                    .child(format!("{} ({})", cat, cnt))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.history_category_filter = Some(cat_str.clone());
                                        this.selected_history_idx = 0;
                                        cx.notify();
                                    }))
                            })),
                    )
                    .child(
                        div()
                            .id("btn-reload-disk-history")
                            .px_2()
                            .py(px(2.0))
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(BG_BTN))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .text_size(px(11.0))
                            .text_color(rgb(TEXT_SECONDARY))
                            .child("刷新日志")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.edr.load_persisted_history();
                                cx.notify();
                            })),
                    ),
            )
            .child(Self::table_header_bar(
                &[
                    ("时间 / 分类", 0.18),
                    ("对象", 0.18),
                    ("摘要", 0.64),
                ],
                "序号 / PID",
            ))
            .child(
                div()
                    .id("hist-table-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_1()
                    .overflow_scroll()
                    .children(filtered.into_iter().take(180).map(|(idx, rec)| {
                        let is_selected = self.selected_history_idx == idx;
                        let dot_hex = match rec.category.as_str() {
                            "告警发现" => DOT_RED,
                            "大模型会诊" | "9006深度取证" => DOT_AMBER,
                            _ => DOT_GREEN,
                        };
                        let row_key = format!("hist:{}", rec.seq_id);
                        let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                        let row_key_click = row_key.clone();

                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .px_2()
                            .py(px(5.0))
                            .rounded_sm()
                            .bg(if is_selected {
                                rgb(BG_CARD_SELECTED)
                            } else {
                                rgb(BG_CARD)
                            })
                            .border_1()
                            .border_color(if is_selected {
                                rgb(BORDER_SELECTED)
                            } else {
                                rgb(BORDER_SUBTLE)
                            })
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!("row-hist-{}", rec.seq_id)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .cursor_pointer()
                                    .gap_2()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_history_idx = idx;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w(relative(0.18))
                                            .min_w(px(0.0))
                                            .gap_1()
                                            .child(
                                                Self::row_expand_btn(
                                                    format!("exp-hist-{}", rec.seq_id),
                                                    is_exp,
                                                )
                                                .on_click(cx.listener(
                                                    move |this, _, _, cx| {
                                                        this.selected_history_idx = idx;
                                                        this.toggle_expand_row(
                                                            row_key_click.clone(),
                                                        );
                                                        cx.notify();
                                                    },
                                                )),
                                            )
                                            .child(Self::status_dot(dot_hex))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(format!("{} · {}", rec.timestamp, rec.category)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.18))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(12.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(rec.target_name.clone()),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.64))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(rec.summary.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_end()
                                            .w(px(124.0))
                                            .flex_shrink_0()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child(if rec.pid > 0 {
                                                format!("PID {} · #{}", rec.pid, rec.seq_id)
                                            } else {
                                                format!("#{}", rec.seq_id)
                                            }),
                                    ),
                            )
                            .children(is_exp.then(|| {
                                Self::inline_row_drawer(&[
                                    ("目标路径", &rec.target_path),
                                    ("完整摘要", &rec.summary),
                                    ("审计细节", &rec.detail),
                                ])
                            }))
                    })),
            )
    }

    // ========================================================================
    // 7. 决策模型配合 × 推理模型配置工作台（支持直接键盘输入编辑、剪贴板粘贴、超参数步进调节、单独/联合实测与热应用）
    // ========================================================================
    fn render_editable_input_row(
        &self,
        row_id: &str,
        label: &str,
        field: ConfigEditField,
        value: &str,
        placeholder: &str,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let is_focused = self.active_config_field == Some(field);
        let display_txt = if value.is_empty() {
            if is_focused {
                "▏".to_string()
            } else {
                placeholder.to_string()
            }
        } else if is_focused {
            format!("{}▏", value)
        } else {
            value.to_string()
        };

        div()
            .flex()
            .flex_row()
            .items_center()
            .w_full()
            .min_w(px(0.0))
            .gap_1p5()
            .child(
                div()
                    .w(px(140.0))
                    .flex_shrink_0()
                    .text_size(px(11.0))
                    .text_color(rgb(TEXT_MUTED))
                    .child(label.to_string()),
            )
            // 可点击聚焦并直接用键盘输入/退格/Cmd+V 粘贴的输入框
            .child(
                div()
                    .id(SharedString::from(format!("inp-box-{}", row_id)))
                    .flex_1()
                    .min_w(px(0.0))
                    .px_2()
                    .py(px(3.5))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(if is_focused {
                        rgb(BG_CARD_SELECTED)
                    } else {
                        rgb(BG_PANEL)
                    })
                    .border_1()
                    .border_color(if is_focused {
                        rgb(DOT_GREEN)
                    } else {
                        rgb(BORDER_SUBTLE)
                    })
                    .truncate()
                    .text_size(px(11.5))
                    .text_color(if value.is_empty() && !is_focused {
                        rgb(TEXT_MUTED)
                    } else {
                        rgb(TEXT_PRIMARY)
                    })
                    .child(display_txt)
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.active_config_field = Some(field);
                        window.focus(&this.focus_handle);
                        cx.notify();
                    })),
            )
            // 一键从剪贴板粘贴按钮
            .child(
                div()
                    .id(SharedString::from(format!("inp-paste-{}", row_id)))
                    .flex_shrink_0()
                    .px_1p5()
                    .py(px(3.0))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(BG_BTN))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .text_size(px(10.5))
                    .text_color(rgb(TEXT_SECONDARY))
                    .child("粘贴")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.active_config_field = Some(field);
                        window.focus(&this.focus_handle);
                        let clip = Self::read_system_clipboard();
                        if !clip.is_empty() {
                            *this.get_config_field_mut(field) = clip;
                            if field == ConfigEditField::ReasoningModelName {
                                this.edr.preferred_llm_model =
                                    this.edr.model_config.reasoning_model_name.clone();
                            }
                            this.edr.save_model_config();
                        }
                        cx.notify();
                    })),
            )
            // 一键清空重新输入按钮
            .child(
                div()
                    .id(SharedString::from(format!("inp-clear-{}", row_id)))
                    .flex_shrink_0()
                    .px_1p5()
                    .py(px(3.0))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(BG_BTN))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .text_size(px(10.5))
                    .text_color(rgb(TEXT_MUTED))
                    .child("清空")
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.active_config_field = Some(field);
                        window.focus(&this.focus_handle);
                        this.get_config_field_mut(field).clear();
                        this.edr.save_model_config();
                        cx.notify();
                    })),
            )
    }

    fn render_model_config_and_collab_view(&self, cx: &mut Context<Self>) -> gpui::Div {
        let cfg = self.edr.model_config.clone();
        let policy_rev = self.edr.decision_engine.current_revision();
        let (target_pid, target_name, target_path, target_sum) = self
            .edr
            .alerts
            .get(self.selected_alert_idx)
            .or_else(|| self.edr.alerts.first())
            .map(|a| {
                (
                    a.pid,
                    a.process_name.clone(),
                    a.exe_path.clone(),
                    a.short_summary.clone(),
                )
            })
            .unwrap_or_else(|| {
                (
                    std::process::id(),
                    "vnb-security-assistant".to_string(),
                    std::env::current_exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| {
                            crate::platform::app_file("vnb-security-assistant")
                                .to_string_lossy()
                                .into_owned()
                        }),
                    "本机安全控制平面自检".to_string(),
                )
            });

        let t_name1 = target_name.clone();
        let t_path1 = target_path.clone();
        let t_sum1 = target_sum.clone();
        let t_name2 = target_name.clone();
        let t_path2 = target_path.clone();
        let t_sum2 = target_sum.clone();
        let t_name3 = target_name.clone();
        let t_path3 = target_path.clone();
        let t_sum3 = target_sum.clone();

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .overflow_hidden()
            .child(
                div()
                    .id("model-config-scroll-container")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_2()
                    .overflow_scroll()
            // 顶部操作栏：精简标题 + 手册二次展开开关 + 快捷操作按钮
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .flex_shrink_0()
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SELECTED))
                    .gap_1()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .min_w(px(0.0))
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .truncate()
                                            .text_size(px(12.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("模型与协同 · v1.{}", policy_rev)),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-model-manual-top",
                                            "使用手册",
                                            self.show_model_manual_card,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_model_manual_card =
                                                !this.show_model_manual_card;
                                            cx.notify();
                                        })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap_1()
                                    .child(
                                        div()
                                            .id("btn-apply-hyperparams")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(DOT_GREEN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("应用重算")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-test-collab-pipeline")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(BORDER_SELECTED))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(if self.reasoning_in_flight.is_some() {
                                                "验证中..."
                                            } else {
                                                "全链路验证"
                                            })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let job = this.edr.prepare_reasoning_collab_job(
                                                    target_pid,
                                                    &t_name1,
                                                    &t_path1,
                                                    &t_sum1,
                                                );
                                                this.spawn_reasoning_task(
                                                    job,
                                                    format!("正在异步执行 {} 全链路协同验证...", t_name1),
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-open-config-json")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child("配置文件")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.save_model_config();
                                                let p = LocalEdrEngine::model_config_file_path();
                                                crate::platform::open_file_in_editor(&p);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-reload-config-json")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child("重载")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config = LocalEdrEngine::load_model_config();
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-reset-config-default")
                                            .px_2()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .border_1()
                                            .border_color(rgb(BORDER_SUBTLE))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("默认")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config = Default::default();
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .truncate()
                            .text_size(px(10.5))
                            .text_color(rgb(TEXT_SECONDARY))
                            .child(cfg.last_collab_test_summary.clone()),
                    ),
            )
            // ==================== 第一部分：决策模型可编辑配置面板 ====================
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("① 决策模型 · libbittrit 零乘法"),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-toggle-dec-card",
                                            if self.show_model_dec_card { "收起" } else { "展开" },
                                            self.show_model_dec_card,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_model_dec_card = !this.show_model_dec_card;
                                            cx.notify();
                                        })),
                                    ),
                            )
                            .child(
                                div()
                                    .id("btn-test-dec-only")
                                    .px_2()
                                    .py(px(2.5))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN_ACTIVE))
                                    .border_1()
                                    .border_color(rgb(BORDER_SELECTED))
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(if self.reasoning_in_flight.is_some() {
                                        "实测中..."
                                    } else {
                                        "实测决策"
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        let job = this.edr.prepare_test_decision_job(
                                            target_pid,
                                            &t_name2,
                                            &t_path2,
                                            &t_sum2,
                                        );
                                        this.spawn_reasoning_task(
                                            job,
                                            format!("正在异步实测决策模型 [{}]...", t_name2),
                                            cx,
                                        );
                                    })),
                            ),
                    )
                    .children(self.show_model_dec_card.then(|| {
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .gap_1p5()
                    // 1.1 调用模式切换
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .w_full()
                            .gap_1p5()
                            .child(
                                div()
                                    .w(px(140.0))
                                    .flex_shrink_0()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_MUTED))
                                    .child("决策模型调用模式："),
                            )
                            .child(
                                div()
                                    .id("btn-dec-mode-net")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if cfg.decision_mode == DecisionCallMode::Network9006System1 {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .border_1()
                                    .border_color(
                                        if cfg.decision_mode == DecisionCallMode::Network9006System1 {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        },
                                    )
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("网络 9006 (/v1/systemone)")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.edr.model_config.decision_mode =
                                            DecisionCallMode::Network9006System1;
                                        this.edr.save_model_config();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("btn-dec-mode-simple")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if cfg.decision_mode == DecisionCallMode::SimpleLocalSza {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .border_1()
                                    .border_color(
                                        if cfg.decision_mode == DecisionCallMode::SimpleLocalSza {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        },
                                    )
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("本地 7B 离线直调 (S->Z->A)")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.edr.model_config.decision_mode =
                                            DecisionCallMode::SimpleLocalSza;
                                        this.edr.save_model_config();
                                        cx.notify();
                                    })),
                            ),
                    )
                    // 1.2 可编辑输入框：决策模型网络调用 URL
                    .child(self.render_editable_input_row(
                        "dec-ep",
                        "决策网关 URL (可编辑)：",
                        ConfigEditField::DecisionEndpoint,
                        &cfg.decision_endpoint,
                        "输入如 http://127.0.0.1:9006/v1/systemone",
                        cx,
                    ))
                    // 1.3 决策模型 4 大超参数交互步进微调器 (`[-]` / `[+]`)
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_wrap()
                            .w_full()
                            .gap_2()
                            // (a) Softmax 温度
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("Softmax温度:"),
                                    )
                                    .child(
                                        div()
                                            .id("dec-temp-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.decision_temperature =
                                                    (this.edr.model_config.decision_temperature - 0.05)
                                                        .clamp(0.15, 2.00);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{:.2}", cfg.decision_temperature)),
                                    )
                                    .child(
                                        div()
                                            .id("dec-temp-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.decision_temperature =
                                                    (this.edr.model_config.decision_temperature + 0.05)
                                                        .clamp(0.15, 2.00);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (b) Qwen2.5 语义门控增益
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("Qwen2.5语义门控:"),
                                    )
                                    .child(
                                        div()
                                            .id("dec-gate-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.micro_lm_gate_gain =
                                                    (this.edr.model_config.micro_lm_gate_gain - 0.05)
                                                        .clamp(0.05, 1.20);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{:.2}", cfg.micro_lm_gate_gain)),
                                    )
                                    .child(
                                        div()
                                            .id("dec-gate-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.micro_lm_gate_gain =
                                                    (this.edr.model_config.micro_lm_gate_gain + 0.05)
                                                        .clamp(0.05, 1.20);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (c) 高危拦截偏置调节
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("高危拦截偏置:"),
                                    )
                                    .child(
                                        div()
                                            .id("dec-bias-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.z3_threat_bias =
                                                    (this.edr.model_config.z3_threat_bias - 0.10)
                                                        .clamp(-0.80, 0.80);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{:+.2}", cfg.z3_threat_bias)),
                                    )
                                    .child(
                                        div()
                                            .id("dec-bias-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.z3_threat_bias =
                                                    (this.edr.model_config.z3_threat_bias + 0.10)
                                                        .clamp(-0.80, 0.80);
                                                let _ = this.edr.apply_decision_model_hyperparams();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (d) 向推理模型移交阈值
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("移交推理阈值:"),
                                    )
                                    .child(
                                        div()
                                            .id("dec-handoff-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.handoff_risk_threshold =
                                                    (this.edr.model_config.handoff_risk_threshold
                                                        - 0.05)
                                                        .clamp(0.05, 0.95);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{:.2}", cfg.handoff_risk_threshold)),
                                    )
                                    .child(
                                        div()
                                            .id("dec-handoff-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.handoff_risk_threshold =
                                                    (this.edr.model_config.handoff_risk_threshold
                                                        + 0.05)
                                                        .clamp(0.05, 0.95);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (e) 反向蒸馏开关
                            .child(
                                div()
                                    .id("btn-toggle-distill")
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if cfg.distill_feedback_to_decision {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .border_1()
                                    .border_color(if cfg.distill_feedback_to_decision {
                                        rgb(BORDER_SELECTED)
                                    } else {
                                        rgb(BORDER_SUBTLE)
                                    })
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(if cfg.distill_feedback_to_decision {
                                        "反向蒸馏回写: 开启"
                                    } else {
                                        "反向蒸馏回写: 关闭"
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.edr.model_config.distill_feedback_to_decision =
                                            !this.edr.model_config.distill_feedback_to_decision;
                                        this.edr.save_model_config();
                                        cx.notify();
                                    })),
                            ),
                    )
                    // 1.4 决策模型实测输出回显框
                    .child(
                        div()
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_PANEL))
                            .text_size(px(10.5))
                            .text_color(rgb(TEXT_SECONDARY))
                            .child(cfg.last_decision_test_output),
                    )
                    }))
            )
            // ==================== 第二部分：推理模型可编辑配置面板 ====================
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("② 推理模型 · HTTP / CLI"),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-toggle-reas-card",
                                            if self.show_model_reas_card { "收起" } else { "展开" },
                                            self.show_model_reas_card,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_model_reas_card = !this.show_model_reas_card;
                                            cx.notify();
                                        })),
                                    ),
                            )
                            .child(
                                div()
                                    .id("btn-test-reas-only")
                                    .px_2()
                                    .py(px(2.5))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(rgb(BG_BTN_ACTIVE))
                                    .border_1()
                                    .border_color(rgb(BORDER_SELECTED))
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(if self.reasoning_in_flight.is_some() {
                                        "推理中..."
                                    } else {
                                        "实测推理"
                                    })
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        let job = this.edr.prepare_test_reasoning_job(
                                            target_pid,
                                            &t_name3,
                                            &t_path3,
                                            &t_sum3,
                                        );
                                        this.spawn_reasoning_task(
                                            job,
                                            format!("正在异步实测推理模型 [{}]...", t_name3),
                                            cx,
                                        );
                                    })),
                            ),
                    )
                    .children(self.show_model_reas_card.then(|| {
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .gap_1p5()
                    // 2.1 推理调用方式切换 + 快捷模型预设
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_wrap()
                            .w_full()
                            .gap_1p5()
                            .child(
                                div()
                                    .w(px(140.0))
                                    .flex_shrink_0()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_MUTED))
                                    .child("推理调用模式与预设："),
                            )
                            .child(
                                div()
                                    .id("btn-reas-mode-net")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if cfg.reasoning_mode == ReasoningCallMode::NetworkHttpChat {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .border_1()
                                    .border_color(
                                        if cfg.reasoning_mode == ReasoningCallMode::NetworkHttpChat {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        },
                                    )
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("网络调用 (HTTP API)")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.edr.model_config.reasoning_mode =
                                            ReasoningCallMode::NetworkHttpChat;
                                        this.edr.save_model_config();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("btn-reas-mode-simple")
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .cursor_pointer()
                                    .bg(if cfg.reasoning_mode == ReasoningCallMode::SimpleCliGateway {
                                        rgb(BG_BTN_ACTIVE)
                                    } else {
                                        rgb(BG_BTN)
                                    })
                                    .border_1()
                                    .border_color(
                                        if cfg.reasoning_mode == ReasoningCallMode::SimpleCliGateway {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        },
                                    )
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("简易调用 (本地 CLI 网关)")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.edr.model_config.reasoning_mode =
                                            ReasoningCallMode::SimpleCliGateway;
                                        this.edr.save_model_config();
                                        cx.notify();
                                    })),
                            )
                            .children(
                                [
                                    ("qwen3.8-27b", "预设: qwen3.8-27b"),
                                    ("mimo-v2-flash", "预设: mimo-v2-flash (9B)"),
                                    ("qwen2.5-coder-3b", "预设: qwen2.5-3b"),
                                ]
                                .into_iter()
                                .enumerate()
                                .map(|(i, (m_id, m_label))| {
                                    let is_sel = cfg.reasoning_model_name == m_id;
                                    let m_str = m_id.to_string();
                                    div()
                                        .id(SharedString::from(format!("btn-reas-preset-{}", i)))
                                        .px_2()
                                        .py(px(3.0))
                                        .rounded_sm()
                                        .cursor_pointer()
                                        .bg(if is_sel {
                                            rgb(BG_BTN_ACTIVE)
                                        } else {
                                            rgb(BG_BTN)
                                        })
                                        .border_1()
                                        .border_color(if is_sel {
                                            rgb(BORDER_SELECTED)
                                        } else {
                                            rgb(BORDER_SUBTLE)
                                        })
                                        .text_size(px(10.5))
                                        .text_color(rgb(TEXT_SECONDARY))
                                        .child(m_label)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.edr.model_config.reasoning_model_name =
                                                m_str.clone();
                                            this.edr.preferred_llm_model = m_str.clone();
                                            this.edr.save_model_config();
                                            cx.notify();
                                        }))
                                }),
                            ),
                    )
                    // 2.2 5 个可点击键盘直接编辑/粘贴的输入框
                    .child(self.render_editable_input_row(
                        "reas-ep",
                        "推理 API URL (可编辑)：",
                        ConfigEditField::ReasoningEndpoint,
                        &cfg.reasoning_endpoint,
                        "输入如 http://127.0.0.1:9006/v1/chat/completions",
                        cx,
                    ))
                    .child(self.render_editable_input_row(
                        "reas-model",
                        "模型 ID/名称 (可编辑)：",
                        ConfigEditField::ReasoningModelName,
                        &cfg.reasoning_model_name,
                        "输入如 qwen3.8-27b / mimo-v2-flash / gpt-4o",
                        cx,
                    ))
                    .child(self.render_editable_input_row(
                        "reas-key",
                        "API Key / Token (选填)：",
                        ConfigEditField::ReasoningApiKey,
                        &cfg.reasoning_api_key,
                        "本地 9006 免填；外部网关点击此处输入或粘贴 Bearer Key",
                        cx,
                    ))
                    .child(self.render_editable_input_row(
                        "reas-cli",
                        "简易 CLI 命令 (可编辑)：",
                        ConfigEditField::SimpleCliCommand,
                        &cfg.simple_cli_command,
                        "输入本地模型网关或 CLI 可执行路径，如 model-gateway-rs",
                        cx,
                    ))
                    .child(self.render_editable_input_row(
                        "reas-prompt",
                        "系统提示词 (可编辑)：",
                        ConfigEditField::CustomSystemPrompt,
                        &cfg.custom_system_prompt,
                        "输入自定义安全分析 System Prompt",
                        cx,
                    ))
                    // 2.3 推理模型超参数步进调节器 (`[-]` / `[+]`)
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .flex_wrap()
                            .w_full()
                            .gap_2()
                            // (a) 采样温度
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("推理Temperature:"),
                                    )
                                    .child(
                                        div()
                                            .id("reas-temp-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_temperature =
                                                    (this.edr.model_config.reasoning_temperature
                                                        - 0.05)
                                                        .clamp(0.0, 1.0);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{:.2}", cfg.reasoning_temperature)),
                                    )
                                    .child(
                                        div()
                                            .id("reas-temp-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_temperature =
                                                    (this.edr.model_config.reasoning_temperature
                                                        + 0.05)
                                                        .clamp(0.0, 1.0);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (b) MaxTokens
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("MaxTokens:"),
                                    )
                                    .child(
                                        div()
                                            .id("reas-tok-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-32")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_max_tokens = this
                                                    .edr
                                                    .model_config
                                                    .reasoning_max_tokens
                                                    .saturating_sub(32)
                                                    .max(64);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{}", cfg.reasoning_max_tokens)),
                                    )
                                    .child(
                                        div()
                                            .id("reas-tok-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+32")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_max_tokens = (this
                                                    .edr
                                                    .model_config
                                                    .reasoning_max_tokens
                                                    + 32)
                                                    .min(1024);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    ),
                            )
                            // (c) Timeout ms
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .px_2()
                                    .py_1()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child("超时时间:"),
                                    )
                                    .child(
                                        div()
                                            .id("reas-to-minus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("-500ms")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_timeout_ms = this
                                                    .edr
                                                    .model_config
                                                    .reasoning_timeout_ms
                                                    .saturating_sub(500)
                                                    .max(1000);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("{}ms", cfg.reasoning_timeout_ms)),
                                    )
                                    .child(
                                        div()
                                            .id("reas-to-plus")
                                            .px_1p5()
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("+500ms")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_timeout_ms = (this
                                                    .edr
                                                    .model_config
                                                    .reasoning_timeout_ms
                                                    + 500)
                                                    .min(20000);
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    ),
                            ),
                    )
                    // 2.4 推理模型实测输出回显框
                    .child(
                        div()
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_PANEL))
                            .text_size(px(10.5))
                            .text_color(rgb(TEXT_SECONDARY))
                            .child(cfg.last_reasoning_test_output),
                    )
                    }))
            )
            // ==================== 第三部分：默认折叠的操作手册与参数字典 ====================
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.0))
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child("③ 操作说明与参数字典"),
                            )
                            .child(
                                Self::disclosure_chip(
                                    "btn-toggle-manual-card",
                                    if self.show_model_manual_card { "收起说明" } else { "展开详情" },
                                    self.show_model_manual_card,
                                )
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.show_model_manual_card = !this.show_model_manual_card;
                                    cx.notify();
                                })),
                            ),
                    )
                    .children(self.show_model_manual_card.then(|| {
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_PANEL))
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(DOT_GREEN))
                                    .child("【一、交互式输入框与快捷键操作说明】"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("1. 激活编辑：鼠标左键点击任意带「可编辑」标识的输入框，右侧出现高亮边框与闪烁光标 `▋` 即可直接键盘输入字符。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("2. 快捷键与按钮：激活输入框后支持 `Backspace` 逐字删除、`Cmd+V` 粘贴系统剪贴板、或直接点击行尾 `[粘贴剪贴板]` / `[清空]` 按钮；所有改动实时写入 `edr_model_config.json`。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("3. 外部编辑器联动：点击顶部 `[打开配置文件]` 可直接调起系统文本编辑器修改 `edr_model_config.json`，改完后点击 `[重载文件]` 即刻生效。"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_PANEL))
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(BORDER_SELECTED))
                                    .child("【二、决策模型 (Decision Model) 调用方式与超参数说明】"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 网络调用 (HTTP /v1/systemone)：通过可配置的 `决策网关 URL`（默认 `http://127.0.0.1:9006/v1/systemone`）请求毫秒级二进制 SimHash 与 System-1 原子意图初筛（~0.04ms）。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 简易调用 (本地 S->Z->A 进程内直调)：零网络开销，直接在进程内运行 16x16 时序因果状态矩阵 `S_t` + 本地 `Qwen2.5-1.5B SafeTensors` Layer-0 语义门控。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• Softmax 温度 (0.15~2.00)：控制潜空间意图概率 `P(Z|S)` 的锐利度；温度越低裁决越果断，温度越高分布越平滑。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• Qwen2.5 语义门控 (0.05~1.20)：调节本地 1.5B 词嵌入对命令行/路径文本语义的放大权重；调高可增强对伪装路径与无签名工具的敏感度。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 高危拦截偏置 (-0.80~+0.80)：调节 `Z3_MaliciousThreat` 先验偏置；调高 (`+`) 更倾向触发 `A2/A3` 主动拦截，调低 (`-`) 减少开发环境误报。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 移交推理阈值 (0.15~0.95)：当决策模型时序异常分 >= 该阈值（或动作非 A0）时，自动将 `SimHash + P(Z|S)` 移交推理模型深度复核。"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_PANEL))
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(DOT_AMBER))
                                    .child("【三、推理模型 (Reasoning Model) 调用方式与蒸馏闭环说明】"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 网络调用 (HTTP API)：向 `推理 API URL` 发送标准 OpenAI `/v1/chat/completions` 请求；支持本地 9006 集群（免 Key）或任意远程大模型网关（填写 `API Key`）。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 简易调用 (本地 CLI 网关)：无需构造复杂 HTTP 请求，直接通过 `简易 CLI 命令`（默认 `model-gateway-rs`）执行本地命令行快速推演，断网或网关异常时自动降级本地专家引擎。"),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child("• 策略蒸馏回写 (Distillation)：开启「允许推理结论蒸馏回写决策权重」后，推理模型确认良性开发组件时自动加白放行 (`A0`)，确认高危暴露时通过 `ArcSwap` 无锁更新决策权重 (`v1.x`)。"),
                            ),
                    )
                    }))
            ))
    }

    // ========================================================================
    // 7. 广告拦截与广告垃圾清理视图 (`AdBlockCleanupView`)
    // ========================================================================
    fn render_ad_block_and_cleanup_view(&self, cx: &mut Context<Self>) -> gpui::Div {
        let popup_cnt = self
            .edr
            .desktop_windows
            .iter()
            .filter(|w| w.is_ad_popup_candidate)
            .count();
        let cand_cnt = self.edr.ad_blocker.pending_cleanup_count();
        let reclaim_mb =
            (self.edr.ad_blocker.pending_reclaimable_bytes() as f64) / (1024.0 * 1024.0);
        let reclaimed_mb =
            (self.edr.ad_blocker.total_reclaimed_bytes as f64) / (1024.0 * 1024.0);
        let conn_cnt = self.edr.ad_blocker.ad_connections.len();
        let hosts_on = self.edr.ad_blocker.hosts_status.active_in_etc_hosts;
        let auto_pop = self.edr.ad_blocker.auto_intercept_popups;
        let engine_kind_label = "智能广告与弹窗实时拦截引擎";

        let sub_tab = self.ad_sub_tab;
        let last_msg = self.edr.ad_blocker.last_action_message.clone();
        let expanded_key = self.expanded_row_key.clone();

        div()
            .flex()
            .flex_col()
            .flex_1()
            .w_full()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .gap_1p5()
            // 顶部极简标题与操作控制栏 + 可二次展开引擎详情
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(BG_CARD))
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .gap_1p5()
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(12.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(format!(
                                        "广告拦截 · 弹窗 {} · 垃圾 {} ({:.2} MB) · 外联 {}",
                                        popup_cnt, cand_cnt, reclaim_mb, conn_cnt
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap_1()
                                    .child(
                                        div()
                                            .id("btn-ad-auto-pop")
                                            .px_2()
                                            .py(px(2.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if auto_pop { rgb(BG_BTN_ACTIVE) } else { rgb(BG_BTN) })
                                            .border_1()
                                            .border_color(if auto_pop { rgb(BORDER_SELECTED) } else { rgb(BORDER_SUBTLE) })
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(if auto_pop { "自动拦窗:开" } else { "自动拦窗:关" })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.ad_blocker.auto_intercept_popups =
                                                    !this.edr.ad_blocker.auto_intercept_popups;
                                                if this.edr.ad_blocker.auto_intercept_popups {
                                                    let _ = this.edr.intercept_all_ad_popup_windows();
                                                }
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-ad-kill-all-pops")
                                            .px_2()
                                            .py(px(2.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(BORDER_SELECTED))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("清弹窗")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.intercept_all_ad_popup_windows();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-ad-clean-all")
                                            .px_2()
                                            .py(px(2.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .border_1()
                                            .border_color(rgb(BORDER_SELECTED))
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child("清垃圾")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.clean_all_ad_artifacts();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-ad-toggle-hosts")
                                            .px_2()
                                            .py(px(2.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(if hosts_on { rgb(BG_BTN_ACTIVE) } else { rgb(BG_BTN) })
                                            .border_1()
                                            .border_color(if hosts_on { rgb(BORDER_SELECTED) } else { rgb(BORDER_SUBTLE) })
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(if hosts_on { "Hosts盾:开" } else { "开启Hosts盾" })
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.toggle_hosts_ad_shield(true);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-ad-details-toggle",
                                            "引擎详情",
                                            self.show_ad_detail_drawer,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_ad_detail_drawer = !this.show_ad_detail_drawer;
                                            cx.notify();
                                        })),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .w_full()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .gap_1()
                                    .children(
                                        [
                                            (
                                                AdBlockSubTab::DesktopPopups,
                                                format!("桌面弹窗 ({}/{})", popup_cnt, self.edr.desktop_windows.len()),
                                            ),
                                            (
                                                AdBlockSubTab::ArtifactsCleanup,
                                                format!("垃圾清理 ({})", cand_cnt),
                                            ),
                                            (
                                                AdBlockSubTab::DomainShield,
                                                format!(
                                                    "域名与外联 ({}/{})",
                                                    self.edr.ad_blocker.domain_rules.len(),
                                                    conn_cnt
                                                ),
                                            ),
                                        ]
                                        .into_iter()
                                        .enumerate()
                                        .map(|(idx, (t, lbl))| {
                                            let act = sub_tab == t;
                                            div()
                                                .id(SharedString::from(format!("ad-subtab-{}", idx)))
                                                .px_2()
                                                .py(px(2.0))
                                                .rounded_sm()
                                                .cursor_pointer()
                                                .bg(if act { rgb(BG_BTN_ACTIVE) } else { rgb(BG_PANEL) })
                                                .border_1()
                                                .border_color(if act { rgb(BORDER_SELECTED) } else { rgb(BORDER_SUBTLE) })
                                                .text_size(px(10.5))
                                                .text_color(if act { rgb(TEXT_PRIMARY) } else { rgb(TEXT_SECONDARY) })
                                                .child(lbl)
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.ad_sub_tab = t;
                                                    cx.notify();
                                                }))
                                        }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.0))
                                    .truncate()
                                    .text_size(px(10.5))
                                    .text_color(rgb(DOT_GREEN))
                                    .child(format!(
                                        "智能广告防护 · 已释放 {:.2} MB · {}",
                                        reclaimed_mb, last_msg
                                    )),
                            ),
                    )
                    .children(self.show_ad_detail_drawer.then(|| {
                        Self::inline_row_drawer(&[
                            ("引擎类型", engine_kind_label),
                            ("Hosts规则", &self.edr.ad_blocker.hosts_status.rules_file_path),
                            ("拦截状态", &self.edr.ad_blocker.hosts_status.status_message),
                            ("最近回执", &last_msg),
                        ])
                    })),
            )
            // 主列表区
            .child(match sub_tab {
                AdBlockSubTab::DesktopPopups => div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h(px(0.0))
                    .gap_1p5()
                    .child(
                        div()
                            .id("ad-windows-scroll")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .w_full()
                            .min_h(px(0.0))
                            .rounded_sm()
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .bg(rgb(BG_PANEL))
                            .overflow_scroll()
                            .children(self.edr.desktop_windows.iter().enumerate().map(|(idx, w)| {
                                let selected = idx == self.selected_ad_win_idx;
                                let dot = if w.is_ad_popup_candidate { DOT_RED } else { DOT_GREEN };
                                let row_key = format!("adwin:{}", idx);
                                let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                                let row_key_click = row_key.clone();
                                let win_geo = format!(
                                    "{}×{} @ ({},{}) {}",
                                    w.bounds.2,
                                    w.bounds.3,
                                    w.bounds.0,
                                    w.bounds.1,
                                    if w.is_topmost_floating { "置顶" } else { "常规" }
                                );
                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(5.0))
                                    .border_b_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .bg(if selected { rgb(BG_CARD_SELECTED) } else { rgb(BG_PANEL) })
                                    .gap_1()
                                    .child(
                                        div()
                                            .id(SharedString::from(format!("ad-win-row-{}", idx)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .cursor_pointer()
                                            .gap_2()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.selected_ad_win_idx = idx;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .w(relative(0.20))
                                                    .min_w(px(0.0))
                                                    .gap_1()
                                                    .child(
                                                        Self::row_expand_btn(
                                                            format!("exp-adwin-{}", idx),
                                                            is_exp,
                                                        )
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                this.selected_ad_win_idx = idx;
                                                                this.toggle_expand_row(
                                                                    row_key_click.clone(),
                                                                );
                                                                cx.notify();
                                                            },
                                                        )),
                                                    )
                                                    .child(Self::status_dot(dot))
                                                    .child(
                                                        div()
                                                            .flex_1()
                                                            .min_w(px(0.0))
                                                            .truncate()
                                                            .text_size(px(11.5))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child(format!("{} ({})", w.app_name, w.pid)),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.26))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(w.window_title.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.20))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(win_geo.clone()),
                                            )
                                            .child(
                                                div()
                                                    .w(relative(0.24))
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(w.plain_reason.clone()),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_row()
                                                    .items_center()
                                                    .justify_end()
                                                    .w(px(124.0))
                                                    .flex_shrink_0()
                                                    .gap_1()
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!("btn-mute-win-{}", idx)))
                                                            .px_1p5()
                                                            .py(px(2.0))
                                                            .rounded_sm()
                                                            .cursor_pointer()
                                                            .bg(rgb(BG_BTN_ACTIVE))
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child("拦截")
                                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                                let _ = this.edr.intercept_ad_window_by_idx(idx);
                                                                cx.notify();
                                                            })),
                                                    )
                                                    .child(
                                                        div()
                                                            .id(SharedString::from(format!("btn-trust-win-{}", idx)))
                                                            .px_1p5()
                                                            .py(px(2.0))
                                                            .rounded_sm()
                                                            .cursor_pointer()
                                                            .bg(rgb(BG_BTN))
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_SECONDARY))
                                                            .child("信任")
                                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                                let _ = this.edr.trust_ad_window_by_idx(idx);
                                                                cx.notify();
                                                            })),
                                                    ),
                                            ),
                                    )
                                    .children(is_exp.then(|| {
                                        let win_handle = format!(
                                            "WindowID={} · TID={} · {}",
                                            w.window_id, w.thread_id, win_geo
                                        );
                                        Self::inline_row_drawer(&[
                                            ("程序路径", &w.exe_path),
                                            ("窗口标题", &w.window_title),
                                            ("窗口句柄与坐标", &win_handle),
                                            ("研判依据", &w.plain_reason),
                                        ])
                                    }))
                            })),
                    )
                    // 底部最近已拦截弹窗与撤销恢复区
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .max_h(px(145.0))
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(format!(
                                        "已拦截弹窗 ({}) · 可撤销恢复",
                                        self.edr.window_scanner.blocked_history.len()
                                    )),
                            )
                            .child(
                                div()
                                    .id("ad-blocked-hist-scroll")
                                    .flex()
                                    .flex_col()
                                    .flex_1()
                                    .overflow_scroll()
                                    .gap_0p5()
                                    .children(self.edr.window_scanner.blocked_history.iter().take(12).map(|rec| {
                                        let rid = rec.record_id;
                                        div()
                                            .id(SharedString::from(format!("ad-bhist-{}", rid)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_between()
                                            .w_full()
                                            .px_1p5()
                                            .py(px(2.0))
                                            .rounded_sm()
                                            .bg(rgb(BG_PANEL))
                                            .gap_2()
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(format!(
                                                        "[{}] {} · {} ({})",
                                                        rec.time_str, rec.process_info, rec.window_title, rec.model_decision_tag
                                                    )),
                                            )
                                            .child(if !rec.restored_by_user {
                                                div()
                                                    .id(SharedString::from(format!("btn-restore-ad-{}", rid)))
                                                    .px_1p5()
                                                    .py(px(1.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN))
                                                    .text_size(px(10.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child("恢复")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.restore_blocked_ad_window(rid);
                                                        cx.notify();
                                                    }))
                                                    .into_any_element()
                                            } else {
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(rgb(DOT_GREEN))
                                                    .child("已恢复")
                                                    .into_any_element()
                                            })
                                    })),
                            ),
                    )
                    .into_any_element(),
                AdBlockSubTab::ArtifactsCleanup => div()
                    .id("ad-artifacts-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_h(px(0.0))
                    .rounded_sm()
                    .border_1()
                    .border_color(rgb(BORDER_SUBTLE))
                    .bg(rgb(BG_PANEL))
                    .overflow_scroll()
                    .children(self.edr.ad_blocker.cleanup_candidates.iter().enumerate().map(|(idx, c)| {
                        let selected = idx == self.selected_ad_cand_idx;
                        let dot = if c.cleaned { DOT_GREEN } else if c.ad_model_prob >= 0.85 { DOT_RED } else { DOT_AMBER };
                        let row_key = format!("adcand:{}", c.id);
                        let is_exp = expanded_key.as_deref() == Some(row_key.as_str());
                        let row_key_click = row_key.clone();
                        let model_tag = format!(
                            "{} · {:.2} MB · {:.0}%",
                            c.model_label,
                            (c.size_bytes as f64) / (1024.0 * 1024.0),
                            c.ad_model_prob * 100.0
                        );
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .px_2()
                            .py(px(5.0))
                            .border_b_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .bg(if selected { rgb(BG_CARD_SELECTED) } else { rgb(BG_PANEL) })
                            .gap_1()
                            .child(
                                div()
                                    .id(SharedString::from(format!("ad-cand-row-{}", c.id)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .cursor_pointer()
                                    .gap_2()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.selected_ad_cand_idx = idx;
                                        cx.notify();
                                    }))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .w(relative(0.24))
                                            .min_w(px(0.0))
                                            .gap_1()
                                            .child(
                                                Self::row_expand_btn(
                                                    format!("exp-adcand-{}", c.id),
                                                    is_exp,
                                                )
                                                .on_click(cx.listener(
                                                    move |this, _, _, cx| {
                                                        this.selected_ad_cand_idx = idx;
                                                        this.toggle_expand_row(
                                                            row_key_click.clone(),
                                                        );
                                                        cx.notify();
                                                    },
                                                )),
                                            )
                                            .child(Self::status_dot(dot))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!("[{}] {}", c.kind.cn_label(), c.title)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.32))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(c.path.clone()),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.14))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child(format!(
                                                "{:.2} MB · {:.0}%",
                                                (c.size_bytes as f64) / (1024.0 * 1024.0),
                                                c.ad_model_prob * 100.0
                                            )),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.20))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(c.reason.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_end()
                                            .w(px(96.0))
                                            .flex_shrink_0()
                                            .child(if !c.cleaned {
                                                div()
                                                    .id(SharedString::from(format!("btn-clean-cand-{}", c.id)))
                                                    .px_2()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN_ACTIVE))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SELECTED))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child("清理")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.clean_single_ad_artifact(idx);
                                                        cx.notify();
                                                    }))
                                                    .into_any_element()
                                            } else {
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(DOT_GREEN))
                                                    .child("已清理")
                                                    .into_any_element()
                                            }),
                                    ),
                            )
                            .children(is_exp.then(|| {
                                Self::inline_row_drawer(&[
                                    ("目标路径", &c.path),
                                    ("模型判定", &model_tag),
                                    ("清理原因", &c.reason),
                                ])
                            }))
                    }))
                    .into_any_element(),
                AdBlockSubTab::DomainShield => div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h(px(0.0))
                    .gap_1p5()
                    // 活跃广告/追踪网络连接
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .max_h(px(190.0))
                            .p_1p5()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .gap_1()
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .text_color(rgb(TEXT_PRIMARY))
                                    .child(format!(
                                        "追踪外联 ({}) · {}",
                                        conn_cnt,
                                        if hosts_on { "Hosts已生效" } else { "规则待应用" }
                                    )),
                            )
                            .child(
                                div()
                                    .id("ad-conns-scroll")
                                    .flex()
                                    .flex_col()
                                    .flex_1()
                                    .overflow_scroll()
                                    .gap_0p5()
                                    .children(self.edr.ad_blocker.ad_connections.iter().enumerate().map(|(idx, conn)| {
                                        let sel = idx == self.selected_ad_conn_idx;
                                        div()
                                            .id(SharedString::from(format!("ad-conn-{}", idx)))
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_between()
                                            .w_full()
                                            .px_1p5()
                                            .py(px(3.0))
                                            .rounded_sm()
                                            .bg(if sel { rgb(BG_CARD_SELECTED) } else { rgb(BG_PANEL) })
                                            .gap_2()
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.selected_ad_conn_idx = idx;
                                                cx.notify();
                                            }))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(11.0))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "{} (PID={}) -> {} [{} · {:.0}%]",
                                                        conn.process_name,
                                                        conn.pid,
                                                        conn.remote_endpoint,
                                                        conn.reason,
                                                        conn.ad_model_prob * 100.0
                                                    )),
                                            )
                                            .child(if !conn.blocked {
                                                div()
                                                    .id(SharedString::from(format!("btn-blk-adconn-{}", idx)))
                                                    .px_1p5()
                                                    .py(px(1.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN_ACTIVE))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child("阻断")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.block_ad_connection_at(idx);
                                                        cx.notify();
                                                    }))
                                                    .into_any_element()
                                            } else {
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(DOT_GREEN))
                                                    .child("已阻断")
                                                    .into_any_element()
                                            })
                                    })),
                            ),
                    )
                    // 广告域名屏蔽规则库浏览
                    .child(
                        div()
                            .id("ad-rules-scroll")
                            .flex()
                            .flex_col()
                            .flex_1()
                            .w_full()
                            .min_h(px(0.0))
                            .rounded_sm()
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .bg(rgb(BG_PANEL))
                            .overflow_scroll()
                            .children(self.edr.ad_blocker.domain_rules.iter().enumerate().map(|(idx, r)| {
                                div()
                                    .id(SharedString::from(format!("ad-rule-{}", idx)))
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .px_2()
                                    .py(px(4.0))
                                    .border_b_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .gap_2()
                                    .child(Self::status_dot(if hosts_on { DOT_GREEN } else { DOT_AMBER }))
                                    .child(
                                        div()
                                            .w(relative(0.32))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(format!("0.0.0.0  {}", r.domain)),
                                    )
                                    .child(
                                        div()
                                            .w(relative(0.42))
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(11.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child(r.category.clone()),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(10.5))
                                            .text_color(rgb(TEXT_MUTED))
                                            .child(format!(
                                                "AdGuard {:.0}% | {}",
                                                r.model_ad_score * 100.0,
                                                if hosts_on { "Hosts生效" } else { "待应用" }
                                            )),
                                    )
                            })),
                    )
                    .into_any_element(),
            })
    }

    // ========================================================================
    // 右侧四阶自动分析与自动决策面板（38% 比例宽度随动 + 底部日志流自适应填满 100% 剩余高度）
    // ========================================================================
    fn render_right_inspector_panel(
        &self,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let (
            cache_key,
            target_alert_id,
            target_pid,
            proc_name,
            summary_line,
            exe_path,
            cmdline,
            signer,
            auto_decision_badge,
            llm_verdict,
        ): (
            String,
            Option<u64>,
            u32,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<LlmSecurityVerdict>,
        ) = match self.active_tab {
            EdrWorkbenchTab::AdBlockCleanupView => match self.ad_sub_tab {
                AdBlockSubTab::DesktopPopups => {
                    if let Some(w) = self
                        .edr
                        .desktop_windows
                        .get(self.selected_ad_win_idx)
                        .or_else(|| self.edr.desktop_windows.first())
                    {
                        let key = format!("REAL_PROC:{}:{}", w.pid, w.exe_path);
                        let v = self.edr.llm_verdict_cache.get(&key).cloned();
                        let (intent, prob) = w.decision.dominant_intent();
                        let badge = format!(
                            "AdGuard 7B × 决策模型：{} ({:.0}%) -> {}",
                            intent.code(),
                            prob * 100.0,
                            w.decision.chosen_action.cn_name()
                        );
                        (
                            key,
                            None,
                            w.pid,
                            w.app_name.clone(),
                            w.plain_reason.clone(),
                            w.exe_path.clone(),
                            format!(
                                "WindowID=0x{:X} | 坐标: ({},{}) {}×{} | 置顶={}",
                                w.window_id, w.bounds.0, w.bounds.1, w.bounds.2, w.bounds.3, w.is_topmost_floating
                            ),
                            w.window_title.clone(),
                            badge,
                            v,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "暂无弹窗目标".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "桌面清净".to_string(),
                            None,
                        )
                    }
                }
                AdBlockSubTab::ArtifactsCleanup => {
                    if let Some(c) = self
                        .edr
                        .ad_blocker
                        .cleanup_candidates
                        .get(self.selected_ad_cand_idx)
                        .or_else(|| self.edr.ad_blocker.cleanup_candidates.first())
                    {
                        let key = format!("ADCAND:{}", c.path);
                        let badge = format!(
                            "AdGuard 7B [{} {:.0}%] · {}",
                            c.model_label,
                            c.ad_model_prob * 100.0,
                            if c.cleaned { "已清理" } else { "待清理" }
                        );
                        (
                            key,
                            None,
                            0,
                            c.title.clone(),
                            c.reason.clone(),
                            c.path.clone(),
                            format!(
                                "类别: {} | 大小: {:.2} MB",
                                c.kind.cn_label(),
                                (c.size_bytes as f64) / (1024.0 * 1024.0)
                            ),
                            c.model_label.clone(),
                            badge,
                            None,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "暂无广告残留".to_string(),
                            "已扫描全部启动项、/tmp、App AdSDK与浏览器扩展缓存".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "环境纯净".to_string(),
                            None,
                        )
                    }
                }
                AdBlockSubTab::DomainShield => {
                    if let Some(conn) = self
                        .edr
                        .ad_blocker
                        .ad_connections
                        .get(self.selected_ad_conn_idx)
                        .or_else(|| self.edr.ad_blocker.ad_connections.first())
                    {
                        let key = format!("SOCK:{}:{}", conn.pid, conn.remote_endpoint);
                        let badge = if conn.blocked {
                            "已拦截该广告/追踪连接".to_string()
                        } else {
                            format!("发现广告追踪连接 ({:.0}%)", conn.ad_model_prob * 100.0)
                        };
                        (
                            key,
                            None,
                            conn.pid,
                            conn.process_name.clone(),
                            conn.reason.clone(),
                            conn.exe_path.clone(),
                            format!("远端: {} | 命中: {}", conn.remote_endpoint, conn.matched_domain_or_model),
                            "AdShield Network".to_string(),
                            badge,
                            None,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "Hosts 广告拦截盾".to_string(),
                            self.edr.ad_blocker.hosts_status.status_message.clone(),
                            self.edr.ad_blocker.hosts_status.rules_file_path.clone(),
                            format!("已装载 {} 条内置+自定义广告域名规则", self.edr.ad_blocker.domain_rules.len()),
                            "WhiteRabbitNeo-7B AdGuard".to_string(),
                            if self.edr.ad_blocker.hosts_status.active_in_etc_hosts {
                                "Hosts 系统拦截已开启".to_string()
                            } else {
                                "本地规则就绪".to_string()
                            },
                            None,
                        )
                    }
                }
            },
            EdrWorkbenchTab::ThreatIntelView => match self.intel_sub_tab {
                ThreatIntelSubTab::ReportsAndInvestigate => {
                    if let Some(rep) = self
                        .edr
                        .threat_intel
                        .reports
                        .get(self.selected_intel_report_idx)
                        .or_else(|| self.edr.threat_intel.reports.first())
                    {
                        let key = format!("INTEL:{}", rep.report_id);
                        let badge = format!(
                            "[{}] 评分={:.1}/100 · 情报命中 {}/{}",
                            rep.verdict_level,
                            rep.fused_threat_score,
                            rep.feeds_hit_count,
                            rep.feeds_queried_count
                        );
                        (
                            key,
                            None,
                            rep.pid,
                            format!("{} ({})", rep.process_name, rep.network_fp.protocol_family),
                            rep.recommended_actions.join(" | "),
                            if rep.code_gene.file_path.is_empty() {
                                rep.query_input.clone()
                            } else {
                                rep.code_gene.file_path.clone()
                            },
                            format!(
                                "T5B8={} | DNA={} ({} {:.0}%) | API基因={} | 滚动块={:?}",
                                rep.network_fp.t5b8_hex,
                                rep.code_gene.gene_simhash_64,
                                rep.code_gene.closest_gene_family,
                                rep.code_gene.gene_similarity_pct,
                                rep.code_gene.extracted_api_genes.join(", "),
                                rep.code_gene.rolling_gene_blocks
                            ),
                            format!(
                                "SHA256={} · {}",
                                rep.code_gene.file_sha256, rep.network_fp.ja3_behavior_tag
                            ),
                            badge,
                            None,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "暂未发起调查".to_string(),
                            "在左侧输入目标或运行样本演练提取网络指纹+代码基因".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "Threat Intel & Gene Profiler".to_string(),
                            "待分析".to_string(),
                            None,
                        )
                    }
                }
                ThreatIntelSubTab::IntelFeedsConfig => {
                    if let Some(f) = self
                        .edr
                        .threat_intel
                        .feeds
                        .get(self.selected_intel_feed_idx)
                        .or_else(|| self.edr.threat_intel.feeds.first())
                    {
                        (
                            format!("FEED:{}", f.feed_id),
                            None,
                            0,
                            f.name.clone(),
                            f.description.clone(),
                            f.endpoint_url.clone(),
                            format!(
                                "类型={} | 认证头={} | 超时={}ms | 权重={:.2} | 查询={}次/命中={}次",
                                f.kind.label(),
                                if f.auth_header_name.is_empty() { "无" } else { &f.auth_header_name },
                                f.timeout_ms,
                                f.weight,
                                f.total_queries,
                                f.total_hits
                            ),
                            f.last_status.clone(),
                            if f.enabled { "已启用联查".to_string() } else { "未启用".to_string() },
                            None,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "无情报源".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            None,
                        )
                    }
                }
            },
            EdrWorkbenchTab::FirewallIpsView => match self.fw_sub_tab {
                FirewallIpsSubTab::Rules | FirewallIpsSubTab::PayloadDrills => {
                    if let Some(r) = self
                        .edr
                        .firewall_ips
                        .rules
                        .get(self.selected_fw_rule_idx)
                        .or_else(|| self.edr.firewall_ips.rules.first())
                    {
                        let key = format!("FWRULE:{}", r.rule_id);
                        let port_s = if r.port > 0 { r.port.to_string() } else { "*".to_string() };
                        let badge = format!(
                            "{} · {} (命中 {} 次)",
                            r.action.label(),
                            if r.enabled { "已激活" } else { "已暂停" },
                            r.hit_count
                        );
                        (
                            key,
                            None,
                            0,
                            r.name.clone(),
                            r.reason.clone(),
                            format!("{}:{}", r.remote_ip, port_s),
                            format!(
                                "规则ID={} | 方向={} | 协议={} | 进程={} | 创建={}",
                                r.rule_id, r.direction.label(), r.protocol.label(), r.process_name, r.created_at
                            ),
                            if r.auto_generated_by_ips {
                                "IPS 自动联动生成".to_string()
                            } else {
                                "主机防火墙静态策略".to_string()
                            },
                            badge,
                            None,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "暂无防火墙规则".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            None,
                        )
                    }
                }
                FirewallIpsSubTab::IpsEvents => {
                    if let Some(ev) = self
                        .edr
                        .firewall_ips
                        .ips_events
                        .get(self.selected_ips_event_idx)
                        .or_else(|| self.edr.firewall_ips.ips_events.first())
                    {
                        let key = format!("REAL_PROC:{}:{}", ev.pid, ev.process_name);
                        let v = self.edr.llm_verdict_cache.get(&key).cloned();
                        let badge = format!(
                            "[{}] {} · {}",
                            ev.severity.label(),
                            ev.signature_id,
                            if ev.auto_blocked { "已自动阻断" } else { "仅检测记录" }
                        );
                        (
                            key,
                            None,
                            ev.pid,
                            format!("{} ({})", ev.process_name, ev.category.label()),
                            ev.remediation_note.clone(),
                            ev.dst_or_remote.clone(),
                            format!(
                                "源: {} -> 目标: {} | T5B8={} (T5={}, Δ={:.2}) | 载荷: {}",
                                ev.src_or_local, ev.dst_or_remote, ev.t5b8_hex, ev.t5_regime, ev.t5b8_recon_error, ev.payload_preview
                            ),
                            ev.signature_name.clone(),
                            badge,
                            v,
                        )
                    } else {
                        (
                            String::new(),
                            None,
                            0,
                            "暂无 IPS 拦截事件".to_string(),
                            "可切换至“攻防演练”触发探测测试".to_string(),
                            "-".to_string(),
                            "-".to_string(),
                            "IPS Engine".to_string(),
                            "网络运行正常".to_string(),
                            None,
                        )
                    }
                }
            },
            EdrWorkbenchTab::ProcessLineageView => {
                if let Some(p) = self
                    .edr
                    .live_processes
                    .get(self.selected_proc_idx)
                    .or_else(|| self.edr.live_processes.first())
                {
                    let key = format!("REAL_PROC:{}:{}", p.pid, p.exe_path);
                    let v = self.edr.llm_verdict_cache.get(&key).cloned();
                    let badge = format!(
                        "自动决策：{} ({})",
                        p.decision.chosen_action.cn_name(),
                        p.decision.chosen_action.code()
                    );
                    (
                        key,
                        None,
                        p.pid,
                        p.comm.clone(),
                        p.status_note.clone(),
                        p.exe_path.clone(),
                        p.cmdline.clone(),
                        p.code_signer.clone(),
                        badge,
                        v,
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无选中项".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
            EdrWorkbenchTab::PersistenceGuardView => {
                if let Some(e) = self
                    .edr
                    .persistence_entries
                    .get(self.selected_persist_idx)
                    .or_else(|| self.edr.persistence_entries.first())
                {
                    let key = format!("PERSIST:{}", e.config_path);
                    let v = self.edr.llm_verdict_cache.get(&key).cloned();
                    let badge = if e.is_suspicious {
                        "自动决策：建议核查启动项".to_string()
                    } else {
                        "自动决策：可信驻留 · 自动放行".to_string()
                    };
                    (
                        key,
                        None,
                        e.active_pid.unwrap_or(0),
                        e.label.clone(),
                        e.risk_reason.clone(),
                        e.target_exec.clone(),
                        format!("配置: {} | 参数: {}", e.config_path, e.args_summary),
                        e.code_signer.clone(),
                        badge,
                        v,
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无选中项".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
            EdrWorkbenchTab::NetworkC2View => {
                if let Some(s) = self
                    .edr
                    .active_sockets
                    .get(self.selected_sock_idx)
                    .or_else(|| self.edr.active_sockets.first())
                {
                    let key = format!("SOCK:{}:{}", s.pid, s.local_endpoint);
                    let v = self.edr.llm_verdict_cache.get(&key).cloned();
                    let badge = if s.local_port == 6379 && s.is_wildcard_exposed {
                        "自动决策 [A3]：高危暴露 · 建议立即关闭".to_string()
                    } else if s.is_wildcard_exposed {
                        "自动决策：局域网监听 · 已锁定监控".to_string()
                    } else {
                        "自动决策 [A0]：回环/正常连接 · 自动放行".to_string()
                    };
                    (
                        key,
                        None,
                        s.pid,
                        s.process_name.clone(),
                        s.c2_reason.clone(),
                        s.exe_path.clone(),
                        format!(
                            "本地: {} -> 远端: {} ({})",
                            s.local_endpoint, s.remote_endpoint, s.state
                        ),
                        "Network Socket".to_string(),
                        badge,
                        v,
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无选中项".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
            EdrWorkbenchTab::FimAndVaultView => {
                if let Some(f) = self
                    .edr
                    .fim_records
                    .get(self.selected_fim_idx)
                    .or_else(|| self.edr.fim_records.first())
                {
                    let key = format!("FIM:{}", f.path);
                    let v = self.edr.llm_verdict_cache.get(&key).cloned();
                    let badge = if f.is_alert {
                        "自动决策：已自动执行 chmod 0600 权限收敛".to_string()
                    } else {
                        "自动决策：凭据基线完好 · 自动放行".to_string()
                    };
                    (
                        key,
                        None,
                        0,
                        f.category.clone(),
                        f.status.clone(),
                        f.path.clone(),
                        format!(
                            "权限: {} | 指纹: {} | 香农熵: {:.2}",
                            f.unix_mode_octal, f.current_hash_hex, f.shannon_entropy
                        ),
                        "FIM Credential Guard".to_string(),
                        badge,
                        v,
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无选中项".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
            EdrWorkbenchTab::HistoryLogView => {
                if let Some(h) = self
                    .edr
                    .history_records
                    .get(self.selected_history_idx)
                    .or_else(|| self.edr.history_records.first())
                {
                    let key = format!("REAL_PROC:{}:{}", h.pid, h.target_path);
                    let v = h
                        .llm_verdict
                        .clone()
                        .or_else(|| self.edr.llm_verdict_cache.get(&key).cloned());
                    (
                        key,
                        None,
                        h.pid,
                        h.target_name.clone(),
                        format!("[{}] {}", h.timestamp, h.category),
                        if h.target_path.is_empty() {
                            LocalEdrEngine::history_jsonl_file_path()
                                .to_string_lossy()
                                .into_owned()
                        } else {
                            h.target_path.clone()
                        },
                        h.detail.clone(),
                        format!("审计序号 #{}", h.seq_id),
                        h.summary.clone(),
                        v,
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无历史记录".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
            EdrWorkbenchTab::AlertsCenter | EdrWorkbenchTab::ModelConfigView => {
                if let Some(a) = self
                    .edr
                    .alerts
                    .get(self.selected_alert_idx)
                    .or_else(|| self.edr.alerts.first())
                {
                    let key = format!("REAL_PROC:{}:{}", a.pid, a.exe_path);
                    (
                        key,
                        Some(a.alert_id),
                        a.pid,
                        a.process_name.clone(),
                        a.short_summary.clone(),
                        a.exe_path.clone(),
                        a.target_artifact.clone(),
                        a.code_signer.clone(),
                        a.mitigation_summary.clone(),
                        a.llm_verdict.clone(),
                    )
                } else {
                    (
                        String::new(),
                        None,
                        0,
                        "无选中项".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        "-".to_string(),
                        None,
                    )
                }
            }
        };

        let cur_tab = self.active_tab;
        let sel_pers = self.selected_persist_idx;
        let sel_sock = self.selected_sock_idx;
        let sel_fim = self.selected_fim_idx;
        let cache_key_for_forensic = cache_key.clone();
        let proc_name_for_forensic = proc_name.clone();
        let exe_path_for_forensic = exe_path.clone();
        let summary_for_forensic = summary_line.clone();
        let pname_for_collab = proc_name.clone();
        let epath_for_collab = exe_path.clone();
        let sum_for_collab = summary_line.clone();
        let cur_dec_mode = self.edr.model_config.decision_mode;
        let cur_reas_mode = self.edr.model_config.reasoning_mode;
        let cur_model_name = self.edr.model_config.reasoning_model_name.clone();

        let vuln_plan = self.edr.build_port_vulnerability_plan(
            target_pid,
            &proc_name,
            &exe_path,
            &summary_line,
        );
        let disposal_plan = self.edr.build_threat_disposal_plan(
            target_pid,
            &proc_name,
            &exe_path,
            &summary_line,
        );
        let matrix_plan = self.edr.evaluate_matrix_plan_readonly(
            target_pid,
            &proc_name,
            &exe_path,
            &summary_line,
            target_alert_id,
        );

        let pname_for_vuln = proc_name.clone();
        let epath_for_vuln = exe_path.clone();
        let sum_for_vuln = summary_line.clone();
        let pname_for_matrix = proc_name.clone();
        let epath_for_matrix = exe_path.clone();
        let sum_for_matrix = summary_line.clone();
        let pname_for_a4 = proc_name.clone();
        let epath_for_a4 = exe_path.clone();
        let sum_for_a4 = summary_line.clone();
        let pname_for_a2 = proc_name.clone();
        let epath_for_a2 = exe_path.clone();
        let pname_for_a3 = proc_name.clone();
        let epath_for_a3 = exe_path.clone();
        let pname_for_resume = proc_name.clone();
        let epath_for_resume = exe_path.clone();

        let matrix_steps_str = if matrix_plan.ordered_steps.is_empty() {
            "仅观察核验".to_string()
        } else {
            matrix_plan
                .ordered_steps
                .iter()
                .map(|s| s.cn_label())
                .collect::<Vec<_>>()
                .join(" → ")
        };
        let dry_run_on = self.edr.remediation_matrix.policy.dry_run_mode;
        let guard_on = self
            .edr
            .remediation_matrix
            .policy
            .protect_critical_system_hosts
            && self
                .edr
                .remediation_matrix
                .policy
                .protect_active_document_hosts;
        let fw_link_on = self.edr.remediation_matrix.policy.auto_block_c2_network;
        let has_rollback = self.edr.actuator.receipts.iter().any(|r| !r.rolled_back);
        let target_locator =
            self.edr
                .resolve_target_locator(target_pid, &proc_name, &exe_path, &cmdline);

        let is_high_risk = matches!(
            matrix_plan.risk_tier,
            crate::remediation_matrix::RiskTier::L4Critical
                | crate::remediation_matrix::RiskTier::L3High
        );
        let is_med_risk = matches!(
            matrix_plan.risk_tier,
            crate::remediation_matrix::RiskTier::L2Medium
        );
        let risk_badge_bg = if is_high_risk {
            0x450a0a
        } else if is_med_risk {
            BTN_WARN_BG
        } else {
            BTN_TRUST_BG
        };
        let risk_badge_border = if is_high_risk {
            BTN_DANGER_BORDER
        } else if is_med_risk {
            BTN_WARN_BORDER
        } else {
            BTN_TRUST_BORDER
        };
        let risk_badge_text = if is_high_risk {
            0xfca5a5
        } else if is_med_risk {
            BTN_WARN_TEXT
        } else {
            BTN_TRUST_TEXT
        };
        let action_summary_text = format!(
            "建议方案：{}（{}）",
            Self::policy_action_commercial_label(matrix_plan.effective_action),
            matrix_steps_str
        );

        div()
            .id("edr-right-inspector")
            .flex()
            .flex_col()
            .w(relative(0.38))
            .min_w(px(360.0))
            .h_full()
            .min_h(px(0.0))
            .bg(rgb(BG_PANEL))
            .border_l_1()
            .border_color(rgb(BORDER_SUBTLE))
            .p_2()
            .overflow_hidden()
            .child(
                div()
                    .id("right-inspector-scroll")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .w_full()
                    .min_w(px(0.0))
                    .min_h(px(0.0))
                    .gap_2()
                    .overflow_scroll()
                    // 1. 首要安全处置卡片（醒目主操作 CTA + 可选折叠高级选项与风控护栏）
                    .child(
                        div()
                            .id("right-hero-remediation-card")
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .flex_shrink_0()
                            .p_2()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(0x2b3648))
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .gap_1p5()
                                            .child(Self::status_dot(if is_high_risk {
                                                DOT_RED
                                            } else if is_med_risk {
                                                DOT_AMBER
                                            } else {
                                                DOT_GREEN
                                            }))
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .truncate()
                                                    .text_size(px(12.5))
                                                    .text_color(rgb(TEXT_BRIGHT))
                                                    .child(format!("安全处置 · {}", proc_name)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex_shrink_0()
                                            .px_2()
                                            .py(px(2.0))
                                            .rounded_sm()
                                            .bg(rgb(risk_badge_bg))
                                            .border_1()
                                            .border_color(rgb(risk_badge_border))
                                            .text_size(px(10.5))
                                            .text_color(rgb(risk_badge_text))
                                            .child(format!(
                                                "{} · {}",
                                                matrix_plan.risk_tier.code(),
                                                matrix_plan.vector.cn_label()
                                            )),
                                    ),
                            )
                            .child(
                                div()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child(action_summary_text),
                            )
                            .children(matrix_plan.guardrail_reason.as_ref().map(|reason| {
                                div()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .bg(rgb(BTN_WARN_BG))
                                    .border_1()
                                    .border_color(rgb(BTN_WARN_BORDER))
                                    .text_size(px(10.5))
                                    .text_color(rgb(BTN_WARN_TEXT))
                                    .child(format!("风控提示：{}", reason))
                            }))
                            // 主操作 CTA 按钮行（高对比红 / 蓝 / 绿 / 撤销按钮）
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .pt(px(2.0))
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .id("btn-disp-matrix-exec")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .flex_1()
                                            .py(px(6.5))
                                            .px_3()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(rgb(if dry_run_on {
                                                BTN_WARN_BG
                                            } else {
                                                BTN_DANGER_BG
                                            }))
                                            .border_1()
                                            .border_color(rgb(if dry_run_on {
                                                BTN_WARN_BORDER
                                            } else {
                                                BTN_DANGER_BORDER
                                            }))
                                            .text_size(px(12.0))
                                            .text_color(rgb(if dry_run_on {
                                                BTN_WARN_TEXT
                                            } else {
                                                TEXT_BRIGHT
                                            }))
                                            .child(if dry_run_on {
                                                "演练隔离处置"
                                            } else {
                                                "立即隔离处置"
                                            })
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let _ = this.edr.execute_matrix_remediation(
                                                    target_pid,
                                                    &pname_for_matrix,
                                                    &epath_for_matrix,
                                                    &sum_for_matrix,
                                                    target_alert_id,
                                                    true,
                                                );
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-exec-port-vuln-fix")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .flex_shrink_0()
                                            .py(px(6.5))
                                            .px_2p5()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(rgb(BTN_PRIMARY_BG))
                                            .border_1()
                                            .border_color(rgb(BTN_PRIMARY_BORDER))
                                            .text_size(px(11.5))
                                            .text_color(rgb(TEXT_BRIGHT))
                                            .child(vuln_plan.auto_fix_action_label.clone())
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                let _ = this.edr.execute_port_vulnerability_remediation(
                                                    target_pid,
                                                    &pname_for_vuln,
                                                    &epath_for_vuln,
                                                    &sum_for_vuln,
                                                );
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("btn-disp-a0-trust")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .flex_shrink_0()
                                            .py(px(6.5))
                                            .px_2p5()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(rgb(BTN_TRUST_BG))
                                            .border_1()
                                            .border_color(rgb(BTN_TRUST_BORDER))
                                            .text_size(px(11.5))
                                            .text_color(rgb(BTN_TRUST_TEXT))
                                            .child("信任放行")
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                if let Some(aid) = target_alert_id {
                                                    let _ = this.edr.execute_alert_remediation(
                                                        aid,
                                                        PolicyAction::A0PassAndUntag,
                                                    );
                                                } else if target_pid > 0 {
                                                    this.edr.trusted_pids.insert(target_pid);
                                                }
                                                cx.notify();
                                            })),
                                    )
                                    .children(has_rollback.then(|| {
                                        div()
                                            .id("btn-disp-rollback")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .flex_shrink_0()
                                            .py(px(6.5))
                                            .px_2()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(rgb(BTN_WARN_BG))
                                            .border_1()
                                            .border_color(rgb(BTN_WARN_BORDER))
                                            .text_size(px(11.5))
                                            .text_color(rgb(BTN_WARN_TEXT))
                                            .child("撤销恢复")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let _ = this.edr.rollback_remediation_receipt(None);
                                                cx.notify();
                                            }))
                                    })),
                            )
                            // 次级折叠入口：高级处置选项 / 处置依据
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .pt(px(2.0))
                                    .gap_1p5()
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-right-advanced-toggle",
                                            "高级处置与风控",
                                            self.show_advanced_remediation,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_advanced_remediation =
                                                !this.show_advanced_remediation;
                                            cx.notify();
                                        })),
                                    )
                                    .child(
                                        Self::disclosure_chip(
                                            "btn-right-playbook-toggle",
                                            "处置依据与剧本",
                                            self.show_right_playbook_details,
                                        )
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.show_right_playbook_details =
                                                !this.show_right_playbook_details;
                                            cx.notify();
                                        })),
                                    ),
                            )
                            // 默认折叠：单步外科处置 & 风控护栏开关
                            .children(self.show_advanced_remediation.then(|| {
                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .p_1p5()
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .gap_1p5()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_wrap()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .id("btn-matrix-toggle-guard")
                                                    .px_2()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(if guard_on { BTN_TRUST_BG } else { BG_BTN }))
                                                    .border_1()
                                                    .border_color(rgb(if guard_on {
                                                        BTN_TRUST_BORDER
                                                    } else {
                                                        BORDER_SUBTLE
                                                    }))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(if guard_on {
                                                        BTN_TRUST_TEXT
                                                    } else {
                                                        TEXT_SECONDARY
                                                    }))
                                                    .child(if guard_on { "误杀护栏:开" } else { "误杀护栏:关" })
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        let next = !(this
                                                            .edr
                                                            .remediation_matrix
                                                            .policy
                                                            .protect_critical_system_hosts
                                                            && this
                                                                .edr
                                                                .remediation_matrix
                                                                .policy
                                                                .protect_active_document_hosts);
                                                        this.edr
                                                            .remediation_matrix
                                                            .policy
                                                            .protect_critical_system_hosts = next;
                                                        this.edr
                                                            .remediation_matrix
                                                            .policy
                                                            .protect_active_document_hosts = next;
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-matrix-toggle-dryrun")
                                                    .px_2()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(if dry_run_on { BTN_WARN_BG } else { BG_BTN }))
                                                    .border_1()
                                                    .border_color(rgb(if dry_run_on {
                                                        BTN_WARN_BORDER
                                                    } else {
                                                        BORDER_SUBTLE
                                                    }))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(if dry_run_on {
                                                        BTN_WARN_TEXT
                                                    } else {
                                                        TEXT_SECONDARY
                                                    }))
                                                    .child(if dry_run_on { "演练模式:开" } else { "演练模式:关" })
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.edr.remediation_matrix.policy.dry_run_mode =
                                                            !this.edr.remediation_matrix.policy.dry_run_mode;
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-matrix-toggle-fw")
                                                    .px_2()
                                                    .py(px(2.0))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(if fw_link_on { BTN_INFO_BG } else { BG_BTN }))
                                                    .border_1()
                                                    .border_color(rgb(if fw_link_on {
                                                        BTN_PRIMARY_BORDER
                                                    } else {
                                                        BORDER_SUBTLE
                                                    }))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(if fw_link_on {
                                                        BTN_INFO_TEXT
                                                    } else {
                                                        TEXT_SECONDARY
                                                    }))
                                                    .child(if fw_link_on { "断网联动:开" } else { "断网联动:关" })
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.edr.remediation_matrix.policy.auto_block_c2_network =
                                                            !this.edr.remediation_matrix.policy.auto_block_c2_network;
                                                        cx.notify();
                                                    })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_wrap()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .id("btn-disp-a2-freeze")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN_ACTIVE))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SELECTED))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child("冻结进程")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        if let Some(aid) = target_alert_id {
                                                            let _ = this.edr.execute_alert_remediation(
                                                                aid,
                                                                PolicyAction::A2SurgicalMute,
                                                            );
                                                        } else if target_pid > 1 {
                                                            if let Some(reason) = crate::remediation_matrix::RemediationMatrixEngine::detect_protected_system_target(
                                                                target_pid,
                                                                &pname_for_a2,
                                                                &epath_for_a2,
                                                            ) {
                                                                this.edr.remediation_matrix.blocked_by_guardrail_count += 1;
                                                                this.edr.push_audit_log(format!("[RiskGuard::Blocked] {}", reason));
                                                            } else if this.edr.remediation_matrix.policy.dry_run_mode {
                                                                this.edr.remediation_matrix.dry_run_simulations_count += 1;
                                                                this.edr.push_audit_log(format!(
                                                                    "[DryRun::Suspend] 演练挂起进程 PID={} ({})",
                                                                    target_pid, pname_for_a2
                                                                ));
                                                            } else {
                                                                let ok = crate::platform::suspend_process(target_pid);
                                                                this.edr.push_audit_log(format!(
                                                                    "[OS::Suspend] 已手动冻结进程 PID={} (OS={})",
                                                                    target_pid, ok
                                                                ));
                                                            }
                                                        }
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-disp-sigcont")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BG_BTN))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SUBTLE))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child("恢复运行")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        let _ = this.edr.resume_frozen_process(
                                                            target_pid,
                                                            &pname_for_resume,
                                                            &epath_for_resume,
                                                        );
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-disp-a3-kill")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(BTN_WARN_BG))
                                                    .border_1()
                                                    .border_color(rgb(BTN_WARN_BORDER))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(BTN_WARN_TEXT))
                                                    .child("终止进程树")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        if let Some(aid) = target_alert_id {
                                                            let _ = this.edr.execute_alert_remediation(
                                                                aid,
                                                                PolicyAction::A3ProcessIsolate,
                                                            );
                                                        } else if target_pid > 1 {
                                                            if let Some(reason) = crate::remediation_matrix::RemediationMatrixEngine::detect_protected_system_target(
                                                                target_pid,
                                                                &pname_for_a3,
                                                                &epath_for_a3,
                                                            ) {
                                                                this.edr.remediation_matrix.blocked_by_guardrail_count += 1;
                                                                this.edr.push_audit_log(format!("[RiskGuard::Blocked] {}", reason));
                                                            } else if this.edr.remediation_matrix.policy.dry_run_mode {
                                                                this.edr.remediation_matrix.dry_run_simulations_count += 1;
                                                                this.edr.push_audit_log(format!(
                                                                    "[DryRun::Terminate] 演练隔离进程 PID={} ({})",
                                                                    target_pid, pname_for_a3
                                                                ));
                                                            } else {
                                                                let mut ent = crate::lineage_arena::TrackedEntity::new(
                                                                    target_pid,
                                                                    1,
                                                                    &pname_for_a3,
                                                                    &epath_for_a3,
                                                                    "Manual Target",
                                                                    Default::default(),
                                                                );
                                                                let receipt = this.edr.actuator.execute(
                                                                    &mut ent,
                                                                    PolicyAction::A3ProcessIsolate,
                                                                    true,
                                                                    &crate::edr_engine::LocalEdrEngine::now_hms(),
                                                                );
                                                                this.edr.push_audit_log(format!(
                                                                    "[OS::TerminateTree] 手动隔离 PID={} -> {}",
                                                                    target_pid,
                                                                    receipt.executed_steps.join(" | ")
                                                                ));
                                                            }
                                                        }
                                                        cx.notify();
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-disp-a4-purge")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(0x450a0a))
                                                    .border_1()
                                                    .border_color(rgb(BTN_DANGER_BORDER))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(0xfca5a5))
                                                    .child("深度清除")
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        if let Some(aid) = target_alert_id {
                                                            let _ = this.edr.execute_alert_remediation(
                                                                aid,
                                                                PolicyAction::A4RootPurge,
                                                            );
                                                        } else {
                                                            let _ = this.edr.execute_matrix_remediation(
                                                                target_pid,
                                                                &pname_for_a4,
                                                                &epath_for_a4,
                                                                &sum_for_a4,
                                                                None,
                                                                true,
                                                            );
                                                        }
                                                        cx.notify();
                                                    })),
                                            )
                                    )
                            }))
                            // 默认折叠：处置依据、漏洞修补指南与矩阵编排详情
                            .children(self.show_right_playbook_details.then(|| {
                                div()
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .gap_1()
                                    .child(
                                        div()
                                            .p_1p5()
                                            .rounded_sm()
                                            .bg(rgb(BG_PANEL))
                                            .flex()
                                            .flex_col()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .gap(px(2.5))
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "风险规则：{} ({}) · {}",
                                                        vuln_plan.vuln_id,
                                                        vuln_plan.cwe_tag,
                                                        matrix_plan.rule_id
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(format!(
                                                        "• 风险机理：{}",
                                                        vuln_plan.vulnerability_detail
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(format!(
                                                        "• 攻击路径：{}",
                                                        vuln_plan.attack_vector
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "• 根治建议：{}",
                                                        vuln_plan.config_fix_guide
                                                    )),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .p_1p5()
                                            .rounded_sm()
                                            .bg(rgb(BG_PANEL))
                                            .flex()
                                            .flex_col()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .gap(px(2.0))
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "风险评估：{}分 · 影响半径 {}% · {}",
                                                        matrix_plan.risk_score,
                                                        matrix_plan.blast_radius_score,
                                                        matrix_plan.gate.cn_label()
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(rgb(TEXT_SECONDARY))
                                                    .child(format!(
                                                        "• 执行链：{} ({} -> {})",
                                                        matrix_steps_str,
                                                        matrix_plan.recommended_action.code(),
                                                        matrix_plan.effective_action.code()
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(format!(
                                                        "• 可逆性与依据：{} · {}",
                                                        matrix_plan.reversibility,
                                                        matrix_plan.rationale
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(rgb(TEXT_MUTED))
                                                    .child(disposal_plan.stage3_hardening),
                                            ),
                                    )
                            })),
                    )
                    // 2. 详细信息与溯源定位卡（默认展开，完整展示路径/父进程/网络/工作目录）
                    .child(self.render_target_locator_card(&target_locator, &signer, cx))
                    // 3. 智能研判分析卡片（商业可读结论前置，技术特征/6维取证原始报文按需展开）
                    .child(
                        div()
                            .id("right-intel-analysis-card")
                            .flex()
                            .flex_col()
                            .w_full()
                            .min_w(px(0.0))
                            .flex_shrink_0()
                            .p_2()
                            .rounded_sm()
                            .bg(rgb(BG_CARD))
                            .border_1()
                            .border_color(rgb(BORDER_SUBTLE))
                            .gap_1p5()
                            .child(
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .truncate()
                                            .text_size(px(12.0))
                                            .text_color(rgb(TEXT_BRIGHT))
                                            .child("智能研判与深度取证"),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .flex_shrink_0()
                                            .gap_1()
                                            .child(
                                                Self::disclosure_chip(
                                                    "btn-right-mode-toggle",
                                                    "引擎",
                                                    self.show_right_model_bar,
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.show_right_model_bar =
                                                        !this.show_right_model_bar;
                                                    cx.notify();
                                                })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-llm-27b-reason")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(if self.reasoning_in_flight.is_some() {
                                                        BTN_WARN_BG
                                                    } else {
                                                        BTN_PRIMARY_BG
                                                    }))
                                                    .border_1()
                                                    .border_color(rgb(
                                                        if self.reasoning_in_flight.is_some() {
                                                            BTN_WARN_BORDER
                                                        } else {
                                                            BTN_PRIMARY_BORDER
                                                        },
                                                    ))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(
                                                        if self.reasoning_in_flight.is_some() {
                                                            BTN_WARN_TEXT
                                                        } else {
                                                            TEXT_BRIGHT
                                                        },
                                                    ))
                                                    .child(if self.reasoning_in_flight.is_some() {
                                                        "分析中..."
                                                    } else {
                                                        "深度分析"
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.show_right_evidence_details = true;
                                                        let job_opt = match cur_tab {
                                                            EdrWorkbenchTab::AlertsCenter
                                                            | EdrWorkbenchTab::ModelConfigView
                                                            | EdrWorkbenchTab::AdBlockCleanupView
                                                            | EdrWorkbenchTab::FirewallIpsView
                                                            | EdrWorkbenchTab::ThreatIntelView => {
                                                                Some(
                                                                    this.edr
                                                                        .prepare_reasoning_collab_job(
                                                                            target_pid,
                                                                            &pname_for_collab,
                                                                            &epath_for_collab,
                                                                            &sum_for_collab,
                                                                        ),
                                                                )
                                                            }
                                                            EdrWorkbenchTab::ProcessLineageView
                                                            | EdrWorkbenchTab::HistoryLogView => {
                                                                if target_pid > 0 {
                                                                    this.edr
                                                                        .prepare_process_llm_job(
                                                                            target_pid,
                                                                        )
                                                                } else {
                                                                    None
                                                                }
                                                            }
                                                            EdrWorkbenchTab::PersistenceGuardView => {
                                                                this.edr
                                                                    .prepare_persistence_llm_job(
                                                                        sel_pers,
                                                                    )
                                                            }
                                                            EdrWorkbenchTab::NetworkC2View => {
                                                                this.edr.prepare_socket_llm_job(
                                                                    sel_sock,
                                                                )
                                                            }
                                                            EdrWorkbenchTab::FimAndVaultView => {
                                                                this.edr.prepare_fim_llm_job(sel_fim)
                                                            }
                                                        };
                                                        if let Some(job) = job_opt {
                                                            this.spawn_reasoning_task(
                                                                job,
                                                                format!(
                                                                    "正在深度分析 {} ...",
                                                                    pname_for_collab
                                                                ),
                                                                cx,
                                                            );
                                                        } else {
                                                            cx.notify();
                                                        }
                                                    })),
                                            )
                                            .child(
                                                div()
                                                    .id("btn-llm-forensic")
                                                    .px_2()
                                                    .py(px(2.5))
                                                    .rounded_sm()
                                                    .cursor_pointer()
                                                    .bg(rgb(if self.forensic_in_flight.is_some() {
                                                        BTN_WARN_BG
                                                    } else {
                                                        BTN_INFO_BG
                                                    }))
                                                    .border_1()
                                                    .border_color(rgb(
                                                        if self.forensic_in_flight.is_some() {
                                                            BTN_WARN_BORDER
                                                        } else {
                                                            BTN_PRIMARY_BORDER
                                                        },
                                                    ))
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(
                                                        if self.forensic_in_flight.is_some() {
                                                            BTN_WARN_TEXT
                                                        } else {
                                                            BTN_INFO_TEXT
                                                        },
                                                    ))
                                                    .child(if self.forensic_in_flight.is_some() {
                                                        "取证中..."
                                                    } else {
                                                        "现场取证"
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.spawn_forensic_task(
                                                            cache_key_for_forensic.clone(),
                                                            target_pid,
                                                            proc_name_for_forensic.clone(),
                                                            exe_path_for_forensic.clone(),
                                                            summary_for_forensic.clone(),
                                                            cx,
                                                        );
                                                    })),
                                            ),
                                    ),
                            )
                            .children(self.forensic_in_flight.as_ref().map(|status| {
                                div()
                                    .px_2()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .bg(rgb(BTN_WARN_BG))
                                    .border_1()
                                    .border_color(rgb(BTN_WARN_BORDER))
                                    .text_size(px(10.5))
                                    .text_color(rgb(BTN_WARN_TEXT))
                                    .child(status.clone())
                            }))
                            // 快捷引擎切换条（默认折叠，点击「引擎 ▸」展开）
                            .children(self.show_right_model_bar.then(|| {
                                div()
                                    .flex()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .px_1p5()
                                    .py(px(3.0))
                                    .rounded_sm()
                                    .bg(rgb(BG_PANEL))
                                    .border_1()
                                    .border_color(rgb(BORDER_SUBTLE))
                                    .gap_1()
                                    .child(
                                        div()
                                            .id("quick-toggle-dec-mode")
                                            .px_1p5()
                                            .py(px(1.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(10.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(
                                                if cur_dec_mode == DecisionCallMode::Network9006System1
                                                {
                                                    "决策:在线协同"
                                                } else {
                                                    "决策:本地引擎"
                                                },
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.decision_mode =
                                                    if this.edr.model_config.decision_mode
                                                        == DecisionCallMode::Network9006System1
                                                    {
                                                        DecisionCallMode::SimpleLocalSza
                                                    } else {
                                                        DecisionCallMode::Network9006System1
                                                    };
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("quick-toggle-reas-mode")
                                            .px_1p5()
                                            .py(px(1.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN))
                                            .text_size(px(10.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(
                                                if cur_reas_mode == ReasoningCallMode::NetworkHttpChat {
                                                    "通道:HTTP"
                                                } else {
                                                    "通道:CLI"
                                                },
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.edr.model_config.reasoning_mode =
                                                    if this.edr.model_config.reasoning_mode
                                                        == ReasoningCallMode::NetworkHttpChat
                                                    {
                                                        ReasoningCallMode::SimpleCliGateway
                                                    } else {
                                                        ReasoningCallMode::NetworkHttpChat
                                                    };
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("quick-cycle-model-size")
                                            .px_1p5()
                                            .py(px(1.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .bg(rgb(BG_BTN_ACTIVE))
                                            .text_size(px(10.0))
                                            .text_color(rgb(TEXT_PRIMARY))
                                            .child(cur_model_name.clone())
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                let next_m = match this
                                                    .edr
                                                    .model_config
                                                    .reasoning_model_name
                                                    .as_str()
                                                {
                                                    "qwen3.8-27b" => "mimo-v2-flash",
                                                    "mimo-v2-flash" => "qwen2.5-coder-3b",
                                                    _ => "qwen3.8-27b",
                                                };
                                                this.edr.model_config.reasoning_model_name =
                                                    next_m.to_string();
                                                this.edr.preferred_llm_model = next_m.to_string();
                                                this.edr.save_model_config();
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        div()
                                            .id("quick-jump-model-tab")
                                            .px_1p5()
                                            .py(px(1.5))
                                            .rounded_sm()
                                            .cursor_pointer()
                                            .text_size(px(10.0))
                                            .text_color(rgb(TEXT_SECONDARY))
                                            .child("高级设置 ➔")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.active_tab = EdrWorkbenchTab::ModelConfigView;
                                                cx.notify();
                                            })),
                                    )
                            }))
                            .child(if let Some(v) = llm_verdict {
                                let has_forensic = v.agent_forensic_report.is_some();
                                let forensic_txt_opt = v.agent_forensic_report.clone();
                                div()
                                    .id("llm-verdict-box")
                                    .flex()
                                    .flex_col()
                                    .w_full()
                                    .min_w(px(0.0))
                                    .gap_1()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_row()
                                            .items_center()
                                            .justify_between()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .p_2()
                                            .rounded_sm()
                                            .bg(rgb(BG_PANEL))
                                            .gap_1p5()
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w(px(0.0))
                                                    .text_size(px(11.5))
                                                    .text_color(rgb(TEXT_PRIMARY))
                                                    .child(format!(
                                                        "{} · {}",
                                                        Self::clean_commercial_text(&v.conclusion),
                                                        Self::clean_commercial_text(&v.advice)
                                                    )),
                                            )
                                            .child(
                                                Self::disclosure_chip(
                                                    "btn-right-evidence-toggle",
                                                    if has_forensic {
                                                        "技术证据与取证"
                                                    } else {
                                                        "技术证据"
                                                    },
                                                    self.show_right_evidence_details,
                                                )
                                                .on_click(cx.listener(|this, _, _, cx| {
                                                    this.show_right_evidence_details =
                                                        !this.show_right_evidence_details;
                                                    cx.notify();
                                                })),
                                            ),
                                    )
                                    .children(self.show_right_evidence_details.then(|| {
                                        div()
                                            .flex()
                                            .flex_col()
                                            .w_full()
                                            .min_w(px(0.0))
                                            .gap_1()
                                            .child(
                                                div()
                                                    .p_1p5()
                                                    .rounded_sm()
                                                    .bg(rgb(BG_PANEL))
                                                    .flex()
                                                    .flex_col()
                                                    .w_full()
                                                    .min_w(px(0.0))
                                                    .gap(px(2.5))
                                                    .child(
                                                        div()
                                                            .truncate()
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_MUTED))
                                                            .child(format!(
                                                                "特征: {} | {}",
                                                                v.binary_telemetry, v.activity_telemetry
                                                            )),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_SECONDARY))
                                                            .child(format!(
                                                                "依据: {} {}",
                                                                v.binary_reasoning, v.activity_reasoning
                                                            )),
                                                    ),
                                            )
                                            .children(forensic_txt_opt.map(|forensic_txt| {
                                                div()
                                                    .p_1p5()
                                                    .rounded_sm()
                                                    .bg(rgb(BG_PANEL))
                                                    .border_1()
                                                    .border_color(rgb(BORDER_SELECTED))
                                                    .flex()
                                                    .flex_col()
                                                    .w_full()
                                                    .min_w(px(0.0))
                                                    .gap(px(2.5))
                                                    .child(
                                                        div()
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_PRIMARY))
                                                            .child("深度取证证据包："),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_size(px(10.5))
                                                            .text_color(rgb(TEXT_SECONDARY))
                                                            .child(forensic_txt),
                                                    )
                                            }))
                                    }))
                            } else {
                                div()
                                    .id("llm-verdict-empty")
                                    .text_size(px(11.0))
                                    .text_color(rgb(TEXT_SECONDARY))
                                    .child(format!(
                                        "{} · 点击「深度分析」或「现场取证」查看详细依据",
                                        Self::clean_commercial_text(&auto_decision_badge)
                                    ))
                            }),
                    ),
            )
    }
}

pub fn run_gpui_edr_workbench() {
    Application::new().run(|cx: &mut App| {
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.on_action(|_: &Quit, cx| cx.quit());

        let bounds = Bounds::centered(None, size(px(1380.0), px(860.0)), cx);
        let _ = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |_, cx| cx.new(EdrGpuiWorkbench::new),
        );
        cx.activate(true);
    });
}
