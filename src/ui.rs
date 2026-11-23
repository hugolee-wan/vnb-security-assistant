//! Windows 11 × Ardot 暗色高密度极简风格 UI (`ui.rs`)
//!
//! 视觉与交互设计准则：
//! 1. **Ardot 暗色高密度层级 (Dark-First, High-Density)**：
//!    - 严格遵循 `canvas (#0A0A0C) -> surface (#121216) -> elevated (#1A1A22)` 视觉层级与半透明高光边框；
//!    - 语义色彩一致：阻断/高危用纯红 (`#EF4444`)、安全/放行用翡翠绿 (`#10B981`)、观察/置顶用琥珀黄 (`#FBBF24`)、主强调色用科技青蓝 (`#06B6D4` / `#3B82F6`)。
//! 2. **零抖动卡片网格 + 全卡片可交互 + 底部 X-Ray 决策透视抽屉**：
//!    - 每张窗口卡片支持整卡悬停高亮与点击选中；点击卡片（或 `🔍` 按钮）可在底部展开 12 维特征 $\mathbf{s}_t$、潜空间意图 $\mathbf{Z}_t$ 与贝叶斯动作 $\mathbf{A}_t$ 的实时透视面板；
//!    - 支持一键筛选（`全部` / `🎯 疑似弹窗` / `🛡️ 已设拦截`）、多维搜索（软件名 / 标题 / 路径 / PID）、一键信任白名单（`✓ 信任`）与一键外科拦截（`🚫 拦截`）。
//! 3. **拦截日志完整输出 + 独立悬浮 Toast**：
//!    - 完整展示【模型决策标签】、【拦截进程信息 (PID/PPID/TID/HWND)】、【完整文件路径 (`exe_path`)】与【底层执行器全部系统调用步骤】，点击路径即可复制；
//!    - 采用 `egui::Area` 独立悬浮通知气泡，彻底消除工具栏挤压抖动。

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Arc,
};
use std::time::{Duration, Instant};
use eframe::egui::{
    self, Align, Align2, Color32, CursorIcon, FontId, Id, Layout, Margin, Order, Pos2, Rect,
    Response, RichText, Rounding, Sense, Stroke, Vec2, ViewportBuilder, ViewportId,
};

use crate::ad_blocker::{AdCleanupCandidate, AdConnectionAlert, AdHostsShieldStatus};
use crate::contract::{LatentIntent, PolicyAction};
use crate::decision_model::PolicyDecisionEngine;
use crate::edr_engine::{
    EdrAlertFinding, FimFileRecord, LocalEdrEngine, NetworkSocketRecord, PersistenceEntry,
    ThreatSeverity,
};
use crate::firewall_ips::{FirewallAction, FirewallDirection, FirewallRule, IpsEvent, IpsMode};
use crate::platform::OsFirewallStatus;
use crate::real_scanner::{BlockedAdRecord, RealDesktopWindow, RealWindowScanner};
use crate::threat_intel::{InvestigationReport, ThreatIntelFeedConfig};

// ============================================================================
// Ardot 暗色高密度调色板常量
// ============================================================================
const BG_CANVAS: Color32 = Color32::from_rgb(10, 10, 12); // #0a0a0c
const BG_SURFACE: Color32 = Color32::from_rgb(18, 18, 22); // #121216
const BG_ELEVATED: Color32 = Color32::from_rgb(26, 26, 34); // #1a1a22
const BG_CARD_HOVER: Color32 = Color32::from_rgb(32, 34, 46);
const BG_CARD_AD: Color32 = Color32::from_rgb(36, 16, 24);
const BG_CARD_MANAGED: Color32 = Color32::from_rgb(14, 28, 26);

const BORDER_SUBTLE: Color32 = Color32::from_rgb(38, 41, 54);
const BORDER_HOVER: Color32 = Color32::from_rgb(71, 85, 105);
const ACCENT_CYAN: Color32 = Color32::from_rgb(6, 182, 212); // #06b6d4
const ACCENT_BLUE: Color32 = Color32::from_rgb(37, 99, 235); // #2563eb
const SEMANTIC_GREEN: Color32 = Color32::from_rgb(16, 185, 129); // #10b981
const SEMANTIC_RED: Color32 = Color32::from_rgb(239, 68, 68); // #ef4444
const SEMANTIC_AMBER: Color32 = Color32::from_rgb(251, 191, 36); // #fbbf24
const TEXT_PRIMARY: Color32 = Color32::from_rgb(248, 250, 252);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(148, 163, 184);
const TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinTab {
    /// 窗口与软件磁贴开关
    AppTiles,
    /// 已拦截日志（含进程信息与文件路径信息）
    History,
    /// 本地 EDR 主动防御与实时告警 (进程/C2/端口/凭据/持久化)
    EdrAlerts,
    /// 广告清理与全局 hosts/外联拦截
    AdBlocker,
    /// 主机防火墙与入侵防御 (Firewall & IPS)
    FirewallIps,
    /// 网络攻击指纹、代码基因调查与多情报库联动
    ThreatIntel,
    /// 系统遥测、驻留自启动项与审计日志
    Telemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileFilter {
    /// 全部桌面窗口
    All,
    /// 疑似广告 / 置顶悬浮 / 工具小窗
    SuspiciousOrFloating,
    /// 已开启自动屏蔽的软件或白名单
    ManagedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryFilter {
    /// 全部拦截记录
    All,
    /// 模型自动拦截
    AutoOnly,
    /// 手动拦截+模型学习
    ManualOnly,
}

/// 后台安全工作线程发布的轻量级只读 UI 快照（彻底消除 UI 渲染线程磁盘 I/O 与锁竞争卡顿）
#[derive(Clone)]
pub struct UiSnapshot {
    pub initialized: bool,
    pub auto_block_enabled: bool,
    pub screen_size: (i32, i32),
    pub engine_revision: u64,
    pub mosaic_count: usize,
    pub live_windows: Vec<RealDesktopWindow>,
    pub auto_block_apps: HashSet<String>,
    pub trusted_whitelist_windows: HashSet<u64>,
    pub blocked_history: Vec<BlockedAdRecord>,
    pub live_processes_count: usize,
    pub daemon_agent_installed: bool,
    pub alerts: Vec<EdrAlertFinding>,
    pub active_sockets: Vec<NetworkSocketRecord>,
    pub persistence_entries: Vec<PersistenceEntry>,
    pub fim_records: Vec<FimFileRecord>,
    pub hosts_status: AdHostsShieldStatus,
    pub total_reclaimed_bytes: u64,
    pub ad_last_action_message: String,
    pub ad_cleanup_candidates: Vec<AdCleanupCandidate>,
    pub ad_connections: Vec<AdConnectionAlert>,
    pub fw_os_status: OsFirewallStatus,
    pub fw_ips_mode: IpsMode,
    pub firewall_rules: Vec<FirewallRule>,
    pub ips_events: Vec<IpsEvent>,
    pub fw_total_packets_inspected: u64,
    pub fw_total_packets_blocked: u64,
    pub fw_last_sync_message: String,
    pub intel_feeds: Vec<ThreatIntelFeedConfig>,
    pub intel_reports: Vec<InvestigationReport>,
    pub intel_custom_ioc_count: usize,
    pub intel_last_status_message: String,
    // 预计算角标计数器（消除每帧 UI 渲染遍历 Vec 开销）
    pub suspicious_win_count: usize,
    pub managed_win_count: usize,
    pub pending_alerts_count: usize,
    pub pending_ads_count: usize,
    pub active_fw_rules_count: usize,
    pub enabled_intel_feeds_count: usize,
    pub hardware_tier_label: String,
}

impl Default for UiSnapshot {
    fn default() -> Self {
        Self {
            initialized: false,
            auto_block_enabled: true,
            screen_size: (1920, 1080),
            engine_revision: 0,
            mosaic_count: 0,
            live_windows: Vec::new(),
            auto_block_apps: HashSet::new(),
            trusted_whitelist_windows: HashSet::new(),
            blocked_history: Vec::new(),
            live_processes_count: 0,
            daemon_agent_installed: false,
            alerts: Vec::new(),
            active_sockets: Vec::new(),
            persistence_entries: Vec::new(),
            fim_records: Vec::new(),
            hosts_status: AdHostsShieldStatus::default(),
            total_reclaimed_bytes: 0,
            ad_last_action_message: String::new(),
            ad_cleanup_candidates: Vec::new(),
            ad_connections: Vec::new(),
            fw_os_status: OsFirewallStatus {
                backend_name: "Windows Defender Firewall".to_string(),
                os_firewall_enabled: true,
                stealth_or_profile: "Initializing".to_string(),
                synced_anchor_rules: 0,
                anchor_path: String::new(),
                detail: String::new(),
            },
            fw_ips_mode: IpsMode::PreventAutoBlock,
            firewall_rules: Vec::new(),
            ips_events: Vec::new(),
            fw_total_packets_inspected: 0,
            fw_total_packets_blocked: 0,
            fw_last_sync_message: "防火墙与 IPS 待初始化".to_string(),
            intel_feeds: Vec::new(),
            intel_reports: Vec::new(),
            intel_custom_ioc_count: 0,
            intel_last_status_message: "多情报库待初始化".to_string(),
            suspicious_win_count: 0,
            managed_win_count: 0,
            pending_alerts_count: 0,
            pending_ads_count: 0,
            active_fw_rules_count: 0,
            enabled_intel_feeds_count: 0,
            hardware_tier_label: crate::platform::detect_host_hardware_profile()
                .tier
                .label()
                .to_string(),
        }
    }
}

enum WorkerCmd {
    SetAutoBlock(bool),
    RefreshWindows { notify: bool },
    ForceFullTelemetryScan,
    ClearRestoredHistory,
    ToggleAppAutoBlock { app: String, enable: bool },
    TrustWindow(RealDesktopWindow),
    BlockWindowNow(RealDesktopWindow),
    RestoreAndTrust(u64),
    ResolveTestPopup { auto: bool },
    HardenAllExposedVulnerabilities,
    ToggleEdrDaemon,
    ExecuteAlertRemediation(u64, PolicyAction),
    ResumeFrozenProcess(u32, String, String),
    ToggleHostsAdShield,
    CleanAllAdArtifacts,
    AddCustomAdDomain(String),
    CleanSingleAdArtifact(usize),
    BlockAdConnection(usize),
    UnloadPersistenceAgent(String),
    RemediateFim(String),
    ExecutePortVulnRemediation(u32, String, String, String),
    ToggleIpsMode,
    AddFirewallBlockRule { name: String, remote_ip: String, port: u16 },
    ToggleFirewallRule(String),
    RemoveFirewallRule(String),
    AllowlistFirewallIp(String),
    HardenFirewallPorts,
    SyncOsFirewall(bool),
    RunIpsDrill(String),
    RunThreatInvestigation(String),
    RunThreatInvestigationDrill(String),
    ToggleIntelFeed(String),
    UpdateIntelFeedConfig { feed_id: String, endpoint_url: String, api_key: String },
    AddCustomIntelFeed { name: String, endpoint_url: String, auth_header: String, api_key: String },
    RemoveIntelFeed(String),
    ResetDefaultIntelFeeds,
    BlockFromInvestigationReport(String),
    Shutdown,
}

enum WorkerMsg {
    Snapshot(Arc<UiSnapshot>),
    Toast { msg: String, is_alert: bool },
    ClearAdDomainInput,
}

pub struct SecurityAssistantApp {
    pub current_tab: WinTab,
    pub tile_filter: TileFilter,
    pub history_filter: HistoryFilter,
    /// 总开关：自动屏蔽弹窗
    pub auto_block_enabled: bool,
    pub snapshot: Arc<UiSnapshot>,
    cmd_tx: Sender<WorkerCmd>,
    msg_rx: Receiver<WorkerMsg>,
    pub ad_domain_input: String,
    pub fw_ip_input: String,
    pub fw_port_input: String,
    pub fw_show_kernel_drawer: bool,
    pub intel_query_input: String,
    pub intel_selected_feed_id: String,
    pub intel_feed_name_input: String,
    pub intel_feed_url_input: String,
    pub intel_feed_key_input: String,
    pub intel_show_feeds_drawer: bool,
    pub search_query: String,
    /// 当前选中展开 X-Ray 详情抽屉的窗口 ID
    pub selected_window_id: Option<u64>,
    /// 独立悬浮状态气泡 (文案, 触发时刻, 是否为警告/拦截红标)
    pub toast_short: Option<(String, Instant, bool)>,
    /// 右下角真实测试弹窗
    pub test_ad_popup_open: bool,
    pub test_ad_spawned_at: Option<Instant>,
    style_initialized: bool,
}

impl Drop for SecurityAssistantApp {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(WorkerCmd::Shutdown);
    }
}

impl Default for SecurityAssistantApp {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAssistantApp {
    pub fn new() -> Self {
        Self::new_with_ctx(None)
    }

    pub fn new_with_ctx(ctx: Option<egui::Context>) -> Self {
        let (cmd_tx, msg_rx) = spawn_backend_worker(ctx);

        Self {
            current_tab: WinTab::AppTiles,
            tile_filter: TileFilter::All,
            history_filter: HistoryFilter::All,
            auto_block_enabled: true,
            snapshot: Arc::new(UiSnapshot::default()),
            cmd_tx,
            msg_rx,
            ad_domain_input: String::new(),
            fw_ip_input: String::new(),
            fw_port_input: String::new(),
            fw_show_kernel_drawer: false,
            intel_query_input: "198.51.100.44:4444".to_string(),
            intel_selected_feed_id: "FEED-LOCAL-9006".to_string(),
            intel_feed_name_input: "自定义私有TIP情报库".to_string(),
            intel_feed_url_input: "http://127.0.0.1:9006/v1/systemone".to_string(),
            intel_feed_key_input: String::new(),
            intel_show_feeds_drawer: false,
            search_query: String::new(),
            selected_window_id: None,
            toast_short: None,
            test_ad_popup_open: false,
            test_ad_spawned_at: None,
            style_initialized: false,
        }
    }

    #[inline]
    fn send_cmd(&self, cmd: WorkerCmd) {
        let _ = self.cmd_tx.send(cmd);
    }

    fn show_toast(&mut self, msg: impl Into<String>) {
        self.toast_short = Some((msg.into(), Instant::now(), false));
    }

    fn show_action_toast(&mut self, msg: impl Into<String>, is_alert: bool) {
        self.toast_short = Some((msg.into(), Instant::now(), is_alert));
    }

    fn install_cjk_system_fonts(ctx: &egui::Context) {
        let candidates = [
            r"C:\Windows\Fonts\msyh.ttc",
            r"C:\Windows\Fonts\msyhbd.ttc",
            r"C:\Windows\Fonts\simhei.ttf",
            r"C:\Windows\Fonts\simsun.ttc",
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        ];
        for path in candidates {
            if let Ok(bytes) = std::fs::read(path) {
                let mut fonts = egui::FontDefinitions::default();
                fonts
                    .font_data
                    .insert("cjk_sys".to_owned(), egui::FontData::from_owned(bytes));
                fonts
                    .families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .insert(0, "cjk_sys".to_owned());
                fonts
                    .families
                    .entry(egui::FontFamily::Monospace)
                    .or_default()
                    .push("cjk_sys".to_owned());
                ctx.set_fonts(fonts);
                break;
            }
        }
    }

    fn apply_ardot_theme(&mut self, ctx: &egui::Context) {
        if self.style_initialized {
            return;
        }
        Self::install_cjk_system_fonts(ctx);
        let mut style = (*ctx.style()).clone();
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_CANVAS;
        visuals.window_fill = BG_SURFACE;
        visuals.extreme_bg_color = Color32::from_rgb(8, 8, 10);
        visuals.faint_bg_color = BG_SURFACE;
        visuals.widgets.noninteractive.bg_fill = BG_SURFACE;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER_SUBTLE);
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
        visuals.widgets.inactive.bg_fill = BG_ELEVATED;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER_SUBTLE);
        visuals.widgets.inactive.rounding = Rounding::same(8.0);
        visuals.widgets.hovered.bg_fill = BG_CARD_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_CYAN);
        visuals.widgets.hovered.rounding = Rounding::same(8.0);
        visuals.widgets.active.bg_fill = ACCENT_BLUE;
        visuals.widgets.active.rounding = Rounding::same(8.0);
        visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(6, 182, 212, 48);
        visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT_CYAN);

        style.visuals = visuals;
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.scroll.bar_width = 6.0;
        let hw = crate::platform::detect_host_hardware_profile();
        if hw.tier == crate::platform::HostComputeTier::LowSpec || hw.prefer_low_gpu_overhead {
            ctx.tessellation_options_mut(|opts| {
                opts.feathering = false;
                opts.round_text_to_pixels = true;
            });
        }
        ctx.set_style(style);
        self.style_initialized = true;
    }

    fn current_exe_path_str() -> String {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| r"C:\Program Files\AdPromo\promo_popup.exe".to_string())
    }

    /// 右下角真实弹窗（极简图标化 + 实时倒计时进度条，已节流至 120ms 低功耗重绘）
    fn render_test_ad_popup_viewport(&mut self, ctx: &egui::Context) {
        if !self.test_ad_popup_open {
            return;
        }
        if self.auto_block_enabled {
            if let Some(t0) = self.test_ad_spawned_at {
                if t0.elapsed() >= Duration::from_millis(800) {
                    self.test_ad_popup_open = false;
                    self.test_ad_spawned_at = None;
                    self.send_cmd(WorkerCmd::ResolveTestPopup { auto: true });
                    return;
                }
            }
        }
        ctx.request_repaint_after(Duration::from_millis(120));

        let vp_id = ViewportId::from_hash_of("vnb_win11_ad_test_popup");
        let (sw, sh) = self.snapshot.screen_size;
        let builder = ViewportBuilder::default()
            .with_title("模拟广告弹窗")
            .with_always_on_top()
            .with_decorations(false)
            .with_inner_size([336.0, 178.0])
            .with_position(Pos2::new(
                (sw - 360).max(100) as f32,
                (sh - 250).max(100) as f32,
            ));

        let auto_on = self.auto_block_enabled;
        let elapsed_ratio = self
            .test_ad_spawned_at
            .map(|t| (t.elapsed().as_secs_f32() / 0.8).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let mut manual_close = false;

        ctx.show_viewport_immediate(vp_id, builder, |ui, _class| {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(BG_CARD_AD)
                        .stroke(Stroke::new(1.5_f32, SEMANTIC_RED))
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::same(16.0)),
                )
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                SEMANTIC_AMBER,
                                RichText::new("🎯 [z1 宿主夹带弹窗 · 右下角置顶]").size(11.5).strong(),
                            );
                        });
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("🔥 会员特惠弹窗广告")
                                .size(16.0)
                                .strong()
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(6.0);
                        ui.colored_label(
                            SEMANTIC_GREEN,
                            if auto_on {
                                format!(
                                    "🛡️ 决策模型 S→Z→A 推理完成，外科消音倒计时 {:.0}%",
                                    (1.0 - elapsed_ratio) * 100.0
                                )
                            } else {
                                "自动拦截已暂停 · 点击下方按钮立即拦截并在线学习".to_string()
                            },
                        );
                        ui.add_space(10.0);
                        let btn = egui::Button::new(
                            RichText::new("🚫 立即外科拦截 (a_2)")
                                .size(12.5)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(SEMANTIC_RED)
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(150.0, 32.0));
                        if ui.add(btn).clicked() {
                            manual_close = true;
                        }
                    });
                });
        });

        if manual_close {
            self.test_ad_popup_open = false;
            self.test_ad_spawned_at = None;
            self.send_cmd(WorkerCmd::ResolveTestPopup { auto: false });
        }
    }

    /// 独立悬浮 Toast 气泡（位于界面底部居中，120ms 低功耗淡出重绘，绝不挤压顶部工具栏）
    fn render_floating_toast(&self, ctx: &egui::Context) {
        let Some((msg, t0, is_alert)) = &self.toast_short else {
            return;
        };
        let elapsed = t0.elapsed().as_secs_f32();
        if elapsed >= 3.6 {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(120));

        let alpha = if elapsed > 3.0 {
            ((3.6 - elapsed) / 0.6).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let a_u8 = (alpha * 245.0) as u8;
        let accent = if *is_alert {
            Color32::from_rgba_unmultiplied(239, 68, 68, a_u8)
        } else {
            Color32::from_rgba_unmultiplied(16, 185, 129, a_u8)
        };
        let bg = Color32::from_rgba_unmultiplied(22, 26, 36, a_u8);
        let text_c = Color32::from_rgba_unmultiplied(248, 250, 252, a_u8);

        egui::Area::new(Id::new("ardot_floating_toast"))
            .order(Order::Tooltip)
            .anchor(Align2::CENTER_BOTTOM, Vec2::new(0.0, -18.0))
            .interactable(false)
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(bg)
                    .stroke(Stroke::new(1.2_f32, accent))
                    .rounding(Rounding::same(20.0))
                    .inner_margin(Margin::symmetric(18.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (dot_rect, _) =
                                ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                            ui.painter().circle_filled(dot_rect.center(), 4.0, accent);
                            ui.label(RichText::new(msg).size(12.5).strong().color(text_c));
                        });
                    });
            });
    }
}

// ============================================================================
// Windows 11 × Ardot 风格自定义图形控件：胶囊拨动开关 + 磁贴图标 + 指标徽章
// ============================================================================

fn win11_toggle_switch(ui: &mut egui::Ui, on: &mut bool, scale: f32) -> Response {
    let desired_size = Vec2::new(44.0 * scale, 22.0 * scale);
    let (rect, mut response) = ui.allocate_exact_size(desired_size, Sense::click());
    if response.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool_responsive(response.id, *on);
        let bg_off = Color32::from_rgb(45, 55, 72);
        let bg_on = SEMANTIC_GREEN;
        let bg_color = Color32::from_rgb(
            (bg_off.r() as f32 + (bg_on.r() as f32 - bg_off.r() as f32) * how_on) as u8,
            (bg_off.g() as f32 + (bg_on.g() as f32 - bg_off.g() as f32) * how_on) as u8,
            (bg_off.b() as f32 + (bg_on.b() as f32 - bg_off.b() as f32) * how_on) as u8,
        );

        let radius = 0.5 * rect.height();
        ui.painter()
            .rect_filled(rect, Rounding::same(radius), bg_color);
        if response.hovered() {
            ui.painter().rect_stroke(
                rect,
                Rounding::same(radius),
                Stroke::new(1.0_f32, Color32::from_white_alpha(90)),
            );
        }

        let circle_x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), how_on);
        let center = Pos2::new(circle_x, rect.center().y);
        ui.painter()
            .circle_filled(center, radius * 0.74, Color32::WHITE);
    }

    response
}

fn match_app_icon_and_color(app_name: &str, is_ad: bool) -> (&'static str, Color32) {
    if is_ad {
        return ("🎯", Color32::from_rgb(225, 29, 72));
    }
    let lower = app_name.to_lowercase();
    if lower.contains("chrome")
        || lower.contains("edge")
        || lower.contains("safari")
        || lower.contains("firefox")
    {
        ("🌐", Color32::from_rgb(37, 99, 235))
    } else if lower.contains("wechat")
        || lower.contains("微信")
        || lower.contains("qq")
        || lower.contains("feishu")
        || lower.contains("dingtalk")
    {
        ("💬", Color32::from_rgb(5, 150, 105))
    } else if lower.contains("wps")
        || lower.contains("word")
        || lower.contains("excel")
        || lower.contains("office")
        || lower.contains("notes")
    {
        ("📄", Color32::from_rgb(217, 119, 6))
    } else if lower.contains("code")
        || lower.contains("cursor")
        || lower.contains("term")
        || lower.contains("iterm")
        || lower.contains("antigravity")
    {
        ("⚡", Color32::from_rgb(124, 58, 237))
    } else if lower.contains("finder") || lower.contains("explorer") {
        ("📁", Color32::from_rgb(14, 116, 144))
    } else {
        ("💻", Color32::from_rgb(51, 65, 85))
    }
}

fn draw_app_icon_tile(ui: &mut egui::Ui, app_name: &str, is_ad: bool, size: f32) {
    let (icon, bg) = match_app_icon_and_color(app_name, is_ad);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(size, size), Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter()
            .rect_filled(rect, Rounding::same(size * 0.25), bg);
        ui.painter().rect_stroke(
            rect,
            Rounding::same(size * 0.25),
            Stroke::new(1.0_f32, Color32::from_white_alpha(28)),
        );
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            icon,
            FontId::proportional(size * 0.50),
            Color32::WHITE,
        );
    }
}

fn draw_metric_pill(ui: &mut egui::Ui, label: &str, value: &str, accent: Color32) {
    egui::Frame::none()
        .fill(BG_ELEVATED)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(RichText::new(label).size(11.0).color(TEXT_SECONDARY));
                ui.label(RichText::new(value).size(11.5).strong().color(accent));
            });
        });
}

fn draw_tag_chip(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(Rounding::same(4.0))
        .inner_margin(Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.5).strong().color(fg));
        });
}

fn draw_progress_row(ui: &mut egui::Ui, label: &str, val: f32, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(label)
                .size(11.0)
                .color(TEXT_SECONDARY)
                .monospace(),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{:>3.0}%", val * 100.0))
                    .size(11.0)
                    .strong()
                    .color(color)
                    .monospace(),
            );
            let bar_w = ui.available_width().max(36.0);
            let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 6.0), Sense::hover());
            if ui.is_rect_visible(rect) {
                ui.painter().rect_filled(
                    rect,
                    Rounding::same(3.0),
                    Color32::from_rgb(30, 35, 48),
                );
                let fill_w = (rect.width() * val.clamp(0.0, 1.0)).max(2.0);
                let fill_rect =
                    Rect::from_min_size(rect.min, Vec2::new(fill_w, rect.height()));
                ui.painter()
                    .rect_filled(fill_rect, Rounding::same(3.0), color);
            }
        });
    });
}

fn short_text(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max_chars - 1).collect();
        format!("{}…", prefix)
    }
}

impl eframe::App for SecurityAssistantApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_ardot_theme(ctx);

        // 非阻塞拉取后台线程快照与动作反馈（UI 线程 0 磁盘/进程探针阻塞，静默时 0% 额外重绘）
        while let Ok(msg) = self.msg_rx.try_recv() {
            match msg {
                WorkerMsg::Snapshot(snap) => {
                    self.auto_block_enabled = snap.auto_block_enabled;
                    self.snapshot = snap;
                }
                WorkerMsg::Toast { msg, is_alert } => {
                    self.show_action_toast(msg, is_alert);
                }
                WorkerMsg::ClearAdDomainInput => {
                    self.ad_domain_input.clear();
                }
            }
        }

        // 窗口最小化时跳过全量控件布局与网格生成（待机零 CPU / GPU 占用）
        if ctx.input(|i| i.viewport().minimized.unwrap_or(false)) && !self.test_ad_popup_open {
            return;
        }

        // 支持 Esc 键快速关闭底部详情抽屉或清空搜索框
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            if self.selected_window_id.is_some() {
                self.selected_window_id = None;
            } else if !self.search_query.is_empty() {
                self.search_query.clear();
            }
        }

        self.render_test_ad_popup_viewport(ctx);

        let suspicious_count = self.snapshot.suspicious_win_count;
        let managed_count = self.snapshot.managed_win_count;

        // ── 顶部：Ardot × Windows 11 主控横幅 ──
        egui::TopBottomPanel::top("win11_hero_header")
            .frame(
                egui::Frame::none()
                    .fill(BG_SURFACE)
                    .inner_margin(Margin::symmetric(20.0, 14.0))
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (shield_rect, _) =
                        ui.allocate_exact_size(Vec2::new(48.0, 48.0), Sense::hover());
                    let shield_bg = if self.auto_block_enabled {
                        SEMANTIC_GREEN
                    } else {
                        Color32::from_rgb(71, 85, 105)
                    };
                    ui.painter()
                        .rect_filled(shield_rect, Rounding::same(13.0), shield_bg);
                    ui.painter().rect_stroke(
                        shield_rect,
                        Rounding::same(13.0),
                        Stroke::new(1.0_f32, Color32::from_white_alpha(40)),
                    );
                    ui.painter().text(
                        shield_rect.center(),
                        Align2::CENTER_CENTER,
                        "🛡️",
                        FontId::proportional(25.0),
                        Color32::WHITE,
                    );

                    ui.add_space(8.0);

                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 5.0;
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(if self.auto_block_enabled {
                                    "弹窗广告自动拦截"
                                } else {
                                    "自动拦截已暂停"
                                })
                                .size(18.0)
                                .strong()
                                .color(TEXT_PRIMARY),
                            );
                            draw_tag_chip(
                                ui,
                                &if self.snapshot.initialized {
                                    format!(
                                        "Qwen2.5-1.5B (1536D·78MB) + 806-Tree GBDT & ResMLP v1.{} (记忆槽:{})",
                                        self.snapshot.engine_revision,
                                        self.snapshot.mosaic_count
                                    )
                                } else {
                                    "⏳ 后台正在初始化本地安全模型与终端遥测探针…".to_string()
                                },
                                ACCENT_CYAN,
                                Color32::from_rgba_unmultiplied(6, 182, 212, 28),
                            );
                        });

                        // 关键指标卡片（Metric Pills，永不折行错位）
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            draw_metric_pill(
                                ui,
                                "已拦截",
                                &format!("{} 次", self.snapshot.blocked_history.len()),
                                SEMANTIC_GREEN,
                            );
                            draw_metric_pill(
                                ui,
                                "监测窗口",
                                &format!("{}", self.snapshot.live_windows.len()),
                                ACCENT_CYAN,
                            );
                            draw_metric_pill(
                                ui,
                                "置顶/可疑",
                                &format!("{}", suspicious_count),
                                if suspicious_count > 0 {
                                    SEMANTIC_AMBER
                                } else {
                                    TEXT_SECONDARY
                                },
                            );
                        });
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let mut enabled = self.auto_block_enabled;
                        if win11_toggle_switch(ui, &mut enabled, 1.2)
                            .on_hover_text("开启/暂停全自动模型推理与外科手术屏蔽")
                            .changed()
                        {
                            self.auto_block_enabled = enabled;
                            Arc::make_mut(&mut self.snapshot).auto_block_enabled = enabled;
                            self.send_cmd(WorkerCmd::SetAutoBlock(enabled));
                            if enabled {
                                self.show_toast("🛡️ 已开启全自动弹窗拦截");
                            } else {
                                self.show_action_toast("⏸ 已暂停自动拦截（仍可手动拦截与调优）", true);
                            }
                        }

                        ui.label(
                            RichText::new(if self.auto_block_enabled {
                                "自动守护中"
                            } else {
                                "已暂停"
                            })
                            .size(12.0)
                            .color(if self.auto_block_enabled {
                                SEMANTIC_GREEN
                            } else {
                                TEXT_MUTED
                            }),
                        );

                        ui.add_space(8.0);

                        let demo_btn = egui::Button::new(
                            RichText::new("✨ 弹窗演示")
                                .size(12.5)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(ACCENT_BLUE)
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(94.0, 32.0));

                        if ui
                            .add(demo_btn)
                            .on_hover_text("在右下角弹出一个真实测试广告窗，观察 S→Z→A 推理秒关并记入日志")
                            .clicked()
                        {
                            self.test_ad_popup_open = true;
                            self.test_ad_spawned_at = Some(Instant::now());
                        }
                    });
                });

                ui.add_space(12.0);

                // ── 第二行：主导航 Tab + 快捷过滤胶囊 + 多维搜索框 ──
                ui.horizontal_wrapped(|ui| {
                    let pending_alerts = self.snapshot.pending_alerts_count;
                    let pending_ads = self.snapshot.pending_ads_count;
                    let active_fw_rules = self.snapshot.active_fw_rules_count;
                    let enabled_intel_feeds = self.snapshot.enabled_intel_feeds_count;

                    for (tab_variant, label) in [
                        (
                            WinTab::AppTiles,
                            format!("🧩 窗口管控 ({})", self.snapshot.live_windows.len()),
                        ),
                        (
                            WinTab::EdrAlerts,
                            format!("🛡️ EDR防御 ({})", pending_alerts),
                        ),
                        (
                            WinTab::AdBlocker,
                            format!("🚫 广告清理 ({})", pending_ads),
                        ),
                        (
                            WinTab::FirewallIps,
                            format!(
                                "🔥 防火墙/IPS ({}/{})",
                                active_fw_rules,
                                self.snapshot.ips_events.len()
                            ),
                        ),
                        (
                            WinTab::ThreatIntel,
                            format!(
                                "🔬 调查/情报 ({}/{})",
                                enabled_intel_feeds,
                                self.snapshot.intel_reports.len()
                            ),
                        ),
                        (
                            WinTab::Telemetry,
                            format!("📡 遥测 ({})", self.snapshot.active_sockets.len()),
                        ),
                        (
                            WinTab::History,
                            format!("🕒 日志 ({})", self.snapshot.blocked_history.len()),
                        ),
                    ] {
                        let active = self.current_tab == tab_variant;
                        let btn = egui::Button::new(
                            RichText::new(label).size(12.0).strong().color(if active {
                                Color32::WHITE
                            } else {
                                TEXT_SECONDARY
                            }),
                        )
                        .fill(if active { ACCENT_BLUE } else { BG_ELEVATED })
                        .rounding(Rounding::same(8.0))
                        .min_size(Vec2::new(98.0, 28.0));
                        if ui.add(btn).clicked() {
                            self.current_tab = tab_variant;
                        }
                    }

                    ui.separator();

                    // 上下文快捷筛选胶囊
                    match self.current_tab {
                        WinTab::AppTiles => {
                            for (flt, label) in [
                                (
                                    TileFilter::All,
                                    format!("全部 ({})", self.snapshot.live_windows.len()),
                                ),
                                (
                                    TileFilter::SuspiciousOrFloating,
                                    format!("🎯 置顶/可疑 ({})", suspicious_count),
                                ),
                                (
                                    TileFilter::ManagedOnly,
                                    format!("🛡️ 已设规则 ({})", managed_count),
                                ),
                            ] {
                                let active = self.tile_filter == flt;
                                let pill = egui::Button::new(
                                    RichText::new(label).size(11.5).color(if active {
                                        ACCENT_CYAN
                                    } else {
                                        TEXT_SECONDARY
                                    }),
                                )
                                .fill(if active {
                                    Color32::from_rgba_unmultiplied(6, 182, 212, 28)
                                } else {
                                    BG_CANVAS
                                })
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if active { ACCENT_CYAN } else { BORDER_SUBTLE },
                                ))
                                .rounding(Rounding::same(6.0))
                                .min_size(Vec2::new(68.0, 26.0));
                                if ui.add(pill).clicked() {
                                    self.tile_filter = flt;
                                }
                            }
                        }
                        WinTab::History => {
                            for (flt, label) in [
                                (HistoryFilter::All, "全部记录"),
                                (HistoryFilter::AutoOnly, "🤖 模型自动"),
                                (HistoryFilter::ManualOnly, "👆 手动学习"),
                            ] {
                                let active = self.history_filter == flt;
                                let pill = egui::Button::new(
                                    RichText::new(label).size(11.5).color(if active {
                                        ACCENT_CYAN
                                    } else {
                                        TEXT_SECONDARY
                                    }),
                                )
                                .fill(if active {
                                    Color32::from_rgba_unmultiplied(6, 182, 212, 28)
                                } else {
                                    BG_CANVAS
                                })
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if active { ACCENT_CYAN } else { BORDER_SUBTLE },
                                ))
                                .rounding(Rounding::same(6.0))
                                .min_size(Vec2::new(68.0, 26.0));
                                if ui.add(pill).clicked() {
                                    self.history_filter = flt;
                                }
                            }
                        }
                        WinTab::EdrAlerts
                        | WinTab::AdBlocker
                        | WinTab::FirewallIps
                        | WinTab::ThreatIntel
                        | WinTab::Telemetry => {
                            let rescan_btn = egui::Button::new(
                                RichText::new("🔄 深度重扫")
                                    .size(11.5)
                                    .color(ACCENT_CYAN),
                            )
                            .fill(BG_ELEVATED)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .rounding(Rounding::same(6.0))
                            .min_size(Vec2::new(82.0, 26.0));
                            if ui.add(rescan_btn).clicked() {
                                self.send_cmd(WorkerCmd::ForceFullTelemetryScan);
                                self.show_toast("⏳ 已提交全机深度扫描至后台引擎…");
                            }
                        }
                    }

                    // 右侧：刷新 + 搜索框（支持一键清空）
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(RichText::new("🔄").size(13.5))
                                    .fill(BG_ELEVATED)
                                    .rounding(Rounding::same(8.0))
                                    .min_size(Vec2::new(30.0, 28.0)),
                            )
                            .on_hover_text("立即重新扫描桌面窗口并运行决策模型")
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::RefreshWindows { notify: true });
                            self.show_toast("⏳ 正在后台刷新桌面窗口列表…");
                        }

                        if !self.search_query.is_empty() {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("✕").size(11.5).color(TEXT_SECONDARY),
                                    )
                                    .fill(BG_ELEVATED)
                                    .rounding(Rounding::same(6.0))
                                    .min_size(Vec2::new(24.0, 26.0)),
                                )
                                .on_hover_text("清空搜索 (Esc)")
                                .clicked()
                            {
                                self.search_query.clear();
                            }
                        }

                        ui.add(
                            egui::TextEdit::singleline(&mut self.search_query)
                                .hint_text("🔍 搜软件 / 标题 / PID / 路径...")
                                .desired_width(175.0),
                        );
                    });
                });
            });

        // ── 底部：选中窗口的实时 X-Ray 决策模型透视抽屉（可随时折叠/关闭） ──
        if self.current_tab == WinTab::AppTiles {
            if let Some(sel_id) = self.selected_window_id {
                if let Some(sel_win) = self
                    .snapshot
                    .live_windows
                    .iter()
                    .find(|w| w.window_id == sel_id)
                    .cloned()
                {
                    self.render_selected_window_drawer(ctx, &sel_win);
                } else {
                    self.selected_window_id = None;
                }
            }
        }

        // ── 主体画布 ──
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG_CANVAS)
                    .inner_margin(Margin::symmetric(20.0, 12.0)),
            )
            .show(ctx, |ui| match self.current_tab {
                WinTab::AppTiles => self.render_app_tiles_grid(ui),
                WinTab::History => self.render_history_tiles(ui),
                WinTab::EdrAlerts => self.render_edr_alerts_tab(ui),
                WinTab::AdBlocker => self.render_ad_blocker_tab(ui),
                WinTab::FirewallIps => self.render_firewall_ips_tab(ui),
                WinTab::ThreatIntel => self.render_threat_intel_tab(ui),
                WinTab::Telemetry => self.render_edr_telemetry_tab(ui),
            });

        // ── 独立悬浮 Toast ──
        self.render_floating_toast(ctx);
    }
}

impl SecurityAssistantApp {
    /// 双列大图标软件磁贴网格（整卡悬停反馈 + 点击展开底部 X-Ray 透视面板）
    fn render_app_tiles_grid(&mut self, ui: &mut egui::Ui) {
        let query = self.search_query.trim().to_lowercase();
        let filtered: Vec<RealDesktopWindow> = self
            .snapshot
            .live_windows
            .iter()
            .filter(|w| match self.tile_filter {
                TileFilter::All => true,
                TileFilter::SuspiciousOrFloating => {
                    w.is_ad_popup_candidate || w.is_topmost_floating || w.is_tool_or_popup
                }
                TileFilter::ManagedOnly => {
                    self.snapshot.auto_block_apps.contains(&w.app_name)
                        || self
                            .snapshot
                            .trusted_whitelist_windows
                            .contains(&w.window_id)
                        || w.is_ad_popup_candidate
                }
            })
            .filter(|w| {
                query.is_empty()
                    || w.app_name.to_lowercase().contains(&query)
                    || w.window_title.to_lowercase().contains(&query)
                    || w.exe_path.to_lowercase().contains(&query)
                    || w.pid.to_string().contains(&query)
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(56.0);
                ui.label(RichText::new("🧩").size(38.0));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(if self.snapshot.initialized {
                        "当前筛选或搜索条件下没有匹配的桌面窗口"
                    } else {
                        "⏳ 正在后台加载模型与扫描桌面窗口，请稍候…"
                    })
                    .size(13.5)
                    .color(TEXT_SECONDARY),
                );
                ui.add_space(8.0);
                if self.tile_filter != TileFilter::All || !self.search_query.is_empty() {
                    let reset_btn = egui::Button::new(
                        RichText::new("↺ 重置筛选与搜索")
                            .size(12.0)
                            .color(ACCENT_CYAN),
                    )
                    .fill(BG_ELEVATED)
                    .rounding(Rounding::same(8.0));
                    if ui.add(reset_btn).clicked() {
                        self.tile_filter = TileFilter::All;
                        self.search_query.clear();
                    }
                }
            });
            return;
        }

        let mut to_block_now: Option<RealDesktopWindow> = None;
        let mut to_trust_now: Option<RealDesktopWindow> = None;
        let mut toggle_app: Option<(String, bool)> = None;

        egui::ScrollArea::vertical()
            .id_salt("win11_tiles_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for pair in filtered.chunks(2) {
                    ui.columns(2, |cols| {
                        for (col_idx, win) in pair.iter().enumerate() {
                            let col_ui = &mut cols[col_idx];
                            let is_ad = win.is_ad_popup_candidate;
                            let is_whitelisted = self
                                .snapshot
                                .trusted_whitelist_windows
                                .contains(&win.window_id);
                            let is_selected = self.selected_window_id == Some(win.window_id);
                            let mut app_blocked =
                                self.snapshot.auto_block_apps.contains(&win.app_name) || is_ad;

                            let base_bg = if is_ad {
                                BG_CARD_AD
                            } else if is_selected {
                                Color32::from_rgb(22, 32, 48)
                            } else if app_blocked {
                                BG_CARD_MANAGED
                            } else {
                                BG_SURFACE
                            };

                            let border_c = if is_selected {
                                ACCENT_CYAN
                            } else if is_ad {
                                SEMANTIC_RED
                            } else if app_blocked {
                                SEMANTIC_GREEN
                            } else {
                                BORDER_SUBTLE
                            };

                            let frame_resp = egui::Frame::none()
                                .fill(base_bg)
                                .stroke(Stroke::new(
                                    if is_selected { 1.5_f32 } else { 1.0_f32 },
                                    border_c,
                                ))
                                .rounding(Rounding::same(12.0))
                                .inner_margin(Margin::symmetric(12.0, 10.0))
                                .show(col_ui, |ui| {
                                    ui.horizontal(|ui| {
                                        draw_app_icon_tile(ui, &win.app_name, is_ad, 44.0);
                                        ui.add_space(6.0);

                                        let (dom_intent, dom_prob) = win.decision.dominant_intent();

                                        // 中部三行高密度信息：1. 软件名 + PID + 置顶徽标 | 2. 窗口标题 | 3. 决策模型结论胶囊
                                        ui.vertical(|ui| {
                                            ui.spacing_mut().item_spacing.y = 3.0;
                                            ui.horizontal(|ui| {
                                                ui.spacing_mut().item_spacing.x = 5.0;
                                                ui.label(
                                                    RichText::new(short_text(&win.app_name, 14))
                                                        .size(14.0)
                                                        .strong()
                                                        .color(TEXT_PRIMARY),
                                                );
                                                ui.label(
                                                    RichText::new(format!("PID:{}", win.pid))
                                                        .size(10.5)
                                                        .color(TEXT_MUTED)
                                                        .monospace(),
                                                );
                                                if win.is_topmost_floating {
                                                    draw_tag_chip(
                                                        ui,
                                                        "📌置顶",
                                                        SEMANTIC_AMBER,
                                                        Color32::from_rgba_unmultiplied(
                                                            251, 191, 36, 26,
                                                        ),
                                                    );
                                                }
                                                if is_whitelisted {
                                                    draw_tag_chip(
                                                        ui,
                                                        "✓信任",
                                                        SEMANTIC_GREEN,
                                                        Color32::from_rgba_unmultiplied(
                                                            16, 185, 129, 26,
                                                        ),
                                                    );
                                                }
                                            });

                                            ui.label(
                                                RichText::new(format!(
                                                    "🪟 {}",
                                                    short_text(&win.window_title, 20)
                                                ))
                                                .size(11.5)
                                                .color(TEXT_SECONDARY),
                                            );

                                            let (tag_text, tag_color) = if is_ad {
                                                (
                                                    format!(
                                                        "🎯 {} ({:.0}% 置信度)",
                                                        win.plain_reason,
                                                        win.decision.confidence * 100.0
                                                    ),
                                                    SEMANTIC_RED,
                                                )
                                            } else if app_blocked {
                                                (
                                                    format!(
                                                        "🛡️ 自动拦弹窗 · {} {:.0}%",
                                                        dom_intent.code(),
                                                        dom_prob * 100.0
                                                    ),
                                                    SEMANTIC_GREEN,
                                                )
                                            } else {
                                                (
                                                    format!(
                                                        "✓ {} {} ({:.0}%)",
                                                        dom_intent.code(),
                                                        dom_intent.title(),
                                                        dom_prob * 100.0
                                                    ),
                                                    ACCENT_CYAN,
                                                )
                                            };

                                            ui.label(
                                                RichText::new(tag_text)
                                                    .size(11.0)
                                                    .strong()
                                                    .color(tag_color),
                                            );
                                        });

                                        // 右侧操作区：详情透视按钮 + 立即拦截 + 自动开关
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                ui.spacing_mut().item_spacing.x = 4.0;

                                                let close_btn = egui::Button::new(
                                                    RichText::new("🚫").size(13.5),
                                                )
                                                .fill(Color32::from_rgb(52, 22, 32))
                                                .rounding(Rounding::same(8.0))
                                                .min_size(Vec2::new(28.0, 28.0));

                                                if ui
                                                    .add(close_btn)
                                                    .on_hover_text(
                                                        "立即外科手术拦截此窗口，并通过 ArcSwap 在线学习更新模型策略",
                                                    )
                                                    .clicked()
                                                {
                                                    to_block_now = Some(win.clone());
                                                }

                                                if is_ad && !is_whitelisted {
                                                    let trust_btn = egui::Button::new(
                                                        RichText::new("✓")
                                                            .size(13.0)
                                                            .strong()
                                                            .color(SEMANTIC_GREEN),
                                                    )
                                                    .fill(Color32::from_rgb(18, 42, 36))
                                                    .rounding(Rounding::same(8.0))
                                                    .min_size(Vec2::new(28.0, 28.0));
                                                    if ui
                                                        .add(trust_btn)
                                                        .on_hover_text(
                                                            "标记为信任正常窗口，并向模型反馈 z0 合法交互",
                                                        )
                                                        .clicked()
                                                    {
                                                        to_trust_now = Some(win.clone());
                                                    }
                                                }

                                                let inspect_btn = egui::Button::new(
                                                    RichText::new(if is_selected {
                                                        "🔽"
                                                    } else {
                                                        "🔍"
                                                    })
                                                    .size(12.5),
                                                )
                                                .fill(if is_selected {
                                                    ACCENT_BLUE
                                                } else {
                                                    BG_ELEVATED
                                                })
                                                .rounding(Rounding::same(8.0))
                                                .min_size(Vec2::new(28.0, 28.0));

                                                if ui
                                                    .add(inspect_btn)
                                                    .on_hover_text(
                                                        "展开/收起底部 S→Z→A 决策模型 12 维特征透视面板",
                                                    )
                                                    .clicked()
                                                {
                                                    self.selected_window_id = if is_selected {
                                                        None
                                                    } else {
                                                        Some(win.window_id)
                                                    };
                                                }

                                                if win11_toggle_switch(ui, &mut app_blocked, 0.95)
                                                    .on_hover_text("开启/关闭该软件弹窗自动拦截")
                                                    .changed()
                                                {
                                                    toggle_app = Some((
                                                        win.app_name.clone(),
                                                        app_blocked,
                                                    ));
                                                }
                                            },
                                        );
                                    });
                                });

                            // 整卡悬停高亮与左键点击展开详情抽屉
                            let card_rect = frame_resp.response.rect;
                            let card_click = col_ui.interact(
                                card_rect,
                                Id::new(("win_card_click", win.window_id)),
                                Sense::click(),
                            );
                            if card_click.hovered() {
                                col_ui.painter().rect_stroke(
                                    card_rect,
                                    Rounding::same(12.0),
                                    Stroke::new(1.2_f32, BORDER_HOVER),
                                );
                            }
                            if card_click.clicked() {
                                self.selected_window_id = if is_selected {
                                    None
                                } else {
                                    Some(win.window_id)
                                };
                            }
                        }
                    });
                    ui.add_space(8.0);
                }
            });

        if let Some((app, enable)) = toggle_app {
            if enable {
                Arc::make_mut(&mut self.snapshot)
                    .auto_block_apps
                    .insert(app.clone());
                self.show_toast(format!("🛡️ 已开启「{}」弹窗自动屏蔽", app));
            } else {
                Arc::make_mut(&mut self.snapshot)
                    .auto_block_apps
                    .remove(&app);
                self.show_toast(format!("已关闭「{}」弹窗自动屏蔽", app));
            }
            self.send_cmd(WorkerCmd::ToggleAppAutoBlock { app, enable });
        }

        if let Some(win) = to_trust_now {
            self.send_cmd(WorkerCmd::TrustWindow(win));
        }

        if let Some(win) = to_block_now {
            self.send_cmd(WorkerCmd::BlockWindowNow(win));
        }
    }

    /// 底部 X-Ray 透视面板：展示选中窗口的完整进程血缘、文件路径、12 维特征向量、MoE 潜空间分布 Z_t 与动作代价 A_t
    fn render_selected_window_drawer(&mut self, ctx: &egui::Context, win: &RealDesktopWindow) {
        let mut do_block = false;
        let mut do_trust = false;
        let mut do_close_drawer = false;
        let mut copied_path = false;

        egui::TopBottomPanel::bottom("ardot_xray_inspector_drawer")
            .frame(
                egui::Frame::none()
                    .fill(BG_SURFACE)
                    .stroke(Stroke::new(1.2_f32, ACCENT_CYAN))
                    .inner_margin(Margin::symmetric(20.0, 12.0)),
            )
            .show(ctx, |ui| {
                // 抽屉顶栏：进程信息 + 文件路径 + 快捷动作按钮
                ui.horizontal(|ui| {
                    draw_app_icon_tile(ui, &win.app_name, win.is_ad_popup_candidate, 32.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "🔬 模型实时透视: {}  |  窗口: {}",
                                    win.app_name,
                                    short_text(&win.window_title, 28)
                                ))
                                .size(13.0)
                                .strong()
                                .color(TEXT_PRIMARY),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "(PID:{} · PPID:{} · TID:{} · HWND:0x{:X} · 坐标:{},{} {}×{})",
                                    win.pid,
                                    win.parent_pid,
                                    win.thread_id,
                                    win.window_id,
                                    win.bounds.0,
                                    win.bounds.1,
                                    win.bounds.2,
                                    win.bounds.3
                                ))
                                .size(11.0)
                                .color(TEXT_SECONDARY)
                                .monospace(),
                            );
                        });

                        let path_resp = ui.add(
                            egui::Label::new(
                                RichText::new(format!("📁 可执行路径 (点击复制): {}", win.exe_path))
                                    .size(11.5)
                                    .color(ACCENT_CYAN)
                                    .monospace(),
                            )
                            .sense(Sense::click()),
                        );
                        if path_resp.hovered() {
                            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                        }
                        if path_resp.clicked() {
                            ui.ctx().copy_text(win.exe_path.clone());
                            copied_path = true;
                        }
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("✕ 收起").size(11.5).color(TEXT_SECONDARY),
                                )
                                .fill(BG_ELEVATED)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            do_close_drawer = true;
                        }

                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("🚫 立即拦截 (学习)").size(11.5).color(Color32::WHITE),
                                )
                                .fill(SEMANTIC_RED)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            do_block = true;
                        }

                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("✓ 信任白名单").size(11.5).color(Color32::WHITE),
                                )
                                .fill(SEMANTIC_GREEN)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            do_trust = true;
                        }
                    });
                });

                ui.add_space(6.0);

                // 三列模型推理分解：1. 12维特征 s_t | 2. 潜空间意图分布 Z_t | 3. 期望风险损失与外科手术决策 A_t
                let f = &win.frame_features;
                ui.columns(3, |cols| {
                    // 列 1：12 维特征采集峰值
                    egui::Frame::none()
                        .fill(BG_ELEVATED)
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 8.0))
                        .show(&mut cols[0], |ui| {
                            ui.label(
                                RichText::new("① 12维状态特征采集 s_t ∈ [0,1]^12")
                                    .size(11.5)
                                    .strong()
                                    .color(ACCENT_CYAN),
                            );
                            ui.add_space(3.0);
                            draw_progress_row(ui, "s[0] 键鼠空闲衰减", f[0], SEMANTIC_AMBER);
                            draw_progress_row(ui, "s[1] 置顶无边框掩码", f[1], SEMANTIC_RED);
                            draw_progress_row(ui, "s[3] 屏幕落点区域", f[3], SEMANTIC_AMBER);
                            draw_progress_row(ui, "s[5] 寄生异构调用栈", f[5], SEMANTIC_RED);
                            draw_progress_row(ui, "s[7] 二进制香农熵", f[7], ACCENT_CYAN);
                            draw_progress_row(ui, "s[9] 临时目录落地", f[9], SEMANTIC_RED);
                        });

                    // 列 2：内嵌 Micro-LM + Mosaic 汉明记忆 + MoE 潜空间意图 Z_t
                    egui::Frame::none()
                        .fill(BG_ELEVATED)
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 8.0))
                        .show(&mut cols[1], |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "② Qwen2.5 + 280-Tree GBDT & MLP Z_t (Jev分:{:.1}/10 · 汉明:{:.0}%)",
                                    win.decision.jev_threat_score,
                                    win.decision.mosaic_hamming_sim * 100.0
                                ))
                                .size(11.5)
                                .strong()
                                .color(ACCENT_CYAN),
                            );
                            ui.add_space(3.0);
                            draw_progress_row(
                                ui,
                                "Jev-S1 noul 威胁概率",
                                win.decision.jev_noul_prob,
                                if win.decision.jev_noul_prob > 0.5 {
                                    SEMANTIC_RED
                                } else {
                                    SEMANTIC_GREEN
                                },
                            );
                            draw_progress_row(
                                ui,
                                "Qwen2.5 L0 语义激活度",
                                win.decision.lm_semantic_embed[2],
                                SEMANTIC_AMBER,
                            );
                            let probs = &win.decision.intent_probs;
                            for (intent, p, col) in [
                                (LatentIntent::Z0LegitInteraction, probs[0], SEMANTIC_GREEN),
                                (LatentIntent::Z1HostBundledAd, probs[1], SEMANTIC_AMBER),
                                (LatentIntent::Z2ParasiticAdModule, probs[2], SEMANTIC_RED),
                                (LatentIntent::Z3SilentDropper, probs[3], SEMANTIC_RED),
                            ] {
                                draw_progress_row(
                                    ui,
                                    &format!("{} {}", intent.code(), intent.title()),
                                    p,
                                    col,
                                );
                            }
                        });

                    // 列 3：贝叶斯最小风险决策头 A_t = argmin(C × Z_t)
                    egui::Frame::none()
                        .fill(BG_ELEVATED)
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 8.0))
                        .show(&mut cols[2], |ui| {
                            let act = win.decision.chosen_action;
                            ui.label(
                                RichText::new(format!(
                                    "③ 最优决策 A_t = {} ({})",
                                    act.code(),
                                    act.cn_name()
                                ))
                                .size(11.5)
                                .strong()
                                .color(if win.is_ad_popup_candidate {
                                    SEMANTIC_RED
                                } else {
                                    SEMANTIC_GREEN
                                }),
                            );
                            ui.add_space(3.0);
                            for a in PolicyAction::ALL {
                                let loss = win.decision.expected_losses[a as usize];
                                let chosen = a == act;
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{}{} {}",
                                            if chosen { "▶ " } else { "  " },
                                            a.code(),
                                            a.cn_name()
                                        ))
                                        .size(11.0)
                                        .strong()
                                        .color(if chosen {
                                            ACCENT_CYAN
                                        } else {
                                            TEXT_SECONDARY
                                        })
                                        .monospace(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(
                                            RichText::new(format!("E(L)={:.2}", loss))
                                                .size(10.5)
                                                .color(if chosen {
                                                    TEXT_PRIMARY
                                                } else {
                                                    TEXT_MUTED
                                                })
                                                .monospace(),
                                        );
                                    });
                                });
                            }
                        });
                });
            });

        if copied_path {
            self.show_toast(format!("📋 已复制路径: {}", short_text(&win.exe_path, 28)));
        }
        if do_close_drawer {
            self.selected_window_id = None;
        }
        if do_trust {
            self.send_cmd(WorkerCmd::TrustWindow(win.clone()));
        }
        if do_block {
            self.selected_window_id = None;
            self.send_cmd(WorkerCmd::BlockWindowNow(win.clone()));
        }
    }

    /// 拦截日志卡片：清晰输出【拦截进程信息 (进程名/PID/PPID/TID/HWND)】、【完整文件路径 (`exe_path`)】与【全部底层系统调用】
    fn render_history_tiles(&mut self, ui: &mut egui::Ui) {
        let query = self.search_query.trim().to_lowercase();
        let filtered_records: Vec<BlockedAdRecord> = self
            .snapshot
            .blocked_history
            .iter()
            .filter(|rec| match self.history_filter {
                HistoryFilter::All => true,
                HistoryFilter::AutoOnly => rec.model_decision_tag.starts_with("模型自动"),
                HistoryFilter::ManualOnly => rec.model_decision_tag.starts_with("手动拦截"),
            })
            .filter(|rec| {
                query.is_empty()
                    || rec.app_name.to_lowercase().contains(&query)
                    || rec.window_title.to_lowercase().contains(&query)
                    || rec.exe_path.to_lowercase().contains(&query)
                    || rec.process_info.to_lowercase().contains(&query)
            })
            .cloned()
            .collect();

        if self.snapshot.blocked_history.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(RichText::new("🛡️").size(42.0));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "暂无拦截日志（可点击右上角「✨ 弹窗演示」或软件卡片上的 🚫 体验模型自动拦截与日志落盘）",
                    )
                    .size(13.5)
                    .color(TEXT_SECONDARY),
                );
            });
            return;
        }

        // 日志页顶部快捷操作条：显示落盘文件名 + 一键复制全部日志 + 清理已恢复条目
        let mut clear_restored = false;
        let mut copy_all_logs = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "📄 实时同步落盘文件: 拦截日志.log  ·  共 {} 条匹配记录",
                    filtered_records.len()
                ))
                .size(12.0)
                .color(TEXT_SECONDARY),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self
                    .snapshot
                    .blocked_history
                    .iter()
                    .any(|r| r.restored_by_user)
                {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🧹 清除已恢复记录")
                                    .size(11.5)
                                    .color(TEXT_SECONDARY),
                            )
                            .fill(BG_ELEVATED)
                            .rounding(Rounding::same(6.0)),
                        )
                        .clicked()
                    {
                        clear_restored = true;
                    }
                }

                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("📋 复制全部日志")
                                .size(11.5)
                                .color(ACCENT_CYAN),
                        )
                        .fill(BG_ELEVATED)
                        .rounding(Rounding::same(6.0)),
                    )
                    .clicked()
                {
                    copy_all_logs = true;
                }
            });
        });
        ui.add_space(6.0);

        if clear_restored {
            self.send_cmd(WorkerCmd::ClearRestoredHistory);
        }
        if copy_all_logs {
            let full_log = filtered_records
                .iter()
                .map(|r| {
                    format!(
                        "[{}] [{}] 进程: {} | 路径: {} | 窗口: {}",
                        r.time_str, r.model_decision_tag, r.process_info, r.exe_path, r.window_title
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            ui.ctx().copy_text(full_log);
            self.show_toast(format!("📋 已复制 {} 条完整拦截日志", filtered_records.len()));
        }

        let mut restore_id: Option<u64> = None;
        let mut copied_path: Option<String> = None;

        egui::ScrollArea::vertical()
            .id_salt("win11_history_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for rec in &filtered_records {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(12.0))
                        .inner_margin(Margin::symmetric(14.0, 10.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                draw_app_icon_tile(ui, &rec.app_name, true, 44.0);
                                ui.add_space(8.0);

                                // 中间：清晰输出（1. 模型决策与时间戳 | 2. 进程信息 | 3. 可点击复制的文件路径 | 4. 拦截窗口与底层执行动作）
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 3.0;
                                    ui.horizontal(|ui| {
                                        ui.colored_label(
                                            SEMANTIC_GREEN,
                                            RichText::new(format!("[{}]", rec.model_decision_tag))
                                                .size(12.0)
                                                .strong(),
                                        );
                                        ui.label(
                                            RichText::new(&rec.time_str)
                                                .size(11.5)
                                                .color(TEXT_MUTED)
                                                .monospace(),
                                        );
                                    });

                                    ui.label(
                                        RichText::new(format!("⚙️ 进程信息: {}", rec.process_info))
                                            .size(12.5)
                                            .strong()
                                            .color(TEXT_PRIMARY),
                                    );

                                    let path_resp = ui
                                        .add(
                                            egui::Label::new(
                                                RichText::new(format!(
                                                    "📁 文件路径: {}",
                                                    rec.exe_path
                                                ))
                                                .size(12.0)
                                                .color(ACCENT_CYAN)
                                                .monospace(),
                                            )
                                            .sense(Sense::click()),
                                        )
                                        .on_hover_text("点击复制完整可执行文件路径");
                                    if path_resp.hovered() {
                                        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                                    }
                                    if path_resp.clicked() {
                                        ui.ctx().copy_text(rec.exe_path.clone());
                                        copied_path = Some(rec.exe_path.clone());
                                    }

                                    let exec_summary = rec.actuator_steps.join("  →  ");
                                    ui.label(
                                        RichText::new(format!(
                                            "🪟 窗口: {}  |  🔧 {}",
                                            rec.window_title, exec_summary
                                        ))
                                        .size(11.5)
                                        .color(TEXT_SECONDARY),
                                    );
                                });

                                // 右侧：复制路径图标按钮 + 恢复按钮
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if rec.restored_by_user {
                                        draw_tag_chip(
                                            ui,
                                            "✓ 已恢复并加入白名单",
                                            SEMANTIC_GREEN,
                                            Color32::from_rgba_unmultiplied(16, 185, 129, 28),
                                        );
                                    } else {
                                        let btn = egui::Button::new(
                                            RichText::new("↩ 恢复")
                                                .size(12.0)
                                                .color(Color32::WHITE),
                                        )
                                        .fill(Color32::from_rgb(51, 65, 85))
                                        .rounding(Rounding::same(8.0))
                                        .min_size(Vec2::new(66.0, 28.0));
                                        if ui
                                            .add(btn)
                                            .on_hover_text("恢复显示并通过 ArcSwap 在线修正模型策略为 z0 合法交互")
                                            .clicked()
                                        {
                                            restore_id = Some(rec.record_id);
                                        }
                                    }

                                    ui.add_space(4.0);
                                    let copy_btn = egui::Button::new(
                                        RichText::new("📋").size(13.5),
                                    )
                                    .fill(BG_ELEVATED)
                                    .rounding(Rounding::same(8.0))
                                    .min_size(Vec2::new(30.0, 28.0));
                                    if ui
                                        .add(copy_btn)
                                        .on_hover_text("复制完整进程与文件路径信息")
                                        .clicked()
                                    {
                                        let clip_text = format!(
                                            "[{}] 进程: {} | 路径: {}",
                                            rec.model_decision_tag, rec.process_info, rec.exe_path
                                        );
                                        ui.ctx().copy_text(clip_text);
                                        copied_path = Some(rec.exe_path.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(8.0);
                }
            });

        if let Some(p) = copied_path {
            self.show_toast(format!("📋 已复制路径: {}", short_text(&p, 26)));
        }

        if let Some(rid) = restore_id {
            self.send_cmd(WorkerCmd::RestoreAndTrust(rid));
        }
    }

    /// Windows/跨平台 EDR 主动防御与实时告警面板
    fn render_edr_alerts_tab(&mut self, ui: &mut egui::Ui) {
        let query = self.search_query.trim().to_lowercase();
        let mut pending_remediate: Option<(u64, PolicyAction)> = None;
        let mut pending_resume: Option<(u32, String, String)> = None;

        ui.horizontal_wrapped(|ui| {
            draw_metric_pill(
                ui,
                "活跃进程",
                &self.snapshot.live_processes_count.to_string(),
                ACCENT_CYAN,
            );
            draw_metric_pill(
                ui,
                "网络连接",
                &self.snapshot.active_sockets.len().to_string(),
                ACCENT_BLUE,
            );
            draw_metric_pill(
                ui,
                "告警总数",
                &self.snapshot.alerts.len().to_string(),
                if self.snapshot.alerts.iter().any(|a| !a.auto_mitigated) {
                    SEMANTIC_RED
                } else {
                    SEMANTIC_GREEN
                },
            );
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("🛡️ 一键安全加固")
                            .size(12.0)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(ACCENT_BLUE)
                    .rounding(Rounding::same(8.0)),
                )
                .clicked()
            {
                self.send_cmd(WorkerCmd::HardenAllExposedVulnerabilities);
                self.show_toast("⏳ 正在后台执行一键端口收敛与安全加固…");
            }
            let daemon_label = if self.snapshot.daemon_agent_installed {
                "🟢 后台守护运行中 (点击停用)"
            } else {
                "⚪ 安装系统级后台守护"
            };
            if ui
                .add(
                    egui::Button::new(RichText::new(daemon_label).size(11.5).color(TEXT_PRIMARY))
                        .fill(BG_ELEVATED)
                        .rounding(Rounding::same(8.0)),
                )
                .clicked()
            {
                self.send_cmd(WorkerCmd::ToggleEdrDaemon);
            }
        });
        ui.add_space(8.0);

        let filtered: Vec<_> = self
            .snapshot
            .alerts
            .iter()
            .filter(|a| {
                query.is_empty()
                    || a.title.to_lowercase().contains(&query)
                    || a.process_name.to_lowercase().contains(&query)
                    || a.exe_path.to_lowercase().contains(&query)
                    || a.cmdline.to_lowercase().contains(&query)
                    || a.cwd.to_lowercase().contains(&query)
                    || a.ancestry_chain.to_lowercase().contains(&query)
                    || a.sha256_hex.to_lowercase().contains(&query)
                    || a.pid.to_string().contains(&query)
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            egui::Frame::none()
                .fill(BG_SURFACE)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .rounding(Rounding::same(12.0))
                .inner_margin(Margin::same(18.0))
                .show(ui, |ui| {
                    ui.colored_label(
                        SEMANTIC_GREEN,
                        RichText::new("✓ 当前未发现未处理的 EDR 高危行为告警（进程/C2/驻留/凭据均受监控）")
                            .size(13.5)
                            .strong(),
                    );
                });
        } else {
            egui::ScrollArea::vertical()
                .id_salt("win_edr_alerts_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for alert in &filtered {
                        let sev_color = match alert.severity {
                            ThreatSeverity::Critical | ThreatSeverity::High => SEMANTIC_RED,
                            ThreatSeverity::Medium => SEMANTIC_AMBER,
                            ThreatSeverity::Low | ThreatSeverity::Safe => SEMANTIC_GREEN,
                        };
                        egui::Frame::none()
                            .fill(BG_SURFACE)
                            .stroke(Stroke::new(
                                1.0_f32,
                                if alert.auto_mitigated {
                                    BORDER_SUBTLE
                                } else {
                                    sev_color
                                },
                            ))
                            .rounding(Rounding::same(12.0))
                            .inner_margin(Margin::symmetric(14.0, 10.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        sev_color,
                                        RichText::new(format!(
                                            "[#{:?}] {}",
                                            alert.severity, alert.title
                                        ))
                                        .size(13.0)
                                        .strong(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(
                                            RichText::new(&alert.timestamp)
                                                .size(11.0)
                                                .color(TEXT_MUTED)
                                                .monospace(),
                                        );
                                    });
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "进程: {} (PID={} · PPID={}) | 签名: {} | 路径: {}",
                                        alert.process_name,
                                        alert.pid,
                                        alert.ppid,
                                        alert.code_signer,
                                        alert.exe_path
                                    ))
                                    .size(11.5)
                                    .color(TEXT_SECONDARY),
                                );
                                let mut loc_parts = Vec::new();
                                if !alert.ancestry_chain.is_empty() {
                                    loc_parts.push(format!("谱系: {}", alert.ancestry_chain));
                                }
                                if !alert.cwd.is_empty() {
                                    loc_parts.push(format!("CWD: {}", alert.cwd));
                                }
                                if !alert.entry_script_or_config.is_empty() {
                                    loc_parts.push(format!("入口: {}", alert.entry_script_or_config));
                                }
                                if !alert.sha256_hex.is_empty() {
                                    let short_sha: String = alert.sha256_hex.chars().take(12).collect();
                                    loc_parts.push(format!("SHA256: {}…", short_sha));
                                }
                                if !alert.provenance_hint.is_empty() {
                                    loc_parts.push(alert.provenance_hint.clone());
                                }
                                if !loc_parts.is_empty() {
                                    ui.label(
                                        RichText::new(loc_parts.join(" | "))
                                            .size(10.5)
                                            .color(TEXT_MUTED)
                                            .monospace(),
                                    );
                                }
                                ui.label(
                                    RichText::new(&alert.short_summary)
                                        .size(12.0)
                                        .color(TEXT_PRIMARY),
                                );
                                if !alert.mitigation_summary.is_empty() {
                                    ui.colored_label(
                                        SEMANTIC_GREEN,
                                        RichText::new(format!("处置结果: {}", alert.mitigation_summary))
                                            .size(11.5),
                                    );
                                }
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("✓ A0 加白").size(11.5).color(SEMANTIC_GREEN),
                                            )
                                            .fill(BG_ELEVATED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        pending_remediate =
                                            Some((alert.alert_id, PolicyAction::A0PassAndUntag));
                                    }
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("⏸ A2 冻结").size(11.5).color(SEMANTIC_AMBER),
                                            )
                                            .fill(BG_ELEVATED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        pending_remediate =
                                            Some((alert.alert_id, PolicyAction::A2SurgicalMute));
                                    }
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("▶ 解冻").size(11.5).color(ACCENT_CYAN),
                                            )
                                            .fill(BG_ELEVATED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        pending_resume = Some((
                                            alert.pid,
                                            alert.process_name.clone(),
                                            alert.exe_path.clone(),
                                        ));
                                    }
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("🚫 A3 终止+禁生")
                                                    .size(11.5)
                                                    .color(Color32::WHITE),
                                            )
                                            .fill(SEMANTIC_RED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        pending_remediate =
                                            Some((alert.alert_id, PolicyAction::A3ProcessIsolate));
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }
                });
        }

        if let Some((aid, action)) = pending_remediate {
            self.send_cmd(WorkerCmd::ExecuteAlertRemediation(aid, action));
        }
        if let Some((pid, pname, epath)) = pending_resume {
            self.send_cmd(WorkerCmd::ResumeFrozenProcess(pid, pname, epath));
        }
    }

    /// 广告清理、hosts 屏蔽与外联拦截面板
    fn render_ad_blocker_tab(&mut self, ui: &mut egui::Ui) {
        let mut clean_idx: Option<usize> = None;
        let mut block_conn_idx: Option<usize> = None;

        egui::Frame::none()
            .fill(BG_SURFACE)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let hosts_active = self.snapshot.hosts_status.active_in_etc_hosts;
                    draw_metric_pill(
                        ui,
                        "系统 hosts 拦截",
                        if hosts_active { "已启用" } else { "未启用" },
                        if hosts_active {
                            SEMANTIC_GREEN
                        } else {
                            SEMANTIC_AMBER
                        },
                    );
                    draw_metric_pill(
                        ui,
                        "拦截规则数",
                        &self.snapshot.hosts_status.rule_count.to_string(),
                        ACCENT_CYAN,
                    );
                    draw_metric_pill(
                        ui,
                        "已释放空间",
                        &format!(
                            "{:.2} MB",
                            (self.snapshot.total_reclaimed_bytes as f64) / (1024.0 * 1024.0)
                        ),
                        SEMANTIC_GREEN,
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(if hosts_active {
                                    "🛡 关闭系统 hosts 广告屏蔽"
                                } else {
                                    "🛡 开启系统 hosts 广告屏蔽 (UAC/提权)"
                                })
                                .size(11.5)
                                .color(Color32::WHITE),
                            )
                            .fill(if hosts_active { BG_ELEVATED } else { ACCENT_BLUE })
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.send_cmd(WorkerCmd::ToggleHostsAdShield);
                        self.show_toast("⏳ 正在后台更新系统 hosts 广告拦截盾…");
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🧹 一键清理全部广告残留")
                                    .size(11.5)
                                    .color(Color32::WHITE),
                            )
                            .fill(SEMANTIC_RED)
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.send_cmd(WorkerCmd::CleanAllAdArtifacts);
                        self.show_action_toast("⏳ 正在后台清理全部广告残留…", true);
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("新增广告黑名单域名:")
                            .size(11.5)
                            .color(TEXT_SECONDARY),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ad_domain_input)
                            .hint_text("例如 ads.example.com")
                            .desired_width(220.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(RichText::new("+ 添加规则").size(11.5).color(ACCENT_CYAN))
                                .fill(BG_ELEVATED)
                                .rounding(Rounding::same(6.0)),
                        )
                        .clicked()
                    {
                        let dom = self.ad_domain_input.trim().to_string();
                        if !dom.is_empty() {
                            self.send_cmd(WorkerCmd::AddCustomAdDomain(dom));
                        }
                    }
                });
                if !self.snapshot.ad_last_action_message.is_empty() {
                    ui.label(
                        RichText::new(&self.snapshot.ad_last_action_message)
                            .size(11.0)
                            .color(TEXT_MUTED),
                    );
                }
            });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("win_ad_cleaner_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "📦 广告残留与自启动项 ({})",
                        self.snapshot.ad_cleanup_candidates.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for (idx, item) in self.snapshot.ad_cleanup_candidates.iter().enumerate() {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(10.0))
                        .inner_margin(Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} ({:.1} KB · {:.0}% 置信)",
                                            item.title,
                                            item.size_bytes as f64 / 1024.0,
                                            item.ad_model_prob * 100.0
                                        ))
                                        .size(12.0)
                                        .strong()
                                        .color(if item.cleaned {
                                            SEMANTIC_GREEN
                                        } else {
                                            TEXT_PRIMARY
                                        }),
                                    );
                                    ui.label(
                                        RichText::new(&item.path)
                                            .size(11.0)
                                            .color(TEXT_SECONDARY)
                                            .monospace(),
                                    );
                                    ui.label(
                                        RichText::new(&item.reason)
                                            .size(11.0)
                                            .color(TEXT_MUTED),
                                    );
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if item.cleaned {
                                        ui.colored_label(SEMANTIC_GREEN, "✓ 已清理");
                                    } else if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("🗑 清理").size(11.5).color(Color32::WHITE),
                                            )
                                            .fill(SEMANTIC_RED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        clean_idx = Some(idx);
                                    }
                                });
                            });
                        });
                    ui.add_space(6.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "🌐 广告外联活动检测 ({})",
                        self.snapshot.ad_connections.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for (idx, conn) in self.snapshot.ad_connections.iter().enumerate() {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(10.0))
                        .inner_margin(Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} (PID={}) -> {} [{}]",
                                            conn.process_name,
                                            conn.pid,
                                            conn.remote_endpoint,
                                            conn.matched_domain_or_model
                                        ))
                                        .size(12.0)
                                        .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(&conn.reason)
                                            .size(11.0)
                                            .color(TEXT_SECONDARY),
                                    );
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if conn.blocked {
                                        ui.colored_label(SEMANTIC_GREEN, "✓ 已阻断");
                                    } else if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("🚫 阻断").size(11.5).color(Color32::WHITE),
                                            )
                                            .fill(SEMANTIC_RED)
                                            .rounding(Rounding::same(6.0)),
                                        )
                                        .clicked()
                                    {
                                        block_conn_idx = Some(idx);
                                    }
                                });
                            });
                        });
                    ui.add_space(6.0);
                }
            });

        if let Some(idx) = clean_idx {
            self.send_cmd(WorkerCmd::CleanSingleAdArtifact(idx));
        }
        if let Some(idx) = block_conn_idx {
            self.send_cmd(WorkerCmd::BlockAdConnection(idx));
        }
    }

    /// 主机防火墙与入侵防御 (Firewall & IPS) 控制面板（零 UI 阻塞，异步 Worker 执行）
    fn render_firewall_ips_tab(&mut self, ui: &mut egui::Ui) {
        let mut toggle_rule_id: Option<String> = None;
        let mut remove_rule_id: Option<String> = None;
        let mut allowlist_ip: Option<String> = None;

        let ips_prevent = self.snapshot.fw_ips_mode == IpsMode::PreventAutoBlock;
        let active_rules = self
            .snapshot
            .firewall_rules
            .iter()
            .filter(|r| r.enabled)
            .count();

        egui::Frame::none()
            .fill(BG_SURFACE)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    draw_metric_pill(
                        ui,
                        "OS防火墙",
                        if self.snapshot.fw_os_status.os_firewall_enabled {
                            "已开启"
                        } else {
                            "未开启"
                        },
                        if self.snapshot.fw_os_status.os_firewall_enabled {
                            SEMANTIC_GREEN
                        } else {
                            SEMANTIC_AMBER
                        },
                    );
                    draw_metric_pill(
                        ui,
                        "IPS模式",
                        if ips_prevent { "主动阻断" } else { "仅检测" },
                        if ips_prevent {
                            ACCENT_CYAN
                        } else {
                            SEMANTIC_AMBER
                        },
                    );
                    draw_metric_pill(ui, "活跃规则", &active_rules.to_string(), ACCENT_BLUE);
                    draw_metric_pill(
                        ui,
                        "累计拦截",
                        &self.snapshot.fw_total_packets_blocked.to_string(),
                        SEMANTIC_RED,
                    );

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(if ips_prevent {
                                    "🛡 切换为仅检测模式"
                                } else {
                                    "🛡 开启 IPS 自动阻断防御"
                                })
                                .size(11.5)
                                .color(Color32::WHITE),
                            )
                            .fill(if ips_prevent { BG_ELEVATED } else { ACCENT_BLUE })
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.send_cmd(WorkerCmd::ToggleIpsMode);
                        self.show_toast("⏳ 正在切换 IPS 工作模式…");
                    }

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🧱 一键封堵高危端口")
                                    .size(11.5)
                                    .color(Color32::WHITE),
                            )
                            .fill(SEMANTIC_RED)
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.send_cmd(WorkerCmd::HardenFirewallPorts);
                        self.show_toast("⏳ 正在封堵 6379/445/3389/4444/23 等高危端口…");
                    }

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("📤 导出规则脚本")
                                    .size(11.5)
                                    .color(TEXT_PRIMARY),
                            )
                            .fill(BG_ELEVATED)
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.send_cmd(WorkerCmd::SyncOsFirewall(false));
                        self.show_toast("⏳ 正在导出防火墙策略脚本…");
                    }

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(if self.fw_show_kernel_drawer {
                                    "▾ 内核详情"
                                } else {
                                    "▸ 内核详情"
                                })
                                .size(11.5)
                                .color(ACCENT_CYAN),
                            )
                            .fill(BG_CANVAS)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.fw_show_kernel_drawer = !self.fw_show_kernel_drawer;
                    }
                });

                if self.fw_show_kernel_drawer {
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "后端: {} | 配置状态: {} | 消息: {}",
                                self.snapshot.fw_os_status.backend_name,
                                self.snapshot.fw_os_status.stealth_or_profile,
                                self.snapshot.fw_last_sync_message
                            ))
                            .size(11.0)
                            .color(TEXT_SECONDARY),
                        );
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("⚡ UAC提权应用至 OS 防火墙")
                                        .size(11.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(ACCENT_BLUE)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::SyncOsFirewall(true));
                            self.show_toast("⏳ 正在请求提权下发至 Windows Defender Firewall…");
                        }
                    });
                }

                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("自定义拦截:")
                            .size(11.5)
                            .color(TEXT_SECONDARY),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.fw_ip_input)
                            .hint_text("远端 IP/CIDR 或 *")
                            .desired_width(140.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.fw_port_input)
                            .hint_text("端口 (0=全部)")
                            .desired_width(90.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("➕ 添加阻断规则")
                                    .size(11.5)
                                    .color(Color32::WHITE),
                            )
                            .fill(ACCENT_BLUE)
                            .rounding(Rounding::same(6.0)),
                        )
                        .clicked()
                    {
                        let ip = if self.fw_ip_input.trim().is_empty() {
                            "*".to_string()
                        } else {
                            self.fw_ip_input.trim().to_string()
                        };
                        let port = self.fw_port_input.trim().parse::<u16>().unwrap_or(0);
                        if ip == "*" && port == 0 {
                            self.show_toast("请指定至少一个目标 IP 或具体端口号，防止全网断连");
                        } else {
                            self.send_cmd(WorkerCmd::AddFirewallBlockRule {
                                name: format!("自定义阻断 {}:{}", ip, port),
                                remote_ip: ip,
                                port,
                            });
                            self.fw_ip_input.clear();
                            self.fw_port_input.clear();
                        }
                    }

                    ui.separator();
                    ui.label(
                        RichText::new("IPS攻防演练:")
                            .size(11.5)
                            .color(TEXT_SECONDARY),
                    );
                    for (kind, title) in [
                        ("revshell", "🧪 反弹Shell"),
                        ("shellcode", "🧪 Shellcode"),
                        ("redis_rce", "🧪 Redis RCE"),
                        ("sqli_jndi", "🧪 SQLi/JNDI"),
                        ("benign", "✅ 正常流量"),
                    ] {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(title).size(11.0).color(TEXT_PRIMARY),
                                )
                                .fill(BG_ELEVATED)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::RunIpsDrill(kind.to_string()));
                        }
                    }
                });
            });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("win_fw_ips_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "防火墙策略规则 ({} 条)",
                        self.snapshot.firewall_rules.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for rule in &self.snapshot.firewall_rules {
                    let border_c = if !rule.enabled {
                        BORDER_SUBTLE
                    } else if rule.action == FirewallAction::Allow {
                        SEMANTIC_GREEN
                    } else if rule.auto_generated_by_ips {
                        SEMANTIC_RED
                    } else {
                        SEMANTIC_AMBER
                    };
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, border_c))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("[{}] {}", rule.rule_id, rule.name))
                                        .size(12.0)
                                        .strong()
                                        .color(if rule.enabled {
                                            TEXT_PRIMARY
                                        } else {
                                            TEXT_MUTED
                                        }),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "{} {} {}:{} -> {} (命中 {} 次)",
                                        rule.direction.code(),
                                        rule.protocol.label(),
                                        rule.remote_ip,
                                        if rule.port > 0 {
                                            rule.port.to_string()
                                        } else {
                                            "*".to_string()
                                        },
                                        rule.action.label(),
                                        rule.hit_count
                                    ))
                                    .size(11.0)
                                    .color(TEXT_SECONDARY),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button("删除").clicked() {
                                        remove_rule_id = Some(rule.rule_id.clone());
                                    }
                                    if ui
                                        .small_button(if rule.enabled { "暂停" } else { "启用" })
                                        .clicked()
                                    {
                                        toggle_rule_id = Some(rule.rule_id.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(3.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "IPS 实时入侵拦截与 T5B8 检测事件 ({} 条)",
                        self.snapshot.ips_events.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                if self.snapshot.ips_events.is_empty() {
                    ui.label(
                        RichText::new("当前未捕获入侵流量，可点击上方「IPS攻防演练」测试包特征检测与自动封堵。")
                            .size(11.5)
                            .color(TEXT_MUTED),
                    );
                } else {
                    for ev in &self.snapshot.ips_events {
                        egui::Frame::none()
                            .fill(if ev.auto_blocked { BG_CARD_AD } else { BG_SURFACE })
                            .stroke(Stroke::new(
                                1.0_f32,
                                if ev.auto_blocked {
                                    SEMANTIC_RED
                                } else {
                                    SEMANTIC_AMBER
                                },
                            ))
                            .rounding(Rounding::same(8.0))
                            .inner_margin(Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "[{}] {} · {} ({})",
                                            ev.severity.label(),
                                            ev.signature_id,
                                            ev.signature_name,
                                            ev.process_name
                                        ))
                                        .size(12.0)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} | T5B8={} (Δ={:.2}) | {}",
                                            ev.dst_or_remote,
                                            ev.t5b8_hex,
                                            ev.t5b8_recon_error,
                                            if ev.auto_blocked {
                                                "已自动阻断"
                                            } else {
                                                "仅审计"
                                            }
                                        ))
                                        .size(11.0)
                                        .color(TEXT_SECONDARY),
                                    );
                                    if ev.auto_blocked
                                        && ev.remote_ip != "*"
                                        && !ev.remote_ip.is_empty()
                                        && ui.small_button("加白解封").clicked()
                                    {
                                        allowlist_ip = Some(ev.remote_ip.clone());
                                    }
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "{} | {}",
                                        ev.remediation_note, ev.payload_preview
                                    ))
                                    .size(10.5)
                                    .color(TEXT_MUTED),
                                );
                            });
                        ui.add_space(3.0);
                    }
                }
            });

        if let Some(rid) = toggle_rule_id {
            self.send_cmd(WorkerCmd::ToggleFirewallRule(rid));
        }
        if let Some(rid) = remove_rule_id {
            self.send_cmd(WorkerCmd::RemoveFirewallRule(rid));
        }
        if let Some(ip) = allowlist_ip {
            self.send_cmd(WorkerCmd::AllowlistFirewallIp(ip));
        }
    }

    /// 网络攻击指纹调查、代码基因图谱分析与多情报库联动面板
    fn render_threat_intel_tab(&mut self, ui: &mut egui::Ui) {
        let mut toggle_fid: Option<String> = None;
        let mut remove_fid: Option<String> = None;
        let mut block_rid: Option<String> = None;

        let enabled_cnt = self
            .snapshot
            .intel_feeds
            .iter()
            .filter(|f| f.enabled)
            .count();

        egui::Frame::none()
            .fill(BG_SURFACE)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .rounding(Rounding::same(12.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    draw_metric_pill(
                        ui,
                        "活跃情报库",
                        &format!("{}/{}", enabled_cnt, self.snapshot.intel_feeds.len()),
                        ACCENT_CYAN,
                    );
                    draw_metric_pill(
                        ui,
                        "调查报告",
                        &self.snapshot.intel_reports.len().to_string(),
                        ACCENT_BLUE,
                    );
                    draw_metric_pill(
                        ui,
                        "本地IOC库",
                        &self.snapshot.intel_custom_ioc_count.to_string(),
                        SEMANTIC_GREEN,
                    );
                    ui.label(
                        RichText::new("目标 (IP/文件路径/SHA256):")
                            .size(11.5)
                            .color(TEXT_SECONDARY),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.intel_query_input)
                            .hint_text("198.51.100.44:4444 或 可执行文件路径 或 SHA-256")
                            .desired_width(240.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🔬 发起指纹+基因联查")
                                    .size(11.5)
                                    .color(Color32::WHITE),
                            )
                            .fill(ACCENT_BLUE)
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        let q = self.intel_query_input.trim().to_string();
                        if !q.is_empty() {
                            self.send_cmd(WorkerCmd::RunThreatInvestigation(q));
                            self.show_toast("⏳ 正在提取网络指纹与代码基因并联动多情报库查询…");
                        }
                    }

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(if self.intel_show_feeds_drawer {
                                    "▾ 情报接口配置"
                                } else {
                                    "▸ 情报接口配置"
                                })
                                .size(11.5)
                                .color(ACCENT_CYAN),
                            )
                            .fill(BG_CANVAS)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .rounding(Rounding::same(8.0)),
                        )
                        .clicked()
                    {
                        self.intel_show_feeds_drawer = !self.intel_show_feeds_drawer;
                    }
                });

                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("快捷调查与采样:")
                            .size(11.5)
                            .color(TEXT_SECONDARY),
                    );
                    for (kind, title) in [
                        ("live", "📡 当前可疑外联/进程"),
                        ("revshell_loader", "🧪 反弹Shell+注入基因"),
                        ("redis_rce_cred", "🧪 Redis-RCE+窃密基因"),
                        ("self_exe_clean", "🛡 本程序二进制DNA基线"),
                    ] {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(title).size(11.0).color(TEXT_PRIMARY),
                                )
                                .fill(BG_ELEVATED)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::RunThreatInvestigationDrill(kind.to_string()));
                        }
                    }
                });

                if self.intel_show_feeds_drawer {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("情报接口配置:")
                                .size(11.5)
                                .strong()
                                .color(TEXT_PRIMARY),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.intel_feed_name_input)
                                .hint_text("名称")
                                .desired_width(130.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.intel_feed_url_input)
                                .hint_text("https://... 或 http://...")
                                .desired_width(220.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.intel_feed_key_input)
                                .hint_text("API Key / Auth")
                                .desired_width(140.0),
                        );
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("💾 保存选中源").size(11.0).color(Color32::WHITE),
                                )
                                .fill(ACCENT_BLUE)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::UpdateIntelFeedConfig {
                                feed_id: self.intel_selected_feed_id.clone(),
                                endpoint_url: self.intel_feed_url_input.clone(),
                                api_key: self.intel_feed_key_input.clone(),
                            });
                        }
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("➕ 新增自定义库").size(11.0).color(TEXT_PRIMARY),
                                )
                                .fill(BG_ELEVATED)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::AddCustomIntelFeed {
                                name: self.intel_feed_name_input.clone(),
                                endpoint_url: self.intel_feed_url_input.clone(),
                                auth_header: "Authorization".to_string(),
                                api_key: self.intel_feed_key_input.clone(),
                            });
                        }
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("↺ 恢复默认").size(11.0).color(TEXT_SECONDARY),
                                )
                                .fill(BG_CANVAS)
                                .rounding(Rounding::same(6.0)),
                            )
                            .clicked()
                        {
                            self.send_cmd(WorkerCmd::ResetDefaultIntelFeeds);
                        }
                    });
                }
            });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("win_threat_intel_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "已配置情报库接口 ({} 个 · 默认启用本地 9006 + 离线基因库，支持 OTX / ThreatFox / VT 与自定义 TIP)",
                        self.snapshot.intel_feeds.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for feed in &self.snapshot.intel_feeds {
                    let is_sel = self.intel_selected_feed_id == feed.feed_id;
                    egui::Frame::none()
                        .fill(if is_sel { BG_ELEVATED } else { BG_SURFACE })
                        .stroke(Stroke::new(
                            1.0_f32,
                            if is_sel {
                                ACCENT_CYAN
                            } else if feed.enabled {
                                SEMANTIC_GREEN
                            } else {
                                BORDER_SUBTLE
                            },
                        ))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(
                                        is_sel,
                                        RichText::new(format!("[{}] {}", feed.kind.label(), feed.name))
                                            .size(12.0)
                                            .strong(),
                                    )
                                    .clicked()
                                {
                                    self.intel_selected_feed_id = feed.feed_id.clone();
                                    self.intel_feed_name_input = feed.name.clone();
                                    self.intel_feed_url_input = feed.endpoint_url.clone();
                                    self.intel_feed_key_input = feed.api_key.clone();
                                    self.intel_show_feeds_drawer = true;
                                }
                                ui.label(
                                    RichText::new(format!(
                                        "{} | 权重{:.2} | 查{}次/中{}次 | {}",
                                        feed.endpoint_url,
                                        feed.weight,
                                        feed.total_queries,
                                        feed.total_hits,
                                        feed.last_status
                                    ))
                                    .size(11.0)
                                    .color(TEXT_SECONDARY),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if !feed.is_builtin_default && ui.small_button("删除").clicked() {
                                        remove_fid = Some(feed.feed_id.clone());
                                    }
                                    if ui
                                        .small_button(if feed.enabled { "停用" } else { "启用" })
                                        .clicked()
                                    {
                                        toggle_fid = Some(feed.feed_id.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(3.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "网络攻击指纹 & 代码基因调查报告 ({} 份)",
                        self.snapshot.intel_reports.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                if self.snapshot.intel_reports.is_empty() {
                    ui.label(
                        RichText::new("尚未生成调查报告，请在上方输入调查目标或运行快捷演练。")
                            .size(11.5)
                            .color(TEXT_MUTED),
                    );
                } else {
                    for rep in &self.snapshot.intel_reports {
                        let is_high = rep.fused_threat_score >= 48.0;
                        egui::Frame::none()
                            .fill(if is_high { BG_CARD_AD } else { BG_SURFACE })
                            .stroke(Stroke::new(
                                1.0_f32,
                                if rep.fused_threat_score >= 70.0 {
                                    SEMANTIC_RED
                                } else if is_high {
                                    SEMANTIC_AMBER
                                } else {
                                    SEMANTIC_GREEN
                                },
                            ))
                            .rounding(Rounding::same(8.0))
                            .inner_margin(Margin::symmetric(10.0, 8.0))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "[{} · {:.1}分] {} ({}) | 情报命中 {}/{}",
                                            rep.verdict_level,
                                            rep.fused_threat_score,
                                            rep.query_input,
                                            rep.process_name,
                                            rep.feeds_hit_count,
                                            rep.feeds_queried_count
                                        ))
                                        .size(12.0)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if rep.linked_mitigation_done {
                                            ui.label(
                                                RichText::new("✓ 已封堵入库")
                                                    .size(11.0)
                                                    .color(SEMANTIC_GREEN),
                                            );
                                        } else if ui.small_button("🛡 联动封堵+写入IOC库").clicked() {
                                            block_rid = Some(rep.report_id.clone());
                                        }
                                    });
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "网络指纹: {} | 协议族={} | {} | 特征={}",
                                        rep.network_fp.fingerprint_id,
                                        rep.network_fp.protocol_family,
                                        rep.network_fp.ja3_behavior_tag,
                                        rep.network_fp.matched_attack_markers.join("; ")
                                    ))
                                    .size(11.0)
                                    .color(ACCENT_CYAN),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "代码基因: {} | SimHash={} | 家族={} ({:.1}%) | SHA256={} | API=[{}]",
                                        rep.code_gene.gene_id,
                                        rep.code_gene.gene_simhash_64,
                                        rep.code_gene.closest_gene_family,
                                        rep.code_gene.gene_similarity_pct,
                                        rep.code_gene.file_sha256,
                                        rep.code_gene.extracted_api_genes.join(", ")
                                    ))
                                    .size(10.8)
                                    .color(TEXT_SECONDARY),
                                );
                                for fm in &rep.feed_matches {
                                    ui.label(
                                        RichText::new(format!(
                                            "  • {} [{}] ({:.0}% / {}ms): {}",
                                            fm.feed_name,
                                            fm.status,
                                            fm.confidence * 100.0,
                                            fm.latency_ms,
                                            fm.raw_summary
                                        ))
                                        .size(10.5)
                                        .color(TEXT_MUTED),
                                    );
                                }
                            });
                        ui.add_space(4.0);
                    }
                }
            });

        if let Some(fid) = toggle_fid {
            self.send_cmd(WorkerCmd::ToggleIntelFeed(fid));
        }
        if let Some(fid) = remove_fid {
            self.send_cmd(WorkerCmd::RemoveIntelFeed(fid));
        }
        if let Some(rid) = block_rid {
            self.send_cmd(WorkerCmd::BlockFromInvestigationReport(rid));
        }
    }

    /// 系统自启动驻留项、TCP 套接字暴露面、FIM 凭据与审计日志
    fn render_edr_telemetry_tab(&mut self, ui: &mut egui::Ui) {
        let mut unload_path: Option<String> = None;
        let mut remediate_fim: Option<String> = None;
        let mut fix_port: Option<(u32, String, String, String)> = None;

        egui::ScrollArea::vertical()
            .id_salt("win_telemetry_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "📌 自启动驻留项 ({})",
                        self.snapshot.persistence_entries.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for ent in self.snapshot.persistence_entries.iter().take(30) {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!("[{}] {}", ent.kind, ent.label))
                                            .size(12.0)
                                            .color(if ent.is_suspicious {
                                                SEMANTIC_AMBER
                                            } else {
                                                TEXT_PRIMARY
                                            }),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} -> {}{}{}",
                                            ent.config_path,
                                            ent.target_exec,
                                            ent.active_pid
                                                .map(|p| format!(" · 运行中 PID={}", p))
                                                .unwrap_or_default(),
                                            if ent.provenance_hint.is_empty() {
                                                String::new()
                                            } else {
                                                format!(" · {}", ent.provenance_hint)
                                            }
                                        ))
                                        .size(10.5)
                                        .color(TEXT_SECONDARY),
                                    );
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if !ent.unloaded
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("卸载").size(11.0).color(SEMANTIC_RED),
                                                )
                                                .fill(BG_ELEVATED)
                                                .rounding(Rounding::same(6.0)),
                                            )
                                            .clicked()
                                    {
                                        unload_path = Some(ent.config_path.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "🔌 活跃 TCP 套接字与全网口监听 ({})",
                        self.snapshot.active_sockets.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for sock in self.snapshot.active_sockets.iter().take(40) {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "{} (PID={}) {} -> {} [{} · {}] {:.0}%{}{}",
                                        sock.process_name,
                                        sock.pid,
                                        sock.local_endpoint,
                                        sock.remote_endpoint,
                                        sock.state,
                                        sock.ip_scope_hint,
                                        sock.threat_score * 100.0,
                                        if sock.proc_cwd.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" | CWD={}", sock.proc_cwd)
                                        },
                                        if sock.service_unit.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" | 服务={}", sock.service_unit)
                                        }
                                    ))
                                    .size(11.5)
                                    .color(if sock.is_c2_suspicious || sock.is_wildcard_exposed {
                                        SEMANTIC_AMBER
                                    } else {
                                        TEXT_SECONDARY
                                    })
                                    .monospace(),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if (sock.is_wildcard_exposed || sock.is_c2_suspicious)
                                        && !sock.blocked
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("收敛/冻结").size(11.0).color(ACCENT_CYAN),
                                                )
                                                .fill(BG_ELEVATED)
                                                .rounding(Rounding::same(6.0)),
                                            )
                                            .clicked()
                                    {
                                        fix_port = Some((
                                            sock.pid,
                                            sock.process_name.clone(),
                                            sock.exe_path.clone(),
                                            sock.local_endpoint.clone(),
                                        ));
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "🔐 敏感凭据与临时目录 FIM ({})",
                        self.snapshot.fim_records.len()
                    ))
                    .size(13.0)
                    .strong()
                    .color(TEXT_PRIMARY),
                );
                ui.add_space(4.0);
                for fim in self.snapshot.fim_records.iter().take(25) {
                    egui::Frame::none()
                        .fill(BG_SURFACE)
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "{} [{}] {}{}{}",
                                        fim.path,
                                        fim.unix_mode_octal,
                                        fim.status,
                                        if fim.holder_processes.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" | 占用: {}", fim.holder_processes.join(", "))
                                        },
                                        if fim.provenance_hint.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" | {}", fim.provenance_hint)
                                        }
                                    ))
                                    .size(11.5)
                                    .color(if fim.is_alert {
                                        SEMANTIC_RED
                                    } else {
                                        TEXT_SECONDARY
                                    }),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if fim.is_alert
                                        && !fim.quarantined
                                        && ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("加固/隔离").size(11.0).color(SEMANTIC_AMBER),
                                                )
                                                .fill(BG_ELEVATED)
                                                .rounding(Rounding::same(6.0)),
                                            )
                                            .clicked()
                                    {
                                        remediate_fim = Some(fim.path.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }
            });

        if let Some(cfg_path) = unload_path {
            self.send_cmd(WorkerCmd::UnloadPersistenceAgent(cfg_path));
        }
        if let Some(path) = remediate_fim {
            self.send_cmd(WorkerCmd::RemediateFim(path));
        }
        if let Some((pid, pname, epath, hint)) = fix_port {
            self.send_cmd(WorkerCmd::ExecutePortVulnRemediation(
                pid, pname, epath, hint,
            ));
        }
    }
}

fn build_evaluated_test_popup_window(engine: &PolicyDecisionEngine) -> RealDesktopWindow {
    let feat: crate::contract::FrameFeatures = [
        0.95, // s[0]: 键鼠空闲衰减
        0.96, // s[1]: 置顶无边框掩码
        0.94, // s[2]: 隐藏任务栏图标
        0.92, // s[3]: 右下角通知区落点
        0.08, // s[4]: 内存 W^X 跃迁
        0.86, // s[5]: 非主界面寄生调用栈
        0.05, // s[6]: 跨进程写内存
        0.42, // s[7]: 二进制香农熵
        0.84, // s[8]: 网络推流触发
        0.04, // s[9]: 临时目录落地
        0.02, // s[10]: 自启动篡改
        0.12, // s[11]: 父子路径偏离
    ];
    let state_window = [feat; crate::contract::SEQ_LEN];
    let host_profile = crate::contract::HostContextProfile {
        has_open_user_document: true,
        active_document_hint: Some("宿主软件主工作窗口运行中".to_string()),
        is_critical_shell_host: false,
        has_main_work_window: true,
    };
    let exe_path = SecurityAssistantApp::current_exe_path_str();
    let decision = engine.evaluate_with_context(
        &state_window,
        &host_profile,
        "promo_popup.exe",
        &exe_path,
        "限时特惠广告弹窗",
    );
    let (dom_intent, dom_prob) = decision.dominant_intent();
    RealDesktopWindow {
        window_id: 0xAD01,
        pid: std::process::id(),
        parent_pid: 1,
        thread_id: 1,
        app_name: "promo_popup.exe".to_string(),
        exe_path,
        window_title: "限时特惠广告弹窗".to_string(),
        bounds: (1520, 760, 340, 190),
        is_topmost_floating: true,
        is_tool_or_popup: true,
        input_idle_decay: 0.95,
        frame_features: feat,
        is_ad_popup_candidate: true,
        plain_reason: format!(
            "模型判定 {}→{} ({:.0}%)",
            dom_intent.code(),
            decision.chosen_action.code(),
            dom_prob * 100.0
        ),
        decision,
    }
}

fn build_snapshot(
    initialized: bool,
    auto_block_enabled: bool,
    engine: &PolicyDecisionEngine,
    scanner: &RealWindowScanner,
    edr: &LocalEdrEngine,
    live_windows: &[RealDesktopWindow],
) -> UiSnapshot {
    let suspicious_win_count = live_windows
        .iter()
        .filter(|w| w.is_ad_popup_candidate || w.is_topmost_floating)
        .count();
    let managed_win_count = live_windows
        .iter()
        .filter(|w| {
            scanner.auto_block_apps.contains(&w.app_name)
                || scanner.trusted_whitelist_windows.contains(&w.window_id)
        })
        .count();
    let pending_alerts_count = edr.alerts.iter().filter(|a| !a.auto_mitigated).count();
    let pending_ads_count = edr.ad_blocker.pending_cleanup_count();
    let active_fw_rules_count = edr.firewall_ips.active_rules_count();
    let enabled_intel_feeds_count = edr.threat_intel.enabled_feeds_count();
    let hardware_tier_label = crate::platform::detect_host_hardware_profile()
        .tier
        .label()
        .to_string();

    UiSnapshot {
        initialized,
        auto_block_enabled,
        screen_size: scanner.screen_size,
        engine_revision: engine.current_revision(),
        mosaic_count: engine.mosaic_memory_count(),
        live_windows: live_windows.to_vec(),
        auto_block_apps: scanner.auto_block_apps.clone(),
        trusted_whitelist_windows: scanner.trusted_whitelist_windows.clone(),
        blocked_history: scanner.blocked_history.clone(),
        live_processes_count: edr.live_processes.len(),
        daemon_agent_installed: edr.daemon_agent_installed,
        alerts: edr.alerts.clone(),
        active_sockets: edr.active_sockets.clone(),
        persistence_entries: edr.persistence_entries.clone(),
        fim_records: edr.fim_records.clone(),
        hosts_status: edr.ad_blocker.hosts_status.clone(),
        total_reclaimed_bytes: edr.ad_blocker.total_reclaimed_bytes,
        ad_last_action_message: edr.ad_blocker.last_action_message.clone(),
        ad_cleanup_candidates: edr.ad_blocker.cleanup_candidates.clone(),
        ad_connections: edr.ad_blocker.ad_connections.clone(),
        fw_os_status: edr.firewall_ips.os_status.clone(),
        fw_ips_mode: edr.firewall_ips.mode,
        firewall_rules: edr.firewall_ips.rules.clone(),
        ips_events: edr.firewall_ips.ips_events.clone(),
        fw_total_packets_inspected: edr.firewall_ips.total_packets_inspected,
        fw_total_packets_blocked: edr.firewall_ips.total_packets_blocked,
        fw_last_sync_message: edr.firewall_ips.last_sync_message.clone(),
        intel_feeds: edr.threat_intel.feeds.clone(),
        intel_reports: edr.threat_intel.reports.clone(),
        intel_custom_ioc_count: edr.threat_intel.custom_malicious_iocs.len(),
        intel_last_status_message: edr.threat_intel.last_status_message.clone(),
        suspicious_win_count,
        managed_win_count,
        pending_alerts_count,
        pending_ads_count,
        active_fw_rules_count,
        enabled_intel_feeds_count,
        hardware_tier_label,
    }
}

fn compute_snapshot_fp(
    engine: &PolicyDecisionEngine,
    scanner: &RealWindowScanner,
    edr: &LocalEdrEngine,
    live_windows: &[RealDesktopWindow],
    auto_block_enabled: bool,
) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    auto_block_enabled.hash(&mut h);
    engine.current_revision().hash(&mut h);
    scanner.blocked_history.len().hash(&mut h);
    scanner.auto_block_apps.len().hash(&mut h);
    scanner.trusted_whitelist_windows.len().hash(&mut h);
    live_windows.len().hash(&mut h);
    for w in live_windows {
        w.window_id.hash(&mut h);
        w.is_ad_popup_candidate.hash(&mut h);
        w.is_topmost_floating.hash(&mut h);
        w.window_title.len().hash(&mut h);
    }
    edr.last_state_fingerprint.hash(&mut h);
    edr.live_processes.len().hash(&mut h);
    edr.active_sockets.len().hash(&mut h);
    edr.alerts.len().hash(&mut h);
    edr.alerts.iter().filter(|a| !a.auto_mitigated).count().hash(&mut h);
    edr.persistence_entries.len().hash(&mut h);
    edr.fim_records.len().hash(&mut h);
    edr.daemon_agent_installed.hash(&mut h);
    edr.ad_blocker.hosts_status.active_in_etc_hosts.hash(&mut h);
    edr.ad_blocker.hosts_status.rule_count.hash(&mut h);
    edr.ad_blocker.total_reclaimed_bytes.hash(&mut h);
    edr.ad_blocker.cleanup_candidates.len().hash(&mut h);
    edr.ad_blocker.pending_cleanup_count().hash(&mut h);
    edr.ad_blocker.ad_connections.len().hash(&mut h);
    edr.firewall_ips.mode.is_prevent().hash(&mut h);
    edr.firewall_ips.rules.len().hash(&mut h);
    edr.firewall_ips.active_rules_count().hash(&mut h);
    edr.firewall_ips.ips_events.len().hash(&mut h);
    edr.firewall_ips.total_packets_blocked.hash(&mut h);
    edr.firewall_ips.last_sync_message.hash(&mut h);
    edr.threat_intel.feeds.len().hash(&mut h);
    for f in &edr.threat_intel.feeds {
        f.feed_id.hash(&mut h);
        f.enabled.hash(&mut h);
        f.endpoint_url.hash(&mut h);
        f.last_status.hash(&mut h);
        f.total_hits.hash(&mut h);
    }
    edr.threat_intel.reports.len().hash(&mut h);
    edr.threat_intel.custom_malicious_iocs.len().hash(&mut h);
    edr.threat_intel.last_status_message.hash(&mut h);
    h.finish()
}

fn push_snapshot(
    msg_tx: &Sender<WorkerMsg>,
    ctx: &Option<egui::Context>,
    snap: UiSnapshot,
) {
    let _ = msg_tx.send(WorkerMsg::Snapshot(Arc::new(snap)));
    if let Some(c) = ctx {
        c.request_repaint();
    }
}

fn push_toast(
    msg_tx: &Sender<WorkerMsg>,
    ctx: &Option<egui::Context>,
    msg: impl Into<String>,
    is_alert: bool,
) {
    let _ = msg_tx.send(WorkerMsg::Toast {
        msg: msg.into(),
        is_alert,
    });
    if let Some(c) = ctx {
        c.request_repaint();
    }
}

fn worker_refresh_windows_and_auto_block(
    engine: &PolicyDecisionEngine,
    scanner: &mut RealWindowScanner,
    live_windows: &mut Vec<RealDesktopWindow>,
    auto_block_enabled: bool,
    msg_tx: &Sender<WorkerMsg>,
    ctx: &Option<egui::Context>,
) {
    *live_windows = scanner.scan_real_desktop(engine);
    if !auto_block_enabled {
        return;
    }
    let candidates: Vec<RealDesktopWindow> = live_windows
        .iter()
        .filter(|w| w.is_ad_popup_candidate && !scanner.already_closed_ids.contains(&w.window_id))
        .cloned()
        .collect();
    for win in candidates {
        scanner.close_ad_window_now(&win, true, engine);
        push_toast(
            msg_tx,
            ctx,
            format!(
                "🛡️ 模型已拦截「{}」({}→{})",
                win.app_name,
                win.decision.dominant_intent().0.code(),
                win.decision.chosen_action.code()
            ),
            false,
        );
    }
}

fn spawn_backend_worker(ctx: Option<egui::Context>) -> (Sender<WorkerCmd>, Receiver<WorkerMsg>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
    let (msg_tx, msg_rx) = mpsc::channel::<WorkerMsg>();

    let _ = std::thread::Builder::new()
        .name("vnb-edr-worker".to_string())
        .spawn(move || {
            let engine = PolicyDecisionEngine::new();
            let mut scanner = RealWindowScanner::new();
            let mut live_windows = scanner.scan_real_desktop(&engine);
            let mut edr = LocalEdrEngine::new();
            let mut auto_block_enabled = true;

            let mut last_fp =
                compute_snapshot_fp(&engine, &scanner, &edr, &live_windows, auto_block_enabled);
            push_snapshot(
                &msg_tx,
                &ctx,
                build_snapshot(
                    true,
                    auto_block_enabled,
                    &engine,
                    &scanner,
                    &edr,
                    &live_windows,
                ),
            );

            let hw = crate::platform::detect_host_hardware_profile();
            let win_scan_dur = Duration::from_millis(hw.win_scan_interval_ms);
            let edr_tick_dur = Duration::from_secs(hw.edr_tick_interval_secs);
            let mut next_win_scan = Instant::now() + win_scan_dur;
            let mut next_edr_tick = Instant::now() + edr_tick_dur;

            let handle_cmd = |cmd: WorkerCmd,
                              auto_block_enabled: &mut bool,
                              scanner: &mut RealWindowScanner,
                              live_windows: &mut Vec<RealDesktopWindow>,
                              edr: &mut LocalEdrEngine|
             -> bool {
                match cmd {
                    WorkerCmd::Shutdown => return false,
                    WorkerCmd::SetAutoBlock(enabled) => {
                        *auto_block_enabled = enabled;
                        if enabled {
                            worker_refresh_windows_and_auto_block(
                                &engine,
                                scanner,
                                live_windows,
                                true,
                                &msg_tx,
                                &ctx,
                            );
                        }
                    }
                    WorkerCmd::RefreshWindows { notify } => {
                        worker_refresh_windows_and_auto_block(
                            &engine,
                            scanner,
                            live_windows,
                            *auto_block_enabled,
                            &msg_tx,
                            &ctx,
                        );
                        if notify {
                            push_toast(&msg_tx, &ctx, "🔄 已刷新桌面窗口列表", false);
                        }
                    }
                    WorkerCmd::ForceFullTelemetryScan => {
                        edr.run_full_telemetry_scan();
                        push_toast(&msg_tx, &ctx, "🔍 已完成全机 EDR 与广告遥测重扫", false);
                    }
                    WorkerCmd::ClearRestoredHistory => {
                        scanner.blocked_history.retain(|r| !r.restored_by_user);
                        push_toast(&msg_tx, &ctx, "🧹 已清理已恢复的历史记录", false);
                    }
                    WorkerCmd::ToggleAppAutoBlock { app, enable } => {
                        if enable {
                            scanner.auto_block_apps.insert(app);
                        } else {
                            scanner.auto_block_apps.remove(&app);
                        }
                        worker_refresh_windows_and_auto_block(
                            &engine,
                            scanner,
                            live_windows,
                            *auto_block_enabled,
                            &msg_tx,
                            &ctx,
                        );
                    }
                    WorkerCmd::TrustWindow(win) => {
                        let rev = scanner.trust_window_now(&win, &engine);
                        push_toast(
                            &msg_tx,
                            &ctx,
                            format!(
                                "✓ 已将「{}」加入信任白名单 · 策略热更新至 v1.{}",
                                win.app_name, rev
                            ),
                            false,
                        );
                        worker_refresh_windows_and_auto_block(
                            &engine,
                            scanner,
                            live_windows,
                            *auto_block_enabled,
                            &msg_tx,
                            &ctx,
                        );
                    }
                    WorkerCmd::BlockWindowNow(win) => {
                        scanner.manually_blocked_window_ids.insert(win.window_id);
                        scanner.close_ad_window_now(&win, false, &engine);
                        push_toast(
                            &msg_tx,
                            &ctx,
                            format!(
                                "🚫 已外科拦截「{}」并更新模型策略 v1.{}",
                                win.app_name,
                                engine.current_revision()
                            ),
                            true,
                        );
                        worker_refresh_windows_and_auto_block(
                            &engine,
                            scanner,
                            live_windows,
                            *auto_block_enabled,
                            &msg_tx,
                            &ctx,
                        );
                    }
                    WorkerCmd::RestoreAndTrust(rid) => {
                        if let Some((_wid, app)) = scanner.restore_and_trust(rid, &engine) {
                            push_toast(
                                &msg_tx,
                                &ctx,
                                format!(
                                    "↩ 已恢复「{}」并热更新策略 v1.{}",
                                    app,
                                    engine.current_revision()
                                ),
                                false,
                            );
                            worker_refresh_windows_and_auto_block(
                                &engine,
                                scanner,
                                live_windows,
                                *auto_block_enabled,
                                &msg_tx,
                                &ctx,
                            );
                        }
                    }
                    WorkerCmd::ResolveTestPopup { auto } => {
                        let eval_win = build_evaluated_test_popup_window(&engine);
                        scanner.close_ad_window_now(&eval_win, auto, &engine);
                        if auto {
                            push_toast(
                                &msg_tx,
                                &ctx,
                                "🛡️ 模型已自动外科消音测试弹窗并记入日志",
                                false,
                            );
                        } else {
                            push_toast(
                                &msg_tx,
                                &ctx,
                                format!(
                                    "🚫 已手动拦截弹窗并热更新策略 v1.{}",
                                    engine.current_revision()
                                ),
                                true,
                            );
                        }
                    }
                    WorkerCmd::HardenAllExposedVulnerabilities => {
                        let msg = edr.harden_all_exposed_vulnerabilities();
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::ToggleEdrDaemon => {
                        let msg = edr.toggle_edr_launch_agent_daemon();
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::ExecuteAlertRemediation(aid, action) => {
                        if let Some(msg) = edr.execute_alert_remediation(aid, action) {
                            edr.run_lightweight_telemetry_tick();
                            push_toast(
                                &msg_tx,
                                &ctx,
                                msg,
                                action != PolicyAction::A0PassAndUntag,
                            );
                        }
                    }
                    WorkerCmd::ResumeFrozenProcess(pid, pname, epath) => {
                        let msg = edr.resume_frozen_process(pid, &pname, &epath);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::ToggleHostsAdShield => {
                        let msg = edr.toggle_hosts_ad_shield(true);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::CleanAllAdArtifacts => {
                        let msg = edr.clean_all_ad_artifacts();
                        edr.run_full_telemetry_scan();
                        push_toast(&msg_tx, &ctx, msg, true);
                    }
                    WorkerCmd::AddCustomAdDomain(dom) => {
                        if edr.ad_blocker.add_custom_domain(&dom) {
                            let _ = msg_tx.send(WorkerMsg::ClearAdDomainInput);
                            push_toast(
                                &msg_tx,
                                &ctx,
                                format!("已添加自定义广告屏蔽域名: {}", dom),
                                false,
                            );
                        } else {
                            push_toast(
                                &msg_tx,
                                &ctx,
                                "请输入合法域名（如 ads.example.com）",
                                true,
                            );
                        }
                    }
                    WorkerCmd::CleanSingleAdArtifact(idx) => {
                        let msg = edr.clean_single_ad_artifact(idx);
                        edr.run_full_telemetry_scan();
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::BlockAdConnection(idx) => {
                        let msg = edr.block_ad_connection_at(idx);
                        push_toast(&msg_tx, &ctx, msg, true);
                    }
                    WorkerCmd::UnloadPersistenceAgent(cfg_path) => {
                        let msg = edr.unload_persistence_agent(&cfg_path);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::RemediateFim(path) => {
                        if let Some(msg) = edr.remediate_fim_or_quarantine(&path) {
                            push_toast(&msg_tx, &ctx, msg, false);
                        }
                    }
                    WorkerCmd::ExecutePortVulnRemediation(pid, pname, epath, hint) => {
                        let msg =
                            edr.execute_port_vulnerability_remediation(pid, &pname, &epath, &hint);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::ToggleIpsMode => {
                        let mode = edr.toggle_ips_mode();
                        push_toast(&msg_tx, &ctx, format!("🛡 IPS 模式已切换为 {}", mode.label()), false);
                    }
                    WorkerCmd::AddFirewallBlockRule { name, remote_ip, port } => {
                        let msg = edr.add_firewall_block_rule(
                            &name,
                            FirewallDirection::Both,
                            &remote_ip,
                            port,
                            "Windows 控制台人工添加拦截策略",
                        );
                        push_toast(&msg_tx, &ctx, msg, true);
                    }
                    WorkerCmd::ToggleFirewallRule(rid) => {
                        let msg = edr.toggle_firewall_rule(&rid);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::RemoveFirewallRule(rid) => {
                        let msg = edr.remove_firewall_rule(&rid);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::AllowlistFirewallIp(ip) => {
                        let msg = edr.allowlist_firewall_ip(&ip);
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::HardenFirewallPorts => {
                        let msg = edr.harden_firewall_high_risk_ports();
                        push_toast(&msg_tx, &ctx, msg, true);
                    }
                    WorkerCmd::SyncOsFirewall(apply_kernel) => {
                        let msg = edr.sync_os_firewall_now(apply_kernel);
                        let is_warn = msg.contains("WARN") || msg.contains("取消") || msg.contains("失败");
                        push_toast(&msg_tx, &ctx, msg, is_warn);
                    }
                    WorkerCmd::RunIpsDrill(kind) => {
                        let verdict = edr.run_ips_drill_probe(&kind);
                        push_toast(&msg_tx, &ctx, verdict.verdict_summary, verdict.blocked_by_firewall);
                    }
                    WorkerCmd::RunThreatInvestigation(query) => {
                        let rep = edr.run_threat_investigation(
                            &query,
                            0,
                            "manual_target",
                            None,
                            None,
                            None,
                            None,
                        );
                        push_toast(
                            &msg_tx,
                            &ctx,
                            format!(
                                "🔬 调查完成 [{}] {:.1}分 (命中 {}/{})",
                                rep.verdict_level,
                                rep.fused_threat_score,
                                rep.feeds_hit_count,
                                rep.feeds_queried_count
                            ),
                            rep.fused_threat_score >= 48.0,
                        );
                    }
                    WorkerCmd::RunThreatInvestigationDrill(kind) => {
                        let rep = edr.run_threat_investigation_drill(&kind);
                        push_toast(
                            &msg_tx,
                            &ctx,
                            format!(
                                "🎯 实战演练调查 [{}] {:.1}分 (命中 {}/{})",
                                rep.verdict_level,
                                rep.fused_threat_score,
                                rep.feeds_hit_count,
                                rep.feeds_queried_count
                            ),
                            rep.fused_threat_score >= 48.0,
                        );
                    }
                    WorkerCmd::ToggleIntelFeed(fid) => {
                        let msg = edr.toggle_intel_feed(&fid);
                        let is_alert = msg.contains("[INTEL-WARN]");
                        push_toast(&msg_tx, &ctx, msg, is_alert);
                    }
                    WorkerCmd::UpdateIntelFeedConfig {
                        feed_id,
                        endpoint_url,
                        api_key,
                    } => {
                        let msg = edr.update_intel_feed_config(&feed_id, &endpoint_url, &api_key, None);
                        let is_alert = msg.contains("[INTEL-ERR]") || msg.contains("[INTEL-WARN]");
                        push_toast(&msg_tx, &ctx, msg, is_alert);
                    }
                    WorkerCmd::AddCustomIntelFeed {
                        name,
                        endpoint_url,
                        auth_header,
                        api_key,
                    } => match edr.add_custom_intel_feed(&name, &endpoint_url, &auth_header, &api_key) {
                        Ok(fid) => push_toast(
                            &msg_tx,
                            &ctx,
                            format!("✅ 已接入自定义情报接口 {} ({})", name, fid),
                            false,
                        ),
                        Err(err) => push_toast(
                            &msg_tx,
                            &ctx,
                            format!("❌ 自定义情报接口配置失败: {}", err),
                            true,
                        ),
                    },
                    WorkerCmd::RemoveIntelFeed(fid) => {
                        let msg = edr.remove_intel_feed(&fid);
                        let is_alert = msg.contains("[INTEL-WARN]");
                        push_toast(&msg_tx, &ctx, msg, is_alert);
                    }
                    WorkerCmd::ResetDefaultIntelFeeds => {
                        let msg = edr.reset_default_intel_feeds();
                        push_toast(&msg_tx, &ctx, msg, false);
                    }
                    WorkerCmd::BlockFromInvestigationReport(rid) => {
                        let msg = edr.block_from_investigation_report(&rid);
                        let is_alert = msg.contains("[INTEL-WARN]");
                        push_toast(&msg_tx, &ctx, msg, is_alert);
                    }
                }
                true
            };

            loop {
                let now = Instant::now();
                let next_due = next_win_scan.min(next_edr_tick);
                let timeout = next_due.saturating_duration_since(now);
                match cmd_rx.recv_timeout(timeout) {
                    Ok(cmd) => {
                        if !handle_cmd(
                            cmd,
                            &mut auto_block_enabled,
                            &mut scanner,
                            &mut live_windows,
                            &mut edr,
                        ) {
                            break;
                        }
                        while let Ok(more) = cmd_rx.try_recv() {
                            if !handle_cmd(
                                more,
                                &mut auto_block_enabled,
                                &mut scanner,
                                &mut live_windows,
                                &mut edr,
                            ) {
                                return;
                            }
                        }
                        last_fp = compute_snapshot_fp(
                            &engine,
                            &scanner,
                            &edr,
                            &live_windows,
                            auto_block_enabled,
                        );
                        push_snapshot(
                            &msg_tx,
                            &ctx,
                            build_snapshot(
                                true,
                                auto_block_enabled,
                                &engine,
                                &scanner,
                                &edr,
                                &live_windows,
                            ),
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let tick_now = Instant::now();
                        if tick_now >= next_win_scan {
                            worker_refresh_windows_and_auto_block(
                                &engine,
                                &mut scanner,
                                &mut live_windows,
                                auto_block_enabled,
                                &msg_tx,
                                &ctx,
                            );
                            next_win_scan = tick_now + win_scan_dur;
                        }
                        if tick_now >= next_edr_tick {
                            edr.run_lightweight_telemetry_tick();
                            next_edr_tick = tick_now + edr_tick_dur;
                        }
                        let fp = compute_snapshot_fp(
                            &engine,
                            &scanner,
                            &edr,
                            &live_windows,
                            auto_block_enabled,
                        );
                        if fp != last_fp {
                            last_fp = fp;
                            push_snapshot(
                                &msg_tx,
                                &ctx,
                                build_snapshot(
                                    true,
                                    auto_block_enabled,
                                    &engine,
                                    &scanner,
                                    &edr,
                                    &live_windows,
                                ),
                            );
                        }
                    }
                }
            }
        });

    (cmd_tx, msg_rx)
}

fn launch_native_with_accel(software_fallback: bool) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([920.0, 600.0])
            .with_title("VNB 终端安全卫士 · 本地 EDR 与广告拦截桌面端"),
        vsync: true,
        multisampling: 0,
        depth_buffer: 0,
        stencil_buffer: 0,
        hardware_acceleration: if software_fallback {
            eframe::HardwareAcceleration::Off
        } else {
            eframe::HardwareAcceleration::Preferred
        },
        shader_version: if software_fallback {
            Some(eframe::egui_glow::ShaderVersion::Gl120)
        } else {
            None
        },
        ..Default::default()
    };

    eframe::run_native(
        "VNB 终端安全卫士",
        options,
        Box::new(|cc| Ok(Box::new(SecurityAssistantApp::new_with_ctx(Some(cc.egui_ctx.clone()))))),
    )
}

/// Windows (及非 macOS 桌面平台) `eframe`/`egui` 图形界面统一入口 (`vnb_edr_run_from_cli` 调用)
pub fn run_windows_edr_workbench() -> i32 {
    let hw = crate::platform::detect_host_hardware_profile();
    let force_software = hw.prefer_low_gpu_overhead
        || std::env::args().any(|a| a == "--software-render" || a == "--low-spec")
        || matches!(
            std::env::var("VNB_SOFTWARE_RENDER").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        );

    if let Err(err) = launch_native_with_accel(force_software) {
        if !force_software {
            eprintln!(
                "[ui::run_windows_edr_workbench] 硬件加速渲染初始化失败 ({})，正在自动回退到低配软件 OpenGL 兼容模式...",
                err
            );
            if let Err(sw_err) = launch_native_with_accel(true) {
                eprintln!(
                    "[ui::run_windows_edr_workbench] 软件回退模式启动桌面 GUI 仍失败: {}",
                    sw_err
                );
                return 1;
            }
            return 0;
        }
        eprintln!("[ui::run_windows_edr_workbench] 启动桌面 GUI 失败: {}", err);
        return 1;
    }
    0
}
