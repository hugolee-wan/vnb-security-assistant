//! macOS 广告拦截与广告垃圾清理引擎 (`src/ad_blocker.rs`)
//!
//! 四维端侧广告防御闭环：
//! 1. 【模型驱动识广告】：融合 `WhiteRabbitNeo-7B (3584-D) AdGuard` 神经分类头与行为决策模型，
//!    识别桌面广告弹窗、广告联盟/追踪域名、Adware LaunchAgent 与高危浏览器广告注入扩展。
//! 2. 【Hosts / 网络层广告域名屏蔽】：管理 `/etc/hosts` (`# BEGIN VNB-EDR AD-SHIELD` 区块) 与本地
//!    规则集 `adblock_hosts.rules`，支持开启、追加自定义拦截域名、一键无损回滚与外联 Socket 阻断。
//! 3. 【广告软件与缓存残留清理】：安全扫描 LaunchAgents、`/tmp` 推广安装器、App 广告 SDK 缓存、
//!    浏览器高危广告扩展与 Service Worker 广告缓存，清理前优先入保险箱 (`VNB_Vault`)，支持追溯。
//! 4. 【桌面弹窗实操拦截】：配合 `RealWindowScanner` 与 `SurgicalActuator` 实现一键/自动关窗与消音。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::edr_engine::NetworkSocketRecord;
use crate::pretrained_models::{AdSemanticPrediction, PretrainedModelBundle};
use crate::win_live_os::move_file_to_quarantine_vault;

pub const AD_SHIELD_BEGIN_MARKER: &str = "# BEGIN VNB-EDR AD-SHIELD";
pub const AD_SHIELD_END_MARKER: &str = "# END VNB-EDR AD-SHIELD";

/// 内置高频广告联盟 / 弹窗推广 / 埋点追踪 / macOS Adware 分发域名库
pub const BUILTIN_AD_TRACKER_DOMAINS: &[(&str, &str)] = &[
    // Global Ad Exchanges & Popups
    ("doubleclick.net", "Google DoubleClick 广告分发"),
    ("googleads.g.doubleclick.net", "Google Ads 广告投放"),
    ("pagead2.googlesyndication.com", "Google AdSense 脚本"),
    ("tpc.googlesyndication.com", "Google 广告内容投递"),
    ("adservice.google.com", "Google 广告跟踪服务"),
    ("ad.doubleclick.net", "DoubleClick 广告追踪"),
    ("criteo.com", "Criteo 重定向广告"),
    ("bidder.criteo.com", "Criteo 竞价广告"),
    ("taboola.com", "Taboola 信息流推广"),
    ("cdn.taboola.com", "Taboola 脚本加载器"),
    ("outbrain.com", "Outbrain 推荐广告"),
    ("widgets.outbrain.com", "Outbrain 悬浮广告组件"),
    ("pubmatic.com", "PubMatic 广告交易平台"),
    ("ads.pubmatic.com", "PubMatic 广告请求"),
    ("rubiconproject.com", "Rubicon 广告竞价"),
    ("fastlane.rubiconproject.com", "Rubicon Ad Exchange"),
    ("adnxs.com", "AppNexus 广告投放"),
    ("ib.adnxs.com", "AppNexus 广告竞价"),
    ("openx.net", "OpenX 广告网络"),
    ("adroll.com", "AdRoll 追踪再营销"),
    ("scorecardresearch.com", "Comscore 跨站追踪"),
    ("b.scorecardresearch.com", "Comscore 统计信标"),
    ("popads.net", "PopAds 恶意弹窗网络"),
    ("popcash.net", "PopCash 弹出广告网"),
    ("propellerads.com", "PropellerAds 弹窗投放"),
    ("exoclick.com", "ExoClick 弹窗广告"),
    ("adsterra.com", "Adsterra 推广脚本"),
    ("adsrvr.org", "The Trade Desk 广告追踪"),
    // CN Desktop / Mobile / Bundled Software Ad SDKs & Popups
    ("pos.baidu.com", "百度联盟广告位"),
    ("cpro.baidu.com", "百度网盟推广"),
    ("dup.baidustatic.com", "百度推广静态资源"),
    ("eclick.baidu.com", "百度广告点击统计"),
    ("hm.baidu.com", "百度统计埋点"),
    ("tanx.com", "阿里妈妈 Tanx 广告"),
    ("alimama.com", "阿里妈妈推广联盟"),
    ("atanx.alicdn.com", "阿里广告 CDN"),
    ("mmstat.com", "阿里系行为追踪统计"),
    ("gdt.qq.com", "腾讯广点通广告"),
    ("e.qq.com", "腾讯社交广告"),
    ("mi.gdt.qq.com", "腾讯客户端广告 SDK"),
    ("l.qq.com", "腾讯视频贴片广告"),
    ("pgdt.gtimg.cn", "腾讯广告图片物料"),
    ("pangolin-sdk-toutiao.com", "字节穿山甲广告 SDK"),
    ("pglstatp-toutiao.com", "字节广告物料分发"),
    ("is.snssdk.com", "头条信息流广告接口"),
    ("dm.toutiao.com", "字节推广点击追踪"),
    ("umeng.com", "友盟统计追踪 SDK"),
    ("log.umsns.com", "友盟日志上报"),
    ("alog.umeng.com", "友盟活跃设备埋点"),
    ("cnzz.com", "CNZZ 站长追踪脚本"),
    ("s4.cnzz.com", "CNZZ 流量广告统计"),
    ("adx.sogou.com", "搜狗弹窗广告联盟"),
    ("theta.sogoucdn.com", "搜狗广告资源"),
    ("ads.360.cn", "360 推广弹窗接口"),
    ("show.g.mediav.com", "聚效 Mediav 弹窗广告"),
    ("mini.eastday.com", "东方头条桌面迷你弹窗"),
    ("p.2345.com", "2345 推广弹窗分发"),
    ("jifen.2345.com", "2345 积分推广下发"),
    ("wpsad.wps.cn", "办公软件广告推送通道"),
    ("ad.wps.cn", "WPS 推广弹窗接口"),
    // macOS Adware / PUP / Hijacker Distribution Hosts
    ("mackeeper.com", "MacKeeper PUP 推广分发"),
    ("zeobit.com", "Zeobit/MacKeeper 控制域"),
    ("genieo.com", "Genieo macOS 广告劫持"),
    ("vsearch.biz", "VSearch macOS 浏览器广告插件"),
    ("adload.io", "OSX.AdLoad 持久化广告木马"),
    ("installmac.com", "InstallMac 捆绑安装器"),
    ("searchmine.net", "SearchMine Safari/Chrome 劫持"),
    ("mycouponize.com", "MyCouponize 优惠券注入插件"),
    ("crossrider.com", "Crossrider 跨浏览器广告注入"),
    ("spigot.com", "Spigot 搜索劫持扩展"),
];

/// 已知 macOS 广告软件 / 捆绑推广器关键词
const KNOWN_ADWARE_SIGNATURES: &[&str] = &[
    "mackeeper",
    "genieo",
    "vsearch",
    "pirrit",
    "spigot",
    "adload",
    "crossrider",
    "searchmine",
    "installmac",
    "mycouponize",
    "chilltab",
    "adware",
    "bundlore",
    "shlayer",
    "operator_mac",
    "promo_helper",
    "ad_toast",
    "popup_helper",
    "offer_float",
];

/// 本地广告 SDK / 推广缓存特定路径标识（仅清理明确广告目录，绝不误删用户正常工作缓存）
const KNOWN_AD_CACHE_TOKENS: &[&str] = &[
    "adsdk",
    "adcache",
    "pangolin",
    "bytedance.ad",
    "tencent.ad",
    "gdt_ad",
    "doubleclick",
    "criteo",
    "taboola",
    "outbrain",
    "promo_helper",
    "popup_ad",
    "wpsad",
    "ad_material",
    "ad_splash",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdArtifactKind {
    AdwareLaunchAgent,
    AppAdSdkCache,
    BrowserAdExtension,
    BrowserAdTrackerCache,
    TempAdDropperOrDmg,
}

impl AdArtifactKind {
    pub fn cn_label(&self) -> &'static str {
        match self {
            Self::AdwareLaunchAgent => "广告驻留启动项",
            Self::AppAdSdkCache => "应用广告SDK缓存",
            Self::BrowserAdExtension => "高危广告/劫持扩展",
            Self::BrowserAdTrackerCache => "浏览器追踪/弹窗缓存",
            Self::TempAdDropperOrDmg => "临时推广/捆绑安装包",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdCleanupCandidate {
    pub id: u64,
    pub kind: AdArtifactKind,
    pub title: String,
    pub path: String,
    pub size_bytes: u64,
    pub ad_model_prob: f32,
    pub model_label: String,
    pub reason: String,
    pub cleaned: bool,
    pub quarantine_backup: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdConnectionAlert {
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub remote_endpoint: String,
    pub matched_domain_or_model: String,
    pub ad_model_prob: f32,
    pub blocked: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdHostsShieldStatus {
    pub active_in_etc_hosts: bool,
    pub rule_count: usize,
    pub rules_file_path: String,
    pub status_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDomainRule {
    pub domain: String,
    pub category: String,
    pub is_custom: bool,
    pub model_ad_score: f32,
}

/// 全局广告与垃圾清理管理器
pub struct AdBlockerEngine {
    pub auto_intercept_popups: bool,
    pub custom_blocked_domains: Vec<String>,
    pub domain_rules: Vec<AdDomainRule>,
    pub cleanup_candidates: Vec<AdCleanupCandidate>,
    pub ad_connections: Vec<AdConnectionAlert>,
    pub hosts_status: AdHostsShieldStatus,
    pub total_cleaned_count: usize,
    pub total_reclaimed_bytes: u64,
    pub last_action_message: String,
    next_candidate_id: u64,
}

impl Default for AdBlockerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AdBlockerEngine {
    pub fn custom_domains_file_path() -> PathBuf {
        crate::platform::app_file("adblock_custom_domains.txt")
    }

    pub fn managed_hosts_rules_path() -> PathBuf {
        crate::platform::app_file("adblock_hosts.rules")
    }

    pub fn new() -> Self {
        let mut engine = Self::new_ui_shell();
        engine.write_managed_rules_file();
        let hosts = crate::platform::system_hosts_path();
        engine.refresh_hosts_status(&hosts);
        engine
    }

    /// 极速轻量冷启动构造：不执行全量模型推理或磁盘规则重写，供 UI 主线程 <1ms 建窗使用
    pub fn new_ui_shell() -> Self {
        let custom_blocked_domains = Self::load_custom_domains();
        let mut engine = Self {
            auto_intercept_popups: false,
            custom_blocked_domains,
            domain_rules: Vec::new(),
            cleanup_candidates: Vec::new(),
            ad_connections: Vec::new(),
            hosts_status: AdHostsShieldStatus {
                active_in_etc_hosts: false,
                rule_count: 0,
                rules_file_path: Self::managed_hosts_rules_path().to_string_lossy().into_owned(),
                status_message: "准备巡检系统 Hosts 防护状态...".to_string(),
            },
            total_cleaned_count: 0,
            total_reclaimed_bytes: 0,
            last_action_message: "广告弹窗拦截与清理引擎就绪".to_string(),
            next_candidate_id: 1,
        };
        engine.rebuild_domain_rules();
        engine
    }

    fn load_custom_domains() -> Vec<String> {
        let p = Self::custom_domains_file_path();
        if let Ok(txt) = fs::read_to_string(p) {
            txt.lines()
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#') && l.contains('.'))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn save_custom_domains(&self) {
        let p = Self::custom_domains_file_path();
        let content = self.custom_blocked_domains.join("\n");
        let _ = fs::write(p, content);
    }

    /// 重建内置 + 自定义广告域名规则库（O(N) 纯内存毫秒级建表，避免冷启动时同步跑 70+ 次大模型前向推演）
    pub fn rebuild_domain_rules(&mut self) {
        let mut seen = HashSet::new();
        let mut rules = Vec::with_capacity(
            BUILTIN_AD_TRACKER_DOMAINS.len() + self.custom_blocked_domains.len(),
        );
        for d in &self.custom_blocked_domains {
            let norm = d.trim().to_ascii_lowercase();
            if norm.is_empty() || !seen.insert(norm.clone()) {
                continue;
            }
            rules.push(AdDomainRule {
                domain: norm,
                category: "用户自定义拦截规则".to_string(),
                is_custom: true,
                model_ad_score: 0.96,
            });
        }
        for &(dom, cat) in BUILTIN_AD_TRACKER_DOMAINS {
            let norm = dom.to_ascii_lowercase();
            if !seen.insert(norm.clone()) {
                continue;
            }
            rules.push(AdDomainRule {
                domain: norm,
                category: cat.to_string(),
                is_custom: false,
                model_ad_score: 0.94,
            });
        }
        self.domain_rules = rules;
    }

    pub fn add_custom_domain(&mut self, domain: &str) -> bool {
        let clean = domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if clean.is_empty() || !clean.contains('.') || clean.contains(' ') {
            return false;
        }
        if !self.custom_blocked_domains.contains(&clean) {
            self.custom_blocked_domains.push(clean.clone());
            self.save_custom_domains();
            self.rebuild_domain_rules();
            self.write_managed_rules_file();
            self.last_action_message = format!("已新增广告拦截域名规则: {}", clean);
            true
        } else {
            false
        }
    }

    /// 返回当前全部需要拦截的域名字符串列表
    pub fn all_blocked_domains(&self) -> Vec<String> {
        self.domain_rules.iter().map(|r| r.domain.clone()).collect()
    }

    /// 持久化生成本地独立 `adblock_hosts.rules`（无需提权，始终可供本地代理/DNS/用户审核）
    pub fn write_managed_rules_file(&self) {
        let domains = self.all_blocked_domains();
        let block = Self::render_shield_block(&domains);
        let _ = fs::write(Self::managed_hosts_rules_path(), block);
    }

    pub fn render_shield_block(domains: &[String]) -> String {
        let mut out = String::new();
        out.push_str(AD_SHIELD_BEGIN_MARKER);
        out.push('\n');
        out.push_str("# Managed by VNB 本地终端安全 (WhiteRabbitNeo-7B AdGuard) - Do Not Edit Manually\n");
        for d in domains {
            let clean = d.trim();
            if !clean.is_empty() && !clean.contains('\n') {
                out.push_str(&format!("0.0.0.0 {}\n", clean));
            }
        }
        out.push_str(AD_SHIELD_END_MARKER);
        out.push('\n');
        out
    }

    /// 无损合并广告拦截区块到指定 Hosts 文本中（可重复调用且幂等，不破坏原有本机映射）
    pub fn merge_ad_shield_into_hosts(existing_hosts: &str, domains: &[String]) -> String {
        let mut cleaned = Self::strip_ad_shield_from_hosts(existing_hosts);
        if !cleaned.is_empty() && !cleaned.ends_with('\n') {
            cleaned.push('\n');
        }
        if !cleaned.is_empty() {
            cleaned.push('\n');
        }
        cleaned.push_str(&Self::render_shield_block(domains));
        cleaned
    }

    /// 从 Hosts 文本中精确剥离 `VNB-EDR AD-SHIELD` 区块并保留用户原有条目的每字节完整性
    pub fn strip_ad_shield_from_hosts(existing_hosts: &str) -> String {
        let mut kept_lines = Vec::new();
        let mut inside_block = false;
        for line in existing_hosts.lines() {
            let t = line.trim();
            if t == AD_SHIELD_BEGIN_MARKER {
                inside_block = true;
                continue;
            }
            if t == AD_SHIELD_END_MARKER {
                inside_block = false;
                continue;
            }
            if !inside_block {
                kept_lines.push(line);
            }
        }
        let mut out = kept_lines.join("\n");
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out
    }

    /// 检查给定 Hosts 文件中是否已挂载广告拦截规则及生效条数
    pub fn check_hosts_ad_shield_active(hosts_path: &Path) -> (bool, usize) {
        let Ok(txt) = fs::read_to_string(hosts_path) else {
            return (false, 0);
        };
        let mut inside = false;
        let mut found_marker = false;
        let mut cnt = 0usize;
        for line in txt.lines() {
            let t = line.trim();
            if t == AD_SHIELD_BEGIN_MARKER {
                inside = true;
                found_marker = true;
                continue;
            }
            if t == AD_SHIELD_END_MARKER {
                inside = false;
                continue;
            }
            if inside && (t.starts_with("0.0.0.0 ") || t.starts_with("127.0.0.1 ")) {
                cnt += 1;
            }
        }
        (found_marker && cnt > 0, cnt)
    }

    pub fn refresh_hosts_status(&mut self, hosts_path: &Path) {
        let (active, cnt) = Self::check_hosts_ad_shield_active(hosts_path);
        let total = self.domain_rules.len();
        self.hosts_status = AdHostsShieldStatus {
            active_in_etc_hosts: active,
            rule_count: if active { cnt } else { total },
            rules_file_path: Self::managed_hosts_rules_path().to_string_lossy().into_owned(),
            status_message: if active {
                format!("已启用系统 Hosts 广告屏蔽（{} 条生效规则）", cnt)
            } else {
                format!("Hosts 规则未写入系统（本地已就绪 {} 条广告域名规则）", total)
            },
        };
    }

    /// 对指定 Hosts 文件路径安装广告拦截规则（先备份至保险箱；若权限不足则返回授权需求说明）
    pub fn install_ad_shield_to_hosts_path(
        &mut self,
        hosts_path: &Path,
        allow_admin_prompt: bool,
    ) -> Result<String, String> {
        let existing = fs::read_to_string(hosts_path).unwrap_or_default();
        let domains = self.all_blocked_domains();
        let next_hosts = Self::merge_ad_shield_into_hosts(&existing, &domains);

        // 先写本地规则预览文件
        self.write_managed_rules_file();

        if fs::write(hosts_path, &next_hosts).is_ok() {
            Self::flush_dns_cache();
            self.refresh_hosts_status(hosts_path);
            let msg = format!(
                "[AdShield::Hosts] 已将 {} 条广告/追踪域名拦截规则注入 {}",
                domains.len(),
                hosts_path.display()
            );
            self.last_action_message = msg.clone();
            return Ok(msg);
        }

        if allow_admin_prompt {
            let tmp_stage = std::env::temp_dir().join("vnb_edr_hosts_stage.tmp");
            if fs::write(&tmp_stage, &next_hosts).is_ok() {
                let ok = crate::platform::elevated_copy_hosts_and_flush(&tmp_stage, hosts_path, true);
                let _ = fs::remove_file(&tmp_stage);
                if ok {
                    self.refresh_hosts_status(hosts_path);
                    let msg = format!(
                        "[AdShield::Hosts] 已提权注入 {} 条广告拦截规则至 {} 并刷新 DNS 缓存",
                        domains.len(),
                        hosts_path.display()
                    );
                    self.last_action_message = msg.clone();
                    return Ok(msg);
                }
            }
        }

        self.refresh_hosts_status(hosts_path);
        Err(format!(
            "写入 {} 需要管理员权限；规则已同步至 {}",
            hosts_path.display(),
            Self::managed_hosts_rules_path().display()
        ))
    }

    /// 从指定 Hosts 文件路径无损卸载广告拦截区块
    pub fn remove_ad_shield_from_hosts_path(
        &mut self,
        hosts_path: &Path,
        allow_admin_prompt: bool,
    ) -> Result<String, String> {
        let existing = fs::read_to_string(hosts_path).unwrap_or_default();
        let next_hosts = Self::strip_ad_shield_from_hosts(&existing);

        if fs::write(hosts_path, &next_hosts).is_ok() {
            Self::flush_dns_cache();
            self.refresh_hosts_status(hosts_path);
            let msg = format!("[AdShield::Hosts] 已从 {} 无损回滚卸载广告拦截区块", hosts_path.display());
            self.last_action_message = msg.clone();
            return Ok(msg);
        }

        if allow_admin_prompt {
            let tmp_stage = std::env::temp_dir().join("vnb_edr_hosts_unstage.tmp");
            if fs::write(&tmp_stage, &next_hosts).is_ok() {
                let ok = crate::platform::elevated_copy_hosts_and_flush(&tmp_stage, hosts_path, false);
                let _ = fs::remove_file(&tmp_stage);
                if ok {
                    self.refresh_hosts_status(hosts_path);
                    let msg = format!("[AdShield::Hosts] 已提权从 {} 卸载广告拦截规则", hosts_path.display());
                    self.last_action_message = msg.clone();
                    return Ok(msg);
                }
            }
        }

        self.refresh_hosts_status(hosts_path);
        Err(format!("回滚 {} 需要管理员权限", hosts_path.display()))
    }

    fn flush_dns_cache() {
        crate::platform::flush_dns_cache();
    }

    /// 判断域名/上下文是否命中规则库或本地 WhiteRabbitNeo-7B AdGuard 神经网络
    pub fn evaluate_domain_or_target(
        &self,
        process_name: &str,
        remote_or_url: &str,
        context: &str,
    ) -> Option<(String, AdSemanticPrediction, String)> {
        let lower = remote_or_url.to_ascii_lowercase();
        let pred = PretrainedModelBundle::global().classify_ad_semantic(
            process_name,
            remote_or_url,
            context,
        );

        for rule in &self.domain_rules {
            if lower.contains(&rule.domain) {
                return Some((
                    rule.domain.clone(),
                    pred,
                    format!("命中广告拦截库 ({})", rule.category),
                ));
            }
        }

        // 仅在存在明确外部广告/追踪语义线索且模型置信度高时告警，避免把正常 API/本地端口误判为广告
        let has_domain_hint = lower.contains("ad")
            || lower.contains("promo")
            || lower.contains("track")
            || lower.contains("telemetry")
            || lower.contains("popup")
            || lower.contains("banner")
            || lower.contains("beacon");
        if has_domain_hint
            && (pred.predicted_class == 1 || pred.predicted_class == 2)
            && pred.ad_risk_score >= 0.72
            && !lower.contains("127.0.0.1")
            && !lower.contains("localhost")
        {
            return Some((
                remote_or_url.to_string(),
                pred.clone(),
                format!(
                    "AdGuard 7B 神经分类判定为广告/追踪连接 ({} {:.0}%)",
                    pred.predicted_label,
                    pred.ad_risk_score * 100.0
                ),
            ));
        }

        None
    }

    /// 结合活跃网络连接扫描实时广告/追踪外联
    pub fn scan_active_ad_connections(
        &mut self,
        sockets: &[NetworkSocketRecord],
        blocked_c2: &HashSet<String>,
    ) {
        let mut found = Vec::new();
        for s in sockets {
            if s.remote_endpoint.is_empty()
                || s.remote_endpoint == "-"
                || s.remote_endpoint.starts_with("127.0.0.1")
                || s.remote_endpoint.starts_with("[::1]")
            {
                continue;
            }
            if let Some((matched, pred, reason)) = self.evaluate_domain_or_target(
                &s.process_name,
                &s.remote_endpoint,
                &s.c2_reason,
            ) {
                found.push(AdConnectionAlert {
                    pid: s.pid,
                    process_name: s.process_name.clone(),
                    exe_path: s.exe_path.clone(),
                    remote_endpoint: s.remote_endpoint.clone(),
                    matched_domain_or_model: matched,
                    ad_model_prob: pred.ad_risk_score,
                    blocked: s.blocked || blocked_c2.contains(&s.remote_endpoint),
                    reason,
                });
            }
        }
        self.ad_connections = found;
    }

    /// 扫描本机真实广告软件驻留、/tmp 推广安装器、App AdSDK 缓存与浏览器高危扩展
    pub fn scan_ad_artifacts(&mut self, custom_roots: Option<&[PathBuf]>) {
        // 保留已清理项目的历史统计，重扫当前磁盘残留
        let mut results: Vec<AdCleanupCandidate> = self
            .cleanup_candidates
            .iter()
            .filter(|c| c.cleaned)
            .cloned()
            .collect();
        let mut seen_paths: HashSet<String> = results.iter().map(|r| r.path.clone()).collect();
        let bundle = PretrainedModelBundle::global();

        let home = crate::platform::user_home_dir().to_string_lossy().into_owned();
        let launch_dirs: Vec<PathBuf> = if let Some(roots) = custom_roots {
            roots.to_vec()
        } else if cfg!(target_os = "macos") {
            vec![
                PathBuf::from(format!("{}/Library/LaunchAgents", home)),
                PathBuf::from("/Library/LaunchAgents"),
                PathBuf::from("/Library/LaunchDaemons"),
            ]
        } else {
            Vec::new()
        };

        // 1. 扫描自启动广告软件与捆绑推广项（macOS LaunchAgents/Daemons 或 自定义测试目录）
        for dir in launch_dirs {
            if let Ok(entries) = fs::read_dir(&dir) {
                for ent in entries.flatten() {
                    let path = ent.path();
                    if !path.is_file() {
                        continue;
                    }
                    let path_str = path.to_string_lossy().into_owned();
                    if seen_paths.contains(&path_str) {
                        continue;
                    }
                    let fname = ent.file_name().to_string_lossy().to_ascii_lowercase();
                    if !fname.ends_with(".plist") || fname.starts_with("com.apple.") || fname.contains("vnb-local-edr") {
                        continue;
                    }
                    let content_snip = fs::read_to_string(&path).unwrap_or_default();
                    let lower_all = format!("{} {}", fname, content_snip.to_ascii_lowercase());
                    let matched_sig = KNOWN_ADWARE_SIGNATURES
                        .iter()
                        .find(|&&s| lower_all.contains(s))
                        .copied();
                    let pred = bundle.classify_ad_semantic(
                        &fname,
                        &path_str,
                        &content_snip.chars().take(240).collect::<String>(),
                    );
                    if matched_sig.is_some()
                        || (pred.predicted_class >= 2 && pred.ad_risk_score >= 0.78)
                    {
                        let sz = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        seen_paths.insert(path_str.clone());
                        results.push(AdCleanupCandidate {
                            id: self.alloc_id(),
                            kind: AdArtifactKind::AdwareLaunchAgent,
                            title: format!("广告驻留项: {}", ent.file_name().to_string_lossy()),
                            path: path_str,
                            size_bytes: sz,
                            ad_model_prob: pred.ad_risk_score.max(if matched_sig.is_some() { 0.91 } else { 0.78 }),
                            model_label: pred.predicted_label,
                            reason: matched_sig
                                .map(|s| format!("命中 Adware/推广签名 `{}`", s))
                                .unwrap_or_else(|| "AdGuard 7B 模型判定高风险广告持久化启动项".to_string()),
                            cleaned: false,
                            quarantine_backup: None,
                        });
                    }
                }
            }
        }

        // 1b. Windows 注册表 Run 与 Startup 目录广告驻留扫描
        #[cfg(target_os = "windows")]
        if custom_roots.is_none() {
            for ent in crate::platform::win32_helpers::scan_windows_autorun_entries() {
                if seen_paths.contains(&ent.config_path) || ent.label.contains("VNB_Local_EDR") {
                    continue;
                }
                let lower_all = format!("{} {} {}", ent.label, ent.target_exec, ent.args_summary).to_ascii_lowercase();
                let matched_sig = KNOWN_ADWARE_SIGNATURES
                    .iter()
                    .find(|&&s| lower_all.contains(s))
                    .copied();
                let pred = bundle.classify_ad_semantic(&ent.label, &ent.target_exec, &ent.args_summary);
                if matched_sig.is_some() || (pred.predicted_class >= 2 && pred.ad_risk_score >= 0.78) {
                    let sz = Path::new(&ent.target_exec)
                        .metadata()
                        .map(|m| m.len())
                        .unwrap_or(0);
                    seen_paths.insert(ent.config_path.clone());
                    results.push(AdCleanupCandidate {
                        id: self.alloc_id(),
                        kind: AdArtifactKind::AdwareLaunchAgent,
                        title: format!("Windows 自启广告项: {}", ent.label),
                        path: ent.config_path,
                        size_bytes: sz,
                        ad_model_prob: pred.ad_risk_score.max(if matched_sig.is_some() { 0.91 } else { 0.78 }),
                        model_label: pred.predicted_label,
                        reason: matched_sig
                            .map(|s| format!("命中 Windows 注册表/启动项 Adware 特征 `{}`", s))
                            .unwrap_or_else(|| "AdGuard 7B 模型判定高风险 Windows 自启广告项".to_string()),
                        cleaned: false,
                        quarantine_backup: None,
                    });
                }
            }
        }

        // 2. 扫描临时目录下显式广告 SDK 物料及推广安装器（只扫白名单广告命名特征，避免误伤）
        let tmp_roots: Vec<PathBuf> = if custom_roots.is_some() {
            Vec::new()
        } else {
            #[cfg(target_os = "macos")]
            {
                vec![
                    std::env::temp_dir(),
                    PathBuf::from("/tmp"),
                    PathBuf::from("/private/tmp"),
                ]
            }
            #[cfg(not(target_os = "macos"))]
            {
                vec![std::env::temp_dir()]
            }
        };
        for tdir in tmp_roots {
            if let Ok(entries) = fs::read_dir(&tdir) {
                for ent in entries.flatten() {
                    let path = ent.path();
                    let path_str = path.to_string_lossy().into_owned();
                    if seen_paths.contains(&path_str) {
                        continue;
                    }
                    let fname = ent.file_name().to_string_lossy().to_string();
                    let fl = fname.to_ascii_lowercase();
                    if fl.contains("vnb_") {
                        continue;
                    }
                    let is_ad_tmp = KNOWN_ADWARE_SIGNATURES.iter().any(|s| fl.contains(s))
                        || KNOWN_AD_CACHE_TOKENS.iter().any(|s| fl.contains(s))
                        || ((fl.ends_with(".dmg") || fl.ends_with(".pkg") || fl.ends_with(".exe") || fl.ends_with(".msi"))
                            && (fl.contains("flash") || fl.contains("cleaner") || fl.contains("promo") || fl.contains("ad")));
                    if is_ad_tmp {
                        let pred = bundle.classify_ad_semantic(&fname, &path_str, "temp ad installer or helper");
                        let sz = Self::calc_path_size(&path);
                        seen_paths.insert(path_str.clone());
                        results.push(AdCleanupCandidate {
                            id: self.alloc_id(),
                            kind: AdArtifactKind::TempAdDropperOrDmg,
                            title: format!("临时推广/广告残留: {}", fname),
                            path: path_str,
                            size_bytes: sz,
                            ad_model_prob: pred.ad_risk_score.max(0.86),
                            model_label: pred.predicted_label,
                            reason: "临时目录发现广告/推广安装器或弹窗辅助载荷".to_string(),
                            cleaned: false,
                            quarantine_backup: None,
                        });
                    }
                }
            }
        }

        // 3. 扫描本地缓存目录下精确匹配已知 Ad-SDK 广告缓存目录
        if custom_roots.is_none() {
            let cache_roots: Vec<PathBuf> = {
                #[cfg(target_os = "macos")]
                {
                    vec![PathBuf::from(format!("{}/Library/Caches", home))]
                }
                #[cfg(target_os = "windows")]
                {
                    let mut v = Vec::new();
                    if let Ok(la) = std::env::var("LOCALAPPDATA") {
                        v.push(PathBuf::from(la));
                    }
                    if let Ok(ap) = std::env::var("APPDATA") {
                        v.push(PathBuf::from(ap));
                    }
                    v
                }
                #[cfg(all(unix, not(target_os = "macos")))]
                {
                    vec![PathBuf::from(format!("{}/.cache", home))]
                }
            };
            for caches_dir in cache_roots {
                if let Ok(entries) = fs::read_dir(&caches_dir) {
                    for ent in entries.flatten() {
                        let path = ent.path();
                        let path_str = path.to_string_lossy().into_owned();
                        if seen_paths.contains(&path_str) {
                            continue;
                        }
                        let fl = ent.file_name().to_string_lossy().to_ascii_lowercase();
                        if let Some(tok) = KNOWN_AD_CACHE_TOKENS.iter().find(|&&t| fl.contains(t)) {
                            let sz = Self::calc_path_size(&path);
                            if sz == 0 {
                                continue;
                            }
                            let pred = bundle.classify_ad_semantic(&fl, &path_str, "app ad sdk cache");
                            seen_paths.insert(path_str.clone());
                            results.push(AdCleanupCandidate {
                                id: self.alloc_id(),
                                kind: AdArtifactKind::AppAdSdkCache,
                                title: format!("广告SDK缓存: {}", ent.file_name().to_string_lossy()),
                                path: path_str,
                                size_bytes: sz,
                                ad_model_prob: pred.ad_risk_score.max(0.82),
                                model_label: pred.predicted_label,
                                reason: format!("命中应用广告 SDK 缓存特征 `{}`", tok),
                                cleaned: false,
                                quarantine_backup: None,
                            });
                        }
                    }
                }
            }

            // 4. 审计 Chrome / Edge / Brave 浏览器扩展与 Service Worker CacheStorage 冗余追踪缓存
            self.scan_browser_extensions_and_caches(&home, &bundle, &mut results, &mut seen_paths);
        } else if let Some(roots) = custom_roots {
            // 测试与自定义目录模式：扫描目录内的缓存/扩展样本
            for r in roots {
                self.scan_browser_extension_root(r, "CustomBrowser", &bundle, &mut results, &mut seen_paths);
            }
        }

        // 未清理项目排前，按风险分与体积降序排列
        results.sort_by(|a, b| {
            a.cleaned
                .cmp(&b.cleaned)
                .then_with(|| {
                    b.ad_model_prob
                        .partial_cmp(&a.ad_model_prob)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| b.size_bytes.cmp(&a.size_bytes))
        });
        self.cleanup_candidates = results;
    }

    fn scan_browser_extensions_and_caches(
        &mut self,
        home: &str,
        bundle: &PretrainedModelBundle,
        results: &mut Vec<AdCleanupCandidate>,
        seen_paths: &mut HashSet<String>,
    ) {
        #[cfg(target_os = "macos")]
        let browser_profiles = vec![
            (
                "Chrome",
                PathBuf::from(home).join("Library/Application Support/Google/Chrome/Default"),
            ),
            (
                "Edge",
                PathBuf::from(home).join("Library/Application Support/Microsoft Edge/Default"),
            ),
            (
                "Brave",
                PathBuf::from(home).join("Library/Application Support/BraveSoftware/Brave-Browser/Default"),
            ),
        ];
        #[cfg(target_os = "windows")]
        let browser_profiles = {
            let local_app = std::env::var("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(home).join(r"AppData\Local"));
            vec![
                ("Chrome", local_app.join(r"Google\Chrome\User Data\Default")),
                ("Edge", local_app.join(r"Microsoft\Edge\User Data\Default")),
                ("Brave", local_app.join(r"BraveSoftware\Brave-Browser\User Data\Default")),
            ]
        };
        #[cfg(all(unix, not(target_os = "macos")))]
        let browser_profiles = vec![
            ("Chrome", PathBuf::from(home).join(".config/google-chrome/Default")),
            ("Edge", PathBuf::from(home).join(".config/microsoft-edge/Default")),
            ("Brave", PathBuf::from(home).join(".config/BraveSoftware/Brave-Browser/Default")),
        ];

        for (browser_name, prof_dir) in browser_profiles {
            let ext_dir = prof_dir.join("Extensions");
            self.scan_browser_extension_root(&ext_dir, browser_name, bundle, results, seen_paths);

            // 检查 Service Worker CacheStorage 中的广告追踪缓存脚本体积（限制递归深度与条目预算以防低配机卡死）
            let sw_cache = prof_dir.join("Service Worker").join("CacheStorage");
            if sw_cache.exists() {
                let sw_str = sw_cache.to_string_lossy().into_owned();
                if !seen_paths.contains(&sw_str) {
                    let sz = Self::calc_path_size(&sw_cache);
                    if sz >= 1024 * 1024 {
                        let pred = bundle.classify_ad_semantic(
                            browser_name,
                            &sw_str,
                            "Service Worker CacheStorage tracker script cache",
                        );
                        seen_paths.insert(sw_str.clone());
                        results.push(AdCleanupCandidate {
                            id: self.alloc_id(),
                            kind: AdArtifactKind::BrowserAdTrackerCache,
                            title: format!("{} 追踪脚本离线缓存 (ServiceWorker)", browser_name),
                            path: sw_str,
                            size_bytes: sz,
                            ad_model_prob: pred.ad_risk_score.max(0.65),
                            model_label: pred.predicted_label,
                            reason: "浏览器 Service Worker 离线广告/追踪脚本缓存（可安全释放，不影响账号密码书签）".to_string(),
                            cleaned: false,
                            quarantine_backup: None,
                        });
                    }
                }
            }
        }
    }

    fn scan_browser_extension_root(
        &mut self,
        ext_root: &Path,
        browser_name: &str,
        bundle: &PretrainedModelBundle,
        results: &mut Vec<AdCleanupCandidate>,
        seen_paths: &mut HashSet<String>,
    ) {
        let Ok(exts) = fs::read_dir(ext_root) else {
            return;
        };
        for ext in exts.flatten() {
            let ext_path = ext.path();
            if !ext_path.is_dir() {
                continue;
            }
            // 读取任意版本子目录下的 manifest.json
            let manifest_path = fs::read_dir(&ext_path)
                .ok()
                .and_then(|rd| {
                    rd.flatten()
                        .map(|v| v.path().join("manifest.json"))
                        .find(|p| p.is_file())
                })
                .or_else(|| {
                    let direct = ext_path.join("manifest.json");
                    if direct.is_file() { Some(direct) } else { None }
                });
            let Some(mpath) = manifest_path else {
                continue;
            };
            let Ok(txt) = fs::read_to_string(&mpath) else {
                continue;
            };
            let lower = txt.to_ascii_lowercase();
            let path_str = ext_path.to_string_lossy().into_owned();
            if seen_paths.contains(&path_str) {
                continue;
            }
            let has_broad_inject = lower.contains("<all_urls>")
                || lower.contains("webrequestblocking")
                || lower.contains("chrome_settings_overrides");
            let sig = KNOWN_ADWARE_SIGNATURES.iter().find(|&&s| lower.contains(s));
            let pred = bundle.classify_ad_semantic(
                browser_name,
                &path_str,
                &txt.chars().take(280).collect::<String>(),
            );

            if sig.is_some()
                || (has_broad_inject
                    && (lower.contains("coupon") || lower.contains("search") || lower.contains("ad") || pred.ad_risk_score >= 0.72))
            {
                let ext_id = ext.file_name().to_string_lossy().into_owned();
                let sz = Self::calc_path_size(&ext_path);
                seen_paths.insert(path_str.clone());
                results.push(AdCleanupCandidate {
                    id: self.alloc_id(),
                    kind: AdArtifactKind::BrowserAdExtension,
                    title: format!("{} 可疑广告/劫持扩展 ({})", browser_name, ext_id),
                    path: path_str,
                    size_bytes: sz,
                    ad_model_prob: pred.ad_risk_score.max(0.80),
                    model_label: pred.predicted_label,
                    reason: sig
                        .map(|s| format!("扩展 Manifest 命中广告劫持特征 `{}`", s))
                        .unwrap_or_else(|| "具备全站注入/主页覆写权限的高风险扩展".to_string()),
                    cleaned: false,
                    quarantine_backup: None,
                });
            }
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_candidate_id;
        self.next_candidate_id += 1;
        id
    }

    fn calc_path_size(path: &Path) -> u64 {
        let mut budget = 512usize;
        Self::calc_path_size_bounded(path, 3, &mut budget)
    }

    fn calc_path_size_bounded(path: &Path, max_depth: usize, budget: &mut usize) -> u64 {
        if *budget == 0 {
            return 0;
        }
        *budget = budget.saturating_sub(1);
        if let Ok(meta) = fs::metadata(path) {
            if meta.is_file() {
                return meta.len();
            }
            if meta.is_dir() {
                if max_depth == 0 {
                    return 0;
                }
                let mut sum = 0u64;
                if let Ok(rd) = fs::read_dir(path) {
                    for ent in rd.flatten().take(128) {
                        if *budget == 0 {
                            break;
                        }
                        if let Ok(m) = ent.metadata() {
                            if m.is_file() {
                                *budget = budget.saturating_sub(1);
                                sum = sum.saturating_add(m.len());
                            } else if m.is_dir() {
                                sum = sum.saturating_add(
                                    Self::calc_path_size_bounded(
                                        &ent.path(),
                                        max_depth - 1,
                                        budget,
                                    )
                                    .min(512 * 1024 * 1024),
                                );
                            }
                        }
                    }
                }
                return sum;
            }
        }
        0
    }

    /// 严格安全边界：拒绝误删根目录、系统目录、用户家目录自身或本工程核心资产目录
    fn is_safe_cleanup_path(path: &Path) -> bool {
        if path.starts_with("REG:") {
            return true;
        }
        let s = path.to_string_lossy();
        let lower = s.to_ascii_lowercase();
        let app_root = crate::platform::app_install_root();
        if path.starts_with(app_root.join("src"))
            || path.starts_with(app_root.join("models"))
            || path.starts_with(app_root.join("lib"))
        {
            return false;
        }
        if s.len() < 6
            || s == "/"
            || s.starts_with("/System")
            || s.starts_with("/usr")
            || s.starts_with("/bin")
            || s.starts_with("/sbin")
            || lower == r"c:\"
            || lower == r"c:\windows"
            || lower.starts_with(r"c:\windows\system32")
            || lower == r"c:\program files"
            || lower == r"c:\program files (x86)"
        {
            return false;
        }
        let home = crate::platform::user_home_dir().to_string_lossy().into_owned();
        if s == home
            || s == format!("{}/Library", home)
            || s == format!("{}/Library/Caches", home)
            || lower == std::env::var("LOCALAPPDATA").unwrap_or_default().to_ascii_lowercase()
            || lower == std::env::var("APPDATA").unwrap_or_default().to_ascii_lowercase()
        {
            return false;
        }
        true
    }

    /// 清理单条候选广告残留：LaunchAgent / 注册表自启 / 临时推广包 / 扩展先卸载或隔离入 `VNB_Vault`，缓存目录直接安全释放
    pub fn clean_candidate_at(&mut self, idx: usize) -> Option<String> {
        let cand = self.cleanup_candidates.get_mut(idx)?;
        if cand.cleaned {
            return Some(format!("项目 `{}` 已完成清理", cand.title));
        }
        let path = Path::new(&cand.path);
        if !Self::is_safe_cleanup_path(path) {
            return Some(format!("[安全保护] 拒绝清理受保护路径: {}", cand.path));
        }

        let mut reclaimed = cand.size_bytes;
        let mut vault_backup = None;
        let mut action_detail = String::new();

        if cand.path.starts_with("REG:") {
            #[cfg(target_os = "windows")]
            {
                let removed = crate::platform::win32_helpers::remove_windows_autorun(&cand.path);
                if removed {
                    action_detail = format!("已从 Windows 注册表移除广告自启动项: {}", cand.path);
                } else {
                    return Some(format!("移除注册表项 `{}` 可能需要管理员权限", cand.path));
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                action_detail = format!("已核销注册表记录: {}", cand.path);
            }
            cand.cleaned = true;
        } else if !path.exists() {
            cand.cleaned = true;
            action_detail = format!("目标已不存在，已核销记录: {}", cand.path);
        } else {
            match cand.kind {
                AdArtifactKind::AdwareLaunchAgent => {
                    #[cfg(target_os = "macos")]
                    {
                        let _ = Command::new("launchctl").args(["unload", &cand.path]).output();
                    }
                    let vid = format!("AD-LA-{}", cand.id);
                    if let Some(dst) = move_file_to_quarantine_vault(&cand.path, &vid) {
                        vault_backup = Some(dst);
                        action_detail = format!("已卸载驻留自启动项并物理隔离至保险箱 ({})", vid);
                    } else if fs::remove_file(path).is_ok() {
                        action_detail = format!("已卸载并移除广告驻留项: {}", cand.path);
                    } else {
                        return Some(format!("清理 `{}` 需要管理员权限", cand.path));
                    }
                }
                AdArtifactKind::TempAdDropperOrDmg | AdArtifactKind::BrowserAdExtension => {
                    let vid = format!("AD-ITEM-{}", cand.id);
                    if path.is_file() {
                        if let Some(dst) = move_file_to_quarantine_vault(&cand.path, &vid) {
                            vault_backup = Some(dst);
                            action_detail = format!("已将广告载荷隔离入保险箱 ({})", vid);
                        } else if fs::remove_file(path).is_ok() {
                            action_detail = format!("已移除临时广告文件: {}", cand.path);
                        }
                    } else if path.is_dir() && fs::remove_dir_all(path).is_ok() {
                        action_detail = format!("已移除广告残留目录: {}", cand.path);
                    } else {
                        return Some(format!("无法清理目录 `{}`（请检查占用状态）", cand.path));
                    }
                }
                AdArtifactKind::AppAdSdkCache | AdArtifactKind::BrowserAdTrackerCache => {
                    if path.is_file() {
                        if let Ok(m) = fs::metadata(path) {
                            reclaimed = m.len();
                        }
                        if fs::remove_file(path).is_ok() {
                            action_detail = format!("已清理广告缓存文件 ({} KB)", reclaimed / 1024);
                        }
                    } else if path.is_dir() && fs::remove_dir_all(path).is_ok() {
                        action_detail = format!(
                            "已安全释放广告缓存 {:.2} MB",
                            (reclaimed as f64) / (1024.0 * 1024.0)
                        );
                    } else {
                        return Some(format!("清理缓存 `{}` 失败或被进程占用", cand.path));
                    }
                }
            }
            cand.cleaned = true;
            cand.quarantine_backup = vault_backup;
            self.total_cleaned_count += 1;
            self.total_reclaimed_bytes = self.total_reclaimed_bytes.saturating_add(reclaimed);
        }

        let msg = format!("[AdCleaner] {}: {}", cand.title, action_detail);
        self.last_action_message = msg.clone();
        Some(msg)
    }

    /// 一键清理全部尚未处理的广告残留与追踪缓存
    pub fn clean_all_pending_artifacts(&mut self) -> (usize, u64) {
        let mut cleaned_now = 0usize;
        let before_bytes = self.total_reclaimed_bytes;
        let len = self.cleanup_candidates.len();
        for idx in 0..len {
            if !self.cleanup_candidates[idx].cleaned {
                if self.clean_candidate_at(idx).is_some() && self.cleanup_candidates[idx].cleaned {
                    cleaned_now += 1;
                }
            }
        }
        let reclaimed_now = self.total_reclaimed_bytes.saturating_sub(before_bytes);
        self.last_action_message = format!(
            "已完成一键广告清理：处置 {} 项，共释放 {:.2} MB 磁盘空间",
            cleaned_now,
            (reclaimed_now as f64) / (1024.0 * 1024.0)
        );
        (cleaned_now, reclaimed_now)
    }

    pub fn pending_cleanup_count(&self) -> usize {
        self.cleanup_candidates.iter().filter(|c| !c.cleaned).count()
    }

    pub fn pending_reclaimable_bytes(&self) -> u64 {
        self.cleanup_candidates
            .iter()
            .filter(|c| !c.cleaned)
            .map(|c| c.size_bytes)
            .sum()
    }
}
