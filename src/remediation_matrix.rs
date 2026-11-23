//! 统一威胁处置矩阵与风险控制引擎 (Unified Remediation Matrix & Risk Control)
//!
//! 核心职责：
//! 1. **三维处置矩阵映射**：将 `(ThreatVector × RiskTier × HostContextProfile)` 映射为确定性的
//!    `RemediationMatrixPlan`（包含标准主动作 `A0..A4`、细粒度多阶段杀伤链 `KillChainAction`、
//!    影响面半径 `blast_radius_score` 与可逆性评估 `reversibility`）。
//! 2. **硬性风控护栏 (`RiskControlPolicy`)**：
//!    - 核心系统与自进程防误杀护栏（阻止对 `PID <= 1`、自身进程、`launchd`/`WindowServer`/`Finder`/
//!      Windows `csrss`/`lsass`/`services`/`svchost` 及系统目录核心程序执行挂起或强杀）；
//!    - 活跃工作宿主降级护栏（存在未保存用户文档或关键 Shell 宿主时，阻止自动强杀并降级为人工确认/局域冻结）；
//!    - 干跑演练模式 (`dry_run_mode`) 与单轮自动查杀熔断器 (`max_auto_kills_per_cycle`)，防止误报风暴导致系统雪崩。

use crate::contract::{HostContextProfile, PolicyAction};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 威胁攻击面与处置维度分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatVector {
    ReverseShell,
    ProcessInjection,
    TempDropper,
    PersistenceBackdoor,
    C2Outbound,
    ExposedWildcardPort,
    AdwarePopupHijack,
    CredentialExposure,
    GenericAnomaly,
}

impl ThreatVector {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ReverseShell => "REVSHELL",
            Self::ProcessInjection => "INJECT",
            Self::TempDropper => "DROPPER",
            Self::PersistenceBackdoor => "PERSIST",
            Self::C2Outbound => "C2-NET",
            Self::ExposedWildcardPort => "WILDCARD",
            Self::AdwarePopupHijack => "ADWARE",
            Self::CredentialExposure => "CRED-FIM",
            Self::GenericAnomaly => "ANOMALY",
        }
    }

    pub fn cn_label(&self) -> &'static str {
        match self {
            Self::ReverseShell => "反弹 Shell / 远控指令",
            Self::ProcessInjection => "内存 / DYLD / DLL 注入",
            Self::TempDropper => "临时/隐藏目录未签名载荷",
            Self::PersistenceBackdoor => "自启动持久化后门",
            Self::C2Outbound => "C2 恶意通信 / 情报命中",
            Self::ExposedWildcardPort => "0.0.0.0 全网口高危暴露",
            Self::AdwarePopupHijack => "广告弹窗 / 桌面窗口劫持",
            Self::CredentialExposure => "敏感凭据权限过宽 / 篡改",
            Self::GenericAnomaly => "一般行为异常 / 待研判",
        }
    }
}

/// 处置风险等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    L1Low = 1,
    L2Medium = 2,
    L3High = 3,
    L4Critical = 4,
}

impl RiskTier {
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=100 => Self::L4Critical,
            55..=79 => Self::L3High,
            25..=54 => Self::L2Medium,
            _ => Self::L1Low,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::L1Low => "L1",
            Self::L2Medium => "L2",
            Self::L3High => "L3",
            Self::L4Critical => "L4",
        }
    }

    pub fn cn_label(&self) -> &'static str {
        match self {
            Self::L1Low => "L1 低危观测",
            Self::L2Medium => "L2 中危收敛",
            Self::L3High => "L3 高危拦截",
            Self::L4Critical => "L4 严重猎杀",
        }
    }
}

/// 风险控制放行闸门状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionGate {
    AutoEnforce,
    RequireConfirm,
    BlockedByGuardrail,
    DryRunObserve,
}

impl ExecutionGate {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AutoEnforce => "AUTO",
            Self::RequireConfirm => "CONFIRM",
            Self::BlockedByGuardrail => "GUARDRAIL",
            Self::DryRunObserve => "DRY-RUN",
        }
    }

    pub fn cn_label(&self) -> &'static str {
        match self {
            Self::AutoEnforce => "允许自动/一键执行",
            Self::RequireConfirm => "风控要求人工确认",
            Self::BlockedByGuardrail => "核心护栏禁止强杀",
            Self::DryRunObserve => "干跑演练模式（只审计不破坏）",
        }
    }
}

/// 处置矩阵分解后的标准化原子查杀与加固步骤
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillChainAction {
    SuspendProcessTree,
    TerminateProcessTree,
    BlockSpawnPathAndHash,
    BlockNetworkEndpoints,
    UnloadPersistence,
    QuarantineExecutableOrDrop,
    HardenCredentialAcl,
    AllowlistTrustBaseline,
}

impl KillChainAction {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SuspendProcessTree => "SUSPEND_TREE",
            Self::TerminateProcessTree => "KILL_TREE",
            Self::BlockSpawnPathAndHash => "SPAWN_BLOCK_HASH",
            Self::BlockNetworkEndpoints => "FW_IPS_BLOCK",
            Self::UnloadPersistence => "UNLOAD_PERSIST",
            Self::QuarantineExecutableOrDrop => "QUARANTINE_VAULT",
            Self::HardenCredentialAcl => "CHMOD_0600",
            Self::AllowlistTrustBaseline => "TRUST_ALLOWLIST",
        }
    }

    pub fn cn_label(&self) -> &'static str {
        match self {
            Self::SuspendProcessTree => "挂起进程树防逃逸",
            Self::TerminateProcessTree => "递归击毙父子进程树",
            Self::BlockSpawnPathAndHash => "路径+SHA256双因子禁生",
            Self::BlockNetworkEndpoints => "联动防火墙/IPS阻断端点",
            Self::UnloadPersistence => "卸载移除自启动驻留",
            Self::QuarantineExecutableOrDrop => "隔离可执行体/载荷至保险箱",
            Self::HardenCredentialAcl => "收敛凭据权限(0600/ACL)",
            Self::AllowlistTrustBaseline => "加白放行并写入基线",
        }
    }
}

/// 全局风险控制策略与自动查杀熔断配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskControlPolicy {
    /// 是否允许对确认的高危恶意实体（反弹 Shell / 临时目录恶意执行体 / 注入）自动执行强隔离
    pub auto_enforce_critical: bool,
    /// 全局干跑演练模式：仅输出矩阵推演与审计日志，禁止真实挂起/杀进程/隔离删除文件
    pub dry_run_mode: bool,
    /// 核心系统进程/关键目录防变砖硬护栏
    pub protect_critical_system_hosts: bool,
    /// 活跃工作文档/Shell 宿主防误杀护栏（自动降级为局部静音/人工确认）
    pub protect_active_document_hosts: bool,
    /// 处置 C2 外联或全网口暴露面时自动联动下发 Firewall/IPS 阻断规则
    pub auto_block_c2_network: bool,
    /// 单轮巡检允许自动终止的最大进程数熔断阈值
    pub max_auto_kills_per_cycle: u32,
    /// 当前轮次已触发自动查杀计数
    pub kills_in_current_cycle: u32,
    /// 是否已触发风控熔断器
    pub circuit_breaker_tripped: bool,
    /// 最近轮次时间戳
    pub last_cycle_epoch: u64,
}

impl Default for RiskControlPolicy {
    fn default() -> Self {
        Self {
            auto_enforce_critical: true,
            dry_run_mode: false,
            protect_critical_system_hosts: true,
            protect_active_document_hosts: true,
            auto_block_c2_network: true,
            max_auto_kills_per_cycle: 3,
            kills_in_current_cycle: 0,
            circuit_breaker_tripped: false,
            last_cycle_epoch: 0,
        }
    }
}

/// 矩阵评估输入上下文快照（由引擎统一从 Process/Alert/Socket/Persistence/Intel 聚合构造）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixTargetContext {
    pub pid: u32,
    pub ppid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub code_signer: String,
    pub summary_hint: String,
    pub domain_hint: String,
    pub z3_malicious_prob: f32,
    pub has_reverse_shell: bool,
    pub has_dyld_or_dll_inject: bool,
    pub in_temp_or_hidden: bool,
    pub intel_matched: bool,
    pub is_benign_dev_tool: bool,
    pub is_adware_popup: bool,
    pub is_fim_credential_issue: bool,
    pub wildcard_ports: Vec<u16>,
    pub remote_endpoints: Vec<(String, u16)>,
    pub persistence_paths: Vec<String>,
    pub dropped_files: Vec<String>,
    pub host_profile: HostContextProfile,
    #[serde(default)]
    pub ancestry_chain: String,
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub entry_script_or_config: String,
    #[serde(default)]
    pub sha256_hex: String,
    #[serde(default)]
    pub provenance_hint: String,
}

/// 处置矩阵评估结果与可审计剧本
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationMatrixPlan {
    pub rule_id: String,
    pub vector: ThreatVector,
    pub risk_tier: RiskTier,
    pub risk_score: u8,
    pub blast_radius_score: u8,
    pub reversibility: String,
    pub recommended_action: PolicyAction,
    pub effective_action: PolicyAction,
    pub gate: ExecutionGate,
    pub guardrail_reason: Option<String>,
    pub ordered_steps: Vec<KillChainAction>,
    pub target_ips_ports: Vec<(String, u16)>,
    pub target_persistence_paths: Vec<String>,
    pub target_dropped_files: Vec<String>,
    pub rationale: String,
}

/// 处置矩阵全览规则行（供 UI 展示与审计报告导出）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRuleRow {
    pub rule_id: String,
    pub vector: ThreatVector,
    pub min_tier: RiskTier,
    pub default_action: PolicyAction,
    pub steps_summary: String,
    pub host_guardrail: String,
}

/// 统一处置矩阵与风险控制评估引擎
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationMatrixEngine {
    pub policy: RiskControlPolicy,
    pub evaluations_count: u64,
    pub executed_plans_count: u64,
    pub blocked_by_guardrail_count: u64,
    pub circuit_breaker_trips: u64,
    pub dry_run_simulations_count: u64,
}

impl Default for RemediationMatrixEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RemediationMatrixEngine {
    pub fn new() -> Self {
        Self {
            policy: RiskControlPolicy::default(),
            evaluations_count: 0,
            executed_plans_count: 0,
            blocked_by_guardrail_count: 0,
            circuit_breaker_trips: 0,
            dry_run_simulations_count: 0,
        }
    }

    /// 新巡检周期开始，重置单轮自动查杀熔断计数（按秒或每轮调用）
    pub fn begin_cycle(&mut self, epoch_secs: u64) {
        self.policy.kills_in_current_cycle = 0;
        self.policy.circuit_breaker_tripped = false;
        self.policy.last_cycle_epoch = epoch_secs;
    }

    /// 检查单轮自动查杀配额是否仍未熔断
    pub fn can_auto_kill(&self) -> bool {
        !self.policy.circuit_breaker_tripped
            && self.policy.kills_in_current_cycle < self.policy.max_auto_kills_per_cycle.max(1)
    }

    /// 登记一次自动查杀，若达到上限则触发熔断保护
    pub fn record_auto_kill(&mut self) -> bool {
        self.policy.kills_in_current_cycle = self.policy.kills_in_current_cycle.saturating_add(1);
        if self.policy.kills_in_current_cycle >= self.policy.max_auto_kills_per_cycle.max(1) {
            if !self.policy.circuit_breaker_tripped {
                self.policy.circuit_breaker_tripped = true;
                self.circuit_breaker_trips = self.circuit_breaker_trips.saturating_add(1);
            }
            false
        } else {
            true
        }
    }

    /// 核心防误杀护栏检测：判定目标是否属于受保护系统进程/自身进程/系统目录核心服务
    pub fn detect_protected_system_target(
        pid: u32,
        process_name: &str,
        exe_path: &str,
    ) -> Option<String> {
        if pid == 0 {
            return None;
        }
        if pid == 1 {
            return Some("PID 1 为系统根守护进程 (launchd/init)，禁止挂起或终止".to_string());
        }
        if pid == std::process::id() {
            return Some("目标为当前终端安全防护自身进程，硬护栏拒绝自杀".to_string());
        }
        let pname_lower = process_name.trim().to_ascii_lowercase();
        let path_lower = exe_path.trim().to_ascii_lowercase();

        const CRITICAL_PROC_NAMES: &[&str] = &[
            "kernel_task",
            "launchd",
            "windowserver",
            "loginwindow",
            "finder",
            "dock",
            "systemuiserver",
            "securityd",
            "trustd",
            "diskarbitrationd",
            "notifyd",
            "opendirectoryd",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "smss.exe",
            "svchost.exe",
            "explorer.exe",
            "dwm.exe",
        ];
        if CRITICAL_PROC_NAMES.iter().any(|&c| pname_lower == c) {
            return Some(format!(
                "核心系统宿主进程 `{}` 受硬护栏保护，禁止强制击毙",
                process_name
            ));
        }

        const PROTECTED_SYSTEM_PREFIXES: &[&str] = &[
            "/system/",
            "/usr/libexec/",
            "/usr/sbin/",
            "/sbin/",
            "c:\\windows\\system32\\",
            "c:\\windows\\syswow64\\",
        ];
        if PROTECTED_SYSTEM_PREFIXES
            .iter()
            .any(|p| path_lower.starts_with(p))
            || path_lower.contains("\\windows\\system32\\")
            || path_lower.contains("\\windows\\syswow64\\")
        {
            return Some(format!(
                "受保护系统目录核心二进制 `{}`，硬护栏禁止直接终止",
                exe_path
            ));
        }
        None
    }

    /// 识别目标的主威胁向量 (`ThreatVector`)
    pub fn classify_vector(ctx: &MatrixTargetContext) -> ThreatVector {
        let sum_lower = ctx.summary_hint.to_ascii_lowercase();
        let path_lower = ctx.exe_path.to_ascii_lowercase();

        if ctx.has_reverse_shell
            || sum_lower.contains("反弹")
            || sum_lower.contains("reverse")
            || sum_lower.contains("/dev/tcp/")
        {
            ThreatVector::ReverseShell
        } else if ctx.has_dyld_or_dll_inject
            || sum_lower.contains("dyld")
            || sum_lower.contains("注入")
            || sum_lower.contains("inject")
        {
            ThreatVector::ProcessInjection
        } else if ctx.in_temp_or_hidden
            || path_lower.starts_with("/tmp/")
            || path_lower.starts_with("/private/tmp/")
            || path_lower.contains("\\temp\\")
        {
            ThreatVector::TempDropper
        } else if !ctx.persistence_paths.is_empty()
            || ctx.domain_hint.contains("持久")
            || sum_lower.contains("launchagent")
            || sum_lower.contains("run")
        {
            ThreatVector::PersistenceBackdoor
        } else if ctx.intel_matched || !ctx.remote_endpoints.is_empty() && ctx.z3_malicious_prob >= 0.45
        {
            ThreatVector::C2Outbound
        } else if !ctx.wildcard_ports.is_empty() || sum_lower.contains("0.0.0.0") {
            ThreatVector::ExposedWildcardPort
        } else if ctx.is_adware_popup || sum_lower.contains("弹窗") || sum_lower.contains("广告") {
            ThreatVector::AdwarePopupHijack
        } else if ctx.is_fim_credential_issue
            || ctx.domain_hint.contains("FIM")
            || sum_lower.contains("凭据")
        {
            ThreatVector::CredentialExposure
        } else {
            ThreatVector::GenericAnomaly
        }
    }

    /// 计算定量风险分 (0..=100) 与影响面半径评分 (0..=100)
    pub fn score_risk_and_blast_radius(
        ctx: &MatrixTargetContext,
        vector: ThreatVector,
    ) -> (u8, u8) {
        let mut risk: i32 = (ctx.z3_malicious_prob.clamp(0.0, 1.0) * 58.0) as i32;
        match vector {
            ThreatVector::ReverseShell => risk += 42,
            ThreatVector::ProcessInjection => risk += 38,
            ThreatVector::TempDropper => risk += 34,
            ThreatVector::PersistenceBackdoor => risk += 28,
            ThreatVector::C2Outbound => risk += 30,
            ThreatVector::ExposedWildcardPort => {
                risk += if ctx.wildcard_ports.iter().any(|&p| matches!(p, 6379 | 2375 | 9200)) {
                    32
                } else {
                    20
                };
            }
            ThreatVector::AdwarePopupHijack => risk += 22,
            ThreatVector::CredentialExposure => risk += 24,
            ThreatVector::GenericAnomaly => risk += 10,
        }
        if ctx.intel_matched {
            risk += 24;
        }
        if !ctx.persistence_paths.is_empty() {
            risk += 12;
        }
        if ctx.is_benign_dev_tool {
            risk = (risk - 45).max(5);
        }

        let mut blast: i32 = 15;
        if ctx.host_profile.has_open_user_document {
            blast += 45;
        }
        if ctx.host_profile.is_critical_shell_host {
            blast += 50;
        }
        if ctx.host_profile.has_main_work_window {
            blast += 20;
        }
        if Self::detect_protected_system_target(ctx.pid, &ctx.process_name, &ctx.exe_path).is_some()
        {
            blast = 100;
        } else if vector == ThreatVector::TempDropper || vector == ThreatVector::ReverseShell {
            blast = (blast - 10).max(10);
        }

        (risk.clamp(0, 100) as u8, blast.clamp(0, 100) as u8)
    }

    /// 对具体目标执行处置矩阵推演（只读无状态副作用版本，供 UI 渲染与只读审计调用）
    pub fn evaluate_readonly(&self, ctx: &MatrixTargetContext) -> RemediationMatrixPlan {
        let vector = Self::classify_vector(ctx);
        let (risk_score, blast_radius_score) = Self::score_risk_and_blast_radius(ctx, vector);
        let risk_tier = RiskTier::from_score(risk_score);

        let (rule_id, recommended_action, reversibility, mut ordered_steps, base_rationale) =
            Self::lookup_matrix_cell(ctx, vector, risk_tier);

        // 依据风险控制策略评估执行闸门与有效动作
        let (gate, effective_action, guardrail_reason) =
            self.evaluate_requested_action(ctx, recommended_action, false);

        if matches!(gate, ExecutionGate::BlockedByGuardrail) {
            // 被系统硬护栏拦截时移除进程终止与隔离步骤，仅保留网络侧/凭证侧安全措施
            ordered_steps.retain(|s| {
                !matches!(
                    s,
                    KillChainAction::SuspendProcessTree
                        | KillChainAction::TerminateProcessTree
                        | KillChainAction::QuarantineExecutableOrDrop
                )
            });
            if matches!(vector, ThreatVector::ExposedWildcardPort | ThreatVector::C2Outbound)
                && self.policy.auto_block_c2_network
                && !ordered_steps.contains(&KillChainAction::BlockNetworkEndpoints)
            {
                ordered_steps.insert(0, KillChainAction::BlockNetworkEndpoints);
            }
        } else if matches!(effective_action, PolicyAction::A2SurgicalMute)
            && recommended_action != PolicyAction::A2SurgicalMute
        {
            // 从 A3/A4 降级到 A2 时，步骤同步收敛为先挂起并阻断网络外联
            ordered_steps.retain(|s| {
                !matches!(
                    s,
                    KillChainAction::TerminateProcessTree
                        | KillChainAction::QuarantineExecutableOrDrop
                )
            });
            if !ordered_steps.contains(&KillChainAction::SuspendProcessTree) {
                ordered_steps.insert(0, KillChainAction::SuspendProcessTree);
            }
        }

        let target_ips_ports = Self::dedup_endpoints(&ctx.remote_endpoints);
        let mut persistence = ctx.persistence_paths.clone();
        persistence.sort();
        persistence.dedup();
        let mut drops = ctx.dropped_files.clone();
        if ctx.in_temp_or_hidden && !ctx.exe_path.is_empty() && !drops.contains(&ctx.exe_path) {
            drops.push(ctx.exe_path.clone());
        }
        drops.sort();
        drops.dedup();

        let rationale = match &guardrail_reason {
            Some(reason) => format!(
                "{} | 风控调整 ({} -> {}): {}",
                base_rationale,
                recommended_action.code(),
                effective_action.code(),
                reason
            ),
            None => base_rationale,
        };

        RemediationMatrixPlan {
            rule_id: rule_id.to_string(),
            vector,
            risk_tier,
            risk_score,
            blast_radius_score,
            reversibility: reversibility.to_string(),
            recommended_action,
            effective_action,
            gate,
            guardrail_reason,
            ordered_steps,
            target_ips_ports,
            target_persistence_paths: persistence,
            target_dropped_files: drops,
            rationale,
        }
    }

    /// 对具体目标执行处置矩阵推演（结合风控策略生成确定性查杀/拦截/降级剧本，并累计评估统计）
    pub fn evaluate(&mut self, ctx: &MatrixTargetContext) -> RemediationMatrixPlan {
        self.evaluations_count = self.evaluations_count.saturating_add(1);
        self.evaluate_readonly(ctx)
    }

    /// 针对任意显式/隐式动作请求执行风险控制闸门审计
    pub fn evaluate_requested_action(
        &self,
        ctx: &MatrixTargetContext,
        requested: PolicyAction,
        triggered_by_user: bool,
    ) -> (ExecutionGate, PolicyAction, Option<String>) {
        // A0 放行与 A1 观测不属于破坏性杀伤，直接放行
        if matches!(
            requested,
            PolicyAction::A0PassAndUntag | PolicyAction::A1DeferWait
        ) {
            return (ExecutionGate::AutoEnforce, requested, None);
        }

        // 1. 核心系统与自身进程硬护栏（无论自动或人工，禁止直接挂起/强杀核心 OS 进程）
        if self.policy.protect_critical_system_hosts {
            if let Some(reason) =
                Self::detect_protected_system_target(ctx.pid, &ctx.process_name, &ctx.exe_path)
            {
                return (
                    ExecutionGate::BlockedByGuardrail,
                    PolicyAction::A1DeferWait,
                    Some(reason),
                );
            }
        }

        // 2. 全局干跑演练模式：允许完整评估并记录，但阻止真实物理杀伤
        if self.policy.dry_run_mode {
            return (
                ExecutionGate::DryRunObserve,
                requested,
                Some("全局干跑演练模式开启：仅推演矩阵动作并写入审计，未触及真实进程与文件".to_string()),
            );
        }

        // 3. 活跃工作宿主护栏：有未保存用户文档或重要 Shell 宿主时，防止自动 A3/A4 连坐误杀
        let has_sensitive_host =
            ctx.host_profile.has_open_user_document || ctx.host_profile.is_critical_shell_host;
        if self.policy.protect_active_document_hosts
            && has_sensitive_host
            && matches!(
                requested,
                PolicyAction::A3ProcessIsolate | PolicyAction::A4RootPurge
            )
            && !triggered_by_user
        {
            let doc_note = ctx
                .host_profile
                .active_document_hint
                .as_deref()
                .unwrap_or("活跃开发/办公宿主");
            let downgraded = if ctx.is_adware_popup {
                PolicyAction::A2SurgicalMute
            } else {
                PolicyAction::A1DeferWait
            };
            return (
                ExecutionGate::RequireConfirm,
                downgraded,
                Some(format!(
                    "目标承载 `{}`，禁止无人值守强杀，已降级为 {}",
                    doc_note,
                    downgraded.cn_name()
                )),
            );
        }

        // 4. 自动查杀熔断器检验（仅拦截自动批量查杀，不阻挡人工单点处置）
        if !triggered_by_user
            && matches!(
                requested,
                PolicyAction::A3ProcessIsolate | PolicyAction::A4RootPurge
            )
        {
            if !self.policy.auto_enforce_critical {
                return (
                    ExecutionGate::RequireConfirm,
                    PolicyAction::A1DeferWait,
                    Some("自动强杀策略关闭，请人工复核后触发处置".to_string()),
                );
            }
            if !self.can_auto_kill() {
                return (
                    ExecutionGate::RequireConfirm,
                    PolicyAction::A2SurgicalMute,
                    Some(format!(
                        "已触及单轮自动查杀熔断上限 ({} 次/轮)，自动降级为线程冻结待确认",
                        self.policy.max_auto_kills_per_cycle
                    )),
                );
            }
        }

        (ExecutionGate::AutoEnforce, requested, None)
    }

    /// 导出标准矩阵规则总览表，便于运维审计与 UI 面板展示
    pub fn summary_cell_matrix(&self) -> Vec<MatrixRuleRow> {
        vec![
            MatrixRuleRow {
                rule_id: "MTX-L4-REVSHELL".into(),
                vector: ThreatVector::ReverseShell,
                min_tier: RiskTier::L4Critical,
                default_action: PolicyAction::A4RootPurge,
                steps_summary: "挂起树 -> 递归击毙 -> 路径+SHA256禁生 -> 防火墙封堵C2 -> 隔离载荷".into(),
                host_guardrail: "核心OS进程严禁终止；含活跃文档时自动降级确认".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L4-INJECT".into(),
                vector: ThreatVector::ProcessInjection,
                min_tier: RiskTier::L3High,
                default_action: PolicyAction::A3ProcessIsolate,
                steps_summary: "挂起树 -> 递归击毙 -> 路径+SHA256禁生 -> 阻断外联".into(),
                host_guardrail: "受保护Shell宿主降级为A2挂起待人工确认".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L4-DROPPER".into(),
                vector: ThreatVector::TempDropper,
                min_tier: RiskTier::L3High,
                default_action: PolicyAction::A4RootPurge,
                steps_summary: "挂起树 -> 递归击毙 -> 双因子禁生 -> 卸载自启动 -> 隔离临时目录文件".into(),
                host_guardrail: "保险箱完整保存原路径与哈希，支持一键撤销还原".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L3-PERSIST".into(),
                vector: ThreatVector::PersistenceBackdoor,
                min_tier: RiskTier::L3High,
                default_action: PolicyAction::A4RootPurge,
                steps_summary: "卸载LaunchAgent/Run键 -> 隔离残留Payload -> 进程树清理".into(),
                host_guardrail: "OS自带/苹果公证守护项仅监控不卸载".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L3-C2NET".into(),
                vector: ThreatVector::C2Outbound,
                min_tier: RiskTier::L3High,
                default_action: PolicyAction::A3ProcessIsolate,
                steps_summary: "下发Firewall/IPS出站阻断 -> 挂起/终止外联进程 -> 双因子禁生".into(),
                host_guardrail: "本地127.0.0.1及9006协同端点白名单豁免".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L2-WILDCARD".into(),
                vector: ThreatVector::ExposedWildcardPort,
                min_tier: RiskTier::L2Medium,
                default_action: PolicyAction::A2SurgicalMute,
                steps_summary: "下发入站暴露面阻断规则 -> 保护性挂起非回环暴露实例 (保留数据)".into(),
                host_guardrail: "优先防火墙锁口与挂起，不盲杀数据库/开发服务".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L2-ADWARE".into(),
                vector: ThreatVector::AdwarePopupHijack,
                min_tier: RiskTier::L2Medium,
                default_action: PolicyAction::A2SurgicalMute,
                steps_summary: "精准挂起弹窗线程(A2) -> 隔离广告加载项".into(),
                host_guardrail: "若宿主打开用户文档，绝不终止主进程".into(),
            },
            MatrixRuleRow {
                rule_id: "MTX-L2-CREDFIM".into(),
                vector: ThreatVector::CredentialExposure,
                min_tier: RiskTier::L2Medium,
                default_action: PolicyAction::A1DeferWait,
                steps_summary: "物理收敛凭据文件权限 (chmod 0600 / ACL) -> 保留基线".into(),
                host_guardrail: "无损加固文件权限，不影响正常认证工作流".into(),
            },
        ]
    }

    fn lookup_matrix_cell(
        ctx: &MatrixTargetContext,
        vector: ThreatVector,
        tier: RiskTier,
    ) -> (
        &'static str,
        PolicyAction,
        &'static str,
        Vec<KillChainAction>,
        String,
    ) {
        if ctx.is_benign_dev_tool && !ctx.intel_matched && !ctx.has_reverse_shell {
            return (
                "MTX-L1-BENIGN",
                PolicyAction::A0PassAndUntag,
                "完全可逆 (基线放行)",
                vec![KillChainAction::AllowlistTrustBaseline],
                "协同推理确认为本机开发/合法工作组件，匹配基线放行矩阵单元".to_string(),
            );
        }

        match vector {
            ThreatVector::ReverseShell => (
                "MTX-L4-REVSHELL",
                PolicyAction::A4RootPurge,
                "中度可逆 (文件入保险箱，进程需重启)",
                vec![
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::BlockNetworkEndpoints,
                    KillChainAction::TerminateProcessTree,
                    KillChainAction::BlockSpawnPathAndHash,
                    KillChainAction::UnloadPersistence,
                    KillChainAction::QuarantineExecutableOrDrop,
                ],
                "判定为反弹 Shell / 远控执行链路：必须优先切断网络并连坐击毙父子进程树".to_string(),
            ),
            ThreatVector::ProcessInjection => (
                "MTX-L4-INJECT",
                if tier >= RiskTier::L4Critical {
                    PolicyAction::A4RootPurge
                } else {
                    PolicyAction::A3ProcessIsolate
                },
                "中度可逆 (支持撤销禁生与保险箱还原)",
                vec![
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::BlockNetworkEndpoints,
                    KillChainAction::TerminateProcessTree,
                    KillChainAction::BlockSpawnPathAndHash,
                ],
                "存在 DYLD / DLL / 内存注入特征：按高危拦截矩阵冻结并阻断重生".to_string(),
            ),
            ThreatVector::TempDropper => (
                "MTX-L4-DROPPER",
                PolicyAction::A4RootPurge,
                "中度可逆 (载荷移入保险箱可一键还原)",
                vec![
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::TerminateProcessTree,
                    KillChainAction::BlockSpawnPathAndHash,
                    KillChainAction::BlockNetworkEndpoints,
                    KillChainAction::UnloadPersistence,
                    KillChainAction::QuarantineExecutableOrDrop,
                ],
                "来自临时/隐藏目录的高熵未签名可执行体：全链连根猎杀并送入隔离保险箱".to_string(),
            ),
            ThreatVector::PersistenceBackdoor => (
                "MTX-L3-PERSIST",
                PolicyAction::A4RootPurge,
                "完全可逆 (卸载记录+文件保险箱)",
                vec![
                    KillChainAction::UnloadPersistence,
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::TerminateProcessTree,
                    KillChainAction::BlockSpawnPathAndHash,
                    KillChainAction::QuarantineExecutableOrDrop,
                ],
                "检测到异常自启动持久化驻留：先卸载自启动再清缴关联进程与载荷".to_string(),
            ),
            ThreatVector::C2Outbound => (
                "MTX-L3-C2NET",
                if tier >= RiskTier::L4Critical {
                    PolicyAction::A4RootPurge
                } else {
                    PolicyAction::A3ProcessIsolate
                },
                "中度可逆 (防火墙规则与禁生均可回滚)",
                vec![
                    KillChainAction::BlockNetworkEndpoints,
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::TerminateProcessTree,
                    KillChainAction::BlockSpawnPathAndHash,
                ],
                "命中 C2 恶意通信或威胁情报库：同步下发防火墙阻断规则并封锁执行体指纹".to_string(),
            ),
            ThreatVector::ExposedWildcardPort => (
                "MTX-L2-WILDCARD",
                PolicyAction::A2SurgicalMute,
                "完全可逆 (支持一键解冻恢复与放行)",
                vec![
                    KillChainAction::BlockNetworkEndpoints,
                    KillChainAction::SuspendProcessTree,
                ],
                "服务监听全网段 0.0.0.0：优先下发入站收敛规则与挂起冻结，避免粗暴杀进程损坏数据"
                    .to_string(),
            ),
            ThreatVector::AdwarePopupHijack => (
                "MTX-L2-ADWARE",
                PolicyAction::A2SurgicalMute,
                "完全可逆 (SIGCONT/ResumeThread 秒级恢复)",
                vec![
                    KillChainAction::SuspendProcessTree,
                    KillChainAction::QuarantineExecutableOrDrop,
                ],
                "识别为置顶广告弹窗劫持：执行 A2 外科手术消音并保全工作宿主".to_string(),
            ),
            ThreatVector::CredentialExposure => (
                "MTX-L2-CREDFIM",
                PolicyAction::A1DeferWait,
                "完全可逆 (无损收敛文件 ACL)",
                vec![KillChainAction::HardenCredentialAcl],
                "敏感凭据权限暴露或变更：执行 0600 / ACL 无损加固收敛".to_string(),
            ),
            ThreatVector::GenericAnomaly => {
                let (action, steps) = match tier {
                    RiskTier::L4Critical | RiskTier::L3High => (
                        PolicyAction::A3ProcessIsolate,
                        vec![
                            KillChainAction::SuspendProcessTree,
                            KillChainAction::TerminateProcessTree,
                            KillChainAction::BlockSpawnPathAndHash,
                        ],
                    ),
                    RiskTier::L2Medium => (
                        PolicyAction::A2SurgicalMute,
                        vec![KillChainAction::SuspendProcessTree],
                    ),
                    RiskTier::L1Low => (PolicyAction::A1DeferWait, vec![]),
                };
                (
                    "MTX-GEN-ANOMALY",
                    action,
                    "完全可逆 (支持解冻/回滚)",
                    steps,
                    "依据 S->Z->A 风险置信度落入通用行为异常处置单元".to_string(),
                )
            }
        }
    }

    fn dedup_endpoints(raw: &[(String, u16)]) -> Vec<(String, u16)> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (ip, port) in raw {
            let trimmed = ip.trim();
            if trimmed.is_empty()
                || trimmed == "127.0.0.1"
                || trimmed == "::1"
                || trimmed == "localhost"
            {
                continue;
            }
            let key = (trimmed.to_string(), *port);
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
        out
    }
}
