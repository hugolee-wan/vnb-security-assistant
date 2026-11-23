//! 一、决策模型的数学定义：状态 (S) -> 意图 (Z) -> 动作 (A)
//! 严格对应：
//! 1. 状态输入空间 S_t ∈ R^{16 × 12}（3大域共12维归一化特征）
//! 2. 潜空间意图层 Z_t ∈ R^4（z_0 合法交互, z_1 宿主夹带私货弹窗, z_2 独立寄生广告模块, z_3 静默捆绑与驻留母体）
//! 3. 决策动作空间 A_t ∈ {a_0, a_1, a_2, a_3, a_4} + 5×4 非对称代价矩阵 C

use serde::{Deserialize, Serialize};

/// 时序滑动窗口长度：最近 16 个边界事件
pub const SEQ_LEN: usize = 16;
/// 单步特征维度：3 大域 × 4 维 = 12 维
pub const FEAT_DIM: usize = 12;
/// 潜空间业务意图维度：4 种核心意图
pub const INTENT_DIM: usize = 4;
/// 决策动作空间维度：5 种确定性系统控制指令
pub const ACTION_DIM: usize = 5;

/// 12 维特征索引常量定义
pub mod feat_idx {
    // ── 交互与视觉域 (0..4) ──
    /// 距最近一次人类物理输入（鼠标/键盘）的时间衰减值 (0=刚点击, 1=长时间无人触碰)
    pub const INPUT_IDLE_DECAY: usize = 0;
    /// 窗口置顶/无边框掩码 (WS_EX_TOPMOST | WS_POPUP | 异形分层)
    pub const TOPMOST_BORDERLESS_MASK: usize = 1;
    /// 任务栏隐藏属性 (WS_EX_TOOLWINDOW / 隐藏任务栏按钮)
    pub const TASKBAR_HIDDEN: usize = 2;
    /// 屏幕落点区域编码 (0.0=居中正常, 0.85=右下角弹窗区, 1.0=屏幕外隐藏坐标)
    pub const SCREEN_ZONE_CODE: usize = 3;

    // ── 内存与寄生域 (4..8) ──
    /// 页面是否发生 D -> X（写后执行 RW -> RX/RWX）
    pub const MEM_WX_TRANSITION: usize = 4;
    /// 调用栈是否源自非主程序模块（寄生 DLL / Unbacked 内存）
    pub const FOREIGN_STACK_ORIGIN: usize = 5;
    /// 是否发生跨进程内存写入 / 远程线程注入
    pub const CROSS_PROCESS_WRITE: usize = 6;
    /// 目标内存页或释放载荷的归一化香农熵
    pub const PAYLOAD_SHANNON_ENTROPY: usize = 7;

    // ── 繁殖与外域因果域 (8..12) ──
    /// 是否由网络 Socket_Recv 短时序直接驱动
    pub const SOCKET_RECV_DRIVEN: usize = 8;
    /// 是否写入临时目录可执行文件 (%TEMP% / %APPDATA% 落地 .exe/.dll)
    pub const TEMP_EXEC_WRITE: usize = 9;
    /// 是否篡改自启动注册表 Run 项 / 计划任务
    pub const PERSISTENCE_TAMPER: usize = 10;
    /// 进程谱系偏离度（父子进程目录异构 / 签名断层）
    pub const LINEAGE_DIVERGENCE: usize = 11;
}

/// 12 维特征的元数据描述（用于安全助手 UI 展示与大白话证据翻译）
pub const FEATURE_META: [(&str, &str, &str); FEAT_DIM] = [
    ("键鼠空闲衰减", "交互与视觉域", "触发时无人类键鼠操作（后台无人值守自发行为）"),
    ("置顶/无边框伪装", "交互与视觉域", "强开 WS_EX_TOPMOST 置顶且剥离标准窗口边框"),
    ("隐藏任务栏图标", "交互与视觉域", "设置 ToolWindow 属性逃避任务栏显示"),
    ("高危屏幕落点", "交互与视觉域", "窗口精准落位于右下角通知区或屏幕外隐蔽坐标"),
    ("内存写后执行(D→X)", "内存与寄生域", "内存页发生 RW→RX 动态代码生成或解壳执行"),
    ("非主模块调用栈", "内存与寄生域", "调用栈源自第三方寄生 DLL 而非宿主主程序"),
    ("跨进程内存写入", "内存与寄生域", "检测到向其他进程写入内存或挂载全局钩子"),
    ("高熵加密载荷", "内存与寄生域", "目标页香农熵异常偏高（疑似加壳/混淆广告载荷）"),
    ("网络指令直接驱动", "繁殖与外域因果域", "由 Socket_Recv 远端数据包在极短时序内直接触发"),
    ("释放临时可执行体", "繁殖与外域因果域", "向 Temp/AppData 目录静默释放可执行程序或组件"),
    ("篡改自启动/计划任务", "繁殖与外域因果域", "写入注册表 Run 启动项或注册系统计划任务驻留"),
    ("父子进程谱系异构", "繁殖与外域因果域", "父子进程安装目录与模块签名体系严重偏离"),
];

/// 单步 12 维状态向量
pub type FrameFeatures = [f32; FEAT_DIM];
/// 16 步 × 12 维时序状态矩阵 S_t ∈ R^{16 × 12}
pub type StateMatrix = [[f32; FEAT_DIM]; SEQ_LEN];

/// 潜空间 4 大业务意图枚举 Z_t ∈ R^4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LatentIntent {
    /// z_0: 合法用户交互 / 系统通知（如微信正常弹窗、IDE 编译完成提示、用户主动点击打开的新窗口）
    Z0LegitInteraction = 0,
    /// z_1: 宿主夹带私货弹窗（正常软件主进程内部线程弹出的推广窗，杀进程会导致用户数据丢失）
    Z1HostBundledAd = 1,
    /// z_2: 独立寄生广告模块（专门负责弹窗的 mini_news.exe 或注入在 explorer.exe 里的广告插件）
    Z2ParasiticAdModule = 2,
    /// z_3: 静默捆绑与驻留母体（后台偷偷下载安装全家桶、写计划任务死灰复燃的 Dropper）
    Z3SilentDropper = 3,
}

impl LatentIntent {
    pub const ALL: [LatentIntent; INTENT_DIM] = [
        LatentIntent::Z0LegitInteraction,
        LatentIntent::Z1HostBundledAd,
        LatentIntent::Z2ParasiticAdModule,
        LatentIntent::Z3SilentDropper,
    ];

    pub fn code(&self) -> &'static str {
        match self {
            Self::Z0LegitInteraction => "z_0",
            Self::Z1HostBundledAd => "z_1",
            Self::Z2ParasiticAdModule => "z_2",
            Self::Z3SilentDropper => "z_3",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::Z0LegitInteraction => "合法用户交互 / 正常通知",
            Self::Z1HostBundledAd => "宿主夹带私货弹窗 (保主进程)",
            Self::Z2ParasiticAdModule => "独立寄生广告模块 / 插件",
            Self::Z3SilentDropper => "静默捆绑与驻留母体 (Dropper)",
        }
    }
}

/// 决策动作空间 A_t ∈ {a_0, a_1, a_2, a_3, a_4}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyAction {
    /// a_0: ACTION_PASS_AND_UNTAG (放行并摘牌)
    A0PassAndUntag = 0,
    /// a_1: ACTION_DEFER_WAIT (静默观察 / 模糊地带提醒用户裁决)
    A1DeferWait = 1,
    /// a_2: ACTION_SURGICAL_MUTE (外科手术消音：保主进程、灭子窗口、剥夺置顶、挂起广告UI线程)
    A2SurgicalMute = 2,
    /// a_3: ACTION_PROCESS_ISOLATE (进程击毙与禁生：终止独立广告子进程并加入 Spawn Block)
    A3ProcessIsolate = 3,
    /// a_4: ACTION_ROOT_PURGE (连根拔除与回滚：强杀进程树 + 溯源账本清理注册表/计划任务 + 隔离文件)
    A4RootPurge = 4,
}

impl PolicyAction {
    pub const ALL: [PolicyAction; ACTION_DIM] = [
        PolicyAction::A0PassAndUntag,
        PolicyAction::A1DeferWait,
        PolicyAction::A2SurgicalMute,
        PolicyAction::A3ProcessIsolate,
        PolicyAction::A4RootPurge,
    ];

    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::A0PassAndUntag,
            1 => Self::A1DeferWait,
            2 => Self::A2SurgicalMute,
            3 => Self::A3ProcessIsolate,
            _ => Self::A4RootPurge,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::A0PassAndUntag => "a_0",
            Self::A1DeferWait => "a_1",
            Self::A2SurgicalMute => "a_2",
            Self::A3ProcessIsolate => "a_3",
            Self::A4RootPurge => "a_4",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Self::A0PassAndUntag => "ACTION_PASS_AND_UNTAG",
            Self::A1DeferWait => "ACTION_DEFER_WAIT",
            Self::A2SurgicalMute => "ACTION_SURGICAL_MUTE",
            Self::A3ProcessIsolate => "ACTION_PROCESS_ISOLATE",
            Self::A4RootPurge => "ACTION_ROOT_PURGE",
        }
    }

    pub fn cn_name(&self) -> &'static str {
        match self {
            Self::A0PassAndUntag => "放行并摘牌",
            Self::A1DeferWait => "静默观察 / 待用户确认",
            Self::A2SurgicalMute => "外科手术消音 (保主程序·灭弹窗)",
            Self::A3ProcessIsolate => "进程击毙与禁生 (Spawn Block)",
            Self::A4RootPurge => "连根拔除与账本回滚",
        }
    }

    pub fn actuator_summary(&self) -> &'static str {
        match self {
            Self::A0PassAndUntag => "确认属于正常软件行为，立即从稀疏追踪池移除该对象，释放算力。",
            Self::A1DeferWait => "证据尚处于边界或危害未完全闭合，保持染色追踪并提醒用户一键裁决。",
            Self::A2SurgicalMute => "向目标广告 HWND 投递销毁/隐藏指令，剥夺 TOPMOST 置顶权，仅挂起渲染该窗口的 UI 线程，主程序与用户文档丝毫无损。",
            Self::A3ProcessIsolate => "终止独立的广告子进程，并在钩子/内核层将该 .exe 路径加入禁止孵化名单 (Spawn Block)，拒绝父进程再次拉起。",
            Self::A4RootPurge => "整组进程树急冻强杀 -> 检索《污染溯源账本》自动删除其创建的注册表 Run 项与计划任务 -> 将释放的捆绑文件移入隔离区。",
        }
    }
}

/// 进程上下文安全属性（用于第 2 级门控层与第 3 级动态非对称代价矩阵）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostContextProfile {
    /// 是否关联用户当前正在编辑/打开的文档句柄（如 Word/WPS/IDE 工作区）
    pub has_open_user_document: bool,
    /// 打开的用户文档名称说明（用于在提醒卡片中直观告知用户风险）
    pub active_document_hint: Option<String>,
    /// 是否为系统核心外壳或关键宿主进程（如 explorer.exe）
    pub is_critical_shell_host: bool,
    /// 是否存在用户主动交互的主工作窗口
    pub has_main_work_window: bool,
}

impl Default for HostContextProfile {
    fn default() -> Self {
        Self {
            has_open_user_document: false,
            active_document_hint: None,
            is_critical_shell_host: false,
            has_main_work_window: false,
        }
    }
}

impl HostContextProfile {
    /// 计算宿主保护权重 [0.0, 1.0]：越高代表强杀进程 (a_3 / a_4) 的误伤代价越灾难性
    pub fn protection_vitality(&self) -> f32 {
        let mut score: f32 = 0.0;
        if self.has_open_user_document {
            score += 0.65;
        }
        if self.is_critical_shell_host {
            score += 0.65;
        }
        if self.has_main_work_window {
            score += 0.30;
        }
        score.clamp(0.0, 1.0)
    }
}

/// 5 × 4 非对称代价矩阵 (Asymmetric Cost Matrix C)
/// 行 i ∈ 0..5 对应动作 a_0..a_4，列 j ∈ 0..4 对应真实意图 z_0..z_3
///
/// 设计铁律：
/// - 把弹窗广告漏放了 (z_2 判成 a_0)，损失权重仅为 ~1.0~8.0；
/// - 把用户正在写代码的 IDE 或办公 Word 主进程当木马强杀了 (z_0/z_1 判成 a_4)，损失权重高达 1000.0！
/// - 当宿主持有用户打开的文档句柄时，代价矩阵自动推高 a_3/a_4 对 z_1 的惩罚，强制引导模型输出 a_2（外科手术消音）。
pub fn build_asymmetric_cost_matrix(host: &HostContextProfile) -> [[f32; INTENT_DIM]; ACTION_DIM] {
    let vitality = host.protection_vitality();
    // 当宿主持有用户文档或为 explorer.exe 时，强杀宿主进程的额外惩罚倍增器
    let kill_host_penalty_boost = 1.0 + vitality * 18.0;

    [
        // a_0: ACTION_PASS_AND_UNTAG (放行并摘牌)
        // [对 z_0 合法=0代价, 对 z_1 私货弹窗=漏放代价4.5, 对 z_2 独立广告=漏放代价6.5, 对 z_3 静默母体=漏杀代价22.0]
        [0.0, 4.5, 6.5, 22.0],
        // a_1: ACTION_DEFER_WAIT (静默观察 / 提醒待裁决)
        // 在意图模糊时期望损失适中，充当安全缓冲带
        [1.4, 2.2, 2.5, 4.2],
        // a_2: ACTION_SURGICAL_MUTE (外科手术消音：仅关子窗口+挂起广告UI线程，不伤主进程)
        // 对 z_1 (宿主夹带私货) 代价为 0！即便对 z_0 轻微误消音代价也远低于杀进程
        [6.5, 0.0, 2.4, 14.0],
        // a_3: ACTION_PROCESS_ISOLATE (击毙子进程并加入 Spawn Block)
        // 对 z_2 (独立寄生广告进程) 代价为 0；但若目标实为 z_0/z_1 且持有文档，惩罚急剧升高
        [
            85.0 * kill_host_penalty_boost,
            28.0 * kill_host_penalty_boost,
            0.0,
            5.5,
        ],
        // a_4: ACTION_ROOT_PURGE (连根拔除：强杀进程树 + 回滚注册表/计划任务 + 隔离文件)
        // 对 z_3 (静默捆绑母体) 代价为 0；对 z_0 (正常软件) 固定 1000 灾难级惩罚，对 z_1 宿主同样严厉抑制！
        [
            1000.0,
            55.0 * kill_host_penalty_boost,
            6.0 * (1.0 + vitality * 4.0),
            0.0,
        ],
    ]
}

/// 将 16×12 状态矩阵自动翻译为面向终端用户的“可理解证据链”
pub fn explain_state_evidence(
    state: &StateMatrix,
    host: &HostContextProfile,
) -> Vec<String> {
    let mut peaks = [0.0_f32; FEAT_DIM];
    for step in state.iter() {
        for (i, &val) in step.iter().enumerate() {
            if val > peaks[i] {
                peaks[i] = val;
            }
        }
    }

    let mut bullets = Vec::new();

    if peaks[feat_idx::INPUT_IDLE_DECAY] > 0.70 {
        bullets.push(format!(
            "无人值守触发：触发时距您最近一次键鼠操作衰减度达 {:.0}%（非用户主动点击）",
            peaks[feat_idx::INPUT_IDLE_DECAY] * 100.0
        ));
    } else if peaks[feat_idx::INPUT_IDLE_DECAY] < 0.25 {
        bullets.push("伴随真实人工交互：事件紧随您的鼠标点击或键盘输入发生".to_string());
    }

    if peaks[feat_idx::TOPMOST_BORDERLESS_MASK] > 0.60
        || peaks[feat_idx::TASKBAR_HIDDEN] > 0.60
        || peaks[feat_idx::SCREEN_ZONE_CODE] > 0.70
    {
        bullets.push(
            "弹窗视觉特征：窗口强开 TOPMOST 置顶、隐藏任务栏图标，且落点位于右下角/隐蔽区"
                .to_string(),
        );
    }

    if peaks[feat_idx::FOREIGN_STACK_ORIGIN] > 0.55 {
        bullets.push(
            "寄生调用栈：创建窗口或执行动作的调用栈源自非主程序模块（第三方广告/插件 DLL）"
                .to_string(),
        );
    }

    if peaks[feat_idx::MEM_WX_TRANSITION] > 0.55 || peaks[feat_idx::CROSS_PROCESS_WRITE] > 0.55 {
        bullets.push(
            "高危内存行为：检测到内存页写后执行 (D→X) 或跨进程内存注入特征".to_string(),
        );
    }

    if peaks[feat_idx::SOCKET_RECV_DRIVEN] > 0.60 {
        bullets.push(
            "远端指令驱动：由网络 Socket_Recv 数据包在极短时序窗口内直接触发后续动作".to_string(),
        );
    }

    if peaks[feat_idx::TEMP_EXEC_WRITE] > 0.55 || peaks[feat_idx::PERSISTENCE_TAMPER] > 0.55 {
        bullets.push(
            "静默繁殖与驻留：捕获到 [网络收包 → 释放临时目录可执行文件 → 篡改注册表启动项/计划任务] 因果链"
                .to_string(),
        );
    }

    if let Some(doc) = &host.active_document_hint {
        bullets.push(format!(
            "宿主安全护栏已激活：宿主正持有您的活跃文档「{}」，代价矩阵已锁定禁止强杀主进程",
            doc
        ));
    } else if host.is_critical_shell_host {
        bullets.push(
            "系统核心宿主护栏：目标寄生于系统外壳进程，代价矩阵已屏蔽整进程强杀动作".to_string(),
        );
    }

    if bullets.is_empty() {
        bullets.push("各项时序与瞬时指标均处于正常软件行为基线范围内".to_string());
    }

    bullets
}
