//! 四（模块 2）：血缘与状态池 (State-Lineage-Arena)
//! 1. 维护每个活跃被染色对象的 [16, 12] 环形滑动窗口
//! 2. 维护《污染溯源账本》有向图：记录“谁释放了谁、谁写了哪个自启动项、谁弹出了哪个 HWND 窗口”
//!    供 a_2 (外科手术消音)、a_3 (进程禁生)、a_4 (连根拔除与回滚) 精确检索与执行。

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::contract::{FrameFeatures, HostContextProfile, StateMatrix, FEAT_DIM, SEQ_LEN};

/// 窗口句柄与视觉属性快照（供 a_2 外科手术消音精准打击）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedWindow {
    /// 目标窗口 HWND（十六进制展示或传给 Win32 API）
    pub hwnd: u64,
    /// 渲染该窗口的 UI 线程 TID（用于精准挂起广告线程而不卡死主进程工作线程）
    pub ui_thread_id: u32,
    /// 窗口标题或类名描述
    pub title: String,
    /// 窗口位置与尺寸 (x, y, width, height)
    pub rect: (i32, i32, i32, i32),
    /// 是否携带 WS_EX_TOPMOST 置顶属性
    pub is_topmost: bool,
    /// 是否已被安全助手执行外科手术消音
    pub muted: bool,
}

/// 《污染溯源账本》单条衍生记录（供 a_4 连根拔除与一键回滚使用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContaminationLedger {
    /// 衍生孵化的子进程列表 (PID, 进程名, 可执行路径)
    pub spawned_children: Vec<(u32, String, String)>,
    /// 释放到磁盘的可执行/捆绑文件路径列表
    pub dropped_files: Vec<String>,
    /// 篡改的注册表自启动项列表 (键路径, 值名称, 写入的数据)
    pub registry_run_entries: Vec<(String, String, String)>,
    /// 创建的计划任务名称列表
    pub scheduled_tasks: Vec<String>,
    /// 该对象弹出的可疑/广告窗口列表
    pub popup_windows: Vec<TrackedWindow>,
}

impl Default for ContaminationLedger {
    fn default() -> Self {
        Self {
            spawned_children: Vec::new(),
            dropped_files: Vec::new(),
            registry_run_entries: Vec::new(),
            scheduled_tasks: Vec::new(),
            popup_windows: Vec::new(),
        }
    }
}

impl ContaminationLedger {
    /// 统计账本中记录的污染痕迹总数
    pub fn total_artifacts(&self) -> usize {
        self.spawned_children.len()
            + self.dropped_files.len()
            + self.registry_run_entries.len()
            + self.scheduled_tasks.len()
            + self.popup_windows.len()
    }
}

/// 稀疏追踪池中的单个被染色执行体实体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedEntity {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub signer_info: String,
    /// 宿主上下文安全档案（是否打开用户文档、是否系统关键宿主）
    pub host_profile: HostContextProfile,
    /// 最近 16 步 × 12 维时序状态矩阵 S_t
    pub state_window: StateMatrix,
    /// 已接收的边界事件总帧数
    pub frames_observed: usize,
    /// 该执行体关联的《污染溯源账本》
    pub ledger: ContaminationLedger,
    /// 是否仍在稀疏染色池中活跃追踪（若执行 a_0 摘牌或 a_3/a_4 清理则脱离活跃态）
    pub active_in_arena: bool,
}

impl TrackedEntity {
    pub fn new(
        pid: u32,
        parent_pid: u32,
        process_name: impl Into<String>,
        exe_path: impl Into<String>,
        signer_info: impl Into<String>,
        host_profile: HostContextProfile,
    ) -> Self {
        Self {
            pid,
            parent_pid,
            process_name: process_name.into(),
            exe_path: exe_path.into(),
            signer_info: signer_info.into(),
            host_profile,
            state_window: [[0.0; FEAT_DIM]; SEQ_LEN],
            frames_observed: 0,
            ledger: ContaminationLedger::default(),
            active_in_arena: true,
        }
    }

    /// 推入一个新的 12 维边界事件特征帧，滑动更新 [16, 12] 状态窗口
    pub fn push_frame(&mut self, frame: FrameFeatures) {
        self.state_window.copy_within(1..SEQ_LEN, 0);
        self.state_window[SEQ_LEN - 1] = frame;
        self.frames_observed += 1;
    }

    /// 直接装载完整的 16×12 状态矩阵
    pub fn load_state_matrix(&mut self, matrix: StateMatrix) {
        self.state_window = matrix;
        self.frames_observed = SEQ_LEN;
    }
}

/// 血缘与状态池 (State-Lineage-Arena)
pub struct StateLineageArena {
    entities: HashMap<u32, TrackedEntity>,
}

impl Default for StateLineageArena {
    fn default() -> Self {
        Self::new()
    }
}

impl StateLineageArena {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    pub fn upsert_entity(&mut self, entity: TrackedEntity) {
        self.entities.insert(entity.pid, entity);
    }

    pub fn get_entity(&self, pid: u32) -> Option<&TrackedEntity> {
        self.entities.get(&pid)
    }

    pub fn get_entity_mut(&mut self, pid: u32) -> Option<&mut TrackedEntity> {
        self.entities.get_mut(&pid)
    }

    /// 执行 a_0 (ACTION_PASS_AND_UNTAG) 时调用：从稀疏染色追踪池中摘牌，释放算力
    pub fn untag_entity(&mut self, pid: u32) {
        if let Some(ent) = self.entities.get_mut(&pid) {
            ent.active_in_arena = false;
        }
    }

    /// 当前正在被染色追踪的活跃对象数
    pub fn active_count(&self) -> usize {
        self.entities.values().filter(|e| e.active_in_arena).count()
    }

    pub fn all_entities(&self) -> impl Iterator<Item = &TrackedEntity> {
        self.entities.values()
    }
}
