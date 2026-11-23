//! 端侧内嵌「Qwen2.5-Coder-1.5B (Layer-0 Safetensors) 语义编码器 + 280-Tree LightGBM & SiLU MLP 预训练决策网络 + Mosaic 汉明记忆」
//! (`src/decision_model.rs`)
//!
//! 全部预训练模型权重 100% 封装进独立 `.exe` 可执行文件中（同时支持 `./models/` 外部热加载），零外部依赖、微秒级推理：
//!
//! ```text
//!                  [输入 1: 状态矩阵 S_t (16×12)]      [输入 2: 进程与窗口字节流上下文]
//!                                 │                                   │
//!      ┌──────────────────────────┴──────────┐                        ▼
//!      ▼                                     ▼        【内嵌预训练小 LLM: Qwen2.5-Coder-1.5B Layer-0】
//! 【第 1 级左：TCN 微时序因果编码层】   【第 1 级右：单帧极值层】  (`models/qwen25_security_model.safetensors` +
//!  捕捉跨步因果链 [Recv->Drop->Popup]    提取 16 步内瞬时峰值       `qwen25_bpe_vocab.json` 1024 BPE + QKV Self-Attn)
//!      │                                     │             输出 4 维深层语义嵌入 e_sem ∈ R^4
//!      └──────────────────────────┬──────────┴────────────────────────┘
//!                                 ▼
//!               【内嵌认知记忆: MosaicAssociativeMemory】
//!                • 64-bit 正交位平面指纹 (16 维 × 4 阈值位平面)
//!                • 原生 `XOR & POPCNT` 汉明联想召回与在线记忆巩固
//!                                 │
//!                                 ▼
//!               【第 2 级：预训练双层 SiLU MLP (17->32->4) + 280 棵 LightGBM 决策树森林】
//!                • 融合 `decision_mlp` (Safetensors) + `moe_gating_router.txt` (200 Trees) + `booster_champion_moe.txt` (80 Trees)
//!                • 计算 4 大潜空间意图概率 Z = [z_0, z_1, z_2, z_3] 及 Jev 威胁校准原语 (`jev_noul`, `jev_score`)
//!                                 │
//!                                 ▼
//!               【第 3 级：贝叶斯最小风险决策头 (Bayes Decision Head)】
//!                • 动态 5×4 非对称代价矩阵: E(Loss | a_i) = Cost_Matrix × Z
//!                • 输出期望代价最小的唯一外科手术指令: A_t = argmin_a E(Loss | a)
//! ```

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use crate::contract::{
    build_asymmetric_cost_matrix, feat_idx, HostContextProfile, LatentIntent, PolicyAction,
    StateMatrix, ACTION_DIM, FEAT_DIM, INTENT_DIM, SEQ_LEN,
};
use crate::pretrained_models::PretrainedModelBundle;

/// 决策模型单次推理的完整可解释输出（含 Qwen2.5 Layer-0、280-Tree LightGBM + SiLU MLP、Mosaic 汉明记忆与 Jev 原语）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutput {
    /// 最终选择的期望代价最小动作 argmin_a E(Loss | a)
    pub chosen_action: PolicyAction,
    /// 决策置信度 (0.0 ~ 1.0)
    pub confidence: f32,
    /// 是否处于模糊地带或需要提醒用户交互裁决
    pub needs_user_prompt: bool,
    /// 第 1 级输出：跨时间步因果链激活度 (0.0 ~ 1.0)
    pub temporal_causal_score: f32,
    /// 第 1 级输出：16 步内的单帧极值特征向量
    pub instantaneous_peaks: [f32; FEAT_DIM],
    /// 内嵌 Qwen2.5-1.5B Layer-0 Self-Attention 输出的 4 维语义嵌入
    pub lm_semantic_embed: [f32; INTENT_DIM],
    /// 内嵌 Mosaic 64-bit 位平面记忆库的汉明联想相似度 (0.0 ~ 1.0)
    pub mosaic_hamming_sim: f32,
    /// 内嵌 Jev System 1 `jev_noul` 二元威胁校准概率 (0.0 ~ 1.0)
    pub jev_noul_prob: f32,
    /// 内嵌 Jev System 1 `jev_score` 连续威胁评分 (0.0 ~ 10.0)
    pub jev_threat_score: f32,
    /// 第 2 级输出：4 大潜空间意图概率分布 Z = [z_0, z_1, z_2, z_3]
    pub intent_probs: [f32; INTENT_DIM],
    /// 第 3 级输出：5 种动作各自的期望损失 E(Loss | a_i) = (C × Z)_i
    pub expected_losses: [f32; ACTION_DIM],
    /// 推理耗时（微秒）
    pub latency_us: u64,
    /// 产生该次推理的策略模型版本号
    pub policy_revision: u64,
}

impl DecisionOutput {
    /// 获取主导意图 (argmax Z)
    pub fn dominant_intent(&self) -> (LatentIntent, f32) {
        let mut best_idx = 0;
        let mut best_p = self.intent_probs[0];
        for (i, &p) in self.intent_probs.iter().enumerate().skip(1) {
            if p > best_p {
                best_p = p;
                best_idx = i;
            }
        }
        (LatentIntent::ALL[best_idx], best_p)
    }
}

// ============================================================================
// 模块 A：内嵌真实预训练 Qwen2.5-Coder-1.5B (Layer-0 Safetensors) 语义编码器接口
// ============================================================================

pub struct Qwen25MicroLm;

impl Qwen25MicroLm {
    /// 调用从 `Qwen2.5-Coder-1.5B-Instruct` 真实提取的 1,024 BPE 词表与 Layer-0 Self-Attention 权重执行语义编码
    pub fn encode_context(app_name: &str, exe_path: &str, window_title: &str) -> [f32; INTENT_DIM] {
        PretrainedModelBundle::global().forward_qwen25_semantic_encoder(
            app_name,
            exe_path,
            window_title,
        )
    }
}

// ============================================================================
// 模块 B：内嵌 Wave × Mosaic 64-bit 位平面汉明联想记忆 (XOR & POPCNT)
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MosaicMemoryPrototype {
    /// 64-bit 正交二进制位平面指纹 (8 Heads × 8 Bits)
    pub bits: u64,
    /// 该原型绑定的目标意图
    pub intent: LatentIntent,
    /// 记忆巩固强度
    pub strength: f32,
}

impl MosaicMemoryPrototype {
    /// 将 12 维状态极值 + 4 维 Qwen2.5 语义向量量化为 64-bit 正交位平面指纹 (16 维 × 4 阈值位平面 = 64 bits)
    pub fn encode_fingerprint(peaks: &[f32; FEAT_DIM], sem: &[f32; INTENT_DIM]) -> u64 {
        let mut bits: u64 = 0;
        let thresholds = [0.20_f32, 0.45, 0.70, 0.88];
        for (i, &val) in peaks.iter().chain(sem.iter()).enumerate() {
            for (b_idx, &th) in thresholds.iter().enumerate() {
                if val >= th {
                    let bit_pos = i * 4 + b_idx;
                    bits |= 1u64 << bit_pos;
                }
            }
        }
        bits
    }

    /// 利用 CPU 原生 `XOR` 与 `POPCNT` (`count_ones`) 计算归一化汉明相似度 [0.0, 1.0]
    #[inline]
    pub fn hamming_similarity(a: u64, b: u64) -> f32 {
        let dist = (a ^ b).count_ones();
        (1.0 - (dist as f32 / 64.0)).clamp(0.0, 1.0)
    }
}

/// 策略网络参数包（全部初始权重从 `models/qwen25_security_model.safetensors` 加载，支持 ArcSwap 零停顿在线热更新）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyNetworkWeights {
    /// 策略修订代数（每次用户交互反馈学习后递增）
    pub revision: u64,
    /// 从 Safetensors 预训练模型加载并支持在线微调的 12 维瞬时极值特征权重 `[4 × 12]`
    pub peak_expert_weights: [[f32; FEAT_DIM]; INTENT_DIM],
    /// 从 Safetensors 预训练模型加载并支持在线微调的 4 条跨步时序因果链权重 `[4 × 4]`
    pub causal_chain_weights: [[f32; 4]; INTENT_DIM],
    /// Qwen2.5 Layer-0 语义通道耦合门控 `[4]`
    pub micro_lm_gate: [f32; INTENT_DIM],
    /// 从 Safetensors 预训练模型加载的宿主活跃度门控 `[4]`
    pub host_vitality_gate: [f32; INTENT_DIM],
    /// 从 Safetensors `decision_mlp.fc2.bias` 加载的意图偏置 `[4]`
    pub intent_bias: [f32; INTENT_DIM],
    /// Softmax 温度系数
    pub temperature: f32,
    /// 内嵌 Mosaic 64-bit 汉明联想记忆库（含预训练原型与用户在线反馈写入的记忆槽）
    pub mosaic_prototypes: Vec<MosaicMemoryPrototype>,
}

impl Default for PolicyNetworkWeights {
    fn default() -> Self {
        let bundle = PretrainedModelBundle::global();
        let mut peak_expert_weights = [[0.0_f32; FEAT_DIM]; INTENT_DIM];
        let mut causal_chain_weights = [[0.0_f32; 4]; INTENT_DIM];
        let mut host_vitality_gate = [0.0_f32; INTENT_DIM];

        for z in 0..INTENT_DIM {
            for d in 0..FEAT_DIM {
                peak_expert_weights[z][d] = bundle.distilled_linear_w[z][d];
            }
            for c in 0..4 {
                causal_chain_weights[z][c] = bundle.distilled_linear_w[z][12 + c];
            }
            host_vitality_gate[z] = bundle.distilled_linear_w[z][16];
        }

        let sem_z0 = Qwen25MicroLm::encode_context(
            "explorer.exe",
            r"C:\Windows\explorer.exe",
            "文件资源管理器",
        );
        let sem_z1 = Qwen25MicroLm::encode_context(
            "wps.exe",
            r"C:\Program Files\Kingsoft\WPS Office\wps.exe",
            "双11特惠会员弹窗",
        );
        let sem_z2 = Qwen25MicroLm::encode_context(
            "ad_helper_98a.exe",
            r"C:\Users\Public\AppData\Local\ad_helper_98a.exe",
            "精彩推荐",
        );
        let sem_z3 = Qwen25MicroLm::encode_context(
            "svch0st_up.exe",
            r"C:\Users\Admin\AppData\Local\Temp\svch0st_up.exe",
            "",
        );

        let default_z0_fp =
            MosaicMemoryPrototype::encode_fingerprint(&[0.05; FEAT_DIM], &sem_z0);
        let default_z1_fp = MosaicMemoryPrototype::encode_fingerprint(
            &[0.95, 0.95, 0.92, 0.90, 0.06, 0.85, 0.04, 0.40, 0.82, 0.04, 0.02, 0.10],
            &sem_z1,
        );
        let default_z2_fp = MosaicMemoryPrototype::encode_fingerprint(
            &[0.92, 0.95, 0.92, 0.90, 0.15, 0.90, 0.85, 0.55, 0.88, 0.35, 0.05, 0.92],
            &sem_z2,
        );
        let default_z3_fp = MosaicMemoryPrototype::encode_fingerprint(
            &[0.95, 0.90, 0.96, 1.00, 0.92, 0.88, 0.90, 0.94, 0.90, 0.95, 0.94, 0.96],
            &sem_z3,
        );

        Self {
            revision: 1,
            peak_expert_weights,
            causal_chain_weights,
            micro_lm_gate: [0.35, 0.35, 0.40, 0.40],
            host_vitality_gate,
            intent_bias: bundle.mlp_fc3_b,
            temperature: 0.85,
            mosaic_prototypes: vec![
                MosaicMemoryPrototype {
                    bits: default_z0_fp,
                    intent: LatentIntent::Z0LegitInteraction,
                    strength: 0.55,
                },
                MosaicMemoryPrototype {
                    bits: default_z1_fp,
                    intent: LatentIntent::Z1HostBundledAd,
                    strength: 0.65,
                },
                MosaicMemoryPrototype {
                    bits: default_z2_fp,
                    intent: LatentIntent::Z2ParasiticAdModule,
                    strength: 0.65,
                },
                MosaicMemoryPrototype {
                    bits: default_z3_fp,
                    intent: LatentIntent::Z3SilentDropper,
                    strength: 0.70,
                },
            ],
        }
    }
}

/// 端侧内嵌多专家决策与 Micro-LM 混合引擎（Policy-Decision-Engine）
/// 内部通过 `ArcSwap<PolicyNetworkWeights>` 实现 0 停顿毫秒级策略热更新
pub struct PolicyDecisionEngine {
    weights: ArcSwap<PolicyNetworkWeights>,
}

impl Default for PolicyDecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyDecisionEngine {
    pub fn new() -> Self {
        Self {
            weights: ArcSwap::from_pointee(PolicyNetworkWeights::default()),
        }
    }

    /// 获取当前策略版本号
    pub fn current_revision(&self) -> u64 {
        self.weights.load().revision
    }

    /// 获取当前 Mosaic 联想记忆槽数量
    pub fn mosaic_memory_count(&self) -> usize {
        self.weights.load().mosaic_prototypes.len()
    }

    /// 获取当前策略权重的快照
    pub fn snapshot_weights(&self) -> Arc<PolicyNetworkWeights> {
        self.weights.load_full()
    }

    /// 实时热更新决策模型的超参数（Softmax 温度、Qwen2.5 语义耦合门控、高危意图偏置），零停顿切换 ArcSwap 权重
    pub fn apply_custom_hyperparams(
        &self,
        temperature: f32,
        lm_gate_gain: f32,
        z3_threat_bias_delta: f32,
    ) -> u64 {
        let mut next_w = (*self.weights.load_full()).clone();
        next_w.revision += 1;
        next_w.temperature = temperature.clamp(0.15, 2.50);
        let g = lm_gate_gain.clamp(0.05, 1.50);
        next_w.micro_lm_gate = [g * 0.85, g * 0.85, g, g];
        let base_b = PretrainedModelBundle::global().mlp_fc3_b;
        next_w.intent_bias[0] = base_b[0] - z3_threat_bias_delta * 0.5;
        next_w.intent_bias[3] = base_b[3] + z3_threat_bias_delta;
        let rev = next_w.revision;
        self.weights.store(Arc::new(next_w));
        rev
    }

    /// 执行标准三层混合决策推理（默认使用空字节上下文，自动根据状态特征推导 Micro-LM 语义）
    pub fn evaluate(
        &self,
        state: &StateMatrix,
        host: &HostContextProfile,
    ) -> DecisionOutput {
        self.evaluate_with_context(state, host, "", "", "")
    }

    /// 执行完整「内嵌 1.58-bit Ternary Micro-LM + Mosaic 64-bit 汉明记忆 + Jev-System-1 三层混合决策」推理
    pub fn evaluate_with_context(
        &self,
        state: &StateMatrix,
        host: &HostContextProfile,
        app_name: &str,
        exe_path: &str,
        window_title: &str,
    ) -> DecisionOutput {
        let start = Instant::now();
        let w = self.weights.load();

        // ─────────────────────────────────────────────────────────────
        // 【第 1 级右支：单帧极值特征提取层 (Instantaneous Peak Extractor)】
        // ─────────────────────────────────────────────────────────────
        let mut peaks = [0.0_f32; FEAT_DIM];
        for (t, frame) in state.iter().enumerate() {
            let recency = 0.75 + 0.25 * (t as f32 / (SEQ_LEN - 1) as f32);
            for (d, &v) in frame.iter().enumerate() {
                let weighted = (v * recency).clamp(0.0, 1.0);
                if weighted > peaks[d] {
                    peaks[d] = weighted;
                }
            }
        }

        // ─────────────────────────────────────────────────────────────
        // 【第 1 级左支：微时序上下文编码层 (Temporal Causal Encoder: TCN)】
        // ─────────────────────────────────────────────────────────────
        let causal_chains = Self::extract_temporal_causal_chains(state);
        let temporal_causal_score = causal_chains[1]
            .max(causal_chains[2])
            .max(causal_chains[3])
            .clamp(0.0, 1.0);

        // ─────────────────────────────────────────────────────────────
        // 【内嵌小 LLM 层：Qwen2.5-Coder-1.5B Layer-0 Self-Attention 语义编码】
        // ─────────────────────────────────────────────────────────────
        let bundle = PretrainedModelBundle::global();
        let lm_semantic_embed = if app_name.is_empty() && exe_path.is_empty() {
            [
                (1.0 - peaks[feat_idx::TEMP_EXEC_WRITE]).clamp(0.0, 1.0),
                peaks[feat_idx::FOREIGN_STACK_ORIGIN],
                peaks[feat_idx::LINEAGE_DIVERGENCE].max(peaks[feat_idx::PAYLOAD_SHANNON_ENTROPY]),
                peaks[feat_idx::PERSISTENCE_TAMPER],
            ]
        } else {
            Qwen25MicroLm::encode_context(app_name, exe_path, window_title)
        };

        // ─────────────────────────────────────────────────────────────
        // 【内嵌认知记忆层：Mosaic 64-bit 正交位平面 `XOR & POPCNT` 汉明联想召回】
        // ─────────────────────────────────────────────────────────────
        let fp = MosaicMemoryPrototype::encode_fingerprint(&peaks, &lm_semantic_embed);
        let mut mosaic_boost = [0.0_f32; INTENT_DIM];
        let mut best_hamming_sim = 0.0_f32;
        for proto in &w.mosaic_prototypes {
            let sim = MosaicMemoryPrototype::hamming_similarity(fp, proto.bits);
            if sim > best_hamming_sim {
                best_hamming_sim = sim;
            }
            // 当位平面汉明相似度超过 0.78 (即 64 bits 中 >= 50 bits 一致) 时触发谐振增益
            if sim > 0.78 {
                let idx = proto.intent as usize;
                let resonance = (sim - 0.78) * 4.5 * proto.strength;
                if resonance > mosaic_boost[idx] {
                    mosaic_boost[idx] = resonance;
                }
            }
        }

        // ─────────────────────────────────────────────────────────────
        // 【第 2 级：预训练双层 SiLU MLP + 280-Tree LightGBM 森林 + 在线微调残差】
        // ─────────────────────────────────────────────────────────────
        let vitality = host.protection_vitality();
        let pretrained_logits =
            bundle.forward_pretrained_decision_ensemble(&peaks, &causal_chains, vitality);
        let mut logits = [0.0_f32; INTENT_DIM];

        for z in 0..INTENT_DIM {
            // 计算用户在线交互反馈产生的增量权重残差 ΔW (初始 revision=1 时 ΔW == 0)
            let mut online_delta =
                (w.host_vitality_gate[z] - bundle.distilled_linear_w[z][16]) * vitality;
            for d in 0..FEAT_DIM {
                online_delta +=
                    (w.peak_expert_weights[z][d] - bundle.distilled_linear_w[z][d]) * peaks[d];
            }
            for c in 0..4 {
                online_delta += (w.causal_chain_weights[z][c]
                    - bundle.distilled_linear_w[z][12 + c])
                    * causal_chains[c];
            }

            let sum = pretrained_logits[z]
                + online_delta
                + w.micro_lm_gate[z] * (lm_semantic_embed[z] - 0.5)
                + mosaic_boost[z];
            logits[z] = sum / w.temperature.max(0.1);
        }

        let intent_probs = Self::softmax(logits);

        // Jev System 1 校准原语计算：
        // 1. `jev_noul` 二元威胁概率 P(Threat) = P(z_1) + P(z_2) + P(z_3)
        let jev_noul_prob = (intent_probs[1] + intent_probs[2] + intent_probs[3]).clamp(0.0, 1.0);
        // 2. `jev_score` 连续威胁标尺 (0.0 ~ 10.0)，对寄生与驻留赋予更高严重度权重
        let jev_threat_score = ((intent_probs[1] * 6.8
            + intent_probs[2] * 8.6
            + intent_probs[3] * 9.8
            + temporal_causal_score * 1.2)
            * jev_noul_prob)
            .clamp(0.0, 10.0);

        // ─────────────────────────────────────────────────────────────
        // 【第 3 级：最小风险决策头 (Bayes Minimum Risk Decision Head)】
        // 计算期望损失 E(Loss | a_i) = (Cost_Matrix × Z)_i
        // ─────────────────────────────────────────────────────────────
        let cost_matrix = build_asymmetric_cost_matrix(host);
        let mut expected_losses = [0.0_f32; ACTION_DIM];
        for a in 0..ACTION_DIM {
            let mut loss = 0.0_f32;
            for z in 0..INTENT_DIM {
                loss += cost_matrix[a][z] * intent_probs[z];
            }
            expected_losses[a] = loss;
        }

        let mut best_action_idx = 0;
        let mut min_loss = expected_losses[0];
        let mut second_min_loss = f32::MAX;

        for (a, &loss) in expected_losses.iter().enumerate().skip(1) {
            if loss < min_loss {
                second_min_loss = min_loss;
                min_loss = loss;
                best_action_idx = a;
            } else if loss < second_min_loss {
                second_min_loss = loss;
            }
        }

        let chosen_action = PolicyAction::from_index(best_action_idx);
        let (_, dom_prob) = {
            let mut mp = 0.0_f32;
            let mut mi = 0;
            for (i, &p) in intent_probs.iter().enumerate() {
                if p > mp {
                    mp = p;
                    mi = i;
                }
            }
            (mi, mp)
        };

        let margin_ratio =
            ((second_min_loss - min_loss) / (second_min_loss.abs() + 1.5)).clamp(0.0, 1.0);
        let confidence = (0.65 * dom_prob + 0.35 * margin_ratio).clamp(0.0, 0.999);
        let needs_user_prompt = chosen_action == PolicyAction::A1DeferWait || confidence < 0.72;
        let latency_us = start.elapsed().as_micros().max(1) as u64;

        DecisionOutput {
            chosen_action,
            confidence,
            needs_user_prompt,
            temporal_causal_score,
            instantaneous_peaks: peaks,
            lm_semantic_embed,
            mosaic_hamming_sim: best_hamming_sim,
            jev_noul_prob,
            jev_threat_score,
            intent_probs,
            expected_losses,
            latency_us,
            policy_revision: w.revision,
        }
    }

    /// 基于用户在安全助手上的交互裁决，执行在线增量学习 + Mosaic 64-bit 位平面记忆写入 + ArcSwap 零停顿热更新
    pub fn adapt_from_user_feedback(
        &self,
        state: &StateMatrix,
        host: &HostContextProfile,
        user_action: PolicyAction,
    ) -> u64 {
        let current = self.weights.load_full();
        let mut next = (*current).clone();
        next.revision += 1;

        let target_intent_enum = match user_action {
            PolicyAction::A0PassAndUntag => LatentIntent::Z0LegitInteraction,
            PolicyAction::A1DeferWait => LatentIntent::Z0LegitInteraction,
            PolicyAction::A2SurgicalMute => LatentIntent::Z1HostBundledAd,
            PolicyAction::A3ProcessIsolate => LatentIntent::Z2ParasiticAdModule,
            PolicyAction::A4RootPurge => LatentIntent::Z3SilentDropper,
        };
        let target_intent = target_intent_enum as usize;

        let mut peaks = [0.0_f32; FEAT_DIM];
        for frame in state.iter() {
            for (d, &v) in frame.iter().enumerate() {
                if v > peaks[d] {
                    peaks[d] = v;
                }
            }
        }
        let chains = Self::extract_temporal_causal_chains(state);
        let lr = 0.38_f32;

        // 1. 更新 MoE 专家权重与因果核权重
        for z in 0..INTENT_DIM {
            let sign = if z == target_intent { 1.0 } else { -0.30 };
            for d in 0..FEAT_DIM {
                if peaks[d] > 0.25 {
                    next.peak_expert_weights[z][d] =
                        (next.peak_expert_weights[z][d] + lr * sign * peaks[d]).clamp(-4.5, 4.5);
                }
            }
            for c in 0..4 {
                if chains[c] > 0.25 {
                    next.causal_chain_weights[z][c] =
                        (next.causal_chain_weights[z][c] + lr * sign * chains[c]).clamp(-4.5, 4.5);
                }
            }
        }

        if host.protection_vitality() > 0.4 && user_action == PolicyAction::A2SurgicalMute {
            next.host_vitality_gate[LatentIntent::Z1HostBundledAd as usize] =
                (next.host_vitality_gate[LatentIntent::Z1HostBundledAd as usize] + 0.25)
                    .clamp(-3.0, 3.5);
        }

        // 2. 将当前样本的 64-bit 正交位平面指纹写入 MosaicAssociativeMemory（最多保留 64 个高价值原型）
        let sem = [
            (1.0 - peaks[feat_idx::TEMP_EXEC_WRITE]).clamp(0.0, 1.0),
            peaks[feat_idx::FOREIGN_STACK_ORIGIN],
            peaks[feat_idx::LINEAGE_DIVERGENCE].max(peaks[feat_idx::PAYLOAD_SHANNON_ENTROPY]),
            peaks[feat_idx::PERSISTENCE_TAMPER],
        ];
        let fp = MosaicMemoryPrototype::encode_fingerprint(&peaks, &sem);
        if next.mosaic_prototypes.len() >= 64 {
            next.mosaic_prototypes.remove(4); // 保留前 4 个先验原型，淘汰最早的动态原型
        }
        next.mosaic_prototypes.push(MosaicMemoryPrototype {
            bits: fp,
            intent: target_intent_enum,
            strength: 0.85,
        });

        let new_rev = next.revision;
        self.weights.store(Arc::new(next));
        new_rev
    }

    /// 第 1 级左支：跨时间步微时序因果编码器 (TCN Causal Kernel)
    fn extract_temporal_causal_chains(state: &StateMatrix) -> [f32; 4] {
        let mut early_net_recv = 0.0_f32;
        let mut mid_temp_drop = 0.0_f32;
        let mut late_persistence = 0.0_f32;

        let mut early_injection_or_foreign = 0.0_f32;
        let mut late_stealth_popup = 0.0_f32;
        let mut human_active_recent = 0.0_f32;

        for (t, f) in state.iter().enumerate() {
            let human_now = (1.0 - f[feat_idx::INPUT_IDLE_DECAY]).clamp(0.0, 1.0);
            if t >= SEQ_LEN / 2 && human_now > human_active_recent {
                human_active_recent = human_now;
            }

            if t <= 12 {
                early_net_recv = early_net_recv.max(f[feat_idx::SOCKET_RECV_DRIVEN]);
                early_injection_or_foreign = early_injection_or_foreign.max(
                    f[feat_idx::CROSS_PROCESS_WRITE]
                        .max(f[feat_idx::FOREIGN_STACK_ORIGIN])
                        .max(f[feat_idx::LINEAGE_DIVERGENCE]),
                );
            }

            if (2..=14).contains(&t) {
                mid_temp_drop = mid_temp_drop
                    .max(f[feat_idx::TEMP_EXEC_WRITE].max(f[feat_idx::MEM_WX_TRANSITION] * 0.8));
            }

            if t >= 4 {
                late_persistence = late_persistence.max(f[feat_idx::PERSISTENCE_TAMPER]);
            }

            if t >= 6 {
                let popup_sig = (0.35 * f[feat_idx::TOPMOST_BORDERLESS_MASK]
                    + 0.30 * f[feat_idx::TASKBAR_HIDDEN]
                    + 0.35 * f[feat_idx::SCREEN_ZONE_CODE])
                    * f[feat_idx::INPUT_IDLE_DECAY];
                late_stealth_popup = late_stealth_popup.max(popup_sig);
            }
        }

        let chain0_legit = (human_active_recent * (1.0 - late_persistence)).clamp(0.0, 1.0);
        let chain1_host_popup =
            (late_stealth_popup * (0.5 + 0.5 * early_net_recv) * (1.0 - late_persistence * 0.8))
                .clamp(0.0, 1.0);
        let chain2_parasitic =
            (early_injection_or_foreign * (0.65 * late_stealth_popup + 0.35)).clamp(0.0, 1.0);
        let chain3_dropper =
            ((0.30 * early_net_recv + 0.35 * mid_temp_drop + 0.35 * late_persistence)
                * (if mid_temp_drop > 0.5 && late_persistence > 0.5 {
                    1.25
                } else {
                    0.85
                }))
            .clamp(0.0, 1.0);

        [
            chain0_legit,
            chain1_host_popup,
            chain2_parasitic,
            chain3_dropper,
        ]
    }

    fn softmax(logits: [f32; INTENT_DIM]) -> [f32; INTENT_DIM] {
        let max_l = logits
            .iter()
            .copied()
            .fold(f32::NEG_INFINITY, f32::max);
        let mut exps = [0.0_f32; INTENT_DIM];
        let mut sum = 0.0_f32;
        for i in 0..INTENT_DIM {
            let e = (logits[i] - max_l).exp();
            exps[i] = e;
            sum += e;
        }
        for e in exps.iter_mut() {
            *e /= sum.max(1e-6);
        }
        exps
    }
}
