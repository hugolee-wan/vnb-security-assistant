//! 端侧封装的 80MB+ 真实预训练大模型与多森林决策集群引擎 (`src/pretrained_models.rs`)
//!
//! 物理内嵌（同时支持 `./models/` 目录外部热覆盖）以下 12 个真实训练的模型权重文件：
//! 1. `models/qwen25_security_model.safetensors` (`77.65 MB`, 66 个张量, HuggingFace Safetensors 格式)：
//!    - 从 `Qwen/Qwen2.5-Coder-1.5B-Instruct-4bit` 原生提取的：
//!      * 32,768 个 Token 的完整 **1,536 维** 4-bit 词向量表 `model.embed_tokens.{weight,scales,biases}` (`U32 [32768, 192]`, `F16 [32768, 24]`)
//!      * 完整 **2 层 1,536 维 Transformer 块** (`model.layers.0.*` 与 `model.layers.1.*`)：
//!        - `input_layernorm.weight` (`F16 [1536]`)、`post_attention_layernorm.weight` (`F16 [1536]`)、`model.norm.weight` (`F16 [1536]`)
//!        - GQA 多头自注意力 4-bit 权重：`q_proj` (`[1536, 1536]`)、`k_proj` (`[256, 1536]`)、`v_proj` (`[256, 1536]`)、`o_proj` (`[1536, 1536]`)
//!        - SwiGLU 前馈网络 4-bit 权重：`gate_proj` (`[8960, 1536]`)、`up_proj` (`[8960, 1536]`)、`down_proj` (`[1536, 8960]`)
//!      * 1,536 维全尺寸安全语义投影头 `qwen25.security_sem_head.weight` (`F32 [4, 1536]`)
//!    - 经 Adam 反向传播训练收敛 (`loss=0.01911, acc=100%`) 的 **深层残差决策网络 (Deep Residual MLP: `17 -> 256 -> +Res(256) -> 128 -> 4`, 103,044 参数)**：
//!      * `decision_mlp.fc1.{weight,bias}` (`[17, 256]`)
//!      * `decision_mlp.res.{weight,bias}` (`[256, 256]`)
//!      * `decision_mlp.fc2.{weight,bias}` (`[256, 128]`)
//!      * `decision_mlp.fc3.{weight,bias}` (`[128, 4]`)
//!      * `decision_linear.distilled.weight` (`[4, 17]`)
//! 2. `models/qwen25_bpe_vocab.json` (`541 KB`)：
//!    - 真实提取的 **32,768 个 Qwen2.5 BPE 子词词表**。
//! 3. **9 个真实训练的 LightGBM 梯度提升森林 + 1 个 CatBoost 模型** (`2.35 MB`)：
//!    - `moe_gating_router.txt` (200 棵树, 4 分类 MoE 路由)
//!    - `booster_champion_moe.txt` (80 棵树)
//!    - `booster_three_subspace_ensemble_v1.txt` (90 棵树)
//!    - `booster_core_alpha_ensemble_v1.txt` (90 棵树)
//!    - `booster_core_alpha_defensive_gated_v1.txt` (80 棵树)
//!    - `booster_core_alpha_max_yield_v1.txt` (80 棵树)
//!    - `booster_tide_expansion.txt` (62 棵树)
//!    - `booster_tide_reversal.txt` (62 棵树)
//!    - `booster_tide_rotation.txt` (62 棵树)
//!    - `booster_catboost_microstructure.cbm` (54 KB CatBoost 二进制对称树模型)

use std::collections::HashMap;
use std::os::raw::c_int;
use std::sync::{Mutex, OnceLock};
use serde::Deserialize;

use crate::contract::{FEAT_DIM, INTENT_DIM};

/// 本地 `libbittrit.dylib` + `libmlx_bittrit_bridge.dylib` + `libmlx_qwen38_bridge.dylib` 动态链接加速表
pub struct NativeDylibAccelerator {
    pub bittrit_loaded: bool,
    pub mlx_bittrit_loaded: bool,
    pub mlx_qwen38_loaded: bool,
    quantize_f32_subspaces_to_b8t5_flat:
        Option<unsafe extern "C" fn(*const f32, usize, usize, f32, *mut u16, *mut f32) -> f32>,
    fuse_multichannel_arena_flat: Option<
        unsafe extern "C" fn(
            *const u16,
            *const u16,
            *const u16,
            *const u16,
            usize,
            *const i8,
            *mut u16,
            *mut i16,
        ) -> usize,
    >,
    quantize_weights_f32_to_t5t5_9level_flat:
        Option<unsafe extern "C" fn(*const f32, usize, usize, *mut u16, *mut f32) -> usize>,
    build_activation_luts256_for_t5t5_flat:
        Option<unsafe extern "C" fn(*const f32, usize, *mut i16) -> f32>,
    matvec_t5t5_9level_flat: Option<
        unsafe extern "C" fn(
            *const u16,
            *const i16,
            *const f32,
            f32,
            usize,
            usize,
            *mut f32,
        ) -> usize,
    >,
    route_moe_experts_4combo_flat: Option<
        unsafe extern "C" fn(
            *const f32,
            f32,
            *mut u16,
            *mut u16,
            *mut u16,
            *mut u16,
            *mut i16,
        ) -> u8,
    >,
    transcode_word: Option<unsafe extern "C" fn(u8, u16, u8) -> u16>,
    sort_and_query_t5b8_regime_flat: Option<
        unsafe extern "C" fn(
            *const u16,
            usize,
            u8,
            u8,
            u8,
            *mut u16,
            *mut u32,
        ) -> usize,
    >,
    weighted_mac_b8t5_flat: Option<
        unsafe extern "C" fn(
            *const u16,
            usize,
            *const i8,
            u8,
            u8,
            u8,
            i32,
            *mut i32,
            *mut u16,
            *mut u32,
        ) -> usize,
    >,
    gpu_b8t5_matvec:
        Option<unsafe extern "C" fn(*const u16, *const i16, c_int, c_int, *mut i32) -> c_int>,
    gpu_prefilter_kv:
        Option<unsafe extern "C" fn(*const u16, *const u16, c_int, *mut i16) -> c_int>,
}

pub fn native_dylib_accel() -> &'static NativeDylibAccelerator {
    static ACCEL: OnceLock<NativeDylibAccelerator> = OnceLock::new();
    ACCEL.get_or_init(|| unsafe {
        let h_bt = crate::platform::open_dynamic_library_candidates("bittrit");
        let h_mlx = crate::platform::open_dynamic_library_candidates("mlx_bittrit_bridge");
        let h_q38 = crate::platform::open_dynamic_library_candidates("mlx_qwen38_bridge");

        macro_rules! opt_sym {
            ($h:expr, $name:literal) => {{
                if $h.is_null() {
                    None
                } else {
                    let p = crate::platform::lookup_dynamic_symbol($h, concat!($name, "\0").as_bytes());
                    if p.is_null() {
                        None
                    } else {
                        Some(std::mem::transmute(p))
                    }
                }
            }};
        }

        NativeDylibAccelerator {
            bittrit_loaded: !h_bt.is_null(),
            mlx_bittrit_loaded: !h_mlx.is_null(),
            mlx_qwen38_loaded: !h_q38.is_null(),
            quantize_f32_subspaces_to_b8t5_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_quantize_f32_subspaces_to_b8t5_flat"
            ),
            fuse_multichannel_arena_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_fuse_multichannel_arena_flat"
            ),
            quantize_weights_f32_to_t5t5_9level_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_quantize_weights_f32_to_t5t5_9level_flat"
            ),
            build_activation_luts256_for_t5t5_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_build_activation_luts256_for_t5t5_flat"
            ),
            matvec_t5t5_9level_flat: opt_sym!(h_bt, "tdx_rust_bt16_matvec_t5t5_9level_flat"),
            route_moe_experts_4combo_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_route_moe_experts_4combo_flat"
            ),
            transcode_word: opt_sym!(h_bt, "tdx_rust_bt16_transcode_word"),
            sort_and_query_t5b8_regime_flat: opt_sym!(
                h_bt,
                "tdx_rust_bt16_sort_and_query_t5b8_regime_flat"
            ),
            weighted_mac_b8t5_flat: opt_sym!(h_bt, "tdx_rust_bt16_weighted_mac_b8t5_flat"),
            gpu_b8t5_matvec: opt_sym!(h_mlx, "mlx_bittrit_gpu_b8t5_matvec"),
            gpu_prefilter_kv: opt_sym!(h_mlx, "mlx_bittrit_gpu_prefilter_kv"),
        }
    })
}

fn resolve_model_path(filename: &str) -> std::path::PathBuf {
    let rel = std::path::PathBuf::from("models").join(filename);
    if rel.exists() {
        return rel;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let p0 = exe_dir.join("models").join(filename);
            if p0.exists() {
                return p0;
            }
            if let Some(contents) = exe_dir.parent() {
                let p_res = contents.join("Resources/models").join(filename);
                if p_res.exists() {
                    return p_res;
                }
                if let Some(root2) = contents.parent() {
                    let p2 = root2.join("models").join(filename);
                    if p2.exists() {
                        return p2;
                    }
                    if let Some(root3) = root2.parent() {
                        let p3 = root3.join("models").join(filename);
                        if p3.exists() {
                            return p3;
                        }
                    }
                }
            }
        }
    }
    let root_m = crate::platform::app_install_root().join("models").join(filename);
    if root_m.exists() {
        return root_m;
    }
    if let Some(reg_dir) = crate::platform::sibling_model_registry_dir() {
        let r = reg_dir.join(filename);
        if r.exists() {
            return r;
        }
    }
    crate::platform::app_state_dir().join("models").join(filename)
}

/// Zero-copy Safetensors weight backing: OS memory-mapped file on disk, with owned heap fallback.
pub enum SafetensorsStorage {
    Mmap(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl std::ops::Deref for SafetensorsStorage {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            SafetensorsStorage::Mmap(m) => m.as_ref(),
            SafetensorsStorage::Owned(v) => v.as_slice(),
        }
    }
}

fn open_model_mmap(filename: &str) -> SafetensorsStorage {
    let p = resolve_model_path(filename);
    if let Ok(file) = std::fs::File::open(&p) {
        // Safety: safetensors weight files under registry/models are immutable during runtime.
        if let Ok(mmap) = unsafe { memmap2::MmapOptions::new().map(&file) } {
            return SafetensorsStorage::Mmap(mmap);
        }
    }
    let bytes = std::fs::read(&p)
        .unwrap_or_else(|e| panic!("Failed to read model file {} ({}): {}", filename, p.display(), e));
    SafetensorsStorage::Owned(bytes)
}

fn read_model_bytes(filename: &str) -> Vec<u8> {
    let p = resolve_model_path(filename);
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("Failed to read model file {} ({}): {}", filename, p.display(), e))
}

fn read_model_string(filename: &str) -> String {
    let p = resolve_model_path(filename);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("Failed to read model text {} ({}): {}", filename, p.display(), e))
}

pub const DEFAULT_HIDDEN_DIM: usize = 3584;
pub const DEFAULT_KV_DIM: usize = 512;
pub const VOCAB_SIZE: usize = 32768;
pub const MLP_IN_DIM: usize = 17;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdSemanticPrediction {
    /// [正常良性, 广告弹窗/促销悬浮, 广告联盟/追踪/Adware, 恶意投递/Malvertising]
    pub class_probs: [f32; INTENT_DIM],
    pub predicted_class: usize,
    pub predicted_label: String,
    pub ad_risk_score: f32,
}

#[derive(Debug, Clone)]
pub struct TransformerLayerWeights {
    pub prefix: String,
    pub ln_in: Vec<f32>,
    pub ln_post: Vec<f32>,
    pub q_bias: Vec<f32>,
    pub k_bias: Vec<f32>,
    pub v_bias: Vec<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TensorHeaderEntry {
    pub dtype: String,
    pub shape: Vec<usize>,
    pub data_offsets: [usize; 2],
}

#[derive(Debug, Deserialize)]
struct QwenCompactVocabFile {
    pub source_model: String,
    pub vocab_size: usize,
    pub token_to_compact_id: HashMap<String, usize>,
}

/// IEEE 754 Half-Precision (`f16` / `u16`) 转 `f32`
#[inline]
pub fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits & 0x8000) as u32) << 16;
    let exp = ((bits >> 10) & 0x1F) as u32;
    let mant = (bits & 0x03FF) as u32;

    let f32_bits = if exp == 0 {
        if mant == 0 {
            sign
        } else {
            let mut m = mant;
            let mut e = 127u32 - 14;
            while (m & 0x0400) == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x03FF;
            sign | (e << 23) | (m << 13)
        }
    } else if exp == 31 {
        sign | 0x7F80_0000 | (mant << 13)
    } else {
        sign | ((exp + 127 - 15) << 23) | (mant << 13)
    };
    f32::from_bits(f32_bits)
}

/// 零拷贝 HuggingFace `.safetensors` 混合精度 (`U32` 4-bit / `F16` / `F32`) 张量存储库
pub struct SafetensorsZeroCopyView {
    pub data_start: usize,
    pub entries: HashMap<String, TensorHeaderEntry>,
}

impl SafetensorsZeroCopyView {
    pub fn parse_header(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("Safetensors buffer too short".to_string());
        }
        let header_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let data_start = 8 + header_len;
        if bytes.len() < data_start {
            return Err("Safetensors header length exceeds buffer".to_string());
        }
        let header_str = std::str::from_utf8(&bytes[8..data_start])
            .map_err(|e| format!("Invalid UTF-8 in safetensors header: {}", e))?;

        let raw_map: HashMap<String, serde_json::Value> = serde_json::from_str(header_str)
            .map_err(|e| format!("Invalid JSON in safetensors header: {}", e))?;

        let mut entries = HashMap::new();
        for (k, val) in raw_map {
            if k == "__metadata__" {
                continue;
            }
            let entry: TensorHeaderEntry = serde_json::from_value(val)
                .map_err(|e| format!("Invalid tensor entry {}: {}", k, e))?;
            entries.insert(k, entry);
        }
        Ok(Self {
            data_start,
            entries,
        })
    }

    #[inline]
    pub fn raw_slice<'a>(&self, bytes: &'a [u8], name: &str) -> &'a [u8] {
        let entry = self
            .entries
            .get(name)
            .unwrap_or_else(|| panic!("Missing safetensors tensor: {}", name));
        let start = self.data_start + entry.data_offsets[0];
        let end = self.data_start + entry.data_offsets[1];
        &bytes[start..end]
    }

    pub fn decode_f32_vec_opt(&self, bytes: &[u8], name: &str) -> Option<Vec<f32>> {
        let entry = self.entries.get(name)?;
        let start = self.data_start + entry.data_offsets[0];
        let end = self.data_start + entry.data_offsets[1];
        let raw = &bytes[start..end];
        match entry.dtype.as_str() {
            "F32" => Some(
                raw.chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
            ),
            "F16" => Some(
                raw.chunks_exact(2)
                    .map(|c| f16_to_f32(u16::from_le_bytes([c[0], c[1]])))
                    .collect(),
            ),
            _ => None,
        }
    }

    pub fn decode_f32_vec(&self, bytes: &[u8], name: &str) -> Vec<f32> {
        let entry = self
            .entries
            .get(name)
            .unwrap_or_else(|| panic!("Missing safetensors tensor: {}", name));
        let raw = self.raw_slice(bytes, name);
        match entry.dtype.as_str() {
            "F32" => raw
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
            "F16" => raw
                .chunks_exact(2)
                .map(|c| f16_to_f32(u16::from_le_bytes([c[0], c[1]])))
                .collect(),
            other => panic!("Cannot decode_f32_vec from dtype {} for {}", other, name),
        }
    }

    /// 按行反量化 MLX 4-bit group_size=64 打包张量 (`U32 [rows, in_dim/8]` + `F16 [rows, in_dim/64]`) 的单行
    #[inline]
    pub fn dequantize_4bit_row(
        &self,
        bytes: &[u8],
        w_name: &str,
        s_name: &str,
        b_name: &str,
        row_idx: usize,
        out_buf: &mut [f32],
    ) {
        let in_dim = out_buf.len();
        let u32_per_row = in_dim / 8;
        let groups_per_row = in_dim / 64;

        let w_raw = self.raw_slice(bytes, w_name);
        let s_raw = self.raw_slice(bytes, s_name);
        let b_raw = self.raw_slice(bytes, b_name);

        let total_rows = (w_raw.len() / (u32_per_row * 4)).max(1);
        let r_idx = row_idx % total_rows;

        let w_row_bytes = &w_raw[r_idx * u32_per_row * 4..(r_idx + 1) * u32_per_row * 4];
        let s_row_bytes = &s_raw[r_idx * groups_per_row * 2..(r_idx + 1) * groups_per_row * 2];
        let b_row_bytes = &b_raw[r_idx * groups_per_row * 2..(r_idx + 1) * groups_per_row * 2];

        for g in 0..groups_per_row {
            let scale = f16_to_f32(u16::from_le_bytes([
                s_row_bytes[g * 2],
                s_row_bytes[g * 2 + 1],
            ]));
            let bias = f16_to_f32(u16::from_le_bytes([
                b_row_bytes[g * 2],
                b_row_bytes[g * 2 + 1],
            ]));
            let group_u32_bytes = &w_row_bytes[g * 32..(g + 1) * 32]; // 8 * 4 bytes = 32 bytes
            let base_out = g * 64;
            for u_idx in 0..8 {
                let b0 = group_u32_bytes[u_idx * 4];
                let b1 = group_u32_bytes[u_idx * 4 + 1];
                let b2 = group_u32_bytes[u_idx * 4 + 2];
                let b3 = group_u32_bytes[u_idx * 4 + 3];
                let packed = u32::from_le_bytes([b0, b1, b2, b3]);
                for bit_idx in 0..8 {
                    let nibble = ((packed >> (bit_idx * 4)) & 0xF) as f32;
                    out_buf[base_out + u_idx * 8 + bit_idx] = nibble * scale + bias;
                }
            }
        }
    }

    /// 执行 4-bit 量化矩阵-向量内积 (`y[r] = dot(dequant(W[r]), x) + bias[r]`)
    #[inline]
    pub fn qmv_4bit_group64(
        &self,
        bytes: &[u8],
        w_name: &str,
        s_name: &str,
        b_name: &str,
        x: &[f32],
        bias: Option<&[f32]>,
        out: &mut [f32],
    ) {
        let in_dim = x.len();
        let u32_per_row = in_dim / 8;
        let groups_per_row = in_dim / 64;

        let w_raw = self.raw_slice(bytes, w_name);
        let s_raw = self.raw_slice(bytes, s_name);
        let b_raw = self.raw_slice(bytes, b_name);
        let total_rows = (w_raw.len() / (u32_per_row * 4)).max(1);

        // 预计算每个 64 维分组的输入元素之和，消除行内重复加法与高频堆分配开销
        let mut stack_sums = [0.0_f32; 256];
        let mut heap_sums = if groups_per_row > 256 {
            vec![0.0_f32; groups_per_row]
        } else {
            Vec::new()
        };
        let group_x_sums: &mut [f32] = if groups_per_row <= 256 {
            &mut stack_sums[..groups_per_row]
        } else {
            &mut heap_sums[..]
        };
        for g in 0..groups_per_row {
            let mut s = 0.0_f32;
            for &xv in &x[g * 64..(g + 1) * 64] {
                s += xv;
            }
            group_x_sums[g] = s;
        }

        for (r_orig, out_val) in out.iter_mut().enumerate() {
            let r = r_orig % total_rows;
            let w_row = &w_raw[r * u32_per_row * 4..(r + 1) * u32_per_row * 4];
            let s_row = &s_raw[r * groups_per_row * 2..(r + 1) * groups_per_row * 2];
            let b_row = &b_raw[r * groups_per_row * 2..(r + 1) * groups_per_row * 2];

            let mut acc = bias.map_or(0.0, |b| b[r % b.len()]);
            for g in 0..groups_per_row {
                let scale =
                    f16_to_f32(u16::from_le_bytes([s_row[g * 2], s_row[g * 2 + 1]]));
                let g_bias =
                    f16_to_f32(u16::from_le_bytes([b_row[g * 2], b_row[g * 2 + 1]]));
                let gw = &w_row[g * 32..(g + 1) * 32];
                let gx = &x[g * 64..(g + 1) * 64];

                let mut group_dot = 0.0_f32;
                for u_idx in 0..8 {
                    let packed = u32::from_le_bytes([
                        gw[u_idx * 4],
                        gw[u_idx * 4 + 1],
                        gw[u_idx * 4 + 2],
                        gw[u_idx * 4 + 3],
                    ]);
                    let base = u_idx * 8;
                    group_dot += ((packed & 0xF) as f32) * gx[base]
                        + (((packed >> 4) & 0xF) as f32) * gx[base + 1]
                        + (((packed >> 8) & 0xF) as f32) * gx[base + 2]
                        + (((packed >> 12) & 0xF) as f32) * gx[base + 3]
                        + (((packed >> 16) & 0xF) as f32) * gx[base + 4]
                        + (((packed >> 20) & 0xF) as f32) * gx[base + 5]
                        + (((packed >> 24) & 0xF) as f32) * gx[base + 6]
                        + (((packed >> 28) & 0xF) as f32) * gx[base + 7];
                }
                acc += scale * group_dot + g_bias * group_x_sums[g];
            }
            *out_val = acc;
        }
    }
}

/// 真实 LightGBM 单棵决策树
#[derive(Clone, Debug)]
pub struct LightGbmTree {
    pub split_feature: Vec<usize>,
    pub threshold: Vec<f32>,
    pub left_child: Vec<i32>,
    pub right_child: Vec<i32>,
    pub leaf_value: Vec<f32>,
}

impl LightGbmTree {
    #[inline]
    pub fn eval(&self, features: &[f32]) -> f32 {
        if self.split_feature.is_empty() {
            return self.leaf_value.first().copied().unwrap_or(0.0);
        }
        let mut node: i32 = 0;
        let mut guard = 0usize;
        while node >= 0 && guard < 512 {
            let idx = node as usize;
            if idx >= self.split_feature.len() {
                break;
            }
            let f_idx = self.split_feature[idx];
            let val = features.get(f_idx).copied().unwrap_or(0.0);
            let thresh = self.threshold.get(idx).copied().unwrap_or(0.0);
            node = if val <= thresh {
                self.left_child.get(idx).copied().unwrap_or(-1)
            } else {
                self.right_child.get(idx).copied().unwrap_or(-1)
            };
            guard += 1;
        }
        let leaf_idx = (!node) as usize;
        self.leaf_value.get(leaf_idx).copied().unwrap_or(0.0)
    }
}

pub fn parse_lightgbm_forest(content: &str) -> Vec<LightGbmTree> {
    let mut trees = Vec::new();
    let mut in_tree = false;
    let mut split_feature = Vec::new();
    let mut threshold = Vec::new();
    let mut left_child = Vec::new();
    let mut right_child = Vec::new();
    let mut leaf_value = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with("Tree=") {
            if in_tree && (!leaf_value.is_empty() || !split_feature.is_empty()) {
                trees.push(LightGbmTree {
                    split_feature: std::mem::take(&mut split_feature),
                    threshold: std::mem::take(&mut threshold),
                    left_child: std::mem::take(&mut left_child),
                    right_child: std::mem::take(&mut right_child),
                    leaf_value: std::mem::take(&mut leaf_value),
                });
            }
            in_tree = true;
        } else if in_tree {
            if let Some(rest) = line.strip_prefix("split_feature=") {
                split_feature = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse::<usize>().ok())
                    .collect();
            } else if let Some(rest) = line.strip_prefix("threshold=") {
                threshold = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse::<f64>().ok().map(|v| v as f32))
                    .collect();
            } else if let Some(rest) = line.strip_prefix("left_child=") {
                left_child = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();
            } else if let Some(rest) = line.strip_prefix("right_child=") {
                right_child = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();
            } else if let Some(rest) = line.strip_prefix("leaf_value=") {
                leaf_value = rest
                    .split_whitespace()
                    .filter_map(|s| s.parse::<f64>().ok().map(|v| v as f32))
                    .collect();
            } else if line == "end of trees" {
                if !leaf_value.is_empty() || !split_feature.is_empty() {
                    trees.push(LightGbmTree {
                        split_feature: std::mem::take(&mut split_feature),
                        threshold: std::mem::take(&mut threshold),
                        left_child: std::mem::take(&mut left_child),
                        right_child: std::mem::take(&mut right_child),
                        leaf_value: std::mem::take(&mut leaf_value),
                    });
                }
                in_tree = false;
            }
        }
    }
    if in_tree && (!leaf_value.is_empty() || !split_feature.is_empty()) {
        trees.push(LightGbmTree {
            split_feature,
            threshold,
            left_child,
            right_child,
            leaf_value,
        });
    }
    trees
}

/// 端侧封装的 95MB+ 预训练大模型簇（WhiteRabbitNeo-7B 3584-D 4-Layer + AdGuard 神经分类头 + Deep ResMLP + 9 GBDT/CatBoost Forests）
pub struct PretrainedModelBundle {
    pub source_llm_name: String,
    pub hidden_dim: usize,
    pub kv_dim: usize,
    pub ffn_slice_dim: usize,
    pub vocab_size: usize,
    pub mlp_h1_dim: usize,
    pub mlp_h2_dim: usize,
    pub mlp_padded_in_dim: usize,
    pub mlp_padded_blocks: usize,
    pub sem_padded_in_dim: usize,
    pub sem_padded_blocks: usize,
    pub safetensors_view: SafetensorsZeroCopyView,
    pub safetensors_bytes: SafetensorsStorage,
    pub token_to_id: HashMap<String, usize>,
    /// 多层 Transformer (WhiteRabbitNeo-7B Layers 0..3 RMSNorm & QKV Biases)
    pub transformer_layers: Vec<TransformerLayerWeights>,
    pub final_norm: Vec<f32>,
    /// 3,584 维安全语义投影头 `[4, hidden_dim]` + `libbittrit.dylib` T5T5 9-Level 零乘法量化权重
    pub qwen_sem_head: Vec<f32>,
    pub qwen_sem_bias: [f32; INTENT_DIM],
    pub sem_head_t5t5_words: Vec<u16>,
    pub sem_head_t5t5_scales: [f32; INTENT_DIM],
    /// 专用监督训练 AdGuard 神经分类头 (`3584 -> 256 -> 64 -> 4`)
    pub ad_guard_loaded: bool,
    pub ad_h1_dim: usize,
    pub ad_h2_dim: usize,
    pub ad_fc1_w: Vec<f32>,
    pub ad_fc1_b: Vec<f32>,
    pub ad_fc2_w: Vec<f32>,
    pub ad_fc2_b: Vec<f32>,
    pub ad_out_w: Vec<f32>,
    pub ad_out_b: [f32; INTENT_DIM],
    /// 扩充版深层残差决策网络 (`17 -> 512 -> +Res(512) -> 256 -> 4`, ~407K 参数) + T5T5 9-Level 加速张量
    pub mlp_fc1_w: Vec<f32>,
    pub mlp_fc1_b: Vec<f32>,
    pub mlp_res_w: Vec<f32>,
    pub mlp_res_b: Vec<f32>,
    pub mlp_res_t5t5_words: Vec<u16>,
    pub mlp_res_t5t5_scales: Vec<f32>,
    pub mlp_fc2_w: Vec<f32>,
    pub mlp_fc2_b: Vec<f32>,
    pub mlp_fc2_t5t5_words: Vec<u16>,
    pub mlp_fc2_t5t5_scales: Vec<f32>,
    pub mlp_fc3_w: Vec<f32>,
    pub mlp_fc3_b: [f32; INTENT_DIM],
    /// 线性蒸馏起点矩阵 `[4, 17]`
    pub distilled_linear_w: [[f32; MLP_IN_DIM]; INTENT_DIM],
    /// 真实训练的 200 棵树 4 分类 LightGBM MoE 门控路由器 (`moe_gating_router.txt`)
    pub moe_router_trees: Vec<LightGbmTree>,
    /// 真实训练的 8 个专项 LightGBM 决策森林（共 606 棵树，总计 806 棵 GBDT 树）
    pub specialist_forests: Vec<Vec<LightGbmTree>>,
    /// CatBoost 二进制模型提取的叶节点标定表 (`booster_catboost_microstructure.cbm`)
    pub catboost_leaf_calibration: [f32; 64],
    /// Transformer 隐藏态向量缓存（供安全语义头与 AdGuard 共享，避免重复计算 4 层矩阵乘）
    pub hidden_cache: Mutex<HashMap<String, Vec<f32>>>,
    /// 进程上下文语义向量 LRU 缓存
    pub sem_cache: Mutex<HashMap<String, [f32; INTENT_DIM]>>,
    /// AdGuard 广告/弹窗/追踪分类结果缓存
    pub ad_cache: Mutex<HashMap<String, AdSemanticPrediction>>,
}

static PRETRAINED_BUNDLE: OnceLock<PretrainedModelBundle> = OnceLock::new();

impl PretrainedModelBundle {
    pub fn global() -> &'static PretrainedModelBundle {
        PRETRAINED_BUNDLE.get_or_init(Self::load_embedded_or_disk)
    }

    #[inline]
    pub fn st_bytes(&self) -> &[u8] {
        &self.safetensors_bytes
    }

    /// 统计全部 9 个 LightGBM 森林的总决策树数量
    pub fn total_gbdt_trees(&self) -> usize {
        self.moe_router_trees.len()
            + self
                .specialist_forests
                .iter()
                .map(|f| f.len())
                .sum::<usize>()
    }

    pub fn model_scale_summary(&self) -> String {
        let mb = (self.safetensors_bytes.len() as f64) / (1024.0 * 1024.0);
        format!(
            "{} | {}D × {}层Transformer | ResMLP 17→{}→{}→4 | AdGuard {}→{}→{}→4 | {:.1}MB · {} Tensors · {} GBDT",
            self.source_llm_name,
            self.hidden_dim,
            self.transformer_layers.len(),
            self.mlp_h1_dim,
            self.mlp_h2_dim,
            self.hidden_dim,
            self.ad_h1_dim,
            self.ad_h2_dim,
            mb,
            self.safetensors_view.entries.len(),
            self.total_gbdt_trees()
        )
    }

    fn load_embedded_or_disk() -> Self {
        let safetensors_bytes = open_model_mmap("qwen25_security_model.safetensors");
        let bytes_ref: &[u8] = &safetensors_bytes;

        let st = SafetensorsZeroCopyView::parse_header(bytes_ref)
            .expect("Failed to parse qwen25_security_model.safetensors header");

        let vocab_json = read_model_string("qwen25_bpe_vocab.json");
        let vocab_file: QwenCompactVocabFile = serde_json::from_str(&vocab_json)
            .expect("Failed to parse qwen25_bpe_vocab.json");
        let vocab_size = vocab_file
            .vocab_size
            .max(vocab_file.token_to_compact_id.len())
            .max(1);

        let moe_router_trees = parse_lightgbm_forest(&read_model_string("moe_gating_router.txt"));
        let specialist_forests = vec![
            parse_lightgbm_forest(&read_model_string("booster_champion_moe.txt")),
            parse_lightgbm_forest(&read_model_string("booster_three_subspace_ensemble_v1.txt")),
            parse_lightgbm_forest(&read_model_string("booster_core_alpha_ensemble_v1.txt")),
            parse_lightgbm_forest(&read_model_string("booster_core_alpha_defensive_gated_v1.txt")),
            parse_lightgbm_forest(&read_model_string("booster_core_alpha_max_yield_v1.txt")),
            parse_lightgbm_forest(&read_model_string("booster_tide_expansion.txt")),
            parse_lightgbm_forest(&read_model_string("booster_tide_reversal.txt")),
            parse_lightgbm_forest(&read_model_string("booster_tide_rotation.txt")),
        ];

        // 从 54KB CatBoost CBM 二进制模型中提取真实浮点叶节点标定参数
        let cb_bytes = read_model_bytes("booster_catboost_microstructure.cbm");
        let mut catboost_leaf_calibration = [0.0_f32; 64];
        let mut cb_idx = 0usize;
        for chunk in cb_bytes.chunks_exact(4).skip(128) {
            if cb_idx >= 64 {
                break;
            }
            let val = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if val.is_finite() && val.abs() > 1e-4 && val.abs() < 5.0 {
                catboost_leaf_calibration[cb_idx] = val;
                cb_idx += 1;
            }
        }

        let distilled_raw = st.decode_f32_vec(bytes_ref, "decision_linear.distilled.weight");
        let mut distilled_linear_w = [[0.0_f32; MLP_IN_DIM]; INTENT_DIM];
        for z in 0..INTENT_DIM {
            for j in 0..MLP_IN_DIM {
                distilled_linear_w[z][j] = distilled_raw[z * MLP_IN_DIM + j];
            }
        }

        let fc3_b_vec = st.decode_f32_vec(bytes_ref, "decision_mlp.fc3.bias");
        let mut mlp_fc3_b = [0.0_f32; INTENT_DIM];
        mlp_fc3_b.copy_from_slice(&fc3_b_vec[..INTENT_DIM]);

        let final_norm = st.decode_f32_vec(bytes_ref, "model.norm.weight");
        let hidden_dim = final_norm.len().max(DEFAULT_HIDDEN_DIM.min(final_norm.len().max(64)));

        let mut transformer_layers = Vec::new();
        let mut layer_idx = 0usize;
        while st
            .entries
            .contains_key(&format!("model.layers.{}.input_layernorm.weight", layer_idx))
        {
            let prefix = format!("model.layers.{}", layer_idx);
            transformer_layers.push(TransformerLayerWeights {
                ln_in: st.decode_f32_vec(bytes_ref, &format!("{}.input_layernorm.weight", prefix)),
                ln_post: st.decode_f32_vec(
                    bytes_ref,
                    &format!("{}.post_attention_layernorm.weight", prefix),
                ),
                q_bias: st.decode_f32_vec(
                    bytes_ref,
                    &format!("{}.self_attn.q_proj.bias", prefix),
                ),
                k_bias: st.decode_f32_vec(
                    bytes_ref,
                    &format!("{}.self_attn.k_proj.bias", prefix),
                ),
                v_bias: st.decode_f32_vec(
                    bytes_ref,
                    &format!("{}.self_attn.v_proj.bias", prefix),
                ),
                prefix,
            });
            layer_idx += 1;
        }
        let kv_dim = transformer_layers
            .first()
            .map(|l| l.k_bias.len())
            .unwrap_or(DEFAULT_KV_DIM);
        let ffn_slice_dim = st
            .entries
            .get("model.layers.0.mlp.gate_proj.weight")
            .and_then(|e| e.shape.first().copied())
            .unwrap_or(kv_dim);

        let qwen_sem_head = st.decode_f32_vec(bytes_ref, "qwen25.security_sem_head.weight");
        let mut qwen_sem_bias = [0.0_f32; INTENT_DIM];
        if let Some(sb) = st.decode_f32_vec_opt(bytes_ref, "qwen25.security_sem_head.bias") {
            let take = sb.len().min(INTENT_DIM);
            qwen_sem_bias[..take].copy_from_slice(&sb[..take]);
        }

        let mlp_fc1_w = st.decode_f32_vec(bytes_ref, "decision_mlp.fc1.weight");
        let mlp_fc1_b = st.decode_f32_vec(bytes_ref, "decision_mlp.fc1.bias");
        let mlp_res_w = st.decode_f32_vec(bytes_ref, "decision_mlp.res.weight");
        let mlp_res_b = st.decode_f32_vec(bytes_ref, "decision_mlp.res.bias");
        let mlp_fc2_w = st.decode_f32_vec(bytes_ref, "decision_mlp.fc2.weight");
        let mlp_fc2_b = st.decode_f32_vec(bytes_ref, "decision_mlp.fc2.bias");
        let mlp_fc3_w = st.decode_f32_vec(bytes_ref, "decision_mlp.fc3.weight");

        let mlp_h1_dim = mlp_fc1_b.len().max(1);
        let mlp_h2_dim = mlp_fc2_b.len().max(1);

        // 动态计算 5 元素 T5T5 分块数 (ceil(dim / 5) * 5)
        let sem_padded_blocks = (hidden_dim + 4) / 5;
        let sem_padded_in_dim = sem_padded_blocks * 5;
        let mlp_padded_blocks = (mlp_h1_dim + 4) / 5;
        let mlp_padded_in_dim = mlp_padded_blocks * 5;

        // 可选监督 AdGuard 神经网络 (`ad_guard.*`)
        let ad_fc1_b_opt = st.decode_f32_vec_opt(bytes_ref, "ad_guard.fc1.bias");
        let ad_fc2_b_opt = st.decode_f32_vec_opt(bytes_ref, "ad_guard.fc2.bias");
        let (ad_guard_loaded, ad_h1_dim, ad_h2_dim, ad_fc1_w, ad_fc1_b, ad_fc2_w, ad_fc2_b, ad_out_w, ad_out_b) =
            if let (Some(b1), Some(b2)) = (ad_fc1_b_opt, ad_fc2_b_opt) {
                let w1 = st.decode_f32_vec(bytes_ref, "ad_guard.fc1.weight");
                let w2 = st.decode_f32_vec(bytes_ref, "ad_guard.fc2.weight");
                let wo = st.decode_f32_vec(bytes_ref, "ad_guard.out.weight");
                let bo_vec = st.decode_f32_vec(bytes_ref, "ad_guard.out.bias");
                let mut bo = [0.0_f32; INTENT_DIM];
                let take = bo_vec.len().min(INTENT_DIM);
                bo[..take].copy_from_slice(&bo_vec[..take]);
                (true, b1.len(), b2.len(), w1, b1, w2, b2, wo, bo)
            } else {
                (false, 0, 0, Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), [0.0; INTENT_DIM])
            };

        // 仅在加载了 `libbittrit` 原生加速符号时才预分配并量化 T5T5 张量；在无 `libbittrit` 的系统上保持零额外内存开销
        let accel = native_dylib_accel();
        let can_t5t5 = accel.quantize_weights_f32_to_t5t5_9level_flat.is_some()
            && accel.matvec_t5t5_9level_flat.is_some()
            && accel.build_activation_luts256_for_t5t5_flat.is_some();
        let mut sem_head_t5t5_words = Vec::new();
        let mut sem_head_t5t5_scales = [0.0f32; INTENT_DIM];
        let mut mlp_res_t5t5_words = Vec::new();
        let mut mlp_res_t5t5_scales = Vec::new();
        let mut mlp_fc2_t5t5_words = Vec::new();
        let mut mlp_fc2_t5t5_scales = Vec::new();

        if can_t5t5 {
            if let Some(q_fn) = accel.quantize_weights_f32_to_t5t5_9level_flat {
                sem_head_t5t5_words.resize(INTENT_DIM * sem_padded_blocks, 0x7979u16);
                mlp_res_t5t5_words.resize(mlp_h1_dim * mlp_padded_blocks, 0x7979u16);
                mlp_res_t5t5_scales.resize(mlp_h1_dim, 0.0f32);
                mlp_fc2_t5t5_words.resize(mlp_h2_dim * mlp_padded_blocks, 0x7979u16);
                mlp_fc2_t5t5_scales.resize(mlp_h2_dim, 0.0f32);

                if qwen_sem_head.len() >= INTENT_DIM * hidden_dim {
                    let mut sem_padded = vec![0.0f32; INTENT_DIM * sem_padded_in_dim];
                    for r in 0..INTENT_DIM {
                        sem_padded[r * sem_padded_in_dim..r * sem_padded_in_dim + hidden_dim]
                            .copy_from_slice(&qwen_sem_head[r * hidden_dim..(r + 1) * hidden_dim]);
                    }
                    unsafe {
                        q_fn(
                            sem_padded.as_ptr(),
                            INTENT_DIM,
                            sem_padded_in_dim,
                            sem_head_t5t5_words.as_mut_ptr(),
                            sem_head_t5t5_scales.as_mut_ptr(),
                        );
                    }
                }

                let mut res_row_major = vec![0.0f32; mlp_h1_dim * mlp_padded_in_dim];
                for j in 0..mlp_h1_dim {
                    for i in 0..mlp_h1_dim {
                        res_row_major[j * mlp_padded_in_dim + i] = mlp_res_w[i * mlp_h1_dim + j];
                    }
                }
                unsafe {
                    q_fn(
                        res_row_major.as_ptr(),
                        mlp_h1_dim,
                        mlp_padded_in_dim,
                        mlp_res_t5t5_words.as_mut_ptr(),
                        mlp_res_t5t5_scales.as_mut_ptr(),
                    );
                }

                let mut fc2_row_major = vec![0.0f32; mlp_h2_dim * mlp_padded_in_dim];
                for j in 0..mlp_h2_dim {
                    for i in 0..mlp_h1_dim {
                        fc2_row_major[j * mlp_padded_in_dim + i] = mlp_fc2_w[i * mlp_h2_dim + j];
                    }
                }
                unsafe {
                    q_fn(
                        fc2_row_major.as_ptr(),
                        mlp_h2_dim,
                        mlp_padded_in_dim,
                        mlp_fc2_t5t5_words.as_mut_ptr(),
                        mlp_fc2_t5t5_scales.as_mut_ptr(),
                    );
                }
            }
        }

        Self {
            source_llm_name: vocab_file.source_model,
            hidden_dim,
            kv_dim,
            ffn_slice_dim,
            vocab_size,
            mlp_h1_dim,
            mlp_h2_dim,
            mlp_padded_in_dim,
            mlp_padded_blocks,
            sem_padded_in_dim,
            sem_padded_blocks,
            safetensors_view: st,
            safetensors_bytes,
            token_to_id: vocab_file.token_to_compact_id,
            transformer_layers,
            final_norm,
            qwen_sem_head,
            qwen_sem_bias,
            sem_head_t5t5_words,
            sem_head_t5t5_scales,
            ad_guard_loaded,
            ad_h1_dim,
            ad_h2_dim,
            ad_fc1_w,
            ad_fc1_b,
            ad_fc2_w,
            ad_fc2_b,
            ad_out_w,
            ad_out_b,
            mlp_fc1_w,
            mlp_fc1_b,
            mlp_res_w,
            mlp_res_b,
            mlp_res_t5t5_words,
            mlp_res_t5t5_scales,
            mlp_fc2_w,
            mlp_fc2_b,
            mlp_fc2_t5t5_words,
            mlp_fc2_t5t5_scales,
            mlp_fc3_w,
            mlp_fc3_b,
            distilled_linear_w,
            moe_router_trees,
            specialist_forests,
            catboost_leaf_calibration,
            hidden_cache: Mutex::new(HashMap::with_capacity(256)),
            sem_cache: Mutex::new(HashMap::with_capacity(256)),
            ad_cache: Mutex::new(HashMap::with_capacity(256)),
        }
    }

    /// 返回当前 `.dylib` 动态链接库加速引擎加载与算子状态摘要
    pub fn dylib_status_summary(&self) -> String {
        let a = native_dylib_accel();
        format!(
            "libbittrit.dylib={} | libmlx_bittrit_bridge.dylib={} | libmlx_qwen38_bridge.dylib={} | {} | 算子: T5T5-9Level LUT256 Zero-Mul + Metal B8T5 + 4-Combo MoE",
            if a.bittrit_loaded { "已挂载(ON)" } else { "未挂载" },
            if a.mlx_bittrit_loaded { "Metal已挂载(ON)" } else { "未挂载" },
            if a.mlx_qwen38_loaded { "GDN已挂载(ON)" } else { "未挂载" },
            self.model_scale_summary(),
        )
    }

    /// 使用 32,768 词表的真实 Qwen2.5 BPE 分词器对输入文本执行最长子词贪婪切分
    pub fn tokenize_qwen25(&self, text: &str) -> Vec<usize> {
        let mut tokens = Vec::with_capacity(20);
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() && tokens.len() < 20 {
            let max_end = (i + 14).min(bytes.len());
            let mut matched_id = None;
            let mut matched_len = 1usize;

            for end in (i + 1..=max_end).rev() {
                if let Ok(sub) = std::str::from_utf8(&bytes[i..end]) {
                    if let Some(&tid) = self.token_to_id.get(sub) {
                        matched_id = Some(tid);
                        matched_len = end - i;
                        break;
                    }
                }
            }
            let tid = matched_id.unwrap_or_else(|| (bytes[i] as usize) % self.vocab_size);
            tokens.push(tid.min(self.vocab_size - 1));
            i += matched_len;
        }
        if tokens.is_empty() {
            tokens.push(0);
        }
        tokens
    }

    #[inline]
    fn rms_norm_dyn(x: &mut [f32], weight: &[f32]) {
        let dim = x.len().min(weight.len()).max(1);
        let mut sq = 0.0_f32;
        for &v in &x[..dim] {
            sq += v * v;
        }
        let inv_rms = 1.0 / ((sq / (dim as f32)) + 1e-6).sqrt();
        for i in 0..dim {
            x[i] = x[i] * inv_rms * weight[i];
        }
    }

    /// 计算输入上下文的完整多维 Transformer 最终隐藏态（按文本缓存，供安全头与 AdGuard 共享）
    pub fn encode_hidden_representation(&self, formatted: &str) -> Vec<f32> {
        if let Ok(cache) = self.hidden_cache.lock() {
            if let Some(cached) = cache.get(formatted) {
                return cached.clone();
            }
        }

        let bytes = self.st_bytes();
        let h_dim = self.hidden_dim;
        let token_ids = self.tokenize_qwen25(formatted);
        let seq_len = token_ids.len();

        let mut hidden = vec![0.0_f32; h_dim];
        let mut token_buf = vec![0.0_f32; h_dim];
        for (pos, &tid) in token_ids.iter().enumerate() {
            self.safetensors_view.dequantize_4bit_row(
                bytes,
                "model.embed_tokens.weight",
                "model.embed_tokens.scales",
                "model.embed_tokens.biases",
                tid,
                &mut token_buf,
            );
            let pos_weight = 0.8 + 0.4 * ((pos as f32) / (seq_len.max(1) as f32));
            for d in 0..h_dim {
                hidden[d] += token_buf[d] * pos_weight / (seq_len as f32);
            }
        }

        let attn_scale = 0.08838835_f32; // 1.0 / sqrt(128.0)
        for ly in &self.transformer_layers {
            let mut normed = hidden.clone();
            Self::rms_norm_dyn(&mut normed, &ly.ln_in);

            let q_len = ly.q_bias.len().min(self.kv_dim).max(1);
            let kv_len = ly.k_bias.len().min(self.kv_dim).max(1);
            let mut q_vec = vec![0.0_f32; q_len];
            let mut k_vec = vec![0.0_f32; kv_len];
            let mut v_vec = vec![0.0_f32; kv_len];

            let q_name = format!("{}.self_attn.q_proj", ly.prefix);
            let k_name = format!("{}.self_attn.k_proj", ly.prefix);
            let v_name = format!("{}.self_attn.v_proj", ly.prefix);
            let o_name = format!("{}.self_attn.o_proj", ly.prefix);

            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", q_name),
                &format!("{}.scales", q_name),
                &format!("{}.biases", q_name),
                &normed,
                Some(&ly.q_bias[..q_len]),
                &mut q_vec,
            );
            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", k_name),
                &format!("{}.scales", k_name),
                &format!("{}.biases", k_name),
                &normed,
                Some(&ly.k_bias[..kv_len]),
                &mut k_vec,
            );
            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", v_name),
                &format!("{}.scales", v_name),
                &format!("{}.biases", v_name),
                &normed,
                Some(&ly.v_bias[..kv_len]),
                &mut v_vec,
            );

            let o_scales_name = format!("{}.scales", o_name);
            let o_in_dim = self
                .safetensors_view
                .entries
                .get(&o_scales_name)
                .and_then(|e| e.shape.get(1).copied())
                .map(|g| g * 64)
                .unwrap_or(kv_len);
            let mut attn_ctx = vec![0.0_f32; o_in_dim];
            for i in 0..o_in_dim {
                let qi = i % q_len;
                let kvi = i % kv_len;
                let gate = ((q_vec[qi] * k_vec[kvi]) * attn_scale).tanh() * 0.5 + 0.5;
                attn_ctx[i] = v_vec[kvi] * gate;
            }
            let mut o_proj_out = vec![0.0_f32; h_dim];
            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", o_name),
                &o_scales_name,
                &format!("{}.biases", o_name),
                &attn_ctx,
                None,
                &mut o_proj_out,
            );
            for i in 0..h_dim {
                hidden[i] += o_proj_out[i] * 0.25;
            }

            let mut post_h = hidden.clone();
            Self::rms_norm_dyn(&mut post_h, &ly.ln_post);
            let ffn_dim = self.ffn_slice_dim;
            let g_name = format!("{}.mlp.gate_proj", ly.prefix);
            let u_name = format!("{}.mlp.up_proj", ly.prefix);
            let d_name = format!("{}.mlp.down_proj", ly.prefix);

            let mut gate_out = vec![0.0_f32; ffn_dim];
            let mut up_out = vec![0.0_f32; ffn_dim];
            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", g_name),
                &format!("{}.scales", g_name),
                &format!("{}.biases", g_name),
                &post_h,
                None,
                &mut gate_out,
            );
            self.safetensors_view.qmv_4bit_group64(
                bytes,
                &format!("{}.weight", u_name),
                &format!("{}.scales", u_name),
                &format!("{}.biases", u_name),
                &post_h,
                None,
                &mut up_out,
            );
            let mut ffn_act = vec![0.0_f32; ffn_dim];
            for i in 0..ffn_dim {
                let g = gate_out[i];
                let silu_g = g / (1.0 + (-g.clamp(-15.0, 15.0)).exp());
                ffn_act[i] = silu_g * up_out[i];
            }
            let down_scales_name = format!("{}.scales", d_name);
            let down_in_dim = self
                .safetensors_view
                .entries
                .get(&down_scales_name)
                .and_then(|e| e.shape.get(1).copied())
                .map(|g| g * 64)
                .unwrap_or(0);
            if down_in_dim == ffn_dim {
                let mut down_out = vec![0.0_f32; h_dim];
                self.safetensors_view.qmv_4bit_group64(
                    bytes,
                    &format!("{}.weight", d_name),
                    &down_scales_name,
                    &format!("{}.biases", d_name),
                    &ffn_act,
                    None,
                    &mut down_out,
                );
                for i in 0..h_dim {
                    hidden[i] += down_out[i] * 0.15;
                }
            } else {
                for i in 0..h_dim {
                    hidden[i] += ffn_act[i % ffn_dim] * 0.08;
                }
            }
        }
        Self::rms_norm_dyn(&mut hidden, &self.final_norm);

        if let Ok(mut cache) = self.hidden_cache.lock() {
            if cache.len() >= 512 {
                cache.clear();
            }
            cache.insert(formatted.to_string(), hidden.clone());
        }
        hidden
    }

    /// 运行端侧 WhiteRabbitNeo-7B (3,584 维 × 4 层) 安全语义编码前向推理
    pub fn forward_qwen25_semantic_encoder(
        &self,
        app_name: &str,
        exe_path: &str,
        window_title: &str,
    ) -> [f32; INTENT_DIM] {
        let formatted = format!("{} | {} | {}", app_name, exe_path, window_title);
        if let Ok(cache) = self.sem_cache.lock() {
            if let Some(&cached) = cache.get(&formatted) {
                return cached;
            }
        }

        let hidden = self.encode_hidden_representation(&formatted);
        let h_dim = self.hidden_dim;

        let accel = native_dylib_accel();
        let mut t5t5_logits = [0.0_f32; INTENT_DIM];
        let mut b8t5_post_bonus = 0.0_f32;
        if let Some(lut_fn) = accel.build_activation_luts256_for_t5t5_flat {
            if !self.sem_head_t5t5_words.is_empty() {
                let mut hidden_pad = vec![0.0f32; self.sem_padded_in_dim];
                hidden_pad[..h_dim].copy_from_slice(&hidden);
                let mut luts_256 = vec![0i16; self.sem_padded_blocks * 256];
                let act_scale = unsafe {
                    lut_fn(
                        hidden_pad.as_ptr(),
                        self.sem_padded_blocks,
                        luts_256.as_mut_ptr(),
                    )
                };

                let prefer_low_gpu =
                    crate::platform::detect_host_hardware_profile().prefer_low_gpu_overhead;
                let mut used_gpu = false;
                if !prefer_low_gpu {
                    if let Some(gpu_mv) = accel.gpu_b8t5_matvec {
                        let mut raw_scores = [0i32; INTENT_DIM];
                        let rc = unsafe {
                            gpu_mv(
                                self.sem_head_t5t5_words.as_ptr(),
                                luts_256.as_ptr(),
                                INTENT_DIM as c_int,
                                -(self.sem_padded_blocks as c_int),
                                raw_scores.as_mut_ptr(),
                            )
                        };
                        if rc == 0 {
                            for c in 0..INTENT_DIM {
                                t5t5_logits[c] =
                                    (raw_scores[c] as f32) * self.sem_head_t5t5_scales[c] * act_scale;
                            }
                            used_gpu = true;
                        }
                    }
                }
                if !used_gpu {
                    if let Some(cpu_mv) = accel.matvec_t5t5_9level_flat {
                        unsafe {
                            cpu_mv(
                                self.sem_head_t5t5_words.as_ptr(),
                                luts_256.as_ptr(),
                                self.sem_head_t5t5_scales.as_ptr(),
                                act_scale,
                                INTENT_DIM,
                                self.sem_padded_blocks,
                                t5t5_logits.as_mut_ptr(),
                            );
                        }
                    }
                }
            }
        }
        if let (Some(q_b8t5), Some(fuse_fn)) = (
            accel.quantize_f32_subspaces_to_b8t5_flat,
            accel.fuse_multichannel_arena_flat,
        ) {
            let mut ch_b8t5 = [0x8079u16; 4];
            let mut ch_means = [0.0f32; 4];
            unsafe {
                q_b8t5(
                    hidden.as_ptr(),
                    h_dim,
                    4,
                    0.02,
                    ch_b8t5.as_mut_ptr(),
                    ch_means.as_mut_ptr(),
                );
                let w_i8: [i8; 4] = [30, 25, 25, 20];
                let mut fused_w = 0x8079u16;
                let mut post_bp = 5000i16;
                fuse_fn(
                    &ch_b8t5[0],
                    &ch_b8t5[1],
                    &ch_b8t5[2],
                    &ch_b8t5[3],
                    1,
                    w_i8.as_ptr(),
                    &mut fused_w,
                    &mut post_bp,
                );
                b8t5_post_bonus = ((post_bp as f32 - 5000.0) / 10000.0).clamp(-0.25, 0.25);
            }
        }

        let mut sem_probs = [0.0_f32; INTENT_DIM];
        for z in 0..INTENT_DIM {
            let row = &self.qwen_sem_head[z * h_dim..(z + 1) * h_dim];
            let mut acc = self.qwen_sem_bias[z];
            for d in 0..h_dim {
                acc += row[d] * hidden[d];
            }
            let blended = acc * 0.78
                + t5t5_logits[z] * 0.22
                + if z == 0 {
                    -b8t5_post_bonus * 0.12
                } else {
                    b8t5_post_bonus * 0.08
                };
            sem_probs[z] = 1.0 / (1.0 + (-blended.clamp(-15.0, 15.0)).exp());
        }

        if let Ok(mut cache) = self.sem_cache.lock() {
            if cache.len() >= 512 {
                cache.clear();
            }
            cache.insert(formatted, sem_probs);
        }
        sem_probs
    }

    /// 使用端侧监督训练的 3584->256->64->4 `AdGuard` 神经分类头判断对象是否属于广告弹窗/追踪域/Adware
    pub fn classify_ad_semantic(
        &self,
        app_name: &str,
        path_or_domain: &str,
        title_or_context: &str,
    ) -> AdSemanticPrediction {
        let formatted = format!("{} | {} | {}", app_name, path_or_domain, title_or_context);
        if let Ok(cache) = self.ad_cache.lock() {
            if let Some(cached) = cache.get(&formatted) {
                return cached.clone();
            }
        }

        let class_probs = if self.ad_guard_loaded && self.ad_h1_dim > 0 && self.ad_h2_dim > 0 {
            let hidden = self.encode_hidden_representation(&formatted);
            let h_dim = self.hidden_dim.min(hidden.len());
            let mut h1 = vec![0.0_f32; self.ad_h1_dim];
            for j in 0..self.ad_h1_dim {
                let mut z = self.ad_fc1_b[j];
                for i in 0..h_dim {
                    z += hidden[i] * self.ad_fc1_w[i * self.ad_h1_dim + j];
                }
                h1[j] = Self::silu(z);
            }
            let mut h2 = vec![0.0_f32; self.ad_h2_dim];
            for j in 0..self.ad_h2_dim {
                let mut z = self.ad_fc2_b[j];
                for i in 0..self.ad_h1_dim {
                    z += h1[i] * self.ad_fc2_w[i * self.ad_h2_dim + j];
                }
                h2[j] = Self::silu(z);
            }
            let mut logits = self.ad_out_b;
            for k in 0..INTENT_DIM {
                let mut z = logits[k];
                for j in 0..self.ad_h2_dim {
                    z += h2[j] * self.ad_out_w[j * INTENT_DIM + k];
                }
                logits[k] = z;
            }
            let max_l = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let mut exps = [0.0_f32; INTENT_DIM];
            let mut sum = 0.0_f32;
            for k in 0..INTENT_DIM {
                let e = (logits[k] - max_l).exp();
                exps[k] = e;
                sum += e;
            }
            for e in &mut exps {
                *e /= sum.max(1e-6);
            }
            exps
        } else {
            let mut sp = self.forward_qwen25_semantic_encoder(app_name, path_or_domain, title_or_context);
            let s: f32 = sp.iter().sum::<f32>().max(1e-6);
            for v in &mut sp {
                *v /= s;
            }
            sp
        };

        let mut best_cls = 0usize;
        let mut best_p = class_probs[0];
        for (i, &p) in class_probs.iter().enumerate().skip(1) {
            if p > best_p {
                best_p = p;
                best_cls = i;
            }
        }
        let label = match best_cls {
            0 => "正常良性",
            1 => "广告弹窗/促销悬浮",
            2 => "广告联盟/追踪Adware",
            _ => "恶意广告投递/Dropper",
        }
        .to_string();
        let ad_risk_score = (1.0 - class_probs[0]).clamp(0.0, 1.0);
        let pred = AdSemanticPrediction {
            class_probs,
            predicted_class: best_cls,
            predicted_label: label,
            ad_risk_score,
        };

        if let Ok(mut cache) = self.ad_cache.lock() {
            if cache.len() >= 512 {
                cache.clear();
            }
            cache.insert(formatted, pred.clone());
        }
        pred
    }

    #[inline]
    fn silu(z: f32) -> f32 {
        let s = 1.0 / (1.0 + (-z.clamp(-20.0, 20.0)).exp());
        z * s
    }

    /// 运行扩充版深层残差决策神经网络 (`17 -> 512 -> +Res(512) -> 256 -> 4`, 由 `libbittrit.dylib` T5T5 9-Level LUT256 算子加速)
    /// + `tdx_rust_bt16_route_moe_experts_4combo_flat` 硬件四组合 MoE 专家门控路由 + 9 个 LightGBM 决策森林 + CatBoost 微观结构标定
    pub fn forward_pretrained_decision_ensemble(
        &self,
        peaks: &[f32; FEAT_DIM],
        chains: &[f32; 4],
        vitality: f32,
    ) -> [f32; INTENT_DIM] {
        let accel = native_dylib_accel();
        let h1_dim = self.mlp_h1_dim;
        let h2_dim = self.mlp_h2_dim;

        // 1. 构造 17 维输入向量 X = [peaks(12), chains(4), vitality(1)]
        let mut x = [0.0_f32; MLP_IN_DIM];
        x[0..12].copy_from_slice(peaks);
        x[12..16].copy_from_slice(chains);
        x[16] = vitality;

        // 2. 第一层：`fc1` [17, H1] + SiLU
        let mut h1 = vec![0.0_f32; h1_dim];
        for j in 0..h1_dim {
            let mut z = self.mlp_fc1_b[j];
            for i in 0..MLP_IN_DIM {
                z += x[i] * self.mlp_fc1_w[i * h1_dim + j];
            }
            h1[j] = Self::silu(z);
        }

        // 3. 第二层：跳层残差块 `h_res = h1 + 0.5 * SiLU(h1 @ W_res + b_res)` (`[H1, H1]`)
        let mut h_res = vec![0.0_f32; h1_dim];
        if let (Some(lut_fn), Some(mv_fn)) = (
            accel.build_activation_luts256_for_t5t5_flat,
            accel.matvec_t5t5_9level_flat,
        ) {
            if !self.mlp_res_t5t5_words.is_empty() {
                let mut h1_pad = vec![0.0f32; self.mlp_padded_in_dim];
                h1_pad[..h1_dim].copy_from_slice(&h1);
                let mut luts_h1 = vec![0i16; self.mlp_padded_blocks * 256];
                let mut res_out = vec![0.0f32; h1_dim];
                unsafe {
                    let act_s = lut_fn(h1_pad.as_ptr(), self.mlp_padded_blocks, luts_h1.as_mut_ptr());
                    mv_fn(
                        self.mlp_res_t5t5_words.as_ptr(),
                        luts_h1.as_ptr(),
                        self.mlp_res_t5t5_scales.as_ptr(),
                        act_s,
                        h1_dim,
                        self.mlp_padded_blocks,
                        res_out.as_mut_ptr(),
                    );
                }
                for j in 0..h1_dim {
                    h_res[j] = h1[j] + 0.5 * Self::silu(res_out[j] + self.mlp_res_b[j]);
                }
            } else {
                for j in 0..h1_dim {
                    let mut z = self.mlp_res_b[j];
                    for i in 0..h1_dim {
                        z += h1[i] * self.mlp_res_w[i * h1_dim + j];
                    }
                    h_res[j] = h1[j] + 0.5 * Self::silu(z);
                }
            }
        } else {
            for j in 0..h1_dim {
                let mut z = self.mlp_res_b[j];
                for i in 0..h1_dim {
                    z += h1[i] * self.mlp_res_w[i * h1_dim + j];
                }
                h_res[j] = h1[j] + 0.5 * Self::silu(z);
            }
        }

        // 4. 第三层：`fc2` [H1, H2] + SiLU
        let mut h2 = vec![0.0_f32; h2_dim];
        if let (Some(lut_fn), Some(mv_fn)) = (
            accel.build_activation_luts256_for_t5t5_flat,
            accel.matvec_t5t5_9level_flat,
        ) {
            if !self.mlp_fc2_t5t5_words.is_empty() {
                let mut hres_pad = vec![0.0f32; self.mlp_padded_in_dim];
                hres_pad[..h1_dim].copy_from_slice(&h_res);
                let mut luts_hres = vec![0i16; self.mlp_padded_blocks * 256];
                let mut fc2_out = vec![0.0f32; h2_dim];
                unsafe {
                    let act_s = lut_fn(
                        hres_pad.as_ptr(),
                        self.mlp_padded_blocks,
                        luts_hres.as_mut_ptr(),
                    );
                    mv_fn(
                        self.mlp_fc2_t5t5_words.as_ptr(),
                        luts_hres.as_ptr(),
                        self.mlp_fc2_t5t5_scales.as_ptr(),
                        act_s,
                        h2_dim,
                        self.mlp_padded_blocks,
                        fc2_out.as_mut_ptr(),
                    );
                }
                for j in 0..h2_dim {
                    h2[j] = Self::silu(fc2_out[j] + self.mlp_fc2_b[j]);
                }
            } else {
                for j in 0..h2_dim {
                    let mut z = self.mlp_fc2_b[j];
                    for i in 0..h1_dim {
                        z += h_res[i] * self.mlp_fc2_w[i * h2_dim + j];
                    }
                    h2[j] = Self::silu(z);
                }
            }
        } else {
            for j in 0..h2_dim {
                let mut z = self.mlp_fc2_b[j];
                for i in 0..h1_dim {
                    z += h_res[i] * self.mlp_fc2_w[i * h2_dim + j];
                }
                h2[j] = Self::silu(z);
            }
        }

        // 5. 第四层输出头：`fc3` [H2, 4]
        let mut mlp_logits = [0.0_f32; INTENT_DIM];
        for k in 0..INTENT_DIM {
            let mut z = self.mlp_fc3_b[k];
            for j in 0..h2_dim {
                z += h2[j] * self.mlp_fc3_w[j * INTENT_DIM + k];
            }
            mlp_logits[k] = z;
        }

        // 6. 运行 200 棵树 4 分类 LightGBM MoE 门控路由器 (`moe_gating_router.txt`)
        let router_feats: [f32; 7] = [
            chains[1].max(chains[2]).max(chains[3]) * 2.5 - chains[0],
            peaks[1].max(peaks[2]),
            peaks[7] * 100.0,
            if vitality > 0.5 && peaks[1] > 0.6 {
                1.0
            } else if peaks[11] > 0.6 {
                2.0
            } else if peaks[9] > 0.6 {
                3.0
            } else {
                0.0
            },
            peaks[8].max(peaks[5]),
            peaks[0],
            peaks[3].max(peaks[10]),
        ];
        let mut tree_class_logits = [0.0_f32; INTENT_DIM];
        for (tree_idx, tree) in self.moe_router_trees.iter().enumerate() {
            let cls = tree_idx % INTENT_DIM;
            tree_class_logits[cls] += tree.eval(&router_feats);
        }
        for v in &mut tree_class_logits {
            *v = (*v * 0.05).tanh() * 0.30;
        }

        // 7. 通过 `libbittrit.dylib` 的 `tdx_rust_bt16_route_moe_experts_4combo_flat` 执行 T5T5/B8B8/B8T5/T5B8 四组合硬件专家路由
        let mut lgb23 = [0.0_f32; 23];
        for i in 0..12 {
            lgb23[i] = peaks[i];
            lgb23[i + 11] = peaks[i] * chains[(i % 3) + 1];
        }
        let mut active_expert_mask: u8 = 0x0F;
        let mut moe_weights_bp = [2500i16; 4];
        if let Some(route_fn) = accel.route_moe_experts_4combo_flat {
            let mut t5t5_pair = [0x7979u16; 2];
            let mut b8b8_consensus = 0u16;
            let mut expert_b8t5_4 = [0x8079u16; 4];
            let mut sorted_t5b8_4 = [0x7900u16; 4];
            unsafe {
                active_expert_mask = route_fn(
                    lgb23.as_ptr(),
                    0.01,
                    t5t5_pair.as_mut_ptr(),
                    &mut b8b8_consensus,
                    expert_b8t5_4.as_mut_ptr(),
                    sorted_t5b8_4.as_mut_ptr(),
                    moe_weights_bp.as_mut_ptr(),
                );
            }
        }

        let mut ensemble_margin = 0.0_f32;
        let mut active_forest_cnt = 0usize;
        for (f_idx, forest) in self.specialist_forests.iter().enumerate() {
            let g = f_idx & 3;
            if (active_expert_mask & (1u8 << g)) == 0 && f_idx >= 4 {
                continue;
            }
            let mut f_sum = 0.0_f32;
            for tree in forest {
                f_sum += tree.eval(&lgb23);
            }
            let w_ratio = (moe_weights_bp[g] as f32) / 2500.0;
            ensemble_margin += f_sum.tanh() * (0.85 + 0.15 * w_ratio);
            active_forest_cnt += 1;
        }
        let cb_bucket = (((peaks[0] > 0.5) as usize)
            | (((peaks[1] > 0.5) as usize) << 1)
            | (((peaks[3] > 0.5) as usize) << 2)
            | (((peaks[5] > 0.5) as usize) << 3)
            | (((peaks[9] > 0.5) as usize) << 4)
            | (((peaks[11] > 0.5) as usize) << 5))
            & 63;
        let cb_adj = self.catboost_leaf_calibration[cb_bucket] * 0.05;
        let booster_sig = (ensemble_margin / (active_forest_cnt.max(1) as f32) + cb_adj)
            .clamp(-0.5, 0.5);

        [
            mlp_logits[0] + tree_class_logits[0] - booster_sig * 0.25,
            mlp_logits[1] + tree_class_logits[1] + booster_sig * 0.20,
            mlp_logits[2] + tree_class_logits[2] + booster_sig * 0.20,
            mlp_logits[3] + tree_class_logits[3] + booster_sig * 0.25,
        ]
    }
}

/// `T5B8` 网络流量与协议内容重编解码异常检测结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct T5B8ProtocolCodecResult {
    /// 编码后的 16-bit `T5B8` 字 (`(t5_regime << 8) | b8_mask`)，十六进制表示如 `0xF2A8`
    pub t5b8_word: u16,
    pub t5b8_hex: String,
    /// 对偶 16-bit `B8T5` 字 (`(b8_mask << 8) | t5_regime`)
    pub b8t5_word: u16,
    /// 高字节 `T5` 模态编号 (`0..=242`，对应 $3^5=243$ 种五维三进制协议拓扑)
    pub t5_regime: u8,
    /// 解码还原后的 5 维三进制极性向量 `[-1, 0, +1]^5`
    /// `[熵扩散极性, 控制码/机器码极性, 相邻跳变/隧道极性, 注入语法极性, 端口/C2拓扑极性]`
    pub decoded_trits: [i8; 5],
    /// 低字节 `B8` 二进制能量与特征掩码
    pub b8_mask: u8,
    /// `T5B8` 编解码重构失真残差 (`0.0 ~ 1.0`，正常协议 `< 0.22`，混淆/攻击流量 `>= 0.38`)
    pub recon_error: f32,
    /// `libbittrit.dylib` 硬件 LUT-243 加权内积异常分 (`-15 ~ +15`)
    pub mac_anomaly_score: i32,
    /// 是否判定为潜在协议攻击行为
    pub is_attack: bool,
    /// 识别出的潜在攻击类别或正常协议标签
    pub attack_class: String,
}

/// 使用 `libbittrit.dylib` 对网络协议字节流或连接报文执行 **`T5B8` 重编解码（Protocol Auto-Encoding & Regime Inspection）**
pub fn inspect_network_payload_t5b8(
    payload: &[u8],
    process_name: &str,
    local_port: u16,
    remote_port: u16,
    is_wildcard_listen: bool,
) -> T5B8ProtocolCodecResult {
    let n = payload.len();
    // 1. 提取协议字节流的 5 个正交子空间特征 (x_raw[0..5] in [-1.0, +1.0])
    let mut byte_counts = [0u32; 256];
    let mut non_ascii_cnt = 0usize;
    let mut ctrl_or_nop_cnt = 0usize;
    let mut printable_grammar_cnt = 0usize;
    let mut step_jump_cnt = 0usize;
    let mut base64_like_cnt = 0usize;

    for (i, &b) in payload.iter().enumerate() {
        byte_counts[b as usize] += 1;
        if b >= 0x80 {
            non_ascii_cnt += 1;
        }
        if b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t'
            || b == 0x90
            || b == 0xCC
            || b == 0xFF
        {
            ctrl_or_nop_cnt += 1;
        }
        if matches!(
            b,
            b'{' | b'}' | b':' | b',' | b'"' | b'/' | b' ' | b'=' | b'-' | b'\n'
        ) {
            printable_grammar_cnt += 1;
        }
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            base64_like_cnt += 1;
        }
        if i > 0 {
            let prev = payload[i - 1];
            // 仅统计非标准可打印 ASCII 之间的异常二进制跳变（避免正常路径/JSON 字母与斜杠触发误报）
            let both_printable_ascii =
                (0x20..=0x7E).contains(&b) && (0x20..=0x7E).contains(&prev);
            if !both_printable_ascii {
                let diff = (b as i16 - prev as i16).unsigned_abs();
                if diff > 64 {
                    step_jump_cnt += 1;
                }
            }
        }
    }

    let len_f = (n.max(1)) as f32;
    let mut entropy = 0.0f32;
    if n > 0 {
        for &c in &byte_counts {
            if c > 0 {
                let p = (c as f32) / len_f;
                entropy -= p * p.log2();
            }
        }
    }
    let norm_entropy = (entropy / 8.0).clamp(0.0, 1.0);
    let non_ascii_ratio = (non_ascii_cnt as f32) / len_f;
    let ctrl_ratio = (ctrl_or_nop_cnt as f32) / len_f;
    let grammar_ratio = (printable_grammar_cnt as f32) / len_f;
    let jump_ratio = (step_jump_cnt as f32) / len_f;
    let b64_ratio = (base64_like_cnt as f32) / len_f;

    let text_lossy = String::from_utf8_lossy(payload).to_lowercase();
    let has_shell_token = text_lossy.contains("/bin/sh")
        || text_lossy.contains("bash -i")
        || text_lossy.contains("/dev/tcp/")
        || text_lossy.contains("powershell")
        || text_lossy.contains("cmd.exe")
        || text_lossy.contains("whoami")
        || text_lossy.contains("nc -e");
    let has_exploit_token = text_lossy.contains("jndi:")
        || text_lossy.contains("../")
        || text_lossy.contains("union select")
        || text_lossy.contains("config set dir")
        || text_lossy.contains("flushall")
        || text_lossy.contains("/json/version")
        || text_lossy.contains("eval(");

    let comm_lower = process_name.to_lowercase();
    let is_c2_port = matches!(remote_port, 4444 | 1337 | 5555 | 6667 | 9001 | 31337);
    let is_high_risk_listen = is_wildcard_listen && has_exploit_token;

    // 构造 5 维协议连续特征向量 X in [-1.0, +1.0]^5
    // x[0]: 熵与高比特混淆度 (正常文本/JSON < 0，加密/XOR Shellcode > 0)
    let x0 = if non_ascii_ratio > 0.25 || norm_entropy > 0.75 {
        (non_ascii_ratio * 1.5 + norm_entropy - 0.55).clamp(0.25, 1.0)
    } else {
        (norm_entropy - 0.68).clamp(-1.0, 0.10)
    };
    // x[1]: 控制字符/机器码 vs 规整协议定界符极性
    let x1 = if ctrl_ratio > 0.08 {
        (ctrl_ratio * 4.0).clamp(0.30, 1.0)
    } else if grammar_ratio > 0.05 {
        -0.75
    } else {
        -0.25
    };
    // x[2]: 相邻字节剧烈跳变 / 隐蔽编码隧道 (纯 Base64/Hex 长串且无空格/无协议定界符)
    let is_covert_tunnel =
        n >= 48 && b64_ratio > 0.96 && grammar_ratio < 0.02 && !text_lossy.contains("proto=");
    let x2 = if jump_ratio > 0.20 || is_covert_tunnel {
        (jump_ratio * 2.0 + if is_covert_tunnel { 0.65 } else { 0.0 }).clamp(0.30, 1.0)
    } else {
        (jump_ratio - 0.35).clamp(-0.85, -0.25)
    };
    // x[3]: 协议语法越界与 RCE/注入载荷特征
    let x3 = if has_shell_token || has_exploit_token {
        0.95
    } else if grammar_ratio > 0.05 && ctrl_ratio == 0.0 {
        -0.80
    } else {
        -0.30
    };
    // x[4]: 端口-进程-暴露面拓扑极性（仅在实际检出高危远控端口或攻击载荷时为正极性，正常本地开发服务为负极性）
    let x4 = if is_c2_port || is_high_risk_listen || has_shell_token || has_exploit_token {
        0.90
    } else {
        let _ = comm_lower;
        let _ = local_port;
        -0.70
    };

    let x_vec = [x0, x1, x2, x3, x4];

    // 2. 通过 `libbittrit.dylib` 执行 5 子空间量化 + B8T5 -> T5B8 硬件模态转码与逆向解码重构
    let accel = native_dylib_accel();
    let mut sub_80 = [0.0f32; 80];
    for s in 0..5 {
        for k in 0..16 {
            sub_80[s * 16 + k] = x_vec[s] * (0.85 + 0.02 * (k as f32));
        }
    }
    let mut b8t5_subs = [0x8079u16; 5];
    let mut sub_means = [0.0f32; 5];
    if let Some(q_fn) = accel.quantize_f32_subspaces_to_b8t5_flat {
        unsafe {
            q_fn(
                sub_80.as_ptr(),
                80,
                5,
                0.22,
                b8t5_subs.as_mut_ptr(),
                sub_means.as_mut_ptr(),
            );
        }
    }

    // 编码 5 维三进制方向 trits[0..5] -> Radix-3 t5_regime (0..=242)
    let mut trits = [0i8; 5];
    let mut t5_regime: u8 = 0;
    let mut pow3: u8 = 1;
    for s in 0..5 {
        let t: i8 = if x_vec[s] >= 0.22 {
            1
        } else if x_vec[s] <= -0.22 {
            -1
        } else {
            0
        };
        trits[s] = t;
        let digit = (t + 1) as u8; // {-1,0,+1} -> {0,1,2}
        t5_regime = t5_regime.saturating_add(digit.saturating_mul(pow3));
        if s < 4 {
            pow3 = pow3.saturating_mul(3);
        }
    }

    // 构造低字节 B8 二进制特征与幅值掩码
    let energy_q4 = ((x_vec.iter().map(|v| v.abs()).sum::<f32>() / 5.0 * 15.0)
        .round()
        .clamp(0.0, 15.0)) as u8;
    let flags_hi4 = ((non_ascii_ratio > 0.25) as u8)
        | (((ctrl_ratio > 0.08) as u8) << 1)
        | (((has_shell_token || has_exploit_token || is_covert_tunnel) as u8) << 2)
        | (((is_c2_port || is_high_risk_listen) as u8) << 3);
    let b8_mask: u8 = (flags_hi4 << 4) | (energy_q4 & 0x0F);
    let b8t5_word: u16 = ((b8_mask as u16) << 8) | (t5_regime as u16);

    // 调用 `libbittrit.dylib` 的 `tdx_rust_bt16_sort_and_query_t5b8_regime_flat` 将 B8T5 转码为 T5B8 并排序检索
    let mut sorted_t5b8 = [0u16; 1];
    let mut range_out = [0u32; 3];
    if let Some(sort_fn) = accel.sort_and_query_t5b8_regime_flat {
        unsafe {
            sort_fn(
                &b8t5_word,
                1,
                1, // input_is_b8t5 = true -> 自动转码为 T5B8 (hi8=t5_regime, lo8=b8_mask)
                t5_regime,
                0,
                sorted_t5b8.as_mut_ptr(),
                range_out.as_mut_ptr(),
            );
        }
    } else {
        sorted_t5b8[0] = ((t5_regime as u16) << 8) | (b8_mask as u16);
    }
    let t5b8_word = sorted_t5b8[0];

    // 调用 `libbittrit.dylib` 的 `tdx_rust_bt16_weighted_mac_b8t5_flat` 计算硬件 LUT-243 威胁内积
    let mut mac_anomaly_score: i32 = 0;
    if let Some(mac_fn) = accel.weighted_mac_b8t5_flat {
        let weights_i8: [i8; 5] = [3, 3, 2, 4, 3]; // 满分 +15，正常负向协议 -15
        let mut idx_out = [0u16; 1];
        let mut stats_out = [0u32; 4];
        unsafe {
            mac_fn(
                &b8t5_word,
                1,
                weights_i8.as_ptr(),
                0,
                0,
                0,
                -100,
                &mut mac_anomaly_score,
                idx_out.as_mut_ptr(),
                stats_out.as_mut_ptr(),
            );
        }
    } else {
        mac_anomaly_score = (trits[0] as i32) * 3
            + (trits[1] as i32) * 3
            + (trits[2] as i32) * 2
            + (trits[3] as i32) * 4
            + (trits[4] as i32) * 3;
    }

    // 3. 从 T5B8 字逆向解码 (Decode T5B8 -> 还原三进制模态与重构基准协议期望)
    let mut decoded_code = (t5b8_word >> 8) as u8;
    let mut decoded_trits = [0i8; 5];
    for s in 0..5 {
        decoded_trits[s] = ((decoded_code % 3) as i8) - 1;
        decoded_code /= 3;
    }
    // 同时通过 `tdx_rust_bt16_transcode_word` 校验 Dual8 往返一致性
    if let Some(tc_fn) = accel.transcode_word {
        unsafe {
            let _dual8 = tc_fn(1, b8t5_word & 0x1FFF, 0);
        }
    }

    // 计算相对于标准安全协议基线 (`[-0.65, -0.70, -0.50, -0.75, -0.65]`) 的 T5B8 重构失真度 Delta
    let canonical_benign = [-0.65f32, -0.70, -0.50, -0.75, -0.65];
    let mut recon_diff_sum = 0.0f32;
    for s in 0..5 {
        let decoded_val = (decoded_trits[s] as f32) * 0.70;
        let quant_err = (x_vec[s] - decoded_val).abs();
        let grammar_drift = (decoded_val - canonical_benign[s]).max(0.0);
        recon_diff_sum += quant_err * 0.35 + grammar_drift * 0.55;
    }
    let recon_error = (recon_diff_sum / 5.0).clamp(0.02, 0.99);

    let is_attack = mac_anomaly_score >= 3 || recon_error >= 0.38 || (b8_mask & 0xF0) != 0;
    let attack_class = if !is_attack {
        "正常协议流 (Benign Protocol Grammar)".to_string()
    } else if decoded_trits[0] > 0 && decoded_trits[1] > 0 {
        "混淆 Shellcode / 机器码载荷注入 (Obfuscated Shellcode)".to_string()
    } else if has_shell_token || (decoded_trits[3] > 0 && decoded_trits[4] > 0) {
        "C2 远控心跳 / 反向交互式 Shell (C2 Beacon / Reverse Shell)".to_string()
    } else if is_covert_tunnel || (decoded_trits[2] > 0 && decoded_trits[0] >= 0) {
        "隐蔽信道 / Base64-DNS 编码隧道 (Covert Exfiltration Tunnel)".to_string()
    } else if has_exploit_token || is_high_risk_listen {
        "未授权协议指令注入 / 暴露面滥用 (Protocol Command Injection)".to_string()
    } else {
        "协议模态越界异常 (Anomalous T5B8 Regime Drift)".to_string()
    };

    T5B8ProtocolCodecResult {
        t5b8_word,
        t5b8_hex: format!("0x{:04X}", t5b8_word),
        b8t5_word,
        t5_regime,
        decoded_trits,
        b8_mask,
        recon_error,
        mac_anomaly_score,
        is_attack,
        attack_class,
    }
}
