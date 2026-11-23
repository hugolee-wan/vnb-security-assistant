//! 跨平台 OS 抽象层与运行时路径/进程/网络/注册表原生接口 (`src/platform.rs`)
//!
//! 统一收口 macOS / Windows / Linux 平台差异，彻底消除硬编码个人目录 (`/Users/...`) 与裸 POSIX 命令耦合：
//! 1. **零硬编码路径定位**：优先读取 `VNB_HOME`，其次基于 `current_exe()` / `current_dir()` 向上定位包含 `models/`、`lib/` 或 `Cargo.toml` 的应用根目录；
//!    若安装目录只读（如 `C:\Program Files\`），运行时日志/配置/取证报告自动写入 `%LOCALAPPDATA%\VNB-Security` 或 `~/Library/Application Support/VNB-Security`。
//! 2. **动态库跨平台装载**：macOS/Linux 使用 `dlopen`/`dlsym`，Windows 原生调用 `kernel32` `LoadLibraryW`/`GetProcAddress`。
//! 3. **Win32 原生系统控制与遥测 (Windows 零黑框)**：
//!    - 进程与内存枚举：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `QueryFullProcessImageNameW` + `GetProcessMemoryInfo`
//!    - 进程挂起/解冻/终止：`TH32CS_SNAPTHREAD` (`SuspendThread`/`ResumeThread`) + `TerminateProcess`
//!    - TCP Socket 枚举：`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` (IPv4 + IPv6)
//!    - 自启动项与守护服务：`RegOpenKeyExW` / `RegEnumValueW` / `RegSetValueExW` / `RegDeleteValueW` (`HKCU` & `HKLM` Run + Startup 文件夹)
//!    - 系统 Hosts (`%SystemRoot%\System32\drivers\etc\hosts`)、DNS 刷新 (`ipconfig /flushdns`) 与 UAC 提权写入

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// 主机硬件算力档位（用于低配置电脑 / 老旧 Intel 核显自动降载与渲染节流）
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostComputeTier {
    LowSpec,
    Standard,
    HighPerf,
}

impl HostComputeTier {
    pub fn label(self) -> &'static str {
        match self {
            HostComputeTier::LowSpec => "低配省电均衡 (Low-Spec)",
            HostComputeTier::Standard => "标准平衡 (Standard)",
            HostComputeTier::HighPerf => "高性能实时 (High-Perf)",
        }
    }
}

/// 跨平台主机硬件资源与自适应调度画像（启动时一次性探测并缓存）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostHardwareProfile {
    pub os_name: &'static str,
    pub arch: &'static str,
    pub logical_cores: usize,
    pub total_ram_mb: u64,
    pub tier: HostComputeTier,
    pub low_spec_forced: bool,
    pub prefer_low_gpu_overhead: bool,
    pub win_scan_interval_ms: u64,
    pub edr_tick_interval_secs: u64,
    pub max_ui_list_rows: usize,
}

fn detect_total_ram_mb() -> u64 {
    #[cfg(target_os = "macos")]
    {
        use std::os::raw::{c_char, c_int, c_void};
        extern "C" {
            fn sysctlbyname(
                name: *const c_char,
                oldp: *mut c_void,
                oldlenp: *mut usize,
                newp: *mut c_void,
                newlen: usize,
            ) -> c_int;
        }
        let mut mem_bytes: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        let rc = unsafe {
            sysctlbyname(
                b"hw.memsize\0".as_ptr() as *const c_char,
                (&mut mem_bytes as *mut u64).cast::<c_void>(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 && mem_bytes > 0 {
            return mem_bytes / (1024 * 1024);
        }
    }
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        #[allow(non_snake_case)]
        struct MemoryStatusEx {
            dwLength: u32,
            dwMemoryLoad: u32,
            ullTotalPhys: u64,
            ullAvailPhys: u64,
            ullTotalPageFile: u64,
            ullAvailPageFile: u64,
            ullTotalVirtual: u64,
            ullAvailVirtual: u64,
            ullAvailExtendedVirtual: u64,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
        }
        let mut st = unsafe { std::mem::zeroed::<MemoryStatusEx>() };
        st.dwLength = std::mem::size_of::<MemoryStatusEx>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut st) } != 0 && st.ullTotalPhys > 0 {
            return st.ullTotalPhys / (1024 * 1024);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = fs::read_to_string("/proc/meminfo") {
            for line in info.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    if let Some(kb_s) = rest.split_whitespace().next() {
                        if let Ok(kb) = kb_s.parse::<u64>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
    }
    8192
}

/// 探测本机 CPU/内存/低配模式（通过 `OnceLock` 全局缓存，零重复系统调用）
pub fn detect_host_hardware_profile() -> &'static HostHardwareProfile {
    static HW_PROFILE: OnceLock<HostHardwareProfile> = OnceLock::new();
    HW_PROFILE.get_or_init(|| {
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        let total_ram_mb = detect_total_ram_mb();
        let low_spec_forced = std::env::args().any(|a| a == "--low-spec" || a == "--software-render")
            || matches!(std::env::var("VNB_LOW_SPEC").as_deref(), Ok("1") | Ok("true") | Ok("TRUE"))
            || matches!(
                std::env::var("VNB_SOFTWARE_RENDER").as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE")
            );

        let is_low_hw = logical_cores <= 4 || (total_ram_mb > 0 && total_ram_mb <= 6144);
        let tier = if low_spec_forced || is_low_hw {
            HostComputeTier::LowSpec
        } else if logical_cores <= 8 || total_ram_mb <= 16384 {
            HostComputeTier::Standard
        } else {
            HostComputeTier::HighPerf
        };

        let prefer_low_gpu_overhead =
            low_spec_forced || logical_cores <= 2 || (total_ram_mb > 0 && total_ram_mb <= 4096);

        let (win_scan_interval_ms, edr_tick_interval_secs, max_ui_list_rows) = match tier {
            HostComputeTier::LowSpec => (2600, 15, 80),
            HostComputeTier::Standard => (1600, 10, 120),
            HostComputeTier::HighPerf => (1200, 8, 160),
        };

        HostHardwareProfile {
            os_name: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            logical_cores,
            total_ram_mb,
            tier,
            low_spec_forced,
            prefer_low_gpu_overhead,
            win_scan_interval_ms,
            edr_tick_interval_secs,
            max_ui_list_rows,
        }
    })
}

/// 返回当前运行态进程树的一条标准跨平台快照
#[derive(Debug, Clone)]
pub struct RawOsProcess {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cpu_pct: f32,
    pub rss_mb: f32,
    pub comm: String,
    pub exe_path: String,
    pub cmdline: String,
    pub username: String,
    pub tty: String,
    pub elapsed_time: String,
}

/// 返回当前活跃 TCP Socket 的标准跨平台快照
#[derive(Debug, Clone)]
pub struct RawTcpSocket {
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub local_endpoint: String,
    pub remote_endpoint: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
}

/// 返回 Windows 自启动持久化条目
#[derive(Debug, Clone)]
pub struct WinAutorunEntry {
    pub kind: String,
    pub label: String,
    pub config_path: String,
    pub target_exec: String,
    pub args_summary: String,
}

fn dir_has_app_markers(dir: &Path) -> bool {
    dir.join("models").is_dir()
        || dir.join("lib").is_dir()
        || dir.join("platforms").is_dir()
        || dir.join("Cargo.toml").is_file()
}

/// 带硬超时与并发管道排空的跨平台子进程执行器：
/// 防止 macOS `lsof`/`codesign`/`socketfilterfw` 或 Windows `netsh` 遇到 iCloud/FileProvider/TCC/网络挂起时无限阻塞。
pub fn run_command_with_timeout(cmd: &mut Command, timeout_ms: u64) -> Option<std::process::Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let budget = std::time::Duration::from_millis(timeout_ms.max(20));
    let deadline = std::time::Instant::now() + budget;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = t_out.join().unwrap_or_default();
                let stderr = t_err.join().unwrap_or_default();
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(8));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn is_dir_writable(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let probe = dir.join(format!(".vnb_write_probe_{}", std::process::id()));
    match fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// 查找包含 `models/`、`lib/` 或 `Cargo.toml` 的应用安装/工程根目录（进程级 `OnceLock` 缓存）
pub fn app_install_root() -> PathBuf {
    static INSTALL_ROOT: OnceLock<PathBuf> = OnceLock::new();
    INSTALL_ROOT
        .get_or_init(|| {
            if let Ok(env_root) = std::env::var("VNB_HOME") {
                let p = PathBuf::from(env_root.trim());
                if !env_root.trim().is_empty() && p.exists() {
                    return p;
                }
            }

            if let Ok(exe) = std::env::current_exe() {
                let mut cur = exe.parent();
                for _ in 0..6 {
                    let Some(dir) = cur else { break };
                    if dir_has_app_markers(dir) {
                        return dir.to_path_buf();
                    }
                    cur = dir.parent();
                }
                let mut res_cur = exe.parent();
                for _ in 0..4 {
                    let Some(dir) = res_cur else { break };
                    let res = dir.join("Contents/Resources");
                    if dir_has_app_markers(&res) {
                        return res;
                    }
                    let res2 = dir.join("Resources");
                    if dir_has_app_markers(&res2) {
                        return res2;
                    }
                    res_cur = dir.parent();
                }
            }

            if let Ok(cwd) = std::env::current_dir() {
                let mut cur = Some(cwd.as_path());
                for _ in 0..4 {
                    let Some(dir) = cur else { break };
                    if dir_has_app_markers(dir) {
                        return dir.to_path_buf();
                    }
                    cur = dir.parent();
                }
                return cwd;
            }

            if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
                let p = PathBuf::from(manifest);
                if p.exists() {
                    return p;
                }
            }

            PathBuf::from(".")
        })
        .clone()
}

/// 返回可写状态目录（进程级 `OnceLock` 缓存，彻底消除每次文件访问的磁盘写探测开销）
pub fn app_state_dir() -> PathBuf {
    static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();
    STATE_DIR
        .get_or_init(|| {
            let root = app_install_root();
            if is_dir_writable(&root) {
                return root;
            }

            #[cfg(target_os = "windows")]
            {
                if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
                    let d = PathBuf::from(local_app).join("VNB-Security");
                    let _ = fs::create_dir_all(&d);
                    return d;
                }
                let d = user_home_dir().join(".local/share/vnb-security");
                let _ = fs::create_dir_all(&d);
                d
            }

            #[cfg(target_os = "macos")]
            {
                let d = user_home_dir().join("Library/Application Support/VNB-Security");
                let _ = fs::create_dir_all(&d);
                d
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            {
                let d = user_home_dir().join(".local/share/vnb-security");
                let _ = fs::create_dir_all(&d);
                d
            }
        })
        .clone()
}

/// 获取状态目录下的指定相对路径
pub fn app_file(rel: &str) -> PathBuf {
    app_state_dir().join(rel)
}

/// 跨平台获取当前用户主目录（替代硬编码个人主目录路径）
pub fn user_home_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            if !up.trim().is_empty() {
                return PathBuf::from(up);
            }
        }
        if let (Ok(hd), Ok(hp)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            let combined = format!("{}{}", hd, hp);
            if !combined.trim().is_empty() {
                return PathBuf::from(combined);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home);
        }
    }
    if let Ok(up) = std::env::var("USERPROFILE") {
        if !up.trim().is_empty() {
            return PathBuf::from(up);
        }
    }
    std::env::temp_dir()
}

/// 查找可选模型网关 CLI 默认路径（相对安装目录或兄弟目录发现）
pub fn default_gateway_cli_hint() -> String {
    let bin_name = if cfg!(target_os = "windows") {
        "model-gateway-rs.exe"
    } else {
        "model-gateway-rs"
    };
    let root = app_install_root();
    let local_bin = root.join("bin").join(bin_name);
    if local_bin.exists() {
        return local_bin.to_string_lossy().into_owned();
    }
    if let Some(parent) = root.parent() {
        let sibling_bin = parent.join("model-service/bin").join(bin_name);
        if sibling_bin.exists() {
            return sibling_bin.to_string_lossy().into_owned();
        }
    }
    bin_name.to_string()
}

/// 查找可选外部模型注册表目录（若存在与工程同级的 `model-service/registry`）
pub fn sibling_model_registry_dir() -> Option<PathBuf> {
    let root = app_install_root();
    if let Some(parent) = root.parent() {
        let candidate = parent.join("model-service/registry");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// 返回系统 Hosts 文件跨平台标准路径
pub fn system_hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let sys_root = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("WINDIR"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(sys_root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// 刷新操作系统 DNS 解析缓存
pub fn flush_dns_cache() {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("dscacheutil").arg("-flushcache").status();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("resolvectl").arg("flush-caches").status();
    }
}

/// 提权覆写系统 Hosts 文件并刷新 DNS 缓存
pub fn elevated_copy_hosts_and_flush(src_tmp: &Path, dst_hosts: &Path, backup_original: bool) -> bool {
    #[cfg(target_os = "macos")]
    {
        let src_s = src_tmp.to_string_lossy().replace('\'', "'\\''");
        let dst_s = dst_hosts.to_string_lossy().replace('\'', "'\\''");
        let bak_cmd = if backup_original {
            format!("cp '{}' '{}.vnb.bak' && ", dst_s, dst_s)
        } else {
            String::new()
        };
        let script = format!(
            "do shell script \"{}cp '{}' '{}' && dscacheutil -flushcache && killall -HUP mDNSResponder || true\" with administrator privileges",
            bak_cmd, src_s, dst_s
        );
        matches!(Command::new("osascript").args(["-e", &script]).output(), Ok(ref o) if o.status.success())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let src_s = src_tmp.to_string_lossy().replace('\'', "''");
        let dst_s = dst_hosts.to_string_lossy().replace('\'', "''");
        let bak_ps = if backup_original {
            format!("Copy-Item -LiteralPath '{}' -Destination '{}.vnb.bak' -Force -ErrorAction SilentlyContinue; ", dst_s, dst_s)
        } else {
            String::new()
        };
        let inner = format!(
            "{}Copy-Item -LiteralPath '{}' -Destination '{}' -Force; ipconfig /flushdns | Out-Null",
            bak_ps, src_s, dst_s
        );
        let cmd = format!(
            "Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-WindowStyle','Hidden','-Command','{}'",
            inner.replace('\'', "''")
        );
        matches!(
            Command::new("powershell")
                .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
                .creation_flags(CREATE_NO_WINDOW)
                .output(),
            Ok(ref o) if o.status.success()
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = backup_original;
        matches!(
            Command::new("pkexec").args(["cp", &src_tmp.to_string_lossy(), &dst_hosts.to_string_lossy()]).output(),
            Ok(ref o) if o.status.success()
        )
    }
}

/// 在系统文本编辑器中打开文件（配置调试用）
pub fn open_file_in_editor(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").args(["-t", &path.to_string_lossy()]).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("notepad.exe")
            .arg(path)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("xdg-open").arg(path).spawn();
    }
}

/// 读取系统剪贴板文本
pub fn read_clipboard_text() -> String {
    #[cfg(target_os = "macos")]
    {
        Command::new("pbpaste")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", "Get-Clipboard"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xclip")
            .args(["-o", "-selection", "clipboard"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
}

/// 跨平台写入系统剪贴板（用于一键复制完整定位/取证摘要）
pub fn write_clipboard_text(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().map(|s| s.success()).unwrap_or(false);
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ps_cmd = "[Console]::InputEncoding = [System.Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())";
        if let Ok(mut child) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_cmd])
            .stdin(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().map(|s| s.success()).unwrap_or(false);
        }
        false
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(mut child) = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().map(|s| s.success()).unwrap_or(false);
        }
        false
    }
}

/// 在系统文件管理器中定位并高亮文件或打开所在目录
pub fn reveal_in_file_manager(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    let target = if path.exists() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            parent.to_path_buf()
        } else {
            return false;
        }
    } else {
        return false;
    };

    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("open");
        if target.is_dir() {
            cmd.arg(&target);
        } else {
            cmd.arg("-R").arg(&target);
        }
        cmd.spawn().is_ok()
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = Command::new("explorer");
        if target.is_dir() {
            cmd.arg(&target);
        } else {
            cmd.arg(format!("/select,{}", target.display()));
        }
        cmd.creation_flags(CREATE_NO_WINDOW).spawn().is_ok()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let open_dir = if target.is_dir() {
            target.as_path()
        } else {
            target.parent().unwrap_or(Path::new("/"))
        };
        Command::new("xdg-open").arg(open_dir).spawn().is_ok()
    }
}

/// 批量查询候选 PID 的当前工作目录（单次 `lsof` 调用，杜绝逐进程 N+1 阻塞）
pub fn batch_query_process_cwds(pids: &[u32]) -> HashMap<u32, String> {
    #[allow(unused_mut)]
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }
    #[cfg(target_os = "linux")]
    {
        for &pid in pids.iter().take(48) {
            if pid == 0 {
                continue;
            }
            if let Ok(cwd) = fs::read_link(format!("/proc/{}/cwd", pid)) {
                map.insert(pid, cwd.to_string_lossy().to_string());
            }
        }
        return map;
    }
    #[cfg(target_os = "macos")]
    {
        let mut unique = Vec::new();
        for &pid in pids {
            if pid > 0 && !unique.contains(&pid) {
                unique.push(pid);
                if unique.len() >= 48 {
                    break;
                }
            }
        }
        if unique.is_empty() {
            return map;
        }
        let pid_arg = unique
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut cmd = Command::new("lsof");
        cmd.args(["-b", "-w", "-a", "-d", "cwd", "-n", "-P", "-F", "pn", "-p", &pid_arg]);
        if let Some(out) = run_command_with_timeout(&mut cmd, 350) {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut cur_pid = 0u32;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix('p') {
                    cur_pid = rest.trim().parse::<u32>().unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix('n') {
                    let cwd = rest.trim();
                    if cur_pid > 0 && !cwd.is_empty() {
                        map.entry(cur_pid).or_insert_with(|| cwd.to_string());
                    }
                }
            }
        }
        map
    }
    #[cfg(target_os = "windows")]
    {
        let _ = pids;
        map
    }
}

/// 批量查询敏感/可疑文件当前的实时占用进程 `(pid, comm)`（带 `-b -w` 非阻塞与 350ms 硬超时）
pub fn batch_query_file_holders(paths: &[String]) -> HashMap<String, Vec<(u32, String)>> {
    #[allow(unused_mut)]
    let mut map: HashMap<String, Vec<(u32, String)>> = HashMap::new();
    #[cfg(unix)]
    {
        let mut unique_paths = Vec::new();
        for raw in paths {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed.contains("/.ssh/")
                || trimmed.contains("/Library/CloudStorage")
                || trimmed.contains("/Mobile Documents")
                || trimmed.starts_with("/Volumes/")
                || !Path::new(trimmed).exists()
            {
                continue;
            }
            if !unique_paths.iter().any(|p: &String| p == trimmed) {
                unique_paths.push(trimmed.to_string());
                if unique_paths.len() >= 16 {
                    break;
                }
            }
        }
        if unique_paths.is_empty() {
            return map;
        }
        let mut cmd = Command::new("lsof");
        cmd.args(["-b", "-w", "-n", "-P", "-F", "pcn", "--"])
            .args(&unique_paths);
        if let Some(out) = run_command_with_timeout(&mut cmd, 350) {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut cur_pid = 0u32;
            let mut cur_comm = String::new();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix('p') {
                    cur_pid = rest.trim().parse::<u32>().unwrap_or(0);
                    cur_comm.clear();
                } else if let Some(rest) = line.strip_prefix('c') {
                    cur_comm = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix('n') {
                    let name = rest.trim();
                    if cur_pid > 0 && !name.is_empty() {
                        if let Some(orig) = unique_paths.iter().find(|p| p.as_str() == name) {
                            let entry = map.entry(orig.clone()).or_default();
                            if !entry.iter().any(|(pid, _)| *pid == cur_pid) {
                                entry.push((cur_pid, cur_comm.clone()));
                            }
                        }
                    }
                }
            }
        }
        map
    }
    #[cfg(windows)]
    {
        let _ = paths;
        map
    }
}

/// 解析 Windows `Zone.Identifier` ADS 文本并提炼来源 URL 与安全区说明
pub fn parse_zone_identifier_content(raw: &str) -> Option<String> {
    let mut zone_id: Option<&str> = None;
    let mut host_url: Option<String> = None;
    let mut referrer_url: Option<String> = None;
    for line in raw.lines() {
        let t = line.trim();
        if let Some((k, v)) = t.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "zoneid" => {
                    zone_id = Some(match val {
                        "0" => "LocalMachine (ZoneId=0)",
                        "1" => "LocalIntranet (ZoneId=1)",
                        "2" => "TrustedSites (ZoneId=2)",
                        "3" => "Internet 下载来源 (ZoneId=3)",
                        "4" => "RestrictedSites (ZoneId=4)",
                        _ => "ZoneId",
                    });
                }
                "hosturl" if !val.is_empty() => host_url = Some(val.to_string()),
                "referrerurl" if !val.is_empty() => referrer_url = Some(val.to_string()),
                _ => {}
            }
        }
    }
    match (host_url.or(referrer_url), zone_id) {
        (Some(url), Some(z)) => Some(format!("{} · 来源: {}", z, url)),
        (Some(url), None) => Some(format!("下载来源: {}", url)),
        (None, Some(z)) => Some(z.to_string()),
        (None, None) => None,
    }
}

#[cfg(target_os = "macos")]
fn read_macos_xattr_bytes(path: &Path, attr: &str) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    extern "C" {
        fn getxattr(
            path: *const c_char,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> isize;
    }

    let c_path = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let c_attr = CString::new(attr).ok()?;
    let len = unsafe {
        getxattr(
            c_path.as_ptr(),
            c_attr.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        )
    };
    if len <= 0 || len > 65536 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let read_len = unsafe {
        getxattr(
            c_path.as_ptr(),
            c_attr.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            0,
        )
    };
    if read_len <= 0 {
        return None;
    }
    buf.truncate(read_len as usize);
    Some(buf)
}

#[cfg(target_os = "macos")]
fn extract_urls_from_bytes(bytes: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    let prefixes: [&[u8]; 3] = [b"https://", b"http://", b"file://"];
    let mut i = 0usize;
    while i < bytes.len() {
        let matched = prefixes
            .iter()
            .any(|p| bytes.len().saturating_sub(i) >= p.len() && &bytes[i..i + p.len()] == *p);
        if matched {
            let mut end = i;
            while end < bytes.len() {
                let b = bytes[end];
                if b < 0x21 || b > 0x7e || matches!(b, b'"' | b'\'' | b'<' | b'>' | b'`') {
                    break;
                }
                end += 1;
            }
            if end > i + 10 {
                if let Ok(s) = std::str::from_utf8(&bytes[i..end]) {
                    if !urls.iter().any(|u: &String| u == s) {
                        urls.push(s.to_string());
                        if urls.len() >= 3 {
                            break;
                        }
                    }
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    urls
}

/// 零子进程检查文件属主与下载溯源（macOS `getxattr` 隔离/WhereFroms / Windows `Zone.Identifier`）
pub fn inspect_file_owner_and_provenance(path: &Path) -> (String, String) {
    let owner = if let Ok(meta) = fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = meta.uid();
            let mode = meta.mode() & 0o777;
            if uid == 0 {
                format!("root (uid=0, {:03o})", mode)
            } else {
                format!("uid={} ({:03o})", uid, mode)
            }
        }
        #[cfg(windows)]
        {
            if meta.permissions().readonly() {
                "只读属性".to_string()
            } else {
                "常规文件".to_string()
            }
        }
    } else {
        "未落盘/无元数据".to_string()
    };

    #[cfg(target_os = "macos")]
    {
        let mut parts = Vec::new();
        if let Some(qbytes) = read_macos_xattr_bytes(path, "com.apple.quarantine") {
            let raw = String::from_utf8_lossy(&qbytes);
            let segs: Vec<&str> = raw.trim().split(';').collect();
            let agent = segs.get(2).copied().unwrap_or("").replace("\\x20", " ");
            let flags = segs.first().copied().unwrap_or("");
            if !agent.is_empty() {
                parts.push(format!("Quarantine[{}({})]", agent, flags));
            } else {
                parts.push(format!("Quarantine({})", flags));
            }
        }
        if let Some(wbytes) = read_macos_xattr_bytes(path, "com.apple.metadata:kMDItemWhereFroms") {
            let urls = extract_urls_from_bytes(&wbytes);
            if !urls.is_empty() {
                parts.push(format!("WhereFroms: {}", urls.join(" <- ")));
            }
        }
        let provenance = if parts.is_empty() {
            if path.exists() {
                "本地落盘 (无隔离下载标记)".to_string()
            } else {
                String::new()
            }
        } else {
            parts.join(" · ")
        };
        (owner, provenance)
    }
    #[cfg(target_os = "windows")]
    {
        let zone_path = format!("{}:Zone.Identifier", path.display());
        let provenance = fs::read_to_string(&zone_path)
            .ok()
            .and_then(|raw| parse_zone_identifier_content(&raw))
            .unwrap_or_else(|| {
                if path.exists() {
                    "本地文件 (无 Zone.Identifier)".to_string()
                } else {
                    String::new()
                }
            });
        (owner, provenance)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        (owner, String::new())
    }
}

fn split_cmdline_tokens(cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in cmdline.chars() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 从命令行和工作目录中提取入口脚本、配置文件路径与工作区目录
pub fn extract_entry_script_and_config(
    exe_path: &str,
    cmdline: &str,
    cwd: &str,
) -> (String, String, String) {
    let tokens = split_cmdline_tokens(cmdline);
    let exe_name = Path::new(exe_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_interpreter = [
        "python",
        "python3",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "bash",
        "zsh",
        "sh",
        "osascript",
        "powershell",
        "pwsh",
        "cmd",
    ]
    .iter()
    .any(|i| exe_name == *i || exe_name.starts_with(&format!("{}.", i)) || exe_name.starts_with(&format!("{}3.", i)));

    let mut entry_script = String::new();
    let mut config_file = String::new();

    let resolve_rel = |tok: &str| -> String {
        if tok.starts_with('/')
            || tok.starts_with("\\\\")
            || (tok.len() >= 3 && tok.as_bytes()[1] == b':')
            || cwd.trim().is_empty()
        {
            tok.to_string()
        } else {
            Path::new(cwd.trim()).join(tok).to_string_lossy().to_string()
        }
    };

    let mut idx = 1usize;
    while idx < tokens.len() {
        let tok = tokens[idx].trim();
        let lower = tok.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "--config" | "-c" | "--conf" | "-f" | "--file" | "--settings"
        ) {
            if let Some(next) = tokens.get(idx + 1) {
                if lower == "-c" && is_interpreter {
                    entry_script = format!("inline: {}", next.chars().take(120).collect::<String>());
                } else if config_file.is_empty() {
                    config_file = resolve_rel(next);
                }
                idx += 2;
                continue;
            }
        }
        if let Some((_, val)) = tok.split_once("--config=") {
            if config_file.is_empty() && !val.is_empty() {
                config_file = resolve_rel(val);
            }
        }
        if config_file.is_empty()
            && !tok.starts_with('-')
            && [
                ".plist", ".yaml", ".yml", ".toml", ".json", ".conf", ".ini", ".env",
            ]
            .iter()
            .any(|ext| lower.ends_with(ext))
        {
            config_file = resolve_rel(tok);
        }
        if entry_script.is_empty()
            && !tok.starts_with('-')
            && (is_interpreter
                || [".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".zsh", ".rb", ".pl", ".ps1", ".bat", ".scpt"]
                    .iter()
                    .any(|ext| lower.ends_with(ext)))
        {
            entry_script = resolve_rel(tok);
        }
        idx += 1;
    }

    let workspace = if !cwd.trim().is_empty() {
        cwd.trim().to_string()
    } else if !entry_script.is_empty() && !entry_script.starts_with("inline:") {
        Path::new(&entry_script)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        Path::new(exe_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    };

    (entry_script, config_file, workspace)
}

/// 归类远端/监听 IP 的网络作用域语义标签
pub fn classify_ip_scope_hint(ip: &str) -> &'static str {
    let trimmed = ip.trim().trim_matches(|c| c == '[' || c == ']');
    if trimmed.is_empty() || trimmed == "*" || trimmed == "0.0.0.0" || trimmed == "::" {
        return "Wildcard (全网卡暴露)";
    }
    if trimmed == "::1" || trimmed == "localhost" || trimmed.starts_with("127.") {
        return "Loopback (本机回环)";
    }
    if let Ok(v4) = trimmed.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
            return "RFC1918 私网";
        }
        if o[0] == 169 && o[1] == 254 {
            return "Link-Local / 云元数据网段";
        }
        if o[0] == 100 && (64..=127).contains(&o[1]) {
            return "CGNAT / 代理隧道段";
        }
        return "公网 IP";
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("fe80:") {
        "Link-Local IPv6"
    } else if lower.starts_with("fc") || lower.starts_with("fd") {
        "ULA 内网 IPv6"
    } else if trimmed.contains(':') {
        "公网 IPv6"
    } else {
        "未知网段"
    }
}

/// 跨平台物理挂起/冻结指定进程的所有调度线程（macOS `SIGSTOP` / Windows `SuspendThread`）
pub fn suspend_process(pid: u32) -> bool {
    if pid <= 1 || pid == std::process::id() {
        return false;
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        win32_helpers::suspend_or_resume_process_threads(pid, true)
    }
}

/// 跨平台物理恢复/解冻指定进程（macOS `SIGCONT` / Windows `ResumeThread`）
pub fn resume_process(pid: u32) -> bool {
    if pid <= 1 || pid == std::process::id() {
        return false;
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        win32_helpers::suspend_or_resume_process_threads(pid, false)
    }
}

/// 跨平台物理终止指定进程（macOS `kill -9` / Windows `OpenProcess + TerminateProcess`）
pub fn terminate_process(pid: u32) -> bool {
    if pid <= 1 || pid == std::process::id() {
        return false;
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        crate::win_live_os::win32_impl::live_terminate_process(pid)
    }
}

/// 跨平台发现指定根进程 `root_pid` 的全部后代子进程 PID（按叶子优先 / 自底向上顺序返回，供先子后父安全清剿）
pub fn collect_descendant_pids(root_pid: u32) -> Vec<u32> {
    if root_pid <= 1 || root_pid == std::process::id() {
        return Vec::new();
    }
    let pairs: Vec<(u32, u32)> = {
        #[cfg(not(target_os = "windows"))]
        {
            let mut cmd = Command::new("ps");
            cmd.args(["-eo", "pid=,ppid="]);
            run_command_with_timeout(&mut cmd, 350)
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .filter_map(|line| {
                            let mut parts = line.split_whitespace();
                            let pid = parts.next()?.parse::<u32>().ok()?;
                            let ppid = parts.next()?.parse::<u32>().ok()?;
                            Some((pid, ppid))
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
        #[cfg(target_os = "windows")]
        {
            win32_helpers::collect_pid_ppid_pairs()
        }
    };

    let mut children_map: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    for (pid, ppid) in pairs {
        if pid > 1 && pid != ppid {
            children_map.entry(ppid).or_default().push(pid);
        }
    }

    let self_pid = std::process::id();
    let mut bfs = std::collections::VecDeque::new();
    let mut seen = std::collections::HashSet::new();
    let mut ordered = Vec::new();
    bfs.push_back(root_pid);
    seen.insert(root_pid);

    while let Some(cur) = bfs.pop_front() {
        if let Some(kids) = children_map.get(&cur) {
            for &kid in kids {
                if kid > 1 && kid != self_pid && seen.insert(kid) {
                    ordered.push(kid);
                    bfs.push_back(kid);
                    if ordered.len() >= 128 {
                        break;
                    }
                }
            }
        }
        if ordered.len() >= 128 {
            break;
        }
    }
    ordered.reverse();
    ordered
}

/// 跨平台安全加固敏感凭据文件权限（Unix `chmod 0600` / Windows `icacls` 收敛至当前用户）
pub fn harden_credential_permissions(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            return fs::set_permissions(path, perms).is_ok();
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let user = std::env::var("USERNAME").unwrap_or_default();
        if user.is_empty() {
            return false;
        }
        let grant_arg = format!("{}:(R,W)", user);
        matches!(
            Command::new("icacls")
                .arg(path)
                .args(["/inheritance:r", "/grant:r", &grant_arg])
                .creation_flags(CREATE_NO_WINDOW)
                .output(),
            Ok(ref o) if o.status.success()
        )
    }
}

/// 查询文件八进制/可读权限标签与是否权限过宽（Unix 按 `mode & 0o077`，Windows 返回 NTFS 状态）
pub fn inspect_file_mode_label(path: &Path) -> (String, bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o644);
        (format!("0{:o}", mode), (mode & 0o077) != 0)
    }
    #[cfg(not(unix))]
    {
        let ro = fs::metadata(path)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false);
        (
            if ro {
                "NTFS(R)".to_string()
            } else {
                "NTFS(RW)".to_string()
            },
            false,
        )
    }
}

/// 读取 PE/Mach-O 头部架构与内嵌证书签名摘要（纯 Rust 零子进程剖析）
pub fn inspect_binary_format_and_pe_signer(exe_path: &str) -> (String, Option<String>) {
    let mut fmt = if cfg!(target_os = "windows") {
        "PE64 Windows Binary".to_string()
    } else if cfg!(target_os = "macos") {
        "Mach-O 64-bit arm64".to_string()
    } else {
        "ELF 64-bit Binary".to_string()
    };
    let mut pe_signer: Option<String> = None;

    if exe_path.is_empty() || !Path::new(exe_path).exists() {
        return (fmt, pe_signer);
    }

    if let Ok(mut f) = fs::File::open(exe_path) {
        let mut hdr = [0u8; 512];
        if let Ok(n) = f.read(&mut hdr) {
            let slice = &hdr[..n];
            if slice.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
                fmt = "Mach-O 64-bit arm64 (0xFEEDFACF)".to_string();
            } else if slice.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
                fmt = "Mach-O Universal Fat Binary (0xCAFEBABE)".to_string();
            } else if slice.starts_with(b"#!") {
                fmt = "Shebang 脚本 (#!)".to_string();
            } else if slice.starts_with(b"\x7fELF") {
                fmt = "ELF 64-bit Binary (0x7F454C46)".to_string();
            } else if slice.starts_with(b"MZ") && slice.len() >= 64 {
                let pe_off = u32::from_le_bytes([slice[60], slice[61], slice[62], slice[63]]) as usize;
                if pe_off + 180 <= slice.len() && &slice[pe_off..pe_off + 4] == b"PE\0\0" {
                    let machine = u16::from_le_bytes([slice[pe_off + 4], slice[pe_off + 5]]);
                    let arch = match machine {
                        0x8664 => "x86_64",
                        0xAA64 => "ARM64",
                        0x014C => "x86",
                        _ => "Unknown",
                    };
                    let opt_magic = u16::from_le_bytes([slice[pe_off + 24], slice[pe_off + 25]]);
                    fmt = format!(
                        "PE/{} {} (0x5A4D)",
                        if opt_magic == 0x020B { "32+" } else { "32" },
                        arch
                    );
                    let sec_dir_off = if opt_magic == 0x020B {
                        pe_off + 24 + 144 // PE32+: Security Directory (idx 4) = +112 + 32
                    } else {
                        pe_off + 24 + 128 // PE32: Security Directory (idx 4) = +96 + 32
                    };
                    if sec_dir_off + 8 <= slice.len() {
                        let cert_rva = u32::from_le_bytes([
                            slice[sec_dir_off],
                            slice[sec_dir_off + 1],
                            slice[sec_dir_off + 2],
                            slice[sec_dir_off + 3],
                        ]);
                        let cert_sz = u32::from_le_bytes([
                            slice[sec_dir_off + 4],
                            slice[sec_dir_off + 5],
                            slice[sec_dir_off + 6],
                            slice[sec_dir_off + 7],
                        ]);
                        let lower = exe_path.to_ascii_lowercase();
                        if cert_rva > 0 && cert_sz > 0 {
                            if lower.contains("\\windows\\") || lower.contains("/windows/") {
                                pe_signer = Some("Microsoft Windows Authenticode (Signed)".to_string());
                            } else {
                                pe_signer = Some("PE Authenticode 数字签名已嵌入".to_string());
                            }
                        } else if lower.contains("\\windows\\system32\\") {
                            pe_signer = Some("Microsoft Windows Catalog System".to_string());
                        } else {
                            pe_signer = Some("🚨 未签名 PE 二进制 (Unsigned)".to_string());
                        }
                    }
                } else {
                    fmt = "Windows PE / DOS Binary (MZ)".to_string();
                }
            }
        }
    }
    (fmt, pe_signer)
}

/// 返回当前操作系统标准的动态链接库候选文件名列表 (`lib<stem>.dylib` / `<stem>.dll` / `lib<stem>.so`)
pub fn platform_shared_lib_filenames(stem: &str) -> Vec<String> {
    let clean = stem
        .trim_end_matches(".dylib")
        .trim_end_matches(".so")
        .trim_end_matches(".dll");
    let bare = clean.strip_prefix("lib").unwrap_or(clean);
    #[cfg(target_os = "macos")]
    {
        vec![format!("lib{}.dylib", bare)]
    }
    #[cfg(target_os = "windows")]
    {
        vec![format!("{}.dll", bare), format!("lib{}.dll", bare)]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        vec![format!("lib{}.so", bare)]
    }
}

/// 跨平台 RAII 动态链接库句柄（自动在析构或显式关闭时释放 `dlclose` / `FreeLibrary`）
pub struct DynamicLibrary {
    handle: *mut std::ffi::c_void,
    pub loaded_name: String,
}

unsafe impl Send for DynamicLibrary {}
unsafe impl Sync for DynamicLibrary {}

impl DynamicLibrary {
    /// 按跨平台搜索优先级加载共享库（自动适配 `.dylib` / `.dll` / `.so`）
    pub fn open(lib_base_name: &str) -> Option<Self> {
        unsafe {
            let h = open_dynamic_library_candidates(lib_base_name);
            if h.is_null() {
                None
            } else {
                Some(Self {
                    handle: h,
                    loaded_name: lib_base_name.to_string(),
                })
            }
        }
    }

    /// 查找并绑定导出 C-ABI 函数/数据符号（`sym_nul` 必须以 `\0` 结尾）
    pub unsafe fn symbol<T: Copy>(&self, sym_nul: &[u8]) -> Option<T> {
        if self.handle.is_null() || sym_nul.is_empty() || *sym_nul.last()? != 0 {
            return None;
        }
        let ptr = lookup_dynamic_symbol(self.handle, sym_nul);
        if ptr.is_null() || std::mem::size_of::<T>() != std::mem::size_of::<*mut std::ffi::c_void>() {
            None
        } else {
            Some(std::mem::transmute_copy(&ptr))
        }
    }
}

impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                close_dynamic_library(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn close_dynamic_library(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        extern "C" {
            fn dlclose(handle: *mut std::ffi::c_void) -> std::os::raw::c_int;
        }
        let _ = dlclose(handle);
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn close_dynamic_library(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        #[link(name = "kernel32")]
        extern "system" {
            fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
        }
        let _ = FreeLibrary(handle);
    }
}

/// 跨平台动态库打开与符号解析（macOS `dlopen` / Linux `dlopen` / Windows `LoadLibraryW` + `SetDllDirectoryW`）
#[cfg(not(target_os = "windows"))]
pub unsafe fn open_dynamic_library_candidates(lib_base_name: &str) -> *mut std::ffi::c_void {
    use std::os::raw::{c_char, c_int};
    extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut std::ffi::c_void;
    }
    const RTLD_LAZY: c_int = 0x1;
    const RTLD_LOCAL: c_int = 0x4;

    let ext = if cfg!(target_os = "macos") { "dylib" } else { "so" };
    let file_name = if lib_base_name.contains('.') {
        lib_base_name.to_string()
    } else {
        format!("lib{}.{}", lib_base_name, ext)
    };

    for cand in build_lib_search_paths(&file_name, None) {
        if cand.components().count() > 1 && !cand.as_os_str().to_string_lossy().starts_with('@') && !cand.exists() {
            continue;
        }
        if let Ok(c_str) = std::ffi::CString::new(cand.to_string_lossy().as_bytes()) {
            let h = dlopen(c_str.as_ptr(), RTLD_LAZY | RTLD_LOCAL);
            if !h.is_null() {
                return h;
            }
        }
    }
    std::ptr::null_mut()
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn lookup_dynamic_symbol(handle: *mut std::ffi::c_void, sym_nul: &[u8]) -> *mut std::ffi::c_void {
    use std::os::raw::c_char;
    extern "C" {
        fn dlsym(handle: *mut std::ffi::c_void, symbol: *const c_char) -> *mut std::ffi::c_void;
    }
    dlsym(handle, sym_nul.as_ptr() as *const c_char)
}

#[cfg(target_os = "windows")]
pub unsafe fn open_dynamic_library_candidates(lib_base_name: &str) -> *mut std::ffi::c_void {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(lpLibFileName: *const u16) -> *mut std::ffi::c_void;
        fn SetDllDirectoryW(lpPathName: *const u16) -> i32;
        fn SetErrorMode(uMode: u32) -> u32;
    }
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;

    let stem = lib_base_name
        .trim_end_matches(".dylib")
        .trim_end_matches(".so")
        .trim_end_matches(".dll");
    let without_lib = stem.strip_prefix("lib").unwrap_or(stem);
    let dll_a = format!("{}.dll", without_lib);
    let dll_b = format!("lib{}.dll", without_lib);

    let prev_mode = SetErrorMode(SEM_FAILCRITICALERRORS);
    for cand in build_lib_search_paths(&dll_a, Some(&dll_b)) {
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
            let _ = SetDllDirectoryW(std::ptr::null());
            let _ = SetErrorMode(prev_mode);
            return h;
        }
    }
    let _ = SetDllDirectoryW(std::ptr::null());
    let _ = SetErrorMode(prev_mode);
    std::ptr::null_mut()
}

#[cfg(target_os = "windows")]
pub unsafe fn lookup_dynamic_symbol(handle: *mut std::ffi::c_void, sym_nul: &[u8]) -> *mut std::ffi::c_void {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
    }
    GetProcAddress(handle, sym_nul.as_ptr())
}

fn current_os_platform_subdir() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

fn push_dir_lib_candidates(paths: &mut Vec<PathBuf>, dir: &Path, names: &[&str]) {
    let os_sub = current_os_platform_subdir();
    for n in names {
        paths.push(dir.join("lib").join(n));
        paths.push(dir.join("platforms").join(os_sub).join("lib").join(n));
        paths.push(dir.join("platforms").join(os_sub).join(n));
        paths.push(dir.join(n));
    }
}

fn build_lib_search_paths(primary: &str, secondary: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let os_sub = current_os_platform_subdir();
    let names: Vec<&str> = match secondary {
        Some(s) if s != primary => vec![primary, s],
        _ => vec![primary],
    };

    if let Ok(env_root) = std::env::var("VNB_HOME") {
        let trimmed = env_root.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            push_dir_lib_candidates(&mut paths, &p, &names);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            push_dir_lib_candidates(&mut paths, exe_dir, &names);
            if let Some(contents) = exe_dir.parent() {
                for n in &names {
                    paths.push(contents.join("Resources/lib").join(n));
                    paths.push(contents.join("Frameworks").join(n));
                }
                push_dir_lib_candidates(&mut paths, contents, &names);
                if let Some(root2) = contents.parent() {
                    push_dir_lib_candidates(&mut paths, root2, &names);
                    if let Some(root3) = root2.parent() {
                        push_dir_lib_candidates(&mut paths, root3, &names);
                    }
                }
            }
        }
    }

    let install_root = app_install_root();
    push_dir_lib_candidates(&mut paths, &install_root, &names);
    for n in &names {
        paths.push(PathBuf::from("lib").join(n));
        paths.push(PathBuf::from("platforms").join(os_sub).join("lib").join(n));
        paths.push(PathBuf::from("platforms").join(os_sub).join(n));
        if cfg!(target_os = "macos") {
            paths.push(PathBuf::from(format!("@loader_path/{}", n)));
        }
        paths.push(PathBuf::from(n));
    }
    paths
}

// ============================================================================
// Windows 原生 Win32 底层遥测、线程冻结、网络与注册表驻留实现
// ============================================================================
#[cfg(target_os = "windows")]
pub mod win32_helpers {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
        Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WRITE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ, THREAD_SUSPEND_RESUME,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DAEMON_REG_VAL: &str = "VNB_Local_EDR_Daemon";
    const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn suspend_or_resume_process_threads(pid: u32, suspend: bool) -> bool {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut touched = 0usize;
            if Thread32First(snap, &mut te) != 0 {
                loop {
                    if te.th32OwnerProcessID == pid {
                        let ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if !ht.is_null() {
                            if suspend {
                                SuspendThread(ht);
                            } else {
                                ResumeThread(ht);
                            }
                            CloseHandle(ht);
                            touched += 1;
                        }
                    }
                    if Thread32Next(snap, &mut te) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            touched > 0
        }
    }

    pub fn collect_windows_processes() -> Vec<RawOsProcess> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut pe) != 0 {
                loop {
                    let pid = pe.th32ProcessID;
                    if pid > 0 {
                        let end = pe
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(pe.szExeFile.len());
                        let comm = OsString::from_wide(&pe.szExeFile[..end])
                            .to_string_lossy()
                            .into_owned();
                        let exe_path = crate::win_live_os::win32_impl::query_exe_full_path(pid)
                            .unwrap_or_else(|| comm.clone());
                        let mut rss_mb = 0.0_f32;
                        let h = OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                            FALSE,
                            pid,
                        );
                        if !h.is_null() {
                            let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
                            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                            if GetProcessMemoryInfo(h, &mut pmc, pmc.cb) != 0 {
                                rss_mb = (pmc.WorkingSetSize as f32) / (1024.0 * 1024.0);
                            }
                            CloseHandle(h);
                        }
                        out.push(RawOsProcess {
                            pid,
                            ppid: pe.th32ParentProcessID,
                            uid: 0,
                            cpu_pct: 0.0,
                            rss_mb,
                            comm: comm.clone(),
                            exe_path: exe_path.clone(),
                            cmdline: exe_path,
                            username: String::new(),
                            tty: String::new(),
                            elapsed_time: String::new(),
                        });
                    }
                    if Process32NextW(snap, &mut pe) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }

    pub fn collect_pid_ppid_pairs() -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut pe) != 0 {
                loop {
                    if pe.th32ProcessID > 0 {
                        out.push((pe.th32ProcessID, pe.th32ParentProcessID));
                    }
                    if Process32NextW(snap, &mut pe) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }

    fn tcp_state_name(dw_state: u32) -> &'static str {
        match dw_state {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "ACTIVE",
        }
    }

    pub fn collect_windows_tcp_sockets() -> Vec<RawTcpSocket> {
        let mut results = Vec::new();
        let mut pid_info: HashMap<u32, (String, String)> = HashMap::new();
        for p in collect_windows_processes() {
            pid_info.insert(p.pid, (p.comm, p.exe_path));
        }

        unsafe {
            // IPv4 TCP 表
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                FALSE,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size > 0 {
                let mut buf = vec![0u8; size as usize + 64];
                if GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut size,
                    FALSE,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ) == 0
                {
                    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                    let rows = std::slice::from_raw_parts(
                        table.table.as_ptr(),
                        table.dwNumEntries as usize,
                    );
                    for row in rows {
                        let lip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string();
                        let lport = u16::from_be(row.dwLocalPort as u16);
                        let rip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)).to_string();
                        let rport = u16::from_be(row.dwRemotePort as u16);
                        let state = tcp_state_name(row.dwState).to_string();
                        let pid = row.dwOwningPid;
                        let (pname, epath) = pid_info
                            .get(&pid)
                            .cloned()
                            .unwrap_or_else(|| (format!("pid_{}", pid), String::new()));
                        let remote_ep = if state == "LISTEN" {
                            "*:*".to_string()
                        } else {
                            format!("{}:{}", rip, rport)
                        };
                        results.push(RawTcpSocket {
                            pid,
                            process_name: pname,
                            exe_path: epath,
                            local_endpoint: format!("{}:{}", lip, lport),
                            remote_endpoint: remote_ep,
                            local_ip: lip,
                            local_port: lport,
                            remote_ip: rip,
                            remote_port: if state == "LISTEN" { 0 } else { rport },
                            state,
                        });
                    }
                }
            }

            // IPv6 TCP 表
            let mut size6: u32 = 0;
            let _ = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size6,
                FALSE,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if size6 > 0 {
                let mut buf6 = vec![0u8; size6 as usize + 64];
                if GetExtendedTcpTable(
                    buf6.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut size6,
                    FALSE,
                    AF_INET6 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ) == 0
                {
                    let table6 = &*(buf6.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                    let rows6 = std::slice::from_raw_parts(
                        table6.table.as_ptr(),
                        table6.dwNumEntries as usize,
                    );
                    for row in rows6 {
                        let lip_raw = Ipv6Addr::from(row.ucLocalAddr);
                        let lip = format!("[{}]", lip_raw);
                        let lport = u16::from_be(row.dwLocalPort as u16);
                        let rip_raw = Ipv6Addr::from(row.ucRemoteAddr);
                        let rip = format!("[{}]", rip_raw);
                        let rport = u16::from_be(row.dwRemotePort as u16);
                        let state = tcp_state_name(row.dwState).to_string();
                        let pid = row.dwOwningPid;
                        let (pname, epath) = pid_info
                            .get(&pid)
                            .cloned()
                            .unwrap_or_else(|| (format!("pid_{}", pid), String::new()));
                        let remote_ep = if state == "LISTEN" {
                            "*:*".to_string()
                        } else {
                            format!("{}:{}", rip, rport)
                        };
                        results.push(RawTcpSocket {
                            pid,
                            process_name: pname,
                            exe_path: epath,
                            local_endpoint: format!("{}:{}", lip, lport),
                            remote_endpoint: remote_ep,
                            local_ip: lip,
                            local_port: lport,
                            remote_ip: rip,
                            remote_port: if state == "LISTEN" { 0 } else { rport },
                            state,
                        });
                    }
                }
            }
        }
        results
    }

    pub fn collect_windows_loaded_modules(pid: u32) -> Vec<String> {
        let mut mods = Vec::new();
        if pid == 0 {
            return mods;
        }
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap == INVALID_HANDLE_VALUE {
                return mods;
            }
            let mut me: MODULEENTRY32W = std::mem::zeroed();
            me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(snap, &mut me) != 0 {
                loop {
                    let end = me
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(me.szModule.len());
                    let mname = OsString::from_wide(&me.szModule[..end])
                        .to_string_lossy()
                        .into_owned();
                    if !mname.is_empty() {
                        mods.push(mname);
                    }
                    if mods.len() >= 12 || Module32NextW(snap, &mut me) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        mods
    }

    /// 枚举指定进程的非系统目录或高危临时目录已加载 DLL 全路径（供 DLL 注入取证定位）
    pub fn collect_windows_suspicious_module_paths(pid: u32) -> Vec<String> {
        let mut suspicious = Vec::new();
        let mut non_os = Vec::new();
        if pid == 0 {
            return suspicious;
        }
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap == INVALID_HANDLE_VALUE || snap.is_null() {
                return suspicious;
            }
            let mut me: MODULEENTRY32W = std::mem::zeroed();
            me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(snap, &mut me) != 0 {
                loop {
                    let end = me
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(me.szExePath.len());
                    let path = String::from_utf16_lossy(&me.szExePath[..end]);
                    let lower = path.to_ascii_lowercase();
                    if !lower.is_empty()
                        && !lower.contains("\\windows\\system32\\")
                        && !lower.contains("\\windows\\winsxs\\")
                        && !lower.contains("\\windows\\syswow64\\")
                        && !lower.contains("\\windows\\servicing\\")
                    {
                        if lower.contains("\\temp\\")
                            || lower.contains("\\appdata\\")
                            || lower.contains("\\programdata\\")
                            || lower.contains("\\users\\public\\")
                            || lower.ends_with(".cpl")
                        {
                            if !suspicious.contains(&path) {
                                suspicious.push(path);
                            }
                        } else if !non_os.contains(&path) {
                            non_os.push(path);
                        }
                    }
                    if suspicious.len() >= 12 || Module32NextW(snap, &mut me) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        for p in non_os {
            if suspicious.len() >= 12 {
                break;
            }
            if !suspicious.contains(&p) {
                suspicious.push(p);
            }
        }
        suspicious
    }

    fn split_reg_exe_and_args(cmd: &str) -> (String, String) {
        let t = cmd.trim();
        if let Some(stripped) = t.strip_prefix('"') {
            if let Some(end_q) = stripped.find('"') {
                return (
                    stripped[..end_q].to_string(),
                    stripped[end_q + 1..].trim().to_string(),
                );
            }
        }
        if let Some((exe, args)) = t.split_once(' ') {
            (exe.to_string(), args.trim().to_string())
        } else {
            (t.to_string(), String::new())
        }
    }

    fn enum_run_hive(root_hive: HKEY, hive_tag: &str, subkey_str: &str, out: &mut Vec<WinAutorunEntry>) {
        unsafe {
            let subkey = to_wide(subkey_str);
            let mut hkey: HKEY = std::ptr::null_mut();
            if RegOpenKeyExW(root_hive, subkey.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
                return;
            }
            let mut idx: u32 = 0;
            loop {
                let mut name_buf = [0u16; 260];
                let mut name_len = name_buf.len() as u32;
                let mut val_type: u32 = 0;
                let mut data_buf = [0u8; 2048];
                let mut data_len = data_buf.len() as u32;
                let st = RegEnumValueW(
                    hkey,
                    idx,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut val_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                );
                idx += 1;
                if st as u32 == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if st != 0 {
                    continue;
                }
                let val_name = OsString::from_wide(&name_buf[..name_len as usize])
                    .to_string_lossy()
                    .into_owned();
                let u16_cnt = (data_len as usize) / 2;
                let u16_slice = std::slice::from_raw_parts(data_buf.as_ptr() as *const u16, u16_cnt);
                let val_end = u16_slice.iter().position(|&c| c == 0).unwrap_or(u16_slice.len());
                let raw_cmd = OsString::from_wide(&u16_slice[..val_end])
                    .to_string_lossy()
                    .into_owned();
                let (target_exec, args_summary) = split_reg_exe_and_args(&raw_cmd);
                out.push(WinAutorunEntry {
                    kind: format!("Registry {}", hive_tag),
                    label: val_name.clone(),
                    config_path: format!("REG:{}\\{}::{}", hive_tag, subkey_str, val_name),
                    target_exec,
                    args_summary,
                });
            }
            RegCloseKey(hkey);
        }
    }

    pub fn scan_windows_autorun_entries() -> Vec<WinAutorunEntry> {
        let mut out = Vec::new();
        enum_run_hive(HKEY_CURRENT_USER, "HKCU", RUN_SUBKEY, &mut out);
        enum_run_hive(
            HKEY_CURRENT_USER,
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            &mut out,
        );
        enum_run_hive(HKEY_LOCAL_MACHINE, "HKLM", RUN_SUBKEY, &mut out);

        // Windows Startup 目录
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup_dir = PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(rd) = fs::read_dir(&startup_dir) {
                for ent in rd.flatten() {
                    let p = ent.path();
                    if p.is_file() {
                        let fname = ent.file_name().to_string_lossy().into_owned();
                        if fname.eq_ignore_ascii_case("desktop.ini") {
                            continue;
                        }
                        let full = p.to_string_lossy().into_owned();
                        out.push(WinAutorunEntry {
                            kind: "Startup Folder".to_string(),
                            label: fname,
                            config_path: full.clone(),
                            target_exec: full,
                            args_summary: "Windows 启动菜单开机自启".to_string(),
                        });
                    }
                }
            }
        }
        out
    }

    pub fn remove_windows_autorun(config_path: &str) -> bool {
        if let Some(spec) = config_path.strip_prefix("REG:") {
            if let Some((hive_and_sub, val_name)) = spec.split_once("::") {
                if let Some((hive_s, subkey_s)) = hive_and_sub.split_once('\\') {
                    let root_hive = if hive_s.eq_ignore_ascii_case("HKLM") {
                        HKEY_LOCAL_MACHINE
                    } else {
                        HKEY_CURRENT_USER
                    };
                    unsafe {
                        let subkey = to_wide(subkey_s);
                        let mut hkey: HKEY = std::ptr::null_mut();
                        if RegOpenKeyExW(root_hive, subkey.as_ptr(), 0, KEY_SET_VALUE | KEY_WRITE, &mut hkey) == 0 {
                            let vname = to_wide(val_name);
                            let st = RegDeleteValueW(hkey, vname.as_ptr());
                            RegCloseKey(hkey);
                            return st == 0;
                        }
                    }
                }
            }
            return false;
        }
        let p = Path::new(config_path);
        if p.exists() {
            return fs::remove_file(p).is_ok();
        }
        false
    }

    pub fn check_windows_daemon_installed() -> bool {
        crate::win_live_os::win32_impl::reg_exists_hkcu_run(DAEMON_REG_VAL)
    }

    pub fn toggle_windows_daemon() -> (bool, String) {
        if check_windows_daemon_installed() {
            let ok = crate::win_live_os::win32_impl::reg_delete_hkcu_run(DAEMON_REG_VAL);
            (
                false,
                format!(
                    "[DAEMON-UNINSTALL] 已从 HKCU\\...\\Run 卸载 {} 后台守护自启项 (ok={})",
                    DAEMON_REG_VAL, ok
                ),
            )
        } else {
            let exe = std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "vnb-security-assistant.exe".to_string());
            let cmd = format!("\"{}\" --daemon", exe);
            let ok = crate::win_live_os::win32_impl::reg_write_hkcu_run(DAEMON_REG_VAL, &cmd);
            if ok {
                let _ = Command::new(&exe)
                    .arg("--daemon")
                    .creation_flags(CREATE_NO_WINDOW)
                    .spawn();
            }
            (
                ok,
                format!(
                    "[DAEMON-INSTALL] 已注册 HKCU\\...\\Run\\{} 并启动静默守护进程 (ok={})",
                    DAEMON_REG_VAL, ok
                ),
            )
        }
    }
}

// ============================================================================
// 跨平台主机防火墙状态查询与规则同步原语 (macOS PF+ALF / Windows Defender Firewall)
// ============================================================================

/// 操作系统原生防火墙运行状态快照
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsFirewallStatus {
    pub backend_name: String,
    pub os_firewall_enabled: bool,
    pub stealth_or_profile: String,
    pub synced_anchor_rules: usize,
    pub anchor_path: String,
    pub detail: String,
}

/// 跨平台下发给系统防火墙后端的单条标准规则描述
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallRuleOsSpec {
    pub rule_id: String,
    /// "IN" | "OUT" | "BOTH"
    pub direction: String,
    /// "TCP" | "UDP" | "ANY"
    pub protocol: String,
    /// "any" 或 IP/CIDR
    pub remote_ip: String,
    /// 0 表示全端口
    pub port: u16,
    /// "BLOCK" | "ALLOW"
    pub action: String,
    pub comment: String,
}

fn sanitize_fw_token(raw: &str, fallback: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '-' | '_'))
        .collect();
    if clean.is_empty() {
        fallback.to_string()
    } else {
        clean
    }
}

fn count_vnb_rules_in_file(path: &Path) -> usize {
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    text.lines()
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with("REM ")
        })
        .count()
}

/// 查询当前操作系统原生防火墙开启状态与本地已同步规则文件
pub fn query_os_firewall_status() -> OsFirewallStatus {
    #[cfg(target_os = "macos")]
    {
        let anchor_file = app_file("vnb_pf.anchor");
        let synced_cnt = count_vnb_rules_in_file(&anchor_file);

        let mut cmd_alf = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw");
        cmd_alf.arg("--getglobalstate");
        let alf_out = run_command_with_timeout(&mut cmd_alf, 400)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let mut cmd_stealth = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw");
        cmd_stealth.arg("--getstealthmode");
        let stealth_out = run_command_with_timeout(&mut cmd_stealth, 400)
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let alf_lower = alf_out.to_ascii_lowercase();
        let alf_on = alf_lower.contains("enabled") || alf_lower.contains("state = 1");
        let stealth_on = stealth_out.to_ascii_lowercase().contains("enabled");

        let mut cmd_pf = Command::new("/sbin/pfctl");
        cmd_pf.args(["-s", "info"]);
        let pf_info = run_command_with_timeout(&mut cmd_pf, 400)
            .map(|o| {
                let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                s
            })
            .unwrap_or_default();
        let pf_on = pf_info.to_ascii_lowercase().contains("status: enabled");

        return OsFirewallStatus {
            backend_name: "macOS PF + ALF (socketfilterfw)".to_string(),
            os_firewall_enabled: alf_on || pf_on,
            stealth_or_profile: format!(
                "ALF={} · PF={} · 隐身模式={}",
                if alf_on { "开启" } else { "关闭" },
                if pf_on { "启用" } else { "待按需挂载" },
                if stealth_on { "开启" } else { "关闭" }
            ),
            synced_anchor_rules: synced_cnt,
            anchor_path: anchor_file.to_string_lossy().into_owned(),
            detail: if alf_out.is_empty() {
                "PF Anchor 就绪 (非 root 仅可导出策略文件，点击“应用至系统内核”时触发授权)".to_string()
            } else {
                format!("{} | {}", alf_out, stealth_out)
            },
        };
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let script_file = app_file("vnb_firewall_sync.cmd");
        let synced_cnt = count_vnb_rules_in_file(&script_file);

        let mut cmd = Command::new("netsh");
        cmd.args(["advfirewall", "show", "allprofiles", "state"])
            .creation_flags(CREATE_NO_WINDOW);
        let out = run_command_with_timeout(&mut cmd, 600)
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let upper = out.to_ascii_uppercase();
        let on_count = upper.matches("ON").count() + out.matches("启用").count();
        let off_count = upper.matches("OFF").count() + out.matches("关闭").count();
        let enabled = on_count > 0;

        return OsFirewallStatus {
            backend_name: "Windows Defender Firewall (netsh advfirewall)".to_string(),
            os_firewall_enabled: enabled,
            stealth_or_profile: format!("开启配置文件数={} · 关闭数={}", on_count, off_count),
            synced_anchor_rules: synced_cnt,
            anchor_path: script_file.to_string_lossy().into_owned(),
            detail: if out.trim().is_empty() {
                "Windows 防火墙状态待查询".to_string()
            } else {
                out.lines()
                    .take(8)
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join(" | ")
            },
        };
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let anchor_file = app_file("vnb_nft_rules.conf");
        let synced_cnt = count_vnb_rules_in_file(&anchor_file);
        OsFirewallStatus {
            backend_name: "Linux nftables / iptables".to_string(),
            os_firewall_enabled: synced_cnt > 0,
            stealth_or_profile: "Rule Export Ready".to_string(),
            synced_anchor_rules: synced_cnt,
            anchor_path: anchor_file.to_string_lossy().into_owned(),
            detail: "Linux 防火墙策略文件就绪".to_string(),
        }
    }
}

/// 生成标准跨平台防火墙规则脚本（macOS 生成 PF anchor 语法；Windows 生成 netsh 批处理）
pub fn render_pf_or_netsh_script(specs: &[FirewallRuleOsSpec]) -> String {
    #[cfg(not(target_os = "windows"))]
    {
        let mut out = String::from(
            "# VNB Security Assistant - Host Firewall Anchor Rules (PF Syntax)\n\
             # Auto-generated by VNB Local Firewall & IPS Engine\n",
        );
        for spec in specs {
            let act = if spec.action.eq_ignore_ascii_case("ALLOW") {
                "pass"
            } else {
                "block drop"
            };
            let proto_clause = match spec.protocol.to_ascii_uppercase().as_str() {
                "TCP" => "proto tcp ",
                "UDP" => "proto udp ",
                _ => "proto { tcp, udp } ",
            };
            let remote = sanitize_fw_token(&spec.remote_ip, "any");
            let id = sanitize_fw_token(&spec.rule_id, "vnb_rule");
            let dir_upper = spec.direction.to_ascii_uppercase();
            let dirs: Vec<&str> = match dir_upper.as_str() {
                "IN" => vec!["in"],
                "OUT" => vec!["out"],
                _ => vec!["in", "out"],
            };
            for d in dirs {
                let (from_part, to_part) = if d == "in" {
                    (
                        remote.as_str(),
                        if spec.port > 0 { "any port" } else { "any" },
                    )
                } else {
                    ("any", remote.as_str())
                };
                if d == "in" {
                    if spec.port > 0 {
                        out.push_str(&format!(
                            "{} {} quick {}from {} to any port {} # {}: {}\n",
                            act,
                            d,
                            proto_clause,
                            from_part,
                            spec.port,
                            id,
                            spec.comment.replace('\n', " ")
                        ));
                    } else if remote != "any" {
                        out.push_str(&format!(
                            "{} {} quick {}from {} to any # {}: {}\n",
                            act,
                            d,
                            proto_clause,
                            from_part,
                            id,
                            spec.comment.replace('\n', " ")
                        ));
                    }
                } else if spec.port > 0 {
                    out.push_str(&format!(
                        "{} {} quick {}from any to {} port {} # {}: {}\n",
                        act,
                        d,
                        proto_clause,
                        to_part,
                        spec.port,
                        id,
                        spec.comment.replace('\n', " ")
                    ));
                } else if remote != "any" {
                    out.push_str(&format!(
                        "{} {} quick {}from any to {} # {}: {}\n",
                        act,
                        d,
                        proto_clause,
                        to_part,
                        id,
                        spec.comment.replace('\n', " ")
                    ));
                }
            }
        }
        out
    }

    #[cfg(target_os = "windows")]
    {
        let mut out = String::from(
            "@echo off\r\n\
             REM VNB Security Assistant - Windows Defender Firewall Sync Script\r\n",
        );
        for spec in specs {
            let id = sanitize_fw_token(&spec.rule_id, "vnb_rule");
            let rule_name = format!("VNB_EDR_{}", id);
            let act = if spec.action.eq_ignore_ascii_case("ALLOW") {
                "allow"
            } else {
                "block"
            };
            let proto = match spec.protocol.to_ascii_uppercase().as_str() {
                "TCP" => "TCP",
                "UDP" => "UDP",
                _ => "ANY",
            };
            let remote = sanitize_fw_token(&spec.remote_ip, "any");
            let dirs: Vec<&str> = match spec.direction.to_ascii_uppercase().as_str() {
                "IN" => vec!["in"],
                "OUT" => vec!["out"],
                _ => vec!["in", "out"],
            };
            for d in dirs {
                let full_name = format!("{}_{}", rule_name, d.to_ascii_uppercase());
                out.push_str(&format!(
                    "netsh advfirewall firewall delete rule name=\"{}\" >nul 2>&1\r\n",
                    full_name
                ));
                let mut cmd = format!(
                    "netsh advfirewall firewall add rule name=\"{}\" dir={} action={} protocol={}",
                    full_name, d, act, proto
                );
                if spec.port > 0 && (proto == "TCP" || proto == "UDP") {
                    if d == "in" {
                        cmd.push_str(&format!(" localport={}", spec.port));
                    } else {
                        cmd.push_str(&format!(" remoteport={}", spec.port));
                    }
                }
                if remote != "any" {
                    cmd.push_str(&format!(" remoteip={}", remote));
                }
                out.push_str(&format!("{}\r\n", cmd));
            }
        }
        out
    }
}

/// 将规则同步写入策略文件，并在显式允许时（非沙盒模式）提权应用至 OS 内核防火墙
pub fn sync_os_firewall_rules(
    specs: &[FirewallRuleOsSpec],
    apply_to_os_kernel: bool,
    sandbox_export_path: Option<&Path>,
) -> Result<String, String> {
    let rendered = render_pf_or_netsh_script(specs);
    let target_path = match sandbox_export_path {
        Some(p) => p.to_path_buf(),
        None => {
            #[cfg(target_os = "windows")]
            {
                app_file("vnb_firewall_sync.cmd")
            }
            #[cfg(not(target_os = "windows"))]
            {
                app_file("vnb_pf.anchor")
            }
        }
    };

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建防火墙策略目录失败: {}", e))?;
    }
    fs::write(&target_path, rendered.as_bytes())
        .map_err(|e| format!("写入防火墙策略文件失败 ({}): {}", target_path.display(), e))?;

    let rule_lines = count_vnb_rules_in_file(&target_path);

    if sandbox_export_path.is_some() || !apply_to_os_kernel {
        return Ok(format!(
            "[FW-STAGE] 已同步生成 {} 条跨平台内核防火墙规则到 {}（未触发现网内核提权）",
            rule_lines,
            target_path.display()
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let anchor_quoted = target_path.to_string_lossy().replace('\'', "'\\''");
        let shell_cmd = format!(
            "/sbin/pfctl -E 2>/dev/null || true; /sbin/pfctl -a com.vnb.edr -f '{}' && /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            anchor_quoted
        );
        let osa_escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
        let status = Command::new("osascript")
            .args([
                "-e",
                &format!("do shell script \"{}\" with administrator privileges", osa_escaped),
            ])
            .status()
            .map_err(|e| format!("调用 osascript 提权加载 PF 防火墙失败: {}", e))?;
        if status.success() {
            Ok(format!(
                "[FW-KERNEL-SYNC] 已提权启用 macOS ALF + PF Anchor (com.vnb.edr · {} 条规则已生效)",
                rule_lines
            ))
        } else {
            Err("用户取消提权或 pfctl 加载规则返回非零状态（本地策略文件已保留）".to_string())
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let path_escaped = target_path.to_string_lossy().replace('\'', "''");
        let ps = format!(
            "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"{}\"' -Verb RunAs -Wait -WindowStyle Hidden",
            path_escaped
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| format!("调用 PowerShell UAC 同步 Windows 防火墙失败: {}", e))?;
        if status.success() {
            Ok(format!(
                "[FW-KERNEL-SYNC] 已通过 UAC 提权应用 {} 条 Windows Defender 防火墙规则",
                rule_lines
            ))
        } else {
            Err("UAC 授权取消或 netsh 规则同步失败（脚本已保存在本地）".to_string())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(format!(
            "[FW-STAGE] Linux 环境已写入 {} 条防火墙规则至 {}",
            rule_lines,
            target_path.display()
        ))
    }
}
