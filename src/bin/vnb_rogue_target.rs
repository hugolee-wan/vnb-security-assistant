#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
//! 独立外部真实靶机进程 (`vnb-rogue-target.exe`)
//!
//! 纯图形子系统进程（零命令行黑框），用于在 Windows 真机上以 **100% 真实独立进程、真实 Win32 置顶弹窗、
//! 真实 TCP Socket 通信、真实磁盘高熵可执行体释放、真实原生 Registry API `RegSetValueExW` 写入** 的方式，
//! 供 `vnb-security-assistant` 从外部通过纯 OS API 实时检测发现、提醒与外科手术处置验证！

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn get_live_verify_dir() -> PathBuf {
    let d = std::env::temp_dir()
        .join("vnb_security_live_verify")
        .join("dropped_stage");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// 真实建立本地回环 TCP Socket 传输一段指令/高熵载荷，产生真实的内核网络收发事件
fn perform_real_loopback_socket_io(payload_size: usize) -> Vec<u8> {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return vec![0xAA; payload_size];
    };
    let Ok(addr) = listener.local_addr() else {
        return vec![0xAA; payload_size];
    };

    let handle = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut state: u64 = 0x853C_49E6_748F_EA9B;
            let mut buf = Vec::with_capacity(payload_size);
            for i in 0..payload_size {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
                buf.push(((v >> ((i % 8) * 8)) & 0xFF) as u8);
            }
            let _ = conn.write_all(&buf);
        }
    });

    let mut received = Vec::new();
    if let Ok(mut client) = TcpStream::connect(addr) {
        let _ = client.read_to_end(&mut received);
    }
    let _ = handle.join();
    received
}

#[cfg(target_os = "windows")]
fn run_win32_popup_loop(title_str: &str, bottom_right: bool, offscreen_1x1: bool) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetSystemMetrics,
        IsWindow, PeekMessageW, RegisterClassW, ShowWindow, TranslateMessage, MSG, PM_REMOVE,
        SM_CXSCREEN, SM_CYSCREEN, SW_SHOWNOACTIVATE, WM_CLOSE, WNDCLASSW, WS_CAPTION,
        WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW, WS_POPUP, WS_SYSMENU, WS_VISIBLE,
    };

    let to_w = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };

    unsafe {
        unsafe extern "system" fn wnd_proc(
            hwnd: HWND,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> isize {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }

        let cls = to_w("VNB_RealRogueTarget_WndClass");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: std::ptr::null_mut(),
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: 16 as *mut core::ffi::c_void,
            lpszMenuName: std::ptr::null(),
            lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);

        let sw = GetSystemMetrics(SM_CXSCREEN).max(1920);
        let sh = GetSystemMetrics(SM_CYSCREEN).max(1080);

        let (ex_style, style, x, y, w, h) = if offscreen_1x1 {
            (
                WS_EX_TOOLWINDOW,
                WS_POPUP | WS_VISIBLE,
                -32000,
                -32000,
                1,
                1,
            )
        } else if bottom_right {
            (
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                WS_POPUP | WS_VISIBLE,
                sw - 380,
                sh - 270,
                360,
                220,
            )
        } else {
            (
                0,
                WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                (sw - 600) / 2,
                (sh - 400) / 2,
                600,
                400,
            )
        };

        let title_w = to_w(title_str);
        let hwnd = CreateWindowExW(
            ex_style,
            cls.as_ptr(),
            title_w.as_ptr(),
            style,
            x,
            y,
            w,
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        );
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);

        // 写下当前真实窗口句柄与线程信息到状态文件，供跨平台日志对齐参考（主程序在 Windows 下亦直接用 EnumWindows 扫描）
        let mut msg: MSG = std::mem::zeroed();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(120) {
            if IsWindow(hwnd) == 0 {
                break;
            }
            while PeekMessageW(&mut msg, hwnd, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_CLOSE {
                    DestroyWindow(hwnd);
                    return;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn run_win32_popup_loop(_title_str: &str, _bottom_right: bool, _offscreen_1x1: bool) {
    std::thread::sleep(Duration::from_secs(60));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args
        .iter()
        .find_map(|a| a.strip_prefix("--mode="))
        .unwrap_or("host-ad");

    let stage_dir = get_live_verify_dir();
    let my_pid = std::process::id();

    match mode {
        // 模式 1：宿主主进程正打开重要办公文档读写心跳，同时内部子线程弹出右下角置顶无边框广告窗
        "host-ad" => {
            let doc_path = stage_dir.join("正在编辑_2026Q4产品架构方案.docx");
            let running = Arc::new(AtomicBool::new(true));
            let r_clone = Arc::clone(&running);

            // 主工作线程：持续向办公文档写入心跳，证明主进程一旦被误杀会导致文档写入中断
            std::thread::spawn(move || {
                let mut seq = 0u64;
                while r_clone.load(Ordering::Relaxed) {
                    seq += 1;
                    let content = format!(
                        "PID={} 宿主文档主线程活跃心跳 seq={} (若执行 a_2 外科手术消音，广告窗消失但此心跳持续增长)\n",
                        my_pid, seq
                    );
                    let _ = std::fs::write(&doc_path, content);
                    std::thread::sleep(Duration::from_millis(100));
                }
            });

            let _ = perform_real_loopback_socket_io(512);
            run_win32_popup_loop(
                &format!("【真实右下角置顶广告】超级会员特惠弹窗 (PID={})", my_pid),
                true,
                false,
            );
            running.store(false, Ordering::Relaxed);
        }

        // 模式 2：独立寄生广告子进程（Socket 收包后直接弹出右下角置顶无边框窗）
        "parasitic-popup" => {
            let _ = perform_real_loopback_socket_io(1024);
            run_win32_popup_loop(
                &format!("【迷你热点资讯】右下角寄生广告窗 (PID={})", my_pid),
                true,
                false,
            );
        }

        // 模式 3：静默捆绑与驻留母体（真实 Socket 接收高熵载荷 -> 释放 Temp 可执行文件 -> 写注册表 Run 启动项 -> 1x1 隐藏窗）
        "silent-dropper" => {
            let payload = perform_real_loopback_socket_io(4096);
            let dropped_exe = stage_dir.join(format!("vnb_rogue_bundle_{}.exe", my_pid));
            let _ = std::fs::write(&dropped_exe, &payload);
            let dropped_str = dropped_exe.to_string_lossy().into_owned();

            #[cfg(target_os = "windows")]
            unsafe {
                use std::os::windows::ffi::OsStrExt;
                use windows_sys::Win32::System::Registry::{
                    RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
                    KEY_SET_VALUE, KEY_WRITE, REG_SZ,
                };
                let to_w = |s: &str| -> Vec<u16> {
                    std::ffi::OsStr::new(s)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect()
                };
                let subkey = to_w(r"Software\Microsoft\Windows\CurrentVersion\Run");
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0,
                    KEY_SET_VALUE | KEY_WRITE,
                    &mut hkey,
                ) == 0
                {
                    let vname = to_w("VNB_Test_Rogue_AutoRun");
                    let vdata = to_w(&dropped_str);
                    let _ = RegSetValueExW(
                        hkey,
                        vname.as_ptr(),
                        0,
                        REG_SZ,
                        vdata.as_ptr() as *const u8,
                        (vdata.len() * 2) as u32,
                    );
                    RegCloseKey(hkey);
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let reg_file = stage_dir.join("reg_run_VNB_Test_Rogue_AutoRun.txt");
                let _ = std::fs::write(reg_file, &dropped_str);
            }

            run_win32_popup_loop(
                &format!("VNB_HiddenDropper_Host (PID={})", my_pid),
                false,
                true,
            );
        }

        // 模式 4：正常人工交互创建的标准居中窗口
        _ => {
            run_win32_popup_loop(
                &format!("正常标准工作窗口 (PID={})", my_pid),
                false,
                false,
            );
        }
    }
}
