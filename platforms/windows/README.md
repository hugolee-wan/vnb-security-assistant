# Windows 平台构建与运行 (`platforms/windows`)

本目录存放 **Windows (Win10 / Win11 x86_64)** 平台的构建脚本、启动器与动态链接库（`vnb_edr_gpui.dll`）。
Windows 端采用 **Win32 原生遥测 API (`windows-sys`) + `egui/eframe` 桌面工作台**，全程无黑框（`CREATE_NO_WINDOW`）。

## 目录结构

```text
platforms/windows/
├── build_windows.ps1              # PowerShell 一键编译与打包脚本
├── start_windows_edr.bat          # Windows 双击启动脚本
├── vnb-security-assistant.exe     # 编译后生成的宿主启动器
└── lib/
    └── vnb_edr_gpui.dll           # 编译后生成的 Windows 核心 EDR 动态库
```

## 构建与运行

1. **在 Windows 上本地编译**：
   ```powershell
   .\platforms\windows\build_windows.ps1
   ```
2. **启动图形工作台**：
   双击 `platforms\windows\start_windows_edr.bat` 或运行 `.\platforms\windows\vnb-security-assistant.exe`。
3. **无头巡检模式**：
   ```powershell
   .\platforms\windows\vnb-security-assistant.exe --headless-check
   ```
