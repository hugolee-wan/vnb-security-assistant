# macOS 平台构建与运行 (`platforms/macos`)

本目录存放 **macOS (Apple Silicon / Metal 4 GPUI 原生)** 平台的构建脚本、动态链接库（`.dylib`）与原生 `.app` 应用包。

## 目录结构

```text
platforms/macos/
├── VNB终端安全助手.app/           # macOS 原生双击可运行应用包
├── 启动终端安全.command           # Finder 双击一键启动脚本
├── vnb-security-assistant         # macOS 命令行启动器
├── build_macos.sh                 # macOS 一键编译、符号对齐与 .app 封装脚本
└── lib/                           # macOS 专属动态链接库 (.dylib)
    ├── libvnb_edr_gpui.dylib      # GPUI Metal 4 渲染引擎 + EDR 核心业务库
    ├── libbittrit.dylib           # T5T5 9-Level LUT256 零乘法算子与 MoE 路由
    ├── libtdx_view_dylib.dylib    # 零拷贝视图核心库
    ├── libmlx_bittrit_bridge.dylib
    └── libmlx_qwen38_bridge.dylib
```

## 快速启动

1. **Finder 双击启动**：打开 `platforms/macos/`，直接双击 `VNB终端安全助手.app` 或 `启动终端安全.command`。
2. **命令行启动 GUI**：
   ```bash
   ./platforms/macos/vnb-security-assistant
   ```
3. **无头全量巡检（输出 JSON 报告）**：
   ```bash
   ./platforms/macos/vnb-security-assistant --headless-check
   ```
4. **重新编译与打包**：
   ```bash
   ./platforms/macos/build_macos.sh
   ```
