# Linux 平台构建与运行 (`platforms/linux`)

本目录存放 **Linux (`x86_64` / `aarch64`)** 平台的构建脚本、启动脚本与共享动态链接库（`libvnb_edr_gpui.so`）。
Linux 端支持 `/proc` 原生进程与套接字遥测、`nftables/iptables` 防火墙规则生成、守护进程模式（`--daemon`）及 `egui/eframe` 桌面工作台。

## 目录结构

```text
platforms/linux/
├── build_linux.sh                 # Linux 一键编译与 .so 封装脚本
├── start_linux_edr.sh             # Linux 启动脚本
├── vnb-security-assistant         # 编译后生成的 Linux 宿主启动器
└── lib/
    └── libvnb_edr_gpui.so         # 编译后生成的 Linux 核心 EDR 动态库
```

## 构建与运行

1. **安装构建依赖（Ubuntu / Debian 示例）**：
   ```bash
   sudo apt-get update && sudo apt-get install -y build-essential pkg-config libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
   ```
2. **一键编译**：
   ```bash
   ./platforms/linux/build_linux.sh
   ```
3. **运行 GUI / 无头巡检 / 后台守护**：
   ```bash
   ./platforms/linux/start_linux_edr.sh
   ./platforms/linux/start_linux_edr.sh --headless-check
   ./platforms/linux/start_linux_edr.sh --daemon
   ```
