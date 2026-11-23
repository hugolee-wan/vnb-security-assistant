# VNB 终端安全助手 (`vnb-security-assistant` v2.1)

跨平台端侧智能终端安全（EDR）系统，支持 **macOS / Windows / Linux** 三大平台：
- **统一跨平台内核 (`src/`)**：共享 114 张量 `WhiteRabbitNeo-7B` 蒸馏安全语义与广告分类权重（`models/qwen25_security_model.safetensors`）、806 棵 GBDT 决策森林、T5B8 三进制网络载荷检测、多源威胁情报代码基因提取与本地防火墙/IPS 联动。
- **分平台原生构建与交付 (`platforms/{macos,windows,linux}`)**：
  - **macOS (`platforms/macos/`)**：基于 **Zed GPUI Metal 4 原生渲染** + `libbittrit.dylib` (`T5T5 / T5B8 / B8T5` 零乘法算子与 4-Combo MoE 路由) + 100% 物理自包含 `.app` 应用包。
  - **Windows (`platforms/windows/`)**：基于 **Win32 原生无黑框遥测 API (`windows-sys`)** + `egui/eframe` 桌面工作台 + Windows Defender 防火墙联动（`vnb_edr_gpui.dll`）。
  - **Linux (`platforms/linux/`)**：基于 **`/proc` 原生遥测** + `nftables/iptables` 规则导出 + `egui/eframe` 桌面工作台与轻量 `--daemon` 守护模式（`libvnb_edr_gpui.so`）。

---

## 一、三平台快速启动与构建

### 1. macOS 平台 (`platforms/macos/`) — 已内置自包含可运行包
- **Finder 双击直接运行**：打开 [`platforms/macos/`](./platforms/macos/)，直接双击 **[`VNB终端安全助手.app`](./platforms/macos/VNB终端安全助手.app)** 或 **[`启动终端安全.command`](./platforms/macos/启动终端安全.command)**。
- **终端命令行运行 GUI**：
  ```bash
  open "./platforms/macos/VNB终端安全助手.app"
  # 或直接运行启动器：
  ./platforms/macos/vnb-security-assistant
  ```
- **重新编译并打包 macOS `.app`**：
  ```bash
  ./platforms/macos/build_macos.sh
  ```

### 2. Windows 平台 (`platforms/windows/`)
- **一键编译 Windows `.exe` 与 `.dll`**：
  ```powershell
  .\platforms\windows\build_windows.ps1
  ```
- **启动 Windows 图形工作台**：
  双击 [`platforms\windows\start_windows_edr.bat`](./platforms/windows/start_windows_edr.bat) 或运行 `.\platforms\windows\vnb-security-assistant.exe`。

### 3. Linux 平台 (`platforms/linux/`)
- **一键编译 Linux 可执行程序与 `.so`**：
  ```bash
  ./platforms/linux/build_linux.sh
  ```
- **启动 Linux 工作台或守护进程**：
  ```bash
  ./platforms/linux/start_linux_edr.sh
  ```

### 4. 跨平台通用 CLI 无头巡检与后台守护模式
三大平台的可执行文件均支持相同的命令行参数：
```bash
# 输出跨平台 C-ABI 版本、硬件算力档位与动态库挂载状态
./platforms/macos/vnb-security-assistant --abi-info

# 无头全量真实 EDR 巡检（输出结构化 JSON 诊断报告）
./platforms/macos/vnb-security-assistant --headless-check

# 常驻后台主动防御守护进程模式（按主机算力档位自适应轮询）
./platforms/macos/vnb-security-assistant --daemon
```

---

## 二、仓库目录结构说明（三平台分离架构）

```text
./
├── .github/workflows/
│   └── release.yml                    # GitHub Actions 三平台 (macOS / Windows / Linux) 自动编译与产物打包流水线
├── platforms/                         # 按操作系统物理分离的发布产物、动态库与构建脚本
│   ├── macos/                         # [macOS 专属] GPUI Metal 4 原生应用包与 .dylib 动态库集群
│   │   ├── VNB终端安全助手.app/       # macOS 原生双击可运行应用包
│   │   ├── 启动终端安全.command       # Finder 双击一键启动脚本
│   │   ├── vnb-security-assistant     # macOS 宿主启动器 (380 KB)
│   │   ├── build_macos.sh             # macOS 一键编译、符号对齐与封装脚本
│   │   └── lib/                       # 5 个 macOS 实体动态链接库 (6.9 MB, @loader_path 自包含挂载)
│   │       ├── libvnb_edr_gpui.dylib          # (5.4 MB) GPUI Metal 4 渲染引擎 + EDR 核心业务库
│   │       ├── libbittrit.dylib               # (1.1 MB) T5T5 9-Level LUT256 零乘法算子 + 4-Combo MoE 路由
│   │       ├── libtdx_view_dylib.dylib        # (392 KB) 零拷贝视图核心库
│   │       ├── libmlx_bittrit_bridge.dylib    # (20 KB)  原生 T5T5/B8T5 LUT256 + Dual8 Popcount 加速桥
│   │       └── libmlx_qwen38_bridge.dylib     # (20 KB)  原生 GDN 状态机融合桥
│   ├── windows/                       # [Windows 专属] Win32 原生遥测 + egui 桌面工作台
│   │   ├── build_windows.ps1          # PowerShell 一键编译与 DLL 封装脚本
│   │   ├── start_windows_edr.bat      # Windows 双击无黑框启动脚本
│   │   └── README.md                  # Windows 构建与运行说明
│   └── linux/                         # [Linux 专属] /proc 遥测 + nftables 防火墙 + egui/Daemon
│       ├── build_linux.sh             # Linux 一键编译与 .so 封装脚本
│       ├── start_linux_edr.sh         # Linux 启动脚本
│       └── README.md                  # Linux 依赖安装与运行说明
├── models/                            # 三平台共享的 12 个实体预训练模型权重 (99 MB)
│   ├── qwen25_security_model.safetensors  # (96 MB)  114 张量完整版 3,584-D 安全语义、4层 GQA Transformer 与广告分类网络权重
│   ├── qwen25_bpe_vocab.json              # (544 KB) 32,768 Token Qwen2.5 BPE 子词词表
│   ├── moe_gating_router.txt              # (692 KB) 200 棵树 4 分类 LightGBM MoE 门控路由器
│   ├── booster_*.txt                      # (1.8 MB) 8 个专项 LightGBM 决策森林（共 606 棵树，总计 806 棵树）
│   └── booster_catboost_microstructure.cbm # (56 KB)  CatBoost 对称树叶节点微观结构标定表
├── scripts/
│   ├── build_dylib_thin.sh            # 指向 platforms/macos/build_macos.sh 的兼容快捷入口
│   └── build_pretrained_safetensors.py # 离线构建 qwen25_security_model.safetensors 的可复现导出脚本
├── src/                               # 统一跨平台 Rust 源码 (main.rs + lib.rs + platform.rs + gpui_edr.rs + ui.rs)
├── edr_model_config.json              # 决策模型与可选推理网关配置文件
├── Cargo.toml                         # 跨平台条件编译依赖配置 (macOS -> gpui, Windows/Linux -> eframe/egui + windows-sys)
├── LICENSE                            # Apache-2.0 开源许可证
└── SECURITY.md                        # 安全策略与合法防御免责声明
```

---

## 三、核心功能使用指南

### 1. 五大实时终端安全域监控
顶部导航栏与主工作台提供五大安全域实时观测与处置：
1. **全局态势与潜意图矩阵 (`Z0 ~ Z3`)**：
   - `Z0` 正常业务交互 (`A0` 放行)
   - `Z1` 宿主捆绑广告弹窗 (`A2` 外科手术静默：仅精准摘除寄生广告子窗口，保留用户的 Word/WPS/浏览器主文档窗口)
   - `Z2` 独立寄生推广模块 (`A3` 进程挂起隔离 `SIGSTOP` / Windows `SuspendThread`)
   - `Z3` 静默木马投递器/高危驻留 (`A4` 根除清理并吊销持久化项)
2. **实时进程与动态库审计 (`Live Processes`)**：
   - 自动扫描本机活动进程、代码签名、父子谱系与打开句柄，支持点击单个进程执行 **「深度取证协同」** 或 **「一键外科处置」**。
3. **持久化驻留监控 (`Persistence`)**：
   - macOS 扫描 `LaunchAgents`/`LaunchDaemons`/Cron；Windows 扫描 `HKCU/HKLM Run` 注册表与 Startup 目录；Linux 扫描 `systemd`/Cron，识别可疑自启动驻留并支持一键隔离。
4. **文件完整性监控 (`FIM`)**：
   - 监控敏感目录与二进制哈希变更，实时标记异常篡改。
5. **活动网络套接字、防火墙与 C2 阻断 (`Active Sockets & Firewall/IPS`)**：
   - 监控本机外联端口与远程端点，内置 T5B8 载荷检测，支持同步规则至 macOS `pfctl`、Windows `netsh advfirewall` 或 Linux `nftables`。
