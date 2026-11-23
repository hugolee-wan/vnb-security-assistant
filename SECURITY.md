# Security Policy & Responsible Use Disclaimer (安全策略与免责声明)

## 1. 授权与合规使用声明 (Authorized Defensive Use Only)

`vnb-security-assistant`（VNB 终端安全助手）是一款面向终端主机安全防护（EDR）、广告弹窗外科手术静默及恶意驻留检测的防御与安全研究工具。

- **仅限合法防御与授权测试**：使用者仅可在自己拥有合法所有权或已获得明确书面授权的终端设备上运行、测试或部署本软件。
- **高危处置操作提示**：本系统提供 `A2`（窗口级外科手术静默）、`A3`（进程 `SIGSTOP` 挂起隔离）及 `A4`（恶意持久化项吊销与网络 C2 阻断）等主动响应能力。在生产环境启用自动阻断（`--daemon`）前，建议先通过 `--headless-check` 或 GUI 观察模式完成基线确认。
- **免责条款**：本项目按 Apache-2.0 协议以“现状（AS IS）”提供，开发者与贡献者不对因误报拦截、不当配置或未授权使用所导致的任何直接或间接损失承担责任。

## 2. 支持版本 (Supported Versions)

| 版本 | 支持状态 | 说明 |
| :--- | :--- | :--- |
| `0.2.x` (`v2.1`) | ✅ 维护中 | 支持 macOS (GPUI Metal 原生) 与 Windows/Linux (egui 跨平台工作台) |
| `< 0.2.0` | ❌ 已停止 | 历史早期原型版本 |

## 3. 安全漏洞上报 (Reporting a Vulnerability)

如果你在本项目中发现了安全漏洞（例如：规则/模型绕过、本地权限提升、记忆库污染或 FFI 内存安全隐患）：

1. **请勿在公开 GitHub Issues 中直接贴出 0-day 利用代码（PoC）**。
2. 请优先通过 GitHub 仓库的 **Private Vulnerability Reporting (Security Advisories)** 功能私密提交报告。
3. 报告中请尽量包含：
   - 受影响模块（如 `edr_engine.rs`、`pretrained_models.rs`、`surgical_actuator.rs` 或动态库接口）
   - 复现步骤与环境信息（OS 版本、架构）
   - 潜在影响评估与修复建议
