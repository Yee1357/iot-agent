# IoT 漏洞挖掘 Agent 项目

## 项目说明

IoT 固件自动化漏洞挖掘系统。Claude 作为 Agent，通过 Python 工具链调用 IDA Pro（idalib headless）和 Linux VM 完成固件解包、二进制逆向、漏洞发现与验证。

## 环境配置

### IDA Pro
- 安装路径：在 `.env` 中配置 `IOT_AGENT_IDA_INSTALL_DIR`
- 两种分析模式：
  - **MCP 模式**：IDA GUI 运行 + MCP 插件（配置在 `.mcp.json`）
  - **Headless 模式**：`IDAHeadlessClient` 调用 idalib SDK，无需 GUI
- 初始化：`ensure_idalib_config()` 自动修复 `ida-config.json`

### Python 环境
- conda 环境：`iot-agent`（Python 3.12）
- 安装：`pip install -e .`

### VM 连接
- 凭据在 `.env` 中配置
- `VMRemoteExecutor` 通过 SSH 执行命令，支持连接复用（推荐用 `async with` 上下文管理器）
- 已装工具：binwalk、radare2、QEMU（mips/arm）、FirmAE（`/opt/firmae`）

## 关键文件

| 文件 | 用途 |
|------|------|
| `src/iot_agent/config.py` | 配置管理 + `ensure_idalib_config()` |
| `src/iot_agent/tools/ida_mcp.py` | `IDAHeadlessClient` + MCP Client |
| `src/iot_agent/tools/remote_vm.py` | VM SSH 远程执行 |
| `src/iot_agent/tools/firmware_acquire.py` | 固件下载 + `extract()` 标准化到 `rootfs/` |
| `src/iot_agent/tools/firmware_sources.py` | 多源固件搜索（OpenWrt/TP-Link/GitHub） |
| `src/iot_agent/tools/firmware_index.py` | 固件本地 SQLite 索引缓存 |
| `src/iot_agent/tools/emulation_env.py` | QEMU/FirmAE 模拟管理 |
| `.env` | 环境配置（不入库） |
| `.mcp.json` | IDA MCP 连接配置 |

## 分析流程

```
┌── VM (Linux) ──────────────────────────────────────────┐
│                                                        │
│  Level 1: FirmwareAcquirer.extract() → rootfs/         │
│  Level 2: radare2 初筛 → system/sprintf/strcpy 调用者   │
│  Level 4: FirmAE / QEMU 模拟 → PoC 验证                │
│                                                        │
│  需要 IDA 时: vm.download() → Windows                  │
└────────────────────────────────────────────────────────┘
                         │
                         ▼
┌── Windows (IDA) ──────────────────────────────────────┐
│                                                        │
│  Level 3: IDAHeadlessClient.decompile()                │
│  CONFIRMED / DISPROVED / WEAKENED / NEEDS_DYNAMIC      │
└────────────────────────────────────────────────────────┘
```

## 分析结束清理

```python
from iot_agent.tools.ida_mcp import cleanup_ida_files
cleanup_ida_files("<elf_directory>")
```
