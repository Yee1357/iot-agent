# IoT 漏洞挖掘 Agent

通过 IDA Pro（MCP / idalib headless）和 Linux VM 进行 IoT 固件解包、二进制逆向、漏洞发现与验证。

## 系统要求

| 组件 | 要求 |
|------|------|
| **Python** | 3.12+（conda 环境 `iot-agent`） |
| **IDA Pro** | 9.x（GUI + MCP 插件，或纯 headless idalib） |
| **Linux VM** | Ubuntu，SSH 可达，安装 binwalk / radare2 / QEMU / FirmAE |

## 快速安装

```bash
conda create -n iot-agent python=3.12 -y
conda activate iot-agent
pip install -e .
cp .env.example .env   # 编辑填入 VM 和 IDA 配置
```

## 配置

通过 `.env` 文件配置（`IOT_AGENT_` 前缀）：

```bash
# IDA Pro
IOT_AGENT_IDA_INSTALL_DIR=D:/path/to/IDA

# Linux VM
IOT_AGENT_VM_SSH_HOST=your-vm-ip
IOT_AGENT_VM_SSH_PORT=22
IOT_AGENT_VM_SSH_USER=ubuntu
IOT_AGENT_VM_SSH_PASSWORD=your-password
```

## 项目结构

```
iot-agent/
├── src/iot_agent/
│   ├── config.py                 # 配置 + ensure_idalib_config()
│   ├── tools/
│   │   ├── ida_mcp.py            # IDAHeadlessClient + MCP Client
│   │   ├── remote_vm.py          # VM SSH 远程执行
│   │   ├── firmware_acquire.py   # 固件下载 + extract() 标准化解包
│   │   ├── firmware_sources.py   # 多源固件搜索（OpenWrt/TP-Link/GitHub）
│   │   ├── firmware_index.py     # 固件本地 SQLite 索引缓存
│   │   ├── ida_scanner.py        # IDA headless 扫描器（两轮筛选）
│   │   ├── emulation_env.py      # QEMU/FirmAE 模拟管理
│   │   └── analysis_store.py     # 分析结果持久化（SQLite + JSON 导出）
├── .claude/
│   └── skills/
│       ├── iot-agent.md          # 入口：共享设施 + 路由
│       ├── iot-vuln-discovery.md # 主力：四级递进漏洞挖掘
│       ├── iot-vuln-patterns.md  # IoT 漏洞模式参考库
│       ├── iot-emulate-firmware.md
│       ├── iot-cross-model-hunt.md
│       └── iot-patch-bypass.md
├── .mcp.json
├── .env.example
└── pyproject.toml
```

## 分析流程

```
┌── VM ────────────────────────────────────────────┐
│  Level 1: FirmwareAcquirer.extract() → rootfs/    │
│  Level 2: radare2 初筛 → 候选列表                 │
│  Level 4: FirmAE / QEMU 模拟 → PoC 验证           │
└──────────────────────────────────────────────────┘
                       │
                       ▼ (需要 IDA 时 vm.download)
┌── Windows ───────────────────────────────────────┐
│  Level 3: IDAHeadlessClient.decompile() → 验证    │
│  仅做反编译，每个候选 CONFIRMED/DISPROVED/...      │
└──────────────────────────────────────────────────┘
```

## VM 环境安装

```bash
sudo apt install binwalk radare2 squashfs-tools
sudo apt install qemu-system-mips qemu-system-arm qemu-user-static
git clone https://github.com/pr0v3rbs/FirmAE /opt/firmae
cd /opt/firmae && ./install.sh
```
