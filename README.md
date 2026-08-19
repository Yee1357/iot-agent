# IoT 漏洞挖掘 Agent

通过 Claude Code（Agent 主体）+ MCP 工具链（VM SSH + IDA Pro）进行 IoT 固件解包、二进制逆向、漏洞发现与验证。

**设计原则**：
- Claude Code 是 Agent 主体，不写自定义 agent loop / 记忆——会话续跑靠 Claude Code resume，任务续跑靠 SQLite（AnalysisStore），跨会话经验靠 ExperienceStore（自我迭代）
- 所有工具通过 `iot-agent` MCP server（stdio）暴露，Claude Code 只调工具，不在对话里内嵌 Python
- VM 上只做两级轻量动态验证（-L 快速试错 → chroot 包裹 qemu 的正式验证），系统态模拟（FirmAE / QEMU system）已移除
- 动态验证按证据分级：A 级（单进程直达 sink）完整验证；B 级（需补运行时数据）/ C 级（需多进程/网络/内核）报告静态证据与建议、交用户决策，不硬补

## 系统要求

| 组件 | 要求 |
|------|------|
| **Claude Code** | 已安装，配置 `.mcp.json` |
| **Python** | 3.12+（conda 环境 `iot-agent`） |
| **IDA Pro** | 9.x（headless idalib，可选） |
| **Linux VM** | Ubuntu，SSH 可达，安装 binwalk / radare2 / qemu-user-static |

## 快速安装

```bash
conda create -n iot-agent python=3.12 -y
conda activate iot-agent
pip install -e .
cp .env.example .env   # 编辑填入 VM 和 IDA 配置
```

## MCP 配置（Claude Code 接线）

`.mcp.json` 注册本项目工具链：

```json
{
  "mcpServers": {
    "iot-agent": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "iot_agent.mcp_server"]
    }
  }
}
```

- **首次使用**：在项目目录运行 `claude`，首次启动会提示批准 `iot-agent` server——批准后每次启动自动加载，工具自动暴露给 LLM（无需任何开关）
- **`python` 必须是 conda `iot-agent` 环境的解释器**（否则缺 `mcp` 模块，server 静默失败、工具不出现）。若 `python` 不在 PATH，把 `command` 换成绝对路径（如 `D:\anaconda3\envs\iot-agent\python.exe`）
- 工作目录默认是项目根（无需 `cwd` 字段；如需指定可自行添加）
- **验证**：`claude mcp list` 应显示 `iot-agent: ✓ Connected`；若 ✘ 或 Pending，按上面排查
- **IDA 反编译**：`ida-pro-mcp` 走用户级配置（`claude mcp add` 已注册的 stdio 版，IDA 自带 python 跑插件），不在项目 `.mcp.json` 里重复注册，避免 scope 冲突；无 GUI 时用 `iot_ida_headless_scan`

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
│   ├── config.py                 # 配置
│   ├── mcp_server.py             # MCP server（工具唯一入口，SSH 连接池）
│   └── tools/
│       ├── remote_vm.py          # VM SSH 远程执行（连接复用）
│       ├── firmware_acquire.py   # 固件下载 + extract() 标准化解包
│       ├── firmware_sources.py   # 多源固件搜索（OpenWrt/TP-Link/GitHub）
│       ├── firmware_index.py     # 固件本地 SQLite 索引缓存
│       ├── ida_mcp.py            # IDAHeadlessClient + MCP Client
│       ├── ida_scanner.py        # IDA headless 扫描器（两轮筛选）
│       ├── emulation_env.py      # 动态验证（-L 试错 + chroot 包裹 qemu，无系统态）
│       ├── runtime_assets.py     # chroot 运行时资产（libnvram/busybox）
│       └── analysis_store.py     # 任务/发现/经验持久化（SQLite）
├── .claude/
│   └── skills/
│       ├── iot-agent.md          # 入口：身份 + 路由 + 工具速查
│       ├── iot-vuln-discovery.md # 主力：四级递进漏洞挖掘
│       ├── iot-vuln-patterns.md  # IoT 漏洞模式参考库（含厂商特有模式）
│       ├── iot-emulate-firmware.md # 试错 + chroot+qemu 动态验证
│       ├── iot-cross-model-hunt.md
│       └── iot-patch-bypass.md
├── knowledge/                    # 厂商分析知识库（机器可读，扫描时合并）
│   ├── README.md
│   └── dlink.json
├── .mcp.json
├── .env.example
├── CLAUDE.md                     # Agent 决策中枢（身份/流水线/止损/记忆）
└── pyproject.toml
```

## 分析流程

```
┌── VM ──────────────────────────────────────────────┐
│  Level 1: FirmwareAcquirer.extract() → rootfs/      │
│  Level 2: radare2 初筛 → 候选列表                   │
│  Level 4: -L 试错 → chroot+qemu 正式验证 → PoC 结果  │
└────────────────────────────────────────────────────┘
                       │
                       ▼ (需要 IDA 时 iot_vm_download)
┌── Windows ─────────────────────────────────────────┐
│  Level 3: IDAHeadlessScanner / decompile → verdict  │
│  仅做反编译，每个候选 CONFIRMED/DISPROVED/...        │
└────────────────────────────────────────────────────┘
```

## 断点续跑 & 经验记忆

- **候选级续跑**：任务中断后 `iot_analysis_resume_task(task_id)` 返回未判定候选，已判定 verdict 的自动跳过
- **经验记忆**：`iot_experience_load(vendor, arch)` 开局加载经验摘要；`iot_experience_record(...)` 记录教训；`iot_experience_bump(...)` 迭代反馈
- 数据存于 `data/analysis.db`（SQLite）

## VM 环境安装

```bash
sudo apt install binwalk radare2 squashfs-tools
sudo apt install qemu-user-static   # user-mode 动态验证
```
