# IoT 漏洞挖掘 Agent

把 Claude Code 变成 IoT 固件漏洞挖掘助手。Claude 通过 MCP 调用工具，在 Linux VM 上完成固件解包、危险函数初筛、qemu 动态验证，可选在 Windows + IDA Pro 做反编译核查；任务、发现和经验记忆落在本地 SQLite。所有结论要求 source→sink 证据链，不允许纯模式猜测。

> 个人研究项目。核心价值是跨会话复用：断点续跑、经验记忆、厂商知识累积。

## 工作流程

一次分析分四级渐进验证，结论统一标记为 `CONFIRMED / DISPROVED / WEAKENED / NEEDS_DYNAMIC`：

| 级 | 做什么 | 在哪执行 |
|----|--------|----------|
| L1 攻击面 | 固件解包，建模号/版本/架构 + CGI、httpd、网络守护进程清单 | VM |
| L2 初筛 | radare2 扫 `system`/`sprintf`/`strcpy` 等危险 sink 的调用者，产出候选列表 | VM |
| L3 反编译 | IDA headless 逐候选追踪参数来源，核查 source→sink 数据流 | Windows（可选） |
| L4 动态验证 | qemu-user 快速试错 → chroot 包裹 qemu 正式验证 | VM |

流程细节由 `.claude/skills/` 下的 skill 定义（`iot-vuln-discovery` 等），不需要读代码也能跑通。任务与发现实时落库，中断后按未决候选续跑。

## 组成

| 组件 | 角色 |
|------|------|
| Claude Code | Agent 主体：决策、推进、verdict 判定（行为约束见 `CLAUDE.md`） |
| iot-agent MCP server | 唯一工具接口，stdio 暴露 `iot_*` 系列工具 |
| Linux VM | 执行层：解包 / radare2 / qemu 动态验证（SSH） |
| IDA Pro（可选） | L3 反编译核查，仅 Windows |
| SQLite | `data/analysis.db`：任务、发现、经验记忆 |

除 IDA 反编译在 Windows 外，其余操作全部在 VM 上完成。

## 环境要求

- **Windows 本机**：Python 3.12（conda）、Claude Code，可选 IDA Pro 9.x
- **Linux VM**：`binwalk radare2 squashfs-tools qemu-user-static`，SSH 可达

## 安装

```bash
conda create -n iot-agent python=3.12 -y
conda activate iot-agent
pip install -e .
cp .env.example .env   # 填 VM SSH 与 IDA 路径
```

- `.mcp.json` 已注册 `iot-agent` server（经 `conda run -n iot-agent` 启动），项目目录启动 `claude` 即自动拉起，`iot_*` 工具直接可用
- 大部分操作依赖 VM；仅对已有 ELF 跑 IDA headless 扫描时可不连 VM

## 使用

项目目录下启动 `claude`，直接说目标，例如：

> 分析某品牌某型号路由器固件
> 验证这个 httpd 的 RCE
> 对比新旧固件，看漏洞修没修、能不能绕过

Claude 按描述自动调起对应 skill；也可直接 `/iot-vuln-discovery`、`/iot-patch-bypass` 等显式触发。

工具族一览（MCP 工具名统一 `iot_` 前缀）：

| 工具族 | 用途 |
|--------|------|
| `iot_vm_*` | VM shell 执行 / 文件传输 |
| `iot_firmware_*` | 固件下载、解包、缓存查询 |
| `iot_emulation_*` | 架构判定 / qemu 定位 / 两级动态验证 / 清理 |
| `iot_analysis_*` | 任务与发现落库 / 续跑 / 统计 |
| `iot_experience_*` | 经验记忆：记录、加载、反馈迭代 |
| `iot_ida_*` / `iot_knowledge_*` | IDA headless 扫描 / 厂商 sink 知识合并 |

## License

MIT