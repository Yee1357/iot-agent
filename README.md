# IoT 漏洞挖掘 Agent

基于 **Claude Code + MCP 工具链**的 IoT 固件漏洞挖掘助手：自动完成固件下载解包、攻击面识别、危险函数初筛、IDA 反编译验证与动态验证，产出带完整证据链的漏洞报告。

## 功能

- **固件获取与解包**：agent 用 WebSearch 定位官方固件直链 → VM 下载 → binwalk 递归解包并自动定位 rootfs
- **四级挖掘流水线**：
  - **L1 攻击面识别**：型号 / 版本 / 架构 + CGI、httpd、网络守护进程清单
  - **L2 危险 sink 初筛**：radare2 扫描 system / sprintf / strcpy 等危险函数调用者，产出按优先级排序的候选列表
  - **L3 反编译验证**：IDA headless 扫描（自动排除硬编码参数、追踪参数来源、提取上下文），逐候选给出 verdict
  - **L4 动态验证**：qemu user-mode 快速试错 → chroot 包裹 qemu 正式验证（无 binfmt 依赖、无系统态模拟）
- **verdict 体系**：CONFIRMED / DISPROVED / WEAKENED / NEEDS_DYNAMIC，结论必须来自 source→sink 证据链
- **断点续跑**：任务与发现实时落库，中断后按未决候选恢复
- **经验记忆**：跨会话沉淀漏洞模式 / 误报规律 / 验证技巧，支持反馈迭代与历史报告批量消化
- **厂商知识合并**：`knowledge/<vendor>.json`（本地维护）登记厂商特有 sink / taint source，扫描时自动并入
- **自动止损**：循环检测与尝试硬上限，环境受阻按四级路径升级、必要时交用户决策

## 架构

| 层 | 组件 | 职责 |
|----|------|------|
| Agent 主体 | Claude Code | 决策、流程推进、verdict 判定（策略见 `CLAUDE.md` 与 `.claude/skills/`） |
| 工具层 | iot-agent MCP server | 唯一工具入口，`iot_*` 工具经 stdio 暴露 |
| 执行层 | Linux VM（SSH） | 解包、radare2 初筛、动态验证（user-mode / chroot） |
| 反编译层 | Windows + IDA Pro | L3 反编译（headless / ida-pro-mcp，可选） |
| 数据层 | SQLite | 任务 / 发现 / 经验持久化（本地，不入库） |

**原则：除 IDA 反编译外，所有操作都在 VM 上完成。**

## 快速开始

```bash
conda create -n iot-agent python=3.12 -y
conda activate iot-agent
pip install -e .
cp .env.example .env   # 填写 VM SSH 与 IDA 配置
```

- `.mcp.json` 已注册 `iot-agent` server 并指向 conda 环境的 Python 绝对路径，`.claude/settings.json` 已预授权：项目目录运行 `claude` 后 `iot_*` 工具自动可用，无需手动批准
- VM 安装：`sudo apt install binwalk radare2 squashfs-tools qemu-user-static`
- IDA Pro 9.x 可选（headless idalib）

## 使用

在 Claude Code 中说「分析 <品牌型号> 固件」，自动触发 `iot-vuln-discovery` 工作流。工具族：

| 工具族 | 用途 |
|--------|------|
| `iot_vm_*` | VM shell / 文件传输 |
| `iot_firmware_*` | 固件下载解包 / 缓存查询 |
| `iot_emulation_*` | 架构判定 / qemu 定位 / 两级动态验证 / 清理 |
| `iot_analysis_*` | 任务与发现持久化 / 续跑 / 统计 |
| `iot_experience_*` | 经验记录 / 加载 / 反馈 / 报告消化 |
| `iot_ida_*` / `iot_knowledge_*` | headless 扫描 / 厂商知识 |

## 数据与隐私

- 任务、发现、经验存于本地 `data/analysis.db`；固件缓存与索引在 `data/firmwares/`、`data/firmware_index.db`；历史报告消化源在 `data/my_vuln_reports/`；报告在 `reports/`；ELF 在 `elfs/`；厂商知识 json 在 `knowledge/` —— 以上均为本地数据，已被 `.gitignore` 排除，不会进入 Git 仓库
- `knowledge/README.md` 仅保留说明文档，具体厂商知识 `<vendor>.json` 只存本地
- 报告与经验禁止出现机器特定路径（约定路径与占位符），保证跨会话安全复用
- 迁移机器时拷贝 `data/` 与 `knowledge/` 即可带走全部积累

## 目录

```
src/iot_agent/        # MCP server 与工具实现
.claude/skills/       # 工作流 skill（路由 / 挖掘 / 验证 / 模式库）
knowledge/            # 厂商知识：README.md 入库，<vendor>.json 仅本地
data/                 # 本地数据库（analysis.db 经验库、固件缓存与索引、历史报告消化源）
reports/              # 分析报告（本地）
back_paths/           # 本地攻击面/路径分析产物（不入库）
CLAUDE.md             # Agent 决策中枢
```