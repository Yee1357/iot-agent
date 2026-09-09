---
name: iot-agent
description: IoT 固件漏洞挖掘 Agent 的入口 skill。任何 hunt 的开局必读：路由到专项 skill、MCP 工具速查、开局/收尾检查单、经验记忆流程、止损提问格式。用户要求分析固件、验证漏洞、跨型号分析、补丁绕过等任何 IoT 安全任务时使用。
argument-hint: "[firmware|binary|report]"
---

# IoT 漏洞挖掘 Agent（入口）

身份、架构分工、硬约束（止损上限 / L3 升级 / 经验回写 / 清理）见 `CLAUDE.md`，本 skill 不重复。

## 工作流路由

| 任务 | Skill |
|------|-------|
| 独立漏洞挖掘（主力工作流） | `iot-vuln-discovery` |
| 动态验证（user-mode/chroot） | `iot-emulate-firmware` |
| 已知漏洞的跨型号影响 | `iot-cross-model-hunt` |
| 固件补丁绕过分析 | `iot-patch-bypass` |

> 知识参考：漏洞模式读 `knowledge/vuln-patterns.md`；qemu/仿真环境坑读
> `knowledge/emulation-experiences.md`；紧凑经验用 `iot_experience_load()` 加载。

## 开局与收尾检查单

**开局**：
1. `iot_vm_check_tools()` 确认环境就绪（缺工具 → 报告修复方向）
2. `iot_experience_load(vendor=目标厂商, arch=已知架构)` + `iot_analysis_insights(vendor=...)` 加载经验与误报洞察
3. 续跑场景：`iot_analysis_list_tasks(status="running")` → `iot_analysis_resume_task(task_id)` → 从 pending 候选继续

**收尾**：
1. `iot_analysis_mark_completed(task_id)`（或 mark_failed 注明原因）
2. 1-3 条本次教训 `iot_experience_record` 入库
3. `iot_ida_cleanup()` / `iot_emulation_chroot_cleanup()` 清理
4. 报告写入 `reports/`

## MCP 工具速查

### VM / shell
- `iot_vm_execute(command, timeout)` — VM 上执行任意命令（连接池复用，多次调用便宜）
- `iot_vm_check_tools()` — 检查 VM 工具安装（binwalk/radare2/qemu-user/python3）
- `iot_vm_upload(local, remote)` / `iot_vm_download(remote, local)` — SFTP 传文件

### 固件
- `iot_firmware_extract(url_or_path, brand, model, version)` — 下载（URL）+ 解包，返回 rootfs 路径。URL 由 agent 用 WebSearch/WebFetch 找官方直链（优先厂商官网，避免社区第三方镜像）
- `iot_firmware_list_cached(...)` / `iot_firmware_cache_stats()` / `iot_firmware_cache_status()` — 缓存查询

### 动态验证（L4，两级：试错 → chroot+qemu 验证）
- `iot_emulation_detect_arch(rootfs)` — 判定架构（mips/mipsel/arm/...），不要猜
- `iot_emulation_ensure_qemu(arch)` — 定位 qemu-user 二进制（PATH → /usr/local/bin → find 兜底）
- `iot_emulation_user_mode(rootfs, command, arch)` — **快速试错**（-L），结果不作为最终 verdict
- `iot_emulation_chroot_user_mode(rootfs, command, arch, inject_nvram)` — **正式验证**（chroot 包裹 qemu），唯一 verdict 依据
- `iot_emulation_chroot_cleanup(workdir, process_match, remove_workdir)` — 杀进程 + 卸载 + 删工作副本

### 分析持久化
- `iot_analysis_create_task(...)` / `iot_analysis_add_finding(...)` / `iot_analysis_update_finding(id, verdict, notes)`
- `iot_analysis_mark_level(task_id, level)` / `iot_analysis_mark_completed` / `iot_analysis_mark_failed`
- `iot_analysis_list_tasks(...)` / `iot_analysis_get_findings(task_id, verdict)` / `iot_analysis_resume_task(task_id)` / `iot_analysis_export_task(task_id)` / `iot_analysis_stats()`

### 经验记忆
- `iot_experience_load(vendor, arch, category, limit)` — 开局加载经验摘要
- `iot_experience_record(category, scenario, detail, vendor, arch)` — 记录经验（scenario+vendor+arch 唯一 upsert）
- `iot_experience_bump(exp_id, success)` — 迭代反馈
- `iot_experience_ingest_report(report_path, vendor, arch)` — 批量消化历史报告进经验库
- `iot_experience_export_markdown(category, min_success)` — 导出成熟经验供固化回写（≥3 次成功的 pattern 固化到 `knowledge/vuln-patterns.md` 或 `knowledge/<vendor>.json`）
- `iot_analysis_insights(vendor)` — 历史 verdict 聚合（哪些 sink 误报率高）
- `iot_experience_stats()` — 经验统计

### IDA / 知识库
- `iot_ida_headless_scan(binary_path, vendor="")` — headless 两轮筛选（传 vendor 合并 `knowledge/<vendor>.json` 厂商特有 sink/taint）
- `iot_knowledge_vendors()` — 列出 knowledge/ 有哪些厂商知识文件
- `iot_ida_cleanup(elf_directory)` — 清理 IDA 临时文件

## 经验记忆流程（自我迭代，半自动）

- **开局加载**：`iot_experience_load(vendor=..., arch=...)` + `iot_analysis_insights(vendor=...)`（哪些 sink 误报率高）
- **历史报告消化**：`iot_experience_ingest_report("reports/<xxx>.md", vendor=..., arch=...)`（开局或收尾做一次）
- **关键节点记录**（立即 `iot_experience_record`）：
  - `env`：环境坑及解法（如"某厂商固件需先挂载 jffs2"）
  - `pattern`：可复用漏洞模式（如"D-Link cgibin 的 sobj_get_string 是 taint source"）
  - `false_positive`：误报规律（如"system 参数经 xmldbc 白名单校验，不可控"）
  - `verification`：验证技巧（如"chroot+qemu 验证需要工作副本"）
- **经验回写（强制，每洞一次）**：候选动态复现成功或明确受阻后，先 `iot_experience_record` 入库（先加载/查重，语义重叠 bump 原条目），环境坑长文增量更新 `knowledge/emulation-experiences.md`（查重纪律见该文档头部，语义重叠合入或交叉引用），**然后**才进下一个候选。原则：逐洞沉淀，不攒批。
- **hunt 结束**：最重要的 1-3 条教训入库
- **迭代反馈**：再次验证有效 → `iot_experience_bump(exp_id, success=True)`；证伪 → bump(False)
- **固化回写**：pattern 类经验累计成功 ≥3 → `iot_experience_export_markdown(category="pattern", min_success=3)` 导出，人工固化到 `knowledge/vuln-patterns.md` 或 `knowledge/<vendor>.json`

## L3 升级提问格式（触发条件见 CLAUDE.md 硬约束）

```text
受阻原因：<一句话说明卡在哪>
已尝试：<列表，含次数与变体>
失败根因（如有）：<证据，如日志片段>
可选路径：
  A. <路径 + 成本/风险>
  B. <路径 + 成本/风险>
  C. 终止本次 hunt（保留续跑点）
建议：<推荐 A/B/C 及理由>
```

机制：用 `ask_user` 工具提问（用户可点选），不要用普通文本长问；提问前先 `iot_analysis_mark_level` 落库，保证用户选"终止"后可无缝续跑。

## 报告规范

报告/经验中禁止机器特定路径（本机绝对路径、用户名、`/home/xxx`、`C:\Users\xxx`）。统一约定路径：rootfs 写 `/data/extracted/<brand>/<model>_<ver>/rootfs`，本地 ELF 写 `elfs/<binary>`，VM 日志写 `/tmp/xxx.log`。原因：报告会被 `iot_experience_ingest_report` 消化成经验跨会话复用，隐私路径会误导后续 hunt。经验库只沉淀可复用知识；入库后抽查 `detail`，发现隐私信息立即用 `iot_experience_record` 刷新或删除。
