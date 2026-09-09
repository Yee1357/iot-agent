---
name: iot-vuln-discovery
description: IoT 固件独立漏洞挖掘。四级递进验证：攻击面识别→radare2初筛→IDA验证→动态验证（user-mode/chroot）。用户要求分析固件、逆向 binary、查找漏洞时使用。
argument-hint: "[firmware|binary]"
---

# IoT 漏洞挖掘工作流

你是资深 IoT 固件安全研究员。漏洞挖掘不是一步到位，而是逐层收敛：

```
Level 1: 攻击面识别 → 找出二进制入口和攻击面
Level 2: 危险 sink 初筛 → 产出候选列表
Level 3: IDA 反编译验证 → 对每个候选给出明确结论
Level 4: 动态验证 → user-mode/chroot 跑起来确认可利用性
```

**关键约束**：Level 3 必须对 Level 2 产出的每个候选逐一给出结论，不允许跳过。**所有工具走 MCP，禁止内嵌 Python。**

---

## Level 1：攻击面识别 + CVE 情报

**目标**：提取型号、版本信息，找出攻击面（CGI、HTTP 服务、网络守护进程）。

1. 固件解包：WebSearch/WebFetch 找官方固件直链 → `iot_firmware_extract(firmware_url_or_path, brand, model, version)` → 得到 rootfs 路径
2. 提取型号/版本（VM）：
   ```
   iot_vm_execute("cat <rootfs>/etc/product.txt <rootfs>/etc/version 2>/dev/null")
   iot_vm_execute("grep -r 'model\\|version\\|firmware' <rootfs>/etc/ --include='*.conf' --include='*.xml' 2>/dev/null | head -20")
   iot_vm_execute("strings <rootfs>/bin/busybox | grep -i 'dlink\\|cisco\\|tplink\\|netgear\\|tenda\\|totolink' | head -5")
   ```
3. 识别攻击面（VM）：
   ```
   iot_vm_execute("find <rootfs> -type f \\( -name '*.cgi' -o -name '*.sh' \\) | head -50")
   iot_vm_execute("grep -r 'httpd\\|lighttpd\\|nginx\\|mini_httpd' <rootfs>/etc/")
   iot_vm_execute("ls <rootfs>/usr/sbin/ <rootfs>/sbin/ <rootfs>/bin/")
   ```
4. 识别架构：`iot_emulation_detect_arch(rootfs)`（L4 也要用）

需要 IDA 反编译时再 `iot_vm_download(remote, "elfs/<binary>")` 传到 Windows。

---

## Level 2：危险 sink 初筛（VM radare2）

**目标**：快速定位危险函数调用者，产出候选列表。**不传文件到 Windows、不启动 IDA。**

### 危险 sink 清单

| 类别 | 函数 | 关注点 |
|------|------|--------|
| 命令执行 | `system`, `popen`, `execve`, `exec*`, `__system` | 参数是否用户可控 |
| 栈溢出 | `sprintf`, `strcpy`, `strcat`, `gets`, `sscanf("%s")` | dst 是否栈缓冲区、src 是否可控 |
| 堆/内存 | `memcpy`, `strncpy`, `malloc(user_val * n)` | size 参数是否可控 |
| 格式化串 | `printf`, `fprintf`, `syslog`, `snprintf` | fmt 是否用户可控 |
| 文件操作 | `fopen`, `read`, `write`, `unlink`, `rename` | path 是否用户可控 |

### 初筛方法（VM，逐 binary 扫描）

```
iot_vm_execute("for bin in <rootfs>/usr/sbin/*; do file $bin | grep -q ELF || continue; echo '=== $bin ==='; r2 -q -c 'aaa; axt sym.imp.system; axt sym.imp.popen' $bin 2>/dev/null; r2 -q -c 'aaa; axt sym.imp.sprintf; axt sym.imp.strcpy; axt sym.imp.strcat' $bin 2>/dev/null; r2 -q -c 'aaa; axt sym.imp.gets; axt sym.imp.memcpy; axt sym.imp.printf' $bin 2>/dev/null; done", timeout=600)
```

stripped ELF 无输出时，改用 `rabin2 -i` / `strings` 兜底。

### 候选列表格式

```
候选 #N | binary | 函数名 | 地址 | sink | 初步判断
```

**优先级判断规则**：

**高优先级**（必须深入分析）：
- `system(user_input)` / `popen(user_input)` — 参数直接来自外部输入
- `sprintf(stack_buf, user_input)` / `strcpy(stack_buf, user_input)` — 用户输入写入栈缓冲区，无长度限制
- 函数名含 `cgi`/`handler`/`parse` + 任一 sink — 网络请求处理路径

**中优先级**（值得看上下文）：
- `sprintf(buf, "%s", user_input)` / `snprintf(buf, size, user_input)` — 有长度限制但内容未过滤
- `system(nvram_get("xxx"))` — 间接可控（NVRAM 可通过 web 修改）
- sink 参数经过字符串拼接（`strcat`/多次 `sprintf`）

**低优先级**（可快速排除）：
- `system("reboot")` / `system("killall httpd")` — 硬编码命令
- `strcpy(local_var, local_const)` — 源是编译期常量
- sink 在 `if (debug)` 或 `#ifdef DEBUG` 分支内

---

## Level 3：IDA 反编译验证（两轮筛选）

### 第一轮：Headless Scanner 自动筛（零 AI 消耗）

```
iot_ida_headless_scan("elfs/<binary>", vendor="<厂商>")
# vendor 可选：合并 knowledge/<vendor>.json 的厂商特有 sink/taint source
#   （如 D-Link 的 lxmldbc_system / sobj_get_string，见 knowledge/vuln-patterns.md 厂商 wrapper）
# 输出：VulnerabilityFinding 列表，每个 finding 只含 sink 附近 ±8 行上下文
```

自动完成：找 sink 调用者 → 排除硬编码参数 → 追踪参数来源标记 taint source → 提取 ±8 行上下文 → 按风险排序。

### 第二轮：AI 精筛 + 深入分析

看第一轮输出，基于 ±8 行上下文判断哪些值得深入。对值得深入的候选，请求完整反编译做数据流追踪（`ida-pro-mcp` 的 `decompile` 工具或 headless）。

### 数据流分析方法

从 sink 参数**逆向追踪**到 source：

1. **确定 sink 参数变量**：`system(arg1)` → arg1 是哪个变量？
2. **追踪变量定义**：向上找赋值链，直到 `getenv`/`recv`/HTTP 字段等 source
3. **识别过滤/转换**：路径上是否有长度限制、内容过滤、编码转换、权限检查
4. **判定可达性**：函数是否在 HTTP 请求处理路径上？是否需要认证？有无前置条件？

### 过滤有效性判断

**无效过滤（标记 CONFIRMED）**：
- `snprintf(buf, 256, "%s", user_input)` — 限长但内容没过滤
- `sprintf(buf, "prefix_%s", user_input)` — 加了前缀但用户部分仍可注入
- `strstr(user_input, ";")` 检查了但**没有拒绝**（结果未用于分支）
- `tolower/toupper/strip` — 不影响命令注入

**有效过滤（标记 DISPROVED）**：
- 硬编码常量：`system("reboot")` — 参数完全不可控
- 白名单校验后才使用：`if (in_whitelist(input)) { system(input); }`
- 截断到不可利用长度：`snprintf(buf, 4, "%s", input)`
- 路径规范化 + 前缀检查：`realpath()` 后验证

**需要动态验证（标记 NEEDS_DYNAMIC）**：
- 缓冲区大小运行时确定（`malloc` 从配置读取）
- 间接调用：`func_ptr(user_input)`
- 过滤函数逻辑复杂无法确定
- 多线程/竞态条件

### 每个候选必须回答的问题

1. **source**：sink 参数从哪来？
2. **路径**：source → ... → sink 经过了什么处理？（逐行列出赋值和调用）
3. **过滤**：路径上有什么过滤？是否有效？（引用具体代码行）
4. **可达性**：从网络请求到该函数是否可达？有无认证？
5. **结论**：CONFIRMED / DISPROVED / WEAKENED / NEEDS_DYNAMIC

### 结论标记

| 结论 | 含义 |
|------|------|
| **CONFIRMED** | 完整数据流：用户输入 → sink，无有效过滤，可达，**且通过 A 级动态验证**（或静态铁证链 + A 级动态） |
| **DISPROVED** | 输入不可控 / 路径不可达 / 经过了有效过滤 |
| **WEAKENED** | 存在隐患但利用受限（需认证、需特定配置、竞态条件） |
| **NEEDS_DYNAMIC** | 静态无法判断，或动态验证依赖 B/C 级环境 |

### 验证边界与证据分级（配合 iot-emulate-firmware 的验证边界）

用户态模拟只能完整验证 **A 级**（单进程内、输入→sink 直接可达）。分级与处理：

| 级别 | 判定 | 处理 |
|------|------|------|
| **A 级** | 输入直达 sink，无运行时数据/多进程/网络依赖 | 完整动态验证 → 可 CONFIRMED |
| **B 级** | 需补少量运行时数据（xmldb/NVRAM）才能走完 | **不硬补**，报告静态证据 + 模拟进度 + 建议，交用户 |
| **C 级** | 需多进程/网络会话/内核接口 | 不验证，报告静态结论 + 建议（真机/系统态），交用户 |

**NEEDS_DYNAMIC 的 notes 必须写明**（禁止笼统标注）：
```
验证级别：B/C
静态证据链：<source → ... → sink，逐环列出>
模拟进度：<实际走到哪一步，如"M-SEARCH 脚本已生成，php 查询 xmldb 接口数据失败">
缺失环境：<如"xmldb /runtime/inf 节点未初始化">
建议：<如"真机复现 / 系统态模拟 / 补 xmldb 数据">
```

**hunt 策略**：L2/L3 优先筛 A 级候选；B/C 级给静态 verdict + 级别标注，不投动态验证时间。

### 落库与进度

每个候选给出结论后立即：
```
iot_analysis_add_finding(task_id, title=..., severity=..., binary_name=..., vulnerable_function=..., vulnerable_address=..., source_sink=..., description=..., confidence=..., verdict="confirmed|disproved|weakened|needs_dynamic")
iot_analysis_mark_level(task_id, 3)
```

---

verdict 判定推演示例见 `knowledge/vuln-patterns.md` §判定推演示例。
---

## Level 4：动态验证（两级：试错 → chroot+qemu 验证）

对 CONFIRMED / WEAKENED / NEEDS_DYNAMIC 的发现做运行时验证。**禁止系统态模拟（FirmAE/QEMU system）**：

1. **架构 + qemu 前置**：`iot_emulation_detect_arch(rootfs)` 判架构；`iot_emulation_ensure_qemu(arch)` 确认 qemu 在位（缺失 → 报告安装命令，走升级路径）
2. **快速试错**：`iot_emulation_user_mode(rootfs, command, arch)` — 便宜确认 sink 是否执行；**结果不作为最终 verdict**（-L 下绝对路径落到 host）
3. **正式验证**：`iot_emulation_chroot_user_mode(rootfs, command, arch, inject_nvram=...)` — chroot 包裹 qemu，guest 看到设备视图（/etc、/tmp、fork/exec 都在 rootfs 内），**唯一 verdict 依据**。详见 `iot-emulate-firmware` skill
4. 验证完成后回填：`iot_analysis_update_finding(finding_id, verdict="confirmed", notes="PoC 结果")`
5. 清理：`iot_emulation_chroot_cleanup(workdir, remove_workdir=True)`

**止损**：每个方案最多尝试 2 次，失败换下一个；全部失败 → 保持 NEEDS_DYNAMIC 并记录原因。

### 输出报告

```
## 漏洞分析报告

| # | 漏洞 | 严重度 | Source → Sink | 结论 |
|---|------|--------|---------------|------|
| 1 | xxx   | HIGH   | getenv("UID") → sprintf → system | CONFIRMED |

### 漏洞 #1 详情
- 位置：<binary> @ <func> @ <addr>
- 数据流：...
- 攻击向量：...
- PoC：...
- 修复建议：...
```

---

## 关键规则

### 系统化覆盖
Level 2 的每个候选必须在 Level 3 给出结论，Level 3 CONFIRMED 的在 Level 4 动态验证。不许跳过。

### 误报识别（标记 DISPROVED）
- sink 参数完全是硬编码常量（如 `system("reboot")`）
- 用户输入经过了有效的白名单校验
- 危险代码在 `#ifdef DEBUG` 等不可达分支
- 缓冲区大小经编译期常量计算，确认安全
- `execve()` 传入 `{"/bin/sh", "-c", hardcoded_string, NULL}`

### 参考资料
- IoT 常见漏洞模式：`knowledge/vuln-patterns.md`（含厂商特有 wrapper 模式，本地知识库）
- 厂商特有 sink/taint 机器清单：`knowledge/<vendor>.json`
- 动态验证细节：`iot-emulate-firmware`
- 发现的真实案例记录到 `AnalysisStore`；经验沉淀到 `iot_experience_record`；
  历史报告批量消化用 `iot_experience_ingest_report`；误报规律查询 `iot_analysis_insights(vendor)`
