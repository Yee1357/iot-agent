---
name: iot-vuln-discovery
description: IoT 固件独立漏洞挖掘。三级递进验证：攻击面识别→radare2初筛→IDA验证→动态验证。用户要求分析固件、逆向 binary、查找漏洞时使用。
argument-hint: "[firmware|binary]"
---

# IoT 漏洞挖掘工作流

你是 IoT 固件漏洞挖掘专家。

| 环境 | 用途 |
|------|------|
| **VM (Linux)** | Level 1 解包、Level 2 radare2 初筛、Level 4 QEMU 动态验证 + PoC |
| **Windows (IDA)** | **仅** Level 3 反编译验证 |

**除了 IDA 反编译，其他所有操作都在 VM 上完成。**

## 四级验证流程

漏洞挖掘不是一步到位，而是逐层收敛：

```
Level 1: 攻击面识别 → 找出二进制入口和攻击面
Level 2: 危险 sink 初筛 → 产出候选列表
Level 3: IDA 反编译验证 → 对每个候选给出明确结论
Level 4: 动态验证 → QEMU 跑起来确认可利用性
```

每一层都可能排除掉上一层的候选。**关键约束**：在 Level 3 中，必须对 Level 2 产出的每个候选逐一给出结论，不允许跳过。

---

## Level 1：攻击面识别 + CVE 情报

### 目标
从固件中提取型号、版本信息，找出攻击面（CGI、HTTP 服务、网络守护进程）。

### 步骤

**1a. 固件解包 + 标准化（VM）**

```python
from iot_agent.tools.firmware_acquire import FirmwareAcquirer
from iot_agent.tools.remote_vm import VMRemoteExecutor

async with VMRemoteExecutor() as vm:
    acquirer = FirmwareAcquirer(vm)
    rootfs = await acquirer.extract("<firmware_path>", brand="dlink", model="dir-815", version="v1")
    # Output: /data/extracted/dlink/dir-815_v1/rootfs/
```

**1b. 提取型号/版本信息（VM）**

```bash
cat <rootfs>/etc/product.txt <rootfs>/etc/version 2>/dev/null
grep -r "model\|version\|firmware" <rootfs>/etc/ --include="*.conf" --include="*.xml" 2>/dev/null | head -20
strings <rootfs>/bin/busybox | grep -i "dlink\|cisco\|tplink\|netgear\|tenda\|totolink" | head -5
```

**1c. 识别攻击面（VM）**

```bash
find <rootfs> -type f \( -name "*.cgi" -o -name "*.sh" \) | head -50
grep -r "httpd\|lighttpd\|nginx\|mini_httpd" <rootfs>/etc/
ls <rootfs>/usr/sbin/ <rootfs>/sbin/ <rootfs>/bin/
```

**1d. 识别 ELF 架构（VM）**
```bash
file <rootfs>/usr/sbin/* <rootfs>/bin/* | grep ELF
readelf -h <binary> | grep -E "Class|Machine"
```

需要 IDA 反编译时再 `vm.download()` 传到 Windows。

---

## Level 2：危险 sink 初筛（VM radare2）

### 目标
在 VM 上用 radare2 快速定位危险函数调用者，产出候选列表。**不传文件到 Windows、不启动 IDA**——token 消耗最小。

### 危险 sink 清单
| 类别 | 函数 | 关注点 |
|------|------|--------|
| 命令执行 | `system`, `popen`, `execve`, `exec*`, `__system` | 参数是否用户可控 |
| 栈溢出 | `sprintf`, `strcpy`, `strcat`, `gets`, `sscanf("%s")` | dst 是否为栈缓冲区、src 是否可控 |
| 堆/内存 | `memcpy`, `strncpy`, `malloc(user_val * n)` | size 参数是否可控 |
| 格式化串 | `printf`, `fprintf`, `syslog`, `snprintf` | fmt 是否用户可控 |
| 文件操作 | `fopen`, `read`, `write`, `unlink`, `rename` | path 是否用户可控 |

### 初筛方法

```bash
# VM 上逐 binary 扫描
for bin in <rootfs>/usr/sbin/*; do
    file $bin | grep -q ELF || continue
    echo "=== $bin ==="
    # system/popen 调用者
    r2 -q -c 'aaa; axt sym.imp.system; axt sym.imp.popen' $bin 2>/dev/null
    # sprintf/strcpy/strcat 调用者
    r2 -q -c 'axt sym.imp.sprintf; axt sym.imp.strcpy; axt sym.imp.strcat' $bin 2>/dev/null
    # gets/memcpy/printf 调用者
    r2 -q -c 'axt sym.imp.gets; axt sym.imp.memcpy; axt sym.imp.printf' $bin 2>/dev/null
done
```

### 候选列表格式

过滤后记录：

```
候选 #N | binary | 函数名 | 地址 | sink | 初步判断
```

**优先级判断规则：**

**高优先级**（必须深入分析）：
- `system(user_input)` / `popen(user_input)` — 参数直接来自外部输入
- `sprintf(stack_buf, user_input)` — 用户输入写入栈缓冲区，无长度限制
- `strcpy(stack_buf, user_input)` — 同上
- 函数名含 `cgi`/`handler`/`parse` + 任一 sink — 网络请求处理路径

**中优先级**（值得看上下文）：
- `sprintf(buf, "%s", user_input)` — 有格式化但不限制内容
- `snprintf(buf, size, user_input)` — 有长度限制但内容未过滤
- `system(nvram_get("xxx"))` — 间接可控（如果 NVRAM 可通过 web 修改）
- sink 的参数经过字符串拼接（`strcat`/多次 `sprintf`）

**低优先级**（可快速排除）：
- `system("reboot")` / `system("killall httpd")` — 硬编码命令
- `strcpy(local_var, local_const)` — 源是编译期常量
- `sprintf(buf, "Content-Type: text/html")` — 固定 HTTP 头
- sink 在 `if (debug)` 或 `#ifdef DEBUG` 分支内

---

## Level 3：IDA 反编译验证（两轮筛选）

### 目标
对 Level 2 产出的每个候选，通过 IDA 反编译追踪数据流，给出明确结论。

### 第一轮：Headless Scanner 自动筛（零 AI 消耗）

用 `IDAHeadlessScanner` 在 headless IDA 中跑 Python 自动分析：

```python
from iot_agent.tools.ida_mcp import IDAHeadlessClient
from iot_agent.tools.ida_scanner import IDAHeadlessScanner

with IDAHeadlessClient("elfs/<binary>") as ida:
    scanner = IDAHeadlessScanner(ida)
    findings = scanner.systematic_scan()
    # 输出：VulnerabilityFinding 列表
    # 每个 finding 的 decompiled_code 只包含 sink 附近 ±8 行上下文
```

自动完成：
1. 找所有 sink 调用者（system/sprintf/strcpy 等）
2. 排除硬编码参数（如 `system("reboot")`）
3. 追踪参数来源，标记 taint source（getenv/recv 等）
4. 提取 sink 附近 ±8 行上下文（不是整个函数）
5. 按风险排序

### 第二轮：AI 精筛 + 深入分析

AI 看第一轮输出的候选列表，基于 ±8 行上下文快速判断哪些值得深入。

对值得深入的候选，请求完整反编译做数据流追踪：

```python
full_code = ida.decompile(candidate.vulnerable_address)
```

### 数据流分析方法

对每个候选，从 sink 的参数**逆向追踪**到 source：

**步骤 1：确定 sink 的参数变量**
```
system(arg1)  →  arg1 是哪个变量？
sprintf(dst, fmt, arg2)  →  arg2 是哪个变量？
```

**步骤 2：追踪变量定义**
向上查找该变量的赋值：
```
arg1 = buf
buf = strcat(prefix, user_data)  ← 找到拼接点
user_data = getenv("QUERY_STRING")  ← 找到 source
```

**步骤 3：识别过滤/转换**
在 source→sink 路径上，检查是否存在：
- 长度限制：`snprintf`、`strncpy`、`memcpy` 带固定 size
- 内容过滤：`strchr`/`strstr` 检查后拒绝、白名单函数、正则匹配
- 编码转换：`urlencode`/`htmlencode`（可能不充分）
- 权限检查：`check_auth()`、cookie 验证

**步骤 4：判定可达性**
- 该函数是否在 HTTP 请求处理路径上？（CGI handler、URL router）
- 是否需要认证？（查 `check_auth`/`session_verify` 调用）
- 是否有前置条件？（特定 HTTP method、特定 URL path）

### 过滤有效性判断

**无效过滤（仍然危险，标记 CONFIRMED）：**
- `snprintf(buf, 256, "%s", user_input)` — 限制了长度但内容没过滤，溢出仍可能
- `sprintf(buf, "prefix_%s", user_input)` — 加了前缀但用户部分仍可触发注入
- `strstr(user_input, ";")` 检查了但**没有拒绝**（检查结果未用于分支）
- `tolower(user_input)` / `toupper(user_input)` — 大小写转换不影响命令注入
- `strip(user_input)` — 去空格不影响 `;id` 这类 payload

**有效过滤（可以排除，标记 DISPROVED）：**
- 硬编码常量：`system("reboot")` — 参数完全不可控
- 白名单校验后才使用：`if (in_whitelist(input)) { system(input); }` — 只允许已知值
- 截断到不可利用长度：`snprintf(buf, 4, "%s", input)` — 4 字节无法注入有意义的命令
- 路径规范化 + 检查：`realpath()` 后验证前缀 — 路径遍历被阻止

**需要动态验证（标记 NEEDS_DYNAMIC）：**
- 缓冲区大小在运行时确定（`malloc` 从配置读取）
- 间接调用：`func_ptr(user_input)` — 无法静态确定目标
- 过滤函数逻辑复杂，无法确定是否充分
- 多线程/竞态条件场景

### 每个候选必须回答的问题

1. **source**：sink 参数从哪来？（getenv、recv、read、HTTP 字段）
2. **路径**：source → ... → sink 经过了什么处理？（逐行列出赋值和函数调用）
3. **过滤**：路径上有什么过滤？是否有效？（引用具体代码行）
4. **可达性**：从网络请求到这个函数，路径是否可达？有无认证？
5. **结论**：基于以上分析，标记 CONFIRMED/DISPROVED/WEAKENED/NEEDS_DYNAMIC

### 结论标记

| 结论 | 含义 |
|------|------|
| **CONFIRMED** | 完整数据流：用户输入 → sink，无有效过滤，可达 |
| **DISPROVED** | 输入不可控（硬编码常量）/ 路径不可达 / 经过了有效过滤 |
| **WEAKENED** | 存在隐患但利用受限（需认证、需特定配置、竞态条件） |
| **NEEDS_DYNAMIC** | 静态分析无法判断，需 QEMU 跑起来验证（缓冲区大小在运行时确定、间接跳转等） |

### 必须核查的攻击面（逐项覆盖）

对第一轮筛出的每个候选，逐个给出结论：

```
第一轮：IDAHeadlessScanner.systematic_scan() → 候选列表
第二轮：对每个候选：
  1. 读 ±8 行上下文 → 快速判断是否值得深入
  2. 值得深入 → decompile 完整函数
  3. 追踪 sink 参数的数据流
  4. 判断漏洞类别 + 标记结论
```

**不允许跳过任何一个候选。** 发现 CONFIRMED 后继续分析剩余候选。

---

## Level 4：CVE 匹配 + 动态验证

### 4a. 动态验证（VM）

对 CONFIRMED/WEAKENED/NEEDS_DYNAMIC 的发现进行运行时验证。
优先用 FirmAE，失败再用手动 QEMU。详见 `iot-emulate-firmware` skill。

### 4b. 输出报告

```
## 漏洞分析报告

| # | 漏洞 | 严重度 | Source → Sink | 结论 |
|---|------|--------|---------------|------|-----|
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
Level 2 的每个候选必须在 Level 3 中给出结论，Level 3 CONFIRMED 的在 Level 4 动态验证。不许跳过。

### 误报识别
以下情况标记 DISPROVED：
- sink 的参数完全是硬编码常量（如 `system("reboot")`）
- 用户输入经过了有效的白名单校验
- 危险代码在 `#ifdef DEBUG` 等不可达分支
- 缓冲区大小经编译期常量计算，确认安全
- `execve()` 但传入的是 `{"/bin/sh", "-c", hardcoded_string, NULL}`（非 `execve` 本身，而是参数不可控）

### 参考资料
- IoT 常见漏洞模式：`iot-vuln-patterns.md`
- 发现的真实案例记录到 `AnalysisStore`，后续可作为参考积累
