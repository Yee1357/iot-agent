---
name: iot-patch-bypass
description: 补丁绕过分析。获取新旧版本固件，比对差异，分析厂商的修复是否可以绕过。用户要求分析补丁效果、绕过修复、对比固件版本时使用。
argument-hint: "[old_version] [new_version]"
---

# 补丁绕过分析

有些厂商的修复只堵了表面的 PoC，换个参数或入口就能绕过。目标是分析修复的实际效果。

## 工作流程

### Step 1：漏洞情报

确认已知漏洞：
- CVE 编号
- 受影响版本范围
- 漏洞机理（Source → Sink）
- 已公开的 PoC

### Step 2：获取新旧版本固件

```python
async with VMRemoteExecutor() as vm:
    # 确保新旧两个版本的固件都已下载
    await vm.execute("ls /data/firmwares/<vendor>/<model>_v1/")
    await vm.execute("ls /data/firmwares/<vendor>/<model>_v2/")
```

### Step 3：解包

两个版本分别 binwalk 解包。

### Step 4：定位修补位置

**IDA Pro MCP 方法（推荐）**：

分别加载新旧两个 binary → `decompile` 漏洞函数 → 逐行对比伪代码差异。

**VM radare2 辅助**：
```bash
# 函数级对比：哪些函数大小变了
r2 -q -c 'aac; afl~[0]' <old_binary> | sort > /tmp/old_funcs.txt
r2 -q -c 'aac; afl~[0]' <new_binary> | sort > /tmp/new_funcs.txt
diff /tmp/old_funcs.txt /tmp/new_funcs.txt
```

### Step 5：分类修复质量

| 修复类型 | 描述 | 绕过难度 |
|---------|------|---------|
| **输入校验** | 增加了长度检查、白名单过滤 | 低——可能只检查了一处入口 |
| **黑名单** | 过滤特定字符（如 `;`、`|`） | 低——换个字符或编码方式可能绕过 |
| **函数替换** | `system()` → `execve()` | 低——检查其他 system() 调用点 |
| **认证前置** | 在漏洞代码前加了权限检查 | 中——需要先获得认证 |
| **重构** | 重写了整个处理逻辑 | 高——可能需要全新漏洞挖掘 |

### Step 6：绕过可行性评估

对每个差异点，问三个问题：

1. **修复是否完备**？
   - 黑名单：漏了哪些字符？换编码能不能过？
   - 白名单：规则是否足够严格？
   - 长度检查：只检查了一处还是所有入口？

2. **修复是否覆盖所有路径**？
   - 同一函数有没有多个入口能触发同一个 sink？
   - 同一 binary 的其他函数有没有相同的漏洞模式？
   - `system()` 被替换成 `execve()`，但附近有没有另一个 `system()` 没被替换？

3. **修复是否引入新问题**？
   - 新增的过滤函数本身有没有漏洞？
   - 新增的认证检查是否真正有效？

### Step 7：验证

对发现的可绕过路径，在 QEMU 上验证（参见 `iot-emulate-firmware`）。

### Step 8：输出报告

```
## 补丁绕过分析报告

### 修补方式
厂商在 <function> 中增加了对 <parameter> 的 <validation>。

### 绕过路径
1. <另一个参数> 走相同的 sink，未被过滤
2. 换用 <编码方式> 可绕过黑名单
3. ...

### 结论
- 修复质量：低/中/高
- 是否完全修复：是/否
- 若否，新漏洞严重度：...
```
