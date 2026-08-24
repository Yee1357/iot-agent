---
name: iot-cross-model-hunt
description: 跨型号漏洞传播分析。已知某型号存在漏洞，检查同品牌其他型号是否也受影响。用户要求跨型号分析、漏洞传播评估、漏洞影响范围评估时使用。
argument-hint: "[known_model] [vuln_description]"
---

# 跨型号漏洞传播分析

同一厂商的不同产品经常共用底层代码库和 CGI handler，一个型号的漏洞往往影响其他型号。

## 工作流程

### Step 1：漏洞情报收集

复述已知漏洞：
- 漏洞 binary 和函数名
- Source → Sink 数据流
- CVE 编号（如有）
- 当前确认受影响的型号

### Step 2：获取同品牌其他型号固件

用 WebSearch/WebFetch 找该型号官方固件直链后 `iot_firmware_extract(url, brand=..., model=..., version=...)` 下载解包，或 `iot_vm_execute("ls /data/firmware/")` 查看 VM 上已有固件。

### Step 3：解包

对每个型号的固件执行 binwalk 解包（参见 `iot-vuln-discovery` Level 1）。

### Step 4：分析已知漏洞特征

提取漏洞的**可搜索特征**——不依赖型号名、不依赖具体地址，而是代码层面的特征：

| 特征类型 | 示例 |
|---------|------|
| 函数名 | `hedwigcgi_main`、`hnap_main` |
| 字符串常量 | 错误消息、日志格式串 |
| 调用模式 | `getenv("HTTP_SOAPACTION")` → `system()` |
| 二进制哈希 | 疑似同源 .so 的符号相似度 |

### Step 5：跨型号比对

对每个型号：
1. 搜索同名 binary（如 `cgibin`、`httpd`）
2. 搜索同名函数（`list_funcs` → `decompile`）
3. 对比伪代码差异：
   - 完全相同 → **大概率受影响**
   - 函数存在但伪代码有差异 → 需详细对比
   - 函数不存在 → **不受影响**（但需检查是否改名或重构）

### Step 6：动态验证

对可疑受影响的型号，选 1-2 个用两级验证（参见 `iot-emulate-firmware`）：
- 试错：`iot_emulation_user_mode(rootfs, command, arch)`（先 `iot_emulation_detect_arch` + `iot_emulation_ensure_qemu`）
- 正式验证：`iot_emulation_chroot_user_mode(rootfs, command, arch)`，验证完 `iot_emulation_chroot_cleanup(workdir, remove_workdir=True)`

### Step 7：输出影响范围报告

```
| 型号 | 是否存在漏洞函数 | 差异描述 | 验证状态 |
|------|-----------------|---------|---------|
| DIR-645 | 存在，代码一致 | 无差异 | CONFIRMED |
| DIR-815 | 存在，代码一致 | 无差异 | CONFIRMED |
| DIR-860L | 存在，有差异 | system() 调用前增加了白名单检查 | DISPROVED |
```

**经验沉淀**：跨型号比对发现的可复用模式（如"某函数在所有型号都无过滤"）记录到 `iot_experience_record(category="pattern", ...)`。

---

## 注意事项

- 不要仅凭函数名相同就下结论，必须对比伪代码
- 关注编译优化导致的差异（同一源码不同编译选项可能生成不同的反编译结果）
- 部分厂商在不同型号中改名但逻辑相同（如 `do_hnap` → `hnap_handler`）
