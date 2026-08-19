# Vendor Analysis Knowledge (厂商分析知识库)

**工具代码保持厂商无关**。厂商特有的 sink / taint source / 分类规则放在本目录，
由 `ida_scanner.py` 在运行时按 `vendor` 参数加载合并。

## 文件格式

每个厂商一个 JSON 文件，文件名 = 归一化厂商名（小写，如 `dlink.json`）：

```json
{
  "vendor": "dlink",
  "description": "一句话说明该厂商的代码特点",
  "sinks": {
    "<sink函数名>": {
      "cwe": "CWE-78",
      "description": "一句话描述",
      "severity": "HIGH",
      "confidence": 0.7,
      "format_string": false
    }
  },
  "taint_sources": ["<taint函数名>"]
}
```

字段说明：
- `sinks`：厂商封装/独有的危险函数（如 `lxmldbc_system`）。`format_string: true`
  表示第一个参数是格式化串（按格式化 sink 规则分析）；缺省 false。
- `taint_sources`：厂商的输入来源函数（如 `sobj_get_string`）。
- 注意：`sub_40A1C0` 这类**地址符号**只在特定固件版本出现——换固件可能失效，
  优先记录稳定函数名；地址符号建议同时用 `iot_experience_record` 记录到经验库。

## 添加新厂商

1. 复制本目录任意 json 为 `<vendor>.json`，填写厂商特有函数
2. 调用 `iot_ida_headless_scan(binary_path, vendor="<vendor>")` 时自动生效
3. 同时在 `iot-vuln-patterns.md` 的"厂商特有模式"一节补充说明文字
   （代码只读 JSON；文档给 agent 读，二者职责不同）

## 现有文件

| 文件 | 厂商 | 内容 |
|------|------|------|
| `dlink.json` | D-Link | xmldbc 命令注入 wrapper（lxmldbc_system / xmldbc_ephp / xmldbc_ephp_wb）+ CGI 参数 getter（cgibin_parse_request / sobj_get_string） |

## 跨厂商共性观察（按厂商文件割裂的知识在这里补回横向规律）

> 观察来自实战积累，新增厂商时顺手补充/修正。**这不是通用模式库**（通用模式在
> `iot-vuln-patterns.md`），只记录"跨厂商反复出现的厂商侧特征"，用于快速对比。

| 共性 | 说明 | 涉及厂商 |
|------|------|---------|
| 私有"命令执行 wrapper" | 不直接调 `system()`，而是经厂商封装（如 xmldbc 系）。发现模式：`strings <bin> \| grep -i system` + 反编译查 `system()` 的上层调用者 | D-Link（xmldbc）；其他厂商常见 `xxx_system_cmd` / `do_cmd` / `run_cmd` 命名 |
| 私有 CGI 参数 getter | `getenv` 之外，厂商常封装参数解析（D-Link `sobj_get_string`）。L2 初筛时对 taint source 名单做厂商补充 | D-Link；常见命名 `*_get_string` / `*_parse_request` |
| 参数经 NVRAM 间接注入 | web 写配置 → NVRAM → 特权进程读取执行，sink 与 source 跨函数甚至跨进程 | 多家路由器厂商 |
| 硬编码后门 / 认证绕过 | `strcmp(passwd, "hardcoded")`、cookie 后门，跨厂商普遍 | 多家 |

**使用方式**：分析未知厂商固件时，先对照本表排查"该厂商是否也有 wrapper / 私有 getter"，
发现后登记到对应 `<vendor>.json`（机器可读）并补一行本表。
