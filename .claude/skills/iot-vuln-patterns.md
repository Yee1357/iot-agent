---
name: iot-vuln-patterns
description: IoT 固件常见漏洞模式参考。按入口类型分类，提供 source→sink 路径模板和判断依据。
---

# IoT 漏洞模式库

按**入口类型**分类，每种模式包含典型 source→sink 路径和判断要点。

---

## 模式 1：CGI Handler 参数注入

**最常见。** IoT 设备的 web 界面通过 CGI 处理 HTTP 请求。

### 典型路径
```
HTTP GET/POST
  → httpd 解析 URL → QUERY_STRING / POST_BODY
  → getenv("QUERY_STRING") 或 cgibin_parse_request()
  → handler 函数（xxx_cgi / xxxcgi_main）
  → sprintf(buf, param_value)
  → system(buf) 或 strcpy(dst, buf)
```

### 识别特征
- 函数名：`*cgi*`、`*handler*`、`*dispatch*`、`*parse_request*`
- source：`getenv("QUERY_STRING")`、`getenv("REQUEST_URI")`、`getenv("HTTP_COOKIE")`
- 常见 sink 链：`getenv → sprintf → system`

### 判断要点
- 检查 HTTP method 限制（GET vs POST）—— 通常不限制
- 检查是否有 URL path 路由（`/cgi-bin/xxx` 对应哪个 handler）
- CGI 环境变量都是用户可控的（HTTP headers、URL params、cookies）

### 常见变体
| source | sink | 漏洞类型 |
|--------|------|---------|
| `getenv("HTTP_COOKIE")` | `sprintf → system` | 命令注入 |
| `QUERY_STRING` | `sprintf(stack_buf, ...)` | 栈溢出 |
| `POST body` | `strcpy(stack_buf, body)` | 栈溢出 |
| `multipart/form-data` filename | `open(filename, ...)` | 路径遍历 |

---

## 模式 2：UPnP/SSDP 服务注入

**路由器常见。** UPnP 服务处理 SOAP XML 请求，常在特权进程（root）中运行。

### 兟型路径
```
SSDP multicast / UPnP SOAP request
  → XML 解析（mini_xml / mxml）
  → 提取 action 参数 / service URL
  → sprintf(cmd, "wget %s -O /tmp/firmware", url_param)
  → system(cmd)
```

### 识别特征
- 函数名：`*upnp*`、`*ssdp*`、`*soap*`、`*action*`
- 服务端口：TCP 49152、TCP 5000（常见）
- 进程名：`miniupnpd`、`upnpd`、`soapd`

### 判断要点
- UPnP 通常无认证，任何 LAN 设备可访问
- SOAP action 参数经常直接拼入命令
- XML 解析本身也可能有 XXE / buffer overflow

---

## 模式 3：NVRAM 配置注入

**间接注入。** 用户通过 web 界面修改配置 → 存入 NVRAM → 特权进程读取并执行。

### 典型路径
```
Web 界面设置页
  → POST 保存配置
  → nvram_set("wan_dns", user_value)
  → [重启或定时任务]
  → nvram_get("wan_dns")
  → sprintf(cmd, "echo %s > /etc/resolv.conf")
  → system(cmd)
```

### 识别特征
- source：`nvram_get()`、`nvram_safe_get()`、`profile_get()`
- sink：拼接后传给 `system()` / `popen()`
- 两步分离：设置和执行不在同一个函数

### 判断要点
- 检查 NVRAM 值是否在 web 界面可修改（`/www/` 下的 JS/HTML）
- 检查 `nvram_safe_get` vs `nvram_get` —— `safe` 版本可能有转义
- 检查使用 NVRAM 值的进程是否以 root 运行

---

## 模式 4：认证绕过

**不需要 overflow 或 injection。** 直接访问受保护资源。

### 常见绕过方式

**4a. 路径绕过**
```
受保护：/admin/page.cgi
绕过：/admin/../admin/page.cgi 或 /./admin/page.cgi
原因：认证检查和资源加载用不同的路径解析逻辑
```

**4b. 硬编码后门**
```
if (strcmp(password, "REDACTED") == 0) { grant_access(); }
if (cookie == "hax0r") { skip_auth(); }
原因：开发者留下的调试后门
```

**4c. 认证逻辑缺陷**
```
check_auth() 返回 0 表示失败，但代码用了 if (check_auth() >= 0)
原因：返回值判断错误，0 被当作成功
```

### 识别特征
- 查找 `strcmp`/`strncmp` 和硬编码字符串的比较
- 查找认证函数的返回值使用方式
- 对比 URL 路由表和认证中间件的覆盖范围

---

## 模式 5：栈溢出（格式化字符串 / 缓冲区）

### 5a. sprintf 无边界检查

```
char buf[64];
sprintf(buf, "%s", user_input);  // user_input 超过 64 字节 → 溢出
```

**判断：** 如果 `user_input` 来自网络且无长度限制 → CONFIRMED

### 5b. strcpy 无边界检查

```
char dst[128];
strcpy(dst, src);  // src 可控 → 溢出
```

**判断：** 同上。`strcpy` 永远不安全，只要 src 可控。

### 5c. strcat 累积溢出

```
char buf[256];
strcpy(buf, prefix);       // 30 字节
strcat(buf, user_input);   // 230+ 字节 → 溢出
```

**判断：** 单个操作不溢出，但累积后溢出。需要计算总长度。

### 5d. gets（最危险）

```
char buf[64];
gets(buf);  // 永远不安全，无任何边界
```

**判断：** 只要 `gets` 的参数来自任何外部输入 → CONFIRMED

### 堆溢出变体
```
char *p = malloc(64);
strcpy(p, user_input);  // 堆溢出
```
**判断：** 和栈溢出类似，但利用更复杂。标记 CONFIRMED + 注明堆溢出。

---

## 模式 6：文件操作注入

### 6a. 路径遍历

```
filename = getenv("filename");
sprintf(path, "/tmp/%s", filename);
fopen(path, "r");  // filename = "../../etc/passwd" → 读取任意文件
```

**判断：** 检查是否做了 `realpath()` + 前缀校验。没有 → CONFIRMED

### 6b. 任意文件写入

```
filename = getenv("filename");
content = getenv("content");
sprintf(path, "/www/%s", filename);
f = fopen(path, "w");
fwrite(content, 1, len, f);  // 写入 web 目录 → RCE
```

**判断：** 可写入 web 目录 = 可上传 webshell = RCE

### 6c. 任意文件删除

```
unlink(getenv("file"));  // 删除任意文件
```

**判断：** 如果进程以 root 运行，可删除 `/etc/shadow` 等关键文件

---

## 模式 7：整数溢出 → 缓冲区溢出

```
int len = atoi(getenv("Content-Length"));
char *buf = malloc(len + 1);  // len = -1 → malloc(0) → 小缓冲区
recv(sock, buf, len, 0);      // len = 0xFFFFFFFF → 读入海量数据 → 溢出
```

### 识别特征
- `atoi`/`atol` 转换用户输入为长度
- `malloc(user_val + N)` 或 `alloca(user_val)`
- 无范围检查

### 判断要点
- 检查是否有 `len > MAX_SIZE` 类型的边界检查
- `malloc(0)` 在不同实现中行为不同，可能返回小指针

---

## 模式 8：竞态条件（TOCTOU）

```
if (access(file, W_OK) == 0) {   // 检查权限
    // ← 攻击者在这里替换文件（symlink race）
    fd = open(file, O_WRONLY);    // 实际打开的是另一个文件
    write(fd, data, len);
}
```

### 识别特征
- `access()` + `open()` 之间有时间窗口
- `stat()` + `open()` 之间有时间窗口
- 临时文件使用可预测的文件名（`/tmp/xxx`）

### 判断要点
- 标记 NEEDS_DYNAMIC（竞态难以静态确认）
- 概率性利用，需要多次尝试

---

## 快速匹配规则

看到以下模式，直接标记**高优先级**：

| 代码模式 | 动作 |
|---------|------|
| `getenv("HTTP_*")` 后接 `system`/`sprintf` | 高优先级深入 |
| `gets(buf)` | 直接 CONFIRMED |
| `sprintf(buf, user_input)` 且 buf 是栈变量 | 高优先级深入 |
| `nvram_get` → `system` | 检查 NVRAM 是否 web 可写 |
| `strcmp(passwd, "hardcoded")` | 检查是否认证绕过后门 |
| `malloc(atoi(input))` | 检查整数溢出 |
| `unlink(getenv(...))` / `fopen(getenv(...), "w")` | 文件操作注入 |
