---
name: iot-emulation-debug-experience
description: qemu/仿真调试经验库。记录仿真复现（qemu user-mode、chroot、binfmt、xmldb 等设备守护进程）中反复踩中的环境坑、修法与验证技巧；每个漏洞动态复现成功后必须增量回写本文档（参见 CLAUDE.md 经验记忆流程）。
---

# IoT 仿真调试经验库（qemu / chroot / 设备守护进程）

> 用途：动态验证（L4）阶段的**环境坑 + 修法 + 验证技巧**速查。与 `iot-vuln-patterns` skill
> （漏洞模式库，按漏洞类型分类的 source→sink 模板）互补：那边回答"看哪里"，这边回答
> "怎么把候选跑起来并拿到证据"。
>
> 遵守 CLAUDE.md 规范：不出现机器特定路径，一律用约定路径/占位符。
>
> **回写纪律（强制查重）**：
> 1. 新条目落库前先 `grep` 本库关键词查重（如 `后台化|UDP|子目录|挂死|pkill|strace`）；
> 2. 与已有条目语义重叠 → **合入原条目**（追加/更新）或只写**交叉引用**（`详见 2.x`），禁止同知识点二次录入；
> 3. 新旧形态对照时写"与 2.x 相反/相同"建立锚点，不重复描述机制本身；
> 4. md 增量同步 `experiences` 表（scenario 唯一 upsert，语义重叠 bump 原条目而非新增）。

---

## 一、D-Link DNS-320 NAS（ShareCenter，Marvell Kirkwood ARM）专项

### 1.1 固件/架构指纹

| 项 | 值 |
|----|----|
| 型号 | DNS-320（2.06b01 / 2.13.0322.2019） |
| CPU/arch | ARM 32-bit EABI5（`/lib/ld-linux.so.3` 动态加载器，glibc 2.5） |
| Web | lighttpd + CGI（`web/config/default_lighttpd.conf`），CGI 全在 `/cgi/` |
| 渲染/状态层 | **xmldb 守护进程**（`/sbin/xmldb`，Unix socket `/var/run/xmldb_sock`、wto 会话 socket `/var/run/xmldb_sock_wto`）；CLI 即 `xmldbc`（同二进制，argv[0]=xmldbc 进入 CLI 模式，`-l/-g/-s/-S`） |
| 表单解析 | **libcgic**：`cgiFormString` / `cgiCookieString` / `cgiHeaderStatus` / `cgiHeaderContentType` |
| Rootfs | squashfs(LZMA) @ 0x3F5020 + ramdisk(ext2, glibc 2.5+loader) /lib 覆盖 |
| 配置 | `/default/config.xml`（出厂默认 XML，含 `hw_ver=DNS-320`、`sw_ver_1=2.06b01`） |

### 1.2 认证模型（复现时最关键）

- `cgiMain` 分发：`cmd` 参数（libcgic 解析）与接口名字符串 `strcmp` 链分发；**个别接口的 strcmp 在认证门调用之前**（`cgi_set_wto`，天然免认证）。
- 认证门 `fcn.00011108`（system_mgr）→ 细分校验 `fcn.00010f6c(cookie_username, REMOTE_ADDR)`:
  - **`REMOTE_ADDR == "127.0.0.1"` → 直接返回认证通过（本机信任）**——qemu 复现时可用它跳过会话；
  - cookie/REMOTE_ADDR 为空、或 cookie 命中内置名单 `{root, anonymous, nobody, guest, ...}` → 返回 10（拒绝；**名单语义是"不走 wto 校验、直接拒"**，反映到动态行为就是无任何 socket 调用即 404）；
  - 其余 → `fcn.00010da0(cookie, ip)` wto 会话校验：`xml_get_int("/system_mgr/idle/time")`（主库配置，**斜杠路径**，缺失返回 -1 → 一律拒绝）+ 会话 `name==cookie && wto_ip==REMOTE_ADDR && wto_login==1 && (now-wto_time) < 60*idle`。
- 认证失败 → `cgiHeaderStatus(404, "not found")` + "Status: 404 not found\n"——**不要误判为接口不存在**。
- 已实证免认证（分派在门禁前）：vuln_96 `cgi_set_wto`（`cgiMain` @ 0xf968 直接进分支，处理器把 `admin + REMOTE_ADDR` 写成 wto 会话 `wto_login=1`）。
- **会话复用链（已验证）**：`POST cmd=cgi_set_wto`（无 cookie）→ wto 库出现 `(name=admin, wto_ip=攻击者IP, wto_login=1)` → 之后同 IP + `Cookie: username=admin` 即可过门禁访问全部认证接口（含命令注入类）——比 127.0.0.1 信任路径更贴近真实攻击面，后续认证后漏洞一律用它验证。

### 1.3 命令注入模式（D-Link8 系列 96–159 大量此类）

- 形态：handler 内部 `system()/popen()` 拼接用户参数，多数是 `sprintf(buf, "cmd ... %s ...", user_param)`。
- `cgi_ntp_time` 实际调用形态：`sh -c (sntp -r \`<f_ntp_server>\` >/dev/null) &`（反引号命令替换直达 /bin/sh）。
- 注入 payload：反引号 `` `cmd` `` 或 `;cmd;`。**URL 表单 payload 里避免裸 `&`**（表单解析截断，壳报 "EOF in backquote substitution"；细节与编码见 2.4）。

### 1.4 [pattern] apkg 系（app_mgr/apkg_mgr.cgi）UDP 桥接 + "后台化" system 形态（vuln_134 实锤）

- **二进制位置坑**：`apkg_mgr.cgi` 在 **`cgi/app_mgr/` 子目录**（md 写裸名 `apkg_mgr.cgi` 直接找会 No such file）；同款：`remote_backup.cgi`→`cgi/backup_mgr/`、`download_mgr.cgi`→`cgi/download_mgr/`。找不到 binary 先 `ls cgi/*/`。
- **形态**：handler 先 `APKG_COMMAND(f_module_name, <cmd>)`（`libapkg2.so`，UDP 127.0.0.1 通知 apkg 守护进程）——**即使被桥接阻塞，返回后不检查错误**，照样执行：
  - `f_web` 空/非 "1" → `system("(addons_follow-up.sh stop %s > /dev/null) &", f_module_name)`（注入点 1）
  - `f_web=1` → 同上但 `start`（注入点 2，非 aMule 名字时才拼接）
- **与 2.17 相反**：该格式串整体 `( ... ) &` 后台化 → **system() 立即返回，不会反引号挂死**；payload 不需要自带 `>/dev/null`。
- **UDP 桥接阻塞处理**：无 apkg 守护进程时 `APKG_COMMAND` 内部 `select(tv_sec=120)` 等回包 → **CGI 挂 ~120s 后继续**。`timeout` 必须 ≥150s，12s 实验会误判"注入未执行"。加速路线（未实施）：查 `libapkg2.so` 的 `reloc.apkg_addr`/端口起 UDP listener 喂包可跳过等待。
- **验证技巧复用 2.17**：timeout 后台跑 → 轮询端口 → `nc` 连 shell → `touch /tmp/marker`。
- 附带现象：CGI 尾部偶发 `qemu: uncaught target signal 11`（段错误）**不影响注入结论**——system 的命令已后台执行。

### 1.5 [pattern] dsk_mgr.cgi FMT_create_diskmgr：直连 system、双参数注入（vuln_139 实锤）

- 形态：`system("diskmgr -m %s -f %s -n > /dev/null &", f_raidlevel, f_filesystem)`——**无 UDP 桥接、无 APKG 依赖**，请求后 ~6s 直接出结果（CGI exit 0 + `<res>1</res>`），复现无需长 timeout。
- **双注入点**：`f_filesystem`（md 主打的）和 `f_raidlevel` 都拼进命令；格式串带尾部 `&` → 后台化，**不挂死**。
- 判断是否要等 UDP 桥接：`rabin2 -l <cgi>` 看是否依赖 `libapkg2.so`——依赖才走 1.4 的 120s select；不依赖（如 dsk_mgr）直接到 system。
- 环境噪音（不影响结论）：`ln: 无法创建符号链接 '/var/www/xml/lang.xml'`、`kill_running_process: not found` 等。

---

## 二、qemu user-mode 复现 D-Link（xmldbc）CGI 的完整做法（坑全记录）

路径占位：`<MERGED>` = rootfs(squashfs)+ramdisk 叠加后的合并目录；`<Q>` = `qemu-arm-static`。

### 2.0 环境准备

```
mkdir <MERGED> && cp -a <squashfs-root>/. <MERGED>/ && cp -a <ramdisk>/. <MERGED>/
# 补固件缺失的 .so 符号链接（libxml2.so.2 等 ld 报错时迭代补）
env LD_LIBRARY_PATH=usrlib:lib <Q> -L <MERGED> ./something # 报 "cannot open shared object file: X" → ln -s <real> <dir>/X
```

### 2.1 [env] qemu-user 对 AF_UNIX `bind()` 不做 `-L` 前缀翻译

- **症状**：启动 `xmldb -s /var/run/xmldb_sock_wto`（qemu 直跑）→ `bind: Permission denied`；guest 进程实际 bind 到**宿主真实 `/var/run`**（非 root 不可写）。
- **修法**：用 root 起守护进程绑定真实路径 + 在 guest 视图放符号链接指向真实 socket，双向覆盖（无论 connect 是否翻译都可达）：
  ```
  sudo setsid bash -c "cd <MERGED> && exec env LD_LIBRARY_PATH=usrlib:lib <Q> -L . ./sbin/xmldb -n config -s /var/run/xmldb_sock_wto"
  ln -sf /var/run/xmldb_sock_wto <MERGED>/var/run/xmldb_sock_wto
  ```

### 2.2 [env] binfmt_misc F 标志不支持 interpreter 带参数；ARM ELF 直 exec 缺 loader

- **症状 A**：binfmt 注册 interpreter 带 `-L ...` 参数 → 写入 `/proc/sys/fs/binfmt_misc/register` 失败（ENOENT / Invalid argument）。
- **修法**：注册裸 interpreter 前缀，`flags=POF`：
  ```
  :qemu-arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff...:/usr/local/bin/qemu-arm-static:POF
  ```
- **症状 B**：ARM ELF 直 exec（binfmt 生效后）→ `qemu: Could not open '/lib/ld-linux.so.3'` 或 dash 报 `not found` / `Exec format error`。原因：内核 binfmt_elf 找不到 guest 解释器就 ENOENT，须让 guest loader 可见：
  ```
  sudo ln -sf <MERGED>/lib/ld-linux.so.3 /lib/ld-linux.so.3
  # 其余 guest 库由继承的 LD_LIBRARY_PATH=usrlib:lib 覆盖（cwd=<MERGED>）
  ```

### 2.3 [env] `pkill` 匹配/误杀自己的 shell；`pkill -x` 杀不掉 qemu 包装进程

- **症状 A**：SSH 会话的构建命令含目标名时，`pkill -f <name>` 匹配到 bash/zsh 自身命令行 → 命令瞬间空输出 + exit 1。
- **修法 A**：匹配精确进程名 `pkill -x utelnetd`；若进程名是 qemu wrapper（如 `qemu-arm-static`），按二进制路径 `pkill -f "[t]ools/utelnetd"`（括号技巧防自匹配）。
- **症状 B（vuln_141 实测）**：经 binfmt 跑的 ARM 程序（如 `tools/utelnetd`）**进程 comm 是 `qemu-arm-static`**，`pkill -x utelnetd` 根本匹配不到 → 端口残留、后续测试端口冲突。**一律用 `pkill -f '[t]ools/utelnetd'`**。

### 2.4 [env] 表单项里的 `&` 会截断注入 payload

- **症状**：反引号注入的壳命令带 `2>&1` → CGI 收到被 `&` 截断的值，shell 报 `Syntax error: EOF in backquote substitution`。
- **修法**：payload 用 `>/dev/null`（不引入 `&`）或把 `&` 编码 `%26`。`=`、`%`、`+` 同理视 libcgic 表现编码。

### 2.5 [env] qemu user-mode 文件路径"半透明"，`touch /tmp/x` 落在宿主真实 /tmp

- **事实**：qemu user-mode 对部分 syscall 的文件路径不做 `-L` 翻译（实测 `> /tmp/x` 直接写宿主真实 /tmp；AF_UNIX bind 同病，见 2.1）。
- **利用**：验证 RCE 直接在宿主 `/tmp` 检查 marker 文件——简单可靠，不用猜 guest 内路径。
- **前置标志类检查**（如 handler 内 `access("/tmp/system_ready")`，缺则提前 return 不达 sink）：**guest 与宿主 /tmp 双份 touch** 双保险（哪侧生效未逐一验证，两侧都建成本为零）。

### 2.6 [tech] 用 `qemu -strace` 观察 guest syscall

- `<Q> -strace ./bin` 打印 guest syscall（socket/access/open），比宿主 strace 直观。**注意不跟踪 fork 子进程**。
- 定位思路：CGI 卡死/404 时先 `-strace`，看它轮询哪个文件/socket——DNS-320 的 system_mgr 会不断 `access("/var/run/xmldb_sock_wto")`（daemon 未起时无限轮询）。

### 2.7 [tech] 分发/认证静态定位速查（radare2）

```
r2 -q -c "aaa; s sym.cgiMain; pdf" <cgi>        # cmd strcmp 分发链 + 认证门
r2 -q -c "aaa; izz~not found" <cgi>             # "Status: 404 not found" 字符串 → cgiMain xref
strings -a <cgi> | grep -E "wto|system|sntp"    # 界面/会话键/调用形态
```
- "404 not found" 的 xref 在 `sym.cgiMain`，其上方 `bl fcn.xxx` 即认证门；返回 1 才继续分发。
- wto 会话键：`/wto/count`, `/wto/item:%d/name`, `/wto/item:%d/wto_ip`, `/wto/item:%d/wto_time`, `/wto/item:%d/wto_login`。

### 2.8 [env] 直调 CGI 模拟 POST 必须带 CONTENT_TYPE（libcgic）

- **症状**：`env REQUEST_METHOD=POST CONTENT_LENGTH=<n> ... qemu ... <cgi>` 下，所有请求都返回 `Status: 404`，连**免认证接口**也 404——误判为"接口有认证"。
- **根因**：libcgic 的 `cgiFormString` 依赖 `CONTENT_TYPE`（application/x-www-form-urlencoded）解析 body；缺失时 `cmd` 读为空 → 分派不中 → 走认证门 → 404。
- **修法**：三件套 `REQUEST_METHOD=POST + CONTENT_LENGTH=<len> + CONTENT_TYPE=application/x-www-form-urlencoded`，body 经 stdin（`< /tmp/body.bin`，内容 `cmd=...` 无换行）。GET 方式则用 `QUERY_STRING`。

### 2.9 [env] xmldbc 客户端选库：`-S` 是 socket、`-s` 是 set；wto item 编号从 1 起

- `xmldbc -S /var/run/xmldb_sock_wto -g /wto/count` 才是查 wto 库；`-s <path> <value>` 是写。
- 整体 dump 用 `-D <xml文件>`（配合 `-S`）；`-l` 是 reload XML（daemon 姿态）。
- **wto item id 从 1 开始**：`/wto/item:0/name` 读不到，用 `/wto/item:1/name`（踩过）。

### 2.10 [env] DNS-320 认证门依赖主库键 `/system_mgr/idle/time`（斜杠！）

- 症状：wto 会话已建好、cookie/IP 全对，认证门仍拒绝；strace 显示只连了 1 个 socket（读配置）就返回。
- 根因：`fcn.00010da0` 先 `xml_get_int("/system_mgr/idle/time")`，主库（默认 socket）无此键 → -1 → 直接拒。**字符串实际是 `/system_mgr/idle/time`，r2 flag 名 `str._system_mgr_idle_time` 会误导成下划线**。
- 修法：`xmldbc -s /system_mgr/idle/time 30` 后会话校验路径才生效。

### 2.11 [tech] 认证"名单 vs wto 路径"的动态二分：strace 数 socket

- 背景：.rodata 的内联用户名 blob 被 r2 显示成"8 项数组"，reloc 开关都解释不清（实际既非指针数组也非运行时可读表——直接动态判）。
- 方法：逐 cookie 跑 `qemu-arm-static -strace`，统计 `socket/connect` 调用次数：**命中名单 → 提前返回，0 次 socket；走 wto 校验 → 出现 AF_UNIX socket（xml_get_int 读库等）**。
- 实测：root/anonymous/nobody/guest → 0 socket（名单）；admin/zzz/adminx → 有 socket（wto 路径）。

### 2.12 [verification] shutdown/reboot 类处理器：宿主 `/usr/sbin/do_reboot` 桩验证

- CGI 内部 `system("/usr/sbin/do_reboot >/dev/null")` 由子 shell（binfmt 裸 qemu，无 -L）执行 → 解析为**宿主**路径。在宿主放写 marker 的脚本即可证明到达且防真重启。
- 注意：`cgi_shutdown` 实际不直调 do_reboot——它 `LIB_Set_IPC_int(4,1,3)` 写**关机标志**（strace 可见 wto.lock fcntl + 若干 xmldb socket set 写入），由守护进程执行重启；验证以"处理器执行 + 标志写入"为准。

### 2.13 [tech] 二进制 `main` 是 PLT thunk 时的真实入口定位

- **症状**：`r2 s main; pdf` 只见 `add ip,pc; ldr pc,[...]`（thunk），真 main 不在镜像。
- **修法**：`pxw 4 @ <reloc.main 槽>` 取目标地址（DNS-320 system_mgr: 槽 0x1c7f8 = 0x94ac，但 0x94ac 是 PLT 项 → 真 main 在 **libcgic.so**）；更实用的是直接 `axt @ sym.cgiMain` 找谁调它。对 libcgic 系，`cgiMain` 符号通常是 app 导出、main 在共享库。

### 2.14 [env] SSH 非登录 shell 的 PATH 为空 → 注入命令静默失败

- **症状**：paramiko exec 会话不加载 profile，`PATH` 为空；CGI 子进程（system/反引号）里按名字查找的命令（`utelnetd` 等）直接 not found——**静默失败，注入看起来没生效**（vuln_143 反引号替换就是被这个坑了）。
- **修法**：跑 CGI 前显式 `export PATH=<tools目录>:/usr/local/bin:/usr/bin:/bin`（tools 里放验证工具）。

### 2.15 [env] qemu -L 对部分绝对路径 open 不翻译 → 宿主同名目录双向覆盖

- **症状**：`cgi_firmware_upload` 写 `/usr/local/upload/`：merged 视图建好目录仍 ENOENT（qemu 对 `O_CREAT|O_EXCL` 的绝对路径 open 走了宿主路径）。
- **修法**：宿主也建同名目录（`sudo mkdir -p /usr/local/upload && chmod 777`）——与 2.1 AF_UNIX socket 双向符号链接同一思路："两边都可见"。
- 判断方法：guest 程序写文件失败先查**宿主同名路径**是否存在。

### 2.16 [env] qemu -L 对不存在的 guest 绝对路径回退宿主路径

- **症状/事实**：`merged/bin/sh` 不存在时，guest `execve("/bin/sh")` 回退为**宿主 x86-64 sh** 直接执行——注入命令照常生效（vuln_141 里宿主 `/bin/hostname` 输出主机名可作"到达 system()"的证据）；但直接用 `qemu-arm-static /bin/sh` 会报 `Invalid ELF image for this architecture`（qemu 想解释宿主 ELF），属预期而非故障。
- **利用**：判断 system() 是否执行 → payload 里放 `echo $(hostname)` / 写宿主 /tmp 文件即可。
- **推论（cp/mv 前置命令坑）**：system() 内是 `cp -f /etc/NAS_CFG/config.xml /usr/local/config/` 这类**读文件的宿主命令**时，路径解析发生在**宿主侧**——`/etc/NAS_CFG/config.xml` 必须在宿主真实路径存在，否则 cp 失败 → 处理器**提前 return**，连注入的 system 都不执行（vuln_100 cgi_set_schedule 实测：补 guest 视图无效，补宿主 `/etc/NAS_CFG/config.xml` + `/usr/local/config/` 后 cp 才过）。判断法：strace 看 `system()` 的 execve 命令行，失败命令的报错指向哪侧路径就补哪侧。

### 2.17 [verification] CGI 的 system() 反引号替换挂死时的取证法

- **症状**：`sh -c "... \`utelnetd ...\` ..."` 中反引号内程序持有 stdout 管道 → substitution 等 EOF → **CGI 挂起**（`timeout` 杀后 rc=124；vuln_141/142 复现）。
- **修法**：不依赖 CGI 正常返回——`timeout 20 qemu ... &` 后台跑（可加 `-strace` 落盘留证据），**轮询目标端口**出现即 `nc` 连 shell 取证，完事清理进程。端口已监听=注入已执行，CGI 挂不挂不影响结论。
- **姿势铁律（本次再踩）**：SSH 单条串行命令里"先跑 CGI、结束后再 `ss` 查端口"是**错**的——CGI 挂起期间轮询根本没执行，timeout 到期 SIGTERM 杀 qemu 还可能打断 fork 子进程的 `execve`（strace 见 `errno=4 (EINTR)`，sh 都没起来，属预期信号行为而非注入失败）。必须把 CGI 放后台（`(timeout ... &)`），前台循环轮询端口。
- **另一挂起形态（vuln_101 实测）**：分号闭合注入但格式串**无括号包裹**（`rsyncom -e 1 -p '%s' -s -x &`）时，dash 的行尾 `&` **只后台化最后一段**，`';utelnetd...;'` 注入段**前台执行** → daemon 类命令（utelnetd 不退出）挂住 sh（RC=124）；**对比 vuln_98/99 的 `( ... ) &` 括号包裹整体后台不挂**。touch 类秒退命令两者都不挂（RC=0）。取证同法：后台 CGI + 轮询端口（daemon fork 即已监听，vuln_101 约 4s 起端口）。
- 附：**工具中断后远端 SSH 命令会成为孤儿继续跑**——长任务被中断后先 `ps -eo pid,cmd | grep <脚本名>` 清理，再开新命令。

### 2.18 [pattern] multipart 上传 filename 注入（D-Link DNS 系）

- 形态：`cgi_firmware_upload` 把上传 `filename` 拼进 `system("mv ... <filename>")` 与 `system("upload_firmware -n '<filename>' & >/dev/null")`。
- PoC 技巧：filename 用单引号对包裹反引号 `` "'`cmd`'" `` → 拼接后成 `''`cmd`''`，**反引号仍在引号对之外，命令替换生效**（vuln_143 strace 实锤）。
- 排查：文件上传类 CGI 优先查 `cgiFormFileName` 的下游 system 拼接；临时文件路径先确认（`/usr/local/upload/` 等）再补目录。

### 2.19 [tech] 动态复现卡"处理器内部分支前置"时的定位与止损

- 现象：接口分发命中、认证已过（strace 见多次 xmldb socket 调用），但注入 system 不执行、CGI 提前 return（vuln_100 cgi_set_schedule 实测）。
- 定位：strace 数 `execve("/bin/sh")` 次数与命令行——第一个 system 是 `cp -f /etc/NAS_CFG/config.xml ...` 之类**前置命令**且失败（补宿主路径，见 2.16）；后续是 `access(...)` 标志检查（补双 /tmp，见 2.5）；再后是代码内开关分支（如 `[r8+0x18]` crond_type 分派 + `fp-0x64=="1"` 启停开关，r8 结构由库状态填充，表单参数不一定能控制）。
- **止损**：前置文件类坑补完即通；纯代码分支依赖库状态（B/C 级）的，标 NEEDS_DYNAMIC 留档（静态 source→sink 已确认的写进报告），不无限试参——同一失败 ≥3 次即换洞。

---

## 三、通用经验（跨厂商候选）

| 类别 | 经验 |
|------|------|
| pattern | D-Link 系：CGI 用 libcgic 时，`cmd=` 分发串在 `.rodata` 可见，sink 多为 `system()` 格式化拼接 |
| pattern | 认证"404 门"特征：未认证返回 HTTP 404（而非 401/拒绝页）——反编译时认 `cgiHeaderStatus(404,...)` |
| env | 固件合并 rootfs 时必须叠加 ramdisk 的 /lib（glibc 版本不同、loader 只在 ramdisk） |
| verification | 危险命令优先注入 `touch /tmp/<tag>` 验证达 sink；确认后升级为 `utelnetd -p <port> -l /bin/sh` 拿真 shell |
| verification | 宿主 strace 看不到 qemu 内部 → qemu `-strace`（用法见 2.6） |
| false_positive | 不要把"接口不存在/404"当结论——先确认是否认证门返回 404 |

---

## 四、待补验证项（动态 B/C 级，需说明）

- ~~远程（非 127.0.0.1）wto 会话认证路径的完整动态串验证~~ → **已完成（vuln_96）**：cgi_set_wto 免认证建会话 → 同 IP + cookie=admin 过门禁 → cgi_shutdown 处理器执行（IPC 关机标志）→ 链式触发 cgi_ntp_time 注入 RCE。
- cgi_set_wto 写库后立即生效的会话（`wto_login` 由 login_mgr 写入时机）——实测 set_wto 直接写 login=1，无需 login_mgr。
- 真机守护进程消费关机 IPC 标志并执行 do_reboot 的完整链路（需系统态模拟，B/C 级）。

## 五、D-Link deuteron/anweb 系列（DIR-X1530 等，MIPS BE，squashfs+xz）专场

### 5.1 固件/架构指针
| 项 | 值 |
|----|----|
| 型号 | DIR-X1530 (D-Link Russia) FW 4.5.2, tar → uImage(MIPS BE LZMA) + rootfs(squashfs v4.0 xz) |
| Web | `/usr/sbin/anweb`（CivetWeb 1.15）+ 前端 `srv/anweb` JS SPA；主端口 80/443s，拦截 81,4445s，SafeDNS 5353/5454 |
| 后端 | deuteron 体系：JRPC over unix socket（dmsd=dmsd.sock）；anweb 的 `d_jrpcapi_*` 实现在 libglobal.so |
| 状态 | anweb 内 session 体系（device-session-id cookie）；`check_auth` = 向 dmsd 查 `Device.Users.CurrentUser` 非空 |

### 5.2 动态验证要点（chroot+qemu，无 dmsd 也能跑 anweb）
- `qemu-mips-static`（BE）chroot 里 `anweb -D -m 8090` 直接可起；无 dmsd → dmsd 相关报错但 HTTP/WS 全通。
- `qemu-mips-static -strace` 可看 guest connect() 的 socket 路径（qemu strace 对 AF_UNIX sockaddr 只打印长度，路径看长度推断：21 字节= "/var/run/dmsd.sock"）。
- **JRPC wire format（已抓包确认）**：unix STREAM，路径 `/var/run/dmsd.sock`（chroot 里注意 `/var→/tmp/var` symlink，`mkdir -p <rootfs>/tmp/var/run` 后 socat UNIX-LISTEN 即可抓）；帧 = 16B 头（magic `0a 00 97 d1` + u32 len + ...）+ method 块（`04 00 00 00 01 00 01 00 00 00 06 "Login"` 之类）+ msgpack 参数体（jansson 风格 `a5 Login a5 admin`）。做 dmsd 桩需完整逆向 libglobal 的 d_jrpcmsg 序列化，成本高，属 B 级。
- **websocket 协议（已动态验证）**：`/websocket` 握手无鉴权（connect_handler 直接 return 0）；`init <num>` → 状态机 field=1→2；随后 `sysutils:` + JSON 直达 action_handler；action_handler 内 `strncpy(s[256], src, n)` 已有 `data_len<0x81` 上限（CVE-2022-40717 已修）。
- 命令注入走 `action_work_handler`：`snprintf(buf, "%s%s", "unset DEUTERON_SERVICE_ID; ", s)` → `popen(buf,"r")`，输出 getline → json_pack → 回推 websocket。
- **pkill 自杀坑（Kali 登录 shell；机制见 §二 2.3，此处补 mips 拼串解法）**：`pkill -f qemu-mips-static` 会匹配自身 bash -c 命令行（含同名串）→ 会话被杀。mips 侧适用拼串解法：`pkill -f "$(printf '%semu-mips-static' q)"`；或 `pkill -x <comm>`，或把 kill 独立成单独命令。
- **sudo 非交互**：`echo <pass> | sudo -S <cmd>`（kali 用户密码 kali 也可提权）。
- 清理：`pkill` + `umount` + `rm -rf chroot 工作副本`，注意先杀进程再 umount proc/devpts。

### 5.3 deuteron 真 dmsd 方案（DIR-X1530 追加）
- `deuteron` = **DMSD/Dsysinit/Dwatcher 三合一**（`deuteron -h` 验证）；chroot+qemu 下 `-f -i` 可完整拉起：自动创建 dmsd.sock/dsysinit.sock/dsysctl.sock/logging.sock/sched.sock + loggingd/linkwatcher 子进程——**真 dmsd 响应方案可行**（此前手写桩卡在响应帧布局）。
- 卡点记录：`-f -d /etc/deuteron/dm.bin` 报 "Datamodel must exist / dm_load error"；`-f -i`（初始化模式）可过 datamodel 阶段，但 anweb 连真 dmsd 后卡在 init（未监听 8090），且 smux_init ioctl 报错刷屏——属于多进程就绪条件（B/C 级），未继续。
- 环境坑：
  - **deuteron 残留 pid 文件 → "Another process already running"**：启动前清 `<rootfs>/tmp/var/run/*.pid` 和 `*.sock`
  - deuteron 全家是**进程树**（主 qemu + fork 子 qemu + daemon 化的 `qemu-mips` loggingd/linkwatcher），清理需杀全树（含不带 `-static` 的 `qemu-mips`），grep 用 `[q]emu`
  - qemu 对 timeout 的 SIGTERM 可能不响应，用 `sudo kill -9 <pid>` 明确杀
- **操作铁律（已由传输层根治，2025-09 起）**：`iot_vm_execute` 的 `execute()` 自动把命令包成 `echo '<b64>' | base64 -d | bash -s`（见 2.x 条目与 `iot-emulate-firmware` 常见问题），调用方直接传原始命令即可，**无需再手动 base64 包装**（重复包装无害但多余）。`pkill -f` 与含目标串的命令仍严禁同批（自杀式匹配），杀进程用独立命令 + `pgrep`/显式 PID
