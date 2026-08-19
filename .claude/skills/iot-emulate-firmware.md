---
name: iot-emulate-firmware
description: 固件动态验证。两级模式：qemu-user -L 快速试错（不作为最终结论）+ chroot 包裹 qemu 的正式验证（唯一 verdict 依据）。系统态模拟（FirmAE/QEMU system）已移除。用户要求验证漏洞、复现攻击时使用。
argument-hint: "[firmware_model]"
---

# 固件动态验证（两级：试错 → chroot+qemu 验证）

**所有操作在 VM 上完成，工具一律走 MCP。**

## 铁律

- **系统态模拟（FirmAE、手动 QEMU system mode）已从本项目移除**——不要尝试安装、不要拼 qemu-system 命令行。
- 动态验证只有两级：
  1. **快速试错** `iot_emulation_user_mode`（`qemu-<arch>-static -L <rootfs> <cmd>`）——便宜，但**结果不作为最终 verdict**（`-L` 只重定向 loader/库，guest 的绝对路径会落到 host 文件系统）
  2. **正式验证** `iot_emulation_chroot_user_mode`（chroot 包裹 qemu）——**唯一可以作为动态 verdict 依据的路径**
- binfmt 依赖的裸 chroot 方案已删除（chroot+qemu 完全覆盖且更真实、无 binfmt 依赖）。

## 验证边界（铁律：只完整验证 A 级，B/C 级交用户）

**用户态模拟（chroot+qemu）只启动了一个进程视图——没有设备开机流程**：
xmldb/NVRAM 运行时数据是空的、httpd/upnpd 等 daemon 不在、/proc 厂商文件缺失、
网络事件不会进来。所以漏洞必须分级，**只对 A 级做完整验证**：

| 级别 | 定义 | 例子 | 处理 |
|------|------|------|------|
| **A 级** | 单进程内、输入→sink 直接可达，不依赖运行时数据/多进程/网络 | 命令注入直接 `system()`、栈溢出、文件操作、格式串 | **完整验证**（user-mode 或 chroot+qemu）→ 可 CONFIRMED |
| **B 级** | 需补少量运行时数据（xmldb/NVRAM 节点）才能走完 | 本次 SSDP（`INF_getcurripaddr` 需接口数据）、经 NVRAM 的间接注入 | **不硬补**：静态证据 + 模拟走到哪一步，报告交用户决策 |
| **C 级** | 依赖多进程协同/网络会话/内核接口 | 认证绕过链路、需要真实 HTTP 会话的 handler、ioctl 设备 | **不验证**：报告静态分析结论 + 建议（真机/系统态），交用户 |

**B/C 级处理流程**（禁止无限尝试）：
1. 最多 2 次环境尝试（止损规则）
2. 输出结构化报告：静态证据链 + 模拟实际走到哪一步 + **缺失的环境** + 建议（补数据 / 真机复现 / 系统态模拟）
3. 交用户决策，findings 保持 NEEDS_DYNAMIC，**notes 写明上述内容**（不是笼统的"需要动态验证"）

**hunt 策略**：L2/L3 阶段优先筛选 A 级候选（输入直达 sink、无运行时依赖）；B/C 级候选正常给出静态 verdict 但标记级别，不投入动态验证时间。

## 前置：架构与 qemu 定位

```text
iot_emulation_detect_arch(rootfs)              # → "mipsel" 等，不要猜
iot_emulation_ensure_qemu(arch)                # 定位 qemu：PATH → /usr/local/bin → find 兜底
# found=True 拿到 path；found=False 时返回安装命令，走升级路径 L3 交用户决策
```

## 方式一：快速试错（-L，10 秒级）

```text
iot_emulation_user_mode(rootfs_path=rootfs, command="./poc 'payload'", arch="mipsel")
# → {started, exit_code, stdout, stderr, arch, qemu}
```

**用途与限制**：
- 适合：命令注入 sink 是否真的执行、文件是否存在、程序能否被 `-L` 拉起
- **限制**：guest 内部绝对路径（`/etc`、`/tmp`、`/bin/sh`）落到 **host** 文件系统——`system()` 注入的副作用、写 pid 文件、读固件配置都是 host 的，不代表设备行为
- **试错结果只能用于排除/初判，不能写进 verdict**。要下结论必须走方式二

## 方式二：正式验证（chroot 包裹 qemu）

```text
iot_emulation_chroot_user_mode(rootfs_path="/data/extracted/<brand>/<model>_<ver>/rootfs",
                               command="/usr/sbin/kworker --super 127.0.0.1 --port 7000 --config /etc/kworker.cfg",
                               arch="mipsel",        # 来自 detect_arch
                               inject_nvram=False)   # 程序读 NVRAM 时设 True（自动注入 libnvram）
# → {started, stage, workdir, qemu, pid, log_tail, error}
```

自动完成（参考实战验证脚本的成熟模式）：
1. 定位 qemu（`/usr/local/bin` → PATH → find 兜底），缺失即报安装命令
2. **工作副本**：`cp -a rootfs/. <rootfs>.chroot-qemu/`（幂等，只在缺失时重建）——**原始 rootfs 永不被污染**
3. 复制 `qemu-<arch>-static` 到工作副本 `/usr/bin/`，bind mount `/dev` `/dev/pts` `/proc`
4. 后台启动：`chroot <workdir> /usr/bin/qemu-<arch>-static [-E LD_PRELOAD=/lib/libnvram.so] -- <command>`
   —— **qemu 进程本身被 chroot**，guest 的绝对路径、fork/exec 固件二进制（如 `/bin/sh`）全部在 rootfs 视图内，**且不依赖 binfmt_misc**
5. 存活检测 + 日志回传

**为什么这是唯一正式验证**：程序读 `/etc/kworker.cfg`、写 `/var/run/kworker.pid`、`execve("/bin/sh")`（busybox）都在工作副本里发生——这就是设备真实视图，结果可直接当 verdict。

**验证完必须清理**：
```text
iot_emulation_chroot_cleanup(workdir="<rootfs>.chroot-qemu", process_match="qemu-.*-static", remove_workdir=True)
# 杀进程 + 卸载 dev/pts/proc + （可选）删除工作副本
```

## 典型验证流程（命令注入类）

```text
1. iot_emulation_detect_arch(rootfs) → arch
2. iot_emulation_ensure_qemu(arch)   → 确认 qemu 在位
3. iot_emulation_user_mode(rootfs, "echo PROBE; id", arch)   # 试错：sink 是否真执行
4. iot_emulation_chroot_user_mode(rootfs, "<目标程序> <注入参数>", arch, inject_nvram=True)
   # 正式验证：payload 在设备视图内执行
5. 检查 log_tail 中 payload 的副作用（写文件/回连/输出），回填 verdict
6. iot_emulation_chroot_cleanup(workdir, remove_workdir=True)
```

## 常见问题

- 固件需要 NVRAM 配置 → `inject_nvram=True`（自动下载注入 libnvram.so + `-E LD_PRELOAD`）；仍报错则检查 `/proc` 厂商文件是否缺失（判断是否影响目标服务）
- 程序需要交互/等待 → `timeout` 参数控制；`command` 里可带 shell 重定向（`> /tmp/out`）把副作用写进工作副本取证
- qemu-user 不支持特定 syscall/段错误 → 记录原因，标 NEEDS_DYNAMIC（止损规则）
- 工作副本很大 → 磁盘紧张时验证完立即 `remove_workdir=True` 清理
- **`/tmp` 或 `/var/run` 写不进去（"can't create"）** → 固件 /tmp 通常是 symlink→/var/tmp 且 /var/run 不存在（设备上 /var 是 tmpfs），chroot 必须挂 tmpfs（工具已自动处理；手动排查时 `ls -ld <workdir>/var/tmp <workdir>/var/run` 确认）
- **`-L` 模式跑 guest 程序报 "Invalid ELF image"** → `-L` 只重定向 guest 内部 open，**程序路径本身是 host 路径**，必须写完整 host 路径（`qemu-mipsel-static -L <rootfs> <rootfs>/bin/sh ...`）；chroot 模式无此问题
- **VM 诊断命令静默失败** → VM 默认 shell 可能是 zsh：`echo ===XXX===` 触发 `=command` 展开报错、含单引号的命令嵌套 `bash -c '...'` 会截断。**VM 上跑多段命令统一用 base64 编码执行**（`echo <b64> | base64 -d | bash`），这是项目已验证的稳法
- **固件 daemon 需要运行时数据**（xmldb/NVRAM）→ 属 B 级，按验证边界处理，不硬补

## 取舍原则

- **值得修**：成本低，不修就完全不能跑
- **值得绕过**：有替代路径达到验证目的
- **不值得修**：与漏洞验证无关的环境问题

目标是让目标服务跑起来接收请求——不是让整个固件完美运行。
