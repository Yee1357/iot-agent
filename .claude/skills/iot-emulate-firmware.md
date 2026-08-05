---
name: iot-emulate-firmware
description: QEMU 全系统模拟。在 VM 上用 FirmAE 或手动 QEMU 启动固件，验证漏洞。用户要求模拟固件、跑起来验证漏洞、复现攻击时使用。
argument-hint: "[firmware_model]"
---

# QEMU 固件模拟 & 动态验证
**所有操作在 VM 上完成。**

## 铁律：内核与镜像的来源

- **禁止自行搜索或猜测内核下载地址。** 内核一律来自清单 `/data/qemu-images/kernels/manifest.json`（由 `scripts/provision_kernels.py` 维护）。
- 补齐内核（VM 上执行，幂等）：
```bash
python /path/to/scripts/provision_kernels.py --arch mipsel   # 或 --all
```
- QEMU 启动参数一律使用模板 `/data/qemu-images/boot-templates.json`（由 `EmulationManager.load_boot_template()` 读取），**不要手工拼 QEMU 命令行**。

## 方式一：FirmAE（优先）

代码调用（推荐）：
```python
from iot_agent.tools.remote_vm import VMRemoteExecutor
from iot_agent.tools.emulation_env import EmulationManager

async with VMRemoteExecutor() as vm:
    emu = EmulationManager(vm)
    result = await emu.start_firmae("/data/firmware/xxx.bin")
    # result: {started, stage, reason, ip, qemu_pid, log_tail}
```

- `start_firmae()` 会执行 init + run（`run.sh -r`）并在后台轮询启动日志，直到出现登录/init 标记、失败标记或超时。
- **判断标准**：`result["started"] == True` 才算启动成功；失败时看 `result["stage"]`（launch / boot_failed / timeout）和 `result["reason"]`（kernel panic / no init / …），据此决定修复方向，不要盲目重试。
- 设备 IP：`result["ip"]`；也可随时查 `emu.get_emulated_device_info()`。

等价手动命令（调试 FirmAE 内部流程时才用）：
```bash
cd /opt/firmae && bash ./init.sh <firmware_path> && bash ./run.sh -r <firmware_path>
```

## 方式二：手动 QEMU（FirmAE 失败后的兜底）

按模板启动，不要手拼参数：
```python
result = await emu.start_qemu_system(arch="mipsel")
# {started, log, error, template, command}
```
- **镜像自动下载**：`start_qemu_system()` 启动前会自动检查 kernel/initrd/qcow2 是否就位，缺失即自动下载（内核等小文件同步下；约 270-290MB 的 qcow2 后台下载）。
  - 显式等待/查进度：
    ```python
    from iot_agent.tools import kernel_assets
    await kernel_assets.ensure_boot_images(vm, "mipsel")   # 阻塞直到就绪
    status = await kernel_assets.boot_image_status(vm, "mipsel")  # 查进度
    ```
  - 返回 `stage="provisioning"` 表示镜像还在下载，不要重试启动，先轮询进度。
- 模板里的 kernel/disk 是文件名，位于 `/data/qemu-images/`；来源为 aurel32 Debian 镜像（`people.debian.org/~aurel32/qemu/`），下载地址与架构映射见 `kernel_assets.BOOT_IMAGES`。
- 启动后验证：`curl -v http://127.0.0.1:8080/`（hostfwd 端口来自模板）。

## 方式三：D-Link 固件一键系统态（推荐给 D-Link/类 D-Link）

针对 D-Link 系固件（DIR-8xx 等），用现成脚本一条命令完成整套系统态：

```bash
python scripts/emulate_dlink.py --firmware /path/on/vm/fw.bin
# 或直接给已解包的 rootfs：
python scripts/emulate_dlink.py --rootfs /path/squashfs-root
```

脚本自动完成：下载 Debian 内核+镜像（缺失时）→ 建 tap0 网络 → 启动 qemu →
注入 rootfs（httpd/htdocs/etc/uClibc 库）→ 启动 xmldb + dbload → 启动 httpd →
验证 Web 界面与 HNAP 响应。状态与停止：

```bash
python scripts/emulate_dlink.py --status
python scripts/emulate_dlink.py --stop
```

**要点**：D-Link 的 httpd 是 Mathopd，动态页面（index.php/HNAP）依赖
`xmldb` 守护进程（`/var/run/xmldb_sock`）——只起 httpd 会导致动态请求挂起，
必须把固件 `usr/sbin/{xmldb,xmldbc,servd}` 传入 guest 并执行
`xmldb -n <image_sign> -t` + `dbload.sh`。Web 端口默认 1234，guest IP
192.168.100.2。

注入 rootfs 并启动服务（仅验证目标服务时最快）——用封装好的标准入口：
```python
res = await emu.chroot_launch(
    rootfs_path="/data/extracted/<brand>/<model>_<ver>/rootfs",
    service="/usr/sbin/httpd",
    arch="mipsel",   # 由 readelf 判定，见 EmulationManager.detect_arch()
)
# res: {started, stage, launch_mode, pid, log_tail, error}
# 结束记得清理：
await emu.chroot_cleanup(rootfs_path="...", service="/usr/sbin/httpd")
```

`chroot_launch()` 自动完成：挂载 proc/dev/tmp → 注入架构匹配的 `libnvram.so`（`LD_PRELOAD`）→ 后台启动服务 → 存活检测（失败会自动去掉 `LD_PRELOAD` 重试一次）。

## 验证策略（按成本排序）

1. **user-mode 优先**：`qemu-mipsel-static -L <rootfs>` 直接跑 PoC（命令注入类最快最稳）。
2. **chroot 注入**：目标只是某个 CGI/守护进程时，chroot rootfs 起服务。
3. **FirmAE 全系统**：需要完整网络栈/内核接口时。
4. **手动 QEMU**：FirmAE 不可用时的兜底。

## 模拟中常见问题
- 固件需要的 NVRAM 配置缺失 → FirmAE 自动处理，手动时搜索 `/nvram` 相关初始化脚本
- `/proc` 下缺少厂商内核模块注册的文件 → 可能导致特定守护进程 crash，判断是否影响目标服务
- 非标准 web 架构（非 httpd + CGI）→ 可能需要逆向理解组件依赖关系

## 取舍原则
- **值得修**：成本低，不修就完全不能跑
- **值得绕过**：有替代路径达到验证目的
- **不值得修**：与漏洞验证无关的环境问题

目标是让目标服务跑起来接收请求——不是让整个固件完美运行。
