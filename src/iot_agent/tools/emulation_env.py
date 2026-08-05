"""Emulation environment management -- QEMU system mode + FirmAE on the VM.

Design rules (also enforced in .claude/skills/iot-emulate-firmware.md):

1. Kernels are NEVER guessed or searched for: ``match_kernel()`` first tries
   a kernel embedded in the rootfs, then reads the kernel manifest
   (``kernel_assets.ensure_kernel``).
2. Manual QEMU boots from per-arch templates (``boot-templates.json``), not
   from command lines invented on the spot.
3. FirmAE is the preferred system-emulation path; ``start_firmae()`` runs the
   full init + run flow in the background and polls logs to report whether
   the device actually booted (and why not, if it failed).
4. For single-service verification (CGI/daemon), ``chroot_launch()`` prepares
   a chroot of the extracted rootfs with proc/dev/tmp mounts and the arch
   matched libnvram, then optionally starts the target service -- no full
   system emulation needed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time

import structlog

from iot_agent.config import settings
from iot_agent.tools import kernel_assets
from iot_agent.tools.remote_vm import VMRemoteExecutor

logger = structlog.get_logger(__name__)

# Boot markers found in FirmAE serial logs / run logs
_BOOT_OK_MARKERS = [
    "login:", "init started", "starting network", "busybox v", "starting pid",
]
_BOOT_FAIL_MARKERS = [
    "kernel panic", "no init found", "unable to mount root",
    "qemu: fatal", "attempted to kill init",
]


class EmulationManager:
    """Manages QEMU system-mode emulation and FirmAE on the analysis VM."""

    def __init__(self, vm: VMRemoteExecutor):
        self.vm = vm

    async def detect_arch(self, rootfs_path: str) -> str | None:
        """Detect the architecture of a firmware rootfs by inspecting ELF headers."""
        result = await self.vm.execute(
            f"find {rootfs_path} -type f -executable | head -20 | "
            f"xargs -I{{}} readelf -h {{}} 2>/dev/null | "
            f"grep -E 'Machine:|Class:' | head -4"
        )
        if result.exit_code != 0:
            logger.warning(
                "arch detection command failed",
                rootfs=rootfs_path, stderr=result.stderr[:300],
            )
            return None

        text = result.stdout.lower()
        if "mips" in text and "64" not in text:
            return "mips"
        if "mips" in text:
            return "mips64"
        if "arm" in text or "aarch32" in text:
            return "arm"
        if "aarch64" in text:
            return "aarch64"
        if "intel" in text or "x86" in text:
            return "x86"
        logger.warning("unknown architecture", rootfs=rootfs_path, readelf_output=text[:200])
        return None

    async def match_kernel(self, arch: str, rootfs_path: str = "") -> str | None:
        """Return a kernel path for ``arch``.

        Priority: 1) kernel embedded in the firmware rootfs (if given),
        2) kernel manifest -- provisioning from FirmAE binaries or the pinned
        registry URL if the file is missing. Never guesses filenames.
        """
        if rootfs_path:
            result = await self.vm.execute(
                f"find {rootfs_path} -name 'vmlinu*' -o -name 'zImage' "
                f"-o -name 'bzImage' 2>/dev/null | head -1"
            )
            if result.exit_code == 0 and result.stdout.strip():
                kernel_path = result.stdout.strip()
                logger.info("found embedded kernel", path=kernel_path)
                return kernel_path

        return await kernel_assets.ensure_kernel(self.vm, arch)

    async def load_boot_template(self, arch: str) -> dict:
        """Load the per-arch boot template (creating defaults when missing).

        Asset names are always overlaid from ``kernel_assets.BOOT_IMAGES`` so
        the template points at exactly the files that get auto-provisioned.
        """
        path = settings.vm_qemu_boot_templates
        result = await self.vm.execute(f"cat {path} 2>/dev/null || echo __MISSING__")
        if "__MISSING__" in result.stdout:
            await kernel_assets.ensure_boot_templates(self.vm)
            result = await self.vm.execute(f"cat {path} 2>/dev/null || echo __MISSING__")
        try:
            templates = json.loads(result.stdout)
            tmpl = templates.get(arch, {}) or {}
        except (json.JSONDecodeError, ValueError):
            logger.warning("boot templates unreadable", path=path)
            tmpl = {}
        for asset in kernel_assets.BOOT_IMAGES.get(arch, []):
            if asset["role"] in ("kernel", "initrd", "disk"):
                tmpl[asset["role"]] = asset["name"]
        return tmpl

    @staticmethod
    def _full_path(name: str, base: str) -> str:
        return name if name.startswith("/") else f"{base}/{name}"

    async def start_qemu_system(
        self, arch: str = "mips", kernel: str = "", disk_image: str = ""
    ) -> dict:
        """Boot via the per-arch template.

        Returns ``{"started", "log", "error", "template", "command"}``.
        """
        # Auto-provision the boot images (kernel/disk) before booting.
        images = await kernel_assets.ensure_boot_images(self.vm, arch, wait=False)
        if not images.get("ready"):
            return {
                "started": False,
                "stage": "provisioning",
                "status": images,
                "log": "",
                "error": (
                    f"boot images for {arch} are missing; they are downloading "
                    f"in the background -- call "
                    f"kernel_assets.ensure_boot_images(vm, '{arch}') (wait) or "
                    f"boot_image_status() to check progress"
                ),
            }

        tmpl = await self.load_boot_template(arch)
        if not tmpl:
            return {
                "started": False,
                "error": f"no boot template for {arch}",
                "log": "",
            }

        kernel = kernel or self._full_path(
            tmpl.get("kernel", ""), settings.vm_qemu_image_dir
        )
        disk_image = disk_image or self._full_path(
            tmpl.get("disk", ""), settings.vm_qemu_image_dir
        )
        if not kernel or not disk_image:
            return {
                "started": False,
                "error": f"template for {arch} is missing kernel/disk",
                "log": "",
                "template": tmpl,
            }

        initrd = (
            self._full_path(tmpl["initrd"], settings.vm_qemu_image_dir)
            if tmpl.get("initrd")
            else None
        )
        result = await self.vm.run_qemu_system(
            kernel=kernel,
            disk_image=disk_image,
            arch=arch,
            machine=tmpl.get("machine"),
            append=tmpl.get("append"),
            initrd=initrd,
            hostfwd=tmpl.get("hostfwd"),
        )

        # Give QEMU a moment, then verify the process is alive and grab the log
        await self.vm.execute("sleep 8")
        alive = await self.vm.execute("pgrep -f qemu-system >/dev/null 2>&1 && echo alive")
        log = await self.vm.execute(f"tail -n 25 /tmp/qemu-{arch}.log 2>/dev/null")
        started = result.exit_code == 0 and "alive" in alive.stdout
        logger.info("qemu system start", arch=arch, started=started)
        return {
            "started": started,
            "log": log.stdout[-2000:],
            "error": "" if started else "qemu exited or failed to start (see log)",
            "template": tmpl,
            "command": f"kernel={kernel} disk={disk_image} machine={tmpl.get('machine', 'malta')}",
        }

    async def start_firmae(self, firmware_path: str, timeout_sec: int = 900) -> dict:
        """Start FirmAE (init + run) in the background and wait for boot.

        Returns ``{"started", "stage", "reason", "ip", "qemu_pid", "log_tail"}``.
        """
        firmae = settings.firmae_dir
        cmd = (
            f"cd {firmae} && (bash ./init.sh {firmware_path} "
            f"&& bash ./run.sh -r {firmware_path}) "
            f"< /dev/null > /tmp/firmae-run.log 2>&1 & echo started"
        )
        result = await self.vm.execute(cmd, timeout=30)
        if result.exit_code != 0:
            return {
                "started": False,
                "stage": "launch",
                "reason": result.stderr[:300],
                "log_tail": "",
            }

        await self.vm.execute("sleep 20")  # let init.sh extract before polling
        return await self.wait_firmae_ready(timeout_sec=timeout_sec)

    async def wait_firmae_ready(self, timeout_sec: int = 900) -> dict:
        """Poll FirmAE logs until boot succeeds/fails or timeout."""
        deadline = time.monotonic() + timeout_sec
        last_tail = ""
        ip = ""
        while time.monotonic() < deadline:
            log = await self.vm.execute("tail -n 40 /tmp/firmae-run.log 2>/dev/null")
            last_tail = log.stdout[-2500:]
            ip = await self._extract_firmae_ip()
            qemu = await self.vm.execute("pgrep -f qemu-system | head -1")
            qemu_pid = qemu.stdout.strip()

            serial = await self.vm.execute(
                "tail -n 60 $(ls -t /opt/firmae/scratch/*/qemu.initial.serial.log "
                "2>/dev/null | head -1) 2>/dev/null"
            )
            serial_tail = serial.stdout[-3000:]
            low_run = last_tail.lower()
            low_serial = serial_tail.lower()

            if any(m in low_serial for m in _BOOT_OK_MARKERS) or any(
                m in low_run for m in _BOOT_OK_MARKERS
            ):
                logger.info("firmae boot detected", ip=ip or "unknown")
                return {
                    "started": True,
                    "stage": "boot",
                    "reason": "login/init marker found",
                    "ip": ip,
                    "qemu_pid": qemu_pid,
                    "log_tail": (serial_tail or last_tail)[-2000:],
                }

            for marker in _BOOT_FAIL_MARKERS:
                if marker in low_serial or marker in low_run:
                    logger.warning("firmae boot failure detected", marker=marker)
                    return {
                        "started": False,
                        "stage": "boot_failed",
                        "reason": marker,
                        "ip": ip,
                        "qemu_pid": qemu_pid,
                        "log_tail": (serial_tail or last_tail)[-2000:],
                    }

            await asyncio.sleep(15)

        return {
            "started": False,
            "stage": "timeout",
            "reason": f"no boot marker within {timeout_sec}s",
            "ip": ip,
            "log_tail": last_tail[-2000:],
        }

    async def _extract_firmae_ip(self) -> str:
        """Grep the emulated device IP from FirmAE run/serial logs."""
        result = await self.vm.execute(
            "grep -rhoE 'inet addr:[0-9.]+|inet [0-9.]+|ip : [0-9.]+' "
            "/tmp/firmae-run.log /opt/firmae/scratch/*/qemu.initial.serial.log "
            "2>/dev/null | head -1"
        )
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", result.stdout)
        return m.group(1) if m else ""

    async def chroot_launch(
        self,
        rootfs_path: str,
        service: str = "",
        arch: str = "mipsel",
    ) -> dict:
        """Prepare a chroot of the extracted rootfs and optionally run a service.

        Steps:
        1. Provision FirmAE runtime assets (busybox / libnvram / console).
        2. Bind-mount /proc, /dev, /tmp into the rootfs (sudo).
        3. Install the arch-matched libnvram.so into rootfs/lib if missing.
        4. If ``service`` is given, launch it via ``chroot`` with
           ``LD_PRELOAD=/lib/libnvram.so``.

        Returns ``{"started", "stage", "rootfs", "nvram", "log_tail", "error"}``.
        """
        from iot_agent.tools import kernel_assets as ka

        await ka.provision_runtime_assets(self.vm)
        rootfs = rootfs_path.rstrip("/")
        password = settings.vm_ssh_password
        # NOTE: every SSH exec_command is its own session, so sudo's
        # credential cache does NOT carry over -- pipe the password on
        # each privileged command.
        def sudo(cmd: str) -> str:
            return f"echo '{password}' | sudo -S -p '' {cmd}"

        # 1) cache sudo credentials
        r = await self.vm.execute(f"{sudo('-v')} 2>/dev/null && echo SUDO_OK")
        if "SUDO_OK" not in r.stdout:
            return {
                "started": False,
                "stage": "sudo",
                "rootfs": rootfs,
                "error": "sudo credential check failed",
                "log_tail": r.stderr[:300],
            }

        # 2) bind mounts
        mount_script = (
            f"for d in proc dev tmp; do [ -d {rootfs}/$d ] || {sudo(f'mkdir -p {rootfs}/$d')}; done; "
            f"{sudo(f'mount -t proc /proc {rootfs}/proc')} 2>/dev/null || true; "
            f"{sudo(f'mount -o bind /dev {rootfs}/dev')} 2>/dev/null || true; "
            f"{sudo(f'mount -t tmpfs tmpfs {rootfs}/tmp')} 2>/dev/null || true; "
            f"mount | grep {rootfs} | head -5"
        )
        mounts = await self.vm.execute(mount_script)

        # 3) install libnvram for the architecture
        nvram_name = ka.ARCH_RUNTIME.get(arch, {}).get("libnvram", "")
        nvram_installed = ""
        if nvram_name:
            nvram_src = f"{ka.runtime_dir()}/{nvram_name}"
            nvram_installed = f"{rootfs}/lib/libnvram.so"
            await self.vm.execute(
                f"cp -f {nvram_src} {rootfs}/lib/libnvram.so 2>/dev/null || true; "
                f"cp -f {nvram_src} {rootfs}/lib/{nvram_name} 2>/dev/null || true"
            )

        result = {
            "started": False,
            "stage": "prepared",
            "rootfs": rootfs,
            "nvram": nvram_installed,
            "mounts": mounts.stdout.strip()[:500],
            "log_tail": "",
            "error": "",
        }

        # 4) launch the target service (optional)
        if service:
            # The service string may itself contain paths (e.g. '> /tmp/x'),
            # so derive a safe, unique filename from a hash instead of
            # splitting on '/'.
            base = hashlib.sha256(service.encode("utf-8")).hexdigest()[:12]
            logpath = f"/tmp/chroot-{base}.log"
            pidfile = f"{logpath}.pid"
            launch_script = f"/tmp/chroot-launch-{base}.sh"
            result["launch_mode"] = ""
            for attempt, env_prefix in enumerate(
                [
                    "env PATH=/bin:/sbin:/usr/bin:/usr/sbin LD_PRELOAD=/lib/libnvram.so",
                    "env PATH=/bin:/sbin:/usr/bin:/usr/sbin",
                ]
            ):
                # Encode the launch script in base64: avoids quoting hell and
                # detaches the background job so the SSH channel closes
                # immediately. setsid puts the job in a new session (otherwise
                # sshd kills the whole process group when the channel closes);
                # in a non-interactive shell it execs without forking, so the
                # recorded PID stays valid for kill -0.
                script = (
                    f"setsid nohup {env_prefix} chroot {rootfs} {service} "
                    f"< /dev/null > {logpath} 2>&1 &\n"
                    f"echo $! > {pidfile}\n"
                )
                b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
                launch = (
                    f"echo '{password}' | sudo -S -p '' bash -c "
                    f"'echo {b64} | base64 -d > {launch_script} && "
                    f"bash {launch_script} && echo SPAWNED'"
                )
                launched = await self.vm.execute(launch, timeout=30)
                await self.vm.execute("sleep 3")
                pid_read = await self.vm.execute(f"cat {pidfile} 2>/dev/null")
                pid = pid_read.stdout.strip().splitlines()[-1] if pid_read.stdout.strip() else ""
                # kill -0 probes the process; the service runs as root so the
                # probe must also run as root (EPERM otherwise).
                alive = await self.vm.execute(
                    f"echo '{password}' | sudo -S -p '' kill -0 {pid} "
                    f">/dev/null 2>&1 && echo alive"
                ) if pid else None
                if launched.exit_code == 0 and alive is not None and "alive" in alive.stdout:
                    result["started"] = True
                    result["stage"] = "service"
                    result["launch_mode"] = "ld_preload" if attempt == 0 else "plain"
                    result["pid"] = pid
                    break
                # Try once more without LD_PRELOAD before giving up
            log = await self.vm.execute(f"tail -n 20 {logpath} 2>/dev/null")
            result["log_tail"] = log.stdout[-1500:]
            if not result["started"]:
                result["stage"] = "service_failed"
                result["error"] = f"service did not stay alive: {service}"
            logger.info(
                "chroot service launch",
                arch=arch, service=service, started=result["started"],
                mode=result["launch_mode"],
            )
        return result

    async def chroot_cleanup(self, rootfs_path: str, service: str = "") -> dict:
        """Stop the chroot service (if known) and unmount proc/dev/tmp.

        Returns ``{"unmounted": bool, "remaining": str}``. A service still
        running inside the chroot keeps the mounts busy, so it is killed
        first (via the pid recorded at launch), then unmount is attempted
        and falls back to a lazy unmount.
        """
        rootfs = rootfs_path.rstrip("/")
        if not rootfs or rootfs == "/" or not rootfs.startswith("/"):
            return {"unmounted": False, "remaining": "refusing unsafe rootfs path"}
        password = settings.vm_ssh_password

        if service:
            base = hashlib.sha256(service.encode("utf-8")).hexdigest()[:12]
            pidfile = f"/tmp/chroot-{base}.log.pid"
            pid = (await self.vm.execute(f"cat {pidfile} 2>/dev/null")).stdout.strip()
            if pid:
                await self.vm.execute(
                    f"echo '{password}' | sudo -S -p '' kill {pid} 2>/dev/null; sleep 1"
                )

        r = await self.vm.execute(
            f"echo '{password}' | sudo -S -p '' bash -c "
            f"'umount {rootfs}/proc 2>/dev/null; umount -l {rootfs}/proc 2>/dev/null; "
            f"umount {rootfs}/dev 2>/dev/null; umount -l {rootfs}/dev 2>/dev/null; "
            f"umount {rootfs}/tmp 2>/dev/null; umount -l {rootfs}/tmp 2>/dev/null; "
            f"sleep 1; mount | grep -c {rootfs} || true'"
        )
        remaining = r.stdout.strip()
        unmounted = remaining == "0"
        logger.info("chroot cleanup", rootfs=rootfs, unmounted=unmounted, remaining=remaining)
        return {"unmounted": unmounted, "remaining": remaining}

    async def get_emulated_device_info(self) -> dict:
        """Get info about the running emulated device."""
        qemu = await self.vm.execute("ps aux | grep qemu-system | grep -v grep | head -1")
        ip = await self._extract_firmae_ip()
        return {
            "running": bool(qemu.stdout.strip()),
            "ip": ip,
            "status": qemu.stdout.strip(),
        }
