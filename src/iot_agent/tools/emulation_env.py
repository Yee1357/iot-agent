"""Dynamic verification on the VM -- two tiers: quick probe + chroot-wrapped qemu-user.

Design rules (also enforced in .claude/skills/iot-emulate-firmware.md):

1. Full-system emulation (FirmAE, manual QEMU system mode) is REMOVED --
   in practice it was the least reliable part of agent-driven analysis.

2. Dynamic verification has exactly two tiers:
   - **Probe (``user_mode_run``)**: ``qemu-<arch>-static -L <rootfs> <cmd>``.
     Cheap (no sudo, no mounts), but the guest's absolute paths fall through
     to the HOST filesystem (``-L`` only redirects loader/libs). Use it to
     quickly confirm/exclude a sink BEFORE spending setup on the real
     verification. Its result alone is NEVER a final verdict.
   - **Verification (``chroot_user_mode``)**: copy the rootfs to a working
     copy, bind-mount /dev /dev/pts /proc, copy the qemu binary inside, then
     ``chroot <workdir> /usr/bin/qemu-<arch>-static -- <cmd>``. The qemu
     process itself is chrooted, so the guest sees the device view: /etc,
     /var/run, /bin/sh (busybox), /tmp are all inside the rootfs copy, and
     fork/exec of firmware binaries keeps being translated. This is the ONLY
     path whose result counts as a dynamic verdict. No binfmt_misc needed.
3. The binfmt-based ``chroot_launch`` (chroot + rely on host kernel
   binfmt_misc to interpret the ELF) is REMOVED: chroot-wrapped qemu-user is
   strictly more faithful and has no binfmt dependency.
4. qemu binaries are located automatically (``/usr/local/bin`` -> PATH ->
   bounded ``find``); never guessed. If missing, the caller reports the
   install command and escalates to the user (upgrade path L3).
"""

from __future__ import annotations

import base64
import hashlib

import structlog

from iot_agent.config import settings
from iot_agent.tools import runtime_assets
from iot_agent.tools.remote_vm import VMRemoteExecutor

logger = structlog.get_logger(__name__)

#: user-mode qemu binary per detected architecture
_QEMU_USER = {
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "x86": "qemu-x86_64-static",
}


class EmulationManager:
    """Manages lightweight dynamic verification (probe / chroot+qemu) on the VM."""

    def __init__(self, vm: VMRemoteExecutor):
        self.vm = vm

    # ------------------------------------------------------------------
    # qemu binary discovery
    # ------------------------------------------------------------------

    async def find_qemu(self, arch: str) -> str:
        """Locate ``qemu-<arch>-static`` on the VM. Returns absolute path or "".

        Search order: PATH (``command -v``) -> /usr/local/bin ->
        bounded find under /usr /opt /data. Never guesses filenames.
        """
        name = _QEMU_USER.get(arch, "")
        if not name:
            return ""
        r = await self.vm.execute(
            f"command -v {name} 2>/dev/null || ls /usr/local/bin/{name} 2>/dev/null || "
            f"find /usr /opt /data -maxdepth 4 -name '{name}' -type f 2>/dev/null | head -1"
        )
        path = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
        return path or ""

    async def ensure_qemu(self, arch: str) -> dict:
        """Locate qemu for ``arch`` and report. Returns {"arch", "found", "path", "install_hint"}."""
        path = await self.find_qemu(arch)
        if path:
            return {"arch": arch, "found": True, "path": path, "install_hint": ""}
        return {
            "arch": arch,
            "found": False,
            "path": "",
            "install_hint": f"sudo apt-get install -y qemu-user-static   # or place {_QEMU_USER.get(arch, 'qemu-<arch>-static')} in /usr/local/bin",
        }

    # ------------------------------------------------------------------
    # Tier 1: quick probe (-L). NOT a final verdict.
    # ------------------------------------------------------------------

    async def user_mode_run(
        self,
        rootfs_path: str,
        command: str,
        arch: str = "",
    ) -> dict:
        """Quick probe: run ``command`` via qemu user-mode with ``-L rootfs``.

        WARNING: guest absolute paths (/etc, /tmp, /bin/sh) fall through to
        the HOST filesystem -- only loader/libs are redirected. Use this to
        confirm/exclude a sink cheaply; final verdicts require
        ``chroot_user_mode``.

        Returns ``{"started", "exit_code", "stdout", "stderr", "arch", "qemu"}``.
        """
        arch = arch or (await self.detect_arch(rootfs_path)) or ""
        qemu = await self.find_qemu(arch)
        if not qemu:
            return {
                "started": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"qemu-{arch}-static not found on VM (hint: apt-get install qemu-user-static)",
                "arch": arch,
                "qemu": "",
            }
        result = await self.vm.execute(f"{qemu} -L {rootfs_path} {command}", timeout=120)
        logger.info("user-mode probe", arch=arch, qemu=qemu, success=result.success)
        return {
            "started": result.success,
            "exit_code": result.exit_code,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-2000:],
            "arch": arch,
            "qemu": qemu,
        }

    # ------------------------------------------------------------------
    # Tier 2: chroot-wrapped qemu-user. THE dynamic verification path.
    # ------------------------------------------------------------------

    async def chroot_user_mode(
        self,
        rootfs_path: str,
        command: str,
        arch: str = "",
        workdir: str = "",
        inject_nvram: bool = False,
        timeout: int = 120,
    ) -> dict:
        """Verify by running ``command`` inside a chroot of the rootfs.

        Mirrors the proven one-shot repro pattern: copy the rootfs to a
        working copy (never touch the original), copy the qemu binary inside,
        bind-mount /dev /dev/pts /proc, then

            sudo chroot <workdir> /usr/bin/qemu-<arch>-static [env...] -- <command>

        Because the qemu process is chrooted, guest absolute paths (/etc,
        /var/run, /tmp, /bin/sh) resolve inside the working copy and
        fork/exec of firmware binaries keeps being translated. No binfmt
        dependency. This result MAY be used as a dynamic verdict.

        Steps: provision qemu -> copy rootfs (idempotent) -> mounts ->
        launch in background (setsid, pidfile) -> survival check.

        Returns ``{"started", "stage", "workdir", "qemu", "pid", "log_tail", "error"}``.
        """
        arch = arch or (await self.detect_arch(rootfs_path)) or ""
        qemu = await self.find_qemu(arch)
        if not qemu:
            hint = _QEMU_USER.get(arch, "")
            return {
                "started": False,
                "stage": "qemu_missing",
                "workdir": "",
                "qemu": "",
                "pid": "",
                "log_tail": "",
                "error": (
                    f"qemu-{arch}-static not found on VM "
                    f"(hint: sudo apt-get install -y qemu-user-static or place {hint} in /usr/local/bin)"
                ),
            }

        rootfs = rootfs_path.rstrip("/")
        workdir = (workdir or f"{rootfs}.chroot-qemu").rstrip("/")
        if workdir == "/" or not workdir.startswith("/"):
            return {
                "started": False,
                "stage": "bad_workdir",
                "workdir": workdir,
                "error": "refusing unsafe workdir path",
                "log_tail": "",
            }

        password = settings.vm_ssh_password

        def sudo(cmd: str) -> str:
            return f"echo '{password}' | sudo -S -p '' {cmd}"

        # 1) sudo credential cache
        r = await self.vm.execute(f"{sudo('-v')} 2>/dev/null && echo SUDO_OK")
        if "SUDO_OK" not in r.stdout:
            return {
                "started": False,
                "stage": "sudo",
                "workdir": workdir,
                "error": "sudo credential check failed",
                "log_tail": r.stderr[:300],
            }

        # 2) working copy (idempotent): fresh copy only when missing or stale
        qemu_in_chroot = f"{workdir}/usr/bin/{_QEMU_USER.get(arch)}"
        need_copy = False
        check = await self.vm.execute(f"test -d {workdir}/usr/sbin && test -f {qemu_in_chroot} && echo OK")
        if "OK" not in check.stdout:
            need_copy = True
        if need_copy:
            logger.info("building chroot working copy", src=rootfs, dst=workdir)
            await self.vm.execute(
                f"{sudo(f'rm -rf {workdir}')}; {sudo(f'mkdir -p {workdir}')}; "
                f"{sudo(f'cp -a {rootfs}/. {workdir}/')}; "
                f"{sudo(f'mkdir -p {workdir}/usr/bin {workdir}/dev/pts {workdir}/proc {workdir}/tmp')}; "
                f"{sudo(f'cp -f {qemu} {qemu_in_chroot}')}; "
                f"{sudo('chmod 755 %s' % qemu_in_chroot)}"
            )

        # 3) optional libnvram injection (LD_PRELOAD via qemu -E)
        env_prefix = ""
        if inject_nvram:
            nvram_name = runtime_assets.ARCH_RUNTIME.get(arch, {}).get("libnvram", "")
            if nvram_name:
                await runtime_assets.provision_runtime_assets(self.vm)
                nvram_src = f"{runtime_assets.runtime_dir()}/{nvram_name}"
                await self.vm.execute(
                    f"{sudo(f'cp -f {nvram_src} {workdir}/lib/libnvram.so')} 2>/dev/null || true"
                )
                env_prefix = "-E LD_PRELOAD=/lib/libnvram.so "

        # 4) bind mounts (dev/dev/pts/proc) + tmpfs /var/tmp + /var/run.
        # NB: firmware rootfs /var is usually a tmpfs at runtime -- /tmp is a
        # symlink to /var/tmp and /var/run does not exist in the image.
        # Without them the guest cannot write /tmp or /var/run at all
        # ("can't create"), which breaks daemons and lxmldbc scripts.
        mounts = await self.vm.execute(
            f"{sudo(f'mkdir -p {workdir}/var/tmp {workdir}/var/run')}; "
            f"mountpoint -q {workdir}/dev || {sudo(f'mount --bind /dev {workdir}/dev')}; "
            f"mountpoint -q {workdir}/dev/pts || {sudo(f'mount --bind /dev/pts {workdir}/dev/pts')}; "
            f"mountpoint -q {workdir}/proc || {sudo(f'mount -t proc /proc {workdir}/proc')}; "
            f"mountpoint -q {workdir}/var/tmp || {sudo(f'mount -t tmpfs tmpfs {workdir}/var/tmp')}; "
            f"mountpoint -q {workdir}/var/run || {sudo(f'mount -t tmpfs tmpfs {workdir}/var/run')}; "
            f"mount | grep {workdir} | head -7"
        )

        # 5) launch: base64-encoded setsid script so the SSH channel closes
        base = hashlib.sha256((workdir + command).encode("utf-8")).hexdigest()[:12]
        logpath = f"/tmp/chrootqemu-{base}.log"
        pidfile = f"{logpath}.pid"
        script = (
            f"setsid nohup chroot {workdir} /usr/bin/{_QEMU_USER.get(arch)} {env_prefix}-- "
            f"{command} < /dev/null > {logpath} 2>&1 &\n"
            f"echo $! > {pidfile}\n"
        )
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        launch_script = f"/tmp/chrootqemu-launch-{base}.sh"
        launched = await self.vm.execute(
            f"{sudo('bash -c \"echo %s | base64 -d > %s && bash %s && echo SPAWNED\"' % (b64, launch_script, launch_script))}",
            timeout=30,
        )
        await self.vm.execute("sleep 3")
        pid_read = await self.vm.execute(f"cat {pidfile} 2>/dev/null")
        pid = pid_read.stdout.strip().splitlines()[-1] if pid_read.stdout.strip() else ""
        alive = (
            await self.vm.execute(f"{sudo(f'kill -0 {pid}')} >/dev/null 2>&1 && echo alive")
            if pid
            else None
        )
        started = launched.exit_code == 0 and alive is not None and "alive" in alive.stdout
        log = await self.vm.execute(f"tail -n 25 {logpath} 2>/dev/null")
        result = {
            "started": started,
            "stage": "running" if started else "launch_failed",
            "workdir": workdir,
            "qemu": qemu,
            "pid": pid,
            "log_tail": log.stdout[-2000:],
            "mounts": mounts.stdout.strip()[:400],
            "error": "" if started else f"process did not stay alive: {command}",
        }
        logger.info("chroot+qemu launch", arch=arch, started=started, workdir=workdir)
        return result

    async def chroot_cleanup(
        self,
        workdir: str,
        process_match: str = "qemu-.*-static",
        remove_workdir: bool = False,
    ) -> dict:
        """Stop the chrooted qemu process and unmount dev/pts/proc.

        ``workdir`` is the chroot working copy created by
        ``chroot_user_mode``. ``process_match`` is an extended-regex matched
        against the command line of running processes (default: any
        user-mode qemu). Returns ``{"unmounted": bool, "remaining": str}``.
        """
        workdir = (workdir or "").rstrip("/")
        if not workdir or workdir == "/" or not workdir.startswith("/"):
            return {"unmounted": False, "remaining": "refusing unsafe workdir path"}
        password = settings.vm_ssh_password

        await self.vm.execute(
            f"echo '{password}' | sudo -S -p '' pkill -f '{process_match}' 2>/dev/null; sleep 1"
        )
        r = await self.vm.execute(
            f"echo '{password}' | sudo -S -p '' bash -c "
            f"'umount {workdir}/dev/pts 2>/dev/null; umount -l {workdir}/dev/pts 2>/dev/null; "
            f"umount {workdir}/dev 2>/dev/null; umount -l {workdir}/dev 2>/dev/null; "
            f"umount {workdir}/proc 2>/dev/null; umount -l {workdir}/proc 2>/dev/null; "
            f"umount {workdir}/var/tmp 2>/dev/null; umount -l {workdir}/var/tmp 2>/dev/null; "
            f"umount {workdir}/var/run 2>/dev/null; umount -l {workdir}/var/run 2>/dev/null; "
            f"sleep 1; mount | grep -c {workdir} || true'"
        )
        remaining = r.stdout.strip()
        unmounted = remaining == "0"
        if unmounted and remove_workdir:
            await self.vm.execute(
                f"echo '{password}' | sudo -S -p '' rm -rf {workdir}"
            )
        logger.info("chroot+qemu cleanup", workdir=workdir, unmounted=unmounted, remaining=remaining)
        return {"unmounted": unmounted, "remaining": remaining}

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
