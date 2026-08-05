"""One-command D-Link firmware system emulation on the analysis VM.

Automates the full manual recipe: auto-download boot images, set up a tap
network, boot qemu-system-mipsel, inject the firmware rootfs, start the D-Link
runtime stack (xmldb + httpd) and verify the web UI responds.

Usage:
    python scripts/emulate_dlink.py --firmware <path-on-vm> [--arch mipsel]
    python scripts/emulate_dlink.py --rootfs <squashfs-root-on-vm>
    python scripts/emulate_dlink.py --status
    python scripts/emulate_dlink.py --stop
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import posixpath
import sys
from pathlib import Path

from iot_agent.config import settings
from iot_agent.tools import kernel_assets
from iot_agent.tools.remote_vm import VMRemoteExecutor

GUEST_DRIVER = Path(__file__).resolve().parent / "guest_driver.py"

GUEST_IP = "192.168.100.2"
HOST_IP = "192.168.100.1"
WEB_PORT = "1234"
HTTP_SERVE_PORT = 8000
ROOTFS_NAME = "squashfs-root"


async def _upload(vm: VMRemoteExecutor, remote_path: str, content: str) -> None:
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    r = await vm.execute(f"echo {b64} | base64 -d > {remote_path} && echo UPLOADED")
    if "UPLOADED" not in r.stdout:
        raise SystemExit(f"upload failed: {remote_path}")


async def _gd(vm: VMRemoteExecutor, args: list[str], timeout: int = 180) -> str:
    r = await vm.execute(f"python3 /tmp/guest_driver.py {' '.join(args)} 2>&1", timeout=timeout)
    return r.stdout


async def _prepare_tap(vm: VMRemoteExecutor) -> None:
    sudo_user = settings.vm_ssh_user or "kali"
    r = await vm.execute(
        f"echo '{settings.vm_ssh_password}' | sudo -S -p '' bash -c 'ip link set tap0 down 2>/dev/null; "
        f"ip tuntap del dev tap0 2>/dev/null; ip tuntap add dev tap0 mode tap user {sudo_user}; "
        f"ip addr add {HOST_IP}/24 dev tap0 2>/dev/null; ip link set tap0 up'; "
        f"ip -4 addr show tap0 | grep {HOST_IP}"
    )
    if HOST_IP not in r.stdout:
        raise SystemExit(f"tap0 setup failed: {r.stdout}")


async def _prepare_work_image(vm: VMRemoteExecutor, arch: str) -> str:
    disk = "debian_squeeze_mipsel_standard.qcow2" if arch == "mipsel" else (
        "debian_squeeze_mips_standard.qcow2" if arch == "mips" else "debian_squeeze_armel_standard.qcow2"
    )
    work = "dir815-work.qcow2" if arch in ("mips", "mipsel") else "dir815-arm-work.qcow2"
    r = await vm.execute(
        f"cd /data/qemu-images && test -f {work} || cp {disk} {work}; ls -la {work}"
    )
    return work


async def _launch_qemu(vm: VMRemoteExecutor, arch: str, kernel: str, work: str) -> None:
    r = await vm.execute("ps aux | grep -c '[q]emu-system'")
    if r.stdout.strip() not in ("", "0"):
        print("[i] qemu already running, skipping launch")
        return
    # Debian boot kernels live in the images dir, NOT in kernels/ (which
    # holds the FirmAE kernels).
    kernel_path = f"/data/qemu-images/{kernel}"
    machine = "malta" if arch in ("mips", "mipsel") else "versatilepb"
    start = f"""#!/bin/bash
cd /data/qemu-images
exec qemu-system-{"mipsel" if arch == "mipsel" else arch} \\
  -M {machine} -kernel {kernel_path} \\
  -hda {work} \\
  -append 'root=/dev/sda1 console=ttyS0' \\
  -net nic,macaddr=00:16:3e:00:00:01 -net tap,ifname=tap0,script=no,downscript=no \\
  -display none -serial unix:/tmp/qemu-serial.sock,server,nowait \\
  -monitor unix:/tmp/qemu-mon.sock,server,nowait \\
  < /dev/null > /data/qemu-images/qemu-run.log 2>&1
"""
    launch = "#!/bin/bash\nsetsid nohup bash /tmp/start-qemu.sh < /dev/null > /data/qemu-images/qemu-launch.log 2>&1 &\necho DETACHED\n"
    await _upload(vm, "/tmp/start-qemu.sh", start)
    await _upload(vm, "/tmp/launch-qemu.sh", launch)
    r = await vm.execute("rm -f /tmp/qemu-serial.sock; bash /tmp/launch-qemu.sh; sleep 10; ls -la /tmp/qemu-serial.sock 2>&1")
    if "qemu-serial.sock" not in r.stdout:
        raise SystemExit(f"qemu launch failed: {r.stdout}")
    print("[+] qemu launched")


def http_conf(guest_ip: str, port: str) -> str:
    return f"""Umask 026
PIDFile /var/run/httpd.pid
LogGMT On
ErrorLog /log

Tuning
{{
    NumConnections 15
    BufSize 12288
    InputBufSize 4096
    ScriptBufSize 4096
    NumHeaders 100
    Timeout 60
    ScriptTimeout 60
}}

Control
{{
    Types
    {{
        text/html    {{ html htm }}
        text/xml    {{ xml }}
        text/plain    {{ txt }}
        image/gif    {{ gif }}
        image/jpeg    {{ jpg }}
        text/css    {{ css }}
        application/octet-stream {{ * }}
    }}
    Specials
    {{
        Dump        {{ /dump }}
        CGI            {{ cgi }}
        Imagemap    {{ map }}
        Redirect    {{ url }}
    }}
    External
    {{
        /usr/sbin/phpcgi {{ php }}
    }}
}}

Server
{{
    ServerName "Linux, HTTP/1.1, "
    ServerId "1234"
    Family inet
    Interface eth1
    Address {guest_ip}
    Port "{port}"
    Virtual
    {{
        AnyHost
        Control
        {{
            Alias /
            Location /htdocs/web
            IndexNames {{ index.php }}
            External
            {{
                /usr/sbin/phpcgi {{ router_info.xml }}
                /usr/sbin/phpcgi {{ post_login.xml }}
            }}
        }}
        Control
        {{
            Alias /HNAP1
            Location /htdocs/HNAP1
            External
            {{
                /usr/sbin/hnap {{ hnap }}
            }}
            IndexNames {{ index.hnap }}
        }}
    }}
}}
"""


async def _ensure_http_server(vm: VMRemoteExecutor) -> None:
    r = await vm.execute("curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:8000/rootfs.tar 2>/dev/null")
    if r.stdout.strip() == "200":
        return
    await vm.execute(
        "cd /tmp && (setsid nohup python3 -m http.server 8000 --bind 0.0.0.0 "
        "< /dev/null > /tmp/httpd-serve.log 2>&1 &) ; echo STARTED"
    )
    await asyncio.sleep(2)


async def _serve_and_fetch(
    vm: VMRemoteExecutor, rootfs_parent: str, rootfs_name: str, guest_dir: str
) -> None:
    r = await vm.execute(
        f"tar -C {rootfs_parent} -cf /tmp/rootfs.tar {rootfs_name}; "
        f"cd {rootfs_parent}/{rootfs_name} && tar -cf /tmp/usr-sbin.tar "
        "usr/sbin/xmldb usr/sbin/xmldbc usr/sbin/servd usr/sbin/event usr/sbin/phpsh; "
        "ls -la /tmp/rootfs.tar /tmp/usr-sbin.tar"
    )
    print("[+] host tar:", r.stdout.replace("\n", " | ")[-300:])
    await _ensure_http_server(vm)
    out = await _gd(vm, ["fetch", f"http://{HOST_IP}:{HTTP_SERVE_PORT}/rootfs.tar", "/root/rootfs.tar"], timeout=300)
    print("[+] rootfs fetched:", out.replace("\n", " | ")[-120:])
    out = await _gd(vm, ["extract", "/root/rootfs.tar", "/root"], timeout=180)
    print("[+] rootfs extracted:", out.replace("\n", " | ")[-120:])
    out = await _gd(vm, ["fetch", f"http://{HOST_IP}:{HTTP_SERVE_PORT}/usr-sbin.tar", "/root/usr-sbin.tar"], timeout=120)
    print("[+] usr-sbin fetched:", out.replace("\n", " | ")[-120:])
    out = await _gd(vm, ["extract", "/root/usr-sbin.tar", "/"], timeout=120)
    print("[+] usr-sbin installed:", out.replace("\n", " | ")[-120:])


async def _find_rootfs(vm: VMRemoteExecutor, firmware: str) -> tuple[str, str]:
    """Locate (or create) an extracted squashfs-root for the firmware.

    Reuses an existing extraction when present -- binwalk would otherwise
    create yet another ``_fw.bin-N.extracted`` directory on every run.
    Only the firmware's own directory is searched (no full-disk scan).
    """
    fw_parent = posixpath.dirname(firmware)
    probe = (
        f"R=$(find {fw_parent} -maxdepth 4 -type d -name squashfs-root 2>/dev/null | head -1); "
        'echo "ROOTFS=$R"'
    )
    r = await vm.execute(probe)
    rootfs = ""
    for line in r.stdout.splitlines():
        if line.startswith("ROOTFS="):
            rootfs = line.split("=", 1)[1].strip()
    if rootfs:
        print(f"[+] reused existing extraction: {rootfs}")
        # posixpath, not pathlib: on Windows Path() mangles POSIX paths
        return rootfs, posixpath.dirname(rootfs)

    r = await vm.execute(
        f"cd {fw_parent} && binwalk -Me {firmware} > /tmp/binwalk.log 2>&1; {probe}"
    )
    for line in r.stdout.splitlines():
        if line.startswith("ROOTFS="):
            rootfs = line.split("=", 1)[1].strip()
            if rootfs:
                return rootfs, posixpath.dirname(rootfs)
    raise SystemExit(f"could not extract rootfs from {firmware}")


async def _detect_arch(vm: VMRemoteExecutor, rootfs: str) -> str:
    r = await vm.execute(f"file {rootfs}/bin/busybox 2>/dev/null || file {rootfs}/sbin/init")
    low = r.stdout.lower()
    if "mips" in low:
        return "mipsel" if "lsb" in low or "little" in low else "mips"
    if "arm" in low:
        return "arm"
    raise SystemExit(f"unsupported arch in {r.stdout}")


async def _verify(vm: VMRemoteExecutor) -> None:
    # dbload/xmldb need a few seconds to settle; retry until the page answers.
    for attempt in range(4):
        idx = await vm.execute(
            f"curl -s -m 15 -o /dev/null -w '%{{http_code}} %{{size_download}}' http://{GUEST_IP}:{WEB_PORT}/"
        )
        if idx.stdout.strip().startswith("200"):
            break
        await asyncio.sleep(8)
    hnap = await vm.execute(
        f"curl -s -m 15 -o /dev/null -w '%{{http_code}} %{{size_download}}' http://{GUEST_IP}:{WEB_PORT}/HNAP1/"
    )
    print(f"[verify] index.php: {idx.stdout.strip()}")
    print(f"[verify] HNAP1:     {hnap.stdout.strip()}")


async def _run(vm: VMRemoteExecutor, args: argparse.Namespace) -> int:
    await _upload(vm, "/tmp/guest_driver.py", GUEST_DRIVER.read_text(encoding="utf-8"))

    if args.status:
        r = await vm.execute("ps aux | grep -c '[q]emu-system'")
        print("[status] qemu procs:", r.stdout.strip())
        print(await _gd(vm, ["status"], timeout=120))
        return 0

    if args.stop:
        # bracket trick so pkill does not match its own command line
        await vm.execute(
            "pkill -f '[q]emu-system' 2>/dev/null; "
            "pkill -f '[h]ttp.server 8000' 2>/dev/null; "
            f"echo '{settings.vm_ssh_password}' | sudo -S -p '' bash -c "
            "'nmcli con delete tap0 2>/dev/null; ip link del tap0 2>/dev/null; "
            "pkill -f guest_driver 2>/dev/null'; "
            "echo STOPPED"
        )
        return 0

    # locate rootfs
    if args.rootfs:
        rootfs = args.rootfs.rstrip("/")
        rootfs_parent = posixpath.dirname(rootfs)
    else:
        rootfs, rootfs_parent = await _find_rootfs(vm, args.firmware)
    print("[+] rootfs:", rootfs)

    arch = args.arch or await _detect_arch(vm, rootfs)
    print("[+] arch:", arch)

    # 1) boot images (auto-download if missing)
    images = await kernel_assets.ensure_boot_images(vm, arch, wait=True)
    if not images.get("ready"):
        raise SystemExit(f"boot images not ready: {images}")
    kernel_name = next(a["name"] for a in images["assets"] if a["role"] == "kernel")
    print("[+] boot images ready")

    # 2) network + qemu
    await _prepare_tap(vm)
    work = await _prepare_work_image(vm, arch)
    await _launch_qemu(vm, arch, kernel_name, work)

    # 3) wait for guest shell
    for attempt in range(30):
        out = await _gd(vm, ["ensure-shell"], timeout=120)
        if "SHELL_OK" in out:
            print("[+] guest shell ready")
            break
        await asyncio.sleep(5)
    else:
        raise SystemExit("guest did not come up")

    # 4) network + files
    out = await _gd(vm, ["net", GUEST_IP], timeout=60)
    print("[+] guest net:", out.replace("\n", " | ")[-100:])
    await _serve_and_fetch(vm, rootfs_parent, ROOTFS_NAME, "/root")

    # 5) inject + services
    conf_b64 = base64.b64encode(http_conf(GUEST_IP, WEB_PORT).encode()).decode()
    out = await _gd(vm, ["install-dlink", f"/root/{ROOTFS_NAME}", conf_b64], timeout=300)
    print(out.replace("\n", " | ")[-800:])
    sign = await vm.execute(f"cat {rootfs}/etc/config/image_sign 2>/dev/null")
    image_sign = sign.stdout.strip() or "wrgnd08_dlob_dir815"
    out = await _gd(vm, ["services", f"/root/{ROOTFS_NAME}", image_sign], timeout=180)
    print(out.replace("\n", " | ")[-500:])

    await _verify(vm)
    print("\n[done] web UI: http://%s:%s/  (guest %s)" % (GUEST_IP, WEB_PORT, GUEST_IP))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firmware", help="path to the firmware image on the VM")
    p.add_argument("--rootfs", help="path to an already-extracted squashfs-root on the VM")
    p.add_argument("--arch", choices=["mips", "mipsel", "arm"], default="")
    p.add_argument("--status", action="store_true")
    p.add_argument("--stop", action="store_true")
    args = p.parse_args()
    if not (args.status or args.stop) and not (args.firmware or args.rootfs):
        p.error("need --firmware or --rootfs (or --status/--stop)")

    async def _main() -> int:
        async with VMRemoteExecutor() as vm:
            return await _run(vm, args)

    return asyncio.run(_main())


if __name__ == "__main__":
    sys.exit(main())
