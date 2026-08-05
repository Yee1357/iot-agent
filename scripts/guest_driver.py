#!/usr/bin/env python3
"""Guest-side driver -- drives the emulated guest through the qemu serial socket.

This script runs ON the VM host (not inside the guest) and is uploaded there
by ``scripts/emulate_dlink.py``. It is intentionally stdlib-only.

Usage:
    guest_driver.py ensure-shell
    guest_driver.py net <ip>
    guest_driver.py fetch <url> <dest>
    guest_driver.py extract <tar> <dir>
    guest_driver.py install-dlink <rootfs_dir> <http_conf_b64>
    guest_driver.py services <rootfs_dir> <image_sign>
    guest_driver.py status
    guest_driver.py raw <command...>
"""

import base64
import socket
import sys
import time

SOCK = "/tmp/qemu-serial.sock"


class SerialGuest:
    def __init__(self, sock: str = SOCK):
        self.sock = sock
        self.s: socket.socket | None = None

    def connect(self, retries: int = 90, wait: float = 2.0) -> None:
        for _ in range(retries):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.sock)
                self.s = s
                return
            except OSError:
                time.sleep(wait)
        raise SystemExit("serial socket unavailable")

    def recv_until(self, markers: list[str], timeout: float = 30.0) -> str:
        buf = b""
        self.s.settimeout(1.0)  # type: ignore[union-attr]
        end = time.time() + timeout
        while time.time() < end:
            try:
                c = self.s.recv(4096)  # type: ignore[union-attr]
                if not c:
                    break
                buf += c
            except socket.timeout:
                pass
            if any(m.lower().encode() in buf.lower() for m in markers):
                break
        return buf.decode(errors="replace")

    def cmd(self, text: str, markers: list[str] | None = None, timeout: float = 30.0) -> str:
        self.s.sendall((text + "\n").encode())  # type: ignore[union-attr]
        return self.recv_until(markers or ["#"], timeout)

    def ensure_shell(self) -> str:
        """Return a working root shell (login if the guest is at a getty).

        Uses short reads + a newline probe: an idle shell produces no output,
        so a long initial read would block for no reason. The orchestrator
        retries this while the guest is still booting.
        """
        out = self.recv_until(["login:", "#", "~#"], 8)
        self.s.sendall(b"\n")  # type: ignore[union-attr]
        out += self.recv_until(["login:", "#", "~#"], 8)
        if "login" in out.lower():
            for _ in range(3):
                self.s.sendall(b"root\n")  # type: ignore[union-attr]
                time.sleep(0.5)
                out = self.recv_until(["password:", "#"], 15)
                if "#" in out:
                    break
                self.s.sendall(b"root\n")  # type: ignore[union-attr]
                out = self.recv_until(["#", "login:", "incorrect", "denied"], 25)
                if "#" in out:
                    break
        return out

    def close(self) -> None:
        try:
            if self.s is not None:
                self.s.close()
        except Exception:
            pass


def _guest() -> SerialGuest:
    g = SerialGuest()
    g.connect()
    g.ensure_shell()
    return g


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    cmd_name = args[0]

    if cmd_name == "ensure-shell":
        g = _guest()
        print("SHELL_OK", flush=True)
        g.close()
        return 0

    if cmd_name == "net":
        ip = args[1]
        g = _guest()
        out = g.cmd(
            f"for i in eth0 eth1 eth2; do ip addr add {ip}/24 dev $i 2>/dev/null "
            f"&& ip link set $i up && echo NET_IF=$i && break; done"
        )
        print(out[-200:], flush=True)
        g.close()
        return 0

    if cmd_name == "fetch":
        url, dest = args[1], args[2]
        g = _guest()
        out = g.cmd(f"wget -q -O {dest} {url} && stat -c %s {dest} && echo FETCH_OK", timeout=300)
        print(out[-200:], flush=True)
        g.close()
        return 0 if "FETCH_OK" in out else 1

    if cmd_name == "extract":
        tar, dest_dir = args[1], args[2]
        g = _guest()
        out = g.cmd(f"mkdir -p {dest_dir} && tar -C {dest_dir} -xf {tar} && echo EXTRACT_OK", timeout=180)
        print(out[-200:], flush=True)
        g.close()
        return 0 if "EXTRACT_OK" in out else 1

    if cmd_name == "install-dlink":
        rootfs, conf_b64 = args[1], args[2]
        g = _guest()
        out = g.cmd(f"echo {conf_b64} | base64 -d > {rootfs}/http_conf && echo CONF_OK", timeout=30)
        print("conf:", out[-120:], flush=True)
        steps = [
            ("copy_httpd", f"cd {rootfs} && cp http_conf / && cp sbin/httpd / && echo OK"),
            ("copy_htdocs", f"cp -rf {rootfs}/htdocs/. /htdocs/ && echo OK"),
            ("backup_etc", "mkdir -p /etc_bak && cp -r /etc /etc_bak; echo OK"),
            (
                "install_etc",
                # NOTE: use `cp -rf etc /` (no trailing dot) -- the old
                # coreutils in the guest silently fails on `etc/. /`.
                f"rm -rf /etc/services /etc/ppp /etc/iproute2; "
                f"cp -rf {rootfs}/etc /; "
                "test -f /etc/scripts/dbload.sh && echo OK || echo ETC_MISSING",
            ),
            (
                "copy_libs",
                f"cd {rootfs}/lib && cp -f ld-uClibc-0.9.30.1.so ld-uClibc.so.0 "
                "libcrypt-0.9.30.1.so libcrypt.so.0 libc.so.0 libgcc_s.so "
                "libgcc_s.so.1 libuClibc-0.9.30.1.so /lib/ && echo OK",
            ),
            (
                "symlinks",
                "rm -f /htdocs/web/hedwig.cgi /usr/sbin/phpcgi /usr/sbin/hnap; "
                "ln -s /htdocs/cgibin /htdocs/web/hedwig.cgi; "
                "ln -s /htdocs/cgibin /usr/sbin/phpcgi; "
                "ln -s /htdocs/cgibin /usr/sbin/hnap; echo OK",
            ),
        ]
        for name, step in steps:
            out = g.cmd(step, timeout=180)
            tail = out.replace("\n", " | ")[-150:]
            print(f"  {name}: {tail}", flush=True)
            if "OK" not in out:
                print(f"  !! {name} FAILED", flush=True)
                g.close()
                return 1
        g.close()
        print("INSTALL_DONE", flush=True)
        return 0

    if cmd_name == "services":
        rootfs, image_sign = args[1], args[2]
        g = _guest()
        out = g.cmd(
            "mkdir -p /var/servd && "
            f"(/usr/sbin/xmldb -n {image_sign} -t > /dev/console 2>&1 &) ; "
            "sleep 4; ls -la /var/run/xmldb_sock 2>&1"
        )
        print("xmldb:", out[-200:], flush=True)
        out = g.cmd("sh /etc/scripts/dbload.sh > /tmp/dbload.log 2>&1; echo DBLOAD_EXIT=$?", timeout=180)
        print("dbload:", out[-150:], flush=True)
        out = g.cmd("cd / && ./httpd -f http_conf 2>&1 & sleep 3; netstat -ltn 2>/dev/null | grep 1234; echo HTTPD_ISSUED", timeout=45)
        print("httpd:", out[-250:], flush=True)
        g.close()
        return 0 if "1234" in out else 1

    if cmd_name == "status":
        g = _guest()
        out = g.cmd("ps aux | grep -E 'httpd|xmldb' | grep -v grep; netstat -ltn 2>/dev/null | grep 1234; echo STATUS_DONE")
        print(out.replace("\n", " | ")[-600:], flush=True)
        g.close()
        return 0

    if cmd_name == "raw":
        g = _guest()
        out = g.cmd(" ".join(args[1:]), timeout=120)
        print(out, flush=True)
        g.close()
        return 0

    print(f"unknown command: {cmd_name}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
