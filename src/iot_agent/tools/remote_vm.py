"""VM remote execution via SSH — runs heavy analysis tasks on the dedicated security VM."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

import paramiko
import structlog

from iot_agent.config import settings
from iot_agent.exceptions import VMConnectionError

logger = structlog.get_logger(__name__)


@dataclass
class RemoteResult:
    stdout: str
    stderr: str
    exit_code: int
    success: bool

    def __bool__(self) -> bool:
        return self.success


class VMRemoteExecutor:
    """Execute commands on the dedicated security VM via SSH (paramiko).

    Supports connection reuse — use as a context manager for best performance::

        async with VMRemoteExecutor() as vm:
            await vm.execute("ls /")
            await vm.execute("binwalk -Me firmware.bin")  # reuses the same connection

    Without context manager, each operation opens and closes a new connection.
    """

    def __init__(self) -> None:
        self._host = settings.vm_ssh_host
        self._port = settings.vm_ssh_port
        self._user = settings.vm_ssh_user
        self._password = settings.vm_ssh_password
        self._key = settings.vm_ssh_key_path
        self._ssh: paramiko.SSHClient | None = None

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Establish a persistent SSH connection."""
        if self._ssh is not None:
            return
        self._ssh = await asyncio.to_thread(self._make_connection)
        logger.info("SSH connected", host=self._host)

    async def close(self) -> None:
        """Close the persistent SSH connection."""
        if self._ssh is not None:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None
            logger.debug("SSH disconnected")

    async def __aenter__(self) -> "VMRemoteExecutor":
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    # -- connection internals ------------------------------------------------

    def _make_connection(self) -> paramiko.SSHClient:
        """Create a new SSH connection (runs in thread).

        Raises VMConnectionError on connection failure.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self._host,
            "port": self._port,
            "username": self._user,
            "timeout": 10,
        }
        if self._key:
            kwargs["key_filename"] = self._key
        elif self._password:
            kwargs["password"] = self._password
        try:
            ssh.connect(**kwargs)
        except (paramiko.SSHException, OSError) as e:
            raise VMConnectionError(self._host, str(e)) from e
        return ssh

    def _is_alive(self) -> bool:
        """Check if the persistent connection is still alive."""
        if self._ssh is None:
            return False
        transport = self._ssh.get_transport()
        return transport is not None and transport.is_active()

    async def _get_ssh(self) -> paramiko.SSHClient:
        """Return the persistent connection, reconnecting if needed."""
        if self._is_alive():
            return self._ssh  # type: ignore[return-value]
        # Reconnect
        await self.close()
        await self.connect()
        return self._ssh  # type: ignore[return-value]

    @property
    def configured(self) -> bool:
        return bool(self._host and self._user)

    @property
    def _firmware_dir(self) -> str:
        return settings.vm_firmware_dir

    # -- command execution ---------------------------------------------------

    async def is_available(self) -> bool:
        if not self.configured:
            return False
        result = await self.execute("echo ok", timeout=5)
        return result.success and "ok" in result.stdout

    async def execute(self, cmd: str, timeout: int = 300) -> RemoteResult:
        """Run a command on the VM.

        If a persistent connection is open (context manager), reuses it.
        Otherwise opens a one-off connection.
        """
        if not self.configured:
            return RemoteResult("", "VM not configured", -1, False)

        def _run(ssh: paramiko.SSHClient) -> RemoteResult:
            try:
                _in, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
                return RemoteResult(
                    stdout=stdout.read().decode(errors="replace"),
                    stderr=stderr.read().decode(errors="replace"),
                    exit_code=stdout.channel.recv_exit_status(),
                    success=True,
                )
            except paramiko.SSHException:
                raise  # let outer code handle retry
            except Exception as e:
                return RemoteResult("", str(e), -1, False)

        try:
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_run, ssh)
        except (paramiko.SSHException, VMConnectionError):
            # Connection died — retry once with a fresh connection
            logger.warning("SSH connection lost, reconnecting")
            await self.close()
            await self.connect()
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_run, ssh)

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """SCP a file to VM."""
        if not self.configured:
            return False

        def _scp(ssh: paramiko.SSHClient) -> bool:
            try:
                sftp = ssh.open_sftp()
                sftp.put(local_path, remote_path)
                sftp.close()
                return True
            except Exception:
                logger.exception("scp upload failed")
                return False

        try:
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_scp, ssh)
        except (paramiko.SSHException, VMConnectionError):
            logger.warning("SSH connection lost during upload, reconnecting")
            await self.close()
            await self.connect()
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_scp, ssh)

    async def download(self, remote_path: str, local_path: str) -> bool:
        """SCP a file from VM."""
        if not self.configured:
            return False

        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        def _scp(ssh: paramiko.SSHClient) -> bool:
            try:
                sftp = ssh.open_sftp()
                sftp.get(remote_path, local_path)
                sftp.close()
                return True
            except Exception:
                logger.exception("scp download failed")
                return False

        try:
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_scp, ssh)
        except (paramiko.SSHException, VMConnectionError):
            logger.warning("SSH connection lost during download, reconnecting")
            await self.close()
            await self.connect()
            ssh = await self._get_ssh()
            return await asyncio.to_thread(_scp, ssh)

    # -- High-level wrappers ------------------------------------------------

    async def check_tools(self) -> dict[str, bool]:
        """Check which analysis tools are installed on the VM."""
        tools = ["binwalk", "radare2",
                 "qemu-mips-static", "qemu-mipsel-static", "qemu-arm-static",
                 "python3"]
        checks = []
        for t in tools:
            checks.append(f"which {t} >/dev/null 2>&1 && echo '{t}:ok' || echo '{t}:fail'")
        r = await self.execute("; ".join(checks))
        statuses = {t: False for t in tools}
        for line in r.stdout.splitlines():
            if ":" in line:
                name, status = line.strip().split(":", 1)
                if name in statuses:
                    statuses[name] = status == "ok"
        return statuses

    async def run_binwalk(self, firmware_path: str, output_dir: str) -> RemoteResult:
        """Extract firmware with binwalk."""
        cmd = f"mkdir -p {output_dir} && cd {output_dir} && binwalk -Me {firmware_path} 2>&1"
        return await self.execute(cmd, timeout=600)

    async def check_firmware_integrity(self, path: str, md5: str = "") -> bool:
        """Verify firmware file exists (and optionally hash)."""
        if md5:
            r = await self.execute(f"md5sum {path}")
            return md5 in r.stdout
        r = await self.execute(f"test -f {path} && echo ok")
        return r.success and "ok" in r.stdout
