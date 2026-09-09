"""VM remote execution via SSH — runs heavy analysis tasks on the dedicated security VM."""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import dataclass

import paramiko
import structlog

from iot_agent.config import settings
from iot_agent.exceptions import VMConnectionError

logger = structlog.get_logger(__name__)


@dataclass
class RemoteResult:
    """Result of a VM command.

    ``success`` means the command *exited with code 0* (not merely "SSH
    transport worked"). ``exit_code`` is always authoritative; on transport
    failure ``success`` is False and ``exit_code`` is -1.
    """

    stdout: str
    stderr: str
    exit_code: int
    success: bool


def _shell_safe(cmd: str) -> str:
    """Ship cmd past the VM login shell via ``echo '<b64>' | base64 -d | bash -s``.

    sshd hands the command string to the user's login shell (zsh on kali),
    where quotes/``$``/globs in paths used to explode. base64 of UTF-8 is
    quote-free ASCII that no shell parser can touch, and forcing bash pins
    shell semantics. The decoded script IS ``bash -s``'s stdin, so inner
    stdin readers see EOF once the script is consumed. Line endings are
    normalized to LF first — host-side callers may leak CRLF, which bash
    would otherwise reject as ``$'\\r': command not found``.
    """
    script = cmd.replace("\r\n", "\n").replace("\r", "\n")
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"echo '{encoded}' | base64 -d | bash -s"


class VMRemoteExecutor:
    """Execute commands on the dedicated security VM via SSH (paramiko).

    One persistent connection is reused across all operations (auto-reconnect
    on drop); every public operation is serialized by an asyncio lock so
    concurrent tool calls cannot interleave on the same paramiko client.
    """

    def __init__(self) -> None:
        self._host = settings.vm_ssh_host
        self._port = settings.vm_ssh_port
        self._user = settings.vm_ssh_user
        self._password = settings.vm_ssh_password
        self._key = settings.vm_ssh_key_path
        self._ssh: paramiko.SSHClient | None = None
        #: serializes public operations; connect/close have their own lock so
        #: first-connect races are safe without deadlocking (lock order:
        #: ``_op_lock`` -> ``_conn_lock``, never the reverse).
        self._op_lock = asyncio.Lock()
        self._conn_lock = asyncio.Lock()

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Establish a persistent SSH connection (idempotent, race-safe)."""
        async with self._conn_lock:
            if self._ssh is not None:
                return
            self._ssh = await asyncio.to_thread(self._make_connection)
            logger.info("SSH connected", host=self._host)

    async def close(self) -> None:
        """Close the persistent SSH connection."""
        async with self._conn_lock:
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
        # Keepalive keeps the flow warm and detects a silently dropped link
        # (vmnet/NAT) before the next call has to find out via its read timeout.
        transport = ssh.get_transport()
        if transport is not None:
            transport.set_keepalive(15)
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

    async def execute(self, cmd: str, timeout: int = 300) -> RemoteResult:
        """Run a command on the VM over the pooled connection.

        The command is transported shell-safe (see :func:`_shell_safe`) and
        executed by ``bash -s`` on the VM. ``success`` is True only when the
        command exited 0; always check ``exit_code`` for the authoritative
        status.
        """
        if not self.configured:
            return RemoteResult("", "VM not configured", -1, False)

        def _run(ssh: paramiko.SSHClient) -> RemoteResult:
            try:
                _in, stdout, stderr = ssh.exec_command(_shell_safe(cmd), timeout=timeout)
                # Drain both streams BEFORE waiting on the exit status:
                # recv_exit_status() ignores the channel timeout entirely and,
                # called with unread output beyond the transport window
                # (2 MiB default), deadlocks forever while holding _op_lock.
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                exit_code = stdout.channel.recv_exit_status()
                return RemoteResult(
                    stdout=out,
                    stderr=err,
                    exit_code=exit_code,
                    success=exit_code == 0,
                )
            except paramiko.SSHException:
                raise  # let outer code handle retry
            except Exception as e:
                return RemoteResult("", str(e), -1, False)

        async with self._op_lock:
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

        async with self._op_lock:
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

        async with self._op_lock:
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
