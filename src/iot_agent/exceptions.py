"""Project-wide exception hierarchy for IoT Agent.

Usage:
    from iot_agent.exceptions import IoTAgentError, VMConnectionError

    # Catch all project errors
    try:
        ...
    except IoTAgentError as e:
        logger.error("agent error", error=str(e))

    # Catch specific categories
    try:
        ...
    except VMConnectionError as e:
        logger.error("VM unreachable", host=e.host, reason=e.reason)
"""


class IoTAgentError(Exception):
    """Base exception for all IoT Agent errors."""


# ---------------------------------------------------------------------------
# VM errors
# ---------------------------------------------------------------------------


class VMConnectionError(IoTAgentError):
    """SSH connection to VM failed."""

    def __init__(self, host: str, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(f"VM connection failed ({host}): {reason}")


class VMCommandError(IoTAgentError):
    """VM command execution failed with non-zero exit code."""

    def __init__(self, cmd: str, exit_code: int, stderr: str):
        self.cmd = cmd
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(f"Command failed (exit {exit_code}): {stderr[:200]}")


# ---------------------------------------------------------------------------
# IDA errors
# ---------------------------------------------------------------------------


class IDAError(IoTAgentError):
    """Base IDA analysis error."""


class IDAConnectionError(IDAError):
    """Cannot connect to IDA (MCP server down or headless init failed)."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(f"IDA connection failed: {detail}")


# ---------------------------------------------------------------------------
# Firmware errors
# ---------------------------------------------------------------------------


class FirmwareError(IoTAgentError):
    """Firmware extraction or processing error."""

    def __init__(self, message: str, path: str = ""):
        self.path = path
        super().__init__(message)


class FirmwareSourceError(FirmwareError):
    """Firmware source search/download error."""

    def __init__(self, message: str, source: str = ""):
        self.source = source
        super().__init__(message)


