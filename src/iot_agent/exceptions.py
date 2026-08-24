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


# ---------------------------------------------------------------------------
# IDA errors
# ---------------------------------------------------------------------------


class IDAError(IoTAgentError):
    """Base IDA analysis error."""