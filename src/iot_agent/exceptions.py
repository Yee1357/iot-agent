"""Project-wide exception hierarchy for IoT Agent.

Usage:
    from iot_agent.exceptions import VMConnectionError

    try:
        ...
    except VMConnectionError as e:
        logger.error("VM unreachable", host=e.host, reason=e.reason)
"""


class VMConnectionError(Exception):
    """SSH connection to VM failed."""

    def __init__(self, host: str, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(f"VM connection failed ({host}): {reason}")