"""IoT Firmware Vulnerability Discovery Agent.

Claude Code 作为 Agent 主体，通过 iot-agent MCP server（stdio）调用本工具链：
VM SSH 远程执行、固件获取/解包、IDA 反编译验证、user-mode/chroot 动态验证。
任务进度（续跑）与跨会话经验（自我迭代）持久化在 SQLite。
"""

__version__ = "0.1.0"

from iot_agent.exceptions import (
    IoTAgentError,
    VMConnectionError,
    VMCommandError,
    IDAError,
    IDAConnectionError,
    FirmwareError,
    FirmwareSourceError,
)
