"""IoT Agent tools — VM, firmware, IDA, dynamic verification (user-mode/chroot)."""

from iot_agent.tools.remote_vm import VMRemoteExecutor, RemoteResult
from iot_agent.tools.firmware_acquire import FirmwareAcquirer
from iot_agent.tools.firmware_sources import FirmwareResult, search_all
from iot_agent.tools.firmware_index import FirmwareIndex
from iot_agent.tools.analysis_store import AnalysisStore
from iot_agent.tools.emulation_env import EmulationManager
from iot_agent.tools.ida_mcp import VulnerabilityFinding, cleanup_ida_files

# IDA clients require idapro / MCP SDK — import explicitly:
#   from iot_agent.tools.ida_mcp import IDAMCPClient, IDAHeadlessClient
#   from iot_agent.tools.ida_scanner import IDAHeadlessScanner, IDASystematicScanner
# Chroot runtime assets (libnvram/busybox):
#   from iot_agent.tools import runtime_assets
