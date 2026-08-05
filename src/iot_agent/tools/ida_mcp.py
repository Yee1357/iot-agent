"""IDA Pro MCP Client — wraps MCP streamable HTTP connection to IDA."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

import structlog
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client as _http_client
from mcp.client.sse import sse_client as _sse_client

from iot_agent.config import settings
from iot_agent.exceptions import IDAConnectionError, IDAError

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class VulnerabilityFinding:
    """Structured vulnerability finding from binary analysis."""

    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    cwe_id: str  # e.g. CWE-121
    cve_id: str | None = None
    vulnerable_function: str = ""
    vulnerable_address: str = ""
    source_sink_path: str = ""
    description: str = ""
    decompiled_code: str = ""
    exploit_vector: str = ""
    confidence: float = 0.0
    is_known: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Low-level MCP client
# ---------------------------------------------------------------------------


class IDAMCPClient:
    """Async MCP client that connects to the IDA Pro MCP server."""

    def __init__(self, url: str | None = None, timeout: int | None = None):
        self.url = url or settings.ida_mcp_url
        self.timeout = timeout or settings.ida_mcp_timeout
        self._session: ClientSession | None = None
        self._transport_ctx = None
        self._tools: dict[str, Any] = {}

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        """Establish MCP session and discover available tools."""
        logger.info("connecting to IDA MCP", url=self.url)

        # Pre-flight: quick HTTP check before touching MCP SDK
        import httpx
        probe_url = self.url.replace("/mcp", "/").replace("/sse", "/")
        try:
            async with httpx.AsyncClient(timeout=3.0) as hc:
                await hc.get(probe_url)
        except Exception:
            raise IDAConnectionError(
                f"IDA MCP server not reachable at {self.url}. "
                f"Open IDA Pro GUI and load your target binary."
            )

        use_sse = "/sse" in self.url
        if use_sse:
            self._transport_ctx = _sse_client(self.url)
        else:
            self._transport_ctx = _http_client(self.url, timeout=float(self.timeout))

        streams = await self._transport_ctx.__aenter__()
        if len(streams) == 3:
            self._read, self._write, _sock = streams
        else:
            self._read, self._write = streams

        self._session = ClientSession(self._read, self._write)
        await self._session.__aenter__()
        await self._session.initialize()

        result = await self._session.list_tools()
        self._tools = {t.name: t.model_dump() for t in result.tools}
        logger.info("connected to IDA MCP", tool_count=len(self._tools))

    async def close(self) -> None:
        """Close session and transport, swallowing all cleanup errors."""
        # Suppress noisy MCP SDK cleanup errors
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                if self._session is not None:
                    await self._session.__aexit__(None, None, None)
            except BaseException:
                pass
            self._session = None

            try:
                if self._transport_ctx is not None:
                    await self._transport_ctx.__aexit__(None, None, None)
            except BaseException:
                pass
            self._transport_ctx = None

        logger.debug("disconnected from IDA MCP")

    async def __aenter__(self) -> "IDAMCPClient":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # -- generic tool call --------------------------------------------------

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call any MCP tool by name with optional arguments."""
        if self._session is None:
            raise IDAError("Not connected — call connect() first")

        arguments = arguments or {}
        logger.debug("mcp call", tool=name, args=arguments)

        try:
            result = await self._session.call_tool(name, arguments)
        except Exception:
            logger.exception("mcp tool error", tool=name)
            raise

        if not result.content:
            return None

        # Most IDA tools return a single text content block
        first = result.content[0]

        if hasattr(first, "text"):
            text: str = first.text
            # Try JSON parse for structured results
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text
        return first

    async def get_loaded_path(self) -> str | None:
        """Return the file path of the currently loaded binary."""
        try:
            health = await self.call_tool("server_health", {})
            if isinstance(health, dict):
                return health.get("input_path") or health.get("idb_path")
        except Exception:
            pass
        return None

    async def is_available(self) -> bool:
        """Check if IDA MCP server is responding."""
        try:
            await self.call_tool("server_health", {})
            return True
        except Exception:
            return False

    # -- typed helpers for common tools -------------------------------------

    async def decompile(self, addr: str) -> str:
        """Decompile function at address/name.  Returns pseudocode string."""
        result = await self.call_tool("decompile", {"addr": addr})
        if isinstance(result, dict):
            return result.get("code", str(result))
        return str(result)

    async def survey_binary(self) -> dict:
        """Get compact overview of the loaded binary."""
        r = await self.call_tool("survey_binary", {"detail_level": "standard"})
        return r if isinstance(r, dict) else {}

    async def xrefs_to(self, addr_or_addrs: str | list[str]) -> list[dict]:
        """Get cross-references TO the given address(es)."""
        r = await self.call_tool("xrefs_to", {"addrs": addr_or_addrs})
        if isinstance(r, dict):
            return r.get("result", [])
        return r if isinstance(r, list) else []

    async def imports_query(self, filters: list[str]) -> list[dict]:
        """Query imports by name filters."""
        queries = [{"filter": f} for f in filters]
        r = await self.call_tool("imports_query", {"queries": queries})
        if isinstance(r, dict):
            return r.get("result", [])
        return r if isinstance(r, list) else []

    async def analyze_function(self, addr: str) -> dict:
        """Compact single-function analysis."""
        r = await self.call_tool("analyze_function", {"addr": addr})
        return r if isinstance(r, dict) else {}

    async def find_regex(self, pattern: str, limit: int = 50) -> list[dict]:
        """Search strings by regex."""
        r = await self.call_tool("find_regex", {"pattern": pattern, "limit": limit})
        if isinstance(r, dict):
            return r.get("matches", r)
        return r if isinstance(r, list) else []


# ---------------------------------------------------------------------------
# Headless idalib mode (no GUI / no MCP server needed)
# ---------------------------------------------------------------------------


class IDAHeadlessClient:
    """Thin wrapper around idapro (idalib) for headless binary analysis.

    Use this when you don't have IDA GUI open — no MCP server required.
    All analysis runs in-process via the IDA C++ kernel loaded as a DLL.
    """

    def __init__(self, binary_path: str | None = None):
        self._binary_path = binary_path
        self._opened = False

    def open(self, binary_path: str | None = None) -> bool:
        """Open a binary for analysis. Auto-analysis runs and waits.

        IMPORTANT: All Python imports must happen BEFORE calling open().
        idalib replaces file descriptors during init, which will break
        subsequent importlib reads.
        """
        path = binary_path or self._binary_path
        if not path:
            raise ValueError("No binary path provided")

        from iot_agent.config import ensure_idalib_config
        ensure_idalib_config()
        import idapro

        self._binary_path = path
        result = idapro.open_database(path, True)
        self._opened = (result == 0)
        return self._opened

    def close(self, save: bool = False) -> None:
        """Close current database."""
        if self._opened:
            import idapro
            idapro.close_database(save)
            self._opened = False

    # All IDAPython imports are done inside methods (after open())
    # to avoid the open() fd-replacement issue.

    def decompile(self, addr: str | int) -> str | None:
        """Decompile function at address/name."""
        import ida_hexrays
        if isinstance(addr, str):
            import ida_name, idc
            ea = ida_name.get_name_ea(idc.BADADDR, addr)
        else:
            ea = addr
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc else None

    def survey(self) -> dict:
        """Return overview: architecture, function count, entry points."""
        import idautils, idc, ida_funcs
        funcs = list(idautils.Functions())
        return {
            "arch": idc.get_inf_attr(idc.INF_PROCNAME),
            "functions": len(funcs),
            "top_by_size": sorted(
                [
                    {
                        "addr": hex(f),
                        "name": ida_funcs.get_func_name(f),
                        "size": idc.get_func_attr(f, idc.FUNCATTR_END) - f,
                    }
                    for f in funcs
                ],
                key=lambda x: x["size"],
                reverse=True,
            )[:20],
        }

    def find_dangerous_callers(self) -> list[dict]:
        """Find all callers of dangerous sink functions."""
        import idautils, idc, ida_funcs

        sinks = [
            "strcpy", "sprintf", "strcat", "gets",
            "memcpy", "read", "recv", "fread",
            "system", "popen", "execve", "execl", "execlp",
            "printf", "fprintf", "vsprintf", "snprintf",
        ]

        results = []
        for f in idautils.Functions():
            name = ida_funcs.get_func_name(f)
            if name not in sinks and f"_{name}" not in str(sinks):
                continue
            for xref in idautils.XrefsTo(f):
                if xref.frm and ida_funcs.get_func_name(xref.frm):
                    caller = ida_funcs.get_func_name(xref.frm)
                    results.append({
                        "sink": name,
                        "sink_addr": hex(f),
                        "caller": caller,
                        "caller_addr": hex(xref.frm),
                    })
        return results

    def imports_query(self, filters: list[str]) -> list[dict]:
        """Query imports by name filters. Headless implementation using IDAPython.

        Returns format compatible with MCP version:
        [{"data": [{"addr": ..., "imported_name": ...}]}]
        """
        import idautils, ida_funcs

        results: list[dict] = []
        for f in idautils.Functions():
            name = ida_funcs.get_func_name(f)
            if not name:
                continue
            # Check if name matches any filter (case-insensitive substring)
            name_lower = name.lower().lstrip("_")
            if any(fltr.lower() in name_lower for fltr in filters):
                results.append({
                    "data": [{
                        "addr": hex(f),
                        "imported_name": name,
                    }]
                })
        return results

    def xrefs_to(self, addrs: str | list[str]) -> list[dict]:
        """Get cross-references to given addresses. Headless implementation.

        Returns format compatible with MCP version:
        [{"addr": ..., "xrefs": [{"addr": ..., "type": "code", "fn": {"name": ...}}]}]
        """
        import idautils, ida_funcs

        if isinstance(addrs, str):
            addrs = [addrs]

        results: list[dict] = []
        for addr_str in addrs:
            try:
                ea = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
            except (ValueError, TypeError):
                continue

            xrefs = []
            for xref in idautils.XrefsTo(ea):
                if xref.frm:
                    caller_name = ida_funcs.get_func_name(xref.frm) or "unknown"
                    xrefs.append({
                        "addr": hex(xref.frm),
                        "type": "code",
                        "fn": {"name": caller_name},
                    })

            results.append({
                "addr": addr_str,
                "xrefs": xrefs,
            })
        return results

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()


def cleanup_ida_files(elf_path: str) -> int:
    """Delete IDA-generated files (.i64/.id0/.id1/.id2/.nam/.til) for a binary.
    Returns number of files removed."""
    from pathlib import Path
    p = Path(elf_path)
    patterns = [
        p.with_suffix(".i64"), p.with_suffix(".idb"),
        p.with_name(p.name + ".id0"), p.with_name(p.name + ".id1"),
        p.with_name(p.name + ".id2"), p.with_name(p.name + ".nam"),
        p.with_name(p.name + ".til"),
    ]
    count = 0
    for pat in patterns:
        if pat.exists():
            pat.unlink()
            count += 1
    return count


