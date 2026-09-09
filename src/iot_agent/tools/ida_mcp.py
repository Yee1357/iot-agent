"""IDA Pro helpers — headless idalib client and finding data model.

The GUI path is covered by the external ``ida-pro-mcp`` server (registered at
user level, see README). This module only provides:

- ``VulnerabilityFinding`` — the shared structured finding data model.
- ``IDAHeadlessClient`` — in-process idalib wrapper (no GUI / no MCP server).
- ``cleanup_ida_files`` — remove IDA-generated temp files after analysis.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Data model
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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

    def imports_query(self, filters: list[str]) -> list[dict]:
        """Query functions by name filters. Headless implementation using IDAPython.

        Returns: [{"addr": hex, "imported_name": name}]
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
                    "addr": hex(f),
                    "imported_name": name,
                })
        return results

    def xrefs_to(self, addrs: str | list[str]) -> list[dict]:
        """Get code cross-references to given addresses. Headless implementation.

        Returns: [{"addr": hex_of_import, "xrefs": [{"addr": caller_hex, "fn": name}]}]
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
                        "fn": caller_name,
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