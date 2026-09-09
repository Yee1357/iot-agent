"""IDA binary analysis — headless scanner + analysis helpers.

Provides ``IDAHeadlessScanner`` (primary, runs on headless IDA via idalib),
producing ``VulnerabilityFinding`` lists for AI consumption. The optional
MCP-based scanner (``IDASystematicScanner``) was removed — the GUI path is
covered by the external ``ida-pro-mcp`` server.

Vendor neutrality: the scanner contains ONLY generic sink/source lists.
Vendor-specific sinks / taint sources live in the ``knowledge/`` directory
(project root, one JSON per vendor) and are merged at runtime when a
``vendor`` argument is given -- see ``load_vendor_knowledge``.

Analysis helpers (extract_sink_context, is_hardcoded_arg, etc.) are
pure Python functions that operate on decompiled pseudocode strings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import structlog

from iot_agent.tools.ida_mcp import (
    IDAHeadlessClient,
    VulnerabilityFinding,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants (generic only — vendor specifics come from knowledge/)
# ---------------------------------------------------------------------------

DANGEROUS_SINKS = [
    "strcpy", "sprintf", "strcat", "gets",
    "memcpy", "read", "recv", "fread",
    "system", "popen", "execve", "execl", "execlp",
    "printf", "fprintf", "vsprintf", "snprintf",
]

TAINT_SOURCES = [
    "getenv", "recv", "read", "fread", "fgets",
]

# sink -> (CWE, description, severity, confidence)
_SINK_CLASSIFICATION: dict[str, tuple[str, str, str, float]] = {
    "system":   ("CWE-78", "command injection",  "HIGH", 0.6),
    "popen":    ("CWE-78", "command injection",  "HIGH", 0.6),
    "execve":   ("CWE-78", "command injection",  "HIGH", 0.6),
    "execl":    ("CWE-78", "command injection",  "HIGH", 0.6),
    "execlp":   ("CWE-78", "command injection",  "HIGH", 0.6),
    "sprintf":  ("CWE-121", "buffer overflow",   "HIGH", 0.5),
    "vsprintf": ("CWE-121", "buffer overflow",   "HIGH", 0.5),
    "strcpy":   ("CWE-120", "buffer overflow risk", "HIGH", 0.4),
    "strcat":   ("CWE-120", "buffer overflow risk", "HIGH", 0.4),
    "gets":     ("CWE-120", "buffer overflow risk", "HIGH", 0.4),
}
_SINK_DEFAULT = ("CWE-20", "", "MEDIUM", 0.2)


# ---------------------------------------------------------------------------
# Vendor knowledge loading (knowledge/<vendor>.json at project root)
# ---------------------------------------------------------------------------

_KNOWLEDGE_DIR = Path(__file__).resolve().parents[3] / "knowledge"


def load_vendor_knowledge(vendor: str = "") -> dict[str, Any]:
    """Load vendor-specific sinks/taint sources from the knowledge directory.

    Returns ``{"vendor", "sinks": {name: {...}}, "taint_sources": [...]}``.
    Empty (no vendor / file missing / unreadable) returns an empty profile --
    callers simply fall back to the generic lists.
    """
    empty = {"vendor": vendor, "sinks": {}, "taint_sources": []}
    if not vendor:
        return empty
    path = _KNOWLEDGE_DIR / f"{vendor.strip().lower()}.json"
    if not path.is_file():
        logger.debug("no vendor knowledge file", vendor=vendor, path=str(path))
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("vendor knowledge unreadable", vendor=vendor, path=str(path))
        return empty
    return {
        "vendor": data.get("vendor", vendor),
        "sinks": data.get("sinks", {}),
        "taint_sources": data.get("taint_sources", []),
    }


def list_vendor_knowledge() -> list[dict[str, Any]]:
    """List available vendor knowledge files (knowledge/*.json).

    Each entry: {"vendor", "file", "sinks", "taint_sources"}. Used by the
    agent at hunt start to check whether the target vendor has machine
    knowledge to merge into the scan.
    """
    out: list[dict[str, Any]] = []
    if not _KNOWLEDGE_DIR.is_dir():
        return out
    for p in sorted(_KNOWLEDGE_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        out.append({
            "vendor": data.get("vendor", p.stem),
            "file": p.name,
            "sinks": len(data.get("sinks", {}) or {}),
            "taint_sources": len(data.get("taint_sources", []) or []),
        })
    return out


# Format-string sinks: the dangerous arg is NOT the format string (1st arg),
# but the variadic args that get interpolated.  A format string containing
# %s / %n / %x means external data flows in → must NOT be treated as safe.
# Generic set; vendor format-string sinks are merged per scan (see
# _merge_vendor_knowledge).
_FORMAT_STRING_SINKS = {"sprintf", "vsprintf", "snprintf", "fprintf",
                        "printf", "syslog"}


def _merge_vendor_knowledge(
    vendor: str = "",
) -> tuple[list[str], list[str], dict[str, tuple[str, str, str, float]], set[str]]:
    """Merge vendor knowledge over the generic lists.

    Returns (sinks, taint_sources, sink_classification, format_string_sinks).
    """
    kn = load_vendor_knowledge(vendor)
    sinks = list(DANGEROUS_SINKS)
    taint = list(TAINT_SOURCES)
    classification = dict(_SINK_CLASSIFICATION)
    format_sinks = set(_FORMAT_STRING_SINKS)

    for name, info in kn["sinks"].items():
        sinks.append(name)
        classification[name] = (
            info.get("cwe", _SINK_DEFAULT[0]),
            info.get("description", ""),
            info.get("severity", _SINK_DEFAULT[2]),
            float(info.get("confidence", _SINK_DEFAULT[3])),
        )
        if info.get("format_string"):
            format_sinks.add(name)

    taint.extend(kn["taint_sources"])
    return sinks, taint, classification, format_sinks


# ---------------------------------------------------------------------------
# Analysis helpers (pure Python, no IDA dependency)
# ---------------------------------------------------------------------------


def extract_sink_context(code: str, sink_name: str, context_lines: int = 8) -> str:
    """Extract lines around a sink call from decompiled pseudocode.

    Returns only the surrounding context (default ±8 lines), not the
    entire function. This is for AI quick triage — not final analysis.
    """
    lines = code.splitlines()
    # Find lines that contain the sink call: sink_name(
    pattern = re.compile(r'\b' + re.escape(sink_name) + r'\s*\(')
    hits = [i for i, line in enumerate(lines) if pattern.search(line)]

    if not hits:
        return ""

    # Take the first hit and extract surrounding lines
    hit = hits[0]
    start = max(0, hit - context_lines)
    end = min(len(lines), hit + context_lines + 1)

    snippet = lines[start:end]
    # Add line markers so AI knows where the sink is
    result = []
    for i, line in enumerate(snippet):
        lineno = start + i
        marker = "  ← SINK" if lineno == hit else ""
        result.append(f"  {lineno:4d} | {line}{marker}")
    return "\n".join(result)


def is_hardcoded_arg(
    code: str,
    sink_name: str,
    format_string_sinks: set[str] | None = None,
) -> bool:
    """Check if a sink's argument is a hardcoded string constant.

    system("reboot")  -> True  (safe, can exclude)
    system(cmd_buf)   -> False (needs further analysis)
    sprintf(buf, "svc %s", input) -> False (format string has %s)
    sprintf(buf, "Content-Type: text/html") -> True (no placeholders)

    ``format_string_sinks`` overrides the generic format-sink set (used when
    vendor knowledge adds vendor format sinks).
    """
    format_sinks = format_string_sinks if format_string_sinks is not None else _FORMAT_STRING_SINKS
    # Find the sink call line — match the outermost call only
    pattern = re.compile(r'\b' + re.escape(sink_name) + r'\s*\((.+)')
    for line in code.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        arg_part = m.group(1).strip()

        # --- Format-string sinks (sprintf / vendor wrappers / …) ----------
        # The format string may be arg[0] (vendor wrapper sinks) or arg[1]
        # (sprintf) or arg[2] (snprintf).  We find the first string
        # literal in the arg list and treat that as the format string.
        if sink_name in format_sinks:
            # Find all string-literal positions in the full arg text
            all_strs = list(re.finditer(r'"([^"]*)"', arg_part))
            if not all_strs:
                return False  # no literal at all → not hardcoded
            # Pick the format string: for arg[0]-format sinks it's the 1st;
            # for sprintf/vsprintf it's the 2nd; for snprintf/fprintf 3rd.
            fmt_pos = 0
            if sink_name in ("sprintf", "vsprintf"):
                fmt_pos = min(1, len(all_strs) - 1)
            elif sink_name in ("snprintf", "fprintf"):
                fmt_pos = min(2, len(all_strs) - 1)
            fmt_match = all_strs[fmt_pos]
            fmt_body = fmt_match.group(1)
            # Has %s / %d / %x / %n … → external data can flow in
            if re.search(r'%[sdixn]', fmt_body):
                return False
            # No placeholders AND no extra non-literal arguments after
            # the format string → truly hardcoded
            rest = arg_part[fmt_match.end():].strip()
            if rest == '' or rest.startswith(')'):
                return True
            # There are more args after the format string → they may be
            # user-controlled even if the format has no placeholders
            # (e.g. snprintf(buf, sz, msg, user_val))
            extra = rest.lstrip(',').strip()
            if extra.startswith('"') or extra.startswith(')') or extra == '':
                return True
            return False

        # --- Single-arg sinks (system / popen) ---------------------------
        if arg_part.startswith('"'):
            first_str = re.match(r'"([^"]*)"', arg_part)
            if first_str:
                rest = arg_part[first_str.end():].strip()
                # system("reboot") or popen("cmd", "r") — first arg is literal
                if rest.startswith(')') or rest == '' or rest.startswith(', "'):
                    return True
            return False
        if arg_part.startswith("'") and arg_part[2:3] == "'":
            return True

        # --- Two-arg sinks (strcpy / strcat / strncpy / memcpy) ----------
        # The dangerous arg is the *source* (2nd arg), not the dest (1st).
        # strcpy(dest, "literal") → safe;  strcpy(dest, var) → not safe.
        if sink_name in ("strcpy", "strcat", "strncpy", "memcpy"):
            parts = [a.strip() for a in arg_part.split(",")]
            if len(parts) >= 2:
                src = parts[1].strip()
                if src.startswith('"'):
                    return True  # source is a string literal
            return False

    # Pattern didn't match any line → can't determine, treat as not hardcoded
    return False


def trace_arg_source(
    code: str,
    sink_name: str,
    taint_sources: list[str] | None = None,
    format_string_sinks: set[str] | None = None,
) -> dict[str, Any]:
    """Trace the source of a sink's argument (1-2 hop def-use chain).

    ``taint_sources`` / ``format_string_sinks`` override the generic lists
    (used when vendor knowledge is merged into the scan).

    Returns:
        {
            "arg": "cmd_buf",           # direct argument name
            "source": "getenv",         # source function (if found)
            "source_detail": "QUERY_STRING",
            "is_tainted": True,         # from known taint source?
            "trace_lines": "...",       # code snippet of the trace path
        }
    """
    taint = taint_sources if taint_sources is not None else TAINT_SOURCES
    format_sinks = format_string_sinks if format_string_sinks is not None else _FORMAT_STRING_SINKS
    result: dict[str, Any] = {
        "arg": "",
        "source": "",
        "source_detail": "",
        "is_tainted": False,
        "trace_lines": "",
    }

    lines = code.splitlines()

    # Step 1: find the sink call and extract its argument
    sink_pattern = re.compile(r'\b' + re.escape(sink_name) + r'\s*\(([^)]+)\)')
    arg_name = ""
    for line in lines:
        m = sink_pattern.search(line)
        if not m:
            continue
        raw_args = m.group(1).strip()

        # For format-string sinks (sprintf/vendor wrappers/…), the first arg
        # is a destination or format string — the *dangerous* args are the
        # ones that fill %s / %d / %n placeholders (args after the format).
        if sink_name in format_sinks:
            # Split args, skip the format string (2nd arg for sprintf,
            # 1st arg for arg[0]-format sinks which is pure format).
            parts = [a.strip() for a in raw_args.split(",")]
            # arg0-format sink(fmt, ...) → fmt is parts[0]
            # sprintf(dst, fmt, ...)    → fmt is parts[1]
            # snprintf(dst, sz, fmt, …) → fmt is parts[2]
            fmt_idx = 0
            if sink_name in ("sprintf", "vsprintf"):
                fmt_idx = 1
            elif sink_name in ("snprintf", "fprintf"):
                fmt_idx = 2
            # Collect every arg AFTER the format string
            extra_args = parts[fmt_idx + 1:]
            # Return the first non-literal extra arg as the taint target
            for a in extra_args:
                a = a.strip()
                if a and not a.startswith('"'):
                    arg_name = a
                    break
            if arg_name:
                break
            # All extra args are literals → fall through (safe)
            return result

        # Non-format sinks: first arg is the dangerous one
        arg_name = raw_args.split(",")[0].strip()
        break

    if not arg_name or arg_name.startswith('"'):
        return result

    result["arg"] = arg_name

    # Step 2: search for assignments to arg_name in the code
    # Patterns: arg = expr;  arg = func(...);  type arg = ...;
    assign_pattern = re.compile(
        r'(?:(?:\w+\s*\*?\s*)?)'  # optional type prefix
        + re.escape(arg_name) + r'\s*=\s*(.+?);'
    )

    trace_lines = []
    for line in lines:
        m = assign_pattern.search(line)
        if not m:
            continue
        rhs = m.group(1).strip()
        trace_lines.append(line.strip())

        # Check if RHS calls a taint source
        for src in taint:
            if src in rhs:
                result["source"] = src
                result["is_tainted"] = True
                # Try to extract the argument of the taint source
                src_m = re.search(re.escape(src) + r'\s*\(\s*"?([^")\s]+)', rhs)
                if src_m:
                    result["source_detail"] = src_m.group(1)
                break

        # If not a direct taint source, check for string concatenation
        # involving the arg (e.g., sprintf(buf, "cmd %s", arg))
        if not result["source"]:
            for line2 in lines:
                if arg_name in line2 and ("sprintf" in line2 or "strcat" in line2 or "strcpy" in line2):
                    trace_lines.append(line2.strip())
                    break

        if result["source"]:
            break

    result["trace_lines"] = "\n".join(f"    {l}" for l in trace_lines[:5])
    return result


def classify_finding(
    sink: str,
    context: str,
    sink_classification: dict[str, tuple[str, str, str, float]] | None = None,
    taint_sources: list[str] | None = None,
) -> tuple[str, str, str, float]:
    """Classify a finding based on sink type + context.

    More accurate than pure table lookup:
    - hardcoded arg -> lower confidence
    - taint source in context -> higher confidence

    Returns (cwe, description, severity, confidence).
    """
    classification = sink_classification if sink_classification is not None else _SINK_CLASSIFICATION
    taint = taint_sources if taint_sources is not None else TAINT_SOURCES
    cwe, desc, severity, confidence = classification.get(sink, _SINK_DEFAULT)

    # Boost if taint source visible in context
    for src in taint:
        if src in context:
            confidence = min(confidence + 0.2, 1.0)
            if confidence > 0.7:
                severity = "CRITICAL"
            break

    return cwe, desc, severity, confidence


# ---------------------------------------------------------------------------
# IDAHeadlessScanner — primary scanner, runs on headless IDA
# ---------------------------------------------------------------------------


class IDAHeadlessScanner:
    """Systematic vulnerability scanner using headless IDA.

    Python layer does mechanical pre-screening:
    1. Find all sink callers
    2. Filter hardcoded args (exclude safe calls)
    3. Extract sink context (±8 lines, not full function)
    4. Trace arg sources
    5. Rank by risk

    Output: refined candidate list for AI second-round triage.

    ``vendor`` (optional) merges vendor-specific sinks/taint sources from
    ``knowledge/<vendor>.json`` -- the scanner stays vendor-neutral by default.
    """

    def __init__(self, client: IDAHeadlessClient, vendor: str = ""):
        self.client = client
        self.vendor = vendor
        (
            self.sinks,
            self.taint_sources,
            self.sink_classification,
            self.format_string_sinks,
        ) = _merge_vendor_knowledge(vendor)

    def find_dangerous_calls(self) -> list[dict]:
        """Find all callers of dangerous sink functions.

        Uses IDAHeadlessClient.imports_query() + xrefs_to() for
        structured, batch-capable lookup.
        """
        # Get functions matching dangerous sinks
        imports = self.client.imports_query(self.sinks)

        # Collect unique addresses (imports_query returns flat dicts)
        import_map: dict[str, dict] = {}
        for imp in imports:
            if isinstance(imp, dict) and imp.get("addr"):
                import_map[imp["addr"]] = imp

        all_addrs = list(import_map.keys())
        if not all_addrs:
            return []

        # Batch xrefs: [{"addr": import_hex, "xrefs": [{"addr", "fn"}]}]
        xrefs_data = self.client.xrefs_to(all_addrs)

        results: list[dict] = []
        for entry in xrefs_data:
            if not isinstance(entry, dict):
                continue
            imp_addr = entry.get("addr", "")
            imp = import_map.get(imp_addr)
            if not imp:
                continue
            for xr in entry.get("xrefs", []):
                if not isinstance(xr, dict):
                    continue
                results.append({
                    "dangerous_func": imp["imported_name"],
                    "import_addr": imp_addr,
                    "caller_addr": xr.get("addr"),
                    "caller_name": xr.get("fn", "unknown"),
                })
        return results

    def systematic_scan(self) -> list[VulnerabilityFinding]:
        """Full pipeline: find sinks -> filter -> context -> rank.

        Output VulnerabilityFinding.decompiled_code contains only
        the ±8 line context snippet (not the full function).
        AI uses this for quick triage, then requests full decompile
        for candidates worth deeper analysis.
        """
        # Step 1: All dangerous calls
        dangerous_calls = self.find_dangerous_calls()
        logger.info("dangerous calls found", count=len(dangerous_calls))

        # Step 2: Deduplicate by (caller, sink)
        seen: set[str] = set()
        unique: list[dict] = []
        for dc in dangerous_calls:
            key = f"{dc['caller_name']}:{dc['dangerous_func']}"
            if key not in seen:
                seen.add(key)
                unique.append(dc)

        logger.info("unique caller-sink pairs", count=len(unique))

        # Step 3: Analyze each candidate
        findings: list[VulnerabilityFinding] = []
        for dc in unique:
            sink = dc["dangerous_func"]
            caller = dc["caller_name"]
            caller_addr = dc["caller_addr"]

            # Decompile full function (headless in-memory, no AI context cost)
            # caller_addr may be a hex string — convert to int for IDA
            try:
                addr_int = int(caller_addr, 16) if isinstance(caller_addr, str) else caller_addr
                full_code = self.client.decompile(addr_int)
                if not full_code:
                    continue
                full_code = str(full_code)
            except Exception:
                logger.warning("decompile failed, skipping", caller=caller, addr=caller_addr)
                continue

            # Check if hardcoded arg -> safe, skip
            if is_hardcoded_arg(full_code, sink, self.format_string_sinks):
                logger.debug("skipping hardcoded arg", caller=caller, sink=sink)
                continue

            # Extract context snippet (±8 lines around sink)
            context = extract_sink_context(full_code, sink, context_lines=8)

            # Trace arg source
            taint_info = trace_arg_source(
                full_code, sink,
                taint_sources=self.taint_sources,
                format_string_sinks=self.format_string_sinks,
            )

            # Classify
            cwe, desc, severity, confidence = classify_finding(
                sink, context,
                sink_classification=self.sink_classification,
                taint_sources=self.taint_sources,
            )

            # Build source-sink path description
            source_desc = ""
            if taint_info["is_tainted"]:
                source_desc = f"{taint_info['source']}({taint_info.get('source_detail', '')})"
            # caller_addr is already a hex string from IDA
            addr_str = caller_addr if isinstance(caller_addr, str) else hex(caller_addr)
            source_sink = f"{source_desc} → {sink}" if source_desc else f"{sink} @ {addr_str}"

            title = f"{sink}() call in {caller}" + (f" — {desc}" if desc else "")
            findings.append(VulnerabilityFinding(
                title=title,
                severity=severity,
                cwe_id=cwe,
                vulnerable_function=caller,
                vulnerable_address=str(caller_addr),
                source_sink_path=source_sink,
                description=taint_info.get("trace_lines", ""),
                decompiled_code=context,  # Only ±8 lines, not full function
                confidence=confidence,
            ))

        # Sort by confidence descending
        findings.sort(key=lambda f: f.confidence, reverse=True)

        logger.info("headless scan complete",
                     total=len(findings),
                     high_risk=sum(1 for f in findings if f.confidence >= 0.5))
        return findings
