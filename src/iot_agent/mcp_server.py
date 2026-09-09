"""MCP server that exposes the IoT Agent toolchain to Claude Code.

Architecture
------------
Claude Code is the agent/orchestrator.  This module intentionally does NOT
implement an agent loop, conversation memory, or task scheduling.  It only
exposes deterministic, single-purpose tools that Claude Code can call through
MCP (stdio).  Long-lived state lives in SQLite:

- ``AnalysisStore``  -- analysis tasks, findings (candidate-level resume).
- ``ExperienceStore`` (same DB) -- reusable lessons across hunts; the agent
  loads a filtered digest at hunt start and records lessons at hunt end.
  This is *knowledge*, not agent memory -- no loop logic here.

All VM tools share one pooled ``VMRemoteExecutor`` inside this server process,
so consecutive tool calls reuse a single SSH connection (auto-reconnect on
drop) instead of paying a handshake per call.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from iot_agent.tools.analysis_store import AnalysisStore
from iot_agent.tools.emulation_env import EmulationManager
from iot_agent.tools.firmware_acquire import FirmwareAcquirer
from iot_agent.tools.firmware_index import FirmwareIndex
from iot_agent.tools.ida_mcp import VulnerabilityFinding, cleanup_ida_files
from iot_agent.tools.remote_vm import VMRemoteExecutor

app = FastMCP("iot-agent")

# ---------------------------------------------------------------------------
# Pooled VM connection (reused across tool calls in this server process)
# ---------------------------------------------------------------------------

_vm: VMRemoteExecutor | None = None


def _get_vm() -> VMRemoteExecutor:
    """Return the shared VM executor, creating it on first use."""
    global _vm
    if _vm is None:
        _vm = VMRemoteExecutor()
    return _vm


async def _vm_ready() -> VMRemoteExecutor:
    """Return the shared executor with a live connection."""
    vm = _get_vm()
    await vm.connect()
    return vm


# ---------------------------------------------------------------------------
# VM / shell tools
# ---------------------------------------------------------------------------


@app.tool()
async def iot_vm_execute(command: str, timeout: int = 300) -> dict[str, Any]:
    """Run a shell command on the analysis VM and return stdout/stderr/exit code.

    Use for binwalk, radare2, qemu-user, PoC validation and any other VM-side
    work. The SSH connection is pooled -- repeated calls are cheap.
    """
    vm = await _vm_ready()
    result = await vm.execute(command, timeout=timeout)
    return {
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@app.tool()
async def iot_vm_check_tools() -> dict[str, bool]:
    """Check which analysis tools are installed on the VM."""
    vm = await _vm_ready()
    return await vm.check_tools()


@app.tool()
async def iot_vm_upload(local_path: str, remote_path: str) -> bool:
    """Upload a local file to the VM via SFTP."""
    vm = await _vm_ready()
    return await vm.upload(local_path, remote_path)


@app.tool()
async def iot_vm_download(remote_path: str, local_path: str) -> bool:
    """Download a file from the VM to the local machine via SFTP."""
    vm = await _vm_ready()
    return await vm.download(remote_path, local_path)


# ---------------------------------------------------------------------------
# Firmware acquisition / extraction
# ---------------------------------------------------------------------------


@app.tool()
async def iot_firmware_extract(
    firmware_url_or_path: str,
    brand: str = "unknown",
    model: str = "unknown",
    version: str = "unknown",
) -> str | None:
    """Download (if URL) and extract a firmware image on the VM. Returns rootfs path.

    Find the firmware download URL yourself (WebSearch / vendor support pages,
    prefer official vendor direct links) and pass it here.
    """
    vm = await _vm_ready()
    acquirer = FirmwareAcquirer(vm)
    return await acquirer.extract(
        firmware_url_or_path, brand=brand, model=model, version=version
    )


@app.tool()
def iot_firmware_list_cached(
    vendor: str = "",
    model: str = "",
    version: str = "",
) -> list[dict[str, Any]]:
    """List firmware already cached in the local SQLite index."""
    return FirmwareIndex().search(vendor=vendor, model=model, version=version)


@app.tool()
def iot_firmware_cache_stats() -> dict[str, Any]:
    """Return aggregate statistics about the firmware cache."""
    return FirmwareIndex().stats()


@app.tool()
async def iot_firmware_cache_status() -> dict[str, Any]:
    """Return status of the local firmware cache directory on the VM."""
    vm = await _vm_ready()
    acquirer = FirmwareAcquirer(vm)
    return await acquirer.cache_status()


# ---------------------------------------------------------------------------
# Dynamic verification -- user-mode + chroot ONLY (system emulation removed)
# ---------------------------------------------------------------------------


@app.tool()
async def iot_emulation_detect_arch(rootfs_path: str) -> str | None:
    """Detect the CPU architecture of a firmware rootfs (mips/mipsel/arm/...)."""
    vm = await _vm_ready()
    emu = EmulationManager(vm)
    return await emu.detect_arch(rootfs_path)


@app.tool()
async def iot_emulation_ensure_qemu(arch: str) -> dict[str, Any]:
    """Locate qemu-user-static for an architecture on the VM (search, not guess).

    Search order: PATH -> /usr/local/bin -> bounded find under /usr /opt /data.
    Returns found/path, or the install command when missing (escalate to user).
    """
    vm = await _vm_ready()
    emu = EmulationManager(vm)
    return await emu.ensure_qemu(arch)


@app.tool()
async def iot_emulation_user_mode(
    rootfs_path: str,
    command: str,
    arch: str = "",
) -> dict[str, Any]:
    """QUICK PROBE (NOT a final verdict): run a command via qemu user-mode -L.

    ``-L`` only redirects loader/libs -- guest absolute paths (/etc, /tmp,
    /bin/sh) fall through to the HOST filesystem. Use it to cheaply confirm
    or exclude a sink before the full verification; final verdicts must come
    from ``iot_emulation_chroot_user_mode``.
    """
    vm = await _vm_ready()
    emu = EmulationManager(vm)
    return await emu.user_mode_run(rootfs_path, command, arch=arch)


@app.tool()
async def iot_emulation_chroot_user_mode(
    rootfs_path: str,
    command: str,
    arch: str = "",
    workdir: str = "",
    inject_nvram: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    """THE dynamic verification path: run a command inside a chroot-wrapped qemu.

    Copies the rootfs to a working copy (original untouched), copies
    qemu-<arch>-static inside, bind-mounts /dev /dev/pts /proc, then
    ``chroot <workdir> /usr/bin/qemu-<arch>-static -- <command>``. The guest
    sees the device view (/etc, /tmp, /bin/sh, fork/exec all inside the
    rootfs) with NO binfmt_misc dependency. This result MAY be a final
    verdict. Use ``iot_emulation_chroot_cleanup`` afterwards.
    """
    vm = await _vm_ready()
    emu = EmulationManager(vm)
    return await emu.chroot_user_mode(
        rootfs_path=rootfs_path,
        command=command,
        arch=arch,
        workdir=workdir,
        inject_nvram=inject_nvram,
        timeout=timeout,
    )


@app.tool()
async def iot_emulation_chroot_cleanup(
    workdir: str,
    process_match: str = "qemu-.*-static",
    remove_workdir: bool = False,
) -> dict[str, Any]:
    """Stop a chrooted qemu process and unmount its dev/pts/proc bind mounts.

    ``workdir`` is the chroot working copy from ``iot_emulation_chroot_user_mode``.
    Set ``remove_workdir=True`` to also delete the working copy after unmount.
    """
    vm = await _vm_ready()
    emu = EmulationManager(vm)
    return await emu.chroot_cleanup(
        workdir=workdir, process_match=process_match, remove_workdir=remove_workdir
    )


# ---------------------------------------------------------------------------
# Analysis persistence (results, not agent memory)
# ---------------------------------------------------------------------------


@app.tool()
def iot_analysis_create_task(
    firmware_id: str,
    vendor: str = "",
    model: str = "",
    version: str = "",
    rootfs_path: str = "",
    notes: str = "",
) -> int:
    """Create an analysis task in SQLite. Returns task id."""
    return AnalysisStore().create_task(
        firmware_id=firmware_id,
        vendor=vendor,
        model=model,
        version=version,
        rootfs_path=rootfs_path,
        notes=notes,
    )


@app.tool()
def iot_analysis_add_finding(
    task_id: int,
    title: str,
    severity: str = "",
    cwe_id: str = "",
    cve_id: str = "",
    binary_name: str = "",
    vulnerable_function: str = "",
    vulnerable_address: str = "",
    source_sink: str = "",
    description: str = "",
    code_context: str = "",
    exploit_vector: str = "",
    confidence: float = 0.0,
    verdict: str = "pending",
    notes: str = "",
) -> int:
    """Record a vulnerability finding under an analysis task. Returns finding id."""
    finding = VulnerabilityFinding(
        title=title,
        severity=severity,
        cwe_id=cwe_id,
        cve_id=cve_id or None,
        vulnerable_function=vulnerable_function,
        vulnerable_address=vulnerable_address,
        source_sink_path=source_sink,
        description=description,
        decompiled_code=code_context,
        exploit_vector=exploit_vector,
        confidence=confidence,
    )
    return AnalysisStore().add_finding(
        task_id, finding, verdict=verdict, notes=notes, binary_name=binary_name
    )


@app.tool()
def iot_analysis_update_finding(
    finding_id: int,
    verdict: str = "",
    notes: str = "",
) -> None:
    """Update a finding's verdict and/or notes (e.g. after L4 verification)."""
    store = AnalysisStore()
    fields: dict[str, Any] = {}
    if verdict:
        fields["verdict"] = verdict
    if notes:
        fields["notes"] = notes
    if fields:
        store.update_finding(finding_id, **fields)


@app.tool()
def iot_analysis_mark_level(task_id: int, level: int) -> None:
    """Mark the task as having completed up to this analysis level (1-4)."""
    AnalysisStore().mark_level(task_id, level)


@app.tool()
def iot_analysis_mark_completed(task_id: int) -> None:
    """Mark the task as completed."""
    AnalysisStore().mark_completed(task_id)


@app.tool()
def iot_analysis_mark_failed(task_id: int, error: str = "") -> None:
    """Mark the task as failed (with an optional reason)."""
    AnalysisStore().mark_failed(task_id, error)


@app.tool()
def iot_analysis_list_tasks(
    status: str = "",
    vendor: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List analysis tasks, optionally filtered by status/vendor."""
    return AnalysisStore().list_tasks(
        status=status or None, vendor=vendor or None, limit=limit
    )


@app.tool()
def iot_analysis_get_findings(
    task_id: int,
    verdict: str = "",
) -> list[dict[str, Any]]:
    """Get findings for an analysis task, optionally filtered by verdict."""
    return AnalysisStore().get_findings(task_id, verdict=verdict or None)


@app.tool()
def iot_analysis_resume_task(task_id: int) -> dict[str, Any]:
    """Return a task plus its still-pending candidates for resuming a hunt.

    Candidates whose verdict is CONFIRMED/DISPROVED/WEAKENED are excluded --
    the agent can skip straight to the pending ones.
    """
    return AnalysisStore().resume_task(task_id)


@app.tool()
def iot_analysis_export_task(task_id: int) -> dict[str, Any]:
    """Export an analysis task and all findings as a JSON-serializable dict."""
    return AnalysisStore().export_task(task_id)


@app.tool()
def iot_analysis_stats() -> dict[str, Any]:
    """Return aggregate statistics about stored analysis tasks/findings."""
    return AnalysisStore().stats()


# ---------------------------------------------------------------------------
# Experience memory (cross-session knowledge)
# ---------------------------------------------------------------------------


@app.tool()
def iot_experience_record(
    category: str,
    scenario: str,
    detail: str,
    vendor: str = "",
    arch: str = "",
    source_task_id: int | None = None,
) -> int:
    """Record a reusable lesson learned during analysis.

    Categories: ``env`` (environment pitfalls), ``pattern`` (reusable
    vulnerability patterns), ``false_positive`` (things that looked dangerous
    but were not), ``verification`` (dynamic-verification tricks),
    ``workflow`` (process improvements). Same scenario+vendor+arch refreshes
    the existing entry instead of duplicating. Returns experience id.
    """
    return AnalysisStore().record_experience(
        category=category,
        scenario=scenario,
        detail=detail,
        vendor=vendor,
        arch=arch,
        source_task_id=source_task_id,
    )


@app.tool()
def iot_experience_load(
    category: str = "",
    vendor: str = "",
    arch: str = "",
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Load reusable lessons for the current hunt context.

    Call this at hunt start with the target vendor/arch to get a compact
    digest (details truncated to 300 chars) of what worked and what did not.
    """
    return AnalysisStore().search_experiences(
        category=category, vendor=vendor, arch=arch, limit=limit
    )


@app.tool()
def iot_experience_bump(exp_id: int, success: bool = True) -> None:
    """Mark an experience as having worked (success=True) or not again."""
    AnalysisStore().bump_experience(exp_id, success=success)


@app.tool()
def iot_experience_stats() -> dict[str, Any]:
    """Return aggregate statistics about the experience memory."""
    return AnalysisStore().experience_stats()


@app.tool()
def iot_experience_ingest_report(
    report_path: str,
    vendor: str = "",
    arch: str = "",
    category: str = "pattern",
) -> list[int]:
    """Parse a markdown report and record each section as an experience.

    Use this to digest historical reports (reports/*.md) into the experience
    memory: each ``##``/``###`` section becomes one entry. Returns ids.
    """
    return AnalysisStore().ingest_report(
        report_path, vendor=vendor, arch=arch, category=category
    )


@app.tool()
def iot_experience_export_markdown(
    category: str = "pattern",
    min_success: int = 3,
    limit: int = 20,
) -> str:
    """Export proven experiences as a markdown block for manual promotion.

    Solidify dynamic lessons (success_count - fail_count >= min_success)
    back into the static knowledge docs (knowledge/vuln-patterns.md).
    """
    return AnalysisStore().export_experience_markdown(
        category=category, min_success=min_success, limit=limit
    )


@app.tool()
def iot_analysis_insights(vendor: str = "") -> dict[str, Any]:
    """Aggregate historical findings into insights: by binary / sink / CWE.

    Includes verdict distributions and false-positive rates, so the agent
    learns which sinks for a vendor are usually false positives.
    """
    return AnalysisStore().findings_insights(vendor=vendor)


# ---------------------------------------------------------------------------
# IDA headless scanning (optional; requires local idapro installation)
# ---------------------------------------------------------------------------


@app.tool()
def iot_knowledge_vendors() -> list[dict[str, Any]]:
    """List vendor knowledge files available in knowledge/.

    Call at hunt start to check whether the target vendor has machine
    knowledge (sinks/taint sources) to merge into the headless scan.
    """
    from iot_agent.tools.ida_scanner import list_vendor_knowledge
    return list_vendor_knowledge()


@app.tool()
def iot_ida_headless_scan(binary_path: str, vendor: str = "") -> list[dict[str, Any]]:
    """Run the headless IDA systematic scanner on a local ELF file.

    This is only available on the machine that has IDA Pro / idalib installed.
    If IDA is already running, prefer the separate ``ida-pro-mcp`` server.
    Pass ``vendor`` (e.g. "dlink") to merge vendor-specific sinks/taint
    sources from ``knowledge/<vendor>.json``.
    """
    from iot_agent.tools.ida_mcp import IDAHeadlessClient
    from iot_agent.tools.ida_scanner import IDAHeadlessScanner

    with IDAHeadlessClient(binary_path) as ida:
        scanner = IDAHeadlessScanner(ida, vendor=vendor)
        findings = scanner.systematic_scan()
        return [f.to_dict() for f in findings]


@app.tool()
def iot_ida_cleanup(elf_directory: str) -> int:
    """Delete IDA-generated files (.i64/.id0/.id1/.id2/.nam/.til) for a dir.

    Run after each ELF is fully analyzed; keeps only the raw ELF files.
    Returns the number of files removed.
    """
    return cleanup_ida_files(elf_directory)


def main() -> None:
    """Run the MCP server.

    Default transport is stdio (for Claude Code). Pass ``--transport sse``
    (or ``streamable-http``) to serve over HTTP; bind host/port via the
    FASTMCP_HOST / FASTMCP_PORT environment variables.
    """
    import sys

    transport = "stdio"
    if "--transport" in sys.argv:
        i = sys.argv.index("--transport")
        if i + 1 < len(sys.argv):
            transport = sys.argv[i + 1]
    app.run(transport=transport)


if __name__ == "__main__":
    main()
