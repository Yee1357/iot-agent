"""Chroot runtime assets for single-service dynamic verification on the VM.

Only the NVRAM shim survives of the former FirmAE asset set: it lets
``EmulationManager.chroot_user_mode(inject_nvram=True)`` preload an
arch-matched ``libnvram.so`` into a chrooted qemu-user process so a single
CGI/daemon can read NVRAM values without a full system image.

Full-system emulation (FirmAE, manual QEMU system mode, kernels, boot
templates, busybox/console shims) was deliberately removed — see
``emulation_env.py`` for the design rationale. Provisioning here is
idempotent and mirror-aware.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import structlog

from iot_agent.config import settings
from iot_agent.tools.remote_vm import VMRemoteExecutor

logger = structlog.get_logger(__name__)


#: NVRAM shim binaries used for chroot injection. All from the
#: pr0v3rbs/FirmAE release v1.0 (verified via GitHub API 2026-07-31).
RUNTIME_ASSETS: dict[str, dict[str, Any]] = {
    "libnvram.so.mipseb": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipseb",
        "size": 37416,
    },
    "libnvram.so.mipsel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipsel",
        "size": 37416,
    },
    "libnvram.so.armel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.armel",
        "size": 33872,
    },
}

#: arch -> runtime asset names
ARCH_RUNTIME: dict[str, dict[str, str]] = {
    "mips": {"libnvram": "libnvram.so.mipseb"},
    "mipsel": {"libnvram": "libnvram.so.mipsel"},
    "arm": {"libnvram": "libnvram.so.armel"},
}


def runtime_dir() -> str:
    """Remote runtime-assets directory on the VM."""
    return settings.vm_runtime_dir


def runtime_manifest_path() -> str:
    return f"{runtime_dir()}/runtime-manifest.json"


def _asset_url(url: str) -> str:
    """Apply the optional download mirror prefix (provenance stays official)."""
    mirror = settings.download_mirror.strip().rstrip("/")
    return f"{mirror}/{url}" if mirror else url


async def _file_ok(vm: VMRemoteExecutor, path: str, size: int | None) -> bool:
    if size is None:
        check = await vm.execute(f"test -f {path} && echo OK")
        return check.exit_code == 0 and "OK" in check.stdout
    st = await vm.execute(f"stat -c %s {path} 2>/dev/null")
    return st.stdout.strip() == str(size)


def _download_script(name: str, info: dict) -> str:
    size_check = (
        f"[ \"$(stat -c %s {name})\" = \"{info['size']}\" ] || "
        f"{{ echo SIZE_MISMATCH; exit 3; }}"
        if info.get("size")
        else "true"
    )
    return f"""
set -e
mkdir -p {runtime_dir()}
cd {runtime_dir()}
wget -c -q --tries=5 --timeout=60 -O {name} '{_asset_url(info['url'])}'
{size_check}
sha256sum {name} | awk '{{print $1}}'
""".strip()


async def provision_runtime_assets(
    vm: VMRemoteExecutor, dry_run: bool = False
) -> dict:
    """Download runtime binaries into ``runtime_dir()`` (idempotent).

    Returns ``{"downloaded": [...], "skipped": [...], "failed": [...]}``.
    """
    summary: dict[str, list[str]] = {"downloaded": [], "skipped": [], "failed": []}
    if dry_run:
        summary["downloaded"] = list(RUNTIME_ASSETS)
        return summary

    await vm.execute(f"mkdir -p {runtime_dir()}")
    manifest: dict = {}
    raw = await vm.execute(f"cat {runtime_manifest_path()} 2>/dev/null || echo __MISSING__")
    if "__MISSING__" not in raw.stdout:
        try:
            manifest = json.loads(raw.stdout)
        except json.JSONDecodeError:
            pass

    for name, info in RUNTIME_ASSETS.items():
        dest = f"{runtime_dir()}/{name}"
        if await _file_ok(vm, dest, info.get("size")):
            summary["skipped"].append(name)
            continue
        logger.info("downloading runtime asset", name=name, size=info["size"])
        result = await vm.execute(_download_script(name, info), timeout=300)
        if result.exit_code != 0:
            logger.error("runtime asset download failed", name=name, stderr=result.stderr[:200])
            summary["failed"].append(name)
            continue
        hashed = await vm.execute(f"sha256sum {dest} | awk '{{print $1}}'")
        sha256 = hashed.stdout.strip().splitlines()[0] if hashed.stdout.strip() else ""
        manifest[name] = {
            "sha256": sha256,
            "url": info["url"],
            "source": "pr0v3rbs/FirmAE@v1.0",
            "size": info["size"],
        }
        summary["downloaded"].append(name)

    payload = base64.b64encode(
        json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    await vm.execute(f"echo {payload} | base64 -d > {runtime_manifest_path()}")
    return summary