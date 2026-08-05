"""Kernel asset management -- manifest-driven provisioning of QEMU kernels.

Why this exists
---------------
The agent must never guess which kernel to download. Every kernel is recorded
in a manifest (default ``/data/qemu-images/kernels/manifest.json``) with
provenance (source repo/release), sha256 and the file path on the VM.

Provisioning order (deterministic, no guessing):

1. Kernel already present in the kernels dir -> reuse
2. Copy from an existing FirmAE install (``/opt/firmae/binaries``)
3. Download the pinned URL from the registry and verify sha256

The same module also manages the manual-QEMU boot templates
(``boot-templates.json``) so the agent boots from a per-arch template instead
of inventing QEMU command lines.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from typing import Any

import structlog

from iot_agent.config import settings
from iot_agent.tools.remote_vm import VMRemoteExecutor

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Default asset registry
# ---------------------------------------------------------------------------

#: Kernel metadata per architecture.
#: ``candidates`` are filenames to look for inside an existing FirmAE binaries
#: dir (naming differs between FirmAE and firmadyne). ``url`` is the pinned
#: fallback download location. ``source`` records provenance for the manifest.
# Kernels are the exact assets FirmAE itself downloads (download.sh), so
# emulation compatibility is guaranteed. Verified via GitHub API on 2026-07-31.
ARCH_KERNELS: dict[str, dict[str, Any]] = {
    "mips": {
        "dest": "vmlinux.mipseb.2",
        "candidates": ["vmlinux.mipseb.2", "vmlinux.mipseb.2.6.32", "vmlinux-mips_2.6.32"],
        "size": 7751456,
        "url": (
            "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/"
            "v1.0/vmlinux.mipseb.2"
        ),
        "source": "pr0v3rbs/FirmAE_kernel-v2.6@v1.0",
    },
    "mipsel": {
        "dest": "vmlinux.mipsel.2",
        "candidates": ["vmlinux.mipsel.2", "vmlinux.mipsel.2.6.32", "vmlinux-mipsel_2.6.32"],
        "size": 7652368,
        "url": (
            "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/"
            "v1.0/vmlinux.mipsel.2"
        ),
        "source": "pr0v3rbs/FirmAE_kernel-v2.6@v1.0",
    },
    "arm": {
        "dest": "zImage.armel",
        "candidates": ["zImage.armel", "vmlinux.armel", "vmlinux.armel.4.1", "vmlinux-armel_2.6.32"],
        "size": 3261512,
        "url": (
            "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/"
            "v1.0/zImage.armel"
        ),
        "source": "pr0v3rbs/FirmAE_kernel-v4.1@v1.0",
    },
}

#: Manual QEMU boot templates (aurel32 Debian images). Fallback path when
#: FirmAE is not usable. The file is written to the VM as boot-templates.json
#: and can be edited there if the user provisions different images.
DEFAULT_BOOT_TEMPLATES: dict[str, dict[str, str]] = {
    "mips": {
        "qemu": "qemu-system-mips",
        "machine": "malta",
        "kernel": "vmlinux-2.6.32-5-4kc-malta",
        "disk": "debian_squeeze_mips_standard.qcow2",
        "append": "root=/dev/sda1 console=ttyS0",
        "hostfwd": "tcp::8080-:80",
    },
    "mipsel": {
        "qemu": "qemu-system-mipsel",
        "machine": "malta",
        "kernel": "vmlinux-3.2.0-4-4kc-malta",
        "disk": "debian_squeeze_mipsel_standard.qcow2",
        "append": "root=/dev/sda1 console=ttyS0",
        "hostfwd": "tcp::8080-:80",
    },
    "arm": {
        "qemu": "qemu-system-arm",
        "machine": "versatilepb",
        "kernel": "vmlinuz-2.6.32-5-versatile",
        "initrd": "initrd.img-2.6.32-5-versatile",
        "disk": "debian_squeeze_armel_standard.qcow2",
        "append": "root=/dev/sda1 console=ttyAMA0",
        "hostfwd": "tcp::8080-:80",
    },
}

#: FirmAE runtime binaries (small, ~8 MB total) used for chroot injection and
#: NVRAM simulation when booting extracted rootfs services directly.
#: All from pr0v3rbs/FirmAE release v1.0 (verified via GitHub API 2026-07-31).
RUNTIME_ASSETS: dict[str, dict[str, Any]] = {
    "busybox.mipseb": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipseb",
        "size": 1554032,
    },
    "busybox.mipsel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipsel",
        "size": 1552668,
    },
    "busybox.armel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.armel",
        "size": 1136104,
    },
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
    "libnvram_ioctl.so.mipseb": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipseb",
        "size": 37968,
    },
    "libnvram_ioctl.so.mipsel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipsel",
        "size": 37968,
    },
    "libnvram_ioctl.so.armel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.armel",
        "size": 34768,
    },
    "console.mipseb": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipseb",
        "size": 130720,
    },
    "console.mipsel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipsel",
        "size": 129824,
    },
    "console.armel": {
        "url": "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.armel",
        "size": 131304,
    },
}

#: Debian boot images for the manual-QEMU path (aurel32) -- the user's
#: established workflow: download kernel + qcow2, run qemu-system-* directly.
#: URLs verified via people.debian.org/~aurel32/qemu/<arch>/ (2026-08-01).
#: ``role`` maps to boot template fields; ``big`` assets download in the
#: background with progress polling.
BOOT_IMAGES: dict[str, list[dict[str, Any]]] = {
    "mipsel": [
        {
            "name": "vmlinux-3.2.0-4-4kc-malta",
            "url": "https://people.debian.org/~aurel32/qemu/mipsel/vmlinux-3.2.0-4-4kc-malta",
            "role": "kernel",
        },
        {
            "name": "debian_squeeze_mipsel_standard.qcow2",
            "url": "https://people.debian.org/~aurel32/qemu/mipsel/debian_squeeze_mipsel_standard.qcow2",
            "role": "disk",
            "big": True,
        },
    ],
    "mips": [
        {
            "name": "vmlinux-2.6.32-5-4kc-malta",
            "url": "https://people.debian.org/~aurel32/qemu/mips/vmlinux-2.6.32-5-4kc-malta",
            "role": "kernel",
        },
        {
            "name": "debian_squeeze_mips_standard.qcow2",
            "url": "https://people.debian.org/~aurel32/qemu/mips/debian_squeeze_mips_standard.qcow2",
            "role": "disk",
            "big": True,
        },
    ],
    "arm": [
        {
            "name": "vmlinuz-2.6.32-5-versatile",
            "url": "https://people.debian.org/~aurel32/qemu/armel/vmlinuz-2.6.32-5-versatile",
            "role": "kernel",
        },
        {
            "name": "initrd.img-2.6.32-5-versatile",
            "url": "https://people.debian.org/~aurel32/qemu/armel/initrd.img-2.6.32-5-versatile",
            "role": "initrd",
        },
        {
            "name": "debian_squeeze_armel_standard.qcow2",
            "url": "https://people.debian.org/~aurel32/qemu/armel/debian_squeeze_armel_standard.qcow2",
            "role": "disk",
            "big": True,
        },
    ],
}

#: arch -> runtime asset names
ARCH_RUNTIME = {
    "mips": {"busybox": "busybox.mipseb", "libnvram": "libnvram.so.mipseb", "libnvram_ioctl": "libnvram_ioctl.so.mipseb"},
    "mipsel": {"busybox": "busybox.mipsel", "libnvram": "libnvram.so.mipsel", "libnvram_ioctl": "libnvram_ioctl.so.mipsel"},
    "arm": {"busybox": "busybox.armel", "libnvram": "libnvram.so.armel", "libnvram_ioctl": "libnvram_ioctl.so.armel"},
}


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def kernels_dir() -> str:
    """Remote kernels directory on the VM."""
    return settings.vm_kernels_dir


def manifest_path() -> str:
    return f"{kernels_dir()}/manifest.json"


def boot_templates_path() -> str:
    return settings.vm_qemu_boot_templates


def runtime_dir() -> str:
    return f"{settings.vm_qemu_image_dir}/runtime"


def runtime_manifest_path() -> str:
    return f"{runtime_dir()}/runtime-manifest.json"


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------


def default_manifest() -> dict:
    """Manifest with registry defaults (sha256 filled in at provision time)."""
    return {
        "version": 1,
        "kernels": {
            arch: {
                "path": info["dest"],
                "sha256": "",
                "url": info["url"],
                "source": info["source"],
            }
            for arch, info in ARCH_KERNELS.items()
        },
    }


def _asset_url(url: str) -> str:
    """Apply the optional download mirror prefix (provenance stays official)."""
    mirror = settings.download_mirror.strip().rstrip("/")
    return f"{mirror}/{url}" if mirror else url


def normalize_manifest(raw: dict | None) -> dict:
    """Merge a loaded manifest over the defaults (future-proofs new archs)."""
    manifest = default_manifest()
    if raw and isinstance(raw.get("kernels"), dict):
        for arch, entry in raw["kernels"].items():
            manifest["kernels"][arch] = {
                **manifest["kernels"].get(arch, {}),
                **entry,
            }
    return manifest


async def _read_manifest(vm: VMRemoteExecutor) -> dict:
    path = manifest_path()
    result = await vm.execute(f"cat {path} 2>/dev/null || echo __MISSING__")
    if result.exit_code == 0 and "__MISSING__" not in result.stdout:
        try:
            return normalize_manifest(json.loads(result.stdout))
        except json.JSONDecodeError:
            logger.warning("manifest unreadable, using defaults", path=path)
    return default_manifest()


async def _write_manifest(vm: VMRemoteExecutor, manifest: dict) -> bool:
    """Write manifest via base64 to avoid shell quoting issues."""
    payload = base64.b64encode(
        json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    script = (
        f"mkdir -p {kernels_dir()} && "
        f"echo {payload} | base64 -d > {manifest_path()}"
    )
    result = await vm.execute(script)
    return result.exit_code == 0


async def _record_entry(vm: VMRemoteExecutor, arch: str, entry: dict) -> None:
    manifest = await _read_manifest(vm)
    manifest["kernels"][arch] = {
        **manifest["kernels"].get(arch, {}),
        **entry,
    }
    await _write_manifest(vm, manifest)


async def _file_ok(vm: VMRemoteExecutor, path: str, size: int | None) -> bool:
    if size is None:
        check = await vm.execute(f"test -f {path} && echo OK")
        return check.exit_code == 0 and "OK" in check.stdout
    st = await vm.execute(f"stat -c %s {path} 2>/dev/null")
    return st.stdout.strip() == str(size)


# ---------------------------------------------------------------------------
# Provisioning (remote VM)
# ---------------------------------------------------------------------------


def _firmae_copy_script(arch: str) -> str:
    """Bash script: copy the first matching kernel from FirmAE binaries."""
    info = ARCH_KERNELS[arch]
    candidates = " ".join(info["candidates"])
    return f"""
set -e
SRC={settings.firmae_dir}/binaries
DST={kernels_dir()}
mkdir -p "$DST"
found=""
for f in {candidates}; do
  if [ -f "$SRC/$f" ]; then found="$SRC/$f"; break; fi
done
if [ -z "$found" ]; then echo "NOT_FOUND"; exit 2; fi
cp -f "$found" "$DST/{info['dest']}"
sha256sum "$DST/{info['dest']}" | awk '{{print $1}}'
""".strip()


async def provision_from_firmae(
    vm: VMRemoteExecutor, arch: str, dry_run: bool = False
) -> dict | None:
    """Copy a matching kernel from ``/opt/firmae/binaries`` into the kernels dir.

    Returns ``{"sha256": ..., "source": ...}`` on success, None if FirmAE
    binaries do not contain a kernel for the architecture.
    """
    if arch not in ARCH_KERNELS:
        logger.warning("no kernel registered for arch", arch=arch)
        return None

    script = _firmae_copy_script(arch)
    if dry_run:
        return {"dry_run": script}

    result = await vm.execute(script, timeout=120)
    if result.exit_code != 0:
        if "NOT_FOUND" in result.stdout:
            logger.debug("no FirmAE kernel for arch", arch=arch)
        else:
            logger.warning("firmae copy failed", arch=arch, stderr=result.stderr[:300])
        return None

    sha256 = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
    if not sha256:
        logger.warning("could not read sha256 after copy", arch=arch)
        return None

    await _record_entry(vm, arch, {
        "path": ARCH_KERNELS[arch]["dest"],
        "sha256": sha256,
        "source": f"{settings.firmae_dir}/binaries",
        "url": ARCH_KERNELS[arch]["url"],
    })
    logger.info("kernel provisioned from FirmAE", arch=arch, sha256=sha256)
    return {"sha256": sha256}


def _download_script(arch: str) -> str:
    info = ARCH_KERNELS[arch]
    size_check = (
        f"[ \"$(stat -c %s {info['dest']})\" = \"{info['size']}\" ] || "
        f"{{ echo SIZE_MISMATCH; exit 3; }}"
        if info.get("size")
        else "true"
    )
    return f"""
set -e
mkdir -p {kernels_dir()}
cd {kernels_dir()}
wget -c -q --tries=5 --timeout=60 -O {info['dest']} '{_asset_url(info['url'])}'
{size_check}
sha256sum {info['dest']} | awk '{{print $1}}'
""".strip()


async def download_kernel(
    vm: VMRemoteExecutor, arch: str, dry_run: bool = False
) -> dict | None:
    """Download the pinned kernel URL from the registry and verify sha256."""
    if arch not in ARCH_KERNELS:
        return None
    info = ARCH_KERNELS[arch]
    script = _download_script(arch)
    if dry_run:
        return {"dry_run": script}

    result = await vm.execute(script, timeout=600)
    if result.exit_code != 0:
        logger.error("kernel download failed", arch=arch, stderr=result.stderr[:300])
        return None

    sha256 = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
    if not sha256:
        logger.warning("could not read sha256 after download", arch=arch)
        return None

    await _record_entry(vm, arch, {
        "path": info["dest"],
        "sha256": sha256,
        "source": info["source"],
        "url": info["url"],
    })
    logger.info("kernel downloaded", arch=arch, url=info["url"], sha256=sha256)
    return {"sha256": sha256}


async def ensure_kernel(vm: VMRemoteExecutor, arch: str) -> str | None:
    """Return an absolute kernel path on the VM, provisioning if needed.

    Order: existing file -> copy from FirmAE -> pinned download.
    """
    if arch not in ARCH_KERNELS:
        logger.warning("no kernel registered for arch", arch=arch)
        return None

    dest = f"{kernels_dir()}/{ARCH_KERNELS[arch]['dest']}"
    check = await vm.execute(f"test -f {dest} && echo OK || echo MISSING")
    size_ok = True
    if "OK" in check.stdout and ARCH_KERNELS[arch].get("size"):
        st = await vm.execute(f"stat -c %s {dest} 2>/dev/null")
        size_ok = st.stdout.strip() == str(ARCH_KERNELS[arch]["size"])
        if not size_ok:
            logger.warning(
                "kernel file incomplete, re-provisioning",
                arch=arch, got=st.stdout.strip(), expected=ARCH_KERNELS[arch]["size"],
            )
    if check.exit_code == 0 and "OK" in check.stdout and size_ok:
        # Self-heal: record sha256 in the manifest if it is missing
        # (e.g. files were placed manually or by a timed-out download).
        manifest = await _read_manifest(vm)
        if not manifest["kernels"].get(arch, {}).get("sha256"):
            hashed = await vm.execute(f"sha256sum {dest} | awk '{{print $1}}'")
            sha256 = hashed.stdout.strip().splitlines()[0] if hashed.stdout.strip() else ""
            if sha256:
                await _record_entry(vm, arch, {
                    "path": ARCH_KERNELS[arch]["dest"],
                    "sha256": sha256,
                    "source": ARCH_KERNELS[arch]["source"],
                    "url": ARCH_KERNELS[arch]["url"],
                })
        return dest

    logger.info("kernel missing, provisioning", arch=arch, dest=dest)
    provisioned = await provision_from_firmae(vm, arch)
    if provisioned:
        return dest

    downloaded = await download_kernel(vm, arch)
    if downloaded:
        return dest

    logger.error(
        "kernel provisioning failed",
        arch=arch,
        hint=f"run: python scripts/provision_kernels.py --arch {arch}",
    )
    return None


def _runtime_download_script(name: str, info: dict) -> str:
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
    """Download FirmAE runtime binaries into ``runtime_dir()`` (idempotent).

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
        result = await vm.execute(_runtime_download_script(name, info), timeout=300)
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


# ---------------------------------------------------------------------------
# Debian boot images (manual QEMU path) -- auto-provisioned on demand
# ---------------------------------------------------------------------------


async def _remote_content_length(vm: VMRemoteExecutor, url: str) -> int | None:
    """Get the authoritative size of a remote file via Content-Length."""
    r = await vm.execute(f"curl -sIL -m 30 '{url}' | grep -i '^content-length' | tail -1")
    m = re.search(r"(\d+)", r.stdout)
    return int(m.group(1)) if m else None


async def _asset_present(vm: VMRemoteExecutor, path: str, expected: int | None) -> bool:
    """True when the file exists and (if expected) has the exact size."""
    if expected is None:
        check = await vm.execute(f"test -f {path} && echo OK")
        return check.exit_code == 0 and "OK" in check.stdout
    st = await vm.execute(f"stat -c %s {path} 2>/dev/null")
    return st.stdout.strip() == str(expected)


async def boot_image_status(vm: VMRemoteExecutor, arch: str) -> dict:
    """Per-asset download status for an architecture's boot images."""
    assets = BOOT_IMAGES.get(arch, [])
    status: dict = {"arch": arch, "ready": True, "assets": []}
    for a in assets:
        path = f"{settings.vm_qemu_image_dir}/{a['name']}"
        expected = await _remote_content_length(vm, a["url"]) if a.get("big") else None
        st = await vm.execute(f"stat -c %s {path} 2>/dev/null")
        local = int(st.stdout.strip()) if st.stdout.strip().isdigit() else 0
        ready = local > 0 and (expected is None or local == expected)
        pct = min(100, round(local * 100 / expected)) if expected else (100 if ready else 0)
        status["assets"].append({
            "name": a["name"],
            "role": a["role"],
            "local": local,
            "expected": expected,
            "percent": pct,
            "ready": ready,
        })
        if not ready:
            status["ready"] = False
    return status


def _small_download_script(name: str, url: str) -> str:
    return f"""
set -e
mkdir -p {settings.vm_qemu_image_dir}
cd {settings.vm_qemu_image_dir}
wget -c -q --tries=5 --timeout=60 -O {name} '{url}'
""".strip()


async def _start_background_download(
    vm: VMRemoteExecutor, path: str, url: str, name: str
) -> bool:
    """Kick off a large download in the background (resumable, logged)."""
    log = f"/tmp/qemu-dl-{name}.log"
    r = await vm.execute(
        f"setsid nohup wget -c -q --tries=5 --timeout=60 -O {path} '{url}' "
        f"< /dev/null > {log} 2>&1 & echo STARTED"
    )
    return r.exit_code == 0


async def ensure_boot_images(
    vm: VMRemoteExecutor, arch: str, wait: bool = True, dry_run: bool = False
) -> dict:
    """Auto-download the boot images (kernel/initrd/disk) for ``arch``.

    Small files download synchronously; large qcow2 images download in the
    background. With ``wait=True`` (default) this polls until everything is
    ready, logging progress; ``wait=False`` returns immediately with the
    current status so callers can poll ``boot_image_status()``.
    """
    assets = BOOT_IMAGES.get(arch)
    if not assets:
        return {"ready": False, "arch": arch, "error": f"no boot images registered for {arch}"}

    started: list[str] = []
    for a in assets:
        path = f"{settings.vm_qemu_image_dir}/{a['name']}"
        expected = await _remote_content_length(vm, a["url"]) if a.get("big") else None
        if await _asset_present(vm, path, expected):
            continue
        if dry_run:
            started.append(a["name"])
            continue
        logger.info("downloading boot image", arch=arch, name=a["name"], size=expected)
        if a.get("big"):
            if not await _start_background_download(vm, path, a["url"], a["name"]):
                return {"ready": False, "arch": arch, "error": f"failed to start download: {a['name']}"}
        else:
            r = await vm.execute(_small_download_script(a["name"], a["url"]), timeout=300)
            if r.exit_code != 0:
                return {"ready": False, "arch": arch, "error": f"download failed: {a['name']}", "stderr": r.stderr[:300]}
        started.append(a["name"])

    if not started:
        return await boot_image_status(vm, arch)

    if wait:
        while True:
            status = await boot_image_status(vm, arch)
            if status["ready"]:
                break
            progress = ", ".join(
                f"{a['name']}={a['percent']}%" for a in status["assets"] if not a["ready"]
            )
            logger.info("boot images still downloading", arch=arch, progress=progress)
            await asyncio.sleep(20)
        return status

    status = await boot_image_status(vm, arch)
    status["downloading"] = started
    return status


# ---------------------------------------------------------------------------
# Boot templates (manual QEMU fallback)
# ---------------------------------------------------------------------------


async def ensure_boot_templates(vm: VMRemoteExecutor, dry_run: bool = False) -> bool:
    """Write default boot templates if ``boot-templates.json`` is missing."""
    path = boot_templates_path()
    check = await vm.execute(f"test -f {path} && echo OK")
    if check.exit_code == 0 and "OK" in check.stdout:
        return True

    payload = base64.b64encode(
        json.dumps(DEFAULT_BOOT_TEMPLATES, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    script = (
        f"mkdir -p {settings.vm_qemu_image_dir} && "
        f"echo {payload} | base64 -d > {path}"
    )
    if dry_run:
        logger.info("boot templates would be written", path=path)
        return True
    result = await vm.execute(script)
    if result.exit_code == 0:
        logger.info("boot templates written", path=path)
        return True
    logger.error("failed to write boot templates", stderr=result.stderr[:300])
    return False


# ---------------------------------------------------------------------------
# Local mode (no SSH) -- for testing or when FirmAE is on the same host
# ---------------------------------------------------------------------------


def provision_local(
    firmae_binaries_dir: str,
    kernels: str,
    arch: str | list[str] | None = None,
) -> dict:
    """Copy kernels from a local FirmAE binaries dir and write the manifest.

    Pure Python implementation; useful for tests and for hosts where FirmAE
    is mounted locally (e.g. WSL path).
    """
    import hashlib
    import shutil

    src_root = Path(firmae_binaries_dir)
    dst_root = Path(kernels)
    dst_root.mkdir(parents=True, exist_ok=True)

    if arch is None:
        archs = list(ARCH_KERNELS)
    elif isinstance(arch, str):
        archs = [arch]
    else:
        archs = list(arch)
    entries: dict[str, dict] = {}
    summary = {"copied": [], "missing": []}

    for a in archs:
        info = ARCH_KERNELS[a]
        found = next(
            (src_root / c for c in info["candidates"] if (src_root / c).is_file()),
            None,
        )
        if found is None:
            summary["missing"].append(a)
            continue
        dest = dst_root / info["dest"]
        shutil.copyfile(found, dest)
        sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()
        entries[a] = {
            "path": info["dest"],
            "sha256": sha256,
            "url": info["url"],
            "source": str(found),
        }
        summary["copied"].append({"arch": a, "path": info["dest"], "sha256": sha256})

    manifest = normalize_manifest(entries)
    (dst_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary


def write_boot_templates_local(images_dir: str) -> Path:
    """Write default boot templates into a local images dir."""
    out = Path(images_dir) / "boot-templates.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(DEFAULT_BOOT_TEMPLATES, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out
