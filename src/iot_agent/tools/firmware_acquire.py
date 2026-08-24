"""Firmware acquisition, extraction, and normalization — all on VM.

Firmware URLs are found by the agent itself (WebSearch / vendor support
pages); this module only does the deterministic part:
- Direct URL download (wget on VM)
- Extract + normalize nested firmware to standardized rootfs/ layout
- Local SQLite index for caching downloaded firmware metadata

Usage:
    from iot_agent.tools.firmware_acquire import FirmwareAcquirer
    from iot_agent.tools.remote_vm import VMRemoteExecutor

    async with VMRemoteExecutor() as vm:
        acquirer = FirmwareAcquirer(vm)

        # Direct URL download + extract
        rootfs = await acquirer.extract(
            "https://download1.dlink.com/...",
            brand="dlink", model="dir-815", version="v1"
        )
"""

from __future__ import annotations

import structlog
from iot_agent.tools.firmware_index import FirmwareIndex
from iot_agent.tools.remote_vm import VMRemoteExecutor, RemoteResult

logger = structlog.get_logger(__name__)


class FirmwareAcquirer:
    """
    Downloads and extracts IoT firmware on the analysis VM.

    Supports:
    - Direct URL download (wget on VM)
    - Extract + normalize nested firmware to standardized rootfs/ layout
    - Local SQLite index for dedup and caching
    """

    def __init__(
        self,
        vm: VMRemoteExecutor,
        db_path: str = "",
    ) -> None:
        self.vm = vm
        self.index = FirmwareIndex(db_path)

    # -----------------------------------------------------------------------
    # Download
    # -----------------------------------------------------------------------

    async def from_url(self, url: str, output_dir: str = "") -> str | None:
        """Download firmware from a direct URL. Returns path on VM or None."""
        if not self.vm.configured:
            logger.warning("VM not configured, cannot download firmware")
            return None

        # Check index for existing download
        cached = self.index.find_by_url(url)
        if cached and cached.get("local_path"):
            # Verify file still exists on VM
            check = await self.vm.execute(f"test -f {cached['local_path']} && echo exists")
            if "exists" in check.stdout:
                logger.info("firmware already downloaded", path=cached["local_path"])
                return cached["local_path"]

        out = output_dir or self.vm._firmware_dir
        filename = url.rsplit("/", 1)[-1].split("?")[0] or "firmware.bin"
        remote_path = f"{out}/{filename}"

        logger.info("downloading firmware", url=url, dest=remote_path)
        result: RemoteResult = await self.vm.execute(
            f"mkdir -p {out} && wget -q --show-progress -O {remote_path} '{url}' 2>&1",
            timeout=600,
        )
        if result.success:
            logger.info("firmware downloaded", path=remote_path)
            # Record in index
            self.index.record(url=url, local_path=remote_path, source="direct")
            return remote_path
        logger.error("firmware download failed", url=url, dest=remote_path, stderr=result.stderr[:500])
        return None

    # -----------------------------------------------------------------------
    # Extract
    # -----------------------------------------------------------------------

    async def extract(
        self,
        firmware_path: str,
        brand: str = "unknown",
        model: str = "unknown",
        version: str = "unknown",
    ) -> str | None:
        """
        Download (if URL) and extract a firmware image to a standardized rootfs/.

        Handles nested formats (zip→.web→.bin→squashfs→cpio...) automatically.
        Returns the path to the rootfs/ directory on VM, or None on failure.
        """
        if not self.vm.configured:
            return None

        if firmware_path.startswith("http"):
            firmware_path = await self.from_url(firmware_path)
            if not firmware_path:
                return None

        base = f"/data/extracted/{brand}/{model}_{version}"
        raw_dir = f"{base}/_raw"
        rootfs_dir = f"{base}/rootfs"

        logger.info("extracting firmware", path=firmware_path, dest=base)

        # Step 1: binwalk recursive extraction
        await self.vm.execute(f"mkdir -p {raw_dir}")
        result = await self.vm.execute(
            f"cd {raw_dir} && binwalk -Me {firmware_path} 2>&1",
            timeout=600,
        )

        # Step 2: find the actual root filesystem
        find_rootfs = await self.vm.execute(
            f"find {raw_dir} -type d "
            f"\\( -name 'bin' -o -name 'sbin' -o -name 'etc' -o -name 'usr' \\) "
            f"-print 2>/dev/null | sort | head -20"
        )

        # Heuristic: look for directories that look like a Linux rootfs
        markers = ["bin/sh", "etc/passwd", "etc/init.d", "usr/sbin", "lib/libc.so"]
        root_candidates = []
        for line in find_rootfs.stdout.splitlines():
            line = line.strip()
            if not line or line.endswith("/bin") or line.endswith("/sbin"):
                parent = line.rstrip("bin").rstrip("sbin").rstrip("/")
                root_candidates.append(parent)
            elif line.endswith("/etc"):
                parent = line.rstrip("etc").rstrip("/")
                root_candidates.append(parent)
            elif line.endswith("/usr"):
                parent = line.rstrip("usr").rstrip("/")
                root_candidates.append(parent)

        # Dedup and pick the best candidate
        from collections import Counter
        best = None
        for path, _ in Counter(root_candidates).most_common(10):
            for marker in markers:
                r = await self.vm.execute(f"test -f {path}/{marker} && echo found")
                if "found" in r.stdout:
                    best = path
                    break
            if best:
                break

        if not best:
            # Fallback: pick the deepest directory with /etc
            result = await self.vm.execute(
                f"find {raw_dir} -type f -name 'passwd' -path '*/etc/passwd' 2>/dev/null | "
                f"head -1 | sed 's|/etc/passwd||'"
            )
            if result.success and result.stdout.strip():
                best = result.stdout.strip()

        if not best:
            logger.error("could not locate rootfs in extracted firmware", raw_dir=raw_dir)
            return None

        # Step 3: copy to standardized rootfs/
        await self.vm.execute(f"rm -rf {rootfs_dir}")
        result = await self.vm.execute(
            f"cp -a {best}/. {rootfs_dir}/ 2>&1",
            timeout=120,
        )

        if not result.success:
            logger.error("failed to copy rootfs", stderr=result.stderr)
            return None

        logger.info("firmware extracted", rootfs=rootfs_dir, source=best)

        # Update index (record = upsert by URL; covers both URL downloads
        # recorded by from_url and direct local-path inputs)
        self.index.record(
            vendor=brand, model=model, version=version,
            url=firmware_path, rootfs_path=rootfs_dir,
        )
        self.index.mark_extracted(firmware_path, rootfs_dir)

        return rootfs_dir

    # -----------------------------------------------------------------------
    # Cache / index
    # -----------------------------------------------------------------------

    async def cache_status(self) -> dict:
        """Return status of the local firmware cache on the VM."""
        result = await self.vm.execute(
            f"echo '=== Firmware Cache ===' && "
            f"ls -lh {self.vm._firmware_dir}/ 2>/dev/null || echo 'empty'"
        )
        return {
            "available": self.vm.configured,
            "cache_dir": str(self.vm._firmware_dir),
            "contents": result.stdout.strip(),
            "index": self.index.stats(),
        }
