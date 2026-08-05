"""Firmware acquisition, extraction, and normalization — all on VM.

Supports:
- Multi-source search (OpenWrt, TP-Link, GitHub)
- Direct URL download (wget on VM)
- Extract + normalize nested firmware to standardized rootfs/ layout
- Local SQLite index for caching downloaded firmware metadata

Usage:
    from iot_agent.tools.firmware_acquire import FirmwareAcquirer
    from iot_agent.tools.remote_vm import VMRemoteExecutor

    async with VMRemoteExecutor() as vm:
        acquirer = FirmwareAcquirer(vm)

        # Search for firmware across sources
        results = await acquirer.search_sources("dlink", "dir-815")

        # Search → download → extract in one step
        rootfs = await acquirer.search_and_download("dlink", "dir-815")

        # Direct URL download + extract
        rootfs = await acquirer.extract(
            "https://download1.dlink.com/...",
            brand="dlink", model="dir-815", version="v1"
        )

        # Check local cache
        cached = acquirer.list_cached(vendor="dlink")
"""

from __future__ import annotations

import structlog
from iot_agent.tools.firmware_index import FirmwareIndex
from iot_agent.tools.firmware_sources import (
    FirmwareResult,
    FirmwareSource,
    normalize_vendor,
    search_all,
)
from iot_agent.tools.remote_vm import VMRemoteExecutor, RemoteResult

logger = structlog.get_logger(__name__)


class FirmwareAcquirer:
    """
    Downloads and extracts IoT firmware on the analysis VM.

    Supports:
    - Direct URL download (wget on VM)
    - Extract + normalize nested firmware to standardized rootfs/ layout
    - Multi-source firmware search (OpenWrt, TP-Link, GitHub)
    - Local SQLite index for dedup and caching
    """

    def __init__(
        self,
        vm: VMRemoteExecutor,
        db_path: str = "./data/firmware_index.db",
    ) -> None:
        self.vm = vm
        self.index = FirmwareIndex(db_path)

    # -----------------------------------------------------------------------
    # Search
    # -----------------------------------------------------------------------

    async def search_sources(
        self,
        vendor: str,
        model: str,
        limit: int = 20,
    ) -> list[FirmwareResult]:
        """Search all firmware sources for matching vendor/model.

        Returns a list of FirmwareResult from OpenWrt, TP-Link, GitHub.
        Partial failures are logged and skipped.
        """
        results = await search_all(vendor, model, limit=limit)
        logger.info("firmware search complete",
                     vendor=vendor, model=model, found=len(results))
        return results

    async def search_and_download(
        self,
        vendor: str,
        model: str,
        version: str = "",
        brand: str = "",
    ) -> str | None:
        """Search sources, pick best match, download, extract. Returns rootfs path.

        Selection priority: version match > source priority (openwrt > tp-link > github) > file size.
        """
        results = await self.search_sources(vendor, model)
        if not results:
            logger.warning("no firmware found", vendor=vendor, model=model)
            return None

        # Filter by version if specified
        if version:
            versioned = [r for r in results if version.lower() in r.version.lower()]
            if versioned:
                results = versioned

        # Sort: prefer openwrt (most reliable), then by having a version
        source_priority = {"openwrt": 0, "tp-link": 1, "github": 2}
        results.sort(key=lambda r: (source_priority.get(r.source, 9), not bool(r.version)))

        best = results[0]
        logger.info("selected firmware",
                     vendor=best.vendor, model=best.model,
                     version=best.version, source=best.source, url=best.url)

        # Check local index first
        cached = self.index.find_by_url(best.url)
        if cached and cached.get("rootfs_path"):
            logger.info("firmware already cached", rootfs=cached["rootfs_path"])
            return cached["rootfs_path"]

        # Download
        fw_path = await self.from_url(best.url)
        if not fw_path:
            return None

        # Extract
        effective_brand = brand or best.vendor or vendor
        rootfs = await self.extract(
            fw_path,
            brand=effective_brand,
            model=best.model,
            version=best.version or version,
        )
        return rootfs

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
        Extract and normalize a firmware image to a standardized rootfs/.

        Handles nested formats (zip→.web→.bin→squashfs→cpio...) automatically.
        Returns the path to the rootfs/ directory on VM, or None on failure.
        """
        if not self.vm.configured:
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

        # Update index
        if firmware_path.startswith("http"):
            self.index.mark_extracted(firmware_path, rootfs_dir)
        else:
            self.index.record(
                vendor=brand, model=model, version=version,
                url=firmware_path, rootfs_path=rootfs_dir,
            )

        return rootfs_dir

    # -----------------------------------------------------------------------
    # Cache / index
    # -----------------------------------------------------------------------

    def list_cached(
        self,
        vendor: str = "",
        model: str = "",
        version: str = "",
    ) -> list[dict]:
        """Query local firmware index."""
        return self.index.search(vendor=vendor, model=model, version=version)

    def cache_stats(self) -> dict:
        """Return cache statistics."""
        return self.index.stats()

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
