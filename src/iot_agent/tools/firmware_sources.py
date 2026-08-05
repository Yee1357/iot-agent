"""Multi-source firmware discovery for IoT devices.

Provides a unified search interface across multiple firmware sources:
- OpenWrt: official releases directory
- TP-Link: structured support page URLs
- GitHub: firmware mirror repositories

Usage:
    from iot_agent.tools.firmware_sources import search_all, OpenWrtSource

    async with OpenWrtSource() as src:
        results = await src.search("dlink", "dir-815")

    # Or search all sources at once:
    results = await search_all("dlink", "dir-815")
"""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------


@dataclass
class FirmwareResult:
    """A firmware download candidate from any source."""

    vendor: str          # normalized lowercase vendor name
    model: str           # device model
    version: str         # firmware version (empty if unknown)
    url: str             # direct download URL
    source: str          # source identifier: "openwrt" / "tp-link" / "github"
    filename: str        # filename from URL
    size: int | None = None       # file size in bytes, None if unknown
    extra: dict = field(default_factory=dict)  # arch, build, checksum, etc.


# ---------------------------------------------------------------------------
# Vendor normalization
# ---------------------------------------------------------------------------

_VENDOR_ALIASES: dict[str, str] = {
    "dlink": "d-link",
    "d_link": "d-link",
    "tplink": "tp-link",
    "tp_link": "tp-link",
    "tp-link technologies": "tp-link",
    "netgear": "netgear",
    "cisco": "cisco",
    "linksys": "linksys",
    "asus": "asus",
    "tenda": "tenda",
    "xiaomi": "xiaomi",
    "huawei": "huawei",
    "zte": "zte",
    "mercury": "mercury",
    "fast": "fast",
}


def normalize_vendor(vendor: str) -> str:
    """Normalize vendor name to canonical lowercase form."""
    v = vendor.strip().lower()
    return _VENDOR_ALIASES.get(v, v)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class FirmwareSource(ABC):
    """Base class for firmware search sources."""

    name: str = "base"

    async def connect(self) -> None:
        """Create HTTP client (override if needed)."""

    async def close(self) -> None:
        """Close HTTP client (override if needed)."""

    async def __aenter__(self) -> "FirmwareSource":
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    @abstractmethod
    async def search(
        self, vendor: str, model: str, limit: int = 20
    ) -> list[FirmwareResult]:
        """Search for firmware matching vendor + model."""


# ---------------------------------------------------------------------------
# OpenWrt source
# ---------------------------------------------------------------------------

_OPENWRT_RELEASES_URL = "https://downloads.openwrt.org/releases/"
# Match directory entries like "23.05.5/" or "24.10.0/"
_OPENWRT_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)/$")


class OpenWrtSource(FirmwareSource):
    """Search OpenWrt official firmware releases.

    Strategy: fetch version list from releases page, then for each version
    fetch the targets page and look for matching firmware files.
    """

    name = "openwrt"

    def __init__(self, base_url: str = _OPENWRT_RELEASES_URL) -> None:
        self._base_url = base_url
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={"User-Agent": "iot-vuln-agent/0.1"},
                timeout=30,
                follow_redirects=True,
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search(
        self, vendor: str, model: str, limit: int = 20
    ) -> list[FirmwareResult]:
        if self._client is None:
            await self.connect()
        assert self._client is not None

        vendor_n = normalize_vendor(vendor)
        model_lower = model.strip().lower()
        results: list[FirmwareResult] = []

        try:
            versions = await self._list_versions()
        except Exception as e:
            logger.warning("openwrt: failed to list versions", error=str(e))
            return []

        # Search latest 5 versions to balance speed vs coverage
        for ver in versions[:5]:
            try:
                fw_list = await self._search_version(ver, vendor_n, model_lower)
                results.extend(fw_list)
                if len(results) >= limit:
                    break
            except Exception as e:
                logger.warning("openwrt: search version failed",
                               version=ver, error=str(e))
                continue

        return results[:limit]

    async def _list_versions(self) -> list[str]:
        """Get sorted list of release versions (newest first)."""
        assert self._client is not None
        resp = await self._client.get(self._base_url)
        resp.raise_for_status()

        versions: list[str] = []
        for m in _OPENWRT_VERSION_RE.finditer(resp.text):
            versions.append(m.group(1))

        # Sort by semver, newest first
        def _ver_key(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split("."))

        versions.sort(key=_ver_key, reverse=True)
        return versions

    async def _search_version(
        self, version: str, vendor: str, model: str
    ) -> list[FirmwareResult]:
        """Search a specific OpenWrt version for matching firmware.

        OpenWrt organizes firmware by target/arch, not by vendor/model.
        We scan the generic and device-specific directories.
        """
        assert self._client is not None
        results: list[FirmwareResult] = []

        # OpenWrt puts device firmware under targets/{target}/
        # We need to search the full targets listing
        targets_url = f"{self._base_url}{version}/targets/"
        try:
            resp = await self._client.get(targets_url)
            resp.raise_for_status()
        except Exception:
            return []

        # Parse target directories (e.g. "ath79/generic/")
        target_dirs = re.findall(r'href="([^"]+/)"', resp.text)
        # Skip parent dir link
        target_dirs = [d for d in target_dirs if not d.startswith("..")]

        for target_dir in target_dirs[:20]:  # limit to avoid too many requests
            try:
                target_url = f"{targets_url}{target_dir}"
                resp = await self._client.get(target_url)
                resp.raise_for_status()
            except Exception:
                continue

            # Look for firmware files matching vendor/model
            # OpenWrt naming: {vendor}_{model}-{version}-{type}.{ext}
            for line in resp.text.splitlines():
                # Extract href values
                href_match = re.search(r'href="([^"]+)"', line)
                if not href_match:
                    continue
                href = href_match.group(1)

                # Skip directories and non-firmware files
                if href.endswith("/") or href.startswith("?") or href.startswith(".."):
                    continue

                href_lower = href.lower()
                # Match vendor/model in filename
                if (vendor in href_lower or _VENDOR_ALIASES.get(vendor, "") in href_lower):
                    if model in href_lower:
                        file_url = urljoin(target_url, href)
                        results.append(FirmwareResult(
                            vendor=vendor,
                            model=model,
                            version=version,
                            url=file_url,
                            source="openwrt",
                            filename=href,
                            extra={"target": target_dir.rstrip("/")},
                        ))

        return results


# ---------------------------------------------------------------------------
# TP-Link source
# ---------------------------------------------------------------------------

_TPLINK_DOWNLOAD_BASE = "https://www.tp-link.com/support/download/"


class TPLinkSource(FirmwareSource):
    """Search TP-Link official support/download pages.

    TP-Link has structured download URLs per model.
    Strategy: construct download page URL, parse firmware links.
    """

    name = "tp-link"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=30,
                follow_redirects=True,
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search(
        self, vendor: str, model: str, limit: int = 20
    ) -> list[FirmwareResult]:
        if self._client is None:
            await self.connect()
        assert self._client is not None

        vendor_n = normalize_vendor(vendor)
        if vendor_n not in ("tp-link", ""):
            return []

        model_clean = model.strip().lower().replace(" ", "-")
        results: list[FirmwareResult] = []

        # Try the structured download page
        download_url = f"{_TPLINK_DOWNLOAD_BASE}{model_clean}/"
        try:
            resp = await self._client.get(download_url)
            if resp.status_code != 200:
                logger.debug("tp-link: model page not found",
                             model=model_clean, status=resp.status_code)
                return []
        except Exception as e:
            logger.warning("tp-link: request failed", model=model_clean, error=str(e))
            return []

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(resp.text, "lxml")

        # Look for firmware download links
        # TP-Link pages have sections with "Firmware" heading
        for link in soup.find_all("a", href=True):
            href = link["href"]
            href_lower = href.lower()

            # Must be a firmware file
            if not any(ext in href_lower for ext in (".bin", ".zip", ".img", ".rar")):
                continue

            # Must be a direct download link
            if "download" not in href_lower and not href_lower.startswith("http"):
                continue

            # Extract version from link text or filename
            link_text = link.get_text(strip=True)
            version = _extract_tplink_version(link_text, href)

            full_url = href if href.startswith("http") else urljoin(download_url, href)
            results.append(FirmwareResult(
                vendor="tp-link",
                model=model_clean,
                version=version,
                url=full_url,
                source="tp-link",
                filename=href.split("/")[-1],
                extra={"page": download_url},
            ))

            if len(results) >= limit:
                break

        return results


def _extract_tplink_version(text: str, href: str) -> str:
    """Try to extract firmware version from link text or URL."""
    # Common patterns: "V2", "v1.0", "1.0.2 Build 20240101"
    m = re.search(r"[vV](\d+(?:\.\d+)*)", text)
    if m:
        return m.group(1)
    m = re.search(r"[vV](\d+(?:\.\d+)*)", href)
    if m:
        return m.group(1)
    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", text)
    if m:
        return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# GitHub source
# ---------------------------------------------------------------------------

_GITHUB_API = "https://api.github.com"


class GitHubSource(FirmwareSource):
    """Search GitHub for firmware mirror repositories.

    Uses GitHub Search API to find repos that host firmware images,
    then searches releases/contents for matching files.
    """

    name = "github"

    def __init__(self, token: str | None = None) -> None:
        self._token = token
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        if self._client is None:
            headers: dict[str, str] = {
                "User-Agent": "iot-vuln-agent/0.1",
                "Accept": "application/vnd.github.v3+json",
            }
            if self._token:
                headers["Authorization"] = f"token {self._token}"
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=30,
                follow_redirects=True,
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search(
        self, vendor: str, model: str, limit: int = 20
    ) -> list[FirmwareResult]:
        if self._client is None:
            await self.connect()
        assert self._client is not None

        vendor_n = normalize_vendor(vendor)
        query = f"{vendor_n} {model} firmware"
        results: list[FirmwareResult] = []

        try:
            resp = await self._client.get(
                f"{_GITHUB_API}/search/repositories",
                params={"q": query, "sort": "stars", "per_page": 10},
            )
            if resp.status_code == 403:
                logger.warning("github: rate limited (set GITHUB_TOKEN for higher limit)")
                return []
            resp.raise_for_status()
        except Exception as e:
            logger.warning("github: search failed", error=str(e))
            return []

        repos = resp.json().get("items", [])

        # Search each repo's releases for firmware files
        tasks = [
            self._search_repo(repo, vendor_n, model) for repo in repos[:5]
        ]
        repo_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in repo_results:
            if isinstance(r, list):
                results.extend(r)

        return results[:limit]

    async def _search_repo(
        self, repo: dict, vendor: str, model: str
    ) -> list[FirmwareResult]:
        """Search a single repo's releases for matching firmware."""
        assert self._client is not None
        full_name = repo["full_name"]
        results: list[FirmwareResult] = []

        try:
            resp = await self._client.get(
                f"{_GITHUB_API}/repos/{full_name}/releases",
                params={"per_page": 10},
            )
            if resp.status_code != 200:
                return []
            resp.raise_for_status()
        except Exception:
            return []

        for release in resp.json():
            tag = release.get("tag_name", "")
            for asset in release.get("assets", []):
                name = asset["name"].lower()
                if model in name and (vendor in name or not vendor):
                    results.append(FirmwareResult(
                        vendor=vendor,
                        model=model,
                        version=tag.lstrip("vV"),
                        url=asset["browser_download_url"],
                        source="github",
                        filename=asset["name"],
                        size=asset.get("size"),
                        extra={
                            "repo": full_name,
                            "release": tag,
                            "stars": repo.get("stargazers_count", 0),
                        },
                    ))

        return results


# ---------------------------------------------------------------------------
# Aggregate search
# ---------------------------------------------------------------------------

ALL_SOURCES: list[type[FirmwareSource]] = [OpenWrtSource, TPLinkSource, GitHubSource]


async def search_all(
    vendor: str,
    model: str,
    limit: int = 20,
    sources: list[type[FirmwareSource]] | None = None,
) -> list[FirmwareResult]:
    """Search all enabled sources concurrently.

    Returns merged results sorted by source priority (openwrt > tp-link > github).
    Partial failures are logged and skipped.
    """
    src_classes = sources or ALL_SOURCES
    src_instances = [cls() for cls in src_classes]

    # Connect all
    for src in src_instances:
        await src.connect()

    try:
        tasks = [src.search(vendor, model, limit) for src in src_instances]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        merged: list[FirmwareResult] = []
        for src, result in zip(src_instances, all_results):
            if isinstance(result, list):
                merged.extend(result)
            elif isinstance(result, Exception):
                logger.warning("source search failed",
                               source=src.name, error=str(result))

        return merged[:limit]
    finally:
        for src in src_instances:
            await src.close()
