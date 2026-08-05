"""Local firmware index backed by SQLite.

Tracks downloaded firmware: vendor, model, version, URL, local path, hash,
extraction status. Prevents duplicate downloads and enables fast lookup.

Usage:
    from iot_agent.tools.firmware_index import FirmwareIndex

    idx = FirmwareIndex()
    idx.record(vendor="dlink", model="dir-815", version="v1",
               url="http://...", local_path="/data/firmware/dir815.bin",
               file_hash="abc123")
    cached = idx.find_by_url("http://...")
    all_fw = idx.list_all(vendor="dlink")
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class FirmwareIndex:
    """SQLite-backed firmware metadata index."""

    def __init__(self, db_path: str = "./data/firmware_index.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS firmware (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor      TEXT NOT NULL DEFAULT '',
                model       TEXT NOT NULL DEFAULT '',
                version     TEXT NOT NULL DEFAULT '',
                url         TEXT UNIQUE NOT NULL,
                local_path  TEXT NOT NULL DEFAULT '',
                file_hash   TEXT NOT NULL DEFAULT '',
                file_size   INTEGER,
                source      TEXT NOT NULL DEFAULT '',
                extracted   INTEGER DEFAULT 0,
                rootfs_path TEXT NOT NULL DEFAULT '',
                extra       TEXT NOT NULL DEFAULT '{}',
                created_at  REAL NOT NULL,
                updated_at  REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_fw_vendor_model
                ON firmware(vendor, model);
            CREATE INDEX IF NOT EXISTS idx_fw_hash
                ON firmware(file_hash);
        """)
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- write ---------------------------------------------------------------

    def record(
        self,
        *,
        vendor: str = "",
        model: str = "",
        version: str = "",
        url: str,
        local_path: str = "",
        file_hash: str = "",
        file_size: int | None = None,
        source: str = "",
        rootfs_path: str = "",
        extra: dict | None = None,
    ) -> int:
        """Insert or update a firmware record. Returns row id."""
        import json

        conn = self._get_conn()
        now = time.time()

        # Try update first (match by URL)
        existing = conn.execute(
            "SELECT id FROM firmware WHERE url = ?", (url,)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE firmware SET
                    vendor = COALESCE(NULLIF(?, ''), vendor),
                    model = COALESCE(NULLIF(?, ''), model),
                    version = COALESCE(NULLIF(?, ''), version),
                    local_path = COALESCE(NULLIF(?, ''), local_path),
                    file_hash = COALESCE(NULLIF(?, ''), file_hash),
                    file_size = COALESCE(?, file_size),
                    source = COALESCE(NULLIF(?, ''), source),
                    rootfs_path = COALESCE(NULLIF(?, ''), rootfs_path),
                    extra = CASE WHEN ? = '{}' THEN extra ELSE ? END,
                    updated_at = ?
                WHERE id = ?
            """, (
                vendor, model, version, local_path, file_hash,
                file_size, source, rootfs_path,
                json.dumps(extra or {}), json.dumps(extra or {}),
                now, existing["id"],
            ))
            conn.commit()
            return existing["id"]

        # Insert new
        cur = conn.execute("""
            INSERT INTO firmware
                (vendor, model, version, url, local_path, file_hash,
                 file_size, source, rootfs_path, extra, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vendor, model, version, url, local_path, file_hash,
            file_size, source, rootfs_path,
            json.dumps(extra or {}),
            now, now,
        ))
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def mark_extracted(self, url: str, rootfs_path: str) -> None:
        """Mark a firmware record as extracted."""
        conn = self._get_conn()
        conn.execute("""
            UPDATE firmware SET extracted = 1, rootfs_path = ?, updated_at = ?
            WHERE url = ?
        """, (rootfs_path, time.time(), url))
        conn.commit()

    # -- read ----------------------------------------------------------------

    def find_by_url(self, url: str) -> dict | None:
        """Find a firmware record by URL."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM firmware WHERE url = ?", (url,)
        ).fetchone()
        return dict(row) if row else None

    def find_by_hash(self, file_hash: str) -> dict | None:
        """Find a firmware record by file hash."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM firmware WHERE file_hash = ?", (file_hash,)
        ).fetchone()
        return dict(row) if row else None

    def search(
        self,
        vendor: str = "",
        model: str = "",
        version: str = "",
        limit: int = 100,
    ) -> list[dict]:
        """Search firmware by vendor/model/version."""
        conn = self._get_conn()
        conditions: list[str] = []
        params: list[str] = []

        if vendor:
            conditions.append("LOWER(vendor) = LOWER(?)")
            params.append(vendor)
        if model:
            conditions.append("LOWER(model) LIKE LOWER(?)")
            params.append(f"%{model}%")
        if version:
            conditions.append("LOWER(version) LIKE LOWER(?)")
            params.append(f"%{version}%")

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM firmware WHERE {where} ORDER BY updated_at DESC LIMIT ?"
        params.append(str(limit))

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def list_all(self, limit: int = 100) -> list[dict]:
        """List all cached firmware, newest first."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM firmware ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """Aggregate statistics about cached firmware."""
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM firmware").fetchone()[0]
        extracted = conn.execute(
            "SELECT COUNT(*) FROM firmware WHERE extracted = 1"
        ).fetchone()[0]
        by_vendor = {}
        for row in conn.execute(
            "SELECT vendor, COUNT(*) as cnt FROM firmware "
            "WHERE vendor != '' GROUP BY vendor ORDER BY cnt DESC"
        ).fetchall():
            by_vendor[row["vendor"]] = row["cnt"]
        by_source = {}
        for row in conn.execute(
            "SELECT source, COUNT(*) as cnt FROM firmware "
            "WHERE source != '' GROUP BY source ORDER BY cnt DESC"
        ).fetchall():
            by_source[row["source"]] = row["cnt"]

        return {
            "total": total,
            "extracted": extracted,
            "by_vendor": by_vendor,
            "by_source": by_source,
        }
