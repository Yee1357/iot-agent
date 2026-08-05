"""Persistent storage for vulnerability analysis tasks and findings.

SQLite-backed, supports JSON export. Tracks analysis progress across
sessions so work can be resumed after interruption.

Usage:
    from iot_agent.tools.analysis_store import AnalysisStore
    from iot_agent.tools.ida_mcp import VulnerabilityFinding

    store = AnalysisStore()

    # Create a task
    task_id = store.create_task(
        firmware_id="http://example.com/fw.bin",
        vendor="dlink", model="dir-815", version="v1",
        rootfs_path="/data/extracted/dlink/dir-815_v1/rootfs",
    )

    # Record findings
    finding = VulnerabilityFinding(title="...", severity="HIGH", ...)
    store.add_finding(task_id, finding, verdict="confirmed")

    # Track progress
    store.mark_level(task_id, 2)  # completed Level 2
    store.mark_completed(task_id)

    # Export
    store.export_task_json(task_id, "./reports/dir-815.json")
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import structlog

from iot_agent.tools.ida_mcp import VulnerabilityFinding

logger = structlog.get_logger(__name__)


class AnalysisStore:
    """SQLite-backed analysis task and finding storage."""

    def __init__(self, db_path: str = "./data/analysis.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS analysis_tasks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                firmware_id     TEXT NOT NULL,
                vendor          TEXT NOT NULL DEFAULT '',
                model           TEXT NOT NULL DEFAULT '',
                version         TEXT NOT NULL DEFAULT '',
                rootfs_path     TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'pending',
                current_level   INTEGER NOT NULL DEFAULT 0,
                total_findings  INTEGER NOT NULL DEFAULT 0,
                confirmed       INTEGER NOT NULL DEFAULT 0,
                disproved       INTEGER NOT NULL DEFAULT 0,
                notes           TEXT NOT NULL DEFAULT '',
                created_at      REAL NOT NULL,
                updated_at      REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id         INTEGER NOT NULL REFERENCES analysis_tasks(id),
                title           TEXT NOT NULL,
                severity        TEXT NOT NULL DEFAULT '',
                cwe_id          TEXT NOT NULL DEFAULT '',
                cve_id          TEXT NOT NULL DEFAULT '',
                binary_name     TEXT NOT NULL DEFAULT '',
                func_name       TEXT NOT NULL DEFAULT '',
                address         TEXT NOT NULL DEFAULT '',
                source_sink     TEXT NOT NULL DEFAULT '',
                description     TEXT NOT NULL DEFAULT '',
                code_context    TEXT NOT NULL DEFAULT '',
                exploit_vector  TEXT NOT NULL DEFAULT '',
                confidence      REAL NOT NULL DEFAULT 0.0,
                verdict         TEXT NOT NULL DEFAULT 'pending',
                notes           TEXT NOT NULL DEFAULT '',
                created_at      REAL NOT NULL,
                updated_at      REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_task_status
                ON analysis_tasks(status);
            CREATE INDEX IF NOT EXISTS idx_task_vendor
                ON analysis_tasks(vendor, model);
            CREATE INDEX IF NOT EXISTS idx_finding_task
                ON findings(task_id);
            CREATE INDEX IF NOT EXISTS idx_finding_verdict
                ON findings(verdict);
        """)
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -------------------------------------------------------------------
    # Task management
    # -------------------------------------------------------------------

    def create_task(
        self,
        firmware_id: str,
        vendor: str = "",
        model: str = "",
        version: str = "",
        rootfs_path: str = "",
        notes: str = "",
    ) -> int:
        """Create a new analysis task. Returns task id."""
        conn = self._get_conn()
        now = time.time()
        cur = conn.execute("""
            INSERT INTO analysis_tasks
                (firmware_id, vendor, model, version, rootfs_path,
                 status, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)
        """, (firmware_id, vendor, model, version, rootfs_path, notes, now, now))
        conn.commit()
        task_id = cur.lastrowid
        logger.info("analysis task created",
                     task_id=task_id, vendor=vendor, model=model)
        return task_id

    def update_task(self, task_id: int, **fields: object) -> None:
        """Update arbitrary fields on a task."""
        if not fields:
            return
        conn = self._get_conn()
        fields["updated_at"] = time.time()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [task_id]
        conn.execute(
            f"UPDATE analysis_tasks SET {set_clause} WHERE id = ?",
            values,
        )
        conn.commit()

    def get_task(self, task_id: int) -> dict | None:
        """Get a single task by id."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM analysis_tasks WHERE id = ?", (task_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_tasks(
        self,
        status: str | None = None,
        vendor: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """List tasks with optional filters."""
        conn = self._get_conn()
        conditions: list[str] = []
        params: list[object] = []

        if status:
            conditions.append("status = ?")
            params.append(status)
        if vendor:
            conditions.append("LOWER(vendor) = LOWER(?)")
            params.append(vendor)

        where = " AND ".join(conditions) if conditions else "1=1"
        query = (
            f"SELECT * FROM analysis_tasks WHERE {where} "
            f"ORDER BY updated_at DESC LIMIT ?"
        )
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------------
    # Finding management
    # -------------------------------------------------------------------

    def add_finding(
        self,
        task_id: int,
        finding: VulnerabilityFinding,
        verdict: str = "pending",
        notes: str = "",
    ) -> int:
        """Record a VulnerabilityFinding. Returns finding id."""
        conn = self._get_conn()
        now = time.time()
        cur = conn.execute("""
            INSERT INTO findings
                (task_id, title, severity, cwe_id, cve_id,
                 binary_name, func_name, address, source_sink,
                 description, code_context, exploit_vector,
                 confidence, verdict, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            task_id,
            finding.title,
            finding.severity,
            finding.cwe_id,
            finding.cve_id or "",
            finding.vulnerable_function,
            finding.vulnerable_function,
            finding.vulnerable_address,
            finding.source_sink_path,
            finding.description,
            finding.decompiled_code,
            finding.exploit_vector,
            finding.confidence,
            verdict,
            notes,
            now,
            now,
        ))
        conn.commit()

        # Update task counters
        self._refresh_task_counters(task_id)

        finding_id = cur.lastrowid
        logger.info("finding recorded",
                     finding_id=finding_id, task_id=task_id,
                     title=finding.title, verdict=verdict)
        return finding_id

    def update_finding(self, finding_id: int, **fields: object) -> None:
        """Update arbitrary fields on a finding."""
        if not fields:
            return
        conn = self._get_conn()
        fields["updated_at"] = time.time()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [finding_id]
        conn.execute(
            f"UPDATE findings SET {set_clause} WHERE id = ?",
            values,
        )
        conn.commit()

        # Refresh parent task counters if verdict changed
        if "verdict" in fields:
            row = conn.execute(
                "SELECT task_id FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row:
                self._refresh_task_counters(row["task_id"])

    def get_findings(
        self,
        task_id: int,
        verdict: str | None = None,
    ) -> list[dict]:
        """Get findings for a task, optionally filtered by verdict."""
        conn = self._get_conn()
        if verdict:
            rows = conn.execute(
                "SELECT * FROM findings WHERE task_id = ? AND verdict = ? "
                "ORDER BY confidence DESC",
                (task_id, verdict),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE task_id = ? "
                "ORDER BY confidence DESC",
                (task_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------------
    # Progress tracking
    # -------------------------------------------------------------------

    def mark_level(self, task_id: int, level: int) -> None:
        """Mark the task as having completed up to this analysis level."""
        self.update_task(task_id, current_level=level, status="running")
        logger.info("task level updated", task_id=task_id, level=level)

    def mark_completed(self, task_id: int) -> None:
        """Mark task as completed."""
        self.update_task(task_id, status="completed")
        logger.info("task completed", task_id=task_id)

    def mark_failed(self, task_id: int, error: str = "") -> None:
        """Mark task as failed."""
        self.update_task(task_id, status="failed", notes=error)
        logger.info("task failed", task_id=task_id, error=error)

    # -------------------------------------------------------------------
    # JSON export
    # -------------------------------------------------------------------

    def export_task(self, task_id: int) -> dict:
        """Export a complete task with all findings as a dict."""
        task = self.get_task(task_id)
        if not task:
            return {}

        findings = self.get_findings(task_id)
        return {
            "task": task,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "confirmed": sum(1 for f in findings if f["verdict"] == "confirmed"),
                "disproved": sum(1 for f in findings if f["verdict"] == "disproved"),
                "weakened": sum(1 for f in findings if f["verdict"] == "weakened"),
                "needs_dynamic": sum(1 for f in findings if f["verdict"] == "needs_dynamic"),
                "pending": sum(1 for f in findings if f["verdict"] == "pending"),
            },
        }

    def export_task_json(self, task_id: int, path: str) -> None:
        """Export task to a JSON file."""
        data = self.export_task(task_id)
        if not data:
            logger.warning("no task found for export", task_id=task_id)
            return

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        logger.info("task exported", task_id=task_id, path=str(out))

    # -------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------

    def stats(self) -> dict:
        """Aggregate statistics."""
        conn = self._get_conn()
        total_tasks = conn.execute(
            "SELECT COUNT(*) FROM analysis_tasks"
        ).fetchone()[0]
        total_findings = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        by_status = {}
        for row in conn.execute(
            "SELECT status, COUNT(*) as cnt FROM analysis_tasks "
            "GROUP BY status ORDER BY cnt DESC"
        ).fetchall():
            by_status[row["status"]] = row["cnt"]

        by_verdict = {}
        for row in conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM findings "
            "GROUP BY verdict ORDER BY cnt DESC"
        ).fetchall():
            by_verdict[row["verdict"]] = row["cnt"]

        by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings "
            "WHERE verdict = 'confirmed' "
            "GROUP BY severity ORDER BY cnt DESC"
        ).fetchall():
            by_severity[row["severity"]] = row["cnt"]

        return {
            "total_tasks": total_tasks,
            "total_findings": total_findings,
            "tasks_by_status": by_status,
            "findings_by_verdict": by_verdict,
            "confirmed_by_severity": by_severity,
        }

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _refresh_task_counters(self, task_id: int) -> None:
        """Recompute total_findings / confirmed / disproved from findings table."""
        conn = self._get_conn()
        row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                SUM(CASE WHEN verdict = 'disproved' THEN 1 ELSE 0 END) as disproved
            FROM findings WHERE task_id = ?
        """, (task_id,)).fetchone()

        conn.execute("""
            UPDATE analysis_tasks SET
                total_findings = ?, confirmed = ?, disproved = ?, updated_at = ?
            WHERE id = ?
        """, (row["total"], row["confirmed"], row["disproved"],
              time.time(), task_id))
        conn.commit()
