"""Persistent storage for vulnerability analysis tasks, findings and experiences.

SQLite-backed, supports JSON export. Three responsibilities:

- **Tasks / findings** — track analysis progress across sessions so work can
  be resumed after interruption; ``resume_task()`` returns still-pending
  candidates (verdict != CONFIRMED/DISPROVED/WEAKENED).
- **Experiences** — cross-session lessons (env pitfalls, reusable patterns,
  false-positive rules, verification tricks) that let the agent iterate:
  ``record_experience`` (dedup by category+vendor+arch+scenario),
  ``search_experiences`` (compact digest), ``bump_experience`` (feedback).
- **JSON export** — one-call task+findings dump for reports.

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
    store.add_finding(task_id, finding, verdict="confirmed", binary_name="cgibin")

    # Track progress / resume
    store.mark_level(task_id, 2)          # completed Level 2
    pending = store.resume_task(task_id)  # candidate-level checkpointing

    # Experience memory
    store.record_experience(category="pattern", scenario="...", detail="...")
    store.search_experiences(vendor="dlink")
"""

from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

import structlog

from iot_agent.tools.ida_mcp import VulnerabilityFinding

logger = structlog.get_logger(__name__)

#: canonical verdicts (always stored lowercase; input case is normalized)
_VERDICTS = ("confirmed", "disproved", "weakened", "needs_dynamic", "pending")

#: project root (``src/iot_agent/tools/...`` -> repo root) -- DB paths must
#: not depend on the process CWD, the MCP server may start from anywhere.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _norm_verdict(verdict: str) -> str:
    return (verdict or "").strip().lower()


class AnalysisStore:
    """SQLite-backed analysis task and finding storage."""

    def __init__(self, db_path: str = "") -> None:
        self._db_path = Path(db_path) if db_path else _PROJECT_ROOT / "data" / "analysis.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path), timeout=10, check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=10000")
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

            CREATE TABLE IF NOT EXISTS experiences (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                category        TEXT NOT NULL DEFAULT 'general',
                vendor          TEXT NOT NULL DEFAULT '',
                arch            TEXT NOT NULL DEFAULT '',
                scenario        TEXT NOT NULL,
                detail          TEXT NOT NULL,
                source_task_id  INTEGER,
                success_count   INTEGER NOT NULL DEFAULT 1,
                fail_count      INTEGER NOT NULL DEFAULT 0,
                created_at      REAL NOT NULL,
                updated_at      REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_exp_vendor
                ON experiences(vendor, arch);
            CREATE INDEX IF NOT EXISTS idx_exp_category
                ON experiences(category);
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
        binary_name: str = "",
    ) -> int:
        """Record a VulnerabilityFinding. Returns finding id."""
        conn = self._get_conn()
        now = time.time()
        verdict = _norm_verdict(verdict)
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
            binary_name,
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
        if "verdict" in fields:
            fields["verdict"] = _norm_verdict(str(fields["verdict"]))
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
    # Resume support (candidate-level checkpointing)
    # -------------------------------------------------------------------

    def resume_task(self, task_id: int) -> dict:
        """Return everything needed to resume an interrupted analysis task.

        ``pending`` contains findings whose verdict still needs work:
        ``pending`` / ``needs_dynamic`` (already-judged CONFIRMED / DISPROVED
        / WEAKENED candidates are excluded so the agent skips them).
        """
        task = self.get_task(task_id)
        if not task:
            return {}
        findings = self.get_findings(task_id)
        pending = [
            f for f in findings
            if f["verdict"] in ("pending", "", "needs_dynamic")
        ]
        return {
            "task": task,
            "total_findings": len(findings),
            "pending_candidates": pending,
        }

    # -------------------------------------------------------------------
    # Experience memory (cross-session knowledge, not agent state)
    # -------------------------------------------------------------------

    def record_experience(
        self,
        category: str,
        scenario: str,
        detail: str,
        vendor: str = "",
        arch: str = "",
        source_task_id: int | None = None,
    ) -> int:
        """Record a reusable lesson. Returns experience id.

        If an entry with the same (category, vendor, arch, scenario) already
        exists, its ``detail`` is refreshed instead of duplicating -- this is
        how the memory self-iterates without growing unbounded.
        """
        conn = self._get_conn()
        now = time.time()
        row = conn.execute(
            "SELECT id FROM experiences WHERE category = ? AND vendor = ? "
            "AND arch = ? AND scenario = ?",
            (category, vendor, arch, scenario),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE experiences SET detail = ?, source_task_id = ?, "
                "updated_at = ? WHERE id = ?",
                (detail, source_task_id, now, row["id"]),
            )
            conn.commit()
            logger.info("experience refreshed", exp_id=row["id"], category=category)
            return row["id"]

        cur = conn.execute("""
            INSERT INTO experiences
                (category, vendor, arch, scenario, detail,
                 source_task_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (category, vendor, arch, scenario, detail,
              source_task_id, now, now))
        conn.commit()
        logger.info("experience recorded", exp_id=cur.lastrowid, category=category)
        return cur.lastrowid

    def search_experiences(
        self,
        category: str = "",
        vendor: str = "",
        arch: str = "",
        limit: int = 20,
        summary_only: bool = True,
    ) -> list[dict]:
        """Query reusable lessons, optionally filtered by category/vendor/arch.

        ``summary_only`` truncates ``detail`` so the agent can load a digest
        without blowing the context window. Order: most-successful first.
        """
        conn = self._get_conn()
        conditions: list[str] = []
        params: list[object] = []
        if category:
            conditions.append("category = ?")
            params.append(category)
        if vendor:
            conditions.append("LOWER(vendor) = LOWER(?)")
            params.append(vendor)
        if arch:
            conditions.append("arch = ?")
            params.append(arch)
        where = " AND ".join(conditions) if conditions else "1=1"
        query = (
            f"SELECT * FROM experiences WHERE {where} "
            f"ORDER BY (success_count - fail_count) DESC, updated_at DESC LIMIT ?"
        )
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if summary_only:
                d["detail"] = d["detail"][:300]
            out.append(d)
        return out

    def bump_experience(self, exp_id: int, success: bool = True) -> None:
        """Mark an experience as having worked (or not) again."""
        conn = self._get_conn()
        field = "success_count" if success else "fail_count"
        conn.execute(
            f"UPDATE experiences SET {field} = {field} + 1, updated_at = ? "
            "WHERE id = ?",
            (time.time(), exp_id),
        )
        conn.commit()

    def experience_stats(self) -> dict:
        """Aggregate statistics about the experience memory."""
        conn = self._get_conn()
        by_category = {}
        for row in conn.execute(
            "SELECT category, COUNT(*) as cnt FROM experiences "
            "GROUP BY category ORDER BY cnt DESC"
        ).fetchall():
            by_category[row["category"]] = row["cnt"]
        by_vendor = {}
        for row in conn.execute(
            "SELECT vendor, COUNT(*) as cnt FROM experiences "
            "WHERE vendor != '' GROUP BY vendor ORDER BY cnt DESC"
        ).fetchall():
            by_vendor[row["vendor"]] = row["cnt"]
        total = conn.execute("SELECT COUNT(*) FROM experiences").fetchone()[0]
        return {"total": total, "by_category": by_category, "by_vendor": by_vendor}

    def ingest_report(
        self,
        report_path: str,
        vendor: str = "",
        arch: str = "",
        category: str = "pattern",
    ) -> list[int]:
        """Parse a markdown analysis report and record each section as an experience.

        Sections are split on ``## `` / ``### `` headings (skipping the
        document title). Each section becomes one experience entry:
        scenario=heading, detail=body (trimmed, max 1200 chars).
        Returns the list of experience ids (0 recorded when nothing parseable).
        """
        p = Path(report_path)
        if not p.is_file():
            logger.warning("report not found", path=report_path)
            return []
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError:
            logger.warning("report unreadable", path=report_path)
            return []

        sections: list[tuple[str, list[str]]] = []
        current_title = ""
        current_body: list[str] = []
        for line in lines:
            m = re.match(r"^#{2,3}\s+(.+?)\s*$", line.strip())
            if m:
                if current_title:
                    sections.append((current_title, current_body))
                current_title = m.group(1).strip()
                current_body = []
            elif current_title:
                current_body.append(line)
        if current_title:  # trailing section after the last heading
            sections.append((current_title, current_body))

        ids: list[int] = []
        for title, body in sections:
            detail = "\n".join(body).strip()
            if not detail:
                detail = "(no detail in report section)"
            detail = detail[:1200]
            ids.append(self.record_experience(
                category=category,
                scenario=f"[report] {title}",
                detail=detail,
                vendor=vendor,
                arch=arch,
            ))
        logger.info("report ingested", path=report_path,
                    sections=len(sections), recorded=len(ids))
        return ids

    def findings_insights(self, vendor: str = "") -> dict:
        """Aggregate historical findings into reusable insights.

        Groups by binary, sink and CWE with verdict distributions and
        false-positive rates (disproved / total), so the agent can learn
        "which sinks for this vendor are usually false positives".
        """
        conn = self._get_conn()
        vendor_cond = ""
        params: list[object] = []
        if vendor:
            vendor_cond = "AND LOWER(t.vendor) = LOWER(?)"
            params.append(vendor)

        def rows(query: str) -> list[dict]:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

        by_binary = rows(f"""
            SELECT f.binary_name AS name, COUNT(*) AS total,
                   SUM(CASE WHEN f.verdict='confirmed' THEN 1 ELSE 0 END) AS confirmed,
                   SUM(CASE WHEN f.verdict='disproved' THEN 1 ELSE 0 END) AS disproved,
                   SUM(CASE WHEN f.verdict='weakened' THEN 1 ELSE 0 END) AS weakened,
                   SUM(CASE WHEN f.verdict='needs_dynamic' THEN 1 ELSE 0 END) AS needs_dynamic
            FROM findings f JOIN analysis_tasks t ON t.id = f.task_id
            WHERE f.binary_name != '' {vendor_cond}
            GROUP BY f.binary_name ORDER BY total DESC LIMIT 20
        """)
        by_sink = rows(f"""
            SELECT SUBSTR(f.source_sink, 1, 60) AS sink, COUNT(*) AS total,
                   SUM(CASE WHEN f.verdict='confirmed' THEN 1 ELSE 0 END) AS confirmed,
                   SUM(CASE WHEN f.verdict='disproved' THEN 1 ELSE 0 END) AS disproved
            FROM findings f JOIN analysis_tasks t ON t.id = f.task_id
            WHERE f.source_sink != '' {vendor_cond}
            GROUP BY sink ORDER BY total DESC LIMIT 20
        """)
        by_cwe = rows(f"""
            SELECT f.cwe_id AS cwe, COUNT(*) AS total,
                   SUM(CASE WHEN f.verdict='confirmed' THEN 1 ELSE 0 END) AS confirmed,
                   SUM(CASE WHEN f.verdict='disproved' THEN 1 ELSE 0 END) AS disproved
            FROM findings f JOIN analysis_tasks t ON t.id = f.task_id
            WHERE f.cwe_id != '' {vendor_cond}
            GROUP BY f.cwe_id ORDER BY total DESC LIMIT 20
        """)
        for group in (by_binary, by_sink, by_cwe):
            for item in group:
                total = item.get("total") or 0
                disproved = item.get("disproved") or 0
                item["disprove_rate"] = round(disproved / total, 2) if total else 0.0

        return {
            "vendor": vendor or "(all)",
            "by_binary": by_binary,
            "by_sink": by_sink,
            "by_cwe": by_cwe,
        }

    def export_experience_markdown(
        self,
        category: str = "pattern",
        min_success: int = 3,
        limit: int = 20,
    ) -> str:
        """Export top experiences as a markdown block for manual promotion.

        Used to solidify proven dynamic lessons (e.g. success_count >= 3)
        back into the static knowledge docs (``iot-vuln-patterns``).
        """
        rows = self.search_experiences(
            category=category, limit=limit, summary_only=False
        )
        rows = [r for r in rows if (r["success_count"] - r["fail_count"]) >= min_success]
        if not rows:
            return ""
        out = [f"## {category} 经验（已固化候选，success≥{min_success}）", ""]
        for r in rows:
            out.append(f"### {r['scenario']}  (vendor={r['vendor'] or '-'}, arch={r['arch'] or '-'}, 成功{r['success_count']}/失败{r['fail_count']})")
            out.append("")
            out.append(r["detail"].strip())
            out.append("")
        return "\n".join(out)

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
