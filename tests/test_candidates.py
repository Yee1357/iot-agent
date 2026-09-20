"""Candidate trail (``AnalysisStore`` candidates API).

The candidate trail is what makes L2 coverage auditable: a candidate rejected
before it ever became a finding must still leave a trace, or a resumed session
cannot tell what was already ruled out.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iot_agent.tools.analysis_store import AnalysisStore


@pytest.fixture
def store():
    # ponytail: mkdtemp + ignore_errors instead of TemporaryDirectory -- Windows
    # keeps the sqlite WAL handle briefly after close() and rmtree then fails.
    td = tempfile.mkdtemp()
    s = AnalysisStore(db_path=str(Path(td) / "t.db"))
    yield s
    s.close()
    shutil.rmtree(td, ignore_errors=True)


def test_rejected_candidate_keeps_its_reason(store):
    task = store.create_task(firmware_id="fw://x", vendor="acme", model="r1")
    cid = store.add_candidate(
        task, binary_name="cgi/foo.cgi", func_name="cgi_bar", param="name",
        sink_kind="system", status="rejected",
        reason="参数被白名单校验，未到达 sink",
    )
    assert isinstance(cid, int) and cid > 0, cid
    row = [c for c in store.list_candidates(task) if c["id"] == cid][0]
    assert row["status"] == "rejected" and row["reason"] == "参数被白名单校验，未到达 sink"


def test_add_is_idempotent_on_task_binary_func_param(store):
    task = store.create_task(firmware_id="fw://x")
    cid = store.add_candidate(
        task, binary_name="cgi/foo.cgi", func_name="cgi_bar", param="name",
    )
    again = store.add_candidate(
        task, binary_name="cgi/foo.cgi", func_name="cgi_bar", param="name",
        status="promoted", reason="重新定级",
    )
    assert again == cid, f"expected upsert onto {cid}, got {again}"
    row = store.list_candidates(task)[0]
    assert row["status"] == "promoted" and row["reason"] == "重新定级", row


def test_distinct_param_or_func_is_a_distinct_candidate(store):
    task = store.create_task(firmware_id="fw://x")
    cid = store.add_candidate(
        task, binary_name="cgi/foo.cgi", func_name="cgi_bar", param="name",
    )
    other = store.add_candidate(
        task, binary_name="cgi/foo.cgi", func_name="cgi_bar", param="path",
    )
    assert other != cid
    assert len(store.list_candidates(task)) == 2


def test_promote_links_back_to_the_finding(store):
    task = store.create_task(firmware_id="fw://x")
    cid = store.add_candidate(task, binary_name="cgi/foo.cgi", status="new")
    store.mark_candidate_promoted(cid, finding_id=42)
    promoted = store.list_candidates(task)[0]
    assert promoted["status"] == "promoted" and promoted["finding_id"] == 42


def test_status_filter(store):
    task = store.create_task(firmware_id="fw://x")
    store.add_candidate(task, binary_name="cgi/foo.cgi", status="new")
    rejected = store.add_candidate(
        task, binary_name="cgi/baz.cgi", func_name="cgi_qux",
        status="rejected", reason="无 sink",
    )
    assert [c["id"] for c in store.list_candidates(task, status="rejected")] == [rejected]


def test_unknown_status_raises_but_empty_means_unspecified(store):
    task = store.create_task(firmware_id="fw://x")
    for bad in ("done", "CONFIRMED", "pending"):
        with pytest.raises(ValueError):
            store.add_candidate(task, binary_name="x", status=bad)
    # empty string is NOT bad: it means "unspecified" and defaults to new
    defaulted = store.add_candidate(task, binary_name="y", status="")
    assert [c for c in store.list_candidates(task)
            if c["id"] == defaulted][0]["status"] == "new"


def test_resume_surfaces_the_trail(store):
    task = store.create_task(firmware_id="fw://x")
    store.add_candidate(task, binary_name="a", status="new")
    rejected = store.add_candidate(
        task, binary_name="b", status="rejected", reason="无 sink",
    )
    res = store.resume_task(task)
    assert len(res["candidates"]) == 2, res
    assert [c["id"] for c in res["candidates_rejected"]] == [rejected], res


def test_attempt_count_reaches_exhausted_with_guidance(store):
    task = store.create_task(firmware_id="fw://x")
    a = store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    assert (a["count"], a["exhausted"]) == (1, False), a
    b = store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    assert (b["count"], b["exhausted"]) == (2, True), b
    assert b["guidance"], "exhausted attempt must carry guidance"


def test_each_candidate_and_scheme_gets_its_own_budget(store):
    task = store.create_task(firmware_id="fw://x")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    # a different candidate gets its own budget
    c = store.note_attempt(task, "chroot qemu", candidate="bar.cgi/path")
    assert c["count"] == 1 and not c["exhausted"], c
    # a different scheme too
    d = store.note_attempt(task, "strace 取证", candidate="foo.cgi/name")
    assert d["count"] == 1 and not d["exhausted"], d


def test_success_resets_the_exhausted_counter(store):
    task = store.create_task(firmware_id="fw://x")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name", success=True)
    e = store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    assert e["count"] == 1 and not e["exhausted"], e


def test_attempts_survive_into_resume(store):
    task = store.create_task(firmware_id="fw://x")
    store.note_attempt(task, "chroot qemu", candidate="foo.cgi/name")
    store.note_attempt(task, "chroot qemu", candidate="bar.cgi/path")
    assert len(store.list_attempts(task)) == 2
    assert len(store.resume_task(task)["attempts"]) == 2
