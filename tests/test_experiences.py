"""Experience memory's query surface.

Covers two behaviours that were wrong/absent and are easy to regress:

1. a vendor-scoped load must also return the cross-vendor (``vendor == ''``)
   lessons -- matching vendor exactly used to hide them.
2. entries must be readable in full before a read-modify-write, because
   ``search_experiences`` truncates detail to 300 chars.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iot_agent.tools.analysis_store import AnalysisStore

LONG = "x" * 800


@pytest.fixture
def store():
    td = Path(tempfile.mkdtemp())
    s = AnalysisStore(db_path=str(td / "t.db"))
    yield s, td
    s.close()
    shutil.rmtree(td, ignore_errors=True)


def test_vendor_load_includes_cross_vendor_lessons(store):
    s, _ = store
    vendor_id = s.record_experience(
        category="pattern", scenario="厂商专属形态", detail=LONG, vendor="dlink", arch="arm",
    )
    general_id = s.record_experience(
        category="pattern", scenario="跨厂商通用形态", detail="general",
    )
    other_vendor_id = s.record_experience(
        category="pattern", scenario="别家形态", detail="other", vendor="tenda", arch="arm",
    )

    got = {r["id"] for r in s.search_experiences(vendor="dlink")}
    assert vendor_id in got, "own-vendor entry missing"
    assert general_id in got, "cross-vendor entry hidden by vendor filter"
    assert other_vendor_id not in got, "unrelated vendor leaked in"

    strict = {r["id"] for r in s.search_experiences(vendor="dlink", include_general=False)}
    assert strict == {vendor_id}, strict


def test_search_truncates_but_get_returns_full(store):
    s, _ = store
    vid = s.record_experience(
        category="pattern", scenario="厂商专属形态", detail=LONG, vendor="dlink", arch="arm",
    )
    row = [r for r in s.search_experiences(vendor="dlink") if r["id"] == vid][0]
    assert len(row["detail"]) == 300, len(row["detail"])
    assert row["score"] == 1, row  # success_count(1) - fail_count(0)

    full = s.get_experience(vid)
    assert len(full["detail"]) == 800, len(full["detail"])


def test_bump_moves_the_score(store):
    s, _ = store
    vid = s.record_experience(category="pattern", scenario="x", detail="d", vendor="dlink")
    s.bump_experience(vid, success=False)
    assert s.get_experience(vid)["fail_count"] == 1


def test_record_upserts_one_row_per_scenario(store):
    s, _ = store
    s.record_experience(category="pattern", scenario="厂商专属形态",
                        detail=LONG, vendor="dlink", arch="arm")
    s.record_experience(category="pattern", scenario="厂商专属形态",
                        detail="refreshed", vendor="dlink", arch="arm")
    same = s.search_experiences(vendor="dlink", include_general=False)
    assert len(same) == 1 and same[0]["detail"] == "refreshed", same


def test_get_unknown_id_returns_none(store):
    s, _ = store
    assert s.get_experience(999999) is None


def test_ingest_report_skips_boilerplate_headings(store):
    # A report's skeleton recurs everywhere ("固件信息", "PoC", "修复建议");
    # keying a lesson off those headings is how the memory filled up with
    # `[report] 固件信息` noise.
    s, td = store
    rpt = td / "r.md"
    rpt.write_text(
        "# 某固件验证记录\n\n"
        "## 固件信息\n\n- 版本: 1.2.3\n\n"
        "## 静态证据链（source → sink）\n\n1. handler 取参后拼 system\n\n"
        "## 修复建议\n\n1. 白名单\n\n"
        "## [env] chroot 下 httpd 依赖 NVRAM 起不来\n\n裸 chroot 启动即退出\n",
        encoding="utf-8",
    )
    ids = s.ingest_report(str(rpt), vendor="acme", arch="arm")
    assert len(ids) == 1, [s.get_experience(i)["scenario"] for i in ids]
    assert "NVRAM" in s.get_experience(ids[0])["scenario"]
