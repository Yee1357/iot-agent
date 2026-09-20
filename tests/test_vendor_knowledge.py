"""Vendor-knowledge write-back (``promote_vendor_knowledge``).

Two things must hold, and both are easy to get wrong:

1. merge is non-destructive -- promoting a second field must not drop the
   first (the scanner reads this file on every scan);
2. promoting a sink that is already in the *generic* table is flagged, because
   ``_vendor_sink_entry`` discards its description -- silently, which is how
   ``dlink.json`` accumulated prose the scanner never reads.

Runs against a temp knowledge dir; the real ``knowledge/`` is untouched.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iot_agent.tools import ida_scanner


@pytest.fixture
def knowledge_dir():
    """Point the scanner at a throwaway knowledge dir.

    Autouse-style save/restore so a failing assert cannot leak the global into
    the next test -- the real ``knowledge/`` must never be written by a test.
    """
    real_dir = ida_scanner._KNOWLEDGE_DIR
    td = Path(tempfile.mkdtemp())
    ida_scanner._KNOWLEDGE_DIR = td
    yield td
    ida_scanner._KNOWLEDGE_DIR = real_dir
    shutil.rmtree(td, ignore_errors=True)


def test_vendor_new_sink_keeps_its_own_description(knowledge_dir):
    res = ida_scanner.promote_vendor_knowledge(
        vendor="acme", sink_name="acme_run", cwe="CWE-78",
        description="vendor wrapper -> system", severity="HIGH",
        confidence=0.8, format_string=True,
    )
    assert res["warning"] == "", res
    entry = json.loads((knowledge_dir / "acme.json").read_text(encoding="utf-8"))
    assert entry["sinks"]["acme_run"]["description"] == "vendor wrapper -> system"


def test_merge_is_non_destructive(knowledge_dir):
    ida_scanner.promote_vendor_knowledge(
        vendor="acme", sink_name="acme_run", cwe="CWE-78",
        description="vendor wrapper -> system", severity="HIGH",
        confidence=0.8, format_string=True,
    )
    ida_scanner.promote_vendor_knowledge(
        vendor="acme", sink_name="acme_run", severity="CRITICAL",
    )
    entry = json.loads((knowledge_dir / "acme.json").read_text(encoding="utf-8"))
    got = entry["sinks"]["acme_run"]
    assert got["severity"] == "CRITICAL", got
    assert got["description"] == "vendor wrapper -> system", "description lost"
    assert got["cwe"] == "CWE-78" and got["format_string"] is True, got
    assert got["confidence"] == 0.8, got


def test_generic_sink_is_flagged_and_its_description_discarded(knowledge_dir):
    res = ida_scanner.promote_vendor_knowledge(
        vendor="acme", sink_name="system", description="D-Link DNS-320 长叙事",
    )
    assert "already in the generic sink table" in res["warning"], res
    # and the scanner really does ignore that description:
    _, _, cls, _ = ida_scanner._merge_vendor_knowledge("acme")
    assert "D-Link" not in cls["system"][1], cls["system"]


def test_taint_sources_append_without_duplicates(knowledge_dir):
    ida_scanner.promote_vendor_knowledge(vendor="acme", taint_source="websGetVar")
    ida_scanner.promote_vendor_knowledge(vendor="acme", taint_source="websGetVar")
    ida_scanner.promote_vendor_knowledge(vendor="acme", taint_source="acme_getvar")
    entry = json.loads((knowledge_dir / "acme.json").read_text(encoding="utf-8"))
    assert entry["taint_sources"] == ["websGetVar", "acme_getvar"], entry

    # and they reach the scanner's merge:
    _, taint, _, _ = ida_scanner._merge_vendor_knowledge("acme")
    assert "acme_getvar" in taint


def test_guard_rails(knowledge_dir):
    # empty vendor or nothing to promote -> ValueError (our own check)
    for bad in ({"vendor": ""}, {"vendor": "acme"}):
        with pytest.raises(ValueError):
            ida_scanner.promote_vendor_knowledge(**bad)
    # missing vendor -> TypeError (plain Python)
    for bad in ({}, {"sink_name": "x"}):
        with pytest.raises(TypeError):
            ida_scanner.promote_vendor_knowledge(**bad)
