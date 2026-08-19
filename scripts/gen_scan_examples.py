"""Generate real few-shot examples by scanning a real firmware ELF with headless IDA.

Run on the Windows host in the conda iot-agent environment (real IDA install):

    conda activate iot-agent
    python scripts/gen_scan_examples.py

What it does:
1. Opens elfs/DIR815_cgibin with idalib (headless, no GUI)
2. Runs IDAHeadlessScanner.systematic_scan(vendor="dlink") -- merges
   knowledge/dlink.json vendor sinks/taint sources
3. Writes data/scan_findings.json (real sink context, taint traces, verdict
   candidates) -- the raw material for prompt few-shot examples
4. Cleans up IDA temp files (.i64/.id0/...)

If import idapro fails silently (process exits with no output), you are in a
restricted environment that cannot load IDA's kernel DLL -- run this in a
normal terminal instead.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iot_agent.tools.ida_mcp import IDAHeadlessClient, cleanup_ida_files
from iot_agent.tools.ida_scanner import IDAHeadlessScanner

ELF = Path("elfs/DIR815_cgibin")
OUT = Path("data/scan_findings.json")


def main() -> None:
    if not ELF.is_file():
        sys.exit(f"missing {ELF}")
    print(f"[*] scanning {ELF} with vendor=dlink (headless IDA) ...")
    with IDAHeadlessClient(str(ELF)) as ida:
        scanner = IDAHeadlessScanner(ida, vendor="dlink")
        findings = scanner.systematic_scan()
        out = [f.to_dict() for f in findings]
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    cleanup_ida_files(str(ELF))
    print(f"[*] {len(out)} findings -> {OUT}")
    for f in out[:8]:
        print(f"    - {f['title']} | {f['severity']} conf={f['confidence']}")


if __name__ == "__main__":
    main()
