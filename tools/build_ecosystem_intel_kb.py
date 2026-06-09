from __future__ import annotations

"""Build/refresh data/ecosystem_intel_kb.json from data/cve_kb.json.

Usage from project root:
    python tools/build_ecosystem_intel_kb.py

Optional:
    export NVD_API_KEY=...   # recommended for higher NVD API rate limits
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.ecosystem_intel import build_ecosystem_summary, refresh_ecosystem_intel_kb  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh ACCHunter ecosystem intelligence KB using NVD CVE API.")
    parser.add_argument("--no-online", action="store_true", help="Only complete local fallback fields; do not call NVD.")
    parser.add_argument("--no-write", action="store_true", help="Do not write data/ecosystem_intel_kb.json.")
    args = parser.parse_args()

    _, warnings = refresh_ecosystem_intel_kb(force_online=not args.no_online, write=not args.no_write)
    summary = build_ecosystem_summary(online_refresh=False)
    print(f"CVE records: {summary['total_cve_record_count']}")
    print(f"Unique CVEs: {summary['total_cve_count']}")
    print(f"Unique libraries: {summary['total_library_count']}")
    print(f"cve_top: {len(summary['cve_top'])}")
    print(f"tpl_top: {len(summary['tpl_top'])}")
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
