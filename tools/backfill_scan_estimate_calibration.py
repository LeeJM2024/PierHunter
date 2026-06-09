from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.scan_estimator import estimate_scan_duration, profile_apk_for_estimate


COMPLETED_TASKS = [
    ("com.rtbishop.look4sat.apk", 1356.889705, "2026-06-09T11:53:02.791535+00:00"),
    ("com.nkanaev.comics.apk", 435.322758, "2026-06-08T16:24:36.160928+00:00"),
]


def main() -> None:
    calibration_path = PROJECT_ROOT / "storage" / "scan_estimate_calibration.json"
    data = json.loads(calibration_path.read_text(encoding="utf-8-sig"))
    stage_only_data = dict(data)
    stage_only_data.pop("completed_samples", None)
    stage_only_data.pop("completed_sample_count", None)
    stage_only_data.pop("completed_multiplier", None)
    calibration_path.write_text(json.dumps(stage_only_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    completed_samples = []

    for apk_name, actual_seconds, recorded_at in COMPLETED_TASKS:
        apk_path = PROJECT_ROOT / "storage" / "uploads" / apk_name
        if not apk_path.exists():
            continue
        profile = profile_apk_for_estimate(apk_path)
        baseline = estimate_scan_duration(profile, calibration_path)
        ratio = actual_seconds / max(baseline["total_seconds"], 1)
        completed_samples.append(
            {
                "apk_name": apk_name,
                "actual_seconds": int(actual_seconds),
                "base_seconds": int(baseline["total_seconds"]),
                "ratio": round(max(0.35, min(2.8, ratio)), 4),
                "method_count": int(profile.get("method_count") or 0),
                "class_count": int(profile.get("class_count") or 0),
                "dex_count": int(profile.get("dex_count") or 0),
                "recorded_at": recorded_at,
            }
        )

    ratios = [sample["ratio"] for sample in completed_samples]
    data["completed_samples"] = completed_samples
    data["completed_sample_count"] = len(completed_samples)
    data["completed_multiplier"] = round(sum(ratios) / len(ratios), 4) if ratios else 1.0
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    calibration_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        "backfilled",
        data.get("sample_count", 0),
        data["completed_sample_count"],
        data["completed_multiplier"],
    )


if __name__ == "__main__":
    main()
