from __future__ import annotations

import json
import math
import statistics
import struct
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


MODEL_NAME = "dex-static-calibrated-v2"
MAX_SAMPLES = 40


def profile_apk_for_estimate(apk_path: Path) -> dict[str, Any]:
    dex_files: list[dict[str, Any]] = []
    compressed_bytes = 0
    uncompressed_bytes = 0
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for info in archive.infolist():
                if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                    compressed_bytes += info.compress_size
                    uncompressed_bytes += info.file_size
                    with archive.open(info) as handle:
                        header = handle.read(116)
                    method_count = 0
                    class_count = 0
                    if len(header) >= 100 and header[:3] == b"dex":
                        method_count = struct.unpack_from("<I", header, 88)[0]
                        class_count = struct.unpack_from("<I", header, 96)[0]
                    dex_files.append(
                        {
                            "name": info.filename,
                            "compressed_size": info.compress_size,
                            "uncompressed_size": info.file_size,
                            "method_count": method_count,
                            "class_count": class_count,
                        }
                    )
    except (OSError, zipfile.BadZipFile):
        dex_files = []

    method_count = sum(int(item["method_count"]) for item in dex_files)
    class_count = sum(int(item["class_count"]) for item in dex_files)
    return {
        "apk_size": apk_path.stat().st_size if apk_path.exists() else 0,
        "dex_count": len(dex_files),
        "dex_compressed_size": compressed_bytes,
        "dex_uncompressed_size": uncompressed_bytes,
        "method_count": method_count,
        "class_count": class_count,
        "dex_files": dex_files[:8],
    }


def estimate_scan_duration(profile: dict[str, Any], calibration_path: Path | None = None) -> dict[str, Any]:
    estimate = _base_estimate_scan_duration(profile)
    calibration = _load_calibration(calibration_path) if calibration_path else None
    sample_count = int((calibration or {}).get("sample_count") or 0)
    completed_sample_count = int((calibration or {}).get("completed_sample_count") or 0)
    multiplier = float((calibration or {}).get("multiplier") or 1.0)

    if sample_count > 0:
        multiplier = _clamp(multiplier, 0.35, 2.8)
        stage_multipliers = {
            key: _clamp(float(value), 0.2, 4.0)
            for key, value in ((calibration or {}).get("stage_multipliers") or {}).items()
            if key in estimate["stages"]
        }
        scaled_stages = {}
        for key, value in estimate["stages"].items():
            stage_multiplier = stage_multipliers.get(key, multiplier)
            scaled_stages[key] = int(max(value * stage_multiplier, 1))
        total_seconds = int(max(sum(scaled_stages.values()), 300))
        completed_multiplier = _completed_scan_multiplier(calibration, profile)
        if completed_multiplier is not None:
            total_seconds = int(max(total_seconds * completed_multiplier, 300))
            total_scale = total_seconds / max(sum(scaled_stages.values()), 1)
            scaled_stages = {key: int(max(value * total_scale, 1)) for key, value in scaled_stages.items()}
        estimate["total_seconds"] = total_seconds
        estimate["total_minutes"] = int(max(math.ceil(total_seconds / 60), 5))
        estimate["stages"] = scaled_stages
        estimate["calibration"] = {
            "sample_count": sample_count,
            "completed_sample_count": completed_sample_count,
            "multiplier": round(multiplier, 3),
            "stage_multipliers": {key: round(value, 3) for key, value in stage_multipliers.items()},
            "stage_sample_count": (calibration or {}).get("stage_sample_count") or {},
            "completed_multiplier": round(completed_multiplier, 3) if completed_multiplier is not None else None,
            "updated_at": calibration.get("updated_at"),
        }
        estimate["basis"].append(f"历史校准 x{multiplier:.2f}（{sample_count} 项）")
        if completed_multiplier is not None:
            estimate["basis"].append(f"完整任务校准 x{completed_multiplier:.2f}（{completed_sample_count} 项）")
        if sample_count >= 5 and estimate["confidence"] != "low":
            estimate["confidence"] = "high"
        elif estimate["confidence"] == "high":
            estimate["confidence"] = "medium"
    else:
        estimate["calibration"] = {
            "sample_count": 0,
            "completed_sample_count": 0,
            "multiplier": 1.0,
            "updated_at": None,
        }
        if estimate["confidence"] == "high":
            estimate["confidence"] = "medium"

    estimate["model"] = MODEL_NAME
    return estimate


def record_completed_scan(
    calibration_path: Path,
    apk_path: Path,
    started_at: datetime | None,
    finished_at: datetime | None,
) -> dict[str, Any] | None:
    if started_at is None or finished_at is None:
        return None

    started_at = _as_utc_aware(started_at)
    finished_at = _as_utc_aware(finished_at)
    actual_seconds = (finished_at - started_at).total_seconds()
    if actual_seconds < 60:
        return None

    profile = profile_apk_for_estimate(apk_path)
    base_estimate = _base_estimate_scan_duration(profile)
    base_seconds = float(base_estimate["total_seconds"])
    ratio = _clamp(actual_seconds / max(base_seconds, 1.0), 0.35, 2.8)

    calibration = _load_calibration(calibration_path) or {}
    completed_samples = list(calibration.get("completed_samples") or [])
    completed_samples.append(
        {
            "apk_name": apk_path.name,
            "actual_seconds": int(actual_seconds),
            "base_seconds": int(base_seconds),
            "ratio": round(ratio, 4),
            "method_count": int(profile.get("method_count") or 0),
            "class_count": int(profile.get("class_count") or 0),
            "dex_count": int(profile.get("dex_count") or 0),
            "recorded_at": finished_at.isoformat(),
        }
    )
    completed_samples = completed_samples[-MAX_SAMPLES:]
    completed_ratios = [float(sample["ratio"]) for sample in completed_samples if sample.get("ratio")]
    completed_multiplier = statistics.median(completed_ratios) if completed_ratios else 1.0
    updated = {
        "model": MODEL_NAME,
        "sample_count": int(calibration.get("sample_count") or 0),
        "multiplier": float(calibration.get("multiplier") or 1.0),
        "completed_sample_count": len(completed_samples),
        "completed_multiplier": round(_clamp(completed_multiplier, 0.35, 2.8), 4),
        "updated_at": finished_at.isoformat(),
        "source": calibration.get("source", "local_completed_scans"),
        "stage_multipliers": calibration.get("stage_multipliers") or {},
        "stage_sample_count": calibration.get("stage_sample_count") or {},
        "samples": list(calibration.get("samples") or [])[-MAX_SAMPLES:],
        "completed_samples": completed_samples,
    }
    _write_json_atomic(calibration_path, updated)
    return updated


def _base_estimate_scan_duration(profile: dict[str, Any]) -> dict[str, Any]:
    apk_mb = (profile.get("apk_size") or 0) / 1024 / 1024
    dex_mb = (profile.get("dex_uncompressed_size") or 0) / 1024 / 1024
    dex_count = int(profile.get("dex_count") or 0)
    method_count = int(profile.get("method_count") or 0)
    class_count = int(profile.get("class_count") or 0)

    estimated_components = max(1, min(24, math.ceil(class_count / 850))) if class_count else max(1, math.ceil(apk_mb / 12))
    estimated_cves = max(1, min(36, math.ceil(estimated_components * 1.8)))

    init_seconds = 20 + dex_count * 8 + apk_mb * 0.8
    libhunter_seconds = 90 + method_count * 0.010 + class_count * 0.22 + dex_mb * 3.0
    phunter_seconds = 120 + estimated_cves * (55 + math.log1p(max(method_count, 1)) * 3.2)
    report_seconds = 55
    total_seconds = init_seconds + libhunter_seconds + phunter_seconds + report_seconds

    confidence = "high" if method_count and class_count else "medium" if dex_count else "low"
    return {
        "total_seconds": int(max(total_seconds, 300)),
        "total_minutes": int(max(math.ceil(total_seconds / 60), 5)),
        "confidence": confidence,
        "model": "dex-static-cost-v1",
        "estimated_components": estimated_components,
        "estimated_cves": estimated_cves,
        "stages": {
            "init_seconds": int(init_seconds),
            "libhunter_seconds": int(libhunter_seconds),
            "phunter_seconds": int(phunter_seconds),
            "report_seconds": int(report_seconds),
        },
        "basis": [
            f"APK {apk_mb:.1f} MB",
            f"DEX {dex_count} 个",
            f"方法 {method_count:,} 个" if method_count else "方法数未解析",
            f"类 {class_count:,} 个" if class_count else "类数未解析",
        ],
    }


def _load_calibration(calibration_path: Path | None) -> dict[str, Any] | None:
    if calibration_path is None or not calibration_path.exists():
        return None
    try:
        return json.loads(calibration_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None


def _as_utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _completed_scan_multiplier(calibration: dict[str, Any] | None, profile: dict[str, Any]) -> float | None:
    if not calibration:
        return None
    samples = list(calibration.get("completed_samples") or [])
    if not samples:
        return None

    method_count = max(int(profile.get("method_count") or 0), 1)
    class_count = max(int(profile.get("class_count") or 0), 1)
    candidates: list[tuple[float, float]] = []
    for sample in samples:
        ratio = sample.get("ratio")
        sample_methods = int(sample.get("method_count") or 0)
        sample_classes = int(sample.get("class_count") or 0)
        if not ratio or not sample_methods or not sample_classes:
            continue
        method_distance = abs(math.log(method_count / sample_methods))
        class_distance = abs(math.log(class_count / sample_classes))
        distance = method_distance * 0.65 + class_distance * 0.35
        weight = 1 / (1 + distance)
        candidates.append((float(ratio), weight))

    if not candidates:
        stored = calibration.get("completed_multiplier")
        return _clamp(float(stored), 0.35, 2.8) if stored else None

    numerator = sum(ratio * weight for ratio, weight in candidates)
    denominator = sum(weight for _, weight in candidates)
    return _clamp(numerator / max(denominator, 1e-6), 0.5, 1.8)


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_path = Path(handle.name)
    temp_path.replace(path)


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
