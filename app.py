from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db import SessionLocal, get_db, init_db
from backend.models import AnalysisTask, User, VulnerabilityReport
from backend.settings import settings
from backend.tasks import run_analysis_task
from config import ensure_runtime_dirs
from engine.ecosystem_intel import build_ecosystem_summary
from engine.intelligence import build_intelligence_artifact
from engine.scan_estimator import estimate_scan_duration, profile_apk_for_estimate


class AnalyzeRequest(BaseModel):
    filename: Optional[str] = None
    user_id: Optional[str] = None


class IntelligenceAnalyzeRequest(BaseModel):
    task_id: Optional[str] = None
    report: Optional[dict] = None


app = FastAPI(title="APK Vulnerability Scanner API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_frontend_dist = Path(__file__).resolve().parent / "frontend" / "dist"


@app.on_event("startup")
def startup_event() -> None:
    ensure_runtime_dirs()
    settings.ensure_runtime_dirs()
    init_db()


def _sanitize_filename(filename: str) -> str:
    cleaned = Path(filename or "").name
    if not cleaned:
        raise HTTPException(status_code=400, detail="Empty filename")
    return cleaned


def _resolve_apk_path(filename: str) -> Path:
    safe_name = _sanitize_filename(filename)
    apk_path = (settings.upload_dir / safe_name).resolve()
    if apk_path.parent != settings.upload_dir.resolve():
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not apk_path.exists() or not apk_path.is_file():
        raise HTTPException(status_code=404, detail=f"APK not found: {safe_name}")
    return apk_path


def _serialize_task(task: AnalysisTask) -> dict:
    return {
        "task_id": task.id,
        "apk_name": task.apk_name,
        "apk_path": task.apk_path,
        "status": task.status,
        "celery_task_id": task.celery_task_id,
        "report_path": task.report_path,
        "stdout_log_path": task.stdout_log_path,
        "stderr_log_path": task.stderr_log_path,
        "error": task.error_message,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
    }


def _get_or_create_default_user(db: Session) -> User:
    user = db.scalar(select(User).where(User.username == "default"))
    if user is not None:
        return user
    user = User(username="default")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _enqueue_analysis(db: Session, apk_path: Path, user_id: str | None) -> AnalysisTask:
    if user_id:
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
    else:
        user = _get_or_create_default_user(db)

    task = AnalysisTask(
        user_id=user.id,
        apk_name=apk_path.name,
        apk_path=str(apk_path),
        status="queued",
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    try:
        async_result = run_analysis_task.delay(task.id, str(apk_path))
    except Exception as exc:
        task.status = "failed"
        task.error_message = f"Failed to submit Celery task: {exc}"
        db.commit()
        db.refresh(task)
        return task

    task.celery_task_id = async_result.id
    db.commit()
    db.refresh(task)
    return task


def _latest_completed_task(db: Session) -> AnalysisTask | None:
    stmt = (
        select(AnalysisTask)
        .where(AnalysisTask.status == "completed")
        .order_by(AnalysisTask.finished_at.desc())
    )
    return db.scalars(stmt).first()


def _read_json_file(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid report JSON: {exc}") from exc


@lru_cache(maxsize=1)
def _load_cve_kb() -> list[dict]:
    kb_path = settings.project_root / "data" / "cve_kb.json"
    try:
        data = json.loads(kb_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _library_match_keys(name: str | None) -> set[str]:
    raw = str(name or "").strip().lower()
    if not raw:
        return set()
    variants = {
        raw,
        raw.replace(":", "."),
        raw.replace(".", ":"),
        raw.replace("_", "-"),
    }
    parts = re.split(r"[:./]", raw)
    if parts:
        variants.add(parts[-1])
    return {variant for variant in variants if variant}


def _version_sort_key(version: str) -> tuple:
    pieces = re.split(r"([0-9]+)", str(version))
    key: list[tuple[int, object]] = []
    for piece in pieces:
        if not piece:
            continue
        if piece.isdigit():
            key.append((0, int(piece)))
        else:
            key.append((1, piece.lower()))
    return tuple(key)


def _extract_post_patch_version(record: dict) -> str | None:
    cve_id = str(record.get("cve_id") or "")
    artifact = Path(str(record.get("post_patch_jar") or "")).name
    if not cve_id or not artifact:
        return None
    marker = f"-{cve_id}-"
    if marker not in artifact:
        return None
    prefix = artifact.split(marker, 1)[0]
    match = re.search(r"([0-9][0-9A-Za-z._+-]*)$", prefix)
    return match.group(1) if match else None


def _timeline_record_matches_library(record: dict, library_name: str) -> bool:
    library_keys = _library_match_keys(library_name)
    record_keys = _library_match_keys(record.get("library_name"))
    for alias in record.get("aliases") or []:
        record_keys.update(_library_match_keys(alias))
    return bool(library_keys & record_keys)


def _build_cve_version_timeline(report_json: dict) -> list[dict]:
    libraries = [item for item in report_json.get("used_libraries") or [] if isinstance(item, dict)]
    vulnerabilities = [item for item in report_json.get("vulnerabilities") or [] if isinstance(item, dict)]
    if not libraries or not vulnerabilities:
        return []

    kb = _load_cve_kb()
    timeline: list[dict] = []
    for library in libraries:
        library_name = str(library.get("library_name") or library.get("raw_name") or "").strip()
        detected_version = str(library.get("version") or "-").strip()
        related_vulns = [
            vuln for vuln in vulnerabilities
            if str(vuln.get("library") or "").strip() == library_name
        ]
        if not library_name or not related_vulns:
            continue

        cve_items: list[dict] = []
        all_versions: set[str] = set()
        if detected_version and detected_version != "-":
            all_versions.add(detected_version)

        for vuln in related_vulns:
            cve_id = str(vuln.get("cve_id") or "").strip()
            if not cve_id:
                continue
            matching_records = [
                record for record in kb
                if str(record.get("cve_id") or "") == cve_id
                and _timeline_record_matches_library(record, library_name)
            ]
            if not matching_records:
                cve_items.append({
                    "cve_id": cve_id,
                    "status": vuln.get("status") or "UNKNOWN",
                    "affected_versions": [],
                    "affected_from": None,
                    "affected_to": None,
                    "fixed_version": None,
                    "current_affected": False,
                    "knowledge_status": "missing",
                })
                continue

            affected_versions = sorted(
                {
                    str(version)
                    for record in matching_records
                    for version in (record.get("affected_versions") or [])
                    if str(version).strip()
                },
                key=_version_sort_key,
            )
            fixed_versions = sorted(
                {
                    version
                    for record in matching_records
                    for version in [_extract_post_patch_version(record)]
                    if version
                },
                key=_version_sort_key,
            )
            all_versions.update(affected_versions)
            all_versions.update(fixed_versions)

            cve_items.append({
                "cve_id": cve_id,
                "status": vuln.get("status") or "UNKNOWN",
                "affected_versions": affected_versions,
                "affected_from": affected_versions[0] if affected_versions else None,
                "affected_to": affected_versions[-1] if affected_versions else None,
                "fixed_version": fixed_versions[0] if fixed_versions else None,
                "current_affected": detected_version in affected_versions,
                "knowledge_status": "matched",
            })

        sorted_versions = sorted(all_versions, key=_version_sort_key)
        timeline.append({
            "library_name": library_name,
            "detected_version": detected_version,
            "versions": sorted_versions,
            "current_version_index": sorted_versions.index(detected_version) if detected_version in sorted_versions else -1,
            "cves": sorted(cve_items, key=lambda item: (not item.get("current_affected"), item.get("cve_id") or "")),
        })

    return timeline


def _candidate_log_files(task: AnalysisTask) -> list[Path]:
    candidates: list[Path] = []
    for path_text in (task.stdout_log_path, task.stderr_log_path):
        if not path_text:
            continue
        path = Path(path_text)
        if path.exists() and path.is_file():
            candidates.append(path)

    apk_stem = Path(task.apk_name).stem
    for path in settings.log_dir.glob(f"*{apk_stem}*.log"):
        if path.is_file():
            candidates.append(path)

    unique: dict[str, Path] = {str(path.resolve()): path for path in candidates}
    return sorted(unique.values(), key=lambda p: p.name)


def _task_report_json(task: AnalysisTask) -> dict | None:
    if task.report and task.report.report_json is not None:
        return task.report.report_json
    if task.report_path:
        path = Path(task.report_path)
        if path.exists() and path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
    return None


def _refresh_report_intelligence(report_json: dict) -> dict:
    if not isinstance(report_json, dict):
        return report_json
    report_json["cve_version_timeline"] = _build_cve_version_timeline(report_json)
    artifacts = report_json.get("analysis_artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}
        report_json["analysis_artifacts"] = artifacts
    existing = artifacts.get("intelligence")
    if isinstance(existing, dict):
        fallback = existing.get("fallback") if isinstance(existing.get("fallback"), dict) else {}
        if (
            existing.get("status") == "ok"
            and not fallback.get("used")
        ):
            return report_json
    artifacts["intelligence"] = build_intelligence_artifact(report_json, artifacts)
    return report_json


def _severity_from_patch_status(status: str | None) -> str:
    normalized = str(status or "UNKNOWN").upper()
    if normalized in {"PRESENT"}:
        return "critical"
    if normalized in {"PATCH_NOT_PRESENT"}:
        return "high"
    if normalized in {"UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT"}:
        return "medium"
    if normalized in {"PATCH_PRESENT", "NOT_PRESENT"}:
        return "low"
    return "info"


def _day_label(value: datetime) -> str:
    return value.strftime("%m/%d")


def _seconds_between(started: datetime | None, finished: datetime | None) -> float | None:
    if not started or not finished:
        return None
    return max((finished - started).total_seconds(), 0.0)


def _report_file_candidates() -> list[Path]:
    candidates: list[Path] = []
    for report_dir in (settings.report_dir, settings.project_root / "outputs" / "reports"):
        if report_dir.exists() and report_dir.is_dir():
            candidates.extend(sorted(report_dir.glob("*_vuln_report.json")))
    unique: dict[str, Path] = {str(path.resolve()): path for path in candidates if path.is_file()}
    return list(unique.values())


def _delete_files_under(root: Path) -> int:
    root = root.resolve()
    if not root.exists() or not root.is_dir():
        return 0
    deleted = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if root not in resolved.parents:
            continue
        try:
            resolved.unlink()
            deleted += 1
        except OSError:
            continue
    return deleted


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "database_url": settings.database_url,
        "broker": settings.celery_broker_url,
        "storage_dir": str(settings.storage_dir),
    }


@app.get("/api/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)) -> dict:
    tasks = list(db.scalars(select(AnalysisTask).order_by(AnalysisTask.created_at.asc())))
    completed_tasks = [task for task in tasks if task.status == "completed"]
    failed_tasks = [task for task in tasks if task.status == "failed"]
    running_tasks = [task for task in tasks if task.status == "running"]
    queued_tasks = [task for task in tasks if task.status == "queued"]

    reports: list[dict] = []
    seen_report_paths: set[str] = set()
    for task in completed_tasks:
        report_json = _task_report_json(task)
        if report_json is not None:
            reports.append(report_json)
            if task.report_path:
                seen_report_paths.add(str(Path(task.report_path).resolve()))

    for report_path in _report_file_candidates():
        resolved = str(report_path.resolve())
        if resolved in seen_report_paths:
            continue
        try:
            report_json = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(report_json, dict):
            reports.append(report_json)
            seen_report_paths.add(resolved)

    vulnerability_rows: list[dict] = []
    library_rows: list[dict] = []
    patch_evidence_count = 0
    target_class_count = 0
    for report in reports:
        libraries = report.get("used_libraries") or []
        vulnerabilities = report.get("vulnerabilities") or []
        library_rows.extend(row for row in libraries if isinstance(row, dict))
        vulnerability_rows.extend(row for row in vulnerabilities if isinstance(row, dict))

        artifacts = report.get("analysis_artifacts") or {}
        artifact_summary = artifacts.get("summary") or {}
        patch_evidence_count += int(artifact_summary.get("patch_evidence_count") or 0)
        target_class_count += int(artifact_summary.get("target_class_count") or 0)
        if not artifact_summary:
            patch_evidence_count += sum(1 for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("evidence"))
            target_class_count += sum(len(lib.get("target_classes") or []) for lib in libraries if isinstance(lib, dict))

    cve_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    for vuln in vulnerability_rows:
        cve_id = str(vuln.get("cve_id") or "UNKNOWN-CVE")
        status = str(vuln.get("status") or "UNKNOWN")
        cve_counter[cve_id] += 1
        status_counter[status] += 1
        severity_counter[_severity_from_patch_status(status)] += 1

    library_counter: Counter[str] = Counter()
    vulnerable_library_counter: Counter[str] = Counter()
    for lib in library_rows:
        name = str(lib.get("library_name") or lib.get("raw_name") or "unknown")
        library_counter[name] += 1
    for vuln in vulnerability_rows:
        vulnerable_library_counter[str(vuln.get("library") or "unknown")] += 1

    today = datetime.utcnow().date()
    trend = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        day_tasks = [task for task in tasks if task.created_at and task.created_at.date() == day]
        trend.append({
            "day": _day_label(datetime.combine(day, datetime.min.time())),
            "completed": sum(1 for task in day_tasks if task.status == "completed"),
            "failed": sum(1 for task in day_tasks if task.status == "failed"),
            "scanning": sum(1 for task in day_tasks if task.status == "running"),
            "queued": sum(1 for task in day_tasks if task.status == "queued"),
            "total": len(day_tasks),
        })
    if not tasks and reports and trend:
        trend[-1]["completed"] = len(reports)
        trend[-1]["total"] = len(reports)

    durations = [
        seconds
        for seconds in (_seconds_between(task.started_at, task.finished_at) for task in completed_tasks)
        if seconds is not None
    ]
    total_done = len(completed_tasks) + len(failed_tasks)
    if total_done:
        success_rate = round((len(completed_tasks) / total_done) * 100, 1)
    elif reports:
        success_rate = 100.0
    else:
        success_rate = 0.0
    daily_avg = round(sum(day["total"] for day in trend) / len(trend), 1) if trend else 0.0

    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "task_stats": {
            "total_tasks": max(len(tasks), len(reports)),
            "completed_tasks": max(len(completed_tasks), len(reports)),
            "failed_tasks": len(failed_tasks),
            "running_tasks": len(running_tasks),
            "queued_tasks": len(queued_tasks),
            "daily_avg": daily_avg,
            "success_rate": success_rate,
            "avg_scan_seconds": round(sum(durations) / len(durations), 2) if durations else 0.0,
        },
        "vulnerability_stats": {
            "total": len(vulnerability_rows),
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
            "info": severity_counter.get("info", 0),
            "by_status": dict(status_counter),
            "top_cves": [
                {
                    "id": cve_id,
                    "count": count,
                    "severity": _severity_from_patch_status(
                        next((v.get("status") for v in vulnerability_rows if v.get("cve_id") == cve_id), "UNKNOWN")
                    ),
                }
                for cve_id, count in cve_counter.most_common(8)
            ],
        },
        "library_stats": {
            "total_libraries": len(library_rows),
            "unique_libraries": len(library_counter),
            "target_class_count": target_class_count,
            "top_libraries": [
                {
                    "name": name,
                    "count": count,
                    "vulnerability_count": vulnerable_library_counter.get(name, 0),
                }
                for name, count in library_counter.most_common(8)
            ],
        },
        "engine_stats": {
            "patch_evidence_count": patch_evidence_count,
            "semantic_matches": sum(
                1
                for vuln in vulnerability_rows
                if vuln.get("pre_similarity") is not None or vuln.get("post_similarity") is not None
            ),
            "resource_limited": status_counter.get("RESOURCE_LIMIT", 0),
            "unknown_results": sum(status_counter.get(status, 0) for status in ("UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT")),
        },
        "trend": trend,
    }


@app.delete("/api/history")
def clear_history(db: Session = Depends(get_db)) -> dict:
    report_count = db.query(VulnerabilityReport).count()
    task_count = db.query(AnalysisTask).count()
    db.query(VulnerabilityReport).delete(synchronize_session=False)
    db.query(AnalysisTask).delete(synchronize_session=False)
    db.commit()

    deleted_files = 0
    for root in (
        settings.report_dir,
        settings.project_root / "outputs" / "reports",
        settings.log_dir,
        settings.project_root / "outputs" / "logs",
    ):
        deleted_files += _delete_files_under(root)

    return {
        "message": "History cleared",
        "deleted_tasks": task_count,
        "deleted_reports": report_count,
        "deleted_files": deleted_files,
    }


@app.get("/api/ecosystem/summary")
def ecosystem_summary() -> dict:
    return build_ecosystem_summary()


@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...)) -> dict:
    filename = _sanitize_filename(file.filename or "")
    if Path(filename).suffix.lower() != ".apk":
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    destination = (settings.upload_dir / filename).resolve()
    if destination.parent != settings.upload_dir.resolve():
        raise HTTPException(status_code=400, detail="Invalid upload path")

    with destination.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)

    await file.close()
    apk_profile = profile_apk_for_estimate(destination)
    scan_estimate = estimate_scan_duration(apk_profile, settings.storage_dir / "scan_estimate_calibration.json")
    return {
        "message": "Upload successful",
        "filename": filename,
        "path": str(destination),
        "size": destination.stat().st_size,
        "apk_profile": apk_profile,
        "scan_estimate": scan_estimate,
    }


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    if not request.filename:
        raise HTTPException(status_code=400, detail="filename is required")
    apk_path = _resolve_apk_path(request.filename)
    task = _enqueue_analysis(db, apk_path, request.user_id)
    return {
        "message": "Analysis queued",
        "task": _serialize_task(task),
    }


@app.get("/api/task/{task_id}")
@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, db: Session = Depends(get_db)) -> dict:
    task = db.get(AnalysisTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task": _serialize_task(task)}


@app.get("/api/tasks/{task_id}/report")
def get_task_report(task_id: str, db: Session = Depends(get_db)) -> dict:
    task = db.get(AnalysisTask, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != "completed":
        raise HTTPException(status_code=409, detail=f"Task not completed, current status: {task.status}")

    report = task.report
    if report and report.report_json is not None:
        report_json = _refresh_report_intelligence(report.report_json)
        return {
            "task_id": task.id,
            "report_path": report.report_path,
            "report": report_json,
        }

    report_path = Path(task.report_path) if task.report_path else None
    if not report_path:
        raise HTTPException(status_code=404, detail="Report path missing")

    report_json = _refresh_report_intelligence(_read_json_file(report_path))
    return {
        "task_id": task.id,
        "report_path": str(report_path),
        "report": report_json,
    }


@app.get("/api/report")
def get_report(
    task_id: Optional[str] = None,
    apk_name: Optional[str] = None,
    db: Session = Depends(get_db),
) -> dict:
    selected_task: AnalysisTask | None = None
    report_path: Path | None = None

    if task_id:
        selected_task = db.get(AnalysisTask, task_id)
        if selected_task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        if not selected_task.report_path:
            raise HTTPException(status_code=404, detail="Report not ready")
        report_path = Path(selected_task.report_path)
    elif apk_name:
        safe_name = _sanitize_filename(apk_name)
        report_path = settings.report_dir / f"{safe_name}_vuln_report.json"
    else:
        selected_task = _latest_completed_task(db)
        if selected_task and selected_task.report_path:
            report_path = Path(selected_task.report_path)

    if report_path is None:
        raise HTTPException(status_code=404, detail="Report file not found")

    report_json = _read_json_file(report_path)
    report_json = _refresh_report_intelligence(report_json)

    existing = None
    if selected_task is not None:
        existing = selected_task.report
        if existing is None:
            existing = VulnerabilityReport(
                task_id=selected_task.id,
                report_path=str(report_path),
                report_json=report_json,
            )
            db.add(existing)
        else:
            existing.report_path = str(report_path)
            existing.report_json = report_json
        db.commit()

    return {
        "task_id": selected_task.id if selected_task else None,
        "report_path": str(report_path),
        "report": existing.report_json if existing else report_json,
    }


@app.post("/api/intelligence/analyze")
def analyze_intelligence(request: IntelligenceAnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    report_json: dict | None = request.report
    task_id = request.task_id

    if report_json is None and task_id:
        task = db.get(AnalysisTask, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        report_json = _task_report_json(task)
        if report_json is None:
            raise HTTPException(status_code=404, detail="Report not ready")

    if report_json is None:
        raise HTTPException(status_code=400, detail="task_id or report is required")

    artifacts = report_json.get("analysis_artifacts") if isinstance(report_json.get("analysis_artifacts"), dict) else {}
    intelligence = build_intelligence_artifact(report_json, artifacts)
    return {
        "task_id": task_id,
        "status": "ok",
        "intelligence": intelligence,
    }


@app.websocket("/api/logs")
async def websocket_logs(websocket: WebSocket, task_id: Optional[str] = None) -> None:
    await websocket.accept()

    if not task_id:
        await websocket.send_json({"type": "error", "message": "task_id is required"})
        await websocket.close(code=1008)
        return

    offsets: dict[str, int] = {}
    finished_idle_rounds = 0

    try:
        while True:
            with SessionLocal() as db:
                task = db.get(AnalysisTask, task_id)

            if task is None:
                await websocket.send_json({"type": "error", "message": f"Task not found: {task_id}"})
                await websocket.close(code=1008)
                return

            if not offsets:
                await websocket.send_json(
                    {
                        "type": "meta",
                        "task_id": task.id,
                        "apk_name": task.apk_name,
                        "status": task.status,
                    }
                )

            had_new_data = False
            for log_file in _candidate_log_files(task):
                key = str(log_file)
                prev = offsets.get(key, 0)
                try:
                    current_size = log_file.stat().st_size
                except OSError:
                    continue

                if current_size < prev:
                    prev = 0

                if current_size == prev:
                    continue

                with log_file.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(prev)
                    chunk = handle.read()
                    offsets[key] = handle.tell()

                if not chunk:
                    continue

                had_new_data = True
                for line in chunk.splitlines():
                    await websocket.send_json(
                        {
                            "type": "log",
                            "task_id": task.id,
                            "file": log_file.name,
                            "message": line,
                        }
                    )

            if task.status in {"completed", "failed"}:
                if had_new_data:
                    finished_idle_rounds = 0
                else:
                    finished_idle_rounds += 1
                if finished_idle_rounds >= 2:
                    await websocket.send_json(
                        {
                            "type": "done",
                            "task_id": task.id,
                            "status": task.status,
                            "error": task.error_message,
                            "report_path": task.report_path,
                        }
                    )
                    break

            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        return


if _frontend_dist.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=_frontend_dist / "assets"),
        name="frontend-assets",
    )


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    if full_path.startswith("api"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    if not _frontend_dist.exists():
        return JSONResponse(
            {"detail": "Frontend not built. Run `npm run build` in ./frontend first."},
            status_code=503,
        )

    target = (_frontend_dist / full_path).resolve()
    if full_path and target.exists() and target.is_file() and target.parent == _frontend_dist:
        return FileResponse(target)

    index_file = _frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"detail": "Frontend entrypoint not found."}, status_code=503)
