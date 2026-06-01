from __future__ import annotations

import json
import logging
import os
import select as select_module
import subprocess
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from backend.celery_app import celery_app
from backend.db import SessionLocal, init_db
from backend.models import AnalysisTask, VulnerabilityReport
from backend.settings import settings

init_db()
logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _load_report(report_path: Path) -> dict | None:
    if not report_path.exists() or not report_path.is_file():
        return None
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _upsert_task_report(
    db,
    task: AnalysisTask,
    report_path: Path,
    report_json: dict,
) -> None:
    task.status = "completed"
    task.report_path = str(report_path)
    task.error_message = None
    task.finished_at = _utcnow()

    report = task.report
    if report is None:
        report = VulnerabilityReport(
            task_id=task.id,
            report_path=str(report_path),
            report_json=report_json,
        )
        db.add(report)
    else:
        report.report_path = str(report_path)
        report.report_json = report_json


def _materialize_google_hot_app_report(task: AnalysisTask, report_json: dict) -> Path:
    report_path = settings.report_dir / f"{Path(task.apk_name).name}_vuln_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report_json, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    return report_path


def _find_google_hot_app_report(db, task: AnalysisTask) -> tuple[Path, dict] | None:
    apk_name = Path(task.apk_name).name
    apk_name_key = apk_name.casefold()

    stmt = (
        select(AnalysisTask)
        .where(
            AnalysisTask.status == "completed",
            AnalysisTask.id != task.id,
            AnalysisTask.report_path.is_not(None),
        )
        .order_by(AnalysisTask.finished_at.desc(), AnalysisTask.created_at.desc())
    )
    for previous_task in db.scalars(stmt):
        if Path(previous_task.apk_name).name.casefold() != apk_name_key:
            continue
        if previous_task.report and previous_task.report.report_json is not None:
            report_path = Path(previous_task.report.report_path)
            if report_path.exists() and report_path.is_file():
                return report_path, previous_task.report.report_json
            return _materialize_google_hot_app_report(task, previous_task.report.report_json), previous_task.report.report_json
        if previous_task.report_path:
            report_path = Path(previous_task.report_path)
            report_json = _load_report(report_path)
            if report_json is not None:
                return report_path, report_json

    expected_report_name = f"{apk_name}_vuln_report.json"
    report_candidates = [
        settings.report_dir / expected_report_name,
        settings.project_root / "outputs" / "reports" / expected_report_name,
    ]
    for report_dir in (settings.report_dir, settings.project_root / "outputs" / "reports"):
        if report_dir.exists() and report_dir.is_dir():
            report_candidates.extend(
                path
                for path in report_dir.glob("*_vuln_report.json")
                if path.name.casefold() == expected_report_name.casefold()
            )
    for report_path in report_candidates:
        report_json = _load_report(report_path)
        if report_json is not None:
            return report_path, report_json

    return None


def _build_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHON_BIN"] = settings.python_bin
    env["JAVA_BIN"] = settings.java_bin
    env["ANDROID_JAR_PATH"] = str(settings.android_jar_path)
    env["PHUNTER_JAR_PATH"] = str(settings.phunter_jar_path)
    env["PHUNTER_CACHE_DIR"] = str(settings.phunter_cache_dir)
    env["UPLOAD_DIR"] = str(settings.upload_dir)
    env["REPORT_DIR"] = str(settings.report_dir)
    env["LOG_DIR"] = str(settings.log_dir)
    env.setdefault("STORAGE_DIR", str(settings.storage_dir))
    return env


def _run_scanner_with_live_logs(cmd: list[str], stdout_log: Path, stderr_log: Path) -> int:
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    stderr_log.parent.mkdir(parents=True, exist_ok=True)

    with stdout_log.open("w", encoding="utf-8", errors="replace") as stdout_file, stderr_log.open(
        "w",
        encoding="utf-8",
        errors="replace",
    ) as stderr_file:
        process = subprocess.Popen(
            cmd,
            cwd=str(settings.project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_build_subprocess_env(),
            bufsize=1,
        )

        streams = {
            process.stdout.fileno(): (process.stdout, stdout_file) if process.stdout else None,
            process.stderr.fileno(): (process.stderr, stderr_file) if process.stderr else None,
        }
        streams = {fd: pair for fd, pair in streams.items() if pair is not None}

        while streams:
            ready, _, _ = select_module.select(list(streams.keys()), [], [], 0.5)
            if not ready and process.poll() is not None:
                ready = list(streams.keys())

            for fd in ready:
                stream, target = streams[fd]
                line = stream.readline()
                if line:
                    target.write(line)
                    target.flush()
                else:
                    streams.pop(fd, None)

            if process.poll() is None:
                continue

            # Give pipes one last pass before leaving the loop.
            if not ready:
                time.sleep(0.05)

        return process.wait()


@celery_app.task(name="backend.tasks.run_analysis_task", bind=True)
def run_analysis_task(self, task_id: str, apk_path: str) -> dict:
    db = SessionLocal()
    try:
        task = db.get(AnalysisTask, task_id)
        if task is None:
            return {"status": "missing", "task_id": task_id}

        stdout_log = settings.log_dir / f"task_{task_id}.stdout.log"
        stderr_log = settings.log_dir / f"task_{task_id}.stderr.log"
        task.stdout_log_path = str(stdout_log)
        task.stderr_log_path = str(stderr_log)
        task.status = "running"
        task.started_at = _utcnow()
        db.commit()

        google_hot_app_report = _find_google_hot_app_report(db, task)
        if google_hot_app_report is not None:
            _, report_json = google_hot_app_report
            report_path = _materialize_google_hot_app_report(task, report_json)
            stdout_log.write_text("", encoding="utf-8")
            stderr_log.write_text("", encoding="utf-8")
            _upsert_task_report(db, task, report_path, report_json)
            db.commit()
            logger.info(
                "google_hot_app cache hit for task %s apk=%s report=%s",
                task_id,
                task.apk_name,
                report_path,
            )
            return {
                "status": task.status,
                "task_id": task_id,
                "report_path": str(report_path),
                "vulnerability_count": len(report_json.get("vulnerabilities", [])),
                "cache": "google_hot_app",
            }

        cmd = [settings.python_bin, "main.py", "--apk", apk_path]
        logger.info("Starting scan task %s with command: %s", task_id, " ".join(cmd))
        returncode = _run_scanner_with_live_logs(cmd, stdout_log, stderr_log)
        logger.info("Finished scan task %s, returncode=%s", task_id, returncode)

        if returncode != 0:
            task.status = "failed"
            task.error_message = (
                f"Scanner exited with code {returncode}. "
                f"See logs: {stdout_log.name}, {stderr_log.name}"
            )
            task.finished_at = _utcnow()
            db.commit()
            return {
                "status": task.status,
                "task_id": task_id,
                "returncode": returncode,
            }

        report_path = settings.report_dir / f"{Path(apk_path).name}_vuln_report.json"
        if not report_path.exists():
            legacy_report = settings.project_root / "outputs" / "reports" / f"{Path(apk_path).name}_vuln_report.json"
            if legacy_report.exists():
                report_path = legacy_report

        report_json = _load_report(report_path)
        if report_json is None:
            task.status = "failed"
            task.error_message = f"Report not found or invalid JSON: {report_path}"
            task.finished_at = _utcnow()
            db.commit()
            return {"status": task.status, "task_id": task_id}

        _upsert_task_report(db, task, report_path, report_json)

        db.commit()
        return {
            "status": task.status,
            "task_id": task_id,
            "report_path": str(report_path),
            "vulnerability_count": len(report_json.get("vulnerabilities", [])),
        }
    except Exception as exc:
        task = db.get(AnalysisTask, task_id)
        if task is not None:
            task.status = "failed"
            task.error_message = str(exc)
            task.finished_at = _utcnow()
            db.commit()
        raise
    finally:
        db.close()
