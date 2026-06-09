from __future__ import annotations

import hashlib
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from config import DEFAULT_PHUNTER_THREADS, LOG_DIR, MAX_PHUNTER_CONCURRENT
from engine.detector import prewarm_phunter_apk_cache, run_libhunter, run_phunter
from engine.intelligence import build_intelligence_artifact
from engine.kb_manager import KnowledgeBase
from engine.models import ApkContext, TPLibrary, Vulnerability

logger = logging.getLogger(__name__)


def _utc_iso() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _text_excerpt(text: str | None, *, max_lines: int = 80, max_chars: int = 12000) -> dict[str, Any]:
    lines = (text or "").splitlines()
    excerpt_lines = lines[-max_lines:] if len(lines) > max_lines else lines
    excerpt = "\n".join(excerpt_lines)
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
    return {
        "line_count": len(lines),
        "excerpt": excerpt,
        "truncated": len(lines) > max_lines or len(text or "") > max_chars,
    }


def _basename(path_text: str | None) -> str:
    return Path(path_text).name if path_text else ""


def _calc_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _get_apk_basic_info(apk_path: Path) -> dict:
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK path is not a file: {apk_path}")
    stat = apk_path.stat()
    return {
        "name": apk_path.name,
        "path": str(apk_path),
        "file_size": stat.st_size,
        "sha256": _calc_sha256(apk_path),
    }


class AndroidVulnScanner:

    def __init__(self, apk_path: str | Path):
        self.apk_path = Path(apk_path).expanduser().resolve()
        if not self.apk_path.exists():
            raise FileNotFoundError(f"找不到目标 APK: {self.apk_path}")

        raw_info = _get_apk_basic_info(self.apk_path)
        self.context = ApkContext(
            path=raw_info["path"],
            name=raw_info["name"],
            sha256=raw_info["sha256"],
            file_size=raw_info["file_size"],
        )
        self.apk_info = raw_info
        self.kb = KnowledgeBase()
        self._phunter_semaphore = threading.Semaphore(MAX_PHUNTER_CONCURRENT)
        self._artifact_lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        self._stages: dict[str, dict[str, Any]] = {}
        self._stage_order: list[str] = []
        self._analysis_started_at = _utc_iso()
        self._analysis_finished_at: str | None = None
        self._libhunter_artifact: dict[str, Any] = {}
        self._phunter_artifact: dict[str, Any] = {
            "routing": {
                "raw_task_count": 0,
                "deduped_task_count": 0,
                "merged_duplicate_count": 0,
            },
            "apk_prewarm": None,
            "verifications": [],
        }
        self._apk_profile: dict[str, Any] = self._load_apk_profile()

    def scan(self) -> Dict[str, Any]:
        self._begin_stage("init", "初始化分析任务")
        print(
            f"[*] 初始化分析任务: {self.context.name} "
            f"(SHA256: {self.context.sha256[:8]}...)"
        )
        self._finish_stage(
            "init",
            summary=f"APK={self.context.name}, sha256={self.context.sha256}",
            metrics={"apk_size": self.context.file_size},
        )
        self._detect_libraries()
        self._verify_patches()
        self._begin_stage("report", "汇总诊断报告")
        report = self._generate_report()
        self._finish_stage(
            "report",
            summary="报告已汇总",
            metrics={
                "library_count": len(report.get("used_libraries", [])),
                "vulnerability_count": len(report.get("vulnerabilities", [])),
            },
        )
        self._analysis_finished_at = _utc_iso()
        report["analysis_artifacts"] = self._build_analysis_artifacts(report)
        return report

    def _record_event(
        self,
        event_type: str,
        message: str,
        *,
        stage: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "time": _utc_iso(),
            "type": event_type,
            "stage": stage,
            "message": message,
            "payload": payload or {},
        }
        with self._artifact_lock:
            self._events.append(event)

    def _begin_stage(self, key: str, label: str) -> None:
        now = _utc_iso()
        with self._artifact_lock:
            if key not in self._stage_order:
                self._stage_order.append(key)
            self._stages[key] = {
                "key": key,
                "label": label,
                "status": "running",
                "started_at": now,
                "finished_at": None,
                "summary": "",
                "metrics": {},
            }
        self._record_event("stage_started", label, stage=key)

    def _finish_stage(
        self,
        key: str,
        *,
        status: str = "completed",
        summary: str = "",
        metrics: dict[str, Any] | None = None,
    ) -> None:
        with self._artifact_lock:
            stage = self._stages.setdefault(
                key,
                {
                    "key": key,
                    "label": key,
                    "started_at": None,
                },
            )
            stage.update({
                "status": status,
                "finished_at": _utc_iso(),
                "summary": summary,
                "metrics": metrics or {},
            })
        self._record_event("stage_finished", summary or key, stage=key, payload={"status": status})

    def _summarize_command_result(self, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": result.get("status"),
            "returncode": result.get("returncode"),
            "hung": bool(result.get("hung")),
            "timed_out": bool(result.get("timed_out")),
            "cmd": result.get("cmd", []),
            "stdout": _text_excerpt(result.get("raw_stdout")),
            "stderr": _text_excerpt(result.get("raw_stderr")),
        }

    def _build_patch_evidence(
        self,
        lib: TPLibrary,
        vuln: Vulnerability,
        patch_result: dict[str, Any],
    ) -> dict[str, Any]:
        target_classes = patch_result.get("target_classes") or lib.target_classes
        return {
            "source": "PHunter",
            "library": {
                "raw_name": lib.raw_name,
                "name": lib.normalized_name,
                "version": lib.version,
                "similarity": lib.similarity,
            },
            "resources": {
                "pre_patch_jar": vuln.pre_patch_jar,
                "post_patch_jar": vuln.post_patch_jar,
                "patch_diff": vuln.patch_diff,
                "pre_patch_artifact": _basename(vuln.pre_patch_jar),
                "post_patch_artifact": _basename(vuln.post_patch_jar),
                "patch_diff_artifact": _basename(vuln.patch_diff),
            },
            "target_scope": {
                "source": "LibHunter target_classes",
                "class_count": len(target_classes),
                "classes_sample": list(target_classes[:40]),
            },
            "verification": {
                "status": patch_result.get("status"),
                "patch_status": patch_result.get("patch_status"),
                "returncode": patch_result.get("returncode"),
                "retried": bool(patch_result.get("retried")),
                "patch_related_method_count": patch_result.get("patch_related_method_count"),
                "pre_similarity": patch_result.get("pre_similarity"),
                "post_similarity": patch_result.get("post_similarity"),
            },
            "execution": {
                "cmd": patch_result.get("cmd", []),
                "stdout": _text_excerpt(patch_result.get("raw_stdout")),
                "stderr": _text_excerpt(patch_result.get("raw_stderr")),
            },
        }

    def _load_apk_profile(self) -> dict[str, Any]:
        profile_path = LOG_DIR / f"apk_profile_{Path(self.context.path).stem}.json"
        if not profile_path.exists():
            return {}
        try:
            return json.loads(profile_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("Failed to read APK profile: %s", profile_path, exc_info=True)
            return {}

    def _resolve_phunter_limits(
        self,
        tasks: list[tuple[TPLibrary, Vulnerability, list[tuple[TPLibrary, Vulnerability]]]],
    ) -> tuple[int, int, str]:
        profile = self._apk_profile or {}
        risk_level = str(profile.get("risk_level") or "UNKNOWN").upper()
        class_defs = int(profile.get("class_defs") or 0)
        method_ids = int(profile.get("method_ids") or 0)
        dex_count = int(profile.get("dex_count") or 0)
        target_class_total = sum(len(lib.target_classes or []) for lib, _, _ in tasks)

        concurrency = max(1, MAX_PHUNTER_CONCURRENT)
        thread_num = max(1, DEFAULT_PHUNTER_THREADS)
        reason = "configured defaults"

        is_extreme = (
            risk_level == "EXTREME"
            or class_defs >= 20000
            or method_ids >= 150000
            or dex_count >= 4
        )
        is_heavy = (
            is_extreme
            or risk_level == "HIGH"
            or target_class_total >= 80
            or self.context.file_size >= 15 * 1024 * 1024
        )

        if is_extreme:
            concurrency = 1
            thread_num = 1
            reason = "EXTREME APK profile/resource guard"
        elif is_heavy:
            concurrency = min(concurrency, 1)
            thread_num = min(thread_num, 2)
            reason = "heavy APK/resource guard"

        return concurrency, thread_num, reason

    def _detect_libraries(self) -> None:
        self._begin_stage("libhunter", "LibHunter 第三方库识别")
        print("[*] 阶段一: 识别第三方库组件 (基于 LibHunter) ...")
        lib_result = run_libhunter(self.context.path)
        detections = lib_result.get("detections", [])
        self._libhunter_artifact = {
            "status": lib_result.get("status"),
            "returncode": lib_result.get("returncode"),
            "cmd": lib_result.get("cmd", []),
            "result_file": lib_result.get("result_file"),
            "detection_count": len(detections),
            "stdout": _text_excerpt(lib_result.get("raw_stdout")),
            "stderr": _text_excerpt(lib_result.get("raw_stderr")),
            "detections": [
                {
                    "raw_lib": det.get("raw_lib", ""),
                    "library_name": det.get("library_name", ""),
                    "detected_version": det.get("detected_version", ""),
                    "similarity": det.get("similarity", 0.0),
                    "target_class_count": len(det.get("target_classes", []) or []),
                    "target_classes_sample": list((det.get("target_classes", []) or [])[:24]),
                }
                for det in detections
            ],
        }

        if lib_result["status"] == "hung":
            print(
                "[-] LibHunter 心跳超时（长时间无输出），已强制终止。"
                "本次检测跳过库识别阶段，不影响后续流程。"
            )
            logger.warning("LibHunter hung for APK: %s", self.context.name)
            self._finish_stage(
                "libhunter",
                status="hung",
                summary="LibHunter 心跳超时，库识别阶段未完成",
                metrics={"detection_count": 0},
            )
            return

        if lib_result["status"] not in ("success", "no_detections"):
            print(f"[-] 组件识别异常，状态: {lib_result['status']}")
            self._finish_stage(
                "libhunter",
                status="failed",
                summary=f"LibHunter 状态异常: {lib_result['status']}",
                metrics={"detection_count": 0},
            )
            return

        for det in detections:
            lib = TPLibrary(
                raw_name=det.get("raw_lib", ""),
                normalized_name=det.get("library_name", ""),
                version=det.get("detected_version", ""),
                similarity=det.get("similarity", 0.0),
                target_classes=det.get("target_classes", []),
                evidence={
                    "source": "LibHunter",
                    "target_class_count": len(det.get("target_classes", []) or []),
                    "target_classes_sample": list((det.get("target_classes", []) or [])[:24]),
                    "raw_detection": {
                        "raw_lib": det.get("raw_lib", ""),
                        "library_name": det.get("library_name", ""),
                        "detected_version": det.get("detected_version", ""),
                        "similarity": det.get("similarity", 0.0),
                    },
                },
            )
            self.kb.match_cves(lib)
            self.context.libraries.append(lib)

        print(f"    -> 成功提取 {len(self.context.libraries)} 个组件特征")
        self._finish_stage(
            "libhunter",
            summary=f"成功提取 {len(self.context.libraries)} 个组件特征",
            metrics={
                "detection_count": len(self.context.libraries),
                "matched_cve_count": sum(len(lib.vulnerabilities) for lib in self.context.libraries),
            },
        )

    def _verify_patches(self) -> None:
        self._begin_stage("phunter", "PHunter 漏洞补丁验证")
        print("[*] 阶段二: 漏洞情报路由与补丁确诊 (基于 PHunter) ...")

        grouped_tasks: dict[
            tuple[str, str],
            list[tuple[TPLibrary, Vulnerability]],
        ] = {}
        raw_task_count = 0
        for lib in self.context.libraries:
            for vuln in lib.vulnerabilities:
                raw_task_count += 1
                key = (
                    (lib.normalized_name or "").strip().lower(),
                    (vuln.cve_id or "").strip().upper(),
                )
                grouped_tasks.setdefault(key, []).append((lib, vuln))

        tasks: list[tuple[TPLibrary, Vulnerability, list[tuple[TPLibrary, Vulnerability]]]] = []
        for members in grouped_tasks.values():
            # 同库同 CVE 仅选最高相似度候选做一次 PHunter 验证，避免重复 JVM。
            rep_lib, rep_vuln = max(members, key=lambda item: item[0].similarity)
            tasks.append((rep_lib, rep_vuln, members))

        total_vulns = len(tasks)
        self._phunter_artifact["routing"] = {
            "raw_task_count": raw_task_count,
            "deduped_task_count": total_vulns,
            "merged_duplicate_count": raw_task_count - total_vulns,
            "groups": [
                {
                    "library": members[0][0].normalized_name if members else "",
                    "cve_id": members[0][1].cve_id if members else "",
                    "candidate_count": len(members),
                    "selected_version": max(members, key=lambda item: item[0].similarity)[0].version if members else "",
                }
                for members in grouped_tasks.values()
            ],
        }
        if total_vulns == 0:
            print("    -> 当前组件均未命中已知 CVE 情报，无需打补丁，分析结束。")
            self._finish_stage(
                "phunter",
                summary="当前组件均未命中已知 CVE 情报",
                metrics={"raw_task_count": raw_task_count, "deduped_task_count": 0},
            )
            return

        deduped = raw_task_count - total_vulns
        if deduped > 0:
            print(f"    -> 任务去重: {raw_task_count} -> {total_vulns}（合并 {deduped} 个重复项）")

        phunter_concurrency, phunter_thread_num, phunter_limit_reason = self._resolve_phunter_limits(tasks)
        self._phunter_artifact["resource_policy"] = {
            "configured_max_concurrent": MAX_PHUNTER_CONCURRENT,
            "configured_default_threads": DEFAULT_PHUNTER_THREADS,
            "effective_concurrent": phunter_concurrency,
            "effective_thread_num": phunter_thread_num,
            "reason": phunter_limit_reason,
            "apk_profile": self._apk_profile,
        }

        print("    -> 单进程预热 APK 全量 Soot 缓存（threadNum=1）...")
        prewarm_result = prewarm_phunter_apk_cache(self.context.path)
        self._phunter_artifact["apk_prewarm"] = self._summarize_command_result(prewarm_result)
        self._phunter_artifact["apk_prewarm"]["scope_label"] = prewarm_result.get("scope_label", "full")
        prewarm_status = prewarm_result.get("status", "failed")
        if prewarm_status != "success":
            logger.warning(
                "PHunter full APK prewarm failed for APK %s: %s",
                self.context.name,
                prewarm_result.get("reason") or prewarm_result.get("returncode"),
            )
        print(f"    -> APK 全量 Soot 缓存预热完成: status={prewarm_status}.")

        print(
            f"    -> 命中 {total_vulns} 个疑似漏洞记录，"
            f"并发校验（有效 {phunter_concurrency}/{MAX_PHUNTER_CONCURRENT} 个 JVM，"
            f"threadNum={phunter_thread_num}，{phunter_limit_reason}）..."
        )

        def _run_one(
            lib: TPLibrary,
            vuln: Vulnerability,
            members: list[tuple[TPLibrary, Vulnerability]],
        ) -> None:
            cve_meta = {
                "cve_id": vuln.cve_id,
                "pre_patch_jar": vuln.pre_patch_jar,
                "post_patch_jar": vuln.post_patch_jar,
                "patch_diff": vuln.patch_diff,
                "thread_num": phunter_thread_num,
            }
            with phunter_semaphore:
                print(
                    f"      - 验证 [{lib.normalized_name}] 的漏洞: "
                    f"{vuln.cve_id} ..."
                )
                try:
                    patch_result = run_phunter(
                        str(self.context.path),
                        cve_meta,
                        target_classes=lib.target_classes,
                    )

                    if patch_result.get("status") == "resource_limited":
                        print(
                            f"      [!] PHunter 资源受限或超时，"
                            f"CVE {vuln.cve_id} 标记为 RESOURCE_LIMIT。"
                        )
                        logger.warning(
                            "PHunter resource limit for CVE %s / APK %s",
                            vuln.cve_id, self.context.name,
                        )

                    vuln.patch_status = patch_result.get("patch_status", "UNKNOWN")
                    vuln.pre_similarity = patch_result.get("pre_similarity")
                    vuln.post_similarity = patch_result.get("post_similarity")
                    vuln.evidence = self._build_patch_evidence(lib, vuln, patch_result)
                    with self._artifact_lock:
                        self._phunter_artifact["verifications"].append({
                            "cve_id": vuln.cve_id,
                            "library": lib.normalized_name,
                            "version": lib.version,
                            "status": patch_result.get("status"),
                            "patch_status": vuln.patch_status,
                            "pre_similarity": vuln.pre_similarity,
                            "post_similarity": vuln.post_similarity,
                            "patch_related_method_count": patch_result.get("patch_related_method_count"),
                            "target_class_count": len(patch_result.get("target_classes") or []),
                            "retried": bool(patch_result.get("retried")),
                            "hung": bool(patch_result.get("hung")),
                            "timed_out": bool(patch_result.get("timed_out")),
                        })
                    for _, member_vuln in members:
                        member_vuln.patch_status = vuln.patch_status
                        member_vuln.pre_similarity = vuln.pre_similarity
                        member_vuln.post_similarity = vuln.post_similarity
                        member_vuln.evidence = dict(vuln.evidence)

                except Exception as exc:
                    print(f"      [!] 验证过程执行出错: {exc}")
                    logger.exception(
                        "PHunter error for CVE %s / APK %s",
                        vuln.cve_id, self.context.name,
                    )
                    vuln.patch_status = "ERROR"
                    vuln.evidence = {
                        "source": "PHunter",
                        "library": {
                            "raw_name": lib.raw_name,
                            "name": lib.normalized_name,
                            "version": lib.version,
                            "similarity": lib.similarity,
                        },
                        "resources": {
                            "pre_patch_jar": vuln.pre_patch_jar,
                            "post_patch_jar": vuln.post_patch_jar,
                            "patch_diff": vuln.patch_diff,
                        },
                        "target_scope": {
                            "source": "LibHunter target_classes",
                            "class_count": len(lib.target_classes),
                            "classes_sample": list(lib.target_classes[:40]),
                        },
                        "verification": {
                            "status": "failed",
                            "patch_status": "ERROR",
                            "error": str(exc),
                        },
                    }
                    with self._artifact_lock:
                        self._phunter_artifact["verifications"].append({
                            "cve_id": vuln.cve_id,
                            "library": lib.normalized_name,
                            "version": lib.version,
                            "status": "failed",
                            "patch_status": "ERROR",
                            "error": str(exc),
                            "target_class_count": len(lib.target_classes),
                        })
                    for _, member_vuln in members:
                        member_vuln.patch_status = "ERROR"
                        member_vuln.evidence = dict(vuln.evidence)

        phunter_semaphore = threading.Semaphore(phunter_concurrency)
        with ThreadPoolExecutor(max_workers=phunter_concurrency) as executor:
            futures = {
                executor.submit(_run_one, lib, vuln, members): (lib, vuln)
                for lib, vuln, members in tasks
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    lib, vuln = futures[future]
                    logger.error(
                        "Unexpected future error for CVE %s: %s",
                        vuln.cve_id, exc,
                    )
        verification_statuses = [
            item.get("status")
            for item in self._phunter_artifact.get("verifications", [])
        ]
        failed_count = sum(1 for status in verification_statuses if status not in {"success"})
        self._finish_stage(
            "phunter",
            status="completed" if failed_count == 0 else "partial",
            summary=f"完成 {len(verification_statuses)} 个补丁验证任务",
            metrics={
                "raw_task_count": raw_task_count,
                "deduped_task_count": total_vulns,
                "failed_count": failed_count,
                "max_concurrent": MAX_PHUNTER_CONCURRENT,
            },
        )

    def _generate_report(self) -> Dict[str, Any]:
        print("[*] 阶段三: 汇总诊断报告 ...")
        used_libraries: list[dict] = []
        vulnerabilities: list[dict] = []
        seen_vuln_keys: set[tuple[str, str]] = set()

        for lib in self.context.libraries:
            used_libraries.append({
                "raw_name": lib.raw_name,
                "library_name": lib.normalized_name,
                "version": lib.version,
                "similarity": lib.similarity,
                "target_classes": list(lib.target_classes),
                "evidence": lib.evidence,
            })
            for vuln in lib.vulnerabilities:
                vuln_key = (
                    (lib.normalized_name or "").strip().lower(),
                    (vuln.cve_id or "").strip().upper(),
                )
                if vuln_key in seen_vuln_keys:
                    continue
                seen_vuln_keys.add(vuln_key)
                vulnerabilities.append({
                    "cve_id": vuln.cve_id,
                    "library": lib.normalized_name,
                    "status": vuln.patch_status,
                    "pre_similarity": vuln.pre_similarity,
                    "post_similarity": vuln.post_similarity,
                    "evidence": vuln.evidence,
                })

        return {
            "apk_info": {
                "name": self.context.name,
                "sha256": self.context.sha256,
                "size": self.context.file_size,
            },
            "used_libraries": used_libraries,
            "vulnerabilities": vulnerabilities,
        }

    def _build_analysis_artifacts(self, report: dict[str, Any]) -> dict[str, Any]:
        stages = [self._stages[key] for key in self._stage_order if key in self._stages]
        status_counts: dict[str, int] = {}
        for vuln in report.get("vulnerabilities", []):
            status = str(vuln.get("status") or "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1

        library_evidence = [
            {
                "library": lib.get("library_name"),
                "version": lib.get("version"),
                "similarity": lib.get("similarity"),
                "target_class_count": len(lib.get("target_classes") or []),
                "target_classes_sample": list((lib.get("target_classes") or [])[:24]),
                "matched_cve_count": sum(
                    1
                    for vuln in report.get("vulnerabilities", [])
                    if vuln.get("library") == lib.get("library_name")
                ),
            }
            for lib in report.get("used_libraries", [])
        ]

        patch_evidence = [
            {
                "cve_id": vuln.get("cve_id"),
                "library": vuln.get("library"),
                "status": vuln.get("status"),
                "pre_similarity": vuln.get("pre_similarity"),
                "post_similarity": vuln.get("post_similarity"),
                "evidence": vuln.get("evidence") or {},
            }
            for vuln in report.get("vulnerabilities", [])
        ]

        artifacts = {
            "schema_version": 1,
            "generated_at": _utc_iso(),
            "analysis_started_at": self._analysis_started_at,
            "analysis_finished_at": self._analysis_finished_at,
            "execution_trace": {
                "stages": stages,
                "events": list(self._events),
            },
            "engines": {
                "libhunter": self._libhunter_artifact,
                "phunter": self._phunter_artifact,
                "semantic_engine": {
                    "status": "materialized",
                    "source": "PHunter semantic patch verification",
                    "patch_evidence_count": len(patch_evidence),
                    "note": "当前语义证据来自确定性 PHunter 分析；LLM 智能体可在此 evidence 基础上做规划与诊断。",
                },
            },
            "evidence": {
                "libraries": library_evidence,
                "patches": patch_evidence,
            },
            "summary": {
                "library_count": len(report.get("used_libraries", [])),
                "vulnerability_count": len(report.get("vulnerabilities", [])),
                "patch_status_counts": status_counts,
                "patch_evidence_count": len(patch_evidence),
                "target_class_count": sum(item.get("target_class_count", 0) for item in library_evidence),
            },
        }
        artifacts["intelligence"] = build_intelligence_artifact(report, artifacts)
        return artifacts
