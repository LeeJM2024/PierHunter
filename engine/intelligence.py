from __future__ import annotations

import os
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib import error, request

from config import BASE_DIR, CVE_KB_PATH


def _load_local_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")


_load_local_env_file()


def _utc_iso() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _status_counts(vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for vuln in vulnerabilities:
        status = str(vuln.get("status") or "UNKNOWN").upper()
        counts[status] = counts.get(status, 0) + 1
    return counts


def _confidence_from_status(status: str) -> float:
    normalized = status.upper()
    if normalized in {"PATCH_PRESENT", "NOT_PRESENT"}:
        return 0.86
    if normalized in {"PRESENT", "PATCH_NOT_PRESENT"}:
        return 0.78
    if normalized == "DEAD_CODE":
        return 0.72
    if normalized in {"UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT"}:
        return 0.38
    return 0.5


def _artifact_name(path_text: Any) -> str:
    if not path_text:
        return ""
    return Path(str(path_text)).name


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _library_key(value: Any) -> str:
    text = _normalize_text(value).replace("_", "-")
    return text.replace(":", ".")


def _library_purpose(library: str) -> str:
    key = _library_key(library)
    rules = [
        (("junrar",), "用于读取和解压 RAR 压缩文件，常见于漫画、文件管理、归档处理等场景。"),
        (("commons-compress",), "Apache Commons Compress 用于处理 ZIP、TAR、RAR、7z 等压缩归档格式。"),
        (("commons-beanutils",), "Apache Commons BeanUtils 用于 Java Bean 属性访问、对象属性拷贝和反射式数据绑定。"),
        (("commons-io",), "Apache Commons IO 用于文件、流、目录遍历和 IO 工具函数。"),
        (("commons-codec",), "Apache Commons Codec 用于 Base64、Hex、URL 编码、摘要和常见编解码处理。"),
        (("commons-lang", "commons-lang3"), "Apache Commons Lang 提供字符串、集合、反射、异常等 Java 基础工具方法。"),
        (("guava",), "Google Guava 是 Java 常用基础工具库，提供集合、缓存、并发、字符串和函数式辅助能力。"),
        (("jackson",), "Jackson 用于 JSON 序列化和反序列化，常见于接口数据解析和对象映射。"),
        (("gson",), "Gson 用于 JSON 序列化和反序列化，常见于 Android 网络响应解析。"),
        (("okhttp",), "OkHttp 是 Android/Java 常用 HTTP 客户端，用于网络请求、连接池和 TLS 通信。"),
        (("retrofit",), "Retrofit 是 Android/Java 常用 REST API 客户端，通常基于 OkHttp 封装接口调用。"),
        (("kotlin-stdlib",), "Kotlin 标准库提供 Kotlin 语言运行所需的集合、字符串、协程基础辅助和扩展函数。"),
        (("room-runtime", "androidx.room"), "AndroidX Room 用于 SQLite 数据库访问、实体映射和本地持久化。"),
        (("protobuf",), "Protocol Buffers 用于结构化数据序列化，常见于网络协议和本地数据交换。"),
        (("log4j",), "Log4j 是 Java 日志框架，用于应用日志记录、格式化和输出管理。"),
        (("logback",), "Logback 是 Java 日志框架，常作为 SLF4J 的日志实现。"),
        (("bouncycastle", "bcprov"), "Bouncy Castle 是密码学库，提供加密、签名、证书和安全协议相关能力。"),
        (("fastjson",), "Fastjson 用于 JSON 序列化和反序列化，常见于 Java/Android 数据解析。"),
        (("jsoup",), "jsoup 用于 HTML 解析、清洗和网页内容抽取。"),
        (("rxjava",), "RxJava 用于响应式编程和异步事件流处理。"),
    ]
    for needles, purpose in rules:
        if any(needle in key for needle in needles):
            return purpose
    return "该第三方库是 APK 中识别出的外部组件，用于复用成熟功能模块；当前知识库暂无更细用途描述。"


@lru_cache(maxsize=1)
def _load_cve_kb_index() -> dict[tuple[str, str], dict[str, Any]]:
    if not CVE_KB_PATH.exists():
        return {}
    try:
        records = json.loads(CVE_KB_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(records, list):
        return {}

    index: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        cve_id = str(record.get("cve_id") or "").upper()
        if not cve_id:
            continue
        names = [record.get("library_name"), *(record.get("aliases") or [])]
        for name in names:
            key = (_library_key(name), cve_id)
            index[key] = record
    return index


def _find_cve_record(library: str, cve_id: str) -> dict[str, Any] | None:
    index = _load_cve_kb_index()
    cve_key = cve_id.upper()
    lib_key = _library_key(library)
    if (lib_key, cve_key) in index:
        return index[(lib_key, cve_key)]
    for (known_library, known_cve), record in index.items():
        if known_cve != cve_key:
            continue
        if lib_key and (lib_key in known_library or known_library in lib_key):
            return record
    for (_, known_cve), record in index.items():
        if known_cve == cve_key:
            return record
    return None


def _cve_context(library: str, cve_id: str) -> dict[str, Any]:
    record = _find_cve_record(library, cve_id)
    affected_versions = list(record.get("affected_versions") or []) if record else []
    affected_sample = [str(version) for version in affected_versions[:8]]
    version_text = "、".join(affected_sample)
    if len(affected_versions) > len(affected_sample):
        version_text += f" 等 {len(affected_versions)} 个版本"
    if not version_text:
        version_text = "当前知识库未记录具体影响版本"

    summary = (
        f"{cve_id} 是一个公开漏洞编号（CVE，Common Vulnerabilities and Exposures），"
        f"用于标识 {library} 相关的已知安全问题。当前本地知识库记录的影响版本范围：{version_text}。"
    )
    return {
        "summary": summary,
        "affected_versions_sample": affected_sample,
        "affected_version_count": len(affected_versions),
        "patch_artifacts": {
            "pre_patch": _artifact_name(record.get("pre_patch_jar")) if record else "",
            "post_patch": _artifact_name(record.get("post_patch_jar")) if record else "",
            "diff": _artifact_name(record.get("patch_diff")) if record else "",
        },
        "source": "local cve_kb.json" if record else "placeholder without cve_kb match",
    }


def _library_context(library: str, version: Any = None) -> dict[str, Any]:
    return {
        "name": library,
        "version": str(version or "") or None,
        "purpose": _library_purpose(library),
        "source": "local placeholder taxonomy",
    }


def _library_versions(libraries: list[dict[str, Any]]) -> dict[str, Any]:
    versions: dict[str, Any] = {}
    for lib in libraries:
        name = str(lib.get("library_name") or lib.get("raw_name") or "")
        if name:
            versions[_library_key(name)] = lib.get("version")
    return versions


def _build_findings(vulnerabilities: list[dict[str, Any]], libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    versions = _library_versions(libraries)
    for vuln in vulnerabilities[:12]:
        status = str(vuln.get("status") or "UNKNOWN").upper()
        cve_id = str(vuln.get("cve_id") or "UNKNOWN-CVE")
        library = str(vuln.get("library") or "unknown")
        version = versions.get(_library_key(library))
        evidence = vuln.get("evidence") if isinstance(vuln.get("evidence"), dict) else {}
        verification = evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
        target_scope = evidence.get("target_scope") if isinstance(evidence.get("target_scope"), dict) else {}

        if status in {"PRESENT", "PATCH_NOT_PRESENT"}:
            priority = "high"
            rationale = "补丁状态显示漏洞或未修复特征仍存在，应优先复核和修复。"
        elif status in {"UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT"}:
            priority = "medium"
            rationale = "确定性引擎未给出稳定结论，需要补充证据或重跑验证。"
        else:
            priority = "low"
            rationale = "当前确定性证据未显示立即修复风险，可作为已验证项或低优先级项跟踪。"

        findings.append({
            "cve_id": cve_id,
            "library": library,
            "status": status,
            "priority": priority,
            "confidence": _confidence_from_status(status),
            "rationale": rationale,
            "library_context": _library_context(library, version),
            "cve_context": _cve_context(library, cve_id),
            "evidence_refs": {
                "patch_related_method_count": verification.get("patch_related_method_count"),
                "target_class_count": target_scope.get("class_count"),
                "pre_similarity": vuln.get("pre_similarity"),
                "post_similarity": vuln.get("post_similarity"),
            },
        })
    return findings


def _build_library_overview(libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    overview: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lib in libraries[:12]:
        name = str(lib.get("library_name") or lib.get("raw_name") or "unknown")
        key = _library_key(name)
        if key in seen:
            continue
        seen.add(key)
        overview.append(_library_context(name, lib.get("version")))
    return overview


def _build_local_intelligence_artifact(
    report: dict[str, Any],
    analysis_artifacts: dict[str, Any] | None = None,
    *,
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    libraries = [row for row in report.get("used_libraries", []) if isinstance(row, dict)]
    vulnerabilities = [row for row in report.get("vulnerabilities", []) if isinstance(row, dict)]
    artifacts = analysis_artifacts or report.get("analysis_artifacts") or {}
    artifact_summary = artifacts.get("summary") if isinstance(artifacts.get("summary"), dict) else {}
    status_counts = _status_counts(vulnerabilities)
    uncertain_statuses = {"UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT"}
    uncertain_count = sum(status_counts.get(status, 0) for status in uncertain_statuses)
    high_risk_count = sum(status_counts.get(status, 0) for status in ("PRESENT", "PATCH_NOT_PRESENT"))
    patch_evidence_count = int(artifact_summary.get("patch_evidence_count") or sum(1 for vuln in vulnerabilities if vuln.get("evidence")))

    evidence_gaps: list[dict[str, Any]] = []
    if uncertain_count:
        evidence_gaps.append({
            "type": "uncertain_patch_status",
            "count": uncertain_count,
            "message": "存在 UNKNOWN/HUNG/ERROR/RESOURCE_LIMIT 结果，需要补充复验或人工确认。",
        })
    if patch_evidence_count < len(vulnerabilities):
        evidence_gaps.append({
            "type": "missing_patch_evidence",
            "count": len(vulnerabilities) - patch_evidence_count,
            "message": "部分漏洞记录缺少补丁验证 evidence，智能体不能对其做强结论。",
        })
    if not libraries:
        evidence_gaps.append({
            "type": "missing_libraries",
            "count": 1,
            "message": "报告缺少 used_libraries，无法建立组件级解释链。",
        })

    recommended_actions = [
        "优先复核 PRESENT 与 PATCH_NOT_PRESENT 结果，确认是否需要升级组件或替换依赖。",
        "对 UNKNOWN/HUNG/ERROR/RESOURCE_LIMIT 结果执行二次验证，避免将引擎异常误判为安全。",
        "将智能体输出限制在 analysis_artifacts.evidence 和 execution_trace 能支撑的范围内。",
    ]
    if not evidence_gaps:
        recommended_actions.insert(0, "当前报告证据链较完整，可进入面向客户的解释与报告润色阶段。")

    return {
        "schema_version": 1,
        "status": "placeholder",
        "provider": "local-placeholder",
        "model": "acchunter-intelligence-placeholder-v1",
        "generated_at": _utc_iso(),
        "input_contract": {
            "required_fields": [
                "apk_info",
                "used_libraries",
                "vulnerabilities",
                "analysis_artifacts.evidence",
                "analysis_artifacts.execution_trace",
            ],
            "replace_with_real_api_later": True,
        },
        "input_summary": {
            "library_count": len(libraries),
            "vulnerability_count": len(vulnerabilities),
            "patch_evidence_count": patch_evidence_count,
            "status_counts": status_counts,
            "high_risk_count": high_risk_count,
            "uncertain_count": uncertain_count,
        },
        "library_overview": _build_library_overview(libraries),
        "findings": _build_findings(vulnerabilities, libraries),
        "evidence_gaps": evidence_gaps,
        "recommended_actions": recommended_actions,
        "rerun_plan": {
            "required": bool(evidence_gaps),
            "targets": [
                {
                    "cve_id": vuln.get("cve_id"),
                    "library": vuln.get("library"),
                    "reason": f"patch_status={vuln.get('status') or 'UNKNOWN'}",
                }
                for vuln in vulnerabilities
                if str(vuln.get("status") or "UNKNOWN").upper() in uncertain_statuses
            ][:10],
        },
        "api_placeholder": {
            "endpoint": "POST /api/intelligence/analyze",
            "request_shape": {
                "task_id": "optional string",
                "report": "optional report object",
            },
            "response_shape": "this intelligence object",
            "note": "以后接真实智能体 API 时，保持该响应结构或做 schema_version 升级。",
        },
        "fallback": {
            "used": bool(fallback_reason),
            "reason": fallback_reason or "",
        },
    }


def _build_agent_messages(report: dict[str, Any], analysis_artifacts: dict[str, Any]) -> list[dict[str, str]]:
    compact_input = {
        "apk_info": report.get("apk_info") or {},
        "used_libraries": report.get("used_libraries") or [],
        "vulnerabilities": report.get("vulnerabilities") or [],
        "analysis_artifacts": {
            "summary": analysis_artifacts.get("summary"),
            "evidence": analysis_artifacts.get("evidence"),
            "execution_trace": analysis_artifacts.get("execution_trace"),
        },
    }
    system_prompt = (
        "你是 ACCHunter 的安全分析智能体。只能依据输入报告和证据链作结论，"
        "不要编造未提供的漏洞命中、版本或修复证据。你必须只输出一个合法 JSON 对象，"
        "不要输出 Markdown、代码块、解释性前后缀或自然语言寒暄。"
    )
    required_findings = [
        {
            "cve_id": str(vuln.get("cve_id") or "UNKNOWN-CVE"),
            "library": str(vuln.get("library") or "unknown"),
            "status": str(vuln.get("status") or "UNKNOWN").upper(),
        }
        for vuln in compact_input["vulnerabilities"]
        if isinstance(vuln, dict)
    ]
    user_prompt = (
        "请分析本次 APK 第三方库与 CVE 检测任务，并严格返回如下 JSON 结构：\n"
        "{\n"
        '  "summary": "本次任务总体摘要，中文，1-3 句",\n'
        '  "risk_level": "critical/high/medium/low/info",\n'
        '  "library_overview": [\n'
        '    {"name": "库名", "version": "版本或空字符串", "purpose": "该第三方库的用途"}\n'
        "  ],\n"
        '  "findings": [\n'
        "    {\n"
        '      "cve_id": "必须等于输入 vulnerabilities 中的 cve_id",\n'
        '      "library": "必须等于输入 vulnerabilities 中的 library",\n'
        '      "status": "必须等于输入 vulnerabilities 中的 status",\n'
        '      "priority": "high/medium/low",\n'
        '      "confidence": 0.0,\n'
        '      "rationale": "针对这一条 CVE + library 的单项判断，中文，必须填写",\n'
        '      "library_context": {"name": "库名", "version": "版本或空字符串", "purpose": "这个第三方库有什么用，必须填写"},\n'
        '      "cve_context": {"summary": "这个 CVE 是什么，必须填写", "impact": "可能影响", "fix_advice": "修复建议"},\n'
        '      "evidence_refs": {"patch_related_method_count": null, "target_class_count": null, "pre_similarity": null, "post_similarity": null}\n'
        "    }\n"
        "  ],\n"
        '  "evidence_gaps": [{"type": "缺口类型", "message": "证据不足或复验建议"}],\n'
        '  "recommended_actions": ["处置建议 1", "处置建议 2"],\n'
        '  "rerun_plan": {"required": false, "targets": []}\n'
        "}\n\n"
        "硬性要求：\n"
        "1. findings 数组必须存在，且必须为输入 vulnerabilities 中的每一条记录生成一条 finding。\n"
        "2. findings 中每条记录必须保留原始 cve_id、library、status，不得改名、合并或省略。\n"
        "3. rationale、library_context.purpose、cve_context.summary 三个字段不能为空。\n"
        "4. 如果证据不足，要在 rationale 中说明证据边界，不要编造确定性结论。\n"
        "5. 不要输出 Markdown，不要使用 ```json。\n\n"
        f"必须覆盖的 findings 键：{json.dumps(required_findings, ensure_ascii=False)}\n\n"
        "输入如下：\n"
        f"{json.dumps(compact_input, ensure_ascii=False)}"
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _resolve_api_endpoint(raw_url: str, api_type: str) -> str:
    endpoint = raw_url.rstrip("/")
    if endpoint.endswith("/responses") or endpoint.endswith("/chat/completions"):
        return endpoint
    if api_type == "responses":
        return f"{endpoint}/responses"
    return f"{endpoint}/chat/completions"


def _build_real_api_body(model: str, api_type: str, messages: list[dict[str, str]]) -> dict[str, Any]:
    if api_type == "responses":
        system_message = next((msg["content"] for msg in messages if msg.get("role") == "system"), "")
        user_message = next((msg["content"] for msg in messages if msg.get("role") == "user"), "")
        return {
            "model": model,
            "instructions": system_message,
            "input": user_message,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
    return {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }


def _extract_agent_content(response_json: dict[str, Any]) -> Any:
    if "output_text" in response_json:
        return response_json.get("output_text")

    output = response_json.get("output")
    if isinstance(output, list):
        texts: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict):
                    continue
                if isinstance(part.get("text"), str):
                    texts.append(part["text"])
        if texts:
            return "\n".join(texts)

    choices = response_json.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict) and "content" in message:
            return message.get("content")
        if isinstance(choices[0], dict) and "text" in choices[0]:
            return choices[0].get("text")
    if "output" in response_json:
        return response_json.get("output")
    if "result" in response_json:
        return response_json.get("result")
    return response_json


def _parse_agent_content(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if isinstance(content, list):
        return {"items": content}
    if not isinstance(content, str):
        return {"raw": content}

    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"summary": text}
    return parsed if isinstance(parsed, dict) else {"items": parsed}


def _finding_key(finding: dict[str, Any]) -> tuple[str, str]:
    return (
        str(finding.get("cve_id") or finding.get("cveId") or finding.get("id") or "").upper(),
        _library_key(finding.get("library") or finding.get("library_name") or finding.get("component") or ""),
    )


def _merge_agent_findings(
    agent_findings: Any,
    local_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    local_by_key = {_finding_key(finding): finding for finding in local_findings if isinstance(finding, dict)}
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    if isinstance(agent_findings, list):
        for item in agent_findings:
            if not isinstance(item, dict):
                continue
            key = _finding_key(item)
            if not key[0]:
                continue
            local = local_by_key.get(key, {})
            finding = {**local, **item}

            library_context = {**dict(local.get("library_context") or {}), **dict(item.get("library_context") or {})}
            cve_context = {**dict(local.get("cve_context") or {}), **dict(item.get("cve_context") or {})}
            evidence_refs = {**dict(local.get("evidence_refs") or {}), **dict(item.get("evidence_refs") or {})}
            finding["library_context"] = library_context
            finding["cve_context"] = cve_context
            finding["evidence_refs"] = evidence_refs

            if not finding.get("rationale"):
                finding["rationale"] = local.get("rationale") or "智能体未返回单项判断，已使用本地证据兜底。"
            if not library_context.get("purpose"):
                library_context["purpose"] = dict(local.get("library_context") or {}).get("purpose") or _library_purpose(finding.get("library") or "")
            if not cve_context.get("summary"):
                cve_context["summary"] = dict(local.get("cve_context") or {}).get("summary") or f"{finding.get('cve_id')} 是该组件相关的公开漏洞编号。"

            merged.append(finding)
            seen.add(key)

    for key, local in local_by_key.items():
        if key in seen:
            continue
        fallback = dict(local)
        fallback["rationale"] = f"智能体未覆盖该单项，已使用本地证据兜底：{fallback.get('rationale') or ''}".strip()
        merged.append(fallback)
    return merged


def _normalize_real_intelligence(
    agent_payload: dict[str, Any],
    *,
    provider: str,
    model: str,
    raw_response: dict[str, Any],
    local_fallback: dict[str, Any],
) -> dict[str, Any]:
    local_findings = local_fallback.get("findings", []) if isinstance(local_fallback.get("findings"), list) else []
    findings = _merge_agent_findings(agent_payload.get("findings"), local_findings)
    result = {
        "schema_version": 1,
        "status": "ok",
        "provider": provider,
        "model": model,
        "generated_at": _utc_iso(),
        "input_contract": local_fallback.get("input_contract", {}),
        "input_summary": local_fallback.get("input_summary", {}),
        "library_overview": agent_payload.get("library_overview") or local_fallback.get("library_overview", []),
        "findings": findings,
        "evidence_gaps": agent_payload.get("evidence_gaps") or local_fallback.get("evidence_gaps", []),
        "recommended_actions": agent_payload.get("recommended_actions") or local_fallback.get("recommended_actions", []),
        "rerun_plan": agent_payload.get("rerun_plan") or local_fallback.get("rerun_plan", {}),
        "agent_summary": agent_payload.get("summary") or agent_payload.get("agent_summary") or "",
        "risk_level": agent_payload.get("risk_level") or "",
        "fallback": {
            "used": False,
            "reason": "",
        },
    }
    if _env_str("INTELLIGENCE_INCLUDE_RAW_RESPONSE", "false").lower() in {"1", "true", "yes"}:
        result["raw_agent_response"] = raw_response
    return result


def _call_real_intelligence_api(
    report: dict[str, Any],
    analysis_artifacts: dict[str, Any],
    local_fallback: dict[str, Any],
) -> dict[str, Any] | None:
    api_key = _env_str("INTELLIGENCE_API_KEY")
    endpoint = _env_str("INTELLIGENCE_API_URL")
    provider = _env_str("INTELLIGENCE_PROVIDER", "custom-agent")
    model = _env_str("INTELLIGENCE_MODEL", "acchunter-agent")
    timeout = _env_int("INTELLIGENCE_API_TIMEOUT", 60)
    api_type = _env_str("INTELLIGENCE_API_TYPE", "chat_completions").lower().replace("-", "_")

    if not api_key or not endpoint:
        return None

    if api_type not in {"responses", "chat_completions"}:
        api_type = "chat_completions"

    body = _build_real_api_body(model, api_type, _build_agent_messages(report, analysis_artifacts))
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    req = request.Request(
        _resolve_api_endpoint(endpoint, api_type),
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as resp:
        response_text = resp.read().decode("utf-8")
    response_json = json.loads(response_text)
    content = _extract_agent_content(response_json)
    agent_payload = _parse_agent_content(content)
    return _normalize_real_intelligence(
        agent_payload,
        provider=provider,
        model=model,
        raw_response=response_json,
        local_fallback=local_fallback,
    )


def _missing_intelligence_config_reason() -> str:
    missing: list[str] = []
    if not _env_str("INTELLIGENCE_API_KEY"):
        missing.append("INTELLIGENCE_API_KEY")
    if not _env_str("INTELLIGENCE_API_URL"):
        missing.append("INTELLIGENCE_API_URL")
    if not missing:
        return "real intelligence API returned no result"
    return f"missing {', '.join(missing)}"


def build_intelligence_artifact(
    report: dict[str, Any],
    analysis_artifacts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build intelligence output with optional real agent API fallback."""

    artifacts = analysis_artifacts or report.get("analysis_artifacts") or {}
    local_fallback = _build_local_intelligence_artifact(report, artifacts)
    if _env_str("INTELLIGENCE_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        return local_fallback

    try:
        real_result = _call_real_intelligence_api(report, artifacts, local_fallback)
    except (OSError, TimeoutError, json.JSONDecodeError, error.URLError, error.HTTPError, ValueError) as exc:
        return _build_local_intelligence_artifact(
            report,
            artifacts,
            fallback_reason=f"real intelligence API failed: {exc}",
        )

    if real_result is None:
        return _build_local_intelligence_artifact(
            report,
            artifacts,
            fallback_reason=_missing_intelligence_config_reason(),
        )
    return real_result
