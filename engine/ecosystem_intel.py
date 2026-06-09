from __future__ import annotations

import json
import math
import os
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

DISPLAY_LIMIT = 15
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "unknown": 10,
    "info": 10,
}
DEFAULT_SOURCE_LABEL = "生态参考情报"
DEFAULT_SCOPE = "基于本项目 cve_kb.json 的 Android/Java 第三方库 CVE 知识库，不代表当前 APK 已命中"
DEFAULT_METHODOLOGY = (
    "以 data/cve_kb.json 为底表，全量聚合其中出现的 CVE 与第三方组件；"
    "CVE 说明、CVSS 与参考链接优先来自 NVD CVE API / CVE Program 官方记录，"
    "缺失时使用可解释 fallback；排序按严重性、CVSS、影响版本数量、补丁资产完整度和组件风险密度计算。"
)
DEFAULT_VERSION = "2026-06-08"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WEB_URL = "https://nvd.nist.gov/vuln/detail"
CVE_RECORD_URL = "https://github.com/CVEProject/cvelistV5"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
CVE_KB_PATH = DATA_DIR / "cve_kb.json"
ECOSYSTEM_INTEL_KB_PATH = DATA_DIR / "ecosystem_intel_kb.json"


def _utc_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _safe_read_json(path: Path, fallback: Any) -> tuple[Any, str | None]:
    try:
        if not path.exists():
            return fallback, f"JSON file not found: {path}"
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return fallback, f"Invalid JSON in {path}: {exc}"
    except OSError as exc:
        return fallback, f"Failed to read {path}: {exc}"


def _safe_write_json(path: Path, payload: Any) -> str | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return None
    except OSError as exc:
        return f"Failed to write {path}: {exc}"


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_list(value: Any) -> list[str]:
    result: list[str] = []
    for item in _as_list(value):
        if item is None:
            continue
        text = str(item).strip()
        if text:
            result.append(text)
    return result


def _unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


def _normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    if severity in {"critical", "high", "medium", "low", "unknown", "info"}:
        return "unknown" if severity == "info" else severity
    return "unknown"


def _coerce_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return round(number, 1)


def _display_name_from_library_name(library_name: str) -> str:
    if not library_name:
        return "unknown-library"
    parts = [p for p in library_name.replace(":", ".").split(".") if p]
    return parts[-1] if parts else library_name


def _cve_record_url(cve_id: str) -> str:
    # Human-readable repository URL instead of raw URL, stable for references.
    parts = cve_id.split("-")
    if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
        year = parts[1]
        num = int(parts[2])
        bucket = f"{num // 1000}xxx" if num >= 1000 else "0xxx"
        return f"{CVE_RECORD_URL}/blob/main/cves/{year}/{bucket}/{cve_id}.json"
    return CVE_RECORD_URL


def _fallback_cve_detail(cve_id: str, library_name: str, affected_version_count: int) -> dict[str, Any]:
    display_name = _display_name_from_library_name(library_name)
    return {
        "title": f"{cve_id} / {display_name} 组件安全风险",
        "severity": "unknown",
        "cvss_score": None,
        "cvss_vector": "",
        "published": "",
        "last_modified": "",
        "summary": (
            f"{cve_id} 是 data/cve_kb.json 中记录的 {display_name} 相关 CVE，"
            f"本地知识库记录了 {affected_version_count} 个受影响版本。"
        ),
        "impact": "具体影响需要结合目标 APK 是否使用受影响版本、漏洞相关代码是否保留以及调用入口是否可达进行判断。",
        "android_relevance": "该条目只表示 Android/Java 第三方库生态中的参考风险，不代表当前 APK 已命中。",
        "fix_advice": "建议升级到官方修复版本，并结合 PHunter 补丁存在性验证确认最终 APK 中漏洞代码状态。",
        "references": [f"{NVD_WEB_URL}/{cve_id}", _cve_record_url(cve_id)],
        "source_basis": "fallback-from-cve_kb; run tools/build_ecosystem_intel_kb.py or enable ACCHUNTER_ECOSYSTEM_ONLINE_REFRESH=1 to enrich from NVD.",
    }


LIBRARY_SEED_DETAILS: dict[str, dict[str, str]] = {
    "commons-compress": {"usage_hint": "压缩包与归档文件解析", "security_focus": "恶意压缩包、Zip Slip、拒绝服务、内存/CPU 资源消耗"},
    "commons-beanutils": {"usage_hint": "JavaBean 属性反射与对象属性复制", "security_focus": "反射调用、类加载、反序列化链与对象属性注入"},
    "commons-collections4": {"usage_hint": "集合工具与数据结构扩展", "security_focus": "反序列化 gadget 链与危险 Transformer 调用"},
    "commons-text": {"usage_hint": "字符串插值、转义与文本处理", "security_focus": "表达式插值、脚本/URL/DNS 解析触发与远程代码执行"},
    "commons-io": {"usage_hint": "文件、流、路径与 IO 工具", "security_focus": "路径遍历、符号链接、文件大小边界与资源消耗"},
    "commons-lang3": {"usage_hint": "Java 基础工具增强", "security_focus": "边界条件、反射辅助函数、对象处理逻辑"},
    "snakeyaml": {"usage_hint": "YAML 解析与序列化", "security_focus": "不可信 YAML 反序列化、实体扩展和解析资源耗尽"},
    "bcprov-jdkon": {"usage_hint": "Bouncy Castle 密码学 Provider", "security_focus": "签名验证、证书处理、随机数、密钥交换与加密实现缺陷"},
    "kotlin-stdlib": {"usage_hint": "Kotlin 标准库", "security_focus": "临时文件、集合/反射/序列化辅助逻辑与基础 API 安全边界"},
    "nimbus-jose-jwt": {"usage_hint": "JWT/JWS/JWE 与 JOSE 令牌处理", "security_focus": "签名校验、JWE 解密、算法选择、令牌认证绕过"},
    "jackson-databind": {"usage_hint": "JSON 数据绑定与对象映射", "security_focus": "多态反序列化、默认类型、gadget 链和不可信 JSON 输入"},
    "jackson-dataformat-xml": {"usage_hint": "XML 数据绑定", "security_focus": "XML 外部实体、反序列化和解析器配置"},
    "gson": {"usage_hint": "JSON 序列化与反序列化", "security_focus": "不可信 JSON 输入、对象构造、递归/资源消耗"},
    "guava": {"usage_hint": "Google Java 基础工具库", "security_focus": "缓存、文件、集合和辅助 API 的边界条件"},
    "protobuf-javalite": {"usage_hint": "Protocol Buffers Lite 运行库", "security_focus": "二进制消息解析、递归深度、资源消耗和输入校验"},
    "okhttp": {"usage_hint": "Android/Java HTTP 客户端", "security_focus": "TLS、证书校验、重定向、请求走私和连接复用"},
    "okio": {"usage_hint": "高性能 IO 缓冲库", "security_focus": "文件读写、缓冲区边界、压缩流和输入解析"},
    "retrofit": {"usage_hint": "REST API 客户端封装", "security_focus": "请求构造、序列化适配器、URL/路径参数和依赖传递风险"},
    "log4j-core": {"usage_hint": "日志框架核心实现", "security_focus": "日志注入、JNDI/Lookup、配置解析与远程代码执行"},
    "logback-core": {"usage_hint": "日志框架核心组件", "security_focus": "配置解析、反序列化、Socket/Receiver 与日志输入处理"},
    "logback-classic": {"usage_hint": "SLF4J/Logback 日志实现", "security_focus": "日志配置、远程 receiver、序列化和依赖传递风险"},
    "logback-android": {"usage_hint": "Android 日志框架适配", "security_focus": "日志配置解析、文件输出和 Android 端敏感信息泄露"},
    "fastjson": {"usage_hint": "JSON 解析与对象绑定", "security_focus": "autoType、多态反序列化和 gadget 链远程代码执行"},
    "xstream": {"usage_hint": "XML/对象序列化", "security_focus": "XML 反序列化、任意类型实例化和远程代码执行"},
    "dom4j": {"usage_hint": "XML 文档解析", "security_focus": "XXE、实体扩展和 XML 解析器配置"},
    "httpclient": {"usage_hint": "Apache HTTP 客户端", "security_focus": "TLS/主机名校验、重定向、Cookie 和代理处理"},
    "netty-all": {"usage_hint": "异步网络通信框架", "security_focus": "HTTP/2、SSL/TLS、编解码器、内存管理和请求走私"},
    "pdfbox-android": {"usage_hint": "Android PDF 解析与处理", "security_focus": "恶意 PDF 解析、递归对象、资源消耗和文件处理"},
    "itextpdf": {"usage_hint": "PDF 生成与解析", "security_focus": "PDF 解析、XML/字体/附件处理和资源消耗"},
    "junrar": {"usage_hint": "RAR 压缩包解析", "security_focus": "归档遍历、解压边界、内存/CPU 资源消耗"},
    "androidsvg": {"usage_hint": "SVG 解析与渲染", "security_focus": "XML/SVG 解析、外部资源、递归和渲染资源消耗"},
    "filedownloader": {"usage_hint": "Android 文件下载", "security_focus": "下载路径、文件覆盖、权限、URL 输入和中间人风险"},
    "conscrypt-android": {"usage_hint": "Android TLS/加密 Provider", "security_focus": "TLS、证书链、主机名校验和密码套件实现"},
    "nv-websocket-client": {"usage_hint": "WebSocket 客户端", "security_focus": "TLS、握手校验、代理、重定向和消息解析"},
    "smack-core": {"usage_hint": "XMPP 协议客户端核心", "security_focus": "XML 流解析、TLS、认证和协议状态机"},
    "smack-tcp": {"usage_hint": "XMPP TCP 传输", "security_focus": "连接管理、TLS、重连、认证和流解析"},
    "jasypt": {"usage_hint": "Java 加密辅助库", "security_focus": "密码派生、默认算法、配置泄露和密钥管理"},
}


def _fallback_library_detail(library_name: str, aliases: list[str] | None = None) -> dict[str, Any]:
    display_name = _display_name_from_library_name(library_name)
    lower_key_candidates = [display_name.lower(), library_name.lower()]
    seed: dict[str, str] = {}
    for key in lower_key_candidates:
        if key in LIBRARY_SEED_DETAILS:
            seed = LIBRARY_SEED_DETAILS[key]
            break
    package_names = _unique_sorted([library_name, *(aliases or [])])
    usage_hint = seed.get("usage_hint", "Android/Java 第三方组件")
    security_focus = seed.get("security_focus", "关注受影响版本、漏洞代码是否保留、补丁是否存在以及调用入口是否可达")
    return {
        "display_name": display_name,
        "ecosystem": "Android/Java",
        "package_names": package_names,
        "usage_hint": usage_hint,
        "description": f"{library_name or display_name} 是 data/cve_kb.json 中出现的 Android/Java 第三方组件，常作为 APK 的直接或间接依赖进入发布制品。",
        "common_usage": f"主要用于{usage_hint}等业务场景。",
        "security_focus": security_focus,
        "source_basis": "由 cve_kb.json 中的 library_name/aliases 自动归一化，并结合 Android/Java 组件生态常识生成说明；不代表当前 APK 已命中。",
    }


def _normalize_cve_row(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    cve_id = _as_str(row.get("cve_id")).strip()
    library_name = _as_str(row.get("library_name"), "unknown-library").strip() or "unknown-library"
    if not cve_id:
        return None
    return {
        "library_name": library_name,
        "aliases": _string_list(row.get("aliases")),
        "cve_id": cve_id,
        "affected_versions": _string_list(row.get("affected_versions")),
        "pre_patch_jar": _as_str(row.get("pre_patch_jar")),
        "post_patch_jar": _as_str(row.get("post_patch_jar")),
        "patch_diff": _as_str(row.get("patch_diff")),
    }


def _normalize_base_rows(raw_cve_kb: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_cve_kb, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in raw_cve_kb:
        row = _normalize_cve_row(item)
        if row is not None:
            rows.append(row)
    return rows


def _default_intel_shell() -> dict[str, Any]:
    return {
        "version": DEFAULT_VERSION,
        "source_label": DEFAULT_SOURCE_LABEL,
        "scope": DEFAULT_SCOPE,
        "methodology": DEFAULT_METHODOLOGY,
        "generated_by": "ACCHunter ecosystem intelligence enrichment",
        "cve_details": {},
        "library_details": {},
    }


def _intel_metadata(raw_intel: Any) -> dict[str, Any]:
    if not isinstance(raw_intel, dict):
        raw_intel = {}
    shell = _default_intel_shell()
    return {
        "version": _as_str(raw_intel.get("version"), shell["version"]),
        "source_label": _as_str(raw_intel.get("source_label"), DEFAULT_SOURCE_LABEL),
        "scope": _as_str(raw_intel.get("scope"), DEFAULT_SCOPE),
        "methodology": _as_str(raw_intel.get("methodology"), DEFAULT_METHODOLOGY),
        "generated_by": _as_str(raw_intel.get("generated_by"), shell["generated_by"]),
        "cve_details": raw_intel.get("cve_details") if isinstance(raw_intel.get("cve_details"), dict) else {},
        "library_details": raw_intel.get("library_details") if isinstance(raw_intel.get("library_details"), dict) else {},
    }


def _extract_english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en" and desc.get("value"):
            return str(desc["value"]).strip()
    return ""


def _first_sentence(text: str, max_len: int = 160) -> str:
    clean = " ".join(str(text or "").split())
    if not clean:
        return ""
    # Avoid chopping common abbreviations too aggressively; this is just a title fallback.
    for sep in [". ", "; ", "。"]:
        if sep in clean:
            candidate = clean.split(sep, 1)[0].strip(" .;。")
            if 24 <= len(candidate) <= max_len:
                return candidate
    return clean[:max_len].rstrip()


def _extract_cvss(cve: dict[str, Any]) -> tuple[str, float | None, str, str]:
    metrics = cve.get("metrics") or {}
    metric_keys = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for key in metric_keys:
        items = metrics.get(key) or []
        if not items:
            continue
        # Prefer NVD Primary, then any Primary, then first record.
        ordered = sorted(
            items,
            key=lambda item: (
                0 if item.get("source") == "nvd@nist.gov" and item.get("type") == "Primary" else 1,
                0 if item.get("type") == "Primary" else 1,
            ),
        )
        item = ordered[0]
        data = item.get("cvssData") or {}
        score = _coerce_float(data.get("baseScore"))
        severity = _normalize_severity(data.get("baseSeverity") or item.get("baseSeverity"))
        vector = _as_str(data.get("vectorString"))
        source = _as_str(item.get("source"))
        return severity, score, vector, source
    return "unknown", None, "", ""


def _extract_references(cve: dict[str, Any], cve_id: str, limit: int = 10) -> list[str]:
    refs = [f"{NVD_WEB_URL}/{cve_id}", _cve_record_url(cve_id)]
    for ref in cve.get("references") or []:
        url = _as_str(ref.get("url")).strip()
        if url:
            refs.append(url)
    return _unique_sorted(refs)[:limit]


def _detail_from_nvd_cve(cve_wrapper: dict[str, Any], library_name: str, affected_version_count: int) -> tuple[str, dict[str, Any]] | None:
    cve = cve_wrapper.get("cve") if isinstance(cve_wrapper, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = _as_str(cve.get("id")).strip()
    if not cve_id:
        return None
    summary = _extract_english_description(cve)
    severity, score, vector, metric_source = _extract_cvss(cve)
    title_base = _first_sentence(summary) or f"{cve_id} / {_display_name_from_library_name(library_name)} 组件安全风险"
    return cve_id, {
        "title": title_base,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "published": _as_str(cve.get("published")),
        "last_modified": _as_str(cve.get("lastModified")),
        "summary": summary or _fallback_cve_detail(cve_id, library_name, affected_version_count)["summary"],
        "impact": _impact_from_severity(severity),
        "android_relevance": "若目标 APK 直接或间接打包了该第三方库的受影响版本，且漏洞相关代码在发布制品中保留并可被触发，则可能形成 Android 侧供应链风险；该生态条目本身不代表当前 APK 已命中。",
        "fix_advice": "优先升级到官方修复版本；对已扫描 APK，应结合版本识别结果与 PHunter 补丁存在性验证，确认漏洞代码是否仍存在、是否已修复或是否已被裁剪。",
        "references": _extract_references(cve, cve_id),
        "source_basis": f"NVD CVE API; metric_source={metric_source or 'not-provided'}; affected_versions_from=data/cve_kb.json",
    }


def _impact_from_severity(severity: str) -> str:
    severity = _normalize_severity(severity)
    if severity == "critical":
        return "可能导致远程代码执行、认证绕过、敏感数据泄露或大范围拒绝服务等严重后果，应作为最高优先级处理。"
    if severity == "high":
        return "可能造成显著的机密性、完整性或可用性影响，应优先升级并验证补丁状态。"
    if severity == "medium":
        return "通常需要特定输入、配置或调用路径才能触发，但在移动应用供应链中仍应纳入风险排查。"
    if severity == "low":
        return "通常影响范围有限，但仍建议结合依赖版本与代码可达性进行治理。"
    return "公开记录未提供明确严重性评分，需结合官方公告、受影响版本和目标 APK 使用方式进一步研判。"


def _chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _fetch_nvd_details(cve_ids: list[str], *, timeout: float = 30.0, delay_seconds: float = 0.6) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Fetch official CVE metadata from NVD. Network failures are warnings, never API-breaking."""
    if not cve_ids:
        return {}, []

    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"User-Agent": "ACCHunter ecosystem intelligence builder/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    fetched: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    # NVD cveIds supports up to 100 CVE IDs per request.
    for index, batch in enumerate(_chunked(_unique_sorted(cve_ids), 100)):
        params = urllib.parse.urlencode({"cveIds": ",".join(batch)})
        url = f"{NVD_API_URL}?{params}"
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # pragma: no cover - depends on live network
            warnings.append(f"NVD fetch failed for batch {index + 1}: {exc}")
            continue
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cve_id = _as_str(cve.get("id")).strip()
            if cve_id:
                fetched[cve_id] = item
        if delay_seconds > 0 and index < math.ceil(len(cve_ids) / 100) - 1:
            time.sleep(delay_seconds)
    return fetched, warnings


def _merge_online_cve_details(raw_intel: dict[str, Any], rows: list[dict[str, Any]], *, force: bool = False) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    meta = _intel_metadata(raw_intel)
    cve_details: dict[str, Any] = dict(meta["cve_details"])
    cve_ids = _unique_sorted(row["cve_id"] for row in rows)
    needs_fetch = []
    for cve_id in cve_ids:
        detail = cve_details.get(cve_id)
        if force or not isinstance(detail, dict) or not detail.get("summary") or detail.get("source_basis", "").startswith("fallback"):
            needs_fetch.append(cve_id)
    fetched, fetch_warnings = _fetch_nvd_details(needs_fetch)
    warnings.extend(fetch_warnings)

    library_by_cve: dict[str, str] = {}
    affected_count_by_cve: dict[str, int] = {}
    grouped_versions: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        library_by_cve.setdefault(row["cve_id"], row["library_name"])
        grouped_versions[row["cve_id"]].extend(row.get("affected_versions", []))
    for cve_id, versions in grouped_versions.items():
        affected_count_by_cve[cve_id] = len(set(versions))

    for cve_id, wrapper in fetched.items():
        parsed = _detail_from_nvd_cve(wrapper, library_by_cve.get(cve_id, "unknown-library"), affected_count_by_cve.get(cve_id, 0))
        if parsed is None:
            continue
        _, detail = parsed
        existing = cve_details.get(cve_id) if isinstance(cve_details.get(cve_id), dict) else {}
        # Preserve manually curated title/advice if the project later customizes it, but refresh objective official fields.
        merged = {**existing, **detail}
        cve_details[cve_id] = merged

    raw_intel = {**_default_intel_shell(), **raw_intel}
    raw_intel["cve_details"] = cve_details
    raw_intel["version"] = DEFAULT_VERSION
    raw_intel["source_label"] = DEFAULT_SOURCE_LABEL
    raw_intel["scope"] = DEFAULT_SCOPE
    raw_intel["methodology"] = DEFAULT_METHODOLOGY
    raw_intel["generated_by"] = "ACCHunter online enrichment using NVD CVE API plus local cve_kb.json"
    return raw_intel, warnings


def _ensure_complete_intel(raw_intel: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    base = _default_intel_shell()
    if isinstance(raw_intel, dict):
        base.update(raw_intel)
    if not isinstance(base.get("cve_details"), dict):
        base["cve_details"] = {}
    if not isinstance(base.get("library_details"), dict):
        base["library_details"] = {}

    versions_by_cve: dict[str, list[str]] = defaultdict(list)
    library_by_cve: dict[str, str] = {}
    aliases_by_library: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        cve_id = row["cve_id"]
        library_by_cve.setdefault(cve_id, row["library_name"])
        versions_by_cve[cve_id].extend(row.get("affected_versions", []))
        aliases_by_library[row["library_name"]].extend(row.get("aliases", []))

    for cve_id in _unique_sorted(row["cve_id"] for row in rows):
        if not isinstance(base["cve_details"].get(cve_id), dict):
            base["cve_details"][cve_id] = _fallback_cve_detail(cve_id, library_by_cve.get(cve_id, "unknown-library"), len(set(versions_by_cve[cve_id])))
        else:
            fallback = _fallback_cve_detail(cve_id, library_by_cve.get(cve_id, "unknown-library"), len(set(versions_by_cve[cve_id])))
            merged = {**fallback, **base["cve_details"][cve_id]}
            merged["references"] = _unique_sorted(_string_list(merged.get("references")) + fallback["references"])
            base["cve_details"][cve_id] = merged

    for library_name in _unique_sorted(row["library_name"] for row in rows):
        if not isinstance(base["library_details"].get(library_name), dict):
            base["library_details"][library_name] = _fallback_library_detail(library_name, aliases_by_library.get(library_name, []))
        else:
            fallback = _fallback_library_detail(library_name, aliases_by_library.get(library_name, []))
            merged = {**fallback, **base["library_details"][library_name]}
            merged["package_names"] = _unique_sorted(_string_list(merged.get("package_names")) + [library_name] + aliases_by_library.get(library_name, []))
            base["library_details"][library_name] = merged
    return base


def refresh_ecosystem_intel_kb(*, force_online: bool = True, write: bool = True) -> tuple[dict[str, Any], list[str]]:
    raw_cve_kb, cve_read_warning = _safe_read_json(CVE_KB_PATH, [])
    rows = _normalize_base_rows(raw_cve_kb)
    raw_intel, intel_read_warning = _safe_read_json(ECOSYSTEM_INTEL_KB_PATH, _default_intel_shell())
    warnings = [warning for warning in [cve_read_warning, intel_read_warning] if warning]

    completed = _ensure_complete_intel(raw_intel, rows)
    if force_online and rows:
        completed, fetch_warnings = _merge_online_cve_details(completed, rows, force=True)
        warnings.extend(fetch_warnings)
        completed = _ensure_complete_intel(completed, rows)
    if write:
        write_warning = _safe_write_json(ECOSYSTEM_INTEL_KB_PATH, completed)
        if write_warning:
            warnings.append(write_warning)
    return completed, warnings


def _get_cve_detail(cve_id: str, library_name: str, affected_version_count: int, cve_details: dict[str, Any]) -> dict[str, Any]:
    raw_detail = cve_details.get(cve_id)
    if not isinstance(raw_detail, dict):
        raw_detail = {}
    fallback = _fallback_cve_detail(cve_id, library_name, affected_version_count)
    merged = {**fallback, **raw_detail}
    merged["severity"] = _normalize_severity(merged.get("severity"))
    merged["cvss_score"] = _coerce_float(merged.get("cvss_score"))
    merged["references"] = _unique_sorted(_string_list(merged.get("references")) + fallback["references"])
    return merged


def _get_library_detail(library_name: str, aliases: list[str], library_details: dict[str, Any]) -> dict[str, Any]:
    raw_detail = library_details.get(library_name)
    if not isinstance(raw_detail, dict):
        raw_detail = {}
    fallback = _fallback_library_detail(library_name, aliases)
    merged = {**fallback, **raw_detail}
    merged["display_name"] = _as_str(merged.get("display_name"), fallback["display_name"])
    merged["ecosystem"] = _as_str(merged.get("ecosystem"), "Android/Java") or "Android/Java"
    merged["package_names"] = _unique_sorted(_string_list(merged.get("package_names")) + [library_name] + aliases)
    merged["notable_cves"] = _string_list(merged.get("notable_cves"))
    return merged


def _artifact_bonus(rows: list[dict[str, Any]]) -> float:
    pre = any(row.get("pre_patch_jar") for row in rows)
    post = any(row.get("post_patch_jar") for row in rows)
    diff = any(row.get("patch_diff") for row in rows)
    return float(pre + post + diff) * 2.0


def _cve_rank_score(severity: str, cvss_score: float | None, affected_version_count: int, rows: list[dict[str, Any]]) -> float:
    severity_score = SEVERITY_WEIGHTS.get(_normalize_severity(severity), 10)
    cvss_bonus = (cvss_score or 0.0) * 3.0
    version_bonus = min(affected_version_count * 1.2, 35.0)
    patch_bonus = _artifact_bonus(rows)
    record_bonus = min(max(len(rows) - 1, 0) * 0.5, 8.0)
    return round(severity_score + cvss_bonus + version_bonus + patch_bonus + record_bonus, 2)


def _first_non_empty(rows: list[dict[str, Any]], key: str) -> str:
    for row in rows:
        value = _as_str(row.get(key)).strip()
        if value:
            return value
    return ""


def _build_cve_top(rows: list[dict[str, Any]], cve_details: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["cve_id"]].append(row)

    cve_top: list[dict[str, Any]] = []
    for cve_id, cve_rows in grouped.items():
        library_names = _unique_sorted(row["library_name"] for row in cve_rows)
        primary_library = library_names[0] if len(library_names) == 1 else "multi-library"
        affected_versions = _unique_sorted(version for row in cve_rows for version in row.get("affected_versions", []))
        affected_packages = _unique_sorted(
            [row["library_name"] for row in cve_rows]
            + [alias for row in cve_rows for alias in row.get("aliases", [])]
        )
        detail = _get_cve_detail(cve_id, library_names[0] if library_names else "unknown-library", len(affected_versions), cve_details)
        rank_score = _cve_rank_score(detail["severity"], detail["cvss_score"], len(affected_versions), cve_rows)
        cve_top.append(
            {
                "id": cve_id,
                "title": _as_str(detail.get("title"), cve_id),
                "severity": detail["severity"],
                "cvss_score": detail["cvss_score"],
                "cvss_vector": _as_str(detail.get("cvss_vector")),
                "rank_score": rank_score,
                "library_name": primary_library,
                "library_names": library_names,
                "affected_packages": affected_packages,
                "affected_versions": affected_versions,
                "affected_version_count": len(affected_versions),
                "record_count": len(cve_rows),
                "patch_artifacts": {
                    "pre_patch_jar": _first_non_empty(cve_rows, "pre_patch_jar"),
                    "post_patch_jar": _first_non_empty(cve_rows, "post_patch_jar"),
                    "patch_diff": _first_non_empty(cve_rows, "patch_diff"),
                },
                "summary": _as_str(detail.get("summary")),
                "impact": _as_str(detail.get("impact")),
                "android_relevance": _as_str(detail.get("android_relevance")),
                "fix_advice": _as_str(detail.get("fix_advice")),
                "references": _string_list(detail.get("references")),
                "source_basis": _as_str(detail.get("source_basis")),
                "published": _as_str(detail.get("published")),
                "last_modified": _as_str(detail.get("last_modified")),
            }
        )
    return sorted(cve_top, key=lambda item: (-float(item["rank_score"]), item["id"]))


def _tpl_rank_score(cve_count: int, high_risk_cve_count: int, affected_version_count: int, cve_score_sum: float, record_count: int) -> float:
    return round(
        cve_count * 20.0
        + high_risk_cve_count * 35.0
        + min(affected_version_count * 0.8, 80.0)
        + min(cve_score_sum * 0.08, 80.0)
        + min(max(record_count - cve_count, 0) * 1.0, 20.0),
        2,
    )


def _build_tpl_top(rows: list[dict[str, Any]], library_details: dict[str, Any], cve_top: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["library_name"]].append(row)

    cve_by_id = {item["id"]: item for item in cve_top}
    tpl_top: list[dict[str, Any]] = []
    for library_name, lib_rows in grouped.items():
        aliases = _unique_sorted(alias for row in lib_rows for alias in row.get("aliases", []))
        unique_cve_ids = _unique_sorted(row["cve_id"] for row in lib_rows)
        lib_cves = sorted((cve_by_id[cve_id] for cve_id in unique_cve_ids if cve_id in cve_by_id), key=lambda item: (-item["rank_score"], item["id"]))
        high_risk_count = sum(1 for item in lib_cves if item.get("severity") in {"critical", "high"})
        affected_versions = _unique_sorted(version for row in lib_rows for version in row.get("affected_versions", []))
        cve_score_sum = sum(float(item.get("rank_score") or 0) for item in lib_cves)
        rank_score = _tpl_rank_score(len(unique_cve_ids), high_risk_count, len(affected_versions), cve_score_sum, len(lib_rows))
        detail = _get_library_detail(library_name, aliases, library_details)
        tpl_top.append(
            {
                "name": library_name,
                "display_name": detail["display_name"],
                "ecosystem": detail["ecosystem"],
                "rank_score": rank_score,
                "cve_count": len(unique_cve_ids),
                "record_count": len(lib_rows),
                "high_risk_cve_count": high_risk_count,
                "affected_version_count": len(affected_versions),
                "package_names": detail["package_names"],
                "usage_hint": _as_str(detail.get("usage_hint")),
                "description": _as_str(detail.get("description")),
                "common_usage": _as_str(detail.get("common_usage")),
                "security_focus": _as_str(detail.get("security_focus")),
                "notable_cves": [item["id"] for item in lib_cves[:5]],
                "source_basis": _as_str(detail.get("source_basis")),
            }
        )
    return sorted(tpl_top, key=lambda item: (-float(item["rank_score"]), item["name"]))


def _online_refresh_enabled(online_refresh: bool | None) -> bool:
    if online_refresh is not None:
        return online_refresh
    return os.getenv("ACCHUNTER_ECOSYSTEM_ONLINE_REFRESH", "").strip().lower() in {"1", "true", "yes", "on"}


def build_ecosystem_summary(*, online_refresh: bool | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    raw_cve_kb, cve_read_warning = _safe_read_json(CVE_KB_PATH, [])
    if cve_read_warning:
        warnings.append(cve_read_warning)
    rows = _normalize_base_rows(raw_cve_kb)

    raw_intel, intel_read_warning = _safe_read_json(ECOSYSTEM_INTEL_KB_PATH, _default_intel_shell())
    if intel_read_warning:
        warnings.append(intel_read_warning)
    raw_intel = _ensure_complete_intel(raw_intel, rows)

    if _online_refresh_enabled(online_refresh) and rows:
        raw_intel, online_warnings = _merge_online_cve_details(raw_intel, rows, force=False)
        warnings.extend(online_warnings)
        raw_intel = _ensure_complete_intel(raw_intel, rows)
        if not online_warnings:
            write_warning = _safe_write_json(ECOSYSTEM_INTEL_KB_PATH, raw_intel)
            if write_warning:
                warnings.append(write_warning)

    metadata = _intel_metadata(raw_intel)
    cve_top = _build_cve_top(rows, metadata["cve_details"])
    tpl_top = _build_tpl_top(rows, metadata["library_details"], cve_top)

    return {
        "generated_at": _utc_iso(),
        "source_label": metadata["source_label"],
        "scope": metadata["scope"],
        "methodology": metadata["methodology"],
        "knowledge_base_version": metadata["version"],
        "generated_by": metadata["generated_by"],
        "total_cve_count": len({row["cve_id"] for row in rows}),
        "total_cve_record_count": len(rows),
        "total_library_count": len({row["library_name"] for row in rows}),
        "display_limit": DISPLAY_LIMIT,
        "cve_top": cve_top,
        "tpl_top": tpl_top,
        "warnings": warnings,
        "disclaimer": "生态参考情报，不代表当前 APK 已命中；当前 APK 风险应以本地扫描、版本识别和补丁验证结果为准。",
    }
