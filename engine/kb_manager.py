"""漏洞情报库：加载 cve_kb.json，按库名/版本匹配并解析补丁资源路径。"""
from __future__ import annotations

import json
from pathlib import Path

from config import BASE_DIR, CVE_KB_PATH, DATA_DIR, PATCH_DIR
from engine.models import TPLibrary, Vulnerability
from utils.normalizer import build_library_aliases


def resolve_kb_resource_path(raw_path: str) -> str:
    """
    将 cve_kb.json 中的路径解析为绝对路径。

    支持：
    - 绝对路径（含 ~ 展开）：直接 resolve；
    - 相对项目根：如 data/patches/...；
    - 相对 data 或 patches：如仅写 patches/CVE-xxx/file.jar 时依次尝试。
    """
    text = (raw_path or "").strip()
    if not text:
        return str(BASE_DIR.resolve())

    p = Path(text).expanduser()
    if p.is_absolute():
        return str(p.resolve())

    rel = p.as_posix()
    candidates: list[Path] = [BASE_DIR / p]

    if not rel.startswith("data/"):
        candidates.append(DATA_DIR / p)
        candidates.append(PATCH_DIR / p)

    seen: set[str] = set()
    for c in candidates:
        key = str(c.resolve())
        if key in seen:
            continue
        seen.add(key)
        if c.exists():
            return str(c.resolve())

    return str((BASE_DIR / p).resolve())


class KnowledgeBase:
    """加载 CVE 知识库，为检测到的库挂载待验证漏洞列表。"""

    def __init__(self) -> None:
        self._cve_records = self._load_data()

    def _load_data(self) -> list[dict]:
        if not CVE_KB_PATH.exists():
            print(f"[!] 警告: 找不到漏洞情报库文件 {CVE_KB_PATH}，将无法进行漏洞匹配。")
            return []
        with CVE_KB_PATH.open("r", encoding="utf-8") as f:
            kb = json.load(f)
        if not isinstance(kb, list):
            raise ValueError("CVE knowledge base 必须是一个 JSON 数组 (List)")
        return kb

    def _versions_match(self, detected_version: str, affected_versions: list) -> bool:
        if not affected_versions:
            return True
        if not detected_version:
            return False
        return detected_version in {str(v) for v in affected_versions}

    def match_cves(self, library: TPLibrary) -> None:
        lib_aliases = build_library_aliases(library.normalized_name, library.raw_name)

        for record in self._cve_records:
            kb_aliases = build_library_aliases(
                record.get("library_name"),
                *(record.get("aliases") or []),
            )
            if not (lib_aliases & kb_aliases):
                continue
            if not self._versions_match(library.version, record.get("affected_versions")):
                continue

            try:
                pre_jar = resolve_kb_resource_path(record["pre_patch_jar"])
                post_jar = resolve_kb_resource_path(record["post_patch_jar"])
                patch_diff = resolve_kb_resource_path(record["patch_diff"])
            except KeyError as e:
                print(f"[!] cve_kb.json 记录 {record.get('cve_id', '?')} 缺少字段: {e}，跳过。")
                continue

            vuln = Vulnerability(
                cve_id=record["cve_id"],
                pre_patch_jar=pre_jar,
                post_patch_jar=post_jar,
                patch_diff=patch_diff,
            )
            if not any(v.cve_id == vuln.cve_id for v in library.vulnerabilities):
                library.vulnerabilities.append(vuln)
