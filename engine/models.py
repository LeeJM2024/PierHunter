from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Vulnerability:
    """代表一个具体的 CVE 漏洞及其补丁验证状态。"""

    cve_id: str
    pre_patch_jar: str
    post_patch_jar: str
    patch_diff: str

    patch_status: str = "UNTESTED"
    pre_similarity: Optional[float] = None
    post_similarity: Optional[float] = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class TPLibrary:
    """代表 APK 中检测出的第三方库。"""

    raw_name: str
    normalized_name: str
    version: str
    similarity: float
    target_classes: List[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class ApkContext:
    """当前正在分析的 APK 会话上下文。"""

    path: str
    name: str
    sha256: str
    file_size: int
    libraries: List[TPLibrary] = field(default_factory=list)
