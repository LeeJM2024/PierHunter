from __future__ import annotations

import os
from typing import Dict, List

from packaging.version import InvalidVersion, Version


def _version_sort_key(path: str):
    filename = os.path.basename(path)
    stem = filename[:-4] if filename.endswith(".dex") else filename
    version = stem.split("_", 1)[-1] if "_" in stem else stem
    normalized = version.replace("_", ".").strip()
    try:
        return (0, Version(normalized), normalized)
    except InvalidVersion:
        return (1, normalized.lower(), normalized)


def build_lib_groups(lib_dex_folder: str) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    if not os.path.isdir(lib_dex_folder):
        return groups

    for family_name in os.listdir(lib_dex_folder):
        family_path = os.path.join(lib_dex_folder, family_name)
        if not os.path.isdir(family_path):
            continue
        versions = [f"{family_name}/{name}" for name in os.listdir(family_path) if name.endswith(".dex")]
        if versions:
            groups[family_name] = sorted(versions, key=_version_sort_key)

    return groups
