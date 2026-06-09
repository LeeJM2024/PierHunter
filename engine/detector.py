"""LibHunter / PHunter 工具调用：统一日志、工作目录与 subprocess 行为。"""
from __future__ import annotations

import os
import json
import re
import shlex
import shutil
import hashlib
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from config import (
    CVE_KB_PATH,
    DEFAULT_LIBHUNTER_TIMEOUT,
    DEFAULT_PHUNTER_THREADS,
    ANDROID_JAR,
    APK_PICKLE_CACHE_DIR,
    BUCKET_PICKLE_CACHE_DIR,
    JAVA_BIN,
    LIBHUNTER_DIR,
    LIBHUNTER_PROCESSES,    
    LIBHUNTER_SCRIPT,
    LIBHUNTER_TPLS_DEX,
    LIBHUNTER_TPLS_JAR,
    LIB_SIMILAR_THRESHOLD,
    LOG_DIR,
    PHUNTER_DIR,
    PHUNTER_JAR,
    PHUNTER_CACHE_DIR,
    PHUNTER_APK_PREWARM_TIMEOUT,
    PHUNTER_HEARTBEAT_TIMEOUT,
    PHUNTER_TIMEOUT,
    PICKLE_CACHE_DIR,
    PYTHON_BIN,
    RAW_DIR,
    SKELETON_PICKLE_CACHE_DIR,
    SUBPROCESS_HEARTBEAT_TIMEOUT,
    build_pythonpath,
)
from engine.kb_manager import resolve_kb_resource_path
from utils.normalizer import normalize_libhunter_lib
from utils.runner import CommandResult, run_command

_DETECTION_PATTERN = re.compile(
    r"lib:\s*(?P<lib>[^\r\n]+)\s+similarity:\s*(?P<similarity>[0-9.]+)",
    re.IGNORECASE | re.MULTILINE,
)
_LIBHUNTER_BLOCK_PATTERN = re.compile(
    r"(?ims)^\s*(?:lib|library)\s*:\s*.*?(?=^\s*(?:lib|library)\s*:|\Z)"
)
_LIBHUNTER_FIELD_LINE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9 _/\-]*\s*:")
_CLASS_LIST_LINE_PATTERN = re.compile(
    r"(?im)^\s*(?:class(?:\s*names?)?|classes?|class\s*names\s*/\s*packages?|packages?|package\s*names?)\s*:\s*(?P<value>.*)$"
)
_CLASS_TOKEN_PATTERN = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
)
_PATCH_METHODS_PATTERN = re.compile(
    r"patch-related\s+method\s+count\s*=\s*(\d+)",
    re.IGNORECASE,
)
_PRE_SIMILARITY_PATTERN = re.compile(
    r"pre\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)
_POST_SIMILARITY_PATTERN = re.compile(
    r"post\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)
_PHUNTER_RESOURCE_LIMIT_PATTERN = re.compile(
    r"("
    r"pthread_create\s+failed|"
    r"unable\s+to\s+create\s+native\s+thread|"
    r"EAGAIN|"
    r"process/resource\s+limits\s+reached|"
    r"OutOfMemoryError|"
    r"Java\s+heap\s+space|"
    r"GC\s+overhead\s+limit\s+exceeded|"
    r"heartbeat\s+timeout|"
    r"timed\s+out"
    r")",
    re.IGNORECASE,
)   
_PHUNTER_FATAL_PATTERN = re.compile(
    r"(failed\s+to\s+parse\s+command-line\s+arguments|the\s+analysis\s+has\s+failed)",
    re.IGNORECASE,
)
_LIBHUNTER_NOISY_TERMINAL_PATTERNS = (
    re.compile(r"Multiple exit nodes found !", re.IGNORECASE),
    re.compile(r"Unknown instruction\s*:\s*.+invalid_instruction", re.IGNORECASE),
    re.compile(r"Error loading/building lib .*unpack requires a buffer of 4 bytes", re.IGNORECASE),
)


def _has_phunter_fatal(text: str) -> bool:
    return bool(_PHUNTER_FATAL_PATTERN.search(text or ""))


def run_logged_command(
    cmd: List[str],
    *,
    cwd: Optional[Path],
    timeout: Optional[int],
    env: Optional[Dict[str, str]] = None,
    stream_output: bool = True,
    heartbeat_timeout: int = SUBPROCESS_HEARTBEAT_TIMEOUT,
    memory_limit_bytes: int = 0,
    stdout_log: Path,
    stderr_log: Path,
    suppress_terminal_patterns: tuple[re.Pattern[str], ...] = (),
) -> CommandResult:

    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    stderr_log.parent.mkdir(parents=True, exist_ok=True)
    stdout_log.write_text("", encoding="utf-8")
    stderr_log.write_text("", encoding="utf-8")

    def _append(log_path: Path, line: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _safe_echo(line: str) -> None:
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            encoding = (getattr(sys.stdout, "encoding", None) or "utf-8")
            safe = line.encode(encoding, errors="replace").decode(encoding, errors="replace")
            print(safe, flush=True)

    def _should_echo(line: str) -> bool:
        if not stream_output:
            return False
        return not any(p.search(line) for p in suppress_terminal_patterns)

    def _on_stdout(line: str) -> None:
        _append(stdout_log, line)
        if _should_echo(line):
            _safe_echo(line)

    def _on_stderr(line: str) -> None:
        _append(stderr_log, line)
        if _should_echo(line):
            _safe_echo(line)

    result = run_command(
        cmd,
        cwd=cwd,
        timeout=timeout,
        env=env,
        # Echo is handled in callbacks so we can filter noisy lines.
        stream_output=False,
        raise_on_error=False,
        on_stdout_line=_on_stdout,
        on_stderr_line=_on_stderr,
        heartbeat_timeout=heartbeat_timeout,
        memory_limit_bytes=memory_limit_bytes,
    )
    return result


def _parse_detection_text(text: str) -> list[dict]:
    detections = _parse_detection_json(text)
    if detections:
        return detections

    parsed: list[dict] = []
    blocks = _LIBHUNTER_BLOCK_PATTERN.findall(text or "")
    if blocks:
        for block in blocks:
            lib_match = re.search(
                r"(?im)^\s*(?:lib|library)\s*:\s*(?P<lib>[^\r\n]+)",
                block,
            )
            if not lib_match:
                continue
            raw_lib = lib_match.group("lib").strip()
            similarity_match = re.search(
                r"(?im)^\s*similarity\s*:\s*(?P<similarity>[0-9.]+)",
                block,
            )
            similarity = float(similarity_match.group("similarity")) if similarity_match else 0.0
            target_classes = _extract_target_classes_from_block(block)
            normalized = normalize_libhunter_lib(raw_lib)
            parsed.append({
                "raw_lib": raw_lib,
                "library_name": normalized["library_name"],
                "detected_version": normalized["version"],
                "similarity": similarity,
                "target_classes": target_classes,
            })
    else:
        for match in _DETECTION_PATTERN.finditer(text or ""):
            raw_lib = match.group("lib").strip()
            similarity = float(match.group("similarity"))
            normalized = normalize_libhunter_lib(raw_lib)
            parsed.append({
                "raw_lib": raw_lib,
                "library_name": normalized["library_name"],
                "detected_version": normalized["version"],
                "similarity": similarity,
                "target_classes": [],
            })

    parsed.sort(key=lambda item: item["similarity"], reverse=True)
    return parsed


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalize_class_token(token: str) -> str:
    value = (token or "").strip().strip("\"'`")
    if not value:
        return ""
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    value = value.replace("/", ".")
    if value.endswith(".*"):
        value = value[:-2]
    value = value.rstrip(".;").strip()
    return value


def _parse_class_candidates(raw_value: str) -> list[str]:
    raw_value = (raw_value or "").strip()
    if not raw_value:
        return []

    def _flatten(value: object) -> list[str]:
        if isinstance(value, list):
            flattened: list[str] = []
            for item in value:
                flattened.extend(_flatten(item))
            return flattened
        if value is None:
            return []
        return [str(value)]

    parsed_items: list[str] = []
    if raw_value.startswith("[") and raw_value.endswith("]"):
        try:
            loaded = json.loads(raw_value.replace("'", "\""))
            parsed_items = _flatten(loaded)
        except Exception:
            inside = raw_value[1:-1]
            parsed_items = re.split(r"[,;\n]+", inside)
    else:
        parsed_items = re.split(r"[,;\n]+", raw_value)

    normalized: list[str] = []
    for item in parsed_items:
        candidate = _normalize_class_token(str(item).lstrip("-* ").strip())
        if not candidate:
            continue
        if not _CLASS_TOKEN_PATTERN.match(candidate):
            continue
        normalized.append(candidate)
    return _dedupe_preserve_order(normalized)


def _extract_target_classes_from_block(block: str) -> list[str]:
    if not block:
        return []

    classes: list[str] = []
    lines = block.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _CLASS_LIST_LINE_PATTERN.match(line)
        if not match:
            index += 1
            continue
        value = (match.group("value") or "").strip()
        if value:
            classes.extend(_parse_class_candidates(value))
            index += 1
            continue

        index += 1
        extra_lines: list[str] = []
        while index < len(lines):
            next_line = lines[index].strip()
            lowered = next_line.lower()
            if not next_line:
                if extra_lines:
                    break
                index += 1
                continue
            if _LIBHUNTER_FIELD_LINE_PATTERN.match(next_line):
                break
            if lowered.startswith("similarity:") or lowered.startswith("time:"):
                break
            extra_lines.append(next_line.lstrip("-* ").strip())
            index += 1
        if extra_lines:
            classes.extend(_parse_class_candidates(",".join(extra_lines)))

    return _dedupe_preserve_order(classes)


def _parse_detection_json(text: str) -> list[dict]:
    source = (text or "").strip()
    if not source:
        return []
    if not (source.startswith("{") or source.startswith("[")):
        return []

    try:
        payload = json.loads(source)
    except Exception:
        return []

    if isinstance(payload, dict):
        rows = payload.get("detections")
        if not isinstance(rows, list):
            rows = payload.get("libraries")
        if not isinstance(rows, list):
            rows = [payload]
    elif isinstance(payload, list):
        rows = payload
    else:
        return []

    detections: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_lib = str(
            row.get("lib")
            or row.get("library")
            or row.get("name")
            or row.get("raw_lib")
            or ""
        ).strip()
        if not raw_lib:
            continue

        similarity_raw = row.get("similarity")
        try:
            similarity = float(similarity_raw) if similarity_raw is not None else 0.0
        except (TypeError, ValueError):
            similarity = 0.0

        target_classes_raw = (
            row.get("target_classes")
            or row.get("classes")
            or row.get("class_names")
            or row.get("classNames")
            or row.get("Class Names")
            or row.get("Class Names/Packages")
            or row.get("packages")
            or row.get("package_names")
        )
        target_classes: list[str] = []
        if isinstance(target_classes_raw, list):
            for item in target_classes_raw:
                target_classes.extend(_parse_class_candidates(str(item)))
        elif target_classes_raw is not None:
            target_classes = _parse_class_candidates(str(target_classes_raw))

        normalized = normalize_libhunter_lib(raw_lib)
        detections.append({
            "raw_lib": raw_lib,
            "library_name": normalized["library_name"],
            "detected_version": normalized["version"],
            "similarity": similarity,
            "target_classes": _dedupe_preserve_order(target_classes),
        })

    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return detections


def _normalize_target_classes(target_classes: list[str] | None) -> list[str]:
    if not target_classes:
        return []
    normalized: list[str] = []
    for value in target_classes:
        if value is None:
            continue
        normalized.extend(_parse_class_candidates(str(value)))
    return _dedupe_preserve_order(normalized)


def _is_cache_valid(pkl_path: Path, source_dex: Path) -> bool:
    if not pkl_path.exists():
        return False
    try:
        return pkl_path.stat().st_mtime >= source_dex.stat().st_mtime
    # 如果 pkl 的修改时间 >= 源 dex 的修改时间，就认为缓存没过期。
    except OSError:
        return False

# 统计并清理缓存状态
def warm_up_cache(tpl_dex_dir: Path, cache_dir: Path) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    # Support nested layout: tpl_dex/<lib_name>/<version>.dex
    dex_files = list(tpl_dex_dir.rglob("*.dex"))
    total = len(dex_files)
    cached = missing = stale = 0

    for dex in dex_files:
        rel = dex.relative_to(tpl_dex_dir)
        flat_name = str(rel).replace("/", "_").replace("\\", "_")
        pkl = cache_dir / flat_name.replace(".dex", ".pkl")
        if not pkl.exists():
            missing += 1
        elif not _is_cache_valid(pkl, dex):
            stale += 1
            pkl.unlink(missing_ok=True)
        else:
            cached += 1
    # 这个字典后面会被 run_libhunter() 使用
    return {"total": total, "cached": cached, "missing": missing, "stale": stale}


def inspect_libhunter_pickle_cache(cache_dir: Path) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    skeleton = 0
    version = 0
    for pkl in cache_dir.glob("*.pkl"):
        if pkl.name.endswith("_skeleton.pkl"):
            skeleton += 1
        else:
            version += 1
    return {"skeleton": skeleton, "version": version}

# 清空目录内容但保留目录本身(为LibHunter的预热工作做准备)
def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def prewarm_tpl_pickles(*, env: Dict[str, str], timeout: int) -> CommandResult:
    run_root = RAW_DIR / "libhunter" / "_prewarm"
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    ensure_clean_dir(apk_input_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o", str(output_dir),
        "-af", str(apk_input_dir),  # 空目录：仅触发 TPL 指纹提取与 pickle 构建
        "-p", str(LIBHUNTER_PROCESSES), # 并行进程数
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]
    if LIBHUNTER_TPLS_JAR.exists():
        cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])
    return run_logged_command(
        cmd,
        cwd=LIBHUNTER_DIR,
        timeout=timeout,
        env=env,
        stream_output=False,
        # 预热阶段可能长时间无输出，不应按心跳静默误判卡死
        heartbeat_timeout=0,
        stdout_log=LOG_DIR / "libhunter_prewarm.stdout.log",
        stderr_log=LOG_DIR / "libhunter_prewarm.stderr.log",
    )


def run_libhunter(apk_path: str | Path) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()

    checks = {
        "APK 文件": apk_path,
        "LibHunter 入口脚本": LIBHUNTER_SCRIPT,
        "TPL dex 特征库 (-ld)": LIBHUNTER_TPLS_DEX,
    }
    not_found = [f"  {label}: {path}" for label, path in checks.items() if not path.exists()]
    if not_found:
        raise FileNotFoundError("以下路径不存在，请检查目录结构：\n" + "\n".join(not_found))
    if not LIBHUNTER_TPLS_JAR.exists():
        print(
            f"[libhunter] 提示: 未找到 tpl_jar 目录 ({LIBHUNTER_TPLS_JAR})，"
            "将仅使用 tpl_dex 执行检测。"
        )

    env = os.environ.copy()
    env["PYTHONPATH"] = build_pythonpath()
    # TEST-ONLY: lets LibHunter write temporary template timing files beside run logs.
    env["LOG_DIR"] = str(LOG_DIR)
    env["LH_PICKLE_DIR"] = str(PICKLE_CACHE_DIR)
    env["LH_APK_PICKLE_DIR"] = str(APK_PICKLE_CACHE_DIR)
    env["LH_SKELETON_PICKLE_DIR"] = str(SKELETON_PICKLE_CACHE_DIR)
    env["LH_VERSION_PICKLE_DIR"] = str(PICKLE_CACHE_DIR)
    env["LH_BUCKET_PICKLE_DIR"] = str(BUCKET_PICKLE_CACHE_DIR)
    env["LH_MAX_THREAD_NUM"] = str(LIBHUNTER_PROCESSES)
    env["LH_ENABLE_TWO_STAGE"] = "1"
    env["LH_LIB_THRESHOLD"] = str(LIB_SIMILAR_THRESHOLD)
    # 限制每个进程内的 BLAS/OMP 线程，避免多进程场景下线程数爆炸。
    # 把各种常见数值计算库线程数都限制成 1，比如 NumPy/OpenBLAS/MKL
    env.setdefault("OMP_NUM_THREADS", "1")
    env.setdefault("OPENBLAS_NUM_THREADS", "1")
    env.setdefault("MKL_NUM_THREADS", "1")
    env.setdefault("NUMEXPR_NUM_THREADS", "1")
    env.setdefault("VECLIB_MAXIMUM_THREADS", "1")
    env.setdefault("BLIS_NUM_THREADS", "1")

    cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
    version_pickle_stats = inspect_libhunter_pickle_cache(PICKLE_CACHE_DIR)
    skeleton_pickle_stats = inspect_libhunter_pickle_cache(SKELETON_PICKLE_CACHE_DIR)
    print(
        "[libhunter] pickle 索引: "
        f"apk_cache={APK_PICKLE_CACHE_DIR}, "
        f"skeleton={skeleton_pickle_stats['skeleton']} "
        f"({SKELETON_PICKLE_CACHE_DIR}), "
        f"version={version_pickle_stats['version']} ({PICKLE_CACHE_DIR})"
    )
    if cache_stats["total"] == 0:
        print("[libhunter] 警告: tpl_dex 目录为空，无法检测任何库。")
    else:
        miss = cache_stats["missing"] + cache_stats["stale"]
        if miss > 0:
            print(
                f"[libhunter] 缓存预热: {cache_stats['cached']}/{cache_stats['total']} 命中, "
                f"{miss} 个 pkl 需要构建，开始执行预热 ..."
            )
            try:
                prewarm_timeout = max(DEFAULT_LIBHUNTER_TIMEOUT, 2 * 60 * 60)
                prewarm_start = time.time()
                prewarm_result = prewarm_tpl_pickles(env=env, timeout=prewarm_timeout)
                elapsed = time.time() - prewarm_start
                cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
                remain = cache_stats["missing"] + cache_stats["stale"]
                if prewarm_result.returncode == 0 and remain == 0:
                    print(
                        f"[libhunter] 预热完成: 全部 {cache_stats['total']} 个 pkl 就绪 "
                        f"(耗时 {elapsed:.1f}s)。"
                    )
                elif prewarm_result.returncode == 0:
                    print(
                        f"[libhunter] 预热部分完成: 剩余 {remain} 个 pkl 未就绪，"
                        "将在本轮检测中按需构建。"
                    )
                else:
                    print(
                        f"[libhunter] 预热子任务退出码={prewarm_result.returncode}，"
                        "将继续执行检测并按需构建缓存。"
                    )
            except Exception as exc:
                print(
                    f"[libhunter] 预热失败: {exc}，将继续执行检测并按需构建缓存。"
                )
        else:
            print(
                f"[libhunter] 缓存预热: 全部 {cache_stats['total']} 个 pkl 命中，"
                f"跳过反编译阶段。"
            )

    run_root = RAW_DIR / "libhunter" / apk_path.stem
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    apk_input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Some mounted filesystems reject metadata updates such as utime/chmod.
        # LibHunter only needs the APK bytes here, not source file metadata.
        shutil.copyfile(apk_path, apk_input_dir / apk_path.name)

        cmd = [
            str(PYTHON_BIN),
            str(LIBHUNTER_SCRIPT),
            "detect_all",
            "-o", str(output_dir),
            "-af", str(apk_input_dir),
            "-p", str(LIBHUNTER_PROCESSES),
            "-ld", str(LIBHUNTER_TPLS_DEX),
        ]
        if LIBHUNTER_TPLS_JAR.exists():
            cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])

        result = run_logged_command(
            cmd,
            cwd=LIBHUNTER_DIR,
            timeout=None,
            env=env,
            stream_output=True,
            heartbeat_timeout=0,
            stdout_log=LOG_DIR / f"libhunter_{apk_path.stem}.stdout.log",
            stderr_log=LOG_DIR / f"libhunter_{apk_path.stem}.stderr.log",
            suppress_terminal_patterns=_LIBHUNTER_NOISY_TERMINAL_PATTERNS,
        )

        if result.hung:
            return {
                "status": "hung",
                "cmd": result.cmd,
                "returncode": result.returncode,
                "raw_stdout": result.stdout,
                "raw_stderr": result.stderr,
                "result_file": None,
                "detections": [],
            }

        result_candidates = (
            output_dir / f"{apk_path.name}.json",
            output_dir / f"{apk_path.stem}.json",
            output_dir / f"{apk_path.name}.txt",
            output_dir / f"{apk_path.stem}.txt",
        )
        result_file = next((f for f in result_candidates if f.exists()), result_candidates[2])

        if result_file.exists():
            parsed_source = result_file.read_text(encoding="utf-8", errors="replace")
        else:
            parsed_source = "\n".join(p for p in (result.stdout, result.stderr) if p)

        detections = _parse_detection_text(parsed_source)

        if result.returncode != 0:
            status = "failed"
        elif not detections:
            status = "no_detections"
        else:
            status = "success"

        return {
            "status": status,
            "cmd": result.cmd,
            "returncode": result.returncode,
            "raw_stdout": result.stdout,
            "raw_stderr": result.stderr,
            "result_file": None,
            "detections": detections,
        }
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


def _extract_float(pattern: re.Pattern[str], text: str) -> float | None:
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def _extract_int(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def _parse_patch_status(text: str) -> str:
    upper_text = text.upper()
    if "THE PATCH IS NOT PRESENT" in upper_text:
        return "PATCH_NOT_PRESENT"
    if "THE PATCH IS PRESENT" in upper_text:
        return "PATCH_PRESENT"
    return "UNKNOWN"


def _is_phunter_resource_limit(text: str) -> bool:
    return bool(_PHUNTER_RESOURCE_LIMIT_PATTERN.search(text or ""))


def _phunter_combined_output(result: CommandResult) -> str:
    parts = [p for p in (result.stdout, result.stderr) if p]
    if result.hung:
        parts.append("heartbeat timeout")
    if getattr(result, "timed_out", False):
        parts.append("timed out")
    return "\n".join(parts)


def build_phunter_cmd(
    *,
    apk_path: Path | None = None,
    pre_patch_jar: Path | None = None,
    post_patch_jar: Path | None = None,
    patch_diff: Path | None = None,
    thread_num: int | None = None,
    target_classes: list[str] | None = None,
    java_opts: list[str] | None = None,
    prewarm_only: bool = False,
    prewarm_apk_only: bool = False,
) -> list[str]:
    cmd = [str(JAVA_BIN)]
    normalized_limit_classes = _normalize_target_classes(target_classes)
    if java_opts:
        cmd.extend(java_opts)
    cmd.extend(["-jar", str(PHUNTER_JAR)])
    if pre_patch_jar is not None:
        cmd.extend(["--preTPL", str(pre_patch_jar)])
    if post_patch_jar is not None:
        cmd.extend(["--postTPL", str(post_patch_jar)])
    if thread_num is not None:
        cmd.extend(["--threadNum", str(thread_num)])
    cmd.extend(["--androidJar", str(ANDROID_JAR)])
    if patch_diff is not None:
        cmd.extend(["--patchFiles", str(patch_diff)])
    if apk_path is not None:
        cmd.extend(["--targetAPK", str(apk_path)])
    if normalized_limit_classes:
        cmd.extend(["--limitClasses", ",".join(normalized_limit_classes)])
    if prewarm_only:
        cmd.append("--prewarmOnly")
    if prewarm_apk_only:
        cmd.append("--prewarmAPKOnly")
    return cmd


def _load_phunter_prewarm_targets_from_cve_kb() -> list[dict]:
    try:
        payload = json.loads(CVE_KB_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

    if not isinstance(payload, list):
        return []

    targets: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        pre_raw = str(row.get("pre_patch_jar", "")).strip()
        post_raw = str(row.get("post_patch_jar", "")).strip()
        diff_raw = str(row.get("patch_diff", "")).strip()
        if not pre_raw or not post_raw or not diff_raw:
            continue

        pre_path = Path(resolve_kb_resource_path(pre_raw)).expanduser().resolve()
        post_path = Path(resolve_kb_resource_path(post_raw)).expanduser().resolve()
        diff_path = Path(resolve_kb_resource_path(diff_raw)).expanduser().resolve()
        dedupe_key = (str(pre_path), str(post_path), str(diff_path))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        targets.append({
            "cve_id": str(row.get("cve_id", "")).strip() or "UNKNOWN-CVE",
            "pre_patch_jar": str(pre_path),
            "post_patch_jar": str(post_path),
            "patch_diff": str(diff_path),
        })
    return targets


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _compute_binary_analysis_key(source_file: Path) -> str:
    # Keep this aligned with PHunterCacheSupport.computeAnalyzerKey() when scopeClasses is empty.
    return _sha256_file(source_file)


def _compute_patch_summary_key(pre_file: Path, post_file: Path, patch_files: list[Path]) -> str:
    # Keep this aligned with PHunterCacheSupport.computePatchSummaryKey().
    pre_hash = _sha256_file(pre_file)
    post_hash = _sha256_file(post_file)
    patch_hashes: list[str] = []
    for patch_file in patch_files:
        if patch_file.exists():
            patch_hashes.append(_sha256_file(patch_file))
        else:
            patch_hashes.append(f"missing:{str(patch_file)}")
    joined = "\n".join(patch_hashes)
    return _sha256_text(f"pre={pre_hash}\npost={post_hash}\npatch={joined}")


def _collect_keep_keys_from_cve_kb() -> dict[str, set[str]]:
    keep_keys: dict[str, set[str]] = {
        "binary_analysis": set(),
        "patch_summary": set(),
        "apk_analysis": set(),
    }
    targets = _load_phunter_prewarm_targets_from_cve_kb()
    for target in targets:
        pre_file = Path(target["pre_patch_jar"]).expanduser().resolve()
        post_file = Path(target["post_patch_jar"]).expanduser().resolve()
        patch_raw = str(target.get("patch_diff", "")).strip()
        patch_files = [
            Path(part.strip()).expanduser().resolve()
            for part in patch_raw.split(";")
            if part and part.strip()
        ]
        if pre_file.exists():
            keep_keys["binary_analysis"].add(_compute_binary_analysis_key(pre_file))
        if post_file.exists():
            keep_keys["binary_analysis"].add(_compute_binary_analysis_key(post_file))
        if pre_file.exists() and post_file.exists():
            keep_keys["patch_summary"].add(
                _compute_patch_summary_key(pre_file, post_file, patch_files)
            )
    return keep_keys


def cleanup_phunter_cache_by_cve_kb() -> dict:
    cache_root = Path(PHUNTER_CACHE_DIR).expanduser().resolve()
    keep_keys = _collect_keep_keys_from_cve_kb()
    summary = {
        "cache_root": str(cache_root),
        "kept": 0,
        "deleted": 0,
        "scanned": 0,
        "deleted_entries": [],
        "alias_scanned": 0,
        "alias_kept": 0,
        "alias_deleted": 0,
    }
    if not cache_root.exists():
        return summary

    for domain_dir in sorted(p for p in cache_root.iterdir() if p.is_dir()):
        domain = domain_dir.name
        if domain == "apk_analysis":
            continue
        bucket_dir = domain_dir / "soot_cache_hash"
        if not bucket_dir.exists() or not bucket_dir.is_dir():
            continue

        domain_keep_keys = keep_keys.get(domain, set())
        for entry in sorted(p for p in bucket_dir.iterdir() if p.is_dir()):
            summary["scanned"] += 1
            key = entry.name
            if key in domain_keep_keys:
                summary["kept"] += 1
                continue
            shutil.rmtree(entry, ignore_errors=False)
            summary["deleted"] += 1
            summary["deleted_entries"].append(f"{domain}/{key}")

        # 同步清理 binary_analysis 下的旧 alias 映射，避免指向已删除/过期 key。
        if domain == "binary_analysis":
            alias_dir = domain_dir / "_aliases"
            if alias_dir.exists() and alias_dir.is_dir():
                for alias_file in sorted(p for p in alias_dir.iterdir() if p.is_file() and p.name.endswith(".latest")):
                    summary["alias_scanned"] += 1
                    try:
                        alias_key = alias_file.read_text(encoding="utf-8", errors="replace").strip()
                    except OSError:
                        alias_key = ""
                    if (
                        alias_key
                        and alias_key in domain_keep_keys
                        and (bucket_dir / alias_key).is_dir()
                    ):
                        summary["alias_kept"] += 1
                        continue
                    alias_file.unlink(missing_ok=True)
                    summary["alias_deleted"] += 1
    return summary


def run_phunter_template_prewarm(
    cve_meta: dict,
) -> dict:
    pre_patch_jar = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff = Path(cve_meta["patch_diff"]).expanduser().resolve()
    cve_id = str(cve_meta.get("cve_id", "UNKNOWN-CVE"))
    thread_num = int(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS))

    missing_paths = [
        str(path)
        for path in (PHUNTER_JAR, pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        return {
            "status": "skipped",
            "cve_id": cve_id,
            "missing_paths": missing_paths,
            "returncode": None,
            "raw_stdout": "",
            "raw_stderr": "",
        }

    java_opts = shlex.split(os.getenv("PHUNTER_JAVA_OPTS", ""))
    phunter_env = dict(os.environ)
    phunter_env["PHUNTER_CACHE_DIR"] = str(PHUNTER_CACHE_DIR)
    cmd = build_phunter_cmd(
        pre_patch_jar=pre_patch_jar,
        post_patch_jar=post_patch_jar,
        patch_diff=patch_diff,
        thread_num=thread_num,
        java_opts=java_opts,
        prewarm_only=True,
    )
    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=None,
        env=phunter_env,
        stream_output=True,
        heartbeat_timeout=0,
        stdout_log=LOG_DIR / f"phunter_prewarm_{cve_id}.stdout.log",
        stderr_log=LOG_DIR / f"phunter_prewarm_{cve_id}.stderr.log",
    )
    combined = "\n".join(p for p in (result.stdout, result.stderr) if p)

    if result.returncode == 0 and not _has_phunter_fatal(combined):
        status = "success"
    else:
        status = "failed"

    return {
        "status": status,
        "cve_id": cve_id,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
    }


def prewarm_phunter_templates_from_cve_kb(
    *,
    limit: int | None = None,
) -> dict:
    targets = _load_phunter_prewarm_targets_from_cve_kb()
    if limit is not None and limit > 0:
        targets = targets[:limit]

    summary = {
        "total": len(targets),
        "success": 0,
        "failed": 0,
        "skipped": 0,
    }
    if targets:
        print(f"[phunter] 开始模板预热，共 {len(targets)} 项（来源: {CVE_KB_PATH}）")
        for idx, target in enumerate(targets, start=1):
            cve_id = target.get("cve_id", "UNKNOWN-CVE")
            print(f"[phunter] 预热 {idx}/{len(targets)}: {cve_id}")
            result = run_phunter_template_prewarm(target)
            status = result.get("status", "failed")
            if status == "success":
                summary["success"] += 1
                continue
            if status == "skipped":
                summary["skipped"] += 1
                continue
            summary["failed"] += 1
    gc_summary = cleanup_phunter_cache_by_cve_kb()
    summary["gc"] = gc_summary
    print(
        "[phunter] 缓存清理完成: "
        f"scanned={gc_summary['scanned']}, kept={gc_summary['kept']}, deleted={gc_summary['deleted']}"
    )
    return summary


def prewarm_phunter_apk_cache(
    apk_path: str | Path,
) -> dict:
    apk = Path(apk_path).expanduser().resolve()
    if not apk.exists():
        return {
            "status": "skipped",
            "reason": f"APK not found: {apk}",
            "returncode": None,
        }

    missing_paths = [
        str(path)
        for path in (apk, PHUNTER_JAR, ANDROID_JAR)
        if not path.exists()
    ]
    if missing_paths:
        return {
            "status": "skipped",
            "reason": "Missing PHunter APK prewarm input files: " + ", ".join(missing_paths),
            "returncode": None,
        }

    java_opts_raw = os.getenv("PHUNTER_APK_PREWARM_JAVA_OPTS", "-Xmx4g -XX:ActiveProcessorCount=1")
    java_opts = shlex.split(java_opts_raw)
    phunter_env = dict(os.environ)
    phunter_env["PHUNTER_CACHE_DIR"] = str(PHUNTER_CACHE_DIR)

    cmd = build_phunter_cmd(
        apk_path=apk,
        thread_num=1,
        java_opts=java_opts,
        prewarm_apk_only=True,
    )
    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=PHUNTER_APK_PREWARM_TIMEOUT,
        env=phunter_env,
        stream_output=True,
        heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"phunter_prewarm_apk_{apk.stem}_full.stdout.log",
        stderr_log=LOG_DIR / f"phunter_prewarm_apk_{apk.stem}_full.stderr.log",
    )

    combined = _phunter_combined_output(result)
    if result.returncode == 0 and not result.hung and not getattr(result, "timed_out", False) and not _has_phunter_fatal(combined):
        status = "success"
    elif result.hung or getattr(result, "timed_out", False) or _is_phunter_resource_limit(combined):
        status = "resource_limited"
    else:
        status = "failed"

    return {
        "status": status,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "scope_label": "full",
        "java_opts": java_opts_raw,
        "hung": result.hung,
        "timed_out": getattr(result, "timed_out", False),
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
    }


def run_phunter(
    apk_path: str | Path,
    cve_meta: dict,
    target_classes: list[str] | None = None,
) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()
    pre_patch_jar = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff = Path(cve_meta["patch_diff"]).expanduser().resolve()

    missing_paths = [
        str(path)
        for path in (apk_path, PHUNTER_JAR, ANDROID_JAR,
                      pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        raise FileNotFoundError("Missing PHunter input files: " + ", ".join(missing_paths))

    cve_id = cve_meta["cve_id"]
    thread_num = int(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS))
    normalized_target_classes = _normalize_target_classes(target_classes)
    java_opts_raw = os.getenv("PHUNTER_JAVA_OPTS", "-Xmx3g -XX:ActiveProcessorCount=2")
    java_opts = shlex.split(java_opts_raw)
    phunter_env = dict(os.environ)
    phunter_env["PHUNTER_CACHE_DIR"] = str(PHUNTER_CACHE_DIR)

    cmd = build_phunter_cmd(
        apk_path=apk_path,
        pre_patch_jar=pre_patch_jar,
        post_patch_jar=post_patch_jar,
        patch_diff=patch_diff,
        thread_num=thread_num,
        target_classes=normalized_target_classes,
        java_opts=java_opts,
    )

    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=PHUNTER_TIMEOUT,
        env=phunter_env,
        stream_output=True,
        heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stdout.log",
        stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stderr.log",
    )

    combined = _phunter_combined_output(result)
    retried = False
    # 资源不足时触发重试
    if result.returncode != 0 and _is_phunter_resource_limit(combined):
        retried = True
        # 降低线程数
        retry_thread_num = max(1, min(thread_num, 2))
        # 读取重试专用 JVM 参数
        retry_java_opts_raw = os.getenv(
            "PHUNTER_JAVA_RETRY_OPTS",  
            "-Xmx4g -Xss256k -XX:ActiveProcessorCount=1", # -Xss256k：减小线程栈大小
            # -XX:ActiveProcessorCount=2：告诉 JVM 活跃处理器数按 2 处理
        )
        retry_java_opts = shlex.split(retry_java_opts_raw)
        retry_cmd = build_phunter_cmd(
            apk_path=apk_path,
            pre_patch_jar=pre_patch_jar,
            post_patch_jar=post_patch_jar,
            patch_diff=patch_diff,
            thread_num=retry_thread_num,
            target_classes=normalized_target_classes,
            java_opts=retry_java_opts,
        )
        retry_result = run_logged_command(
            retry_cmd,
            cwd=PHUNTER_DIR,
            timeout=PHUNTER_TIMEOUT,
            env=phunter_env,
            stream_output=True,
            heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
            stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stdout.log",
            stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stderr.log",
        )
        result = retry_result
        combined = _phunter_combined_output(result)

    patch_status = _parse_patch_status(combined)
    patch_related_method_count = _extract_int(_PATCH_METHODS_PATTERN, combined)
    pre_similarity = _extract_float(_PRE_SIMILARITY_PATTERN, combined)
    post_similarity = _extract_float(_POST_SIMILARITY_PATTERN, combined)

    if result.returncode == 0 and _has_phunter_fatal(combined):
        status = "failed"
        patch_status = "UNKNOWN"
    elif result.returncode == 0 and not result.hung and not getattr(result, "timed_out", False):
        status = "success"
    elif result.hung or getattr(result, "timed_out", False) or _is_phunter_resource_limit(combined):
        status = "resource_limited"
        patch_status = "RESOURCE_LIMIT"
    else:
        status = "failed"

    return {
        "status": status,
        "cve_id": cve_id,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "patch_status": patch_status,
        "patch_related_method_count": patch_related_method_count,
        "pre_similarity": pre_similarity,
        "post_similarity": post_similarity,
        "target_classes": normalized_target_classes,
        "java_opts": java_opts_raw,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "retried": retried,
        "hung": result.hung,
        "timed_out": getattr(result, "timed_out", False),
    }
