from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional local helper
    load_dotenv = None


def _to_path(value: str, *, base_dir: Path) -> Path:
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = (base_dir / p)
    return p.resolve()


def _env_path(name: str, default: Path, *, base_dir: Path) -> Path:
    raw = os.getenv(name)
    if raw:
        return _to_path(raw, base_dir=base_dir)
    return default.resolve()


def _env_executable(name: str, default: Path | str, *, base_dir: Path) -> Path | str:
    raw = os.getenv(name)
    if not raw:
        return default
    value = raw.strip()
    if not value:
        return default
    if Path(value).is_absolute() or "/" in value or "\\" in value:
        return _to_path(value, base_dir=base_dir)
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# 项目根目录
BASE_DIR = Path(__file__).resolve().parent
if load_dotenv is not None:
    load_dotenv(BASE_DIR / ".env")

# ── 运行时存储目录（Docker volume 友好）──────────────────────────
STORAGE_DIR = _env_path("STORAGE_DIR", BASE_DIR / "storage", base_dir=BASE_DIR)
UPLOAD_DIR = _env_path("UPLOAD_DIR", STORAGE_DIR / "uploads", base_dir=BASE_DIR)
REPORT_DIR = _env_path("REPORT_DIR", STORAGE_DIR / "reports", base_dir=BASE_DIR)
LOG_DIR = _env_path("LOG_DIR", STORAGE_DIR / "logs", base_dir=BASE_DIR)

# ── 兼容旧输出结构 ──────────────────────────────────────────────
OUTPUT_DIR = _env_path("OUTPUT_DIR", BASE_DIR / "outputs", base_dir=BASE_DIR)
RAW_DIR = _env_path("RAW_DIR", OUTPUT_DIR / "raw", base_dir=BASE_DIR)
# 兼容旧变量名：现作为上传目录
INPUT_DIR = UPLOAD_DIR

# ── 数据层 ───────────────────────────────────────────────────
DATA_DIR = _env_path("DATA_DIR", BASE_DIR / "data", base_dir=BASE_DIR)
PATCH_DIR = _env_path("PATCH_DIR", DATA_DIR / "patches", base_dir=BASE_DIR)
CVE_KB_PATH = _env_path("CVE_KB_PATH", DATA_DIR / "cve_kb.json", base_dir=BASE_DIR)

# ── LibHunter pickle 全局缓存目录[预热] ────────────────────────────
PICKLE_CACHE_DIR = _env_path("PICKLE_CACHE_DIR", DATA_DIR / "lib_pickles_cache", base_dir=BASE_DIR)
APK_PICKLE_CACHE_DIR = _env_path(
    "APK_PICKLE_CACHE_DIR",
    DATA_DIR / "apk_pickles_cache",
    base_dir=BASE_DIR,
)
SKELETON_PICKLE_CACHE_DIR = _env_path(
    "SKELETON_PICKLE_CACHE_DIR",
    DATA_DIR / "lib_pickles_skeleton",
    base_dir=BASE_DIR,
)
BUCKET_PICKLE_CACHE_DIR = _env_path(
    "BUCKET_PICKLE_CACHE_DIR",
    DATA_DIR / "lib_pickles_buckets",
    base_dir=BASE_DIR,
)

# TPL 特征库目录
LIBHUNTER_TPLS_DEX = _env_path("LIBHUNTER_TPLS_DEX", DATA_DIR / "tpl_dex", base_dir=BASE_DIR)
LIBHUNTER_TPLS_JAR = _env_path("LIBHUNTER_TPLS_JAR", DATA_DIR / "tpl_jar", base_dir=BASE_DIR)

# ── LibHunter 工具 ────────────────────────────────────────────
LIBHUNTER_DIR = _env_path("LIBHUNTER_DIR", BASE_DIR / "LibHunter", base_dir=BASE_DIR)
LIBHUNTER_SCRIPT = _env_path("LIBHUNTER_SCRIPT", LIBHUNTER_DIR / "LibHunter.py", base_dir=BASE_DIR)

if sys.platform == "win32":
    _lh_venv_python = LIBHUNTER_DIR / ".venv" / "Scripts" / "python.exe"
else:
    _lh_venv_python = LIBHUNTER_DIR / ".venv" / "bin" / "python"
_default_python_bin = _lh_venv_python if _lh_venv_python.exists() else Path(sys.executable)
PYTHON_BIN = _env_executable("PYTHON_BIN", _default_python_bin, base_dir=BASE_DIR)

# ── PHunter 工具 ──────────────────────────────────────────────
PHUNTER_DIR = _env_path("PHUNTER_DIR", BASE_DIR / "PHunter", base_dir=BASE_DIR)
PHUNTER_JAR = _env_path("PHUNTER_JAR_PATH", PHUNTER_DIR / "PHunter.jar", base_dir=BASE_DIR)
ANDROID_JAR = _env_path("ANDROID_JAR_PATH", PHUNTER_DIR / "android-31" / "android.jar", base_dir=BASE_DIR)
PHUNTER_CACHE_DIR = _env_path("PHUNTER_CACHE_DIR", DATA_DIR / "phunter_soot_cache", base_dir=BASE_DIR)

# ── 系统工具 ──────────────────────────────────────────────────
JAVA_BIN = _env_executable("JAVA_BIN", Path(shutil.which("java") or "java"), base_dir=BASE_DIR)

# ── 超时 / 线程 ───────────────────────────────────────────────
_CPU_COUNT = os.cpu_count() or 1
_DEFAULT_LIBHUNTER_PROCESSES = max(1, _CPU_COUNT // 2)
DEFAULT_PHUNTER_THREADS = _env_int("DEFAULT_PHUNTER_THREADS", 4)
DEFAULT_LIBHUNTER_TIMEOUT = _env_int("DEFAULT_LIBHUNTER_TIMEOUT", 40 * 60)
MAX_PHUNTER_CONCURRENT = _env_int("MAX_PHUNTER_CONCURRENT", 4)
LIB_SIMILAR_THRESHOLD = _env_float("LH_LIB_THRESHOLD", 0.85)
SUBPROCESS_HEARTBEAT_TIMEOUT = _env_int("HEARTBEAT_TIMEOUT", 60)
LIBHUNTER_PROCESSES = _env_int("LIBHUNTER_PROCESSES", _DEFAULT_LIBHUNTER_PROCESSES)
LIBHUNTER_HEARTBEAT_TIMEOUT = _env_int("LIBHUNTER_HEARTBEAT_TIMEOUT", 600)


def build_pythonpath() -> str:
    """将 LibHunter 根目录注入 PYTHONPATH，让子进程能找到 module 包"""
    paths = [str(LIBHUNTER_DIR)]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return os.pathsep.join(paths)


def ensure_runtime_dirs() -> None:
    for path in (
        STORAGE_DIR,
        UPLOAD_DIR,
        OUTPUT_DIR,
        LOG_DIR,
        RAW_DIR,
        REPORT_DIR,
        DATA_DIR,
        PATCH_DIR,
        PICKLE_CACHE_DIR,
        APK_PICKLE_CACHE_DIR,
        SKELETON_PICKLE_CACHE_DIR,
        BUCKET_PICKLE_CACHE_DIR,
        PHUNTER_CACHE_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
