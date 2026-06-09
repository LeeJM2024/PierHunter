import logging
import multiprocessing
import os
import os.path
from pathlib import Path

# ── 运行参数 ──────────────────────────────────────────────────
# Default to half of system CPUs (env override still supported).
_CPU_COUNT = multiprocessing.cpu_count() or 1
max_thread_num = int(os.environ.get("LH_MAX_THREAD_NUM", str(max(1, _CPU_COUNT // 2))))

# ── pickle 缓存目录[预热] ──
_fallback_pickle_dir = os.environ.get("LH_PICKLE_DIR", "").strip()
version_pickle_dir = os.environ.get("LH_VERSION_PICKLE_DIR", "").strip() or _fallback_pickle_dir
skeleton_pickle_dir = os.environ.get("LH_SKELETON_PICKLE_DIR", "").strip() or _fallback_pickle_dir
bucket_pickle_dir = os.environ.get("LH_BUCKET_PICKLE_DIR", "").strip()
apk_pickle_dir = os.environ.get("LH_APK_PICKLE_DIR", "").strip() or _fallback_pickle_dir
pickle_dir = version_pickle_dir
if not pickle_dir:
    raise RuntimeError("LH_VERSION_PICKLE_DIR or LH_PICKLE_DIR is required but not set.")
if not skeleton_pickle_dir:
    raise RuntimeError("LH_SKELETON_PICKLE_DIR or LH_PICKLE_DIR is required but not set.")
if not apk_pickle_dir:
    raise RuntimeError("LH_APK_PICKLE_DIR or LH_PICKLE_DIR is required but not set.")
if not bucket_pickle_dir:
    bucket_pickle_dir = os.path.join(os.path.dirname(skeleton_pickle_dir), "lib_pickles_buckets")

os.makedirs(pickle_dir, exist_ok=True)
os.makedirs(skeleton_pickle_dir, exist_ok=True)
os.makedirs(bucket_pickle_dir, exist_ok=True)
os.makedirs(apk_pickle_dir, exist_ok=True)

# 检测模式
detect_type = "lib_version"

class_similar  = 1
method_similar = 0.75
lib_similar    = 0.1


log_file = "log.txt"


def clear_log():
    if not os.path.exists(log_file):
        return
    try:
        os.remove(log_file)
    except OSError:
        # On Windows, the log file may still be held by another process/thread.
        # Logging cleanup should never abort the whole detection workflow.
        try:
            with open(log_file, "w", encoding="utf-8"):
                pass
        except OSError:
            pass


def setup_logger():
    logger = logging.getLogger()
    if not logger.handlers:
        if multiprocessing.current_process().name == "MainProcess":
            logger.setLevel(logging.INFO)
            fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - [%(lineno)d] - %(message)s'
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger

