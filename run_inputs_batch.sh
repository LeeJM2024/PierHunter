#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
STOP_ON_ERROR=0

DEFAULT_INPUT_DIRS=(
  "/datasets/artifact/package/apks_5_compilation_configuration"
  "/datasets/artifact/package/params_tuning_apks"
)
INPUT_DIRS=("${DEFAULT_INPUT_DIRS[@]}")

if [[ -x "${PROJECT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

CPU_TOTAL="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
if ! [[ "${CPU_TOTAL}" =~ ^[0-9]+$ ]] || [[ "${CPU_TOTAL}" -lt 1 ]]; then
  CPU_TOTAL=1
fi

export LIBHUNTER_PROCESSES="${LIBHUNTER_PROCESSES:-${CPU_TOTAL}}"
if [[ "${CPU_TOTAL}" -le 1 ]]; then
  export MAX_PHUNTER_CONCURRENT="${MAX_PHUNTER_CONCURRENT:-1}"
  export DEFAULT_PHUNTER_THREADS="${DEFAULT_PHUNTER_THREADS:-1}"
elif [[ "${CPU_TOTAL}" -le 3 ]]; then
  export MAX_PHUNTER_CONCURRENT="${MAX_PHUNTER_CONCURRENT:-1}"
  export DEFAULT_PHUNTER_THREADS="${DEFAULT_PHUNTER_THREADS:-${CPU_TOTAL}}"
else
  export MAX_PHUNTER_CONCURRENT="${MAX_PHUNTER_CONCURRENT:-2}"
  export DEFAULT_PHUNTER_THREADS="${DEFAULT_PHUNTER_THREADS:-$((CPU_TOTAL / 2))}"
fi

usage() {
  cat <<'EOF'
Usage:
  ./run_inputs_batch.sh [options]

Options:
  -i, --input-dir <dir>    Input APK directory (can be used multiple times)
                           Default:
                           /datasets/artifact/package/apk_13_different_optimization_strategies
                           /datasets/artifact/package/apks_5_compilation_configuration
                           /datasets/artifact/package/params_tuning_apks
                           Logs/reports will be split by source directory basename.
  -p, --python <bin>       Python executable (default: ./.venv/bin/python or python3)
  -s, --stop-on-error      Stop immediately when one APK fails
  -h, --help               Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--input-dir)
      if [[ "$#" -lt 2 ]]; then
        echo "Missing value for $1" >&2
        exit 2
      fi
      if [[ "${INPUT_DIRS[0]}" == "${DEFAULT_INPUT_DIRS[0]}" ]]; then
        INPUT_DIRS=()
      fi
      INPUT_DIRS+=("$2")
      shift 2
      ;;
    -p|--python)
      if [[ "$#" -lt 2 ]]; then
        echo "Missing value for $1" >&2
        exit 2
      fi
      PYTHON_BIN="$2"
      shift 2
      ;;
    -s|--stop-on-error)
      STOP_ON_ERROR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Python executable not found: ${PYTHON_BIN}" >&2
  exit 2
fi

VALID_INPUT_DIRS=()
for dir in "${INPUT_DIRS[@]}"; do
  if [[ -d "${dir}" ]]; then
    VALID_INPUT_DIRS+=("${dir}")
  else
    echo "Warning: input directory not found, skip: ${dir}" >&2
  fi
done

if [[ "${#VALID_INPUT_DIRS[@]}" -eq 0 ]]; then
  echo "No valid input directories found." >&2
  exit 2
fi

sanitize_name() {
  local raw="$1"
  local clean
  clean="$(echo "${raw}" | tr -c 'A-Za-z0-9._-' '_')"
  clean="${clean##_}"
  clean="${clean%%_}"
  if [[ -z "${clean}" ]]; then
    clean="unknown"
  fi
  printf '%s' "${clean}"
}

resolve_source_dir() {
  local apk_path="$1"
  local dir
  for dir in "${VALID_INPUT_DIRS[@]}"; do
    if [[ "${apk_path}" == "${dir}" || "${apk_path}" == "${dir}/"* ]]; then
      printf '%s' "${dir}"
      return 0
    fi
  done
  return 1
}

apk_stem() {
  local apk_path="$1"
  local name
  name="$(basename "${apk_path}")"
  printf '%s' "${name%.[aA][pP][kK]}"
}

profile_apk() {
  local apk_path="$1"
  local log_dir="$2"
  local stem
  stem="$(apk_stem "${apk_path}")"
  local profile_json="${log_dir}/apk_profile_${stem}.json"

  "${PYTHON_BIN}" - "${apk_path}" "${profile_json}" <<'PY'
import json
import os
import re
import struct
import sys
import zipfile

apk_path = sys.argv[1]
profile_json = sys.argv[2]

profile = {
    "apk_path": apk_path,
    "apk_name": os.path.basename(apk_path),
    "apk_size_bytes": 0,
    "apk_size_mb": 0.0,
    "zip_uncompressed_mb": 0.0,
    "entry_count": 0,
    "asset_files": 0,
    "native_libs": 0,
    "dex_count": 0,
    "dex_size_mb": 0.0,
    "dex_files": [],
    "class_defs": 0,
    "method_ids": 0,
    "field_ids": 0,
    "string_ids": 0,
    "type_ids": 0,
    "risk_score": 0.0,
    "risk_level": "UNKNOWN",
    "risk_reasons": [],
}

try:
    profile["apk_size_bytes"] = os.path.getsize(apk_path)
    profile["apk_size_mb"] = profile["apk_size_bytes"] / 1024 / 1024
    with zipfile.ZipFile(apk_path) as zf:
        for info in zf.infolist():
            profile["entry_count"] += 1
            profile["zip_uncompressed_mb"] += info.file_size / 1024 / 1024
            name = info.filename
            if name.startswith("assets/"):
                profile["asset_files"] += 1
            if name.startswith("lib/") and name.endswith(".so"):
                profile["native_libs"] += 1
            if not re.match(r"(^|/)classes(\d*)\.dex$", name):
                continue

            dex = {
                "name": name,
                "size_mb": info.file_size / 1024 / 1024,
                "class_defs": 0,
                "method_ids": 0,
                "field_ids": 0,
                "string_ids": 0,
                "type_ids": 0,
            }
            profile["dex_count"] += 1
            profile["dex_size_mb"] += dex["size_mb"]
            with zf.open(info) as dex_handle:
                header = dex_handle.read(0x70)
            if len(header) >= 0x70 and header[:3] == b"dex":
                dex["string_ids"] = struct.unpack_from("<I", header, 0x38)[0]
                dex["type_ids"] = struct.unpack_from("<I", header, 0x40)[0]
                dex["field_ids"] = struct.unpack_from("<I", header, 0x50)[0]
                dex["method_ids"] = struct.unpack_from("<I", header, 0x58)[0]
                dex["class_defs"] = struct.unpack_from("<I", header, 0x60)[0]
            for key in ("class_defs", "method_ids", "field_ids", "string_ids", "type_ids"):
                profile[key] += dex[key]
            profile["dex_files"].append(dex)

    score = 0.0
    score += profile["class_defs"] / 1000.0
    score += profile["method_ids"] / 10000.0
    score += profile["string_ids"] / 20000.0
    score += max(0, profile["dex_count"] - 1) * 2.0
    score += profile["dex_size_mb"] / 10.0
    profile["risk_score"] = round(score, 2)

    if score >= 60:
        profile["risk_level"] = "EXTREME"
    elif score >= 35:
        profile["risk_level"] = "HIGH"
    elif score >= 15:
        profile["risk_level"] = "MEDIUM"
    else:
        profile["risk_level"] = "LOW"

    if profile["class_defs"] >= 20000:
        profile["risk_reasons"].append("class_defs>=20000")
    if profile["method_ids"] >= 150000:
        profile["risk_reasons"].append("method_ids>=150000")
    if profile["string_ids"] >= 120000:
        profile["risk_reasons"].append("string_ids>=120000")
    if profile["dex_count"] >= 4:
        profile["risk_reasons"].append("dex_count>=4")
    if profile["apk_size_mb"] >= 50 and profile["dex_size_mb"] < 5:
        profile["risk_reasons"].append("large_apk_but_small_dex")
except Exception as exc:
    profile["error"] = str(exc)

os.makedirs(os.path.dirname(profile_json), exist_ok=True)
with open(profile_json, "w", encoding="utf-8") as handle:
    json.dump(profile, handle, ensure_ascii=False, indent=2)

print(
    "[apk-profile] "
    f"risk={profile['risk_level']} score={profile['risk_score']} "
    f"apk_mb={profile['apk_size_mb']:.1f} dex_mb={profile['dex_size_mb']:.1f} "
    f"dex={profile['dex_count']} classes={profile['class_defs']} "
    f"methods={profile['method_ids']} strings={profile['string_ids']} "
    f"native_libs={profile['native_libs']} profile={profile_json}"
)
if profile["risk_reasons"]:
    print("[apk-profile] reasons=" + ",".join(profile["risk_reasons"]))
PY
}

summarize_libhunter_timing() {
  local apk_path="$1"
  local log_dir="$2"
  local stem
  stem="$(apk_stem "${apk_path}")"
  local stderr_log="${log_dir}/libhunter_${stem}.stderr.log"
  local summary_csv="${log_dir}/libhunter_${stem}_progress_summary.csv"
  local summary_json="${log_dir}/libhunter_${stem}_progress_summary.json"

  if [[ ! -f "${stderr_log}" ]]; then
    return 0
  fi

  "${PYTHON_BIN}" - "${stderr_log}" "${summary_csv}" "${summary_json}" <<'PY'
import csv
import json
import os
import re
import sys

stderr_log, summary_csv, summary_json = sys.argv[1:4]

def parse_elapsed(value):
    parts = [int(part) for part in value.split(":")]
    if len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    return parts[0] if parts else 0

pattern = re.compile(
    r"(?P<stage>Stage1|Bucket|FullScan)\s+"
    r"(?P<label>.*?):.*?\|\s*(?P<current>\d+)/(?:\s*)?(?P<total>\d+)\s*"
    r"\[(?P<elapsed>[0-9:]+)(?:<[^,\]]*)?(?:,\s*(?P<metric>[0-9.]+)(?P<unit>s/it|it/s))?",
    re.S,
)

try:
    text = open(stderr_log, "r", encoding="utf-8", errors="replace").read()
except OSError as exc:
    print(f"[libhunter-timing] cannot read {stderr_log}: {exc}")
    sys.exit(0)

events = []
seen = set()
for match in pattern.finditer(text.replace("\r", "\n")):
    current = int(match.group("current"))
    total = int(match.group("total"))
    stage = match.group("stage")
    label = " ".join(match.group("label").split())
    key = (stage, current, total)
    if key in seen:
        continue
    seen.add(key)
    events.append({
        "stage": stage,
        "label": label,
        "current": current,
        "total": total,
        "elapsed_s": parse_elapsed(match.group("elapsed")),
        "delta_elapsed_s": "",
        "metric": match.group("metric") or "",
        "metric_unit": match.group("unit") or "",
        "raw": " ".join(match.group(0).split()),
    })

last_elapsed_by_stage = {}
for event in events:
    previous = last_elapsed_by_stage.get(event["stage"])
    if previous is not None:
        event["delta_elapsed_s"] = max(0, event["elapsed_s"] - previous)
    last_elapsed_by_stage[event["stage"]] = event["elapsed_s"]

os.makedirs(os.path.dirname(summary_csv), exist_ok=True)
with open(summary_csv, "w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(
        handle,
        fieldnames=[
            "stage",
            "label",
            "current",
            "total",
            "elapsed_s",
            "delta_elapsed_s",
            "metric",
            "metric_unit",
            "raw",
        ],
    )
    writer.writeheader()
    writer.writerows(events)

stage_totals = {}
for event in events:
    stage_totals[event["stage"]] = max(stage_totals.get(event["stage"], 0), event["elapsed_s"])

slow_events = sorted(
    [event for event in events if isinstance(event.get("delta_elapsed_s"), int)],
    key=lambda item: item["delta_elapsed_s"],
    reverse=True,
)[:20]

summary = {
    "source_log": stderr_log,
    "summary_csv": summary_csv,
    "event_count": len(events),
    "stage_elapsed_s": stage_totals,
    "slowest_progress_samples": slow_events,
    "note": "Rows are sampled from tqdm progress output. delta_elapsed_s identifies slow progress intervals; mapping a row back to an exact library template requires LibHunter internal task logging.",
}
with open(summary_json, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, ensure_ascii=False, indent=2)

print(
    "[libhunter-timing] "
    f"events={len(events)} summary={summary_json} csv={summary_csv}"
)
for event in slow_events[:5]:
    print(
        "[libhunter-timing] slow "
        f"{event['stage']} {event['current']}/{event['total']} "
        f"delta={event['delta_elapsed_s']}s elapsed={event['elapsed_s']}s "
        f"{event['metric']}{event['metric_unit']}"
    )
PY
}

mapfile -t APK_FILES < <(find "${VALID_INPUT_DIRS[@]}" -type f -iname "*.apk" | sort)
TOTAL="${#APK_FILES[@]}"

if [[ "${TOTAL}" -eq 0 ]]; then
  echo "No APK files found in provided directories."
  exit 0
fi

echo "Project dir : ${PROJECT_DIR}"
echo "Input dirs  :"
for dir in "${VALID_INPUT_DIRS[@]}"; do
  echo "  - ${dir}"
done
echo "Python bin  : ${PYTHON_BIN}"
echo "APK count   : ${TOTAL}"
echo "CPU total   : ${CPU_TOTAL}"
echo "LibHunter   : LIBHUNTER_PROCESSES=${LIBHUNTER_PROCESSES}"
echo "PHunter     : MAX_PHUNTER_CONCURRENT=${MAX_PHUNTER_CONCURRENT}, DEFAULT_PHUNTER_THREADS=${DEFAULT_PHUNTER_THREADS}"
echo

SUCCESS=0
FAILED=0
FAILED_LIST=()
BATCH_START="$(date +%s)"

for idx in "${!APK_FILES[@]}"; do
  apk="${APK_FILES[$idx]}"
  current="$((idx + 1))"
  start_ts="$(date +%s)"
  source_dir="$(resolve_source_dir "${apk}" || true)"
  source_name="$(basename "${source_dir:-unknown}")"
  source_tag="$(sanitize_name "${source_name}")"
  run_log_dir="${PROJECT_DIR}/storage/logs/${source_tag}"
  run_report_dir="${PROJECT_DIR}/storage/reports/${source_tag}"
  mkdir -p "${run_log_dir}" "${run_report_dir}"

  echo "[$current/$TOTAL] Start: ${apk}"
  echo "            group=${source_tag}"
  echo "            log_dir=${run_log_dir}"
  echo "            report_dir=${run_report_dir}"

  profile_apk "${apk}" "${run_log_dir}" || true

  LOG_DIR="${run_log_dir}" REPORT_DIR="${run_report_dir}" "${PYTHON_BIN}" "${PROJECT_DIR}/main.py" --apk "${apk}"
  main_status="$?"

  summarize_libhunter_timing "${apk}" "${run_log_dir}" || true

  if [[ "${main_status}" -eq 0 ]]; then
    SUCCESS="$((SUCCESS + 1))"
    status="OK"
  else
    FAILED="$((FAILED + 1))"
    FAILED_LIST+=("${apk}")
    status="FAILED"
    if [[ "${STOP_ON_ERROR}" -eq 1 ]]; then
      echo "Stop on error enabled, aborting."
      break
    fi
  fi

  end_ts="$(date +%s)"
  echo "[$current/$TOTAL] Done: ${status} (elapsed: $((end_ts - start_ts))s)"
  echo
done

BATCH_END="$(date +%s)"
echo "================ Batch Summary ================"
echo "Total     : ${TOTAL}"
echo "Success   : ${SUCCESS}"
echo "Failed    : ${FAILED}"
echo "Elapsed   : $((BATCH_END - BATCH_START))s"

if [[ "${FAILED}" -gt 0 ]]; then
  echo
  echo "Failed APKs:"
  for apk in "${FAILED_LIST[@]}"; do
    echo "- ${apk}"
  done
  exit 1
fi

echo "All APKs analyzed successfully."
exit 0
