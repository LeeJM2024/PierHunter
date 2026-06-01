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

  if LOG_DIR="${run_log_dir}" REPORT_DIR="${run_report_dir}" "${PYTHON_BIN}" "${PROJECT_DIR}/main.py" --apk "${apk}"; then
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
