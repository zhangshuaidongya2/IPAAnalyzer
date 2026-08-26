#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
PROJECT_ROOT="${SCRIPT_DIR:h}"
VENV_PATH="${PROJECT_ROOT}/.venv"
PYTHON_BIN="${VENV_PATH}/bin/python"
export PIP_CACHE_DIR="${PROJECT_ROOT}/build/pip-cache"
export PYINSTALLER_CONFIG_DIR="${PROJECT_ROOT}/build/pyinstaller-config"

mkdir -p "${PIP_CACHE_DIR}" "${PYINSTALLER_CONFIG_DIR}"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  python3 -m venv "${VENV_PATH}"
fi

"${PYTHON_BIN}" -m pip install --disable-pip-version-check -r "${PROJECT_ROOT}/requirements-build.txt"

export IPA_ANALYZER_VERSION="${IPA_ANALYZER_VERSION:-0.1.0}"
if [[ -z "${PYINSTALLER_TARGET_ARCH:-}" ]]; then
  export PYINSTALLER_TARGET_ARCH="$(uname -m)"
fi
case "${PYINSTALLER_TARGET_ARCH}" in
  arm64|x86_64|universal2) ;;
  *)
    print -u2 "Unsupported PYINSTALLER_TARGET_ARCH: ${PYINSTALLER_TARGET_ARCH}"
    exit 2
    ;;
esac

DIST_ROOT="${IPA_ANALYZER_DIST_ROOT:-${PROJECT_ROOT}/dist/${PYINSTALLER_TARGET_ARCH}}"
WORK_ROOT="${PROJECT_ROOT}/build/pyinstaller/${PYINSTALLER_TARGET_ARCH}"

cd "${PROJECT_ROOT}"
export PYINSTALLER_STRICT_BUNDLE_CODESIGN_ERROR=1
export PYINSTALLER_VERIFY_BUNDLE_SIGNATURE=1
"${VENV_PATH}/bin/pyinstaller" \
  --noconfirm \
  --clean \
  --distpath "${DIST_ROOT}" \
  --workpath "${WORK_ROOT}" \
  "${PROJECT_ROOT}/IPAAnalyzer.spec"

APP_PATH="${DIST_ROOT}/IPA Analyzer.app"
APP_EXECUTABLE="${APP_PATH}/Contents/MacOS/IPA Analyzer"
ACTUAL_ARCHS="$(lipo -archs "${APP_EXECUTABLE}")"
if [[ "${PYINSTALLER_TARGET_ARCH}" == "universal2" ]]; then
  for required_arch in arm64 x86_64; do
    if ! print -r -- "${ACTUAL_ARCHS}" | tr ' ' '\n' | grep -Fx "${required_arch}" >/dev/null; then
      print -u2 "Missing ${required_arch} slice: ${APP_EXECUTABLE}"
      exit 1
    fi
  done
elif [[ "${ACTUAL_ARCHS}" != "${PYINSTALLER_TARGET_ARCH}" ]]; then
  print -u2 "Expected ${PYINSTALLER_TARGET_ARCH}, found ${ACTUAL_ARCHS}: ${APP_EXECUTABLE}"
  exit 1
fi

HOST_ARCH="$(uname -m)"
if [[ "${PYINSTALLER_TARGET_ARCH}" == "${HOST_ARCH}" || "${PYINSTALLER_TARGET_ARCH}" == "universal2" ]]; then
  "${APP_EXECUTABLE}" --smoke-test
elif [[ "${HOST_ARCH}" == "arm64" && "${PYINSTALLER_TARGET_ARCH}" == "x86_64" ]] && \
    arch -x86_64 /usr/bin/true 2>/dev/null; then
  arch -x86_64 "${APP_EXECUTABLE}" --smoke-test
else
  print "Skipping cross-architecture smoke test for ${PYINSTALLER_TARGET_ARCH}."
fi
codesign --verify --deep --strict --verbose=2 "${APP_PATH}"

COLLECTION_PATH="${DIST_ROOT}/IPA Analyzer"
if [[ -d "${COLLECTION_PATH}" ]]; then
  rm -rf "${COLLECTION_PATH}"
fi

print "Built ${APP_PATH}"
