#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"

case "${1:-}" in
    --help|-h)
        cat <<'EOF'
Usage: ./run_debug.sh [IPA_FILE] [--jctools] [--downloads-directory PATH]

直接运行当前 IPAInspector 源码，日志输出到当前终端，无需打包。
首次运行自动创建 .venv 并安装 GUI 依赖，需要 Python 3.11+。

Examples:
  ./run_debug.sh
  ./run_debug.sh "/path/to/Example App.ipa"
  ./run_debug.sh --jctools --downloads-directory "$HOME/Downloads/jctoolsDownloads"
EOF
        exit 0
        ;;
esac

if [[ ! -x "$PYTHON_BIN" ]]; then
    if ! command -v python3 >/dev/null 2>&1 ||
        ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
        echo "需要 Python 3.11 或更高版本，请先安装后再运行。" >&2
        exit 1
    fi
    echo "正在创建 IPAInspector 虚拟环境：$VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

if ! "$PYTHON_BIN" -c 'from PySide6.QtWidgets import QApplication' >/dev/null 2>&1; then
    echo "正在安装 IPAInspector GUI 依赖..."
    export PIP_CACHE_DIR="${PIP_CACHE_DIR:-$ROOT_DIR/build/pip-cache}"
    "$PYTHON_BIN" -m pip install --disable-pip-version-check -r "$ROOT_DIR/requirements.txt"
fi

echo "IPAInspector 将使用当前源码启动，日志输出到当前终端。关闭窗口即可退出。"
export NSUnbufferedIO=YES
exec "$PYTHON_BIN" -u "$ROOT_DIR/gui_main.py" "$@"
