#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
PYTHON_BIN=""
WATCH_PY="$SCRIPT_DIR/mac_net_watch.py"

if [[ ! -f "$WATCH_PY" ]]; then
  echo "Не найден mac_net_watch.py в $SCRIPT_DIR"
  echo "Клонируйте репозиторий целиком и запускайте лаунчер из папки проекта."
  exit 1
fi

python_usable() {
  local bin="$1"
  [[ -n "$bin" && -x "$bin" ]] || return 1
  "$bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}

find_python() {
  local candidates=()
  if command -v python3 >/dev/null 2>&1; then
    candidates+=("$(command -v python3)")
  fi
  candidates+=(
    /opt/homebrew/bin/python3
    /usr/local/bin/python3
    /usr/bin/python3
  )
  local bin
  for bin in "${candidates[@]}"; do
    if python_usable "$bin"; then
      PYTHON_BIN="$bin"
      return 0
    fi
  done
  return 1
}

install_python_with_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    return 1
  fi
  echo "python3 не найден. Устанавливаю через Homebrew..."
  brew install python
  hash -r >/dev/null 2>&1 || true
  find_python
}

if ! find_python; then
  if ! install_python_with_brew; then
    echo "Не удалось автоматически найти python3 3.9+."
    echo "Установите Homebrew с https://brew.sh и запустите снова."
    echo "Либо поставьте Command Line Tools: xcode-select --install"
    exit 1
  fi
fi

chmod +x "$WATCH_PY" "$SCRIPT_DIR/Запустить диагностику.command" "$SCRIPT_DIR/start_diagnostics.command" >/dev/null 2>&1 || true
exec "$PYTHON_BIN" "$WATCH_PY" "$@"
