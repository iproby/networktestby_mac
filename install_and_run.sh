#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN=""

find_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
    return 0
  fi
  return 1
}

install_python_with_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    return 1
  fi
  echo "python3 не найден. Устанавливаю через Homebrew..."
  brew install python
  find_python
}

if ! find_python; then
  if ! install_python_with_brew; then
    echo "Не удалось автоматически найти python3."
    echo "Установите Homebrew с https://brew.sh и запустите снова."
    exit 1
  fi
fi

chmod +x "$SCRIPT_DIR/mac_net_watch.py" "$SCRIPT_DIR/Запустить диагностику.command" "$SCRIPT_DIR/start_diagnostics.command" >/dev/null 2>&1 || true
exec "$PYTHON_BIN" "$SCRIPT_DIR/mac_net_watch.py" "$@"
