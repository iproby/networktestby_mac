#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN=""

print_header() {
  if [ -t 1 ]; then
    clear >/dev/null 2>&1 || true
  fi
  echo "=============================================="
  echo "  mac_net_watch bootstrap"
  echo "=============================================="
  echo
}

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

print_header

if ! find_python; then
  if ! install_python_with_brew; then
    echo "Не удалось автоматически найти или установить python3."
    echo
    echo "Что нужно сделать:"
    echo "1. Установить Homebrew с https://brew.sh"
    echo "2. Повторно запустить этот файл"
    echo
    read "?Нажмите Enter для выхода..."
    exit 1
  fi
fi

echo "Python: $PYTHON_BIN"
echo "Стартую интерфейс диагностики..."
echo
sleep 1

exec "$PYTHON_BIN" "$SCRIPT_DIR/mac_net_watch.py"
