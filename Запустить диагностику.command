#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

print_header() {
  if [ -t 1 ]; then
    clear >/dev/null 2>&1 || true
  fi
  echo "=============================================="
  echo "  mac_net_watch bootstrap"
  echo "=============================================="
  echo
}

print_header

if [[ ! -f "$SCRIPT_DIR/mac_net_watch.py" ]]; then
  echo "Не найден mac_net_watch.py рядом с этим файлом."
  echo "Клонируйте репозиторий целиком и запускайте лаунчер из папки проекта."
  echo
  if [ -t 0 ]; then
    read "?Нажмите Enter для выхода..."
  fi
  exit 1
fi

chmod +x "$SCRIPT_DIR/install_and_run.sh" >/dev/null 2>&1 || true

set +e
"$SCRIPT_DIR/install_and_run.sh" "$@"
status=$?
set -e

if [ "$status" -ne 0 ]; then
  echo
  echo "Запуск завершился с кодом $status."
  if [ -t 0 ]; then
    read "?Нажмите Enter для выхода..."
  fi
fi
exit "$status"
