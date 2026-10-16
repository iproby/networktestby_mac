#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
find_python() {
  local candidate
  for candidate in python3 python /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
      exec "$candidate" "$SCRIPT_DIR/run.py" "$@"
    fi
  done
}
find_python "$@"
if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  brew install python
  find_python "$@"
fi
echo "Установите Python 3.9+ с https://www.python.org/downloads/ и повторите запуск." >&2
exit 2
