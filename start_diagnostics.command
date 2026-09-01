#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
chmod +x "$SCRIPT_DIR/install_and_run.sh" >/dev/null 2>&1 || true
exec "$SCRIPT_DIR/install_and_run.sh" "$@"
