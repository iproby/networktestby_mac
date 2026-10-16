#!/usr/bin/env bash
# Remote entry: curl -fsSL https://raw.githubusercontent.com/iproby/networktestby_mac/main/install.sh | bash
set -euo pipefail

main() {
  local ref candidate python_bin work_dir cleanup
  ref="${NETWATCH_REF:-main}"
  case "$ref" in
    *[!a-zA-Z0-9._/-]*|/*|*..*) echo "Некорректный NETWATCH_REF." >&2; return 2 ;;
  esac
  python_bin=""
  for candidate in python3 python /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
      python_bin="$candidate"
      break
    fi
  done
  if [[ -z "$python_bin" && "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    brew install python
    python_bin="$(brew --prefix)/bin/python3"
  fi
  if [[ -z "$python_bin" ]]; then
    echo "Установите Python 3.9+ с https://www.python.org/downloads/ и повторите команду." >&2
    return 2
  fi
  command -v curl >/dev/null 2>&1 || { echo "Для загрузки нужен curl." >&2; return 2; }
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-installer.XXXXXXXX")"
  # Quote the path now: this local variable goes out of scope before shell exit.
  printf -v cleanup 'rm -rf -- %q' "$work_dir"
  trap "$cleanup" EXIT
  curl -fsSL --connect-timeout 15 --max-time 120 --retry 2 \
    "https://raw.githubusercontent.com/iproby/networktestby_mac/$ref/bootstrap.py" -o "$work_dir/bootstrap.py"
  # A pipe supplies the install script on stdin. Give the app the terminal back.
  if [[ -t 0 ]]; then
    "$python_bin" "$work_dir/bootstrap.py" "$@"
  elif (: </dev/tty) 2>/dev/null; then
    "$python_bin" "$work_dir/bootstrap.py" "$@" </dev/tty
  else
    "$python_bin" "$work_dir/bootstrap.py" "$@" </dev/null
  fi
}

main "$@"
