#!/usr/bin/env bash
# Install a published native release. No Python or administrator rights needed.
set -euo pipefail
main() {
  local release system machine artifact root work_dir cleanup digest expected target previous status
  release="${NETWATCH_RELEASE:-v4.0.0}"
  [[ "$release" =~ ^[a-zA-Z0-9._-]+$ ]] || { echo 'Некорректный тег релиза.' >&2; return 2; }
  system="$(uname -s)"
  machine="$(uname -m)"
  case "$machine" in arm64|aarch64) machine=arm64 ;; amd64|x86_64) machine=x86_64 ;; *) echo 'Нет сборки для этой архитектуры.' >&2; return 2 ;; esac
  case "$system" in
    Darwin) root="${NETWATCH_INSTALL_DIR:-$HOME/Library/Application Support/NetWatch}" ;;
    Linux) root="${NETWATCH_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/NetWatch}" ;;
    *) echo 'Используйте install-native.ps1 в Windows.' >&2; return 2 ;;
  esac
  mkdir -p "$root/native"
  root="$(cd "$root/native" && pwd)"
  if [[ "${NETWATCH_ROLLBACK:-0}" == 1 ]]; then
    [[ -f "$root/previous" ]] || { echo 'Нет предыдущей версии.' >&2; return 2; }
    target="$(cat "$root/previous")"
    [[ "$target" =~ ^[0-9a-f]{64}$ && -x "$root/$target" ]] || { echo 'Предыдущая версия повреждена.' >&2; return 2; }
  else
    artifact="netwatch-$system-$machine"
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-release.XXXXXXXX")"
    printf -v cleanup 'rm -rf -- %q' "$work_dir"
    trap "$cleanup" EXIT
    curl -fSL --connect-timeout 15 --max-time 300 "https://github.com/iproby/networktestby_mac/releases/download/$release/$artifact" -o "$work_dir/app"
    curl -fsSL --connect-timeout 15 --max-time 30 "https://github.com/iproby/networktestby_mac/releases/download/$release/$artifact.sha256" -o "$work_dir/checksum"
    read -r expected _ < "$work_dir/checksum"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo 'Некорректная контрольная сумма.' >&2; return 2; }
    if command -v sha256sum >/dev/null; then digest="$(sha256sum "$work_dir/app")"; else digest="$(shasum -a 256 "$work_dir/app")"; fi
    digest="${digest%% *}"
    [[ "$digest" == "$expected" ]] || { echo 'SHA-256 не совпадает. Запуск отменён.' >&2; return 2; }
    target="$digest"
    if [[ ! -f "$root/$target" ]]; then
      chmod 700 "$work_dir/app"
      "$work_dir/app" --version >/dev/null
      mv "$work_dir/app" "$root/$target"
    fi
  fi
  # Verify cached executables too; never silently run a damaged installation.
  if command -v sha256sum >/dev/null; then digest="$(sha256sum "$root/$target")"; else digest="$(shasum -a 256 "$root/$target")"; fi
  [[ "${digest%% *}" == "$target" ]] || { echo 'Повреждён кеш приложения.' >&2; return 2; }
  previous=''
  [[ ! -f "$root/current" ]] || previous="$(cat "$root/current")"
  if [[ "$previous" != "$target" ]]; then
    [[ ! "$previous" =~ ^[0-9a-f]{64}$ ]] || printf '%s\n' "$previous" > "$root/previous"
    printf '%s\n' "$target" > "$root/current"
  fi
  if [[ -t 0 ]]; then "$root/$target" "$@"
  elif (: </dev/tty) 2>/dev/null; then "$root/$target" "$@" </dev/tty
  else "$root/$target" "$@" </dev/null; fi
}
main "$@"
