#!/usr/bin/env bash
#
# install.sh - install, inspect or remove the agent-security baseline.
#
#   sudo ./install.sh install     copy the scanner and the policy files into the system
#   sudo ./install.sh uninstall   remove everything this script installed
#        ./install.sh status      show what is installed (no root needed)
#
# Environment (all optional):
#   DESTDIR=              stage the files under this directory instead of the real system
#                         (packaging, tests): no root, no probes, no self-test
#   GITLEAKS_BIN=         use this gitleaks binary (it must be the pinned version)
#                         instead of downloading the release
#   GITLEAKS_MIRROR=      base URL of an internal mirror of the gitleaks release files;
#                         the pinned SHA-256 still applies
#   UNIX_SOCKET_OVERLAY=  auto (default) | yes | no. Linux only: install the Claude Code
#                         socket overlay, which is needed when the kernel blocks nested user
#                         namespaces. `auto` probes the machine; staging never probes
#
# The files in the repository are installed as they are, with fixed paths (/opt/agent-security
# and the agents' own system directories). Everything is validated before anything is
# changed, and the scanner goes in before the policies that call it: a hook that points to a
# missing scanner would block every action.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly PREFIX=/opt/agent-security
readonly CODEX_DIR=/etc/codex
readonly MARKER='# Managed by agent-security.'
DESTDIR=${DESTDIR:-}
GITLEAKS_BIN=${GITLEAKS_BIN:-}
GITLEAKS_MIRROR=${GITLEAKS_MIRROR:-https://github.com/gitleaks/gitleaks/releases/download}
UNIX_SOCKET_OVERLAY=${UNIX_SOCKET_OVERLAY:-auto}

# shellcheck source=config/gitleaks.release
. "$ROOT/config/gitleaks.release"

OS= ASSET= CLAUDE_DIR= ROOT_GROUP= USE_OVERLAY=0 WORK=

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
trap 'if [[ -n $WORK ]]; then rm -rf "$WORK"; fi' EXIT

# --- what is installed where ---------------------------------------------------------------

detect_platform() {
  local arch; arch=$(uname -m)
  ROOT_GROUP=$(id -gn 0)
  case "$(uname -s)-$arch" in
    Linux-x86_64)          OS=linux; ASSET=linux_x64;     CLAUDE_DIR=/etc/claude-code ;;
    Linux-aarch64 | Linux-arm64) OS=linux; ASSET=linux_arm64; CLAUDE_DIR=/etc/claude-code ;;
    Darwin-x86_64)         OS=macos; ASSET=darwin_x64;    CLAUDE_DIR="/Library/Application Support/ClaudeCode" ;;
    Darwin-arm64)          OS=macos; ASSET=darwin_arm64;  CLAUDE_DIR="/Library/Application Support/ClaudeCode" ;;
    *) die "unsupported system: $(uname -s) $arch. Use Linux, macOS or WSL2." ;;
  esac
  if [[ $OS == linux ]] && grep -qi microsoft /proc/version 2>/dev/null && ! uname -r | grep -qi wsl2; then
    die "WSL1 is not supported: Claude Code's sandbox needs WSL2."
  fi
}

# One line per file taken from the repository: mode|source|destination. Install, uninstall
# and status all read this list. `manifest all` also lists the optional overlay.
manifest() {
  local f
  echo "0755|$ROOT/bin/agent-secret-scan|$PREFIX/bin/agent-secret-scan"
  echo "0644|$ROOT/config/gitleaks.toml|$PREFIX/etc/gitleaks.toml"
  for f in "$ROOT"/claude/managed-settings.d/*.json; do echo "0644|$f|$CLAUDE_DIR/managed-settings.d/${f##*/}"; done
  if [[ ${1:-} == all ]] || (( USE_OVERLAY )); then
    for f in "$ROOT"/claude/overlays/*.json; do echo "0644|$f|$CLAUDE_DIR/managed-settings.d/${f##*/}"; done
  fi
  for f in "$ROOT"/codex/*.toml; do echo "0644|$f|$CODEX_DIR/${f##*/}"; done
}

# --- checks ------------------------------------------------------------------------------------

# Run as the person who invoked sudo, so that probes see what their agents will see.
as_invoking_user() {
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then sudo -n -u "$SUDO_USER" "$@"; else "$@"; fi
}

preflight() {
  [[ -n $DESTDIR ]] && return 0
  [[ -x /usr/bin/jq ]] || die "jq is required at /usr/bin/jq (apt-get install jq; macOS 15 and later ship it)."
  [[ $OS == linux ]] || return 0
  local missing=()
  command -v bwrap >/dev/null || missing+=(bubblewrap)
  command -v socat >/dev/null || missing+=(socat)
  (( ${#missing[@]} == 0 )) || die "Claude Code's sandbox needs: ${missing[*]} (apt-get install ${missing[*]})."
  as_invoking_user bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net true 2>/dev/null ||
    die "bubblewrap cannot create a sandbox for ${SUDO_USER:-root}. See docs/operations.md (Ubuntu and AppArmor)."
}

# Claude Code's seccomp helper creates a user namespace inside bubblewrap's. Where that is
# blocked (Ubuntu with AppArmor's bwrap profile), the sandbox needs the socket overlay.
decide_overlay() {
  [[ $OS == linux ]] || return 0
  case $UNIX_SOCKET_OVERLAY in
    yes) USE_OVERLAY=1 ;;
    no)  USE_OVERLAY=0 ;;
    auto)
      [[ -n $DESTDIR ]] && return 0
      as_invoking_user bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net \
        -- unshare --user --map-root-user true 2>/dev/null || { USE_OVERLAY=1; say "Nested user namespaces are blocked: adding the Unix-socket overlay for Claude Code."; } ;;
    *) die "UNIX_SOCKET_OVERLAY must be auto, yes or no." ;;
  esac
}

validate() { # a broken policy file would stop the agents from starting
  case $1 in
    *.json) /usr/bin/jq -e . "$1" >/dev/null 2>&1 || die "invalid JSON: $1" ;;
    *.toml) # needs Python 3.11+ (tomllib); without it the check is skipped
            if python3 -I -c 'import tomllib' 2>/dev/null; then
              python3 -I -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' "$1" 2>/dev/null || die "invalid TOML: $1"
            fi ;;
  esac
  return 0
}

# Codex files that someone else manages are not ours to overwrite.
guard_unmanaged() {
  [[ -f $DESTDIR$1 && $1 == $CODEX_DIR/* ]] || return 0
  head -n1 "$DESTDIR$1" | grep -qF "$MARKER" ||
    die "$1 exists and is not managed by agent-security. Merge the repository's file into it by hand, or remove it."
}

# --- install ---------------------------------------------------------------------------------------

put() { # put MODE SOURCE DEST
  if [[ -n $DESTDIR ]]; then
    install -d -m 0755 "$(dirname "$DESTDIR$3")"; install -m "$1" "$2" "$DESTDIR$3"
  else
    install -d -m 0755 -o root -g "$ROOT_GROUP" "$(dirname "$3")"; install -m "$1" -o root -g "$ROOT_GROUP" "$2" "$3"
  fi
}
put_all() { local mode src dest; while IFS='|' read -r mode src dest; do put "$mode" "$src" "$dest"; done; }

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

fetch_gitleaks() { # fetch_gitleaks DEST: the pinned binary, from GITLEAKS_BIN, a previous install or the release
  local hash_var=SHA256_$ASSET tarball=gitleaks_${VERSION}_${ASSET}.tar.gz
  if [[ -n $GITLEAKS_BIN ]]; then
    cp "$GITLEAKS_BIN" "$1"
  elif [[ -x $DESTDIR$PREFIX/bin/gitleaks ]] && "$DESTDIR$PREFIX/bin/gitleaks" version 2>/dev/null | grep -qx "$VERSION"; then
    cp "$DESTDIR$PREFIX/bin/gitleaks" "$1"
  else
    say "Downloading gitleaks $VERSION ($ASSET)"
    curl -fsSL --retry 3 -o "$WORK/$tarball" "$GITLEAKS_MIRROR/v$VERSION/$tarball" || die "download failed: $GITLEAKS_MIRROR/v$VERSION/$tarball"
    [[ $(sha256_of "$WORK/$tarball") == "${!hash_var}" ]] || die "SHA-256 mismatch for $tarball. Nothing was installed."
    tar -xzf "$WORK/$tarball" -C "$WORK" gitleaks
    mv "$WORK/gitleaks" "$1"
  fi
  chmod 0755 "$1"
  "$1" version 2>/dev/null | grep -qx "$VERSION" || die "gitleaks must be version $VERSION."
}

cmd_install() {
  [[ -n $DESTDIR || $EUID -eq 0 ]] || die "run as root: sudo ./install.sh install"
  detect_platform; preflight; decide_overlay
  WORK=$(mktemp -d)

  local src dest
  while IFS='|' read -r _ src dest; do validate "$src"; guard_unmanaged "$dest"; done < <(manifest)
  fetch_gitleaks "$WORK/gitleaks"

  say "Installing the scanner under $PREFIX"
  manifest | awk -F'|' -v p="$PREFIX/" 'index($3, p) == 1' | put_all
  put 0755 "$WORK/gitleaks" "$PREFIX/bin/gitleaks"
  [[ -n $DESTDIR ]] || printf '{"prompt":"self-test"}' | "$PREFIX/bin/agent-secret-scan" 2>/dev/null ||
    die "the installed scanner does not run; no policy was installed."

  say "Installing the Claude Code and Codex policies"
  if (( ! USE_OVERLAY )); then
    for src in "$ROOT"/claude/overlays/*.json; do rm -f "$DESTDIR$CLAUDE_DIR/managed-settings.d/${src##*/}"; done
  fi
  manifest | awk -F'|' -v p="$PREFIX/" 'index($3, p) != 1' | put_all

  say "Done. Restart open Claude Code and Codex sessions, then run: ./verify.sh"
  if [[ -z $DESTDIR && -n ${SUDO_USER:-} ]] && sudo -n -u "$SUDO_USER" sudo -n true 2>/dev/null; then
    warn "$SUDO_USER has passwordless sudo: anything running outside the agents' sandboxes could rewrite this policy."
  fi
}

# --- uninstall and status ---------------------------------------------------------------------------

cmd_uninstall() {
  [[ -n $DESTDIR || $EUID -eq 0 ]] || die "run as root: sudo ./install.sh uninstall"
  detect_platform
  local dest
  while IFS='|' read -r _ _ dest; do
    if [[ $dest != $CODEX_DIR/* ]] || head -n1 "$DESTDIR$dest" 2>/dev/null | grep -qF "$MARKER"; then rm -f "$DESTDIR$dest"
    else warn "$dest is not managed by agent-security; left in place."; fi
  done < <(manifest all)
  rm -f "$DESTDIR$PREFIX/bin/gitleaks"
  for dest in "$PREFIX/bin" "$PREFIX/etc" "$PREFIX" "$CLAUDE_DIR/managed-settings.d" "$CLAUDE_DIR" "$CODEX_DIR"; do
    rmdir "$DESTDIR$dest" 2>/dev/null || true
  done
  say "Removed."
}

cmd_status() {
  detect_platform
  local dest owner problems=0
  report() { # report PATH [optional]
    if [[ ! -e $DESTDIR$1 ]]; then
      if [[ ${2:-} == optional ]]; then printf '  -        %s (optional, not installed)\n' "$1"
      else printf '  MISSING  %s\n' "$1"; problems=1; fi
      return
    fi
    owner=$(stat -c %U "$DESTDIR$1" 2>/dev/null || stat -f %Su "$DESTDIR$1")
    printf '  ok       %-64s owner=%s\n' "$1" "$owner"
    [[ $owner == root || -n $DESTDIR ]] || { warn "$1 is not owned by root."; problems=1; }
  }
  echo "platform: $OS $ASSET"
  while IFS='|' read -r _ _ dest; do
    if [[ -e $ROOT/claude/overlays/${dest##*/} ]]; then report "$dest" optional; else report "$dest"; fi
  done < <(manifest all)
  report "$PREFIX/bin/gitleaks"
  [[ -x $DESTDIR$PREFIX/bin/gitleaks ]] && echo "gitleaks: $("$DESTDIR$PREFIX/bin/gitleaks" version 2>&1 | head -n1) (pinned: $VERSION)"
  exit "$problems"
}

case "${1:-}" in
  install)   cmd_install ;;
  uninstall) cmd_uninstall ;;
  status)    cmd_status ;;
  *) sed -n '3,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; [[ -z ${1:-} || $1 == -h || $1 == --help ]] ;;
esac
