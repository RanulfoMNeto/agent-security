#!/usr/bin/env bash
#
# Tests for install.sh, using DESTDIR staging. Needs no root and no network: gitleaks comes
# from GITLEAKS_BIN, the installed copy, or PATH.

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"

GITLEAKS_BIN=${GITLEAKS_BIN:-$(command -v gitleaks || echo /opt/agent-security/bin/gitleaks)}
[[ -x $GITLEAKS_BIN ]] || { echo "installer: gitleaks not found; set GITLEAKS_BIN" >&2; exit 1; }
export GITLEAKS_BIN

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
D=$T/root; mkdir -p "$D"
inst() { DESTDIR=$D "$ROOT/install.sh" "$@"; }
case "$(uname -s)" in Darwin) CLAUDE="/Library/Application Support/ClaudeCode" ;; *) CLAUDE=/etc/claude-code ;; esac
OVERLAY=$D$CLAUDE/managed-settings.d/20-linux-unix-sockets.json

echo "installer:"
check  "installs into a staging directory"            inst install
check  "installed scanner is executable"              test -x "$D/opt/agent-security/bin/agent-secret-scan"
check  "scanner is installed unchanged"               cmp -s "$ROOT/bin/agent-secret-scan" "$D/opt/agent-security/bin/agent-secret-scan"
check  "claude policy is installed unchanged"         cmp -s "$ROOT/claude/managed-settings.d/10-agent-security.json" "$D$CLAUDE/managed-settings.d/10-agent-security.json"
check  "codex requirements are installed unchanged"   cmp -s "$ROOT/codex/requirements.toml" "$D/etc/codex/requirements.toml"
refuse "no overlay unless requested"                  test -e "$OVERLAY"
check  "status passes"                                inst status

check  "a second run with the overlay"                env UNIX_SOCKET_OVERLAY=yes DESTDIR="$D" "$ROOT/install.sh" install
check  "the overlay is installed unchanged"           cmp -s "$ROOT"/claude/overlays/20-linux-unix-sockets.json "$OVERLAY"
check  "the overlay is removed when no longer needed" env UNIX_SOCKET_OVERLAY=no DESTDIR="$D" "$ROOT/install.sh" install
refuse "the overlay is gone"                          test -e "$OVERLAY"

echo '# company config' > "$D/etc/codex/config.toml"
refuse "refuses to replace an unmanaged codex file"   inst install
check  "leaves that file untouched"                   grep -q 'company config' "$D/etc/codex/config.toml"
rm -f "$D/etc/codex/config.toml"
check  "installs again once it is removed"            inst install

check  "uninstall"                                    inst uninstall
refuse "uninstall leaves no file behind"              bash -c "find '$D' -type f | grep -q ."

# Python before 3.11 has no tomllib: the TOML check is skipped instead of failing.
mkdir -p "$T/old-python"; printf '#!/bin/sh\nexit 1\n' > "$T/old-python/python3"; chmod +x "$T/old-python/python3"
L=$T/legacy-root; mkdir -p "$L"
check  "installs when python3 cannot load tomllib"    env PATH="$T/old-python:$PATH" DESTDIR="$L" "$ROOT/install.sh" install

# A download that does not match the pinned hash is rejected, and nothing is installed.
D=$T/mirror-root; mkdir -p "$D"
# shellcheck source=config/gitleaks.release
. "$ROOT/config/gitleaks.release"
mkdir -p "$T/mirror/v$VERSION"
for asset in linux_x64 linux_arm64 darwin_x64 darwin_arm64; do echo "not a release" > "$T/mirror/v$VERSION/gitleaks_${VERSION}_$asset.tar.gz"; done
refuse "rejects a tarball with the wrong SHA-256"     env -u GITLEAKS_BIN DESTDIR="$D" GITLEAKS_MIRROR="file://$T/mirror" "$ROOT/install.sh" install
refuse "installs nothing after a hash mismatch"       test -e "$D/opt/agent-security/bin/agent-secret-scan"

# A download that matches the pinned hash is installed. A stand-in release replaces the real one,
# in a copy of the repository whose pinned hashes match it.
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
R=$T/pinned-repo; M=$T/valid-mirror; D=$T/download-root
mkdir -p "$R/config" "$M/v$VERSION" "$D" "$T/standin"
printf '#!/bin/sh\necho %s\n' "$VERSION" > "$T/standin/gitleaks"; chmod +x "$T/standin/gitleaks"
{
  echo "VERSION=$VERSION"
  for asset in linux_x64 linux_arm64 darwin_x64 darwin_arm64; do
    tar -czf "$M/v$VERSION/gitleaks_${VERSION}_$asset.tar.gz" -C "$T/standin" gitleaks
    echo "SHA256_$asset=$(sha "$M/v$VERSION/gitleaks_${VERSION}_$asset.tar.gz")"
  done
} > "$R/config/gitleaks.release"
cp "$ROOT/install.sh" "$R/"
ln -s "$ROOT/bin" "$ROOT/claude" "$ROOT/codex" "$R/"
ln -s "$ROOT/config/gitleaks.toml" "$R/config/"
check  "installs a download that matches the pinned hash" env -u GITLEAKS_BIN DESTDIR="$D" GITLEAKS_MIRROR="file://$M" "$R/install.sh" install
check  "the downloaded gitleaks is installed"         test -x "$D/opt/agent-security/bin/gitleaks"

finish installer
