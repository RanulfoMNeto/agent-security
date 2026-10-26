#!/usr/bin/env bash
#
# Tests for tests/probe.py, the probe that verify.sh runs inside the agents' sandboxes.
# Outside a sandbox nothing is blocked, so the reporting is checked against a local listener.
# Needs no root and no network.

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"

SERVER=
T=$(mktemp -d); trap '[[ -n $SERVER ]] && kill "$SERVER" 2>/dev/null; rm -rf "$T"' EXIT
probe() { (cd "$T" && HOME=$T python3 "$ROOT/tests/probe.py" "$@"); }   # HOME: the write probe stays in $T

# A listener that accepts one connection, and a port nothing listens on.
python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
print(s.getsockname()[1], flush=True)
s.accept()' > "$T/port" &
SERVER=$!
for _ in $(seq 50); do [[ -s $T/port ]] && break; sleep 0.1; done
OPEN=$(cat "$T/port")
CLOSED=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')

echo "probe:"
out=$(probe --network "127.0.0.1:$OPEN");   check "reports a connection that succeeds as reachable"  grep -qx 'network=reachable' <<< "$out"
out=$(probe --network "127.0.0.1:$CLOSED"); check "reports a connection that fails as blocked"       grep -qx 'network=blocked' <<< "$out"
out=$(probe);                               check "reports n/a when no host is given"                grep -qx 'network=n/a' <<< "$out"

finish probe
