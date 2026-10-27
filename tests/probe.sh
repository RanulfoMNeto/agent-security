#!/usr/bin/env bash
#
# Tests for tests/probe.py, the probe that verify.sh runs inside the agents' sandboxes.
# Outside a sandbox nothing is blocked, so the reporting is checked against a local listener.
# Needs no root and no network.

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"

SERVER= HTTP=
T=$(mktemp -d); trap '[[ -n $SERVER ]] && kill "$SERVER" 2>/dev/null; [[ -n $HTTP ]] && kill "$HTTP" 2>/dev/null; rm -rf "$T"' EXIT
# HOME: the write probe and git's configuration stay in $T. No proxy: the listeners are local.
probe() { (cd "$T" && HOME=$T GIT_CONFIG_NOSYSTEM=1 no_proxy='*' NO_PROXY='*' python3 "$ROOT/tests/probe.py" "$@"); }

# A listener that accepts one connection, an HTTP server that answers one request (with an
# error status, which still counts as reached), and a port nothing listens on.
python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
print(s.getsockname()[1], flush=True)
s.accept()' > "$T/port" &
SERVER=$!
python3 -c 'import http.server
s = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
print(s.server_address[1], flush=True)
s.handle_request()' > "$T/http-port" 2>/dev/null &
HTTP=$!
for _ in $(seq 50); do [[ -s $T/port && -s $T/http-port ]] && break; sleep 0.1; done
OPEN=$(cat "$T/port")
WEB=$(cat "$T/http-port")
CLOSED=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')

echo "probe:"
out=$(probe --network "127.0.0.1:$OPEN");   check "reports a connection that succeeds as reachable"  grep -qx 'network=reachable' <<< "$out"
out=$(probe --network "127.0.0.1:$CLOSED"); check "reports a connection that fails as blocked"       grep -qx 'network=blocked' <<< "$out"
out=$(probe);                               check "reports n/a when no host is given"                grep -qx 'network=n/a' <<< "$out"
out=$(probe --allowed-url "http://127.0.0.1:$WEB/"); check "reports an HTTP answer as reachable"     grep -qx 'allowed_host=reachable' <<< "$out"
out=$(probe --other-url "http://127.0.0.1:$CLOSED/"); check "reports a failed request as blocked"    grep -qx 'other_host=blocked' <<< "$out"

out=$(probe --git-credential example.com);  check "reports no stored git credential as blocked"      grep -qx 'git_credential=blocked' <<< "$out"
printf '[credential]\n\thelper = "!f() { echo username=u; echo password=p; }; f"\n' > "$T/.gitconfig"
out=$(probe --git-credential example.com);  check "reports a stored git credential as reachable"     grep -qx 'git_credential=reachable' <<< "$out"

finish probe
