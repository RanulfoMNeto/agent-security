#!/usr/bin/env bash
#
# Tests for bin/agent-secret-scan. Needs no root and no network: the script locates its
# files relative to itself, so a temporary copy of the layout is enough.
# gitleaks comes from GITLEAKS_BIN, the installed copy, or PATH.

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"

GITLEAKS_BIN=${GITLEAKS_BIN:-$(command -v gitleaks || echo /opt/agent-security/bin/gitleaks)}
[[ -x $GITLEAKS_BIN && -x /usr/bin/jq ]] || { echo "scanner: gitleaks (set GITLEAKS_BIN) and /usr/bin/jq are required" >&2; exit 1; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc" "$T/untrusted"
cp "$ROOT/bin/agent-secret-scan" "$T/bin/"
cp "$GITLEAKS_BIN" "$T/bin/gitleaks"
cp "$ROOT/config/gitleaks.toml" "$T/etc/"
SCAN=$T/bin/agent-secret-scan
scan() { "$SCAN" 2>/dev/null; }   # reads the event on stdin

TOKEN=$(detectable_token "$SCAN") || { echo "scanner: could not generate a detectable test token" >&2; exit 1; }
event() { /usr/bin/jq -n --arg v "$1" "$2"; }   # event VALUE FILTER: build a JSON event around VALUE

echo "scanner:"
printf '{"prompt":"refactor the parser"}' | scan;                                     check "allows a harmless prompt" test $? -eq 0
event "use $TOKEN please" '{prompt: $v}' | scan;                                     check "blocks a credential in a prompt" test $? -eq 2
event "client = Client(key=\"$TOKEN\")" '{tool_input: {content: $v}}' | scan;        check "blocks a credential inside quoted code" test $? -eq 2
event "$TOKEN # gitleaks:allow" '{prompt: $v}' | scan;                               check "ignores an inline gitleaks:allow comment" test $? -eq 2
printf 'not json' | scan;                                                            check "fails closed on invalid JSON" test $? -eq 2
: | scan;                                                                            check "fails closed on empty input" test $? -eq 2
printf '["a"]' | scan;                                                               check "fails closed on JSON that is not an object" test $? -eq 2

# A repository or the session environment must not be able to switch the scanner off.
printf '[extend]\nuseDefault = true\n[allowlist]\nregexes = [%s.*%s]\n' "'''" "'''" > "$T/untrusted/.gitleaks.toml"
(cd "$T/untrusted" && event "$TOKEN" '{prompt: $v}' | env GITLEAKS_CONFIG="$T/untrusted/.gitleaks.toml" "$SCAN" 2>/dev/null)
check "ignores a repository .gitleaks.toml and GITLEAKS_CONFIG" test $? -eq 2

mv "$T/bin/gitleaks" "$T/bin/gitleaks.moved"
printf '{"prompt":"refactor the parser"}' | scan;                                     check "fails closed when gitleaks is missing" test $? -eq 2

finish scanner
