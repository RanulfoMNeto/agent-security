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
socket_scan() { python3 "$ROOT/tests/socket-stdin.py" "$SCAN" "$@" 2>/dev/null; }

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
event "out $TOKEN" '{hook_event_name: "PostToolUse", tool_response: $v}' | scan;    check "blocks a credential in a tool result (Codex)" test $? -eq 2

# Redact mode (Claude Code's PostToolUse): only the credential changes, the result keeps its shape.
RESULT='{hook_event_name: "PostToolUse", tool_response: {type: "text", file: {content: $v, numLines: 2}}}'
out=$(event "a=1
key=$TOKEN" "$RESULT" | "$SCAN" --redact 2>/dev/null)
check "redacts a credential in a tool result" grep -qF '[REDACTED]' <<< "$out"
refuse "leaves no credential in the redacted result" grep -qF "$TOKEN" <<< "$out"
shape=$(event "x" "$RESULT" | /usr/bin/jq -c '.tool_response | [paths]')
check "keeps the shape of the tool result" test "$(/usr/bin/jq -c '.hookSpecificOutput.updatedToolOutput | [paths]' <<< "$out")" = "$shape"
out=$(event "a=1" "$RESULT" | "$SCAN" --redact 2>/dev/null)
check "prints nothing for a clean tool result" test $? -eq 0 -a -z "$out"
out=$(printf 'not json' | "$SCAN" --redact 2>/dev/null)
check "stops the session when a tool result cannot be scanned" test "$(/usr/bin/jq -r '.continue' <<< "$out")" = false

# Claude Code can supply stdin as a socket: reopening /dev/stdin fails on Linux.
printf '{"prompt":"refactor the parser"}' | socket_scan; check "allows a harmless prompt over a socket" test $? -eq 0
out=$(event "$TOKEN" '{prompt: $v}' | python3 "$ROOT/tests/socket-stdin.py" "$SCAN" 2>&1)
check "blocks a credential over a socket" test $? -eq 2
check "reports detection rather than a socket read failure" credential_detected <<< "$out"
printf 'not json' | socket_scan; check "fails closed on invalid JSON over a socket" test $? -eq 2
: | socket_scan; check "fails closed on empty socket input" test $? -eq 2
out=$(event "a=1" "$RESULT" | socket_scan --redact)
check "prints nothing for a clean tool result over a socket" test $? -eq 0 -a -z "$out"
out=$(event "a=1\nkey=$TOKEN" "$RESULT" | socket_scan --redact)
check "redacts a credential in a tool result over a socket" grep -qF '[REDACTED]' <<< "$out"
refuse "leaves no credential in a redacted socket result" grep -qF "$TOKEN" <<< "$out"
check "keeps the shape of a socket tool result" test "$(/usr/bin/jq -c '.hookSpecificOutput.updatedToolOutput | [paths]' <<< "$out")" = "$shape"
out=$(printf 'not json' | socket_scan --redact)
check "stops the session on invalid JSON over a socket" test "$(/usr/bin/jq -r '.continue' <<< "$out")" = false

"$SCAN" <&- 2>/dev/null; check "fails closed when stdin cannot be read" test $? -eq 2
out=$("$SCAN" --redact <&- 2>/dev/null)
check "stops the session when stdin cannot be read" test "$(/usr/bin/jq -r '.continue' <<< "$out")" = false

# A repository or the session environment must not be able to switch the scanner off.
printf '[extend]\nuseDefault = true\n[allowlist]\nregexes = [%s.*%s]\n' "'''" "'''" > "$T/untrusted/.gitleaks.toml"
(cd "$T/untrusted" && event "$TOKEN" '{prompt: $v}' | env GITLEAKS_CONFIG="$T/untrusted/.gitleaks.toml" "$SCAN" 2>/dev/null)
check "ignores a repository .gitleaks.toml and GITLEAKS_CONFIG" test $? -eq 2

mv "$T/bin/gitleaks" "$T/bin/gitleaks.moved"
refuse "does not count a scanner failure as credential detection" detectable_token "$SCAN"
printf '{"prompt":"refactor the parser"}' | scan;                                     check "fails closed when gitleaks is missing" test $? -eq 2
out=$(event "a=1" "$RESULT" | "$SCAN" --redact 2>/dev/null)
check "stops the session when gitleaks is missing (redact mode)" test "$(/usr/bin/jq -r '.continue' <<< "$out")" = false

finish scanner
