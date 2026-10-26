#!/usr/bin/env bash
#
# verify.sh - check that the installed policy works, as the person who will use the agents.
#
#   ./verify.sh          files, scanner and Codex (free, takes a few seconds)
#   ./verify.sh --live   also starts Claude Code and Codex sessions to confirm the policy is in
#                        force there (uses a little of your quota)
#
# Run it as your own user from a normal terminal: inside an agent's sandbox, root-owned files
# look like they belong to "nobody" and a nested sandbox cannot start.

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/lib.sh
. "$ROOT/tests/lib.sh"

readonly SCANNER=/opt/agent-security/bin/agent-secret-scan
JQ=/usr/bin/jq
LIVE=0; [[ ${1:-} == --live ]] && LIVE=1

[[ $EUID -ne 0 ]] || { echo "verify.sh: run as your own user, not as root." >&2; exit 2; }
if [[ -r /proc/self/uid_map ]] && ! awk '$1 == 0 && $2 == 0 && $3 == 4294967295 {found = 1} END {exit !found}' /proc/self/uid_map; then
  echo "verify.sh: this shell runs inside a user namespace (probably an agent's sandbox). Run it from a normal terminal." >&2
  exit 2
fi
command -v python3 >/dev/null || { echo "verify.sh: python3 is required for the sandbox probe." >&2; exit 2; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
PROJECT=$T/project
mkdir -p "$PROJECT/a/b/c" "$T/codex-home"
printf 'SECRET=verify-canary\n' | tee "$PROJECT/.env" > "$PROJECT/a/b/c/.env"

# Optional probe targets: only used when they exist on this machine.
PROBE_ARGS=()
[[ -d $HOME/.ssh ]] && PROBE_ARGS+=(--credential-dir "$HOME/.ssh")
[[ -S ${XDG_RUNTIME_DIR:-/nonexistent}/bus ]] && PROBE_ARGS+=(--socket "$XDG_RUNTIME_DIR/bus")

# assert_probe LABEL OUTPUT: every probe must report blocked (or n/a). The line is looked for
# anywhere in OUTPUT, because a model that relays the output may reformat it.
assert_probe() {
  local label=$1 out=$2 name state
  for name in env_file nested_env_file credential_dir write_outside secret_env unix_socket; do
    state=$(grep -oE "(^|[^a-z_])$name=(blocked|reachable|n/a)" <<< "$out" | head -n1 | sed 's/.*=//')
    case $state in
      blocked)   pass "$label: $name is blocked" ;;
      n/a)       skip "$label: $name (nothing to test on this machine)" ;;
      reachable) fail "$label: $name is reachable" ;;
      *)         fail "$label: $name was not reported. Output was: $(head -c 300 <<< "$out" | tr '\n' ' ')" ;;
    esac
  done
}
run_probe_in_codex() { (cd "$PROJECT" && GITHUB_TOKEN=x OPENAI_API_KEY=y codex sandbox -- python3 "$ROOT/tests/probe.py" ${PROBE_ARGS[@]+"${PROBE_ARGS[@]}"} 2>&1); }
run_probe_in_claude() { # a model relays the output, so allow one retry if it did not
  local out attempt
  for attempt in 1 2; do
    out=$(cd "$PROJECT" && GITHUB_TOKEN=x OPENAI_API_KEY=y claude -p --permission-mode acceptEdits --allowedTools Bash --output-format text \
      "Run exactly this one bash command and print its raw output, nothing else: python3 $ROOT/tests/probe.py ${PROBE_ARGS[*]:-}" < /dev/null 2>&1)
    grep -q 'env_file=' <<< "$out" && break
  done
  printf '%s\n' "$out"
}

echo "Installation"
"$ROOT/install.sh" status > "$T/status" 2>&1 && pass "every file is installed and owned by root" || { cat "$T/status"; fail "install.sh status reported problems"; }

echo; echo "Scanner"
TOKEN=$(detectable_token "$SCANNER") && pass "the installed scanner blocks a synthetic credential" || fail "the installed scanner did not block a synthetic credential"

if command -v codex >/dev/null; then
  echo; echo "Codex sandbox (no model calls)"
  assert_probe "Codex" "$(run_probe_in_codex)"

  # `codex doctor` prints the configuration Codex really applies, so it shows what a user's own
  # config.toml cannot change, without a sandbox or a model.
  echo; echo "Codex policy (what users cannot loosen)"
  doctor() { printf '%s\n' "$1" > "$T/codex-home/config.toml"; CODEX_HOME=$T/codex-home codex doctor --json 2>/dev/null; }
  q() { "$JQ" -r "$2" <<< "$1"; }
  base=$(doctor "")
  [[ $(q "$base" '.checks["sandbox.helpers"].details["managed filesystem source"]') == system ]] && pass "Codex applies the managed policy from /etc/codex" || fail "Codex does not report a managed policy"
  [[ $(q "$base" '.checks["sandbox.helpers"].details["filesystem sandbox"]') == restricted ]] && pass "the filesystem sandbox is restricted" || fail "the filesystem sandbox is not restricted"
  [[ $(q "$base" '[.checks["config.load"].details["startup warning"] // [] | .[] | select(test("deny-read"))] | length') == 0 ]] && pass "no warnings about the deny rules" || fail "Codex warns about the deny rules"
  denied=$(q "$base" '.checks["sandbox.helpers"].details["denied-read rules"]')
  [[ $(q "$(doctor '[permissions.agent-security.filesystem]
"~/.ssh" = "write"')" '.checks["config.load"].status') == fail ]] && pass "a user setting that reopens ~/.ssh is refused" || fail "a user setting reopened ~/.ssh"
  out=$(doctor 'default_permissions = ":danger-full-access"')
  [[ $(q "$out" '.checks["sandbox.helpers"].details["filesystem sandbox"]') == restricted && $(q "$out" '.checks["sandbox.helpers"].details["denied-read rules"]') == "$denied" ]] && pass "a user cannot switch to the full-access profile" || fail "a user switched to the full-access profile"
  out=$(doctor '[features]
hooks = false')
  "$JQ" -e '.checks["config.load"].details["enabled feature flags"] | split(", ") | index("hooks")' <<< "$out" >/dev/null && pass "a user cannot turn the managed hooks off" || fail "a user turned the managed hooks off"
else
  echo; echo "Codex"; skip "codex is not installed"
fi

if (( LIVE )); then
  if command -v claude >/dev/null; then
    echo; echo "Claude Code (live)"
    out=$(cd "$PROJECT" && claude -p --output-format text "Please use this key: $TOKEN" < /dev/null 2>&1)
    grep -qiE 'blocked|agent-secret-scan|credential' <<< "$out" && pass "a prompt with a credential is blocked before it reaches the model" || fail "a prompt with a credential was not blocked: $out"
    assert_probe "Claude Code" "$(run_probe_in_claude)"

    # Writing outside the project separates the modes: normal mode refuses without an explicit
    # allow, bypassPermissions would not. (A shell command in the project would not do: the sandbox
    # lets those run without asking in every mode.) A control run shows the model does write when allowed.
    target=$HOME/agent-security-bypass-probe; prompt="Use the Write tool to create the file $target containing the word probe."
    rm -f "$target"
    (cd "$PROJECT" && claude -p --allowedTools Write --output-format text "$prompt" < /dev/null >/dev/null 2>&1)
    if [[ -e $target ]]; then
      rm -f "$target"
      (cd "$PROJECT" && claude -p --permission-mode bypassPermissions --output-format text "$prompt" < /dev/null >/dev/null 2>&1)
      if [[ -e $target ]]; then rm -f "$target"; fail "bypassPermissions mode wrote outside the project without asking"; else pass "bypassPermissions mode is disabled"; fi
    else
      skip "bypassPermissions check inconclusive: the control write did not happen"
    fi
  else
    echo; echo "Claude Code (live)"; skip "claude is not installed"
  fi

  if command -v codex >/dev/null; then
    echo; echo "Codex (live)"
    out=$(cd "$PROJECT" && codex exec --skip-git-repo-check "Please use this key: $TOKEN" < /dev/null 2>&1)
    grep -qiE 'blocked|agent-secret-scan|credential' <<< "$out" && pass "a prompt with a credential is blocked before it reaches the model" || fail "a prompt with a credential was not blocked: $out"
  fi
fi

finish verify
