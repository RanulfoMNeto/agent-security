# Shared by the test scripts and verify.sh (sourced, not executed).

failures=0

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
skip() { printf '  skip  %s\n' "$1"; }

# check NAME COMMAND...   passes when the command succeeds
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
# refuse NAME COMMAND...  passes when the command fails
refuse() { local name=$1; shift; if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi; }

# finish LABEL: print the verdict and exit with the matching status.
finish() {
  if (( failures )); then printf '\n%s: FAILED (%d)\n' "$1" "$failures"; exit 1; fi
  printf '\n%s: ok\n' "$1"
}

# Only the detection diagnostic counts: a scanner failure also blocks, for a different reason.
credential_detected() { grep -qF 'agent-secret-scan: a literal credential was detected.'; }

# detectable_token SCANNER: a synthetic GitHub-style token that SCANNER detects. A random token
# can occasionally fall under gitleaks' entropy threshold, so try a few. Generated on the fly
# so that no credential-shaped string is ever committed.
detectable_token() {
  local candidate output status
  for _ in 1 2 3 4 5 6 7 8; do
    candidate=ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 36)
    output=$(printf '{"prompt":"%s"}' "$candidate" | "$1" 2>&1); status=$?
    if [[ $status -eq 2 ]] && credential_detected <<< "$output"; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}
