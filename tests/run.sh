#!/usr/bin/env bash
#
# Run every test of the repository. Needs no root, no network and no agents.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

status=0
for test in ./consistency.py ./scanner.sh ./installer.sh ./probe.sh; do
  "$test" || status=1
done
exit "$status"
