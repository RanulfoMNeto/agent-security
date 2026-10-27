# Contributing

## Before opening a pull request

1. Run `./tests/run.sh`. It needs no root, network or agents. It requires Python 3.11 or later,
   `jq` at `/usr/bin/jq` and gitleaks at the pinned version, taken from `GITLEAKS_BIN`, the
   installed copy or `PATH`.
2. Describe the risk the change addresses and the control it affects.
3. Update [docs/controls.md](docs/controls.md) when a control is added, changed or removed.

## Policy files

- The credential locations, the secret variables and the allowed hosts exist once per agent
  ([operations](docs/operations.md#change-or-add-a-rule) lists where). Change both.
  `tests/consistency.py` fails when they differ.
- Codex files must start with `# Managed by agent-security.`.
- Updating gitleaks is described in [docs/operations.md](docs/operations.md#update).

## Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`test:`, `refactor:` or `chore:`, a summary in the imperative, and a body that explains why.

## Security issues

Report them as described in [SECURITY.md](SECURITY.md).
