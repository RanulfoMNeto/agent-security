# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this
repository. Do not open a public issue for a vulnerability.

Include the agent and version, the platform, the policy file or control involved, and the steps
that reproduce the problem.

## In scope

- A documented control in [docs/controls.md](docs/controls.md) that does not hold: a hook that can
  be skipped, a denied location that can be read, a sandbox setting that a user can loosen.
- The installer: integrity of the downloaded gitleaks, files installed with the wrong owner or
  mode, a policy that can be replaced by an unprivileged user.
- The scanner (`bin/agent-secret-scan`): an input that is allowed and should be blocked, or a way
  to change its configuration from the agent's environment.

Vulnerabilities in Claude Code, Codex CLI or gitleaks themselves belong to their maintainers.

## Supported versions

The `main` branch.
