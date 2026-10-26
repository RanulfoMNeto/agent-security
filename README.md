# Agent Security

A security baseline for AI coding agents, installed with one command: **Claude Code** and
**Codex CLI** on Linux, macOS and WSL2.

It keeps credentials away from the agents, stops literal secrets from reaching a model
provider, blocks the most destructive commands, and confines what the agents' shell commands
can touch. It uses the controls the two tools already ship (managed settings, requirements,
OS sandboxes, permission rules, hooks) and adds one component of its own: a small hook that
runs [gitleaks](https://github.com/gitleaks/gitleaks).

The adversary is the agent acting on bad instructions: a mistaken plan, or a prompt injection
hidden in a file, a web page or a tool result. What is covered, and what is not, is in the
[threat model](docs/threat-model.md).

## Quick start

```sh
git clone <this repository> && cd agent-security
./tests/run.sh               # optional: checks the repository itself, needs no root
sudo ./install.sh install    # installs the scanner and both policies
./verify.sh                  # from a normal terminal; --live also starts real agent sessions
```

Restart any open Claude Code or Codex session: policies are read when a session starts.
`verify.sh` must run in a normal terminal, not inside an agent, and says so if it does not.

Later: `./install.sh status` shows what is installed, `sudo ./install.sh install` after a
`git pull` updates it (it is idempotent), and `sudo ./install.sh uninstall` removes everything.
The rest of the day-to-day work is in [operations](docs/operations.md). The rules restrict the
agents only: open a protected file yourself in your own terminal or editor.

## Requirements

| | |
|---|---|
| Platform | Linux (x86-64, arm64), macOS, or WSL2. Tested only on Ubuntu 26.04; macOS, WSL2 and arm64 follow the vendors' documentation but have not been run. Native Windows is not supported |
| Claude Code | 2.1.295 or later (tested 2.1.309) |
| Codex CLI | 0.138.0 or later (tested 0.163.0) |
| Tools | `bash`, `curl`, `tar`, `sha256sum` or `shasum`, and `jq` at `/usr/bin/jq`. `python3` is optional for the installer and needed by `verify.sh`. Linux also needs `bubblewrap` and `socat` (`apt-get install bubblewrap socat jq`) |

The installer checks all of this first and says what is missing.

## What gets installed

Every file is a byte-for-byte copy of a file in this repository, owned by root, so an agent
running as you cannot edit it. `./install.sh status` lists them.

| Installed to | From | Purpose |
|---|---|---|
| `/opt/agent-security/bin/agent-secret-scan` | `bin/` | The hook both agents call |
| `/opt/agent-security/bin/gitleaks`, `etc/gitleaks.toml` | downloaded and checked against `config/gitleaks.release`; `config/` | Secret detection with gitleaks' default rules |
| `/etc/claude-code/managed-settings.d/` (macOS: `/Library/Application Support/ClaudeCode/…`) | `claude/managed-settings.d/*.json`, and `claude/overlays/*.json` only where needed | Claude Code policy |
| `/etc/codex/config.toml`, `requirements.toml` | `codex/` | Codex profile and enforced requirements |

## What users can and cannot change

The policy is a floor, not a cage.

| Users can | Users cannot |
|---|---|
| Add their own hooks, permission rules, MCP servers and project settings | Remove a deny rule, a credential location or a managed hook |
| Approve a new network host when Claude Code asks | Turn the sandbox off, allow unsandboxed commands, or re-open a protected read path |
| Pick any permission mode except bypass | Enter `bypassPermissions`, or leave Codex's managed profile |
| Use Codex with their own `config.toml` | Weaken the Codex requirements (Codex refuses to load such a config) |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Install stops: "bubblewrap cannot create a sandbox" | Ubuntu 24.04+ restricts user namespaces: [operations](docs/operations.md#ubuntu-2404-and-apparmor) |
| Claude Code exits at start: sandbox unavailable | `failIfUnavailable` is on by design. Install `bubblewrap` and `socat`, then see [operations](docs/operations.md#ubuntu-2404-and-apparmor) |
| Codex: "configuration could not be loaded" | Your `~/.codex/config.toml` conflicts with the managed policy, for example it opens `~/.ssh`. Remove that entry |
| Every prompt or tool call is blocked | The scanner or gitleaks is missing or broken, and hooks fail closed. `./install.sh status`, then `sudo ./install.sh install` |
| A prompt is blocked and looks like a false positive | [operations](docs/operations.md#handle-a-false-positive) |
| The agent cannot read `.env.example` | By design: deny rules have no exceptions |
| Empty `.bashrc`, `.gitconfig`, `.claude/settings.json`… appear as untracked files in a project | Claude Code's Linux sandbox creates placeholders for the paths it protects (seen on 2.1.309). Do not commit them; this repository's `.gitignore` hides them, and your global gitignore can do the same elsewhere |

## Documentation

- [Threat model, design notes and limitations](docs/threat-model.md): what is covered, how, why, and what is not
- [Operations](docs/operations.md): updating, customizing, deploying to many machines, the Ubuntu AppArmor case

## Changing the policy

Open a pull request, run `./tests/run.sh`, and describe the risk the change addresses. The
credential list is written once per tool, in each tool's own format; `tests/consistency.py`
fails if the two drift apart. After merging, everyone runs `sudo ./install.sh install` and
`./verify.sh`.
