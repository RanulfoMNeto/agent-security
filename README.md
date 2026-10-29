# Agent Security

A security baseline for AI coding agents. One installer applies the same set of controls to
**Claude Code** and **Codex CLI** on Linux, macOS and WSL2.

The baseline uses the agents' own mechanisms (managed settings, requirements, OS sandboxes,
network proxies, permission rules, hooks) and adds one component: a hook that scans for
credentials with [gitleaks](https://github.com/gitleaks/gitleaks).

For a visual introduction, the [Agent Security guide](https://ranulfomneto.github.io/agent-security-guide/)
shows how an agent's harness works and where each control acts on it.

## Controls

| Control | Action |
|---|---|
| Credential scanner | Every prompt, tool call and tool result is scanned before it reaches the model or runs. A credential in a prompt or tool call blocks it. In a tool result, Claude Code replaces the credential with `[REDACTED]` and Codex withholds the result |
| Credential locations | Reading 29 credential locations (SSH, cloud, secret stores, browser profiles, tool and git credentials, shell history) and environment files (`.env`, `.env.*`, `.envrc`) in the project and the home directory (Claude Code: also `/tmp`) is denied |
| Environment variables | Secret variables are removed from the commands the agents run |
| Filesystem | Commands write only in the project directory, the temporary directory and package-manager caches. In the project's `.git`, `config` and `hooks` are read-only. Claude Code's file tools cannot change shell startup files, git configuration, `~/.ssh` or autostart entries |
| Network | Commands reach code hosting and package registries (24 hosts) through the agent's proxy. Users can add hosts; Claude Code also asks for the others, Codex refuses them |
| Local services | Unix sockets to the user session, D-Bus, Docker, containerd, snapd, libvirt and X11 are closed |
| Policy integrity | Policy files are owned by root. Users cannot redefine the managed Codex profile or disable the required hooks and proxy. Claude Code's bypass mode is disabled, and no command can run outside the sandbox |

The exact rules, paths and variable names are in [controls](docs/controls.md).

## Install

```sh
git clone https://github.com/RanulfoMNeto/agent-security.git && cd agent-security
./tests/run.sh               # optional: repository tests, no root required
sudo ./install.sh install    # installs the scanner and both policies
./verify.sh                  # run from a regular terminal; --live also starts agent sessions
```

Restart open Claude Code and Codex sessions: policies are read when a session starts.

| Command | Effect |
|---|---|
| `./install.sh status` | Lists the installed files and their owner |
| `sudo ./install.sh install` | Installs or updates (idempotent) |
| `sudo ./install.sh uninstall` | Removes everything the installer added |

The controls restrict the agents. Protected files remain accessible from the user's own terminal
or editor. Commit regularly: agents can change files inside the project.

## Requirements

| | |
|---|---|
| Platform | Linux (x86-64, arm64), macOS, WSL2. Validated on Ubuntu 26.04; macOS, WSL2 and arm64 follow the vendors' documentation. Native Windows is not supported |
| Claude Code | 2.1.295 or later (validated 2.1.309) |
| Codex CLI | 0.138.0 or later (validated 0.163.0) |
| Tools | `bash`, `curl`, `tar`, `sha256sum` or `shasum`, `jq` at `/usr/bin/jq`. Linux also needs `bubblewrap` and `socat` (`apt-get install bubblewrap socat jq`) |
| Python | `python3` is required by `verify.sh`. Python 3.11 or later enables the installer's TOML validation (skipped otherwise) and is required by `tests/run.sh` |

The installer checks these first and reports what is missing.

## Installed files

All files are copies of repository files, owned by root.

| Installed to | Source | Purpose |
|---|---|---|
| `/opt/agent-security/bin/agent-secret-scan` | `bin/` | Hook called by both agents |
| `/opt/agent-security/bin/gitleaks`, `etc/gitleaks.toml` | Release download verified against `config/gitleaks.release`; `config/` | Secret detection |
| `/etc/claude-code/managed-settings.d/` (macOS: `/Library/Application Support/ClaudeCode/managed-settings.d/`) | `claude/managed-settings.d/*.json`; `claude/overlays/*.json` where required | Claude Code policy |
| `/etc/codex/requirements.toml` | `codex/requirements.toml` | Codex permission profile and mandatory controls |
| `/etc/codex/config.toml` | `codex/config.toml` | Default approval policy and shell environment filtering |

## User configuration

| Users can | Not changeable by users |
|---|---|
| Add hooks, permission rules, MCP servers and project settings | Removing a deny rule, a credential location or a managed hook |
| Add network hosts in their own settings, or approve one when Claude Code asks ([operations](docs/operations.md#allow-another-host)) | Changing the managed Codex profile, removing a managed host, or turning off Codex's network proxy |
| Select Claude Code modes except bypass | Entering `bypassPermissions`, selecting a Codex profile other than `agent-security`, or running a command outside the sandbox |
| Use a personal Codex `config.toml` | Loosening the Codex requirements |

Changing or removing the installed policy files requires root.

Codex's `config.toml` contains defaults, not mandatory requirements. Its environment-variable
filter can be changed by user configuration; Codex does not support that setting in
`requirements.toml`.

## Troubleshooting

| Symptom | Cause and resolution |
|---|---|
| Install stops: "bubblewrap cannot create a sandbox" | Ubuntu 24.04+ restricts user namespaces. See [operations](docs/operations.md#ubuntu-2404-and-apparmor) |
| Claude Code exits at start: sandbox unavailable | `failIfUnavailable` is enabled. Install `bubblewrap` and `socat`, then see [operations](docs/operations.md#ubuntu-2404-and-apparmor) |
| Codex: "configuration could not be loaded" | A user or project config redefines `[permissions.agent-security]`, or conflicts with a mandatory rule. Remove the conflicting definition; the managed profile is defined in `requirements.toml` |
| Every prompt or tool call is blocked, or Claude Code stops after each tool call | The scanner or gitleaks is missing or failing, and the hooks block on failure. Run `./install.sh status`, then `sudo ./install.sh install` |
| A prompt is blocked, or a tool result shows `[REDACTED]` or is withheld, and it looks like a false positive | See [operations](docs/operations.md#handle-a-false-positive) |
| A command cannot reach a host | The host is not on the allowlist, or the tool ignores `HTTPS_PROXY` (plain `ssh`, most database drivers). See [operations](docs/operations.md#allow-another-host) |
| Codex: every command fails with `ripgrep unreadable glob scan failed for /home/...` | A directory in the home directory, up to 5 levels deep, cannot be read by the user (often a container's data directory), and Codex stops rather than skip it while it looks for environment files. Find it with `find ~ -mindepth 1 -maxdepth 5 -type d ! -readable`, then make it readable or move it out of the home directory (for container data, a named volume) |
| The agent cannot read `.env.example` | The `.env.*` pattern matches it, and deny rules have no exceptions |
| Empty `.bashrc`, `.gitconfig`, `.claude/settings.json` appear as untracked files | Claude Code's Linux sandbox creates placeholders for the paths it protects (seen on 2.1.309). Do not commit them. This repository's `.gitignore` hides them; a global gitignore does the same elsewhere |

## Documentation

- [Guide](https://ranulfomneto.github.io/agent-security-guide/): an animated walkthrough of the agent loop and each control ([source](https://github.com/RanulfoMNeto/agent-security-guide))
- [Controls](docs/controls.md): every interception, block and restriction, per agent
- [Operations](docs/operations.md): update, customize, deploy, verify, Ubuntu AppArmor
- [Contributing](CONTRIBUTING.md): tests, policy files and commit conventions
- [Security policy](SECURITY.md): how to report a vulnerability

## Repository layout

| Path | Content |
|---|---|
| `install.sh`, `verify.sh` | Installer; post-install verification |
| `bin/` | The scanner |
| `claude/`, `codex/` | Policy files in each agent's native format |
| `config/` | gitleaks configuration and pinned release |
| `docs/` | Documentation |
| `tests/` | Repository tests (`tests/run.sh`) and the sandbox probe used by `verify.sh` |

## License

[MIT](LICENSE)
