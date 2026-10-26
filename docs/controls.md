# Controls

Reference for every control the baseline applies. The controls act on the agents and on the
processes they start. They do not apply to the user's own terminal or editor.

## Precedence

- **Claude Code.** Managed settings apply above user, project, local and command-line settings.
  The files in `managed-settings.d/` are merged in alphabetical order. Other levels can only add.
- **Codex.** `requirements.toml` takes precedence over the user's `~/.codex/config.toml` and over
  command-line options. `/etc/codex/config.toml` is the system layer; the user's file is merged
  on top of it.

## 1. Credential scanner (interception)

Both agents call `/opt/agent-security/bin/agent-secret-scan` on two events.

| Event | Runs | Claude Code | Codex |
|---|---|---|---|
| `UserPromptSubmit` | Before a prompt reaches the model | All prompts | All prompts |
| `PreToolUse` | Before every tool call, MCP tools included | Matcher `*` | Matcher `""` |

**Input.** Every string value of the event JSON: prompt text and tool-call input (commands, file
contents to write, tool arguments). Tool results are not part of these events.

**Detection.** The default rule set of gitleaks 8.30.1 (OpenAI, Anthropic, GitHub, AWS, private
keys and other providers), configured by `/opt/agent-security/etc/gitleaks.toml`. Findings are
redacted.

**Decision.**

| Condition | Exit code | Result |
|---|---|---|
| No credential found | 0 | Allowed |
| Credential found | 2 | Blocked, with a message on stderr |
| Empty input, invalid JSON, or JSON that is not an object | 2 | Blocked |
| gitleaks missing or failing, or the scanner cannot locate its files | 2 | Blocked |

**Isolation.**
- `jq` and `gitleaks` run by absolute path with an empty environment (`env -i`).
- The configuration is always `/opt/agent-security/etc/gitleaks.toml`, and the scanner runs from
  `/opt/agent-security/etc`.
- A repository's `.gitleaks.toml` and `.gitleaksignore`, `GITLEAKS_*` variables and inline
  `gitleaks:allow` comments have no effect.

**Hook execution.**
- *Claude Code:* exec form (`args: []`, no shell, no `PATH`), timeout 10 s, `onFailure: block`,
  so the action is blocked when the hook cannot run.
- *Codex:* timeout 10 s, status messages "Scanning prompt for credentials" and "Scanning tool call
  for credentials". `[features] hooks = true` and `[hooks] managed_dir` make the hooks managed: they
  run without the per-user trust step and users cannot disable them. Codex acts on exit code 2.

## 2. Credential locations (read denied)

Twenty-seven locations are denied in both agents.

| Category | Locations |
|---|---|
| SSH and GPG | `~/.ssh`, `~/.gnupg` |
| Cloud and clusters | `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube` |
| Secret stores | `~/.password-store`, `~/.config/op`, `~/.local/share/keyrings`, `~/Library/Keychains`, `~/.vault-token` |
| Browser profiles | `~/.mozilla`, `~/.config/google-chrome`, `~/.config/chromium`, `~/Library/Application Support/Google/Chrome`, `~/Library/Application Support/Firefox` |
| Developer tool credentials | `~/.config/gh`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.terraform.d/credentials.tfrc.json` |
| Shell history | `~/.bash_history`, `~/.zsh_history` |
| Agent credentials | `~/.claude/.credentials.json`, `~/.codex/auth.json` |

- **Claude Code:** `permissions.deny` entries `Read(<path>)` (`Read(<path>/**)` for directories).
  Claude Code applies them to its file tools and merges them into the OS sandbox, so they also
  bind every command the agent runs.
- **Codex:** `permissions.filesystem.deny_read` in `requirements.toml`, enforced by the OS sandbox
  in every profile.

**Environment files** (`**/.env`, `**/.env.*`, which includes `.env.example`; deny rules have no
exceptions):

| | Mechanism |
|---|---|
| Claude Code | `Read(//**/.env)` and `Read(//**/.env.*)`: Claude Code's file tools anywhere on the machine, and the file commands it recognizes. `sandbox.credentials.files` (`deny`): every command, in the project directory tree at any depth |
| Codex | Profile `agent-security`: `deny` for both patterns under `:workspace_roots`, scanned to a depth of 6 directories (`glob_scan_max_depth`). The rule is in `config.toml` because Codex applies `**/.env` globs only from a profile |

## 3. Environment variables

- **Claude Code:** `sandbox.credentials.envVars` (`deny`, exact names) removes these 19 variables
  from commands: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
  `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `GH_ENTERPRISE_TOKEN`,
  `GITHUB_ENTERPRISE_TOKEN`, `GITLAB_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, `AZURE_CLIENT_SECRET`, `NPM_TOKEN`, `TWINE_PASSWORD`, `SLACK_BOT_TOKEN`,
  `SSH_AUTH_SOCK`. `SSH_AUTH_SOCK` is included so that a running ssh-agent cannot sign with the
  user's keys.
- **Codex:** `shell_environment_policy` with `ignore_default_excludes = false` removes every
  variable whose name contains `KEY`, `SECRET` or `TOKEN`.

## 4. Sandbox

| Aspect | Claude Code | Codex |
|---|---|---|
| Writes | Project directory and temporary directory | Workspace only; `.git` read-only |
| Reads | Denied locations blocked; `allowManagedReadPathsOnly: true` prevents users from re-opening a protected path | Denied locations blocked; the rest of the machine readable |
| Network | None until the user approves a host | None |
| Unix sockets | See section 5 | Blocked |
| Persistence and version-control paths | Native protected paths | Not writable outside the workspace |
| Sandbox required | `enabled: true`; `failIfUnavailable: true` (Claude Code exits rather than run unsandboxed) | Managed profile `agent-security`, which extends the built-in `:workspace` |
| Unsandboxed execution | `allowUnsandboxedCommands: false`, `enableWeakerNestedSandbox: false`, `allowNestedUserNamespaces: false` | Allowed profiles: `agent-security`, `:read-only` |

## 5. Local services (Unix sockets)

- **Claude Code:** where the kernel allows it, Claude Code's seccomp filter blocks Unix sockets.
  Where that filter cannot start (see [operations](operations.md#ubuntu-2404-and-apparmor)), the
  installer adds `20-linux-unix-sockets.json`, which sets `sandbox.network.allowAllUnixSockets` so
  the sandbox starts and denies reads of these paths:

  | Service | Paths |
  |---|---|
  | User session | `/run/user` |
  | System D-Bus | `/run/dbus`, `/var/run/dbus` |
  | Docker | `/run/docker.sock`, `/var/run/docker.sock` |
  | containerd | `/run/containerd` |
  | snapd | `/run/snapd.socket`, `/run/snapd-snap.socket` |
  | libvirt | `/run/libvirt`, `/var/run/libvirt` |
  | X11 | `/tmp/.X11-unix`, `/tmp/.ICE-unix` |

- **Codex:** the sandbox blocks Unix sockets.

## 6. Command rules

- **Claude Code:** `permissions.deny` contains `Bash(rm -r *)`, `Bash(rm -rf *)`, `Bash(rm -fr *)`,
  `Bash(rm -R *)` and `Bash(rm --recursive *)`. The rules match the command text as submitted.
- **Codex:** no command rules; writes are confined to the workspace.

## 7. Permission mode and profile

- **Claude Code:** `permissions.disableBypassPermissionsMode: "disable"` removes
  `bypassPermissions`. Every other permission mode remains available.
- **Codex:** `default_permissions = "agent-security"`. `allowed_permission_profiles` lists
  `agent-security` and `:read-only`; `:danger-full-access` is excluded, which also keeps
  `--dangerously-bypass-approvals-and-sandbox` from leaving the sandbox.

## 8. Installation integrity

- Every policy file is validated (JSON with `jq`, TOML with `tomllib`) before anything is changed.
- gitleaks is downloaded from the release (or a configured mirror) and checked against the SHA-256
  pinned in `config/gitleaks.release`. A mismatch aborts the installation. The version must equal
  the pinned one.
- The scanner is installed and self-tested before the policies that call it.
- An existing `/etc/codex` file that does not start with `# Managed by agent-security.` is never
  overwritten.
- Installed files are copies of the repository files, owned by root. `install.sh status` reports
  a missing file or a file not owned by root.
- The installer warns when the invoking user has passwordless `sudo`.

## Implementation notes

- Claude Code settings are strict JSON and cannot hold comments; the reasons for non-obvious
  choices are recorded in this document.
- The credential list exists once per agent, in each agent's format. `tests/consistency.py` fails
  when the two differ.
- `sandbox.credentials.envVars` accepts exact names only; patterns are rejected.
- A managed settings file that cannot be parsed is not applied and Claude Code refuses to start,
  hence the validation step of the installer.
- Any `*.json` added to `claude/managed-settings.d/` is installed. A numeric prefix controls the
  merge order.
