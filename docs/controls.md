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

Both agents call `/opt/agent-security/bin/agent-secret-scan` on three events.

| Event | Runs | Claude Code | Codex |
|---|---|---|---|
| `UserPromptSubmit` | Before a prompt reaches the model | All prompts | All prompts |
| `PreToolUse` | Before every tool call, MCP tools included | Matcher `*` | Matcher `""` |
| `PostToolUse` | After a tool call succeeds, before its result reaches the model | Matcher `*`, argument `--redact` | Matcher `""` |

**Input.** Every string value of the event JSON: prompt text, tool-call input (commands, file
contents to write, tool arguments) and, on `PostToolUse`, the tool result. With `--redact`, the
tool result (`tool_response`) only. Codex runs no `PostToolUse` hook for hosted tools such as web
search.

**Detection.** The default rule set of gitleaks 8.30.1 (OpenAI, Anthropic, GitHub, AWS, private
keys and other providers), configured by `/opt/agent-security/etc/gitleaks.toml`. Findings are
redacted.

**Decision, block mode** (every hook except Claude Code's `PostToolUse`).

| Condition | Exit code | Result |
|---|---|---|
| No credential found | 0 | Allowed |
| Credential found | 2 | Blocked, with a message on stderr. On Codex's `PostToolUse`, the message replaces the tool result |
| Empty input, invalid JSON, or JSON that is not an object | 2 | Blocked |
| gitleaks missing or failing, or the scanner cannot locate its files | 2 | Blocked |

**Decision, redact mode** (Claude Code's `PostToolUse`). The tool has already run.

| Condition | Output | Result |
|---|---|---|
| No credential found | None | The result reaches the model unchanged |
| Credential found | `updatedToolOutput` | Each credential is replaced with `[REDACTED]` in every string of the result; the structure of the result is unchanged. `additionalContext` tells the model how many were replaced. The replaced result is scanned again |
| A credential remains after the replacement, the input cannot be parsed, or gitleaks fails | `continue: false` | The session stops before the result reaches the model |

**Isolation.**
- `jq` and `gitleaks` run by absolute path with an empty environment (`env -i`).
- The configuration is always `/opt/agent-security/etc/gitleaks.toml`, and the scanner runs from
  `/opt/agent-security/etc`.
- A repository's `.gitleaks.toml` and `.gitleaksignore`, `GITLEAKS_*` variables and inline
  `gitleaks:allow` comments have no effect.

**Hook execution.**
- *Claude Code:* exec form (`args: []`, or `["--redact"]` on `PostToolUse`; no shell, no
  `PATH`), timeout 10 s, `onFailure: block`, so the action is blocked when the hook cannot run.
  On `PostToolUse`, a hook that cannot run shows its error to the model next to the result.
- *Codex:* timeout 10 s, status messages "Scanning prompt for credentials", "Scanning tool call
  for credentials" and "Scanning tool output for credentials". `[features] hooks = true` and
  `[hooks] managed_dir` make the hooks managed: they run without the per-user trust step and
  users cannot disable them. Codex acts on exit code 2.

## 2. Credential locations (read denied)

Twenty-nine locations are denied in both agents.

| Category | Locations |
|---|---|
| SSH and GPG | `~/.ssh`, `~/.gnupg` |
| Cloud and clusters | `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube` |
| Secret stores | `~/.password-store`, `~/.config/op`, `~/.local/share/keyrings`, `~/Library/Keychains`, `~/.vault-token` |
| Browser profiles | `~/.mozilla`, `~/.config/google-chrome`, `~/.config/chromium`, `~/Library/Application Support/Google/Chrome`, `~/Library/Application Support/Firefox` |
| Developer tool credentials | `~/.config/gh`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.terraform.d/credentials.tfrc.json` |
| Git credentials | `~/.git-credentials`, `~/.config/git/credentials` (git's `store` helper), `~/.cache/git/credential` (the socket of git's `cache` helper) |
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

**Startup files** (write denied, Claude Code). `permissions.deny` entries `Edit(<path>)` stop
Claude Code's file tools (Write, Edit, NotebookEdit) from changing files that run commands at
login or configure git and SSH, in every permission mode and when the user approves:

| Category | Paths |
|---|---|
| Shell startup | `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv` |
| Git and SSH | `~/.gitconfig`, `~/.config/git/config`, `~/.ssh/**` |
| Autostart | `~/.config/autostart/**`, `~/Library/LaunchAgents/**` |

Commands cannot write these paths in either agent: the sandbox confines writes to the project
(section 4).

## 3. Environment variables

- **Claude Code:** `sandbox.credentials.envVars` (`deny`, exact names) removes these 59 variables
  from commands:

  | Category | Variables |
  |---|---|
  | AI providers | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AZURE_OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, `COHERE_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `REPLICATE_API_TOKEN`, `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN` |
  | Code hosting | `GITHUB_TOKEN`, `GH_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`, `GITLAB_TOKEN` |
  | Cloud and hosting | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AZURE_CLIENT_SECRET`, `ARM_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDFLARE_API_TOKEN`, `DIGITALOCEAN_ACCESS_TOKEN`, `HCLOUD_TOKEN`, `VERCEL_TOKEN`, `NETLIFY_AUTH_TOKEN`, `HEROKU_API_KEY`, `FLY_API_TOKEN`, `VAULT_TOKEN`, `TF_TOKEN_app_terraform_io` |
  | Package registries | `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `YARN_NPM_AUTH_TOKEN`, `TWINE_PASSWORD`, `UV_PUBLISH_TOKEN`, `POETRY_PYPI_TOKEN_PYPI`, `CARGO_REGISTRY_TOKEN`, `GEM_HOST_API_KEY`, `DOCKERHUB_TOKEN` |
  | CI and code analysis | `CI_JOB_TOKEN`, `CODECOV_TOKEN`, `SONAR_TOKEN`, `SNYK_TOKEN` |
  | Services and secret stores | `SLACK_BOT_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK_URL`, `SENTRY_AUTH_TOKEN`, `STRIPE_SECRET_KEY`, `STRIPE_API_KEY`, `TWILIO_AUTH_TOKEN`, `SENDGRID_API_KEY`, `OP_SERVICE_ACCOUNT_TOKEN`, `BW_SESSION` |
  | SSH agent | `SSH_AUTH_SOCK`, so that a running ssh-agent cannot sign with the user's keys |

- **Codex:** `shell_environment_policy` with `ignore_default_excludes = false` removes every
  variable whose name contains `KEY`, `SECRET` or `TOKEN`, in any case. `exclude` also removes
  `TWINE_PASSWORD`, `GOOGLE_APPLICATION_CREDENTIALS`, `SLACK_WEBHOOK_URL`, `BW_SESSION` and
  `SSH_AUTH_SOCK`, the names on Claude Code's list that those words do not match.

## 4. Sandbox

| Aspect | Claude Code | Codex |
|---|---|---|
| Writes | Project directory and temporary directory; `.git/config` and `.git/hooks` read-only | Workspace and temporary directory (`/tmp`, `$TMPDIR`); `.git/config` and `.git/hooks` read-only |
| Reads | Denied locations blocked; `allowManagedReadPathsOnly: true` prevents users from re-opening a protected path | Denied locations blocked; the rest of the machine readable |
| Network | Allowed hosts (below); another host after the user approves it | Allowed hosts (below); no other host |
| Unix sockets | See section 5 | Blocked |
| Persistence and version-control paths | Native protected paths | Not writable outside the workspace; `.agents`, `.codex` and `.aws` in the workspace read-only |
| Sandbox required | `enabled: true`; `failIfUnavailable: true` (Claude Code exits rather than run unsandboxed) | Managed profile `agent-security`, which extends the built-in `:workspace` |
| Unsandboxed execution | `allowUnsandboxedCommands: false`, `enableWeakerNestedSandbox: false`, `allowNestedUserNamespaces: false` | Allowed profiles: `agent-security`, `:read-only`. No sandbox escalation prompts (section 7) |

**`.git`.** Both agents can commit. `config` and `hooks` stay read-only: either can make git run
a program the next time the user runs git outside the sandbox. Claude Code protects them
natively. Codex's built-in `:workspace` keeps all of `.git` read-only; profile `agent-security`
sets `".git" = "write"`, `".git/config" = "read"` and `".git/hooks" = "read"` under
`:workspace_roots`. When `.git` is a file (a worktree or a submodule), Codex protects the git
directory it points to, which this rule does not open.

**Allowed hosts.** Hosts that serve source code and packages, where reading needs no credential
and writing needs one the agent cannot reach (sections 2 and 3):

| Category | Hosts |
|---|---|
| Code hosting | `github.com`, `*.github.com`, `*.githubusercontent.com`, `gitlab.com` |
| JavaScript | `registry.npmjs.org`, `registry.yarnpkg.com`, `repo.yarnpkg.com` |
| Python | `pypi.org`, `files.pythonhosted.org` |
| Rust | `crates.io`, `index.crates.io`, `static.crates.io`, `static.rust-lang.org` |
| Go | `proxy.golang.org`, `sum.golang.org` |
| Ruby | `rubygems.org`, `index.rubygems.org` |
| Java | `repo.maven.apache.org`, `repo1.maven.org`, `plugins.gradle.org`, `services.gradle.org`, `downloads.gradle.org` |
| .NET and PHP | `api.nuget.org`, `repo.packagist.org` |

- `*.` matches subdomains only; an apex host is listed on its own.
- Commands reach the network through a proxy that each agent runs outside the sandbox and
  announces in `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`. A tool that ignores these variables
  (plain `ssh`, most database drivers) reaches no host.
- **Claude Code:** `sandbox.network.allowedDomains`, every port of each host.
  `allowManagedDomainsOnly` is not set: for another host, Claude Code asks the user, and hosts in
  the user's own settings are added to the list.
- **Codex:** profile `agent-security`, `[permissions.agent-security.network]` with
  `enabled = true` and the hosts as `allow` under `domains`. Only the network proxy applies these
  rules, and a profile with the network on and no proxy reaches every host; `requirements.toml`
  pins `[features] network_proxy = true` so that users cannot turn the proxy off. Codex's proxy
  refuses local and private addresses.
- The list applies to commands. Tools the agents run themselves (Claude Code's WebFetch and
  WebSearch, Codex's web search) follow each agent's own permission rules.

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
- **Codex:** `requirements.toml` `[rules] prefix_rules`: `rm` followed by `-r`, `-rf`, `-fr`, `-R`
  or `--recursive` is `forbidden`. The rule matches the command's first two arguments.

## 7. Permission mode and profile

- **Claude Code:** `permissions.disableBypassPermissionsMode: "disable"` removes
  `bypassPermissions`. Every other permission mode remains available.
- **Codex:** `default_permissions = "agent-security"`. `allowed_permission_profiles` lists
  `agent-security` and `:read-only`; `:danger-full-access` is excluded, which also keeps
  `--dangerously-bypass-approvals-and-sandbox` from leaving the sandbox.
- **Codex approvals:** `allowed_approval_policies` allows `never` and a granular policy, set as
  the default in `config.toml`: on-request with `sandbox_approval = false`. Codex then rejects,
  without asking, every request to run a command outside the sandbox, the request it makes when
  the proxy refuses a host. Other approval prompts (rules, MCP elicitations, permission requests,
  skill scripts) remain. Claude Code's equivalent is `allowUnsandboxedCommands: false`.

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
- The credential locations, the secret variables and the allowed hosts exist once per agent, in
  each agent's format. `tests/consistency.py` fails when the two differ.
- `sandbox.credentials.envVars` accepts exact names only; patterns are rejected.
- A managed settings file that cannot be parsed is not applied and Claude Code refuses to start,
  hence the validation step of the installer.
- Any `*.json` added to `claude/managed-settings.d/` is installed. A numeric prefix controls the
  merge order.
