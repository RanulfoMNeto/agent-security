# Threat model, design notes and limitations

## Who the adversary is

The agent itself, acting on bad instructions: a mistaken plan, or a prompt injection hidden in
a file, a web page or a tool result. The goal is to limit the damage, and to keep secrets from
being sent to a model provider.

## Coverage

| Risk | Claude Code | Codex |
|---|---|---|
| Credential locations read | `Read` deny rules. Claude Code merges them into the OS sandbox, so they hold for every command, not only for its own tools | `deny_read` in requirements, enforced by the OS sandbox; users cannot weaken it |
| `.env` files read | In the project directory tree, at any depth: sandbox `credentials.files`. Anywhere else: only its own file tools and the file commands it recognizes (`cat`) | Inside the workspace, to a depth of 6: a profile rule |
| Literal credentials in prompts and tool calls | `UserPromptSubmit` and `PreToolUse` hooks | Managed hooks, same scanner |
| Secret environment variables | Sandbox `credentials.envVars` (exact names) | `shell_environment_policy`: names containing `KEY`, `SECRET` or `TOKEN` |
| Writes outside the project | Sandbox: project and temp directory only | `:workspace` profile: workspace only; `.git` read-only |
| Network exfiltration by commands | Sandbox: no network until a host is approved | Sandbox: network off |
| Local services as a way out | Sandbox path denies for the user session, system D-Bus, Docker, containerd, snapd, libvirt and X11, on systems that need the overlay; elsewhere a seccomp filter blocks Unix sockets | The sandbox blocks Unix sockets |
| Persistence and VCS writes | Native protected paths | Not writable outside the workspace |
| Destructive commands | `Bash(rm -r …)` and similar deny rules, plus write confinement | Write confinement only |
| Disabling the controls | Root-owned managed settings, `disableBypassPermissionsMode`, sandbox locks | Root-owned requirements: allowed profiles, denied paths, pinned hooks |

## Out of scope

- Detecting prompt injection itself.
- Scanning tool *output* and the contents of files the policy does not protect.
- Secrets with no recognizable format, such as a random password.
- Anything done by the local user or by root.

## Limitations

1. **`Bash` deny rules match command text.** `rm -vrf`, `rm -f -r`, `/bin/rm`, `find … -delete`,
   a script or another program are not matched. Write confinement and version control are what
   protect the project: commit often.
2. **Codex can delete files inside the workspace.** Its sandbox confines writes to the
   workspace and keeps `.git` read-only, but nothing stops `rm -rf` on the project's own files.
3. **`.env` files outside the project are only partly covered.** A shell command in one
   project can read another project's `.env` with a program Claude Code does not recognize
   (`python`, for example) or with Codex. Credential directories in the home directory are
   protected everywhere.
4. **Detection is pattern-based.** Tool output and the files the agent reads are not scanned.
   gitleaks' own OpenAI rule (8.30.1) misses a key whose last character is `-`, because the rule
   requires a word boundary there: roughly 1 key in 64.
5. **Codex's `.env` rule lives in the profile, not in requirements.** Codex applies `**/.env` globs only from a profile. In tests a user's own `config.toml` could not remove the rule, but only requirements are documented as non-overridable, so this is observed behaviour, not a guarantee.
6. **`.env.example` and similar files are unreadable** by the agents: deny rules have no exceptions.
7. **Claude Code's Unix-socket protection is weaker where the overlay is used.** The overlay
   hides a list of paths; a socket outside the list is reachable. Where the kernel allows it,
   Claude Code's seccomp filter blocks Unix sockets entirely.
8. **Codex keeps running if a hook cannot start** (for example if the scanner was deleted);
   Claude Code has `onFailure: block`. The installer puts the scanner in place before the
   policy that calls it, and `./install.sh status` reports a missing file.
9. **Users can extend the policy** with their own hooks, allow rules and network approvals.
   This is deliberate.
10. **Not a boundary against the local user or root.** Anyone with `sudo` can change or remove
   the policy. With passwordless `sudo` (the default on WSL), anything running outside the
   agents' sandboxes could do the same; the installer warns when it detects this.
11. **Native Windows is unsupported:** Claude Code runs commands unsandboxed there.

## Design notes

Why the policy looks the way it does. Claude Code's settings are strict JSON and cannot hold
comments, so the reasons for its non-obvious choices are here; the Codex files and the scanner
explain themselves inline.

- **Managed settings.** The Claude Code files are installed as managed settings (a root-owned
  system directory). Claude Code applies them above user, project, local and command-line
  settings, merges the files in alphabetical order, and lets the other levels only add. Any
  `*.json` added to `claude/managed-settings.d/` is installed too; prefix it with a number to
  control the order.
- **One list of credential paths.** The `Read(...)` deny rules are merged into the OS sandbox by
  Claude Code, so they bind every command, not only its own file tools. Only the `.env` globs
  are repeated in `sandbox.credentials.files`: that glob is anchored at the project, and the
  `Read(//**/.env)` rule does not reach arbitrary programs. Codex's list is `deny_read` in
  `requirements.toml`; `tests/consistency.py` keeps the two equal.
- **Environment variables** are removed with `sandbox.credentials.envVars`. Names must be exact
  (patterns are rejected). `SSH_AUTH_SOCK` is included so a running ssh-agent cannot sign with
  your keys.
- **The sandbox cannot be switched off.** `failIfUnavailable` makes Claude Code exit instead of
  running unsandboxed, `allowUnsandboxedCommands: false` removes the escape hatch, the weakening
  options stay `false`, and `allowManagedReadPathsOnly` stops users from re-opening a read path.
  `disableBypassPermissionsMode` removes `bypassPermissions`.
- **Hooks** run in exec form (`args: []`: no shell, no `PATH`) with `onFailure: block`, before the
  prompt reaches the model and before every tool call, MCP tools included.
- **`Bash(rm -r …)` and `Bash(curl … | bash)`** are a speed bump, not a boundary (limitation 1).
- **The socket overlay** (`claude/overlays/20-linux-unix-sockets.json`) exists because on some
  systems Claude Code's seccomp helper, which normally blocks Unix sockets, cannot start (see
  [operations](operations.md#ubuntu-2404-and-apparmor)). The overlay allows sockets so the
  sandbox can start, and hides the ones that matter by path. The sandbox writes only in the
  project and temp directories, so no `denyWrite` list is needed.
- **Codex splits the policy in two files.** `requirements.toml` holds what users cannot override
  (allowed profiles, denied credential paths, pinned hooks); `config.toml` holds the profile, the
  environment filtering and the `.env` rules.
- **A settings file that cannot be parsed is not applied,** and for managed files Claude Code
  refuses to start. `install.sh` validates every file before installing it for this reason.
