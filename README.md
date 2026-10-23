# Agent Security

Security baseline for AI coding agents (Claude Code and Codex CLI) on a single Linux
workstation. It keeps credentials away from the agents, blocks the most destructive shell
commands, and stops literal secrets from reaching a model provider. Wherever possible it
does this with the agents' own native controls.

The repository is the source of truth for every installed file. Nothing here runs on its
own: the files are installed into system and user configuration locations, as described
below.

## Contents

- [Design principles](#design-principles)
- [Threat model](#threat-model)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration reference](#configuration-reference)
- [Verification](#verification)
- [Operations](#operations)
- [Known limitations](#known-limitations)
- [Uninstallation](#uninstallation)
- [References](#references)

## Design principles

1. **Native first.** Permission rules, managed settings, sandbox profiles, environment
   filtering and hooks are features the agents already provide. This baseline only
   configures them.
2. **Reuse maintained detection.** Credential detection is gitleaks with its default rule
   set. There are no hand-written secret patterns.
3. **Fail closed.** If the scanner can't run or can't parse its input, the action is
   blocked, not allowed.
4. **Tamper resistance.** The Claude Code policy and the scanner are root-owned, so an
   agent running as the user can't edit or switch them off. Codex's configuration lives
   outside every workspace, where its sandbox can't write.
5. **Minimal friction.** Ordinary reads, edits and commands are not slowed down. Routine
   confirmations stay with each agent's own permission mode.

## Threat model

The adversary is the agent itself acting on bad instructions: a mistaken plan, or a
prompt injection hidden in a file, web page or tool result.

| Risk | Example | Covered by |
|---|---|---|
| Credential files sent to the model provider | The agent reads `.env` or `~/.ssh/id_ed25519` | Claude `Read` deny rules; Codex permission profile |
| Literal credentials in prompts or tool calls | A pasted API key, or a key written into source code | `agent-secret-scan` hook, both agents |
| Secret environment variables exposed to commands | A command prints `$GITHUB_TOKEN` | Codex `shell_environment_policy` (Claude: see [limitations](#known-limitations)) |
| Destructive or remote-code commands | `rm -rf …`, `curl … \| bash` | Claude `Bash` deny rules; Codex workspace sandbox |
| Persistence through startup or VCS files | Writing `~/.bashrc` or `.git/hooks` | Claude native protected paths; Codex workspace sandbox |
| The agent weakening its own controls | Editing its policy, or switching to bypass mode | Root-owned managed settings; `disableBypassPermissionsMode` |

**Out of scope:**
- detecting prompt injection itself;
- scanning tool *output* and arbitrary file contents;
- secrets with no recognizable format (for example, a random password);
- network exfiltration by commands in Claude Code (its sandbox is disabled on this
  machine);
- anything done by the local user or by root.

## Architecture

| Control | Claude Code | Codex CLI |
|---|---|---|
| Credential files are unreadable | Managed `permissions.deny` `Read(...)` rules | `[permissions.agent-security.filesystem]` deny entries, enforced by the OS sandbox |
| Literal credentials are blocked | Managed `UserPromptSubmit` and `PreToolUse` hooks | `config.toml` `UserPromptSubmit` and `PreToolUse` hooks |
| Secret variables are hidden from commands | Not available while the sandbox is off | `shell_environment_policy.ignore_default_excludes = false` |
| Destructive commands | Managed `Bash(...)` deny rules | Writes are confined to the workspace by the sandbox |
| Persistence and VCS writes | Native protected paths (no configuration needed) | Not writable outside the workspace; `.git` is read-only inside it |
| Tamper resistance | Root-owned managed settings, `disableBypassPermissionsMode` | Configuration outside the workspace |

Both agents share the same hook command:

```text
prompt or tool call
  └─ hook (UserPromptSubmit / PreToolUse), event JSON on stdin
       └─ /usr/local/bin/agent-secret-scan
            ├─ cd /etc/agent-security        do not read repository-controlled files
            ├─ jq -r '.. | strings'          decode every string value in the event
            └─ gitleaks stdin --config …     default gitleaks rules
                 exit 0 → allow    exit 2 → block (any failure also exits 2)
```

## Repository layout

| Path | Installed to | Purpose |
|---|---|---|
| `bin/agent-secret-scan` | `/usr/local/bin/agent-secret-scan` (root, 0755) | Hook command shared by both agents |
| `gitleaks/gitleaks.toml` | `/etc/agent-security/gitleaks.toml` (root, 0644) | gitleaks configuration: default rules only |
| `claude/managed-settings.d/agent-security.json` | `/etc/claude-code/managed-settings.d/agent-security.json` (root, 0644) | Claude Code managed policy |
| `codex/config.toml` | Merged into `~/.codex/config.toml` | Codex configuration block |

## Requirements

| Component | Version | Notes |
|---|---|---|
| Linux | Tested on Ubuntu 26.04 | `/etc` layout and `bash` are assumed |
| Claude Code | 2.1.295 or later (tested 2.1.309) | `onFailure` in hooks needs 2.1.295 |
| Codex CLI | Tested 0.163.0 | Needs permission profiles and hooks |
| gitleaks | 8.30.1, official release | Ubuntu's package (8.16) has no OpenAI or Anthropic rules |
| jq | Ubuntu package | Already present on most systems: `sudo apt-get install jq` |

Installation needs `sudo`.

## Installation

Run every step from the repository root.

### 1. Install gitleaks

Download the official release, verify its SHA-256 checksum, and install the binary:

```sh
VERSION=8.30.1
TMP=$(mktemp -d)
cd "$TMP"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz"
curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_checksums.txt"
sha256sum --check --ignore-missing "gitleaks_${VERSION}_checksums.txt"
tar -xzf "gitleaks_${VERSION}_linux_x64.tar.gz" gitleaks
sudo install -o root -g root -m 0755 gitleaks /usr/local/bin/gitleaks
cd - && rm -r "$TMP"
```

Stop if `sha256sum` does not print `OK`.

### 2. Install the scanner and the Claude Code policy

```sh
sudo install -o root -g root -m 0755 -d /etc/agent-security /etc/claude-code/managed-settings.d
sudo install -o root -g root -m 0755 bin/agent-secret-scan /usr/local/bin/agent-secret-scan
sudo install -o root -g root -m 0644 gitleaks/gitleaks.toml /etc/agent-security/gitleaks.toml
sudo install -o root -g root -m 0644 claude/managed-settings.d/agent-security.json \
  /etc/claude-code/managed-settings.d/agent-security.json
```

Claude Code reloads managed settings on change. Restart open sessions to be sure.

### 3. Configure Codex

1. Insert the contents of `codex/config.toml` into `~/.codex/config.toml` **above the
   first `[table]` header**. `default_permissions` is a top-level key: placed after a
   header, it would silently belong to that table.
2. Make sure `~/.codex/config.toml` sets neither `sandbox_mode` nor
   `[sandbox_workspace_write]`; Codex doesn't combine them with `default_permissions`.
3. Validate the file:

   ```sh
   python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' ~/.codex/config.toml
   ```

4. Start `codex`, type `/hooks` **inside the interface**, and trust the two
   `agent-secret-scan` hooks. Codex doesn't run non-managed hooks until they are trusted.

## Configuration reference

### Claude Code: `claude/managed-settings.d/agent-security.json`

Claude Code settings files are strict JSON and can't contain comments, so every key is
documented here.

| Key | Value | Rationale |
|---|---|---|
| `$schema` | SchemaStore URL | Editor validation and completion, as recommended by the settings documentation |
| `permissions.disableBypassPermissionsMode` | `"disable"` | Removes `bypassPermissions` (`--dangerously-skip-permissions`), the mode that skips every confirmation. Other modes, including auto, are unaffected |
| `permissions.deny` → `Read(//**/.env)`, `Read(//**/.env.*)` | — | Environment files in any directory (`//` anchors at the filesystem root). This includes `.env.example`, because deny rules can't have exceptions |
| `permissions.deny` → `Read(~/.ssh/**)`, `~/.aws/**`, `~/.azure/**`, `~/.config/gcloud/**`, `~/.kube/**` | — | Credential directories of SSH and the major cloud CLIs |
| `permissions.deny` → `Read(~/.docker/config.json)`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.config/gh/hosts.yml` | — | Registry and Git credential files |
| `permissions.deny` → `Read(~/.claude/.credentials.json)`, `Read(~/.codex/auth.json)` | — | The agents' own login tokens |
| `permissions.deny` → `Bash(rm -r *)`, `Bash(rm -rf *)`, `Bash(rm -fr *)`, `Bash(rm -R *)`, `Bash(rm --recursive *)` | — | Recursive deletion. Run it yourself when you need it |
| `permissions.deny` → `Bash(curl * \| bash)`, `Bash(curl * \| sh)`, `Bash(wget * \| bash)`, `Bash(wget * \| sh)` | — | Downloading and executing a remote script |
| `hooks.UserPromptSubmit[].hooks[]` | `agent-secret-scan` | Scans each prompt before it reaches the model; a blocked prompt is never sent |
| `hooks.PreToolUse[].matcher` | `"*"` | Every tool, including MCP tools |
| `hooks.PreToolUse[].hooks[]` | `agent-secret-scan` | Scans every argument of a tool call before it runs |
| hook `command` | `/usr/local/bin/agent-secret-scan` | Absolute path: no lookup through `PATH` |
| hook `args` | `[]` | Presence of `args` selects exec form: no shell is involved |
| hook `timeout` | `10` | Seconds. A scan takes about 0.3 s |
| hook `onFailure` | `"block"` | A hook that can't start, crashes or times out blocks the action |

How these rules behave natively:
- `deny` rules apply in every permission mode, including auto.
- A `Read` deny also blocks `Edit` and `Write` on the same path, and the file commands
  Claude Code recognizes in Bash (`cat`, `head`, `tail`, `sed`, `tee`, and `<` / `>`
  redirections).
- Managed hooks can't be disabled from user or project settings.

Deliberately not configured:
- **Persistence paths:** writes to `.git`, `.claude`, `.vscode`, `.bashrc`, `.zshrc`,
  `.gitconfig`, `.npmrc` and similar are Claude Code's native *protected paths*. They are
  never auto-approved: you get a prompt in default mode, and the classifier decides in
  auto mode.
- **Cloud metadata endpoints:** irrelevant on a workstation.
- **Prompt-injection patterns:** text heuristics are unreliable; see the threat model.
- **An audit log:** Claude Code already keeps session transcripts in `~/.claude/projects`.

### Scanner: `bin/agent-secret-scan`

The script is commented inline. Its gitleaks invocation:

| Option | Purpose |
|---|---|
| `jq -r '.. \| strings'` (before gitleaks) | Hook events are JSON, where quotes are escaped as `\"`. gitleaks rules expect raw text, so a key inside quoted code would otherwise go undetected |
| `cd /etc/agent-security` | gitleaks reads `.gitleaksignore` from its working directory. Without this, a repository could ship one that suppresses findings |
| `--config /etc/agent-security/gitleaks.toml` | Takes precedence over a repository's `.gitleaks.toml` and the `GITLEAKS_CONFIG` variables |
| `--gitleaks-ignore-path /etc/agent-security` | Reads ignore files only from the root-owned directory |
| `--ignore-gitleaks-allow` | Disregards inline `gitleaks:allow` comments, which an agent could add to its own output |
| `--redact` | Never echoes a detected secret |
| `--log-level error` | Keeps the block reason to the script's single line |
| `--exit-code 2` | Maps "secret found" to the block code that both agents use |

Every other outcome also exits 2: invalid JSON, a missing gitleaks, or a gitleaks error.

### gitleaks: `gitleaks/gitleaks.toml`

The file only sets `[extend] useDefault = true`. The rule set is the default one in the
installed gitleaks release, so updating gitleaks updates the rules.

### Codex: `codex/config.toml`

The block is commented inline. In summary:

| Key | Value | Rationale |
|---|---|---|
| `default_permissions` | `"agent-security"` | Sandbox profile for every command Codex runs |
| `permissions.agent-security.extends` | `":workspace"` | Built-in behaviour: read the machine, write only the workspace |
| `permissions.agent-security.filesystem` | absolute paths = `"deny"` | Same credential locations as Claude Code. The OS sandbox blocks reads and writes |
| `…filesystem.":workspace_roots"` | `"**/.env"`, `"**/.env.*"` = `"deny"` | Environment files inside every workspace |
| `shell_environment_policy.ignore_default_excludes` | `false` | Removes variables whose names contain `KEY`, `SECRET` or `TOKEN` from command environments |
| `[[hooks.UserPromptSubmit]]`, `[[hooks.PreToolUse]]` | `agent-secret-scan` | Same scanner as Claude Code. `matcher = ""` covers every tool, including shell, `apply_patch` and MCP |

Paths are absolute because Codex permission profiles require absolute paths. They name
the user `ranulfo`; adjust them on another machine.

## Verification

### Scanner

```sh
# Allowed: exit 0
printf '{"prompt":"refactor the parser"}' | agent-secret-scan; echo "exit=$?"

# Blocked: exit 2 (a synthetic, correctly formatted GitHub token)
python3 -c 'import json,secrets,string; print(json.dumps({"prompt": "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))}))' \
  | agent-secret-scan; echo "exit=$?"

# Invalid input fails closed: exit 2
printf 'not json' | agent-secret-scan; echo "exit=$?"
```

### Claude Code

1. In a session, run `/status`: `Setting sources` lists managed settings.
2. Run `claude doctor` in a terminal: no settings errors.
3. In a scratch project with a `.env`, ask Claude to read it, both with the Read tool and
   with `cat .env`. Expected: denied by permission settings.
4. Ask Claude to run `rm -rf somedir`. Expected: denied.
5. Paste a synthetic key, such as the token generated above, into a prompt. Expected:
   `UserPromptSubmit operation blocked by hook`.

### Codex

From a project directory that contains a `.env`:

```sh
codex sandbox -- cat .env                              # Permission denied
codex sandbox -- ls ~/.ssh                             # Permission denied
codex sandbox -- sh -c 'echo ok > probe && cat probe'  # ok (workspace is writable)
GITHUB_TOKEN=x codex sandbox -- sh -c 'echo "[$GITHUB_TOKEN]"'  # []
```

After trusting the hooks with `/hooks`, a prompt containing a synthetic key is blocked.

## Operations

### Update gitleaks

1. Check the [gitleaks releases](https://github.com/gitleaks/gitleaks/releases).
2. Repeat [step 1](#1-install-gitleaks) with the new `VERSION`.
3. Run the [scanner verification](#scanner).
4. Update the version in this README and commit.

### Change a rule

1. Edit the file in this repository.
2. Reinstall it with the matching `sudo install` command, or merge the Codex block again.
3. Run the verification for that agent and commit.

Claude Code reloads managed settings automatically. Codex reads `config.toml` at start-up.
If a hook definition changes, trust it again with `/hooks`.

### Handle a false positive

- **Preferred:** don't put the value in the prompt or the code. Reference it through an
  environment variable or a secret manager.
- **If a value must be allowed:** add an allowlist to `gitleaks/gitleaks.toml` (see the
  [gitleaks configuration documentation](https://github.com/gitleaks/gitleaks#configuration))
  and reinstall it.
- These bypasses are intentionally disabled: inline `gitleaks:allow` comments, and a
  repository's `.gitleaks.toml` or `.gitleaksignore`.

### Access a protected file yourself

The rules restrict the agents only. Open the file in your own terminal or editor.

## Known limitations

1. **Claude Code's Bash sandbox is off.** On Ubuntu 24.04 and later,
   `kernel.apparmor_restrict_unprivileged_userns = 1` stops it from starting: every command
   fails with `apply-seccomp: … CAP_SYS_ADMIN`.
   - The official fix is an AppArmor profile at `/etc/apparmor.d/bwrap`, from the
     [sandboxing documentation](https://code.claude.com/docs/en/sandboxing). It declares
     a profile named `bwrap`, the same name as Ubuntu's `bwrap-userns-restrict` profile,
     which the Codex sandbox relies on. That is why it was not applied.
   - Consequence in Claude Code: commands that reach secrets indirectly (for example,
     `python3 -c "open('.env')"`), environment variables, and writes outside the project
     are not confined by the OS. Only the permission rules and confirmations apply.
2. **`Bash` rules match command text.** Equivalent forms such as `find … -delete`, a
   script, or another program are not matched.
3. **Detection is pattern-based.** Secrets with no recognizable format pass. Tool output
   and file contents read by the agent are not scanned.
4. **`.env.example` and similar files are unreadable** by the agents, because deny rules
   can't have exceptions.
5. **Codex can delete files inside the workspace.** Its sandbox confines writes, including
   deletions, to the workspace and keeps `.git` read-only, but has no rule against
   `rm -rf` on the project's own files. Commit often.
6. **Codex continues when a hook can't start**, for example when the script is missing.
   Codex has no equivalent of `onFailure`. Once started, the script blocks on every error.
7. **Codex paths are specific to this user**, because profiles require absolute paths.
8. **Not a boundary against the local user or root.** Anyone with `sudo` can change or
   remove the policy.

## Uninstallation

```sh
sudo rm /etc/claude-code/managed-settings.d/agent-security.json \
  /etc/agent-security/gitleaks.toml \
  /usr/local/bin/agent-secret-scan \
  /usr/local/bin/gitleaks
sudo rmdir /etc/agent-security
```

Then delete the block between `# BEGIN agent-security` and `# END agent-security` in
`~/.codex/config.toml`.

## References

- Claude Code:
  - [Settings](https://code.claude.com/docs/en/settings)
  - [Managed settings](https://code.claude.com/docs/en/managed-settings)
  - [Permissions](https://code.claude.com/docs/en/permissions)
  - [Permission modes](https://code.claude.com/docs/en/permission-modes)
  - [Hooks](https://code.claude.com/docs/en/hooks)
  - [Sandboxing](https://code.claude.com/docs/en/sandboxing)
- Codex:
  - [Hooks](https://learn.chatgpt.com/docs/hooks)
  - [Sandboxing](https://learn.chatgpt.com/docs/sandboxing)
  - [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- gitleaks:
  - [Repository and configuration](https://github.com/gitleaks/gitleaks)
  - [Release v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
