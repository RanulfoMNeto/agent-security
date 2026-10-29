# Operations

## Update

```sh
git pull
./tests/run.sh
sudo ./install.sh install    # idempotent: replaces the installed files
./verify.sh
```

Claude Code reloads managed settings when they change; restart sessions to apply them at once.
Codex reads its files at start-up.

**gitleaks.** In `config/gitleaks.release`, change `VERSION` and replace the four SHA-256 values
with those in the release's `gitleaks_<version>_checksums.txt`. Then run the commands above.

## Change or add a rule

Edit the files in the repository. Five lists exist once per agent, and `./tests/run.sh` fails
when the two copies differ:

| List | Claude Code (`claude/managed-settings.d/10-agent-security.json`) | Codex |
|---|---|---|
| Credential locations | `Read(...)` rules | `deny_read` in `codex/requirements.toml` |
| Secret variables | `sandbox.credentials.envVars` | Names containing `KEY`, `SECRET` or `TOKEN`, plus `shell_environment_policy.exclude` in `codex/config.toml` |
| Environment-file patterns outside the project | `sandbox.filesystem.denyRead` | `"deny"` entries in `[permissions.agent-security.filesystem]` in `codex/requirements.toml` |
| Package-manager caches | `sandbox.filesystem.allowWrite` | `"write"` entries in `[permissions.agent-security.filesystem]` in `codex/requirements.toml` |
| Allowed hosts | `sandbox.network.allowedDomains` | `[experimental_network.domains]` in `codex/requirements.toml` |

Then run `sudo ./install.sh install` and `./verify.sh`. Managed Codex hooks are trusted by policy
and need no approval.

The complete Codex permission profile is defined in `requirements.toml`. Keep it out of user
and project `config.toml` files: Codex rejects another definition with the same name. When
upgrading from the earlier layout, remove any personal `[permissions.agent-security]` sections;
the installer replaces the old system definition in `/etc/codex/config.toml` automatically.

## Allow another host

The allowlist holds code-hosting and package-registry hosts. Users can add hosts for their own
sessions; the managed hosts and the rest of the policy stay in place:

- **Claude Code:** approve the host when Claude Code asks ("Yes, and don't ask again" keeps it),
  or add it to `sandbox.network.allowedDomains` in `~/.claude/settings.json`.
- **Codex:** Codex refuses the host without asking. Add a rule to a file in `~/.codex/rules/`,
  for example `~/.codex/rules/hosts.rules`, and restart Codex:

  ```python
  network_rule(host="<host>", protocol="https", decision="allow")
  ```

`*.example.com` matches subdomains only. Tools that ignore `HTTPS_PROXY` (plain `ssh`, most
database drivers) cannot reach any host. For an organization, add the host to both lists in the
repository (see above).

To maintain a customized distribution, fork the repository, keep `./tests/run.sh` passing and
change what is needed: credential paths, additional Claude Code settings (any `*.json` added to
`claude/managed-settings.d/` is installed), or a mirror for the gitleaks download.

## Handle a false positive

A false positive blocks a prompt or a tool call. In a tool result, Claude Code shows
`[REDACTED]` in place of the value, and Codex replaces the whole result with the scanner's
message.

- **Preferred:** keep the value out of the prompt, the code and the files the agent reads.
  Reference it through an environment variable or a secret manager.
- **When a value must be allowed:** add an allowlist to `config/gitleaks.toml` (see the
  [gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration)), open a pull
  request and reinstall.
- Inline `gitleaks:allow` comments and a repository's own `.gitleaks.toml` or `.gitleaksignore`
  are not honored.

## Deploy to many machines

`install.sh` is idempotent and non-interactive, so a configuration-management tool can run
`sudo ./install.sh install`. To produce files for a package or a configuration-management tool,
stage them:

```sh
DESTDIR=/tmp/agent-security-stage ./install.sh install    # no root, no change to the system
```

The staged tree has the final layout (`/opt/agent-security`, `/etc/claude-code`, `/etc/codex`) and
every file is a copy of a repository file. Staging skips the dependency checks and the self-test
and does not probe the target machine, so it adds the Claude Code socket overlay only when
`UNIX_SOCKET_OVERLAY=yes` is set (see [below](#ubuntu-2404-and-apparmor)). Run `./verify.sh` on a
real machine after deployment.

Without internet access, set `GITLEAKS_MIRROR` to an internal server hosting
`v<version>/gitleaks_<version>_<platform>.tar.gz` (the pinned SHA-256 still applies), or set
`GITLEAKS_BIN` to a binary of the pinned version:
`sudo GITLEAKS_BIN=/path/to/gitleaks ./install.sh install`.

If `/etc/codex/config.toml` or `requirements.toml` already exists and does not start with
`# Managed by agent-security.`, the installer stops without changing anything. Merge the
repository's `codex/*.toml` into those files, or remove them if they are not needed.

## Verification

`./verify.sh` runs as the user, from a regular terminal. Agent sandboxes cannot be nested, so it
refuses to run inside one. `--live` adds the checks that start real agent sessions and use a
little quota.

| Group | Checks |
|---|---|
| Installation | `install.sh status`: every file is present and owned by root |
| Scanner | The installed scanner accepts a harmless prompt over a socket and detects a synthetic credential; scanner errors do not count as detection |
| Sandbox probe (`tests/probe.py`, in the Codex sandbox; with `--live`, also in Claude Code) | Each of these is reported `blocked`: `.env` and `.envrc` in the project, `.env` three directories deep, `.env` and `.envrc` in another repository in the home directory and in `/tmp` (Codex: home only, see [controls](controls.md#2-credential-locations-read-denied)), a credential directory, a write outside the project, a secret environment variable, a Unix socket, a direct network connection, an HTTPS request to a host outside the allowlist (`example.com`), a stored git credential for `github.com`, a file created in `.git/hooks`, `.git/config` opened for writing. An HTTPS request to an allowed host (`pypi.org`), a commit in the test project and a file created in a package-manager cache (the first of `~/.npm`, `~/.cache/pip`, `~/.m2/repository`, `~/.cargo/registry`, `~/go/pkg/mod` that exists) are reported `reachable`. A probe is reported `n/a` when its target is absent: `~/.ssh`, the session bus, a host the user's own terminal cannot reach, a git credential helper, or a package-manager cache |
| Codex policy (`codex doctor --json`) | The managed policy is loaded from `/etc/codex`; the filesystem sandbox is restricted; no deny-rule warnings; a user cannot redefine the managed permission profile; a user cannot select the full-access or read-only profile; a user cannot disable the managed hooks; the network proxy is configured and a user cannot turn it off; the approval policy rejects sandbox escalation and a user cannot turn it back on |
| Live sessions (`--live`) | A prompt containing a credential is blocked in Claude Code and in Codex; a credential in a file the agent prints does not reach the model (Claude Code shows `[REDACTED]`, Codex withholds the result); Claude Code's bypass mode is disabled; neither agent can create an entry in `~/.config/autostart`; in Codex, a host allowed in a rules file of the user's (`example.com`, removed afterwards) is reachable |

## Every Claude Code prompt is blocked with a stdin error

`/dev/stdin: No such device or address` followed by `the hook event is empty or malformed`
means the scanner failed to read the event, before checking for credentials. Claude Code can
deliver hook input over a Unix socket; reopening `/dev/stdin` fails for sockets on Linux.
The scanner must read the inherited stdin descriptor directly. Update and reinstall with the
commands under [Update](#update), then restart Claude Code and run `./verify.sh --live`.
The socket check in `./verify.sh` also catches this without starting an agent.

## Ubuntu 24.04+ and AppArmor

Claude Code's sandbox runs commands under bubblewrap, which needs unprivileged user namespaces.
From Ubuntu 24.04, AppArmor restricts them (`kernel.apparmor_restrict_unprivileged_userns = 1`).
The result depends on the system:

| Situation | Effect | Installer action |
|---|---|---|
| Restriction off (`0`, or no such sysctl) | Everything works, including Claude Code's seccomp socket filter | Base policy only |
| Restriction on, Ubuntu's `bwrap-userns-restrict` profile present (validated on 26.04) | bubblewrap starts, but its children lose capabilities, so Claude Code's seccomp helper cannot create a nested user namespace: `apply-seccomp: write /proc/self/setgroups … caller must provide CAP_SYS_ADMIN` | Installs the socket overlay |
| Restriction on, no profile for bubblewrap (stock 24.04) | bubblewrap cannot create a sandbox | Stops with a message. Add the profile below, then run the installer again |

The installer decides by running the real operations as the user who invoked `sudo`. They can be
run by hand:

```sh
# 1. can bubblewrap create a sandbox?
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net true
# 2. can a user namespace be created inside it? (what Claude Code's seccomp helper does)
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net \
  -- unshare --user --map-root-user true
```

Probe 1 failing means the profile below is needed. Probe 2 failing means the overlay is used.
`UNIX_SOCKET_OVERLAY=yes|no` overrides the decision.

**Profile for stock Ubuntu 24.04**, from the
[Claude Code sandboxing documentation](https://code.claude.com/docs/en/sandboxing) (vendor
documentation; not validated in this repository). Do not add it where
`/etc/apparmor.d/bwrap-userns-restrict` exists: both profiles would attach to `/usr/bin/bwrap`
under the same name.

```text
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
```

Save it as `/etc/apparmor.d/bwrap` and run `sudo systemctl reload apparmor`. With it, bubblewrap's
children keep their capabilities, probe 2 passes and the overlay is not needed.
