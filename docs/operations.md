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

Edit the files in the repository. The credential list exists once per agent: the `Read(...)` rules
in `claude/managed-settings.d/10-agent-security.json` and `deny_read` in `codex/requirements.toml`.
`./tests/run.sh` fails when they differ. Then run `sudo ./install.sh install` and `./verify.sh`.
Managed Codex hooks are trusted by policy and need no approval.

To maintain a customized distribution, fork the repository, keep `./tests/run.sh` passing and
change what is needed: credential paths, additional Claude Code settings (any `*.json` added to
`claude/managed-settings.d/` is installed), or a mirror for the gitleaks download.

## Handle a false positive

- **Preferred:** keep the value out of the prompt and the code. Reference it through an
  environment variable or a secret manager.
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
| Scanner | The installed scanner blocks a synthetic credential |
| Sandbox probe (`tests/probe.py`, in the Codex sandbox; with `--live`, also in Claude Code) | Each of these is reported `blocked`: `.env` in the project, `.env` three directories deep, a credential directory, a write outside the project, a secret environment variable, a Unix socket, a direct network connection. A probe is reported `n/a` when its target is absent: `~/.ssh`, the session bus, or a connection to `example.com:443` that succeeds from the user's own terminal |
| Codex policy (`codex doctor --json`) | The managed policy is loaded from `/etc/codex`; the filesystem sandbox is restricted; no deny-rule warnings; a user setting that re-opens `~/.ssh` is refused; a user cannot select the full-access profile; a user cannot disable the managed hooks |
| Live sessions (`--live`) | A prompt containing a credential is blocked in Claude Code and in Codex; Claude Code's bypass mode is disabled |

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
