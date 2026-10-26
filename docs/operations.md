# Operations

## Update

```sh
git pull
./tests/run.sh
sudo ./install.sh install    # idempotent: replaces the installed files
./verify.sh
```

Claude Code reloads managed settings when they change; restart sessions to be sure. Codex reads
its files at start-up.

**gitleaks:** in `config/gitleaks.release`, change `VERSION` and replace the four SHA-256 values
with the ones in the release's `gitleaks_<version>_checksums.txt`; then run the three commands above.

## Change or add a rule

Edit the files in the repository. The credential list exists once per tool (`Read(...)` rules in
`claude/managed-settings.d/10-agent-security.json`, `deny_read` in `codex/requirements.toml`);
`./tests/run.sh` fails if they differ. Then `sudo ./install.sh install` and `./verify.sh`. Managed
Codex hooks are trusted by policy, so nothing has to be re-approved.

To customize for a company, fork the repository, keep `./tests/run.sh` green, and change what you
need: credential paths, extra Claude Code settings (any `*.json` added to
`claude/managed-settings.d/` is installed), or a mirror for the gitleaks download.

## Handle a false positive

- **Preferred:** do not put the value in the prompt or the code; reference it through an
  environment variable or a secret manager.
- **If a value must be allowed:** add an allowlist to `config/gitleaks.toml` (see the
  [gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration)), open a pull
  request, and reinstall.
- These bypasses are disabled on purpose: inline `gitleaks:allow` comments, and a repository's
  own `.gitleaks.toml` or `.gitleaksignore`.

## Deploy to many machines

`install.sh` is idempotent and non-interactive, so a configuration tool can run
`sudo ./install.sh install`. To produce files for a package or a configuration-management tool
instead, stage them:

```sh
DESTDIR=/tmp/agent-security-stage ./install.sh install    # no root, no change to the system
```

The staged tree has the final layout (`/opt/agent-security`, `/etc/claude-code`, `/etc/codex`) and
every file is a copy of one in the repository. Staging skips the dependency checks and the
self-test and cannot probe the target machine, so it never adds the Claude Code socket overlay on
its own: pass `UNIX_SOCKET_OVERLAY=yes` for machines that need it (see
[below](#ubuntu-2404-and-apparmor)). Run `./verify.sh` on a real machine after deployment.

Without internet access, set `GITLEAKS_MIRROR` to an internal server hosting
`v<version>/gitleaks_<version>_<platform>.tar.gz` (the pinned SHA-256 still applies), or set
`GITLEAKS_BIN` to a binary of the pinned version, for example
`sudo GITLEAKS_BIN=/path/to/gitleaks ./install.sh install`.

If `/etc/codex/config.toml` or `requirements.toml` already exists and does not start with
`# Managed by agent-security.`, the installer stops without changing anything: merge the
repository's `codex/*.toml` into your files by hand, or remove yours if it is not needed.

## Ubuntu 24.04+ and AppArmor

Claude Code's sandbox runs commands under bubblewrap, which needs unprivileged user namespaces.
From Ubuntu 24.04, AppArmor restricts them (`kernel.apparmor_restrict_unprivileged_userns = 1`).
What happens next depends on the system:

| Situation | Effect | What the installer does |
|---|---|---|
| Restriction off (`0`, or no such sysctl) | Everything works, including Claude Code's seccomp socket filter | Base policy only |
| Restriction on, Ubuntu's `bwrap-userns-restrict` profile present (confirmed on 26.04) | bubblewrap starts, but its children lose capabilities, so Claude Code's seccomp helper cannot create a nested user namespace: `apply-seccomp: write /proc/self/setgroups … caller must provide CAP_SYS_ADMIN` | Installs the socket overlay |
| Restriction on, no profile for bubblewrap (stock 24.04) | bubblewrap cannot create a sandbox at all | Stops and says so. Add the profile below, then run the installer again |

The installer decides by trying the real operations as the user who ran `sudo`. You can run them:

```sh
# 1. can bubblewrap create a sandbox?
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net true
# 2. can a user namespace be created inside it? (what Claude Code's seccomp helper does)
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net \
  -- unshare --user --map-root-user true
```

Probe 1 failing means the profile below is needed; probe 2 failing means the overlay is used.
`UNIX_SOCKET_OVERLAY=yes|no` overrides the decision.

**Profile for stock Ubuntu 24.04**, from the
[Claude Code sandboxing documentation](https://code.claude.com/docs/en/sandboxing) (not tested
here). Do not add it where `/etc/apparmor.d/bwrap-userns-restrict` exists: both profiles would
attach to `/usr/bin/bwrap` under the same name.

```text
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
```

Save it as `/etc/apparmor.d/bwrap` and run `sudo systemctl reload apparmor`. With it, bubblewrap's
children keep their capabilities, probe 2 passes, and the overlay is not needed.

A Codex sandbox cannot start inside a Claude Code sandbox (nested user namespaces are exactly what
is blocked), so run `./verify.sh` from a normal terminal.
