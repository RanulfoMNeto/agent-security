#!/usr/bin/env python3
"""Check that the policy files are valid and agree with each other.

The credential locations, the secret environment variables and the allowed network hosts are
written twice, in each tool's own format. This test keeps the two copies from drifting apart.
"""

import fnmatch
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = "/opt/agent-security/bin/agent-secret-scan"
errors = []


def load(path):
    loader = json.loads if path.suffix == ".json" else tomllib.loads
    try:
        return loader(path.read_text())
    except ValueError as exc:  # JSONDecodeError and TOMLDecodeError are both ValueErrors
        errors.append(f"{path.relative_to(ROOT)}: invalid syntax: {exc}")
        return {}


for pattern in ("claude/**/*.json", "codex/*.toml", "config/*.toml"):
    for path in ROOT.glob(pattern):
        load(path)

claude = load(ROOT / "claude/managed-settings.d/10-agent-security.json")
requirements = load(ROOT / "codex/requirements.toml")

# Spell both lists the same way: "~/x" for a location. Environment files are handled apart:
# Codex only applies their globs from the profile in config.toml, not from requirements.toml.
ENV_FILES = {"**/.env", "**/.env.*"}
claude_reads = set()
for rule in claude.get("permissions", {}).get("deny", []):
    match = re.fullmatch(r"Read\((.*)\)", rule)
    if match:
        path = match.group(1).removesuffix("/**")
        claude_reads.add(path[2:] if path.startswith("//") else path)
codex_denies = set(requirements.get("permissions", {}).get("filesystem", {}).get("deny_read", []))
codex_config = load(ROOT / "codex/config.toml")
profile = codex_config.get("permissions", {}).get("agent-security", {})
codex_env_files = {k for k, v in profile.get("filesystem", {}).get(":workspace_roots", {}).items() if v == "deny"}
sandbox_env_files = {e["path"] for e in claude.get("sandbox", {}).get("credentials", {}).get("files", [])}

for path in sorted(claude_reads - ENV_FILES - codex_denies):
    errors.append(f"{path}: denied for Claude Code but not for Codex")
for path in sorted(codex_denies - claude_reads):
    errors.append(f"{path}: denied for Codex but not for Claude Code")
if not ENV_FILES <= claude_reads:
    errors.append("Claude Code must deny reading **/.env and **/.env.*")
if codex_env_files != ENV_FILES:
    errors.append(f"codex/config.toml must deny exactly {sorted(ENV_FILES)} under :workspace_roots, found {sorted(codex_env_files)}")
if sandbox_env_files != ENV_FILES:
    errors.append(f"Claude's sandbox credentials must list exactly {sorted(ENV_FILES)}, found {sorted(sandbox_env_files)}")

# Opening .git in Codex must keep config and hooks read-only, as Claude Code's sandbox does.
roots = profile.get("filesystem", {}).get(":workspace_roots", {})
if roots.get(".git") == "write" and not roots.get(".git/config") == roots.get(".git/hooks") == "read":
    errors.append("codex/config.toml opens .git, so .git/config and .git/hooks must be read")

# Claude Code removes secret variables by exact name. Codex removes names that contain KEY,
# SECRET or TOKEN (any case) plus its `exclude` patterns; together they must cover Claude's list.
env_policy = codex_config.get("shell_environment_policy", {})
if env_policy.get("ignore_default_excludes") is not False:
    errors.append("codex/config.toml must set shell_environment_policy.ignore_default_excludes = false")
for entry in claude.get("sandbox", {}).get("credentials", {}).get("envVars", []):
    name = entry["name"]
    if not re.search("KEY|SECRET|TOKEN", name, re.IGNORECASE) and not any(
            fnmatch.fnmatchcase(name.upper(), pattern.upper()) for pattern in env_policy.get("exclude", [])):
        errors.append(f"{name}: removed for Claude Code but not for Codex")

# The network allowlist is also written once per agent, with the same host patterns. In Codex,
# only the proxy applies it: a profile with the network on and no proxy reaches every host.
claude_hosts = claude.get("sandbox", {}).get("network", {}).get("allowedDomains", [])
codex_network = profile.get("network", {})
codex_hosts = [host for host, rule in codex_network.get("domains", {}).items() if rule == "allow"]
if not claude_hosts or sorted(claude_hosts) != sorted(codex_hosts):
    errors.append("the allowed hosts must be the same for Claude Code and Codex")
if codex_network.get("enabled") and requirements.get("features", {}).get("network_proxy") is not True:
    errors.append("the Codex profile turns the network on, so requirements.toml must pin features.network_proxy")

# Both agents call the same scanner, and Claude Code must block when the hook cannot run.
hooks = [h for groups in claude.get("hooks", {}).values() for g in groups for h in g["hooks"]]
codex_hooks = [h for groups in requirements.get("hooks", {}).values() if isinstance(groups, list) for g in groups for h in g["hooks"]]
if not hooks or not codex_hooks:
    errors.append("both agents need their hooks defined")
for hook in hooks + codex_hooks:
    if hook["command"] != SCANNER:
        errors.append(f"hook command must be {SCANNER}, found {hook['command']}")
for hook in hooks:
    if hook.get("onFailure") != "block":
        errors.append("every Claude Code hook must set onFailure to block")

# Both agents scan prompts, tool calls and tool results. Claude Code's tool results go through
# the scanner's redact mode; every other hook runs in block mode, without arguments.
EVENTS = {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
codex_events = {e for e, groups in requirements.get("hooks", {}).items() if isinstance(groups, list)}
if set(claude.get("hooks", {})) != EVENTS or codex_events != EVENTS:
    errors.append(f"both agents must hook exactly {sorted(EVENTS)}")
for event, groups in claude.get("hooks", {}).items():
    expected = ["--redact"] if event == "PostToolUse" else []
    if any(h.get("args") != expected for g in groups for h in g["hooks"]):
        errors.append(f"Claude Code's {event} hook must have args {expected}")

# install.sh refuses to overwrite a Codex file that does not start with this line.
for path in (ROOT / "codex").glob("*.toml"):
    if not path.read_text().startswith("# Managed by agent-security."):
        errors.append(f"{path.relative_to(ROOT)} must start with '# Managed by agent-security.'")

# The pinned release must have a hash for every platform install.sh supports.
release = (ROOT / "config/gitleaks.release").read_text()
for name in ("linux_x64", "linux_arm64", "darwin_x64", "darwin_arm64"):
    if not re.search(rf"^SHA256_{name}=[0-9a-f]{{64}}$", release, re.MULTILINE):
        errors.append(f"config/gitleaks.release has no valid SHA256_{name}")

if errors:
    print("consistency: FAILED")
    print("\n".join(f"  - {e}" for e in errors))
    sys.exit(1)
print("consistency: ok")
