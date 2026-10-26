#!/usr/bin/env python3
"""Check that the policy files are valid and agree with each other.

The credential locations are written twice, in each tool's own format: Claude Code's `Read(...)`
deny rules and Codex's `deny_read`. This test keeps the two lists from drifting apart.
"""

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
profile = load(ROOT / "codex/config.toml").get("permissions", {}).get("agent-security", {}).get("filesystem", {})
codex_env_files = {k for k, v in profile.get(":workspace_roots", {}).items() if v == "deny"}
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
