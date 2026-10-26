#!/usr/bin/env python3
"""Try the things an agent's shell must not be able to do. Used by verify.sh.

Run it inside an agent's sandbox, in a directory that contains `.env` and `a/b/c/.env`. It
prints one `name=state` line per probe, where state is `blocked` (the policy is enforced),
`reachable` (the policy is not enforced) or `n/a` (nothing to test on this machine).

    probe.py [--credential-dir PATH] [--socket PATH] [--network HOST:PORT]
"""

import argparse
import os
import socket


def attempt(action):
    try:
        action()
    except (OSError, PermissionError):
        return "blocked"
    return "reachable"


def read(path):
    return lambda: open(path).read()


def write_outside():
    path = os.path.expanduser(f"~/agent-security-probe-{os.getpid()}")
    with open(path, "w") as handle:
        handle.write("probe")
    os.remove(path)


def connect(path):
    def action():
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(path)
    return action


def reach(address):
    host, port = address.rsplit(":", 1)
    return lambda: socket.create_connection((host, int(port)), timeout=5).close()


parser = argparse.ArgumentParser()
parser.add_argument("--credential-dir")
parser.add_argument("--socket")
parser.add_argument("--network")
args = parser.parse_args()

results = {
    "env_file": attempt(read(".env")),
    "nested_env_file": attempt(read("a/b/c/.env")),
    "credential_dir": attempt(lambda: os.listdir(args.credential_dir) or (_ for _ in ()).throw(PermissionError())) if args.credential_dir else "n/a",
    "write_outside": attempt(write_outside),
    "secret_env": "reachable" if os.environ.get("GITHUB_TOKEN") or os.environ.get("OPENAI_API_KEY") else "blocked",
    "unix_socket": attempt(connect(args.socket)) if args.socket else "n/a",
    "network": attempt(reach(args.network)) if args.network else "n/a",
}
for name, state in results.items():
    print(f"{name}={state}")
