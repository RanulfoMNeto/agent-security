#!/usr/bin/env python3
"""Try the things an agent's shell must or must not be able to do. Used by verify.sh.

Run it inside an agent's sandbox, in a directory that contains `.env` and `a/b/c/.env`. It
prints one `name=state` line per probe, where state is `blocked`, `reachable` or `n/a` (nothing
to test on this machine). Every probe must report `blocked`, except `allowed_host`: a host on
the policy's network allowlist must be `reachable`.

    probe.py [--credential-dir PATH] [--socket PATH] [--network HOST:PORT]
             [--allowed-url URL] [--other-url URL] [--git-credential HOST]
"""

import argparse
import os
import socket
import subprocess
import urllib.error
import urllib.request


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


def fetch(url):
    """HTTPS through the proxy the sandbox sets in HTTPS_PROXY, as package managers do. Any
    HTTP response, an error status included, means the host was reached."""
    def action():
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=10).close()
        except urllib.error.HTTPError:
            pass
    return action


def git_credential(host):
    """Ask git for the stored HTTPS credential of HOST, as `git push` would, without prompting."""
    def action():
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false", SSH_ASKPASS="/bin/false")
        result = subprocess.run(["git", "credential", "fill"], input=f"protocol=https\nhost={host}\n\n",
                                capture_output=True, text=True, timeout=10, env=env)
        if "password=" not in result.stdout:
            raise PermissionError
    return action


parser = argparse.ArgumentParser()
parser.add_argument("--credential-dir")
parser.add_argument("--socket")
parser.add_argument("--network")
parser.add_argument("--allowed-url")
parser.add_argument("--other-url")
parser.add_argument("--git-credential")
args = parser.parse_args()

results = {
    "env_file": attempt(read(".env")),
    "nested_env_file": attempt(read("a/b/c/.env")),
    "credential_dir": attempt(lambda: os.listdir(args.credential_dir) or (_ for _ in ()).throw(PermissionError())) if args.credential_dir else "n/a",
    "write_outside": attempt(write_outside),
    "secret_env": "reachable" if any(os.environ.get(name) for name in ("GITHUB_TOKEN", "OPENAI_API_KEY", "TWINE_PASSWORD")) else "blocked",
    "unix_socket": attempt(connect(args.socket)) if args.socket else "n/a",
    "network": attempt(reach(args.network)) if args.network else "n/a",
    "other_host": attempt(fetch(args.other_url)) if args.other_url else "n/a",
    "git_credential": attempt(git_credential(args.git_credential)) if args.git_credential else "n/a",
    "allowed_host": attempt(fetch(args.allowed_url)) if args.allowed_url else "n/a",
}
for name, state in results.items():
    print(f"{name}={state}")
