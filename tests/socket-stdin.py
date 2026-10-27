#!/usr/bin/env python3
"""Run a command with stdin delivered over a Unix socket, as in a Claude Code hook."""

import socket
import subprocess
import sys


reader, writer = socket.socketpair()
with reader, writer:
    with subprocess.Popen(sys.argv[1:], stdin=reader) as process:
        reader.close()
        try:
            writer.sendall(sys.stdin.buffer.read())
            writer.shutdown(socket.SHUT_WR)
        except BrokenPipeError:
            pass  # A command that rejects the input may close stdin early.
        writer.close()
        try:
            sys.exit(process.wait(timeout=30))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            sys.exit("socket-stdin: command timed out")
