"""Small stdlib-only hook client. Command text travels locally, never to HTTP."""

import json
import socket
import sys


def main():
    command = sys.stdin.buffer.read(65537)
    if len(command) > 65536:
        print("AIS: command too large to observe", file=sys.stderr)
        return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(sys.argv[1])
            client.sendall(
                json.dumps({"command": command.decode("utf-8")}).encode() + b"\n"
            )
            if client.recv(32) != b"ok\n":
                raise ValueError("Collector rejected observation")
    except (OSError, ValueError, UnicodeError):
        print("AIS: shell observation unavailable; check monitor", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
