"""An interactive shell over whatever a module can execute.

    os-shell> id
    uid=0(root) gid=0(root)

A module supplies one thing: given a command, return its output. Everything else
- the prompt, reading a line, printing what came back, deciding what ends the
session - is identical whichever vulnerability is underneath, so it lives here.

That is also what makes the shells interchangeable to use. A filter chain that
manufactures its payload inside a stream, and a shell written to disk through
Redis, are the same thing from this file's point of view: a function that takes a
command and returns text.
"""

from __future__ import annotations

import sys

EXIT_WORDS = frozenset({"exit", "quit", "q", ":q", "bye"})

BANNER = "type a command, or 'exit' to leave"


def run(execute, prompt: str = "os-shell> ", banner: str = "") -> int:
    """Read commands until the operator leaves.

    Input is read line by line, so a pipe works as well as a terminal:
    `printf 'id\\nexit\\n' | injectorkit.py ...` is a scripted session. A command
    that fails does not end the session - on a real target the failure is usually
    the interesting part.
    """
    if banner:
        print(banner)
    print(BANNER)

    while True:
        try:
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        command = line.strip()
        if not command:
            continue
        if command in EXIT_WORDS:
            return 0
        if command in ("help", "?"):
            print("  any shell command on the target; 'exit' leaves the session")
            continue

        try:
            output = execute(command)
        except Exception as failure:  # noqa: BLE001 - a failed command is not a failed session
            print(f"  execution failed: {failure}", file=sys.stderr)
            continue

        if output.strip():
            print(output.rstrip("\n"))
        else:
            print("  (no output)")


def run_once(execute, command: str, output=None) -> int:
    """One command, for scripting: no prompt, no loop.

    The text goes out exactly as it came back - this is the mode something else
    reads - except when there is none, where saying so is more useful than an
    empty line.
    """
    text = execute(command)
    if output is not None:
        output.write(text)
        if not text.endswith("\n"):
            output.write("\n")
        return 0
    print(text.rstrip("\n") or "(the command produced no output)")
    return 0
