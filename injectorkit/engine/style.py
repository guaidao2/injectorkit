"""Terminal colour: where it helps, and nowhere it would hurt.

A run's output is data first and presentation second. Colour is for the person
watching a scan in a terminal, so it is applied only when something is actually
watching one - off when the output is a pipe, a file or a test, off when NO_COLOR
is set, and always overridable from the command line.

Nothing here changes what a line says. The prefixes already carry the meaning
(`[!]` proved, `[+]` executed, `[>]` next), and the colour only repeats it for
the eye. Strip the escape sequences and the output is exactly what it was.
"""

from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

# Style names the engine can ask for by meaning rather than by colour.
STYLES: dict[str, str] = {
    "title": BOLD + CYAN,
    "muted": DIM,
    "finding": GREEN,
    "execute": BOLD + GREEN,
    "next": CYAN,
    "filter": YELLOW,
    "closed": DIM,
    "covered": DIM,
    "result": BOLD,
    "target": BOLD,
    "error": RED,
    "refused": YELLOW,
    "section": BOLD + BLUE,
    "confirmed": GREEN,
    "likely": YELLOW,
    "inconclusive": DIM,
}

# How a line is coloured when the caller did not say. The prefixes are part of
# the output contract, so they are a reliable thing to read - matched after the
# leading indent, since findings and the board are both indented.
PREFIX_STYLES: tuple[tuple[str, str], ...] = (
    ("[+]", "execute"),
    ("[!]", "finding"),
    ("[>]", "next"),
    ("filter:", "filter"),
    ("result:", "result"),
    ("target:", "target"),
    ("closed paths:", "section"),
    ("not covered:", "section"),
)

# Words that mean something wherever they appear in a line. A board line gets
# no colour of its own, so these are what the eye lands on there.
INLINE_STYLES: tuple[tuple[str, str], ...] = (
    ("[confirmed]", "confirmed"),
    ("[likely]", "likely"),
    ("[inconclusive]", "inconclusive"),
)


def _enable_windows_console() -> None:
    """Ask a Windows console to interpret escape sequences.

    A terminal that already understands ANSI needs nothing; the older console
    host does not, and asking is a no-op where it is already on. A failure here
    is not an error - without it the output is plain, which is what it would have
    been anyway.
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT |
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:  # noqa: BLE001 - presentation must never break a run
        pass


def enabled(mode: str = "auto", stream=None) -> bool:
    """Whether to emit escape sequences.

    Colour is the default, because this output is read by a person: on a terminal
    it is coloured, and when the stream is a pipe or a file - where nobody is
    looking and something may be parsing - it is not.

    `always` is a person asking, and wins outright. `never` turns it off. In
    between, a session that set NO_COLOR gets plain output: that convention
    exists for terminals and collectors that cannot use colour, and honouring it
    costs the default case nothing.
    """
    if mode == "never":
        return False
    if mode == "always":
        _enable_windows_console()
        return True
    if os.environ.get("NO_COLOR"):
        return False

    handle = stream if stream is not None else sys.stdout
    try:
        watching = bool(handle.isatty())
    except (AttributeError, ValueError):
        watching = False
    if watching:
        _enable_windows_console()
    return watching


def paint(text: str, style: str | None, enabled_now: bool) -> str:
    """Wrap text in one style, or return it untouched."""
    if not enabled_now or not style:
        return text
    code = STYLES.get(style, "")
    if not code:
        return text
    return f"{code}{text}{RESET}"


def style_line(line: str, enabled_now: bool) -> str:
    """Colour one line of output by what it says.

    A line with a meaning of its own - a finding, a result, a refusal - is
    coloured whole. Anything else is left alone except for the few words worth
    picking out, which is what keeps the board readable: the confidence marker
    is the part that matters there, not the line around it.
    """
    if not enabled_now or not line:
        return line

    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]

    for prefix, name in PREFIX_STYLES:
        if stripped.startswith(prefix):
            return indent + paint(stripped, name, True)

    for word, name in INLINE_STYLES:
        if word in line:
            code = STYLES.get(name, "")
            if code:
                line = line.replace(word, f"{code}{word}{RESET}")
    return line
