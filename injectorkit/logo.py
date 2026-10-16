"""The banner shown before a run.

The lettering is a standard ASCII-art rendering of the name - figlet's "small"
face. It is kept as finished art rather than generated from a dot grid: these
shapes lean on diagonal strokes and underscores that a grid cannot draw, and the
name is not going to change.

Nothing here is required for a scan to work. It is the front door, and it is
skipped whenever nobody is standing at it.
"""

from __future__ import annotations

from typing import Callable

# Kept under eighty columns so it does not wrap in an ordinary terminal, and
# free of anything but printable ASCII so it survives any font.
ART = r"""
.__              __                   __                    __    .__   __
|__|  ____      |__|  ____    ____  _/  |_   ____  _______ |  | __|__|_/  |_
|  | /    \     |  |_/ __ \ _/ ___\ \   __\ /  _ \ \_  __ \|  |/ /|  |\   __\
|  ||   |  \    |  |\  ___/ \  \___  |  |  (  <_> ) |  | \/|    < |  | |  |
|__||___|  //\__|  | \___  > \___  > |__|   \____/  |__|   |__|_ \|__| |__|
         \/ \______|     \/      \/                             \/
"""

TAGLINE = "web exploitation across several vulnerability classes"
PROJECT = "github.com/guaidao2/injectorkit"
AUTHORS = "coolmoon and guaidao2"


def rows() -> list[str]:
    """The art as rows, with trailing whitespace trimmed."""
    return [line.rstrip() for line in ART.strip("\n").split("\n")]


def width() -> int:
    return max(len(row) for row in rows())


def banner(version: str, paint: Callable[[str, str], str] | None = None) -> str:
    """The whole front matter: name, tagline, version, project and authors.

    `paint` is the run's own colour function, so the banner looks like the rest
    of the output rather than like something bolted on. Without one it is plain
    text, which is what a caller that wants no colour gets.
    """
    style_is = paint if paint is not None else (lambda text, _name: text)
    span = width()

    out = [style_is(row, "title") for row in rows()]
    out.append("")

    gap = max(span - len(TAGLINE) - len(version), 1)
    out.append(style_is(TAGLINE, "muted") + " " * gap + style_is(version, "likely"))
    gap = max(span - len(PROJECT) - len(AUTHORS), 1)
    out.append(style_is(PROJECT, "muted") + " " * gap + style_is(AUTHORS, "muted"))
    return "\n".join(out)
