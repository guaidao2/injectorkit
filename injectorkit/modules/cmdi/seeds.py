"""What a command runner can be asked, and how the value gets in.

A seed here is not a payload. It is a *question* - one command that prints two
markers with a computed number between them - plus the set of ways that command
can be delivered into the parameter. Both halves are derived rather than listed:

  * The question is derived from what proves execution. A shell that ran prints
    the sum; a page that echoed the payload prints the expression. So the seed is
    built from an `Arithmetic`, and every shell has to be able to print a literal
    and print a sum. Those two capabilities are the whole language requirement.

  * The delivery is derived from how the value gets into the command line. If the
    parameter *is* the command there is nothing to escape; if it is appended to a
    command the application already chose, the value has to end that command
    first. Ending it can be done with any of the shell's separators, or by
    putting the payload inside a substitution where it runs during argument
    expansion.

That is why there is no payload table. The space is the product of a shell's two
printing forms and the ways a command can be started, and it is small enough to
write down and reason about.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ...engine.arithmetic import Arithmetic


@dataclass(frozen=True)
class Shell:
    """A command language, reduced to what a proof and its rewrites need.

    Not the whole language. Two printing forms, because that is all the question
    asks for, and the set of rewrite families the dialect can actually run -
    because a rewrite that is valid in one shell and not another has to be gated
    on which shell the target turned out to be, or the tool either misses a
    bypass on the shell that supports it or wastes requests on the one that does
    not.
    """

    name: str
    literal: Callable[[str], str]
    total: Callable[[int, int], str]
    join: str
    # Mutator families this dialect cannot run. Absent means it runs everything.
    cannot: tuple[str, ...] = ()
    note: str = ""

    def allows(self, family: str) -> bool:
        return family not in self.cannot


POSIX = Shell(
    name="posix",
    literal=lambda text: f"echo {text}",
    total=lambda left, right: f"echo $(({left}+{right}))",
    join="; ",
    # `/bin/sh` is dash on Debian and Ubuntu. Dash does not expand braces, so a
    # payload written `{echo,IKCLOSE}` comes out as that literal word and the
    # shell answers `not found`. That is a fact about the dialect, not about
    # brace expansion - see BASH below, where the same rewrite works.
    cannot=("cmd-brace",),
    note="sh and every shell that follows POSIX, which on Linux is usually dash",
)

BASH = Shell(
    name="bash",
    literal=lambda text: f"echo {text}",
    total=lambda left, right: f"echo $(({left}+{right}))",
    join="; ",
    note="bash, which is what an application means when it names the shell itself",
)

CMD = Shell(
    name="cmd",
    literal=lambda text: f"echo {text}",
    # `set /a` prints the result itself, so wrapping it in `echo` would print the
    # expression - which is exactly the thing the proof exists to tell apart.
    total=lambda left, right: f"set /a {left}+{right}",
    join=" & ",
    # The POSIX rewrites are about expansion and word splitting as a POSIX shell
    # does them; cmd does neither, so they would be requests spent proving
    # nothing.
    cannot=("cmd-space", "cmd-brace", "cmd-compute", "cmd-name", "cmd-path"),
    note="the Windows command interpreter",
)

POWERSHELL = Shell(
    name="powershell",
    literal=lambda text: f"Write-Output {text}",
    # Parenthesised, because in PowerShell `$((2+3))` is a subexpression with a
    # stray backslash in front rather than arithmetic: measured on pwsh 7, the
    # POSIX spelling prints `\5` where the proof wants `5`. Same question,
    # different language, and the seed has to be written in the one being asked.
    total=lambda left, right: f"Write-Output ({left}+{right})",
    join="; ",
    # None of the POSIX rewrites apply: there is no `$IFS`, no `$@`, no brace
    # expansion and no `expr`, so they would be requests spent proving nothing.
    cannot=("cmd-space", "cmd-brace", "cmd-compute", "cmd-name", "cmd-path", "cmd-sep"),
    note="PowerShell, which is also the shell on a modern Windows host",
)

SHELLS: tuple[Shell, ...] = (POSIX, BASH, CMD, POWERSHELL)


@dataclass(frozen=True)
class Delivery:
    """How a command gets into a parameter that may not be a whole command.

    `prefix` and `suffix` wrap the command. The empty one is tried first because
    a parameter that is the command needs nothing, and a page that runs what it
    is given costs one request that way rather than several.
    """

    name: str
    prefix: str
    suffix: str
    why: str


DELIVERIES: tuple[Delivery, ...] = (
    Delivery(
        name="direct",
        prefix="",
        suffix="",
        why="the value is the command; nothing has to be escaped",
    ),
    Delivery(
        name="separator",
        prefix="; ",
        suffix="",
        why="ends the command the application chose, so the rest runs after it",
    ),
    Delivery(
        name="pipe",
        prefix="| ",
        suffix="",
        why="sends the application's command output into this one instead",
    ),
    Delivery(
        name="and",
        prefix="&& ",
        suffix="",
        why="runs after the application's command if that one succeeded",
    ),
    Delivery(
        name="or",
        prefix="|| ",
        suffix="",
        why="runs after it if that one failed - which an unknown argument often is",
    ),
    Delivery(
        name="newline",
        prefix="\n",
        suffix="",
        why="a separator that a filter looking for `;` and `|` does not see",
    ),
)

# A substitution delivery - wrapping the command in `$( )` or backticks - is not
# in the list, and its absence is a measurement rather than an oversight. It runs
# the command, but the output of a substitution is an *argument*: the shell puts
# it wherever the substitution sat and prints nothing itself. Asked for the sum
# that way, `ping ... $(echo A; echo 5; echo B)` answers
# `ping: B: Name or service not known`. The command ran and the proof did not
# come back, which is worse than not running it, because it looks like a miss.
#
# It would be the right delivery for a check whose evidence is something other
# than the response - a callback, or a file the caller reads afterwards. This
# module's proof is the response, so it stays out.


def question(shell: Shell, arithmetic: Arithmetic, delivery: Delivery) -> str:
    """One seed: the proof command, delivered the way this delivery describes."""
    body = shell.join.join(
        [
            shell.literal(arithmetic.open),
            shell.total(arithmetic.left, arithmetic.right),
            shell.literal(arithmetic.close),
        ]
    )
    return f"{delivery.prefix}{body}{delivery.suffix}"


def seeds(arithmetic: Arithmetic, shell: Shell = POSIX) -> list[tuple[str, str]]:
    """Every seed for one shell, as (payload, a name for what it is).

    Ordered direct-first: the cheapest question for a target that runs what it is
    given, and the more elaborate deliveries only after that one has not answered.
    """
    return [(question(shell, arithmetic, delivery), delivery.name) for delivery in DELIVERIES]
