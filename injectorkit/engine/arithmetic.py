"""Making a command runner prove it is a command runner.

A page that echoes the payload back will happily return the word "echo", the
marker, and everything around them, so a check for a marker the payload itself
contains proves nothing: an application that never executed anything passes it.

The answer is to ask for something the payload does not contain and cannot
contain - a number. The payload carries an addition; the response has to carry
its result. Echoing the payload back returns `2+3`, not `5`, and only a shell
that ran the arithmetic can produce the second one.

The same question works for any interpreter that evaluates expressions, which is
why it lives here rather than in one module: what differs between them is the
syntax of the command, and that belongs to whoever knows the target's language.
"""

from __future__ import annotations

import secrets


class Arithmetic:
    """A question whose answer proves something ran, not just that text came back.

    One instance covers one check: it mints the two numbers, knows the sum, and
    can build the command that prints it between two markers. The markers are
    fresh so a previous attempt's output - still sitting in a log, say - is not
    mistaken for this one's.
    """

    def __init__(self) -> None:
        self.left = secrets.randbelow(9000) + 1000
        self.right = secrets.randbelow(9000) + 1000
        self.open = "ik" + secrets.token_hex(4)
        self.close = "ik" + secrets.token_hex(4)

    @property
    def answer(self) -> str:
        return str(self.left + self.right)

    def command(self, expression: str = "") -> str:
        """Print the marker, run the arithmetic, print the marker again.

        `expression` overrides the addition, for a caller that wants a check of
        its own between the same markers - the answer to compare against is then
        the caller's business.
        """
        arithmetic = expression or f"$(({self.left}+{self.right}))"
        return f"echo {self.open}; echo {arithmetic}; echo {self.close}"

    def proved(self, body: str) -> str | None:
        """The answer, if the response carries it where only a shell could put it.

        Returns the text between the markers when it is the sum that was asked
        for, so a caller has something to show. None means the arithmetic did not
        run: no marker pair encloses the sum, because the markers are missing or
        because what sits between them is the expression rather than its result.

        Every pair is checked, not just the last. A page that prints the command
        before running it puts the expression in the earlier pair and the result
        in the later one; a page that prints it afterwards does the opposite, and
        looking only at the last pair would report a target that ran the command
        as one that did not. Which order a target echoes in is not something to
        depend on, so neither order is assumed.
        """
        answer = self.answer
        start = body.find(self.open)
        while start != -1:
            end = body.find(self.close, start + len(self.open))
            if end == -1:
                break
            between = body[start + len(self.open) : end].strip()
            if between == answer:
                return between
            start = body.find(self.open, start + len(self.open))
        return None
