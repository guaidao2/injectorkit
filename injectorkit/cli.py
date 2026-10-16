"""Command line: one subcommand per vulnerability class, one shared engine.

    python injectorkit.py ssrf -u "http://target/fetch?url=x"
    python injectorkit.py --help

Engine options are registered once and every class inherits them, so transport,
bypass budget and verbosity behave the same whichever class is running.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import style
from .logo import banner
from .modules import proto, ssrf
from .runtime import build_runtime

MODULES = {
    ssrf.NAME: ssrf,
    proto.NAME: proto,
}


def add_engine_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("request")
    group.add_argument("-X", "--method", default="GET", help="HTTP method for the target request")
    group.add_argument(
        "-H",
        "--header",
        action="append",
        metavar="NAME: VALUE",
        help="extra header (repeatable). One the request already carries wins, because a request "
        "that names its own identity is more specific than a command-line default",
    )
    group.add_argument(
        "-C",
        "--cookie",
        action="append",
        metavar="NAME=VALUE",
        help="a session cookie to send with every request (repeatable). 'a=b; c=d' works, and a "
        "pasted 'Cookie: a=b' is accepted as it comes. Merged with whatever the request already "
        "carries rather than replacing it - dropping the request's own CSRF token would end the "
        "session this exists to keep",
    )
    group.add_argument(
        "--basic-auth",
        metavar="USER:PASSWORD",
        help="HTTP Basic credentials, encoded for you",
    )
    group.add_argument("--data", help="request body")

    engine = parser.add_argument_group("engine")
    engine.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    engine.add_argument("--proxy", help="send traffic through a proxy")
    engine.add_argument(
        "--user-agent",
        default="InjectorKit",
        metavar="STRING",
        help="what to claim to be (default: %(default)s). The honest default leaves a trace the "
        "target's owner can find; change it when the tool's name would pollute what you are reading",
    )
    engine.add_argument(
        "--random-ua",
        action="store_true",
        help="compose a plausible browser User-Agent per request instead, from parts rather than a list",
    )
    engine.add_argument("--verify-tls", action="store_true", help="verify TLS certificates (off by default)")
    engine.add_argument("--follow-redirects", action="store_true", help="follow redirects instead of reading them")
    engine.add_argument("--delay", type=float, default=0.0, help="pause between requests, in seconds")
    engine.add_argument(
        "--retries",
        type=int,
        default=1,
        help="how many times to try again after a connection drops (default: 1). An HTTP "
        "status is never retried - that is the server answering",
    )
    engine.add_argument("--max-requests", type=int, default=300, help="request budget for the run")
    engine.add_argument("--no-bypass", action="store_true", help="do not track filter behaviour or escalate")
    engine.add_argument(
        "--no-pheromone",
        action="store_true",
        help="do not use or update the cross-target priors on which rewrites work",
    )
    engine.add_argument(
        "--pheromone-file",
        default=".injectorkit/pheromone.json",
        metavar="FILE",
        help="where those priors are kept between runs",
    )
    engine.add_argument(
        "--state",
        metavar="FILE",
        help="save progress to this file and resume from it, instead of the automatic "
        "store under .injectorkit/ (scan state, not an authenticated session)",
    )
    engine.add_argument(
        "--flush-session",
        action="store_true",
        help="forget what earlier runs learned about this host before starting",
    )
    engine.add_argument(
        "--forms",
        action="store_true",
        help="fetch the page and submit every form it declares, so parameters that live in a form "
        "body rather than the URL are tested too",
    )
    engine.add_argument(
        "--targets",
        metavar="FILE",
        help="test many targets from one file: a URL, or the path of a saved raw request, per line",
    )
    engine.add_argument(
        "--batch",
        action="store_true",
        help="never ask, take the default answer everywhere. Nothing prompts today, so this changes "
        "nothing yet - it is here because whether to ask is one decision for every class, not a "
        "decision each class makes for itself",
    )
    engine.add_argument("-v", "--verbose", action="count", default=0, help="-v shows traffic, -vv shows tracebacks")
    engine.add_argument("-q", "--quiet", action="store_true", help="print results only")
    engine.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colour the output (default: %(default)s - coloured on a terminal, plain in a pipe or a "
        "file so nothing parsing it has to strip escapes; NO_COLOR is honoured). 'always' forces it",
    )

    oob = parser.add_argument_group("out-of-band")
    oob.add_argument(
        "--oob",
        metavar="HOST:PORT",
        help="run a callback listener here; works when the target can reach this machine",
    )
    oob.add_argument("--oob-public", metavar="HOST", help="address the target should use to reach the listener")
    oob.add_argument(
        "--oob-interactsh",
        metavar="SERVER",
        help="collect callbacks through an interactsh deployment (oast.pro, oast.fun, ... or your own); "
        "resolves from anywhere, which is what a target behind NAT or on the internet needs",
    )
    oob.add_argument("--oob-token", metavar="TOKEN", help="auth token for a private interactsh deployment")
    oob.add_argument("--oob-wait", type=float, default=5.0, help="seconds to wait for a callback per attempt")


class _BannerParser(argparse.ArgumentParser):
    """A parser whose help is introduced by the banner.

    `-h` is the first thing most people type, and argparse answers it before a
    single argument has been read - so the banner has to live here rather than
    after parsing. There are no options to consult yet, so it uses the automatic
    colour rule: a terminal sees it, a pipe does not.
    """

    def print_help(self, file=None) -> None:
        stream = file if file is not None else sys.stdout
        watching = style.enabled("auto", stream)
        print(banner(f"v{__version__}", lambda text, name: style.paint(text, name, watching)), file=stream)
        print(file=stream)
        super().print_help(file)


class _VersionAction(argparse.Action):
    """Prints the banner, then the version, then stops.

    argparse's own version action exits before anything can decorate it, and the
    banner is how this tool says hello - so `--version` says it too.
    """

    def __init__(self, option_strings, dest, **kwargs) -> None:
        kwargs.setdefault("nargs", 0)
        kwargs.setdefault("help", "show program's version number and exit")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        watching = style.enabled("auto")
        print(banner(f"v{__version__}", lambda text, name: style.paint(text, name, watching)))
        print(f"injectorkit {__version__}")
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = _BannerParser(
        prog="injectorkit.py",
        description="InjectorKit - exploitation toolkit for CTF and authorized penetration testing",
    )
    parser.add_argument("--version", action=_VersionAction)

    subcommands = parser.add_subparsers(dest="command", metavar="<class>", parser_class=_BannerParser)
    for name, module in MODULES.items():
        child = subcommands.add_parser(name, help=module.HELP, description=module.HELP)
        add_engine_flags(child)
        module.add_arguments(child)
        child.set_defaults(handler=module.run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2

    runtime = build_runtime(args)
    # The banner is the front door: shown where a person is watching, skipped
    # when the output is being piped or parsed, and skipped under -q as well.
    if not args.quiet and runtime.color_enabled():
        print(banner(f"v{__version__}", runtime.paint), flush=True)

    runtime.info("starting")
    code = 0
    try:
        code = args.handler(args, runtime)
    except KeyboardInterrupt:
        runtime.warn("interrupted; stopping where it is")
        code = 130
    finally:
        if runtime.oob is not None:
            runtime.oob.stop()
        if runtime.pheromone is not None:
            runtime.pheromone.save()
    runtime.info("ending")
    return code
