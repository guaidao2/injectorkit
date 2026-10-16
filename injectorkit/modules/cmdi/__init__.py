"""Command injection: making the target run something, and proving it did.

A parameter that reaches a shell is the most direct thing there is to find,
because finding it is already having it. So the module is shaped around one
question - did the value get executed - and everything else is about asking that
question in a way the target cannot fake.

The question is arithmetic. Two fresh markers with a computed number between
them: a page that reflects the payload returns the expression, and only a shell
that ran it returns the number. That is the whole detection standard, and it does
not depend on the target, the dialect or the filter.

Because it does not depend on the dialect, the dialect becomes something to
search rather than something to assume - see `seeds.SHELLS`. The same holds for
how the value gets into the command line: `seeds.DELIVERIES`. Neither list is a
payload list; both are the axes of a question, which is why a rewrite that only
one shell runs is kept and gated rather than dropped.
"""

from __future__ import annotations

import argparse

from ...core.httpmsg import parse_headers
from ...engine import shell
from ...engine.runner import (
    choose_target,
    close_board,
    close_filters,
    collect_targets,
    emit_summary,
    no_parameters_message,
    open_board,
    open_filters,
    run_targets,
)
from ...engine.statemachine import Engine, RunContext
from .graph import build_graph, command_runner

NAME = "cmdi"
HELP = (
    "command injection: find the parameter that reaches a shell, prove it with an "
    "arithmetic result the target has to have computed, and run a command through it"
)

# Parameters whose names usually hold something that ends up on a command line.
LIKELY_PARAMS = frozenset(
    {
        "cmd",
        "command",
        "exec",
        "execute",
        "run",
        "host",
        "ip",
        "address",
        "target",
        "domain",
        "url",
        "ping",
        "query",
        "q",
        "name",
        "file",
        "path",
        "dir",
        "log",
        "action",
    }
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    # Only what is particular to this class. The request flags, the engine flags
    # and the out-of-band flags are added for every module in `cli.py`, so
    # repeating one here is how two arguments end up fighting over a name.
    parser.add_argument("-u", "--url", help="target URL, including the parameter to attack")
    parser.add_argument("-r", "--request", help="a raw request captured from a proxy")
    parser.add_argument("--param", help="parameter to inject into (default: pick the likely ones)")
    parser.add_argument("--max-params", type=int, default=6, help="how many parameters to try")

    run = parser.add_argument_group("exploitation")
    run.add_argument(
        "--exploit",
        action="store_true",
        help="act on the target: run the command given with --os-cmd through the delivery "
        "that was proved. Without it the run only reports whether the parameter reaches a "
        "shell",
    )
    run.add_argument(
        "--os-cmd",
        metavar="COMMAND",
        help="a command to run through the injection once it is established. Needs --exploit",
    )
    run.add_argument(
        "--os-shell",
        action="store_true",
        help="keep the injection open and run what you type through it. Needs --exploit. "
        "Reads commands from a terminal or from a pipe, so a scripted session works",
    )
    run.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="ask the questions but run nothing, whatever else was given",
    )


def build_context(args: argparse.Namespace, runtime, request, params, board=None) -> RunContext:
    """The run's context, assembled the way every module assembles one.

    No judge of its own: this module's judgement is the arithmetic result, which
    the action computes from the response it already has. A signature table would
    be a second, weaker answer to the same question.
    """
    board = board if board is not None else open_board(args, runtime, request)
    return RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=board,
        bypass=open_filters(args, runtime, request, board),
        oob=runtime.oob,
        pheromone=runtime.pheromone,
        config={
            "request": request,
            "params": params,
            "exploit": bool(args.exploit) and not args.dry_run,
            "dry_run": bool(args.dry_run),
            # Nothing runs unless it was asked for twice over: the flag that says
            # running is what you want, and the command to run.
            "os_cmd": (args.os_cmd or "") if (args.exploit and not args.dry_run) else "",
            "via": [],
            "read": [],
            "upload": "",
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )


def run_one(request, params, args, runtime) -> None:
    """Test one target, then write down what was learned about it.

    Every target gets this, not just the first one with a parameter: `--targets`
    means a batch and `--forms` means every form on the page, so a run that
    answers for one of them and says nothing about the rest reports "nothing
    found" for hosts it never asked.
    """
    ctx = build_context(args, runtime, request, params)
    try:
        Engine(ctx.graph, ctx).run()
    finally:
        # Written even when the run is interrupted. What was learned before a
        # Ctrl+C is exactly what a resumed run needs, and a module that never
        # saves makes --state a flag that silently writes no file.
        emit_summary(runtime, ctx.blackboard, args)
        close_board(args, ctx.blackboard, request)
        close_filters(args, ctx.bypass, request)


def run_shell(args: argparse.Namespace, runtime) -> int:
    """Prove the injection, then keep it open and run what is typed.

    A scan answers "can this run anything"; a shell answers "run this". They want
    the same thing discovered first, so the graph runs once to find the delivery
    and the session sits on top of what it proved - the same shell the protocol
    module uses, because from its side this is just a function from a command to
    its output.
    """
    targets = collect_targets(args, runtime, NAME)
    extra_headers = frozenset(
        name.lower() for name, _ in parse_headers(getattr(args, "header", None) or [])
    )
    request, params, index = choose_target(
        targets, args.param, args.max_params, LIKELY_PARAMS, extra_headers
    )
    if not params:
        raise SystemExit(
            no_parameters_message(targets, args.max_params, LIKELY_PARAMS, extra_headers)
        )
    if index > 1:
        runtime.info(f"target {index} of {len(targets)} is the one with a parameter")

    board = open_board(args, runtime, request)
    ctx = build_context(args, runtime, request, params, board=board)
    try:
        Engine(ctx.graph, ctx).run()
        if not board.get("cmdi.proven"):
            runtime.warn(
                "no command execution was established, so there is nothing to open a shell through"
            )
            return 1
        return shell.run(
            command_runner(ctx),
            prompt=runtime.paint("os-shell> ", "next"),
            banner=runtime.paint(f"command execution on {request.host()}", "section"),
        )
    finally:
        close_board(args, board, request)
        close_filters(args, ctx.bypass, request)


def run(args: argparse.Namespace, runtime) -> int:
    if args.os_shell:
        return run_shell(args, runtime)
    return run_targets(args, runtime, NAME, LIKELY_PARAMS, run_one)
