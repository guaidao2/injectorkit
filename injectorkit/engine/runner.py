"""Where targets come from, which parameters a run may touch, and how a run walks them.

Every module takes the same inputs - one request, a list of them, or the forms a
page declares - picks its parameters the same way, and walks a list of targets
the same way. That much is not knowledge about any one vulnerability, so it lives
here. What is domain knowledge is the list of likely parameter names and the
graph itself, and each module brings its own.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..core.forms import form_request, parse_forms
from ..core.httpmsg import Request, parse_headers
from ..core.params import DEFAULT_SKIP, Param, extract_params
from .blackboard import Blackboard


def request_from_args(args, module: str) -> Request:
    """The target request, from a URL or from a capture.

    A capture saved by a proxy has an origin-form target and carries the host in
    a header, which is also the most common shape a user pastes in. Refusing it
    would mean hand-editing every capture before the tool would look at it.
    """
    if args.request:
        with open(args.request, "rb") as handle:
            request = Request.parse(handle.read())
        if request.url.startswith("/"):
            parsed = urlsplit(args.url) if args.url else None
            host = request.headers.get("Host") or (parsed.netloc if parsed else "")
            if not host:
                raise SystemExit(
                    "the raw request has an origin-form target and no Host header; add --url"
                )
            scheme = parsed.scheme if parsed and parsed.scheme else "http"
            request.url = f"{scheme}://{host}{request.url}"
        return request
    if not args.url:
        raise SystemExit(f"{module} needs -u/--url (or -r for a raw request)")
    return Request.from_url(
        args.url,
        method=args.method or "GET",
        headers=parse_headers(args.header),
        body=args.data,
    )


def collect_targets(args, runtime, module: str) -> list[Request]:
    """Everything worth testing, from whichever input the operator chose.

    A URL is one target. `--forms` adds the requests the page itself declares,
    because the parameters behind a login box or a search field are not in the
    address. `--batch` replaces the single target with a list, which is what
    makes a set of hosts or a folder of captures one command.
    """
    if getattr(args, "batch", None):
        return requests_from_batch(args.batch)
    request = request_from_args(args, module)
    targets = [request]
    if getattr(args, "forms", False):
        targets.extend(requests_from_forms(request, runtime))
    return targets


def requests_from_batch(path: str) -> list[Request]:
    """One target per line: a URL, or the path of a saved raw request."""
    targets: list[Request] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.startswith(("http://", "https://")):
                targets.append(Request.from_url(entry))
                continue
            with open(entry, "rb") as raw:
                targets.append(Request.parse(raw.read()))
    if not targets:
        raise SystemExit(f"{path} names no target")
    return targets


def requests_from_forms(request: Request, runtime) -> list[Request]:
    """Fetch the page once and turn every form it declares into a target."""
    response = runtime.transport.send(request)
    if response.error or not response.body:
        runtime.info(f"  --forms: {request.url} could not be fetched ({response.error or 'empty body'})")
        return []

    forms = parse_forms(response.text, request.url)
    if not forms:
        runtime.info("  --forms: the page declares no form")
        return []

    targets: list[Request] = []
    for form in forms:
        built = form_request(form, request.url)
        if built.url == request.url and not built.body:
            # A form with nothing in it is the page itself; testing it again
            # would only repeat the request that found it.
            continue
        runtime.info(f"  --forms: {form.describe()}")
        targets.append(built)
    return targets


def select_params(
    request: Request,
    requested: str | None,
    max_params: int,
    likely: frozenset[str],
) -> list[Param]:
    """Pick the parameters worth injecting into, best candidate first.

    A hundred requests into a parameter nobody reads is a hundred wasted
    requests, so when the operator did not name one, the names that usually
    carry a URL or a path go first and the rest are still there behind them.
    """
    params = extract_params(request, skip=DEFAULT_SKIP, max_params=64)
    if requested:
        return [param for param in params if param.key() == requested or param.name == requested]
    if len(params) <= 1:
        return params
    ranked = sorted(
        params,
        key=lambda param: (0 if param.name.lower() in likely else 1, param.name),
    )
    return ranked[:max_params]


def run_targets(args, runtime, module: str, likely: frozenset[str], handler) -> int:
    """Walk every target, hand each one's parameters to the module, and report.

    A target with nothing injectable is skipped rather than fatal: with `--batch`
    or `--forms` most targets have no parameter at all, and stopping the run on
    the first one would make both options useless. It is fatal only when nothing
    anywhere had a parameter, which means the operator pointed the tool at the
    wrong thing.
    """
    targets = collect_targets(args, runtime, module)
    if len(targets) > 1:
        runtime.info(f"targets: {len(targets)}")

    tested = 0
    for index, request in enumerate(targets, 1):
        params = select_params(request, args.param, args.max_params, likely)
        if not params:
            runtime.info(f"  [{index}/{len(targets)}] no injectable parameter; skipped")
            continue
        if len(targets) > 1:
            runtime.info("")
            runtime.info(f"=== [{index}/{len(targets)}] {request.describe()} ===")
        handler(request, params, args, runtime)
        tested += 1

    if tested == 0:
        raise SystemExit(
            "no injectable parameter found; name one with --param (parameter keys look like "
            "query:<name>, body:<name>, cookie:<name>, multipart:<name>, json:user.avatar, "
            "or 'json -> <field>')"
        )
    return 0


def open_board(args, runtime, request: Request) -> Blackboard:
    """A board for this target, resumed from a session file when there is one."""
    board = Blackboard(target=request.host())
    if getattr(args, "session", None):
        resumed = resume_session(args.session, board.target)
        if resumed is not None:
            board = resumed
            runtime.info(
                f"  session: {len(board.facts)} facts and {len(board.dead_ends)} closed paths "
                f"carried over from {args.session}"
            )
    return board


def close_board(args, board: Blackboard) -> None:
    """Keep what was learned, when the operator asked for a session file."""
    if getattr(args, "session", None):
        board.save(args.session)


def resume_session(path: str, target: str) -> Blackboard | None:
    """Load a saved board, but only for the target it was recorded against.

    A session is one target's progress. Applying it to another host would feed
    its closed paths to a target that never refused anything, which is how a
    resumed scan quietly skips the thing it was supposed to test.
    """
    try:
        board = Blackboard.load(path)
    except (OSError, ValueError):
        return None
    if board.target != target:
        return None
    return board
