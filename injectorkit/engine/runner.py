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
from ..runtime import credentials
from . import session
from .blackboard import Blackboard
from .bypass import Bypass
from .transport import merge_cookies


def request_from_args(args, module: str) -> Request:
    """The target request, from a URL or from a capture.

    A capture saved by a proxy has an origin-form target and carries the host in
    a header, which is also the most common shape a user pastes in. Refusing it
    would mean hand-editing every capture before the tool would look at it.

    The identity the operator gave - cookies, Basic, extra headers - goes onto
    the request here as well as into the transport's defaults. The transport is
    what puts it on the wire, but a parameter can only be injected into if it is
    part of the request the parameters are read from, and a cookie named with -C
    is a parameter position like any other. Leaving it only in the transport is
    how a session cookie ends up sent but never tested.
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
        # Extra headers belong on a capture as much as on a URL, and they are one
        # of the ways a header becomes injectable at all.
        for name, value in parse_headers(args.header):
            request.headers.set(name, value)
        for name, value in credentials(args):
            if name.lower() == "cookie":
                request.headers.set("Cookie", merge_cookies(request.headers.get("Cookie") or "", value))
            elif not request.headers.get(name):
                request.headers.set(name, value)
        return request
    if not args.url:
        raise SystemExit(f"{module} needs -u/--url (or -r for a raw request)")
    request = Request.from_url(
        args.url,
        method=args.method or "GET",
        headers=parse_headers(args.header),
        body=args.data,
    )
    for name, value in credentials(args):
        if name.lower() == "cookie":
            request.headers.set("Cookie", merge_cookies(request.headers.get("Cookie") or "", value))
        elif not request.headers.get(name):
            request.headers.set(name, value)
    return request


def collect_targets(args, runtime, module: str) -> list[Request]:
    """Everything worth testing, from whichever input the operator chose.

    A URL is one target. `--forms` adds the requests the page itself declares,
    because the parameters behind a login box or a search field are not in the
    address. `--targets` replaces the single target with a list, which is what
    makes a set of hosts or a folder of captures one command.
    """
    if getattr(args, "targets", None):
        return requests_from_batch(args.targets)
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


def emit_summary(runtime, board, args) -> None:
    """Print the run's result, then - only with -v - the list of what it did.

    The bookkeeping exists so the next run can skip this page. It is not a
    result, and printing it among the results is what makes a report unreadable.
    """
    runtime.emit("")
    runtime.emit(board.render())
    if getattr(args, "verbose", 0):
        tried = board.render_bookkeeping()
        if tried:
            runtime.emit("")
            runtime.emit(tried)


def baseline_body(transport, request: Request, note=None) -> tuple[bytes | None, float, bool]:
    """The page's own answer, asked for twice, and what that says about it.

    A page that already prints "root:x:0:0" in a code sample answers every probe
    with it, and a judge that only looks at the probe calls that a finding. The
    response this same request produces untouched is what tells a result apart
    from the page's own content - so it is fetched here and handed to the judge,
    rather than guessed at inside it.

    Twice, because one sample cannot tell a stable page from an unstable one and
    every comparison afterwards is against this. The second request also gives
    the spread a timing check needs: a delay judged against a target that answers
    in 20ms once and 900ms the next time means nothing. Returns the body, the
    spread between the two responses, and whether they agreed.

    `note` is called once per request sent, because these are real traffic and
    the budget the operator set has to include them.
    """
    def fetch():
        response = transport.send(request)
        if note is not None:
            note()
        return response

    first = fetch()
    if first.error:
        return None, 0.0, True
    second = fetch()
    if second.error:
        return first.body, 0.0, True
    return first.body, abs(first.elapsed - second.elapsed), first.body == second.body


def requests_from_forms(request: Request, runtime) -> list[Request]:
    """Fetch the page once and turn every form it declares into a target."""
    response = runtime.transport.send(request)
    if response.error or not response.body:
        runtime.warn(
            f"could not read the page to look for forms: {response.error or 'the body was empty'}"
        )
        return []

    forms = parse_forms(response.text, request.url)
    if not forms:
        runtime.info("the page declares no form")
        return []

    targets: list[Request] = []
    for form in forms:
        built = form_request(form, request.url)
        if built.url == request.url and not built.body:
            # A form with nothing in it is the page itself; testing it again
            # would only repeat the request that found it.
            continue
        runtime.info(f"found a form: {form.describe()}")
        targets.append(built)
    return targets


def select_params(
    request: Request,
    requested: str | None,
    max_params: int,
    likely: frozenset[str],
    extra_headers: frozenset[str] = frozenset(),
) -> list[Param]:
    """Pick the parameters worth injecting into, best candidate first.

    A hundred requests into a parameter nobody reads is a hundred wasted
    requests, so when the operator did not name one, the names that usually
    carry a URL or a path go first and the rest are still there behind them.

    `extra_headers` names the headers the operator passed with -H. A header
    outside the usual set is exactly the case worth having: naming it is the
    clearest statement that this application reads it, and a filter in front of
    the application is the least likely to be looking at it.
    """
    params = extract_params(request, skip=DEFAULT_SKIP, max_params=64, extra_headers=extra_headers)
    if requested:
        return [param for param in params if param.key() == requested or param.name == requested]
    if len(params) <= 1:
        return params
    ranked = sorted(
        params,
        key=lambda param: (0 if param.name.lower() in likely else 1, param.name),
    )
    return ranked[:max_params]


def choose_target(
    targets: list[Request],
    requested: str | None,
    max_params: int,
    likely: frozenset[str],
    extra_headers: frozenset[str] = frozenset(),
):
    """The first target that actually has something to inject into.

    `--forms` adds the page itself alongside the request its form would send, and
    the page is usually first and has no parameters at all. Taking targets[0]
    without looking is how a scan reports "nothing injectable" on a page whose
    form is injectable one entry later.

    Returns the request, its parameters, and its one-based position.
    """
    for index, request in enumerate(targets, 1):
        params = select_params(request, requested, max_params, likely, extra_headers)
        if params:
            return request, params, index
    return (targets[0] if targets else None), [], 0


def no_parameters_message(
    targets: list[Request],
    max_params: int,
    likely: frozenset[str],
    extra_headers: frozenset[str] = frozenset(),
) -> str:
    """What to say when nothing anywhere turned out to hold a parameter.

    The useful part is what was looked at and what each entry held. A list where
    the second target carries a body parameter and the first carries nothing
    explains the outcome in a way that "no injectable parameter" cannot - and
    when every entry really is empty, that is worth knowing too.
    """
    lines = ["no injectable parameters were found. targets checked:"]
    for request in targets:
        found = extract_params(
            request, skip=DEFAULT_SKIP, max_params=max_params, extra_headers=extra_headers
        )
        held = ", ".join(param.key() for param in found) or "no parameters"
        lines.append(f"    {request.describe()}")
        lines.append(f"        {held}")
    lines.append("pass --param <name> to name one yourself; keys look like query:<name>,")
    lines.append("body:<name>, cookie:<name>, multipart:<name>, json:user.avatar")
    return "\n".join(lines)


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
        runtime.info(f"testing {len(targets)} targets")

    # Whatever the operator passed with -H is injectable by name, above and
    # beyond the headers an application is known to read.
    extra_headers = frozenset(
        name.lower() for name, _ in parse_headers(getattr(args, "header", None) or [])
    )

    tested = 0
    for index, request in enumerate(targets, 1):
        params = select_params(request, args.param, args.max_params, likely, extra_headers)
        if not params:
            runtime.info(f"target {index} of {len(targets)} has no parameters; moving on")
            continue
        if len(targets) > 1:
            runtime.info(f"target {index} of {len(targets)}: {request.describe()}")
        handler(request, params, args, runtime)
        tested += 1

    if tested == 0:
        raise SystemExit(
            no_parameters_message(targets, args.max_params, likely, extra_headers)
        )
    return 0


def open_board(args, runtime, request: Request) -> Blackboard:
    """A board for this target: an explicit state file, or the automatic store.

    Progress is kept by default, keyed by host and path, so running the same scan
    again does not repeat what it already worked out. `--state` names a file by
    hand instead, and `--flush-session` throws the automatic store away for this
    host before anything is read from it.
    """
    board = Blackboard(target=request.host())

    if getattr(args, "flush_session", False) and session.flush(request.url):
        runtime.info("forgot what an earlier run learned about this host")

    explicit = getattr(args, "state", None)
    if explicit:
        resumed = resume_session(explicit, board.target)
        if resumed is not None:
            board = resumed
            runtime.warn(
                f"carried over {len(board.facts)} facts and "
                f"{len(board.dead_ends)} closed paths from {explicit}"
            )
        return board

    text = session.load(request.url)
    if text:
        try:
            resumed = Blackboard.from_json(text)
        except ValueError:
            resumed = None
        if resumed is not None and resumed.target == board.target:
            board = resumed
            runtime.info(
                f"resuming: {len(board.facts)} facts and {len(board.dead_ends)} closed "
                f"paths from an earlier run on this page (--flush-session forgets them)"
            )
    return board


def close_board(args, board: Blackboard, request: Request) -> None:
    """Keep what was learned, so the next run on this page starts from it."""
    explicit = getattr(args, "state", None)
    if explicit:
        board.save(explicit)
        return
    session.save(request.url, board.to_json())


def open_filters(args, runtime, request: Request, board: Blackboard) -> Bypass:
    """The filter profile for this host, resumed when there is one to resume.

    The profile is bought with refused requests - the refusal count, the refused
    spellings, the generation a value first got through - and re-earning it on
    the next run costs exactly what it cost the first. A target that has already
    shown it hates `gopher://` should not have to show it again.
    """
    bypass = Bypass(board, enabled=not getattr(args, "no_bypass", False))
    if getattr(args, "flush_session", False):
        return bypass
    remembered = session.load_filters(request.url)
    if remembered:
        loaded = bypass.load_json(remembered)
        if loaded:
            runtime.info(f"resuming what earlier runs learned about the filter here")
    return bypass


def close_filters(args, bypass: Bypass, request: Request) -> None:
    """Keep what this run learned about the target's filters."""
    session.save_filters(request.url, bypass.to_json())


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
