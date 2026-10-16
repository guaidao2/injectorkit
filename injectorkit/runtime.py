"""Process-wide services a module is handed: transport, listener, output."""

from __future__ import annotations

import argparse
import base64
import sys
from dataclasses import dataclass, field

from .engine.interactsh import InteractshClient, InteractshError
from .engine.oob import OOBListener
from .engine.pheromone import PheromoneTable
from .engine import style
from .engine.transport import Transport, TransportOptions


@dataclass
class Runtime:
    """What every module needs and none of them should build itself."""

    transport: Transport
    oob: OOBListener | None = None
    pheromone: PheromoneTable | None = None
    verbose: int = 0
    quiet: bool = False
    color: str = "auto"
    _buffer: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._color = style.enabled(self.color)

    def _render(self, message: str) -> str:
        if not self._color:
            return message
        return "\n".join(style.style_line(line, True) for line in message.split("\n"))

    def paint(self, text: str, style_name: str) -> str:
        """Colour one piece of text the way this run's output is coloured.

        For the things that do not go through emit: a prompt, a banner, a line
        printed by hand. It follows the same setting, so nothing somewhere else
        ends up coloured differently from everything around it.
        """
        return style.paint(text, style_name, self._color)

    def color_enabled(self) -> bool:
        return self._color

    def log(self, message: str) -> None:
        """Per-request traffic, shown only with -v."""
        if self.verbose:
            print(self._render(message), file=sys.stderr, flush=True)

    def emit(self, message: str) -> None:
        """Results: findings, fingerprints, the summary. Always shown."""
        print(self._render(message), flush=True)

    def info(self, message: str) -> None:
        """Progress a reader does not need: suppressed by -q."""
        if not self.quiet:
            print(self._render(message), flush=True)


from .core.httpmsg import parse_headers  # noqa: F401  (re-exported for callers that import it here)


def credentials(args: argparse.Namespace) -> list[tuple[str, str]]:
    """The identity every request carries, from the flags that describe one.

    Three spellings for one idea, because they are not interchangeable in
    practice: a cookie is what a browser session gives you, Basic is what a
    staging environment in front of the application asks for, and a bare header
    covers the rest - bearer tokens, API keys, a house authentication header.
    Making the operator hand-encode one into another is just a way to get it
    wrong.
    """
    pairs: list[tuple[str, str]] = []

    for raw in getattr(args, "cookie", None) or []:
        value = (raw or "").strip()
        if not value:
            continue
        # A cookie pasted from a browser may still have the header name attached,
        # which is the single most common way to get this wrong.
        for prefix in ("Cookie:", "cookie:"):
            if value.startswith(prefix):
                value = value[len(prefix):].strip()
        if value:
            pairs.append(("Cookie", value))

    if getattr(args, "basic_auth", None):
        raw = args.basic_auth.strip()
        user, found, password = raw.partition(":")
        if not found:
            raise SystemExit("--basic-auth expects USER:PASSWORD")
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        pairs.append(("Authorization", f"Basic {token}"))

    return pairs


def build_transport(args: argparse.Namespace) -> Transport:
    return Transport(
        TransportOptions(
            timeout=args.timeout,
            insecure=not args.verify_tls,
            proxy=args.proxy,
            follow_redirects=args.follow_redirects,
            headers=tuple(credentials(args) + parse_headers(args.header)),
            user_agent=args.user_agent,
            random_user_agent=args.random_ua,
            delay=args.delay,
        )
    )


def build_oob(args: argparse.Namespace, log) -> OOBListener | "InteractshClient" | None:
    """Build the out-of-band backend the run asked for.

    Two backends, one interface. The local listener is enough when the target
    can reach this machine; an interactsh deployment is what makes callbacks
    work from behind NAT or against a host on the public internet, where a
    listener on a private address could never be called back.
    """
    if args.oob and args.oob_interactsh:
        raise SystemExit("choose either --oob (a listener here) or --oob-interactsh (a deployment), not both")

    if args.oob_interactsh:
        client = InteractshClient(args.oob_interactsh, token=args.oob_token or "", log=log)
        try:
            client.start()
        except InteractshError as error:
            raise SystemExit(f"interactsh: {error}") from error
        return client

    if not args.oob:
        return None

    host, _, port = args.oob.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("--oob expects HOST:PORT, for example 10.0.0.5:8081")
    listener = OOBListener(bind=host, port=int(port), public_host=args.oob_public or host)
    try:
        listener.start()
    except OSError as error:
        raise SystemExit(f"cannot listen on {args.oob}: {error}") from error
    return listener


def build_runtime(args: argparse.Namespace) -> Runtime:
    runtime = Runtime(
        transport=build_transport(args),
        pheromone=PheromoneTable(path=args.pheromone_file, enabled=not args.no_pheromone).load(),
        verbose=args.verbose,
        quiet=args.quiet,
        color=getattr(args, "color", "auto"),
    )
    runtime.oob = build_oob(args, runtime.log)
    if runtime.oob is not None:
        runtime.info(f"out-of-band: {describe_oob(runtime.oob)}")
    if runtime.pheromone is not None and runtime.verbose and runtime.pheromone.trails:
        runtime.info(f"priors: {len(runtime.pheromone.trails)} rewrite trails carried over")
    return runtime


def describe_oob(oob) -> str:
    """One line saying which callbacks this run can rely on."""
    if isinstance(oob, InteractshClient):
        return f"interactsh deployment {oob.server} (names under *.{oob.suffix})"
    return f"local listener on {oob.bind}:{oob.port} (targets must be able to reach it)"
