"""Placing a payload in a parameter, and climbing when it is refused.

Every vulnerability module starts the same way: take the request the operator
handed over, find the parameter to inject into, put a value there, and watch
what the target does with it. Only the values differ. So the mechanics live here
- inject, escalate, scope what was learned - and a module brings its own seeds
and its own graph.

Escalation is the part worth understanding. Generation 0 is the seed exactly as
written, so an unprotected target costs one request and never sees a mutation. A
generation is exhausted before the next is tried, so cheap rewrites are spent
before exotic ones, and a rewrite this target has already refused is skipped:
a filter that lower-cases its input defeats case-swap once, and rediscovering
that per payload is how a scan turns into noise.
"""

from __future__ import annotations

import ipaddress
import re

from ..core.httpmsg import Request
from ..core.mutate import Kind, Variant
from ..core.params import Encode, Param, Where, pollute, rewrite
from ..core.protocols import with_host
from .blackboard import Confidence

VIA_PLACEHOLDER = "{target}"


def candidates(ctx) -> list[Param]:
    """The parameters this run is allowed to touch."""
    return list(ctx.config.get("params") or [])


def template(ctx) -> Request:
    """The request as the operator supplied it, before any payload."""
    return ctx.config["request"]


def inject(ctx, param: Param, payload: str, action: str, encoded: bool = False):
    """Place a payload in one parameter and send it.

    Encoding is decided per payload, not once for the whole run. An ordinary
    value (`file:///etc/passwd`) must be percent-encoded to survive a query
    string. A value a mutator has already put into transport form
    (`file%3A%2F%2F%2Fetc%2Fpasswd`) must be sent **as it stands**: encoding it
    again hands the application a literal percent sequence instead of a URL, and
    the mutation that was supposed to get past the filter becomes the reason
    nothing works.
    """
    if param.where.value == "header" or encoded:
        encode = Encode.NONE
    else:
        encode = Encode.URL
    request = rewrite(template(ctx), param, payload, encode)
    exchange = ctx.send(request, action=action)
    return request, exchange


def route_via(ctx, payload: str) -> tuple[str, bool]:
    """Send the payload through a host the filter already trusts.

    A whitelist cannot be argued with: the destination has to be named as
    something the filter accepts, and only then reach somewhere else. The
    operator supplies the shape (`http://allowed/redirect?to={target}`) because
    only they know what the target trusts; everything else stays the same.
    """
    templates = ctx.config.get("via") or []
    if not templates:
        return payload, False
    return templates[0].replace(VIA_PLACEHOLDER, payload), True


def inject_escalating(
    ctx,
    param: Param,
    seed: str,
    action: str,
    kind: Kind = Kind.SSRF,
    max_generation: int = 3,
    per_generation: int = 12,
    allow_pollution: bool = True,
):
    """Send a seed, climbing one generation at a time only while refused."""
    host = template(ctx).host()
    start = ctx.bypass.floor(host, action)
    # What a refused rewrite proves, and what it does not. A blocklist matches
    # literals, and payload families carry different ones: `gopher://<internal>`
    # keeps a scheme for the filter to catch however the address is spelled,
    # while `http://<internal>` does not. So the verdict is scoped to the family
    # (scheme, and whether the host is an address or a name), and a rewrite that
    # failed there is not tried again for the next payload in the same family -
    # that is where a scan turns into noise.
    scope = payload_scope(seed)
    last = None

    # Before any rewrite, one attempt that is not a rewrite: the same parameter
    # sent a second time, original value first and payload last. A filter reading
    # one value per name sees the first; a runtime keeping the last sees the
    # payload. It is recorded under its own name so the priors learn whether this
    # target's filter reads every occurrence or only the first.
    if allow_pollution and param.where in (Where.QUERY, Where.BODY, Where.COOKIE):
        request = pollute(template(ctx), param, seed)
        exchange = ctx.send(request, action=action)
        variant = Variant(value=seed, generation=0, mutators=("pollute",))
        last = (request, exchange, variant)
        if not ctx.last_refused:
            if ctx.pheromone is not None:
                ctx.pheromone.reward(scope, ("pollute",), amount=0.5)
            return last
        if ctx.pheromone is not None:
            ctx.pheromone.punish(scope, ("pollute",))

    for generation in range(start, max_generation + 1):
        pool = [
            variant
            for variant in ctx.variants(seed, generation=generation, kind=kind, limit=400)
            if variant.generation == generation
        ]
        # What is likely to get through goes first. This is a prior, not a
        # filter: a rewrite the table dislikes is still tried, just later.
        if ctx.pheromone is not None:
            pool = ctx.pheromone.rank(scope, pool)

        attempted = 0
        for variant in pool:
            if ctx.stopped or attempted >= per_generation:
                break
            if any(ctx.bypass.mutator_dead(host, action, name, scope) for name in variant.mutators):
                continue
            attempted += 1
            routed, used_via = route_via(ctx, variant.value)
            request, exchange = inject(
                ctx,
                param,
                routed,
                action,
                # A routed payload has to survive a query string as a whole, so
                # a variant that was already encoded is no longer in transport
                # form once it has been wrapped.
                encoded=variant.encoded and not used_via,
            )
            last = (request, exchange, variant)

            if ctx.last_refused:
                for name in variant.mutators:
                    ctx.bypass.mark_mutator_dead(host, action, name, scope=scope)
                if ctx.pheromone is not None:
                    ctx.pheromone.punish(scope, variant.mutators)
                ctx.log(f"   {action}: {variant.describe()} was refused")
                continue

            if ctx.pheromone is not None:
                # Clearing the filter is worth something, but not much: whether
                # the value reached a parser is only answerable from the
                # response, and the caller scores that when it finds evidence.
                ctx.pheromone.reward(scope, variant.mutators, amount=0.25)
            if generation > start:
                ctx.bypass.raise_floor(host, action, generation)
                ctx.log(f"   {action}: generation {generation} reached the target, floor raised")
            return last
    return last


def scheme(payload: str) -> str:
    """The scheme a payload starts with."""
    head = payload.split(":", 1)[0]
    return head.lower() if head.isalnum() else ""


def payload_scope(payload: str) -> str:
    """Which family of payload a bypass verdict belongs to.

    A rewrite that failed against `gopher://127.0.0.1` says nothing about the
    same rewrite against `http://127.0.0.1`, and nothing about a host that is a
    name rather than an address - each carries different literals for a filter
    to catch, and the address rewrites only apply to one of them.
    """
    scheme_name = scheme(payload)
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^@/?#]*@)?([^/?#:]*)", payload)
    host = match.group(1).strip("[]") if match else ""
    if not host:
        return f"{scheme_name}:none"
    if host.lower() == "localhost":
        return f"{scheme_name}:name"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return f"{scheme_name}:name"
    return f"{scheme_name}:ip"


def rebind_seeds(ctx, payload: str) -> list[str]:
    """The spellings of a destination worth trying for one probe.

    A name that alternates between an address the target accepts and one it does
    not is a second way to reach the same place: a filter that judged the first
    answer, or a check that resolves once and connects later, is answered by the
    second lookup rather than the first.
    """
    rebind = ctx.config.get("rebind")
    if not rebind:
        return [payload]
    return [payload, with_host(payload, rebind)]


def record(ctx, key: str, value: object, evidence: str, confidence) -> None:
    """Note something on the board, under a module's own key."""
    ctx.blackboard.add(key, value, evidence=evidence, confidence=confidence)


def note_finding(ctx, key: str, entry: dict, confidence=None) -> None:
    """Record a finding and print it. Modules own the key and the wording."""
    record(
        ctx,
        key,
        entry,
        evidence=entry.get("evidence", ""),
        confidence=confidence or entry.get("confidence") or Confidence.CONFIRMED,
    )
    ctx.emit(
        "  [!] {name} via {param}: {evidence}".format(
            name=entry.get("name", "?"),
            param=entry.get("param", "?"),
            evidence=entry.get("evidence", ""),
        )
    )
