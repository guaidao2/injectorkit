"""Ask the target, once, whether anything is filtering.

Every run otherwise learns this the hard way: payloads are sent, some are
refused, and the escalation ladder only finds out afterwards. The cost is the
same either way, but the order is not - knowing at the start changes what gets
sent, and knowing which product is in front changes which spellings are worth
trying first.

The probe is a single request carrying the things filters are built to catch.
It is sent to a parameter the caller already picked, because that is where a
filter watching this application will look.

Two deliberate limits. It runs at most once per host: the answer does not change
per parameter, and the probe is itself traffic. And it is conservative about
concluding anything - a refusal needs a status code an application would not
produce by accident, or wording only a refusal carries, because a false positive
escalates every later payload through generations of mutation that were never
needed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .bypass import BLOCK_STATUSES, classify_refusal

# What a filter is looking for, in one value. SQL, a script tag, a traversal and
# a shell metacharacter - the four categories a request-side rule set is written
# around. Sending them together costs one request instead of four, and a filter
# that catches any of them answers with the same refusal.
PROBE = (
    "1 AND 1=1 UNION SELECT NULL-- "
    "<script>alert(1)</script> "
    "../../../../etc/passwd "
    ";cat /etc/passwd"
)


@dataclass
class ProbeOutcome:
    """What the probe found, in the terms a report uses."""

    refused: bool = False
    vendor: str = ""
    status: int = 0
    # The response to a harmless request, for comparison. Detached from the
    # refusal by construction, which is what makes the comparison mean anything.
    baseline_status: int = 0
    note: str = ""

    def describe(self) -> str:
        if not self.refused:
            return "no filter was found in front of this target"
        who = f" ({self.vendor})" if self.vendor else ""
        return (
            f"the target is behind a filter{who}: a probe carrying SQL, a script tag, a "
            f"traversal and a shell metacharacter was refused with {self.status}"
        )


def probe_filter(ctx, param, action: str = "filter.probe") -> ProbeOutcome:
    """Send the probe once and say what came back.

    The baseline is fetched first and compared against, because a refusal is only
    a refusal if it differs from what the target does with ordinary input: an
    application that answers everything with 403 has refused nothing.
    """
    from .inject import inject

    host = ctx.config["request"].host()

    baseline = ctx.send(ctx.config["request"], action=f"{action}.baseline")
    if baseline.response.error:
        return ProbeOutcome(note="the target did not answer, so nothing was concluded")

    request, exchange = inject(ctx, param, PROBE, action)
    probe = exchange.response
    if probe.error:
        return ProbeOutcome(note="the probe did not get an answer")

    refused, vendor, signature = classify_refusal(baseline.response, probe)
    if ctx.bypass is not None:
        ctx.bypass.record_probe(host, vendor, signature)
        if refused and vendor:
            ctx.bypass.profile(host).vendor = vendor

    result = ProbeOutcome(
        refused=refused,
        vendor=vendor,
        status=probe.status,
        baseline_status=baseline.response.status,
    )
    if not refused and probe.status in BLOCK_STATUSES:
        # Worth saying out loud: the status is one a filter uses, and it was not
        # treated as a refusal because the page did not read like one. That is
        # the conservative call, and the operator can overrule it with --via.
        result.note = (
            f"the probe answered {probe.status}, which filters use, but the page does not "
            "read like a refusal - so it was not taken as one"
        )
    return result


def probe_without_agent(ctx, param, action: str = "filter.probe") -> ProbeOutcome:
    """Ask the same question the way a request that is not a browser would.

    A request with no User-Agent at all is refused or answered differently by
    most filters, which is what makes it worth one request to find out. It is
    evidence of a filter rather than of which one: anything in front of the
    application is likely to treat a missing User-Agent as a scanner.

    Kept separate from the main probe and reported as a difference rather than as
    a refusal, because a target that answers the same either way has told us
    something too - and a target that answers differently has told us only that
    something is watching, not that our payloads will be refused.
    """
    from .inject import inject

    host = ctx.config["request"].host()

    plain = ctx.send(ctx.config["request"], action=f"{action}.baseline")
    if plain.response.error:
        return ProbeOutcome(note="the target did not answer, so nothing was concluded")

    stripped = ctx.config["request"].clone()
    stripped.headers.delete("User-Agent")
    bare = ctx.send(stripped, action=f"{action}.no-agent")
    if bare.response.error:
        return ProbeOutcome(note="the target did not answer without a User-Agent")

    if bare.response.status == plain.response.status:
        return ProbeOutcome(
            baseline_status=plain.response.status,
            note="the target answers a request with no User-Agent the same way",
        )

    note = (
        f"the target answers a request with no User-Agent differently: "
        f"{plain.response.status} normally, {bare.response.status} without one"
    )
    # Recorded on the profile directly rather than through observe(): the response
    # may well be an ordinary page with a different status, and counting that as a
    # refusal would put this target's refusal count up without a payload ever
    # being refused. What it does mean is that marking the host as probed is no
    # longer honest on its own, so the count goes up by one to keep the
    # threshold meaningful.
    if ctx.bypass is not None:
        profile = ctx.bypass.profile(host)
        profile.observed = True
        profile.refusals = max(profile.refusals, 1)
    return ProbeOutcome(
        refused=True,
        status=bare.response.status,
        baseline_status=plain.response.status,
        note=note,
    )
