"""Evidence judging: what counts as proof.

A response changing is not a finding. Applications change their own responses
all the time - a nonce, a clock, a session id - and a tool that reports that
teaches its user to ignore it. The engine accepts four kinds of proof:

* a signature only the target file or service produces
* content that appears once the encoding the payload asked for is undone
* a delay inside the range the payload asked for, and outside measured jitter
* a callback arriving at the listener we planted

Two rules keep matching honest. A signature the payload itself spells is not
evidence, so the echo of the injected value is removed first. And a signature
already present in the baseline is not evidence either.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import statistics
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import quote, unquote

from .blackboard import Confidence
from ..core.httpmsg import Exchange, Response

# Statuses a filter uses to refuse a request. They are unusual enough that an
# application is unlikely to produce them by accident.
REFUSAL_STATUSES = {403, 406, 419, 501, 999}

# Wording that appears when something refused the request rather than the
# application answering it.
REFUSAL_MARKERS = (
    "access denied", "request blocked", "blocked by", "not acceptable",
    "security policy", "web application firewall", "modsecurity", "cloudflare",
    "attention required", "forbidden", "被拦截", "拦截", "安全狗", "宝塔", "雷池",
)

_BASE64_BLOB = re.compile(rb"[A-Za-z0-9+/=]{24,}")


@dataclass
class Verdict:
    """The engine's judgement of one observation."""

    confirmed: bool = False
    confidence: Confidence = Confidence.INCONCLUSIVE
    reason: str = ""
    matched: str = ""
    detail: str = ""

    def __bool__(self) -> bool:
        return self.confirmed


class Judge:
    """Turns responses into verdicts."""

    def __init__(self, baseline: bytes | None = None) -> None:
        self.baseline = (baseline or b"").decode("latin-1", "replace").lower()

    # ------------------------------------------------------------- signatures

    def signature(
        self,
        response: Response,
        signatures: Sequence[str],
        payload: str = "",
        original: str = "",
    ) -> Verdict:
        """Look for a signature that only a successful read or fetch produces."""
        # The payload is removed before any decoding, not after: a page that
        # echoes what it was given hands back the base64 blob the payload
        # carried, and decoding that blob produces the very string a signature
        # looks for. Stripping only the literal spelling misses it entirely and
        # the tool reports its own payload as a finding.
        cleaned = self.strip_payload(response.body, payload)
        if original:
            # An echo shows the payload where the page used to show the original
            # value. Taking the payload out leaves a hole there, and the response
            # still differs from the baseline - a comparison would call that a
            # change the target made. Putting the value back makes it read as the
            # page again, which is the point of knowing what the value was.
            cleaned = self.restore_echo(
                cleaned.decode("latin-1", "replace"), payload, original
            ).encode("latin-1", "replace")
        views = self.decoded_views(cleaned)
        cleaned_views = [self.strip_echo(view, payload).lower() for view in views]
        # A signature can be bytes rather than text: a class file answers with a
        # magic number, an archive with its own header, and both survive a
        # response that was decoded as text on the way out of the application.
        hex_view = cleaned.hex()
        for signature in signatures:
            needle = signature.lower()
            if needle in self.baseline:
                # The page says this for its own reasons.
                continue
            for view, text in zip(views, cleaned_views):
                if needle in text:
                    encoded = not _contains(response.text.lower(), needle)
                    return Verdict(
                        confirmed=True,
                        confidence=Confidence.CONFIRMED,
                        reason=f"signature present: {signature}",
                        matched=signature,
                        detail=(
                            "the page printed what it read through an encoding"
                            if encoded
                            else ""
                        ),
                    )
            if needle in hex_view:
                return Verdict(
                    confirmed=True,
                    confidence=Confidence.CONFIRMED,
                    reason=f"signature present in the bytes: {signature}",
                    matched=signature,
                    detail="the response carries what was read, byte for byte",
                )
        return Verdict(reason="no signature matched")

    def echo(self, response: Response, probe: str) -> Verdict:
        """The injected value came back verbatim, which proves reflection."""
        needle = probe.lower()
        if needle and needle in self.baseline:
            return Verdict(reason="the value is already in the baseline")
        if needle and needle in response.text.lower():
            return Verdict(
                confirmed=True,
                confidence=Confidence.LIKELY,
                reason="the value is reflected verbatim",
                matched=probe,
            )
        return Verdict(reason="the value was not reflected")

    # -------------------------------------------------------------- refusals

    def refused(self, response: Response) -> bool:
        """Whether a response looks like something refused the request."""
        if response.error or response.status >= 500 and response.status != 501:
            # An origin error is a crash, not a refusal.
            return False
        if response.status in REFUSAL_STATUSES:
            return True
        body = response.text.lower()
        return any(marker in body for marker in REFUSAL_MARKERS)

    # ---------------------------------------------------------------- timing

    def timing(
        self,
        samples: Sequence[float],
        expected: float,
        baseline_iqr: float = 0.0,
        min_signal: float = 0.15,
    ) -> Verdict:
        """Judge a delay by whether it is the delay that was asked for.

        Statistics, not a stopwatch. The median has to sit inside the band the
        payload requested - a request that took far longer than asked is
        measuring something else, such as another probe holding the connection -
        and it has to stand well outside the target's own variation.
        """
        if not samples:
            return Verdict(reason="no timing samples")
        median = statistics.median(samples)
        if median < max(min_signal, expected * 0.6):
            return Verdict(reason=f"median {median:.3f}s is below the requested delay")
        if median > expected * 1.6:
            return Verdict(reason=f"median {median:.3f}s is far above the requested delay")
        spread = _iqr(list(samples))
        threshold = max(3 * max(baseline_iqr, spread), min_signal)
        if median - (baseline_iqr or 0.0) < threshold:
            return Verdict(reason="the delay is inside the target's own variation")
        return Verdict(
            confirmed=True,
            confidence=Confidence.LIKELY,
            reason=f"median delay {median:.3f}s against requested {expected:.3f}s",
            matched=f"{median:.3f}s",
        )

    # --------------------------------------------------------------- decoding

    @staticmethod
    def decoded_views(body: bytes) -> list[str]:
        """Every reasonable reading of a body: raw plus common encodings."""
        text = body.decode("latin-1", "replace")
        views = [text, unquote(text), html.unescape(text)]

        for blob in _BASE64_BLOB.findall(body):
            try:
                decoded = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            candidate = decoded.decode("utf-8", "replace")
            if candidate.isprintable() and len(candidate) > 4:
                views.append(candidate)

        stripped = text.strip()
        if re.fullmatch(r"[0-9a-fA-F\s]{16,}", stripped):
            try:
                views.append(bytes.fromhex(re.sub(r"\s", "", stripped)).decode("utf-8", "replace"))
            except ValueError:
                pass
        return views

    @staticmethod
    def strip_payload(body: bytes, payload: str) -> bytes:
        """Remove the payload, and anything it carried, before decoding.

        Both spellings matter: the raw one, and any base64 blob inside it. A
        payload like `data://text/plain;base64,PD9waHA...` echoes back as the
        blob, and decoding that blob yields text a signature would match - the
        tool proving its own input rather than the target's behaviour.
        """
        if not payload:
            return body
        text = body.decode("latin-1", "replace")
        for spelling in Judge._spellings(payload):
            text = text.replace(spelling, "")
        for blob in re.findall(r"[A-Za-z0-9+/=]{12,}", payload):
            text = text.replace(blob, "")
        return text.encode("latin-1", "replace")

    @staticmethod
    def _spellings(payload: str) -> list[str]:
        """The forms a payload can come back in, longest first, without repeats.

        What was sent, what it is as a percent-encoded value, and a decoding of
        that. The encoded form is the one most often missed, and the one a page
        that prints a query string back produces.
        """
        out: list[str] = []
        for candidate in (payload, quote(payload, safe=""), unquote(payload)):
            if candidate and candidate not in out:
                out.append(candidate)
        return sorted(out, key=len, reverse=True)

    @staticmethod
    def strip_echo(text: str, payload: str) -> str:
        """Remove the injected value, so its own echo is not mistaken for proof.

        The payload may come back as it was sent, percent-encoded, or split
        across markup, so every spelling is removed before matching.
        """
        if not payload:
            return text
        spellings = Judge._spellings(payload)
        spellings += [payload.replace("\r\n", ""), payload.replace("\r\n", " ")]
        out = text
        for spelling in sorted({s for s in spellings if s}, key=len, reverse=True):
            out = out.replace(spelling, "")
        return out

    @staticmethod
    def restore_echo(text: str, payload: str, original: str = "") -> str:
        """Put the page's own value back where the payload is.

        Removing an echo is not the same as undoing one. A page that prints the
        parameter straight back shows the payload where it used to show the
        original value, so deleting the payload leaves that spot empty and the
        response still differs from the baseline - a comparison then reports a
        change the target never made. Substituting the original value back makes
        an echo read as the page again, leaving only a real difference.

        Longest spelling first, for the same reason a substitution table is
        ordered that way: a short spelling must not consume part of a longer one.
        """
        if not payload:
            return text
        out = text
        for spelling in Judge._spellings(payload):
            out = out.replace(spelling, original)
        return out


def _contains(haystack: str, needle: str) -> bool:
    return needle in haystack


def _iqr(values: list[float]) -> float:
    if len(values) < 4:
        return 0.0
    ordered = sorted(values)
    half = len(ordered) // 2
    return statistics.median(ordered[half:]) - statistics.median(ordered[:half])


def best_signature(response: Response, signatures: Iterable[str]) -> str:
    """First signature present in a body, ignoring case. Kept for callers that
    only need the match, not the verdict."""
    text = response.text.lower()
    for signature in signatures:
        if signature.lower() in text:
            return signature
    return ""
