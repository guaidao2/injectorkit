"""Interactsh: interactions collected by somebody else's server.

The listener this engine can start works only when the target can reach it. On a
laptop behind NAT, or against anything on the public internet, a target that
runs `curl http://10.0.0.5:8081/...` gets nowhere, and the finding that comes
back says nothing about the payload. A public or self-hosted interactsh
deployment removes that condition: the callback name resolves from anywhere, the
interaction is collected on the far side, and this client fetches it.

The trade is that the traffic leaves the operator's machine, so a deployment is
never chosen for them: a server has to be named explicitly, and without one
out-of-band testing stays off.

This is the exchange projectdiscovery/interactsh speaks:

1. generate an RSA key pair, and register its public half together with a
   correlation id and a secret at POST /register
2. callback names are <label>.<correlation-id>.<server>, which the deployment
   resolves for every name without a second registration
3. GET /poll?id=<correlation-id>&secret=<secret> returns the interactions, each
   record encrypted with a fresh AES key that is itself returned RSA-encrypted
   (AES-GCM, 12-byte nonce prepended)

Nothing here is bespoke: it is what the reference client does.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from typing import Callable

# The one third-party dependency, and it is only for this file. Loading it
# defensively means a missing install costs the out-of-band backend rather than
# the whole tool: a run against a directly reachable target needs no callbacks
# and no cryptography, and should not fail to start because of either.
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_CRYPTO = True
    CRYPTO_ERROR = ""
except ImportError as error:  # pragma: no cover - depends on the environment
    HAVE_CRYPTO = False
    CRYPTO_ERROR = str(error)
    hashes = serialization = padding = rsa = None  # type: ignore[assignment]
    Cipher = algorithms = modes = AESGCM = None  # type: ignore[assignment]

from .oob import Interaction

# Public deployments people commonly use. Listing them is not a preference:
# whichever one is named is the one that sees the traffic.
KNOWN_SERVERS = (
    "oast.pro",
    "oast.fun",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "interactsh.com",
)

# The least time between two network polls. Several actions wait at once, and
# without a floor each waiting action would become a poll per iteration; the
# deployment would see a flood for an answer that only changes when somebody's
# resolver gets round to it.
MIN_POLL_INTERVAL = 2.0

# A deployment validates the correlation id against the xid alphabet, so an id
# built from anything else registers successfully and then never has an
# interaction attributed to it - the failure is silent, which is why it is worth
# spelling out here.
CORRELATION_ID_LENGTH = 20
XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"

# The callback name is <correlation-id><nonce>.<server>, the two run together
# with no separator. The nonce is what makes each callback name unique, and it
# is the part attributed back to the action that planted it.
NONCE_LENGTH = 13
ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_EXCHANGE_TIMEOUT = 20.0


class InteractshError(RuntimeError):
    """Raised when the deployment refuses registration or cannot be reached."""


class InteractshClient:
    """An interactsh deployment, seen through the same interface as a listener."""

    def __init__(
        self,
        server: str,
        token: str = "",
        timeout: float = _EXCHANGE_TIMEOUT,
        log: Callable[[str], None] | None = None,
        poll_interval: float = MIN_POLL_INTERVAL,
    ) -> None:
        self.server = _normalise(server)
        self.host = urllib.parse.urlsplit(self.server).hostname or ""
        self.token = token
        self.timeout = timeout
        self.log = log or (lambda message: None)
        self.poll_interval = poll_interval

        self.correlation_id = ""
        self.secret = ""
        self.suffix = ""
        # Kept for diagnostics: a deployment that answers 200 with something
        # other than a confirmation is worth being able to show.
        self.register_response = ""
        self._key: rsa.RSAPrivateKey | None = None
        self._tokens: set[str] = set()
        self._labels: dict[str, str] = {}
        self._seen: dict[str, list[Interaction]] = {}
        self._last_poll = 0.0

    # ---------------------------------------------------------------- control

    def start(self) -> "InteractshClient":
        """Register with the deployment.

        Done once, up front, rather than lazily: a server that is unreachable or
        refuses the key has to be reported before the run starts, not
        discovered as a series of payloads that could never have been answered.
        """
        if not HAVE_CRYPTO:
            raise InteractshError(
                "interactsh needs the cryptography package, which is not installed "
                f"({CRYPTO_ERROR}). Install it with: pip install cryptography"
            )

        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.correlation_id = _xid()
        self.secret = _random_string(32)
        self.suffix = f"{self.correlation_id}.{self.host}"

        pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        body = json.dumps(
            {
                "public-key": base64.b64encode(pem).decode("ascii"),
                "secret-key": self.secret,
                "correlation-id": self.correlation_id,
            }
        ).encode("ascii")

        response = self._request("/register", data=body, method="POST")
        self.register_response = response.decode("utf-8", "replace")
        if b'"error"' in response:
            raise InteractshError(f"{self.server} refused registration: {response[:200].decode('utf-8', 'replace')}")
        self.log(f"interactsh: registered with {self.server} as {self.suffix}")
        return self

    def stop(self) -> None:
        """Nothing to release: correlation ids expire on the deployment's side."""
        self._tokens.clear()

    def __enter__(self) -> "InteractshClient":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def running(self) -> bool:
        return bool(self.correlation_id and self._key is not None)

    # ----------------------------------------------------------------- tokens

    def new_url(self, label: str) -> tuple[str, str]:
        """Mint a callback name under this registration.

        The name is <correlation-id><nonce>.<server> with no separator, which is
        the shape a deployment attributes interactions by. The nonce is returned
        as the handle: when a callback arrives, that is what ties it to the
        action that planted it.
        """
        if not self.running:
            raise InteractshError("interactsh is not registered")
        nonce = _nonce()
        name = f"{self.correlation_id}{nonce}.{self.host}"
        self._tokens.add(nonce)
        self._labels[nonce] = label
        return f"http://{name}/", nonce

    # -------------------------------------------------------------- polling

    def poll(self, token: str) -> list[Interaction]:
        """Interactions recorded for a token; polling clears them."""
        if not token:
            return []
        self._refresh()
        return list(self._seen.pop(token, []))

    def wait(self, token: str, timeout: float | None = None, interval: float = 0.25) -> list[Interaction]:
        deadline = time.time() + (timeout if timeout is not None else 6.0)
        while time.time() < deadline:
            found = self.poll(token)
            if found:
                return found
            time.sleep(interval)
        return self.poll(token)

    def interactions(self) -> list[Interaction]:
        return [item for items in self._seen.values() for item in items]

    def _refresh(self) -> None:
        if not self.running:
            return
        now = time.time()
        if now - self._last_poll < self.poll_interval:
            return
        self._last_poll = now

        try:
            records = self._fetch()
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, InteractshError) as error:
            self.log(f"interactsh: poll failed: {error}")
            return

        if not records:
            return
        # A record names the callback it hit; matching the name back to the
        # token that planted it is what turns a callback into evidence for one
        # specific action. The match looks at the whole record, not the printed
        # detail: for an HTTP callback the name is in the Host header, and the
        # line a reader sees is the request line.
        for interaction in records:
            haystack = (interaction.raw or interaction.detail).lower()
            for token in self._tokens:
                if token.lower() in haystack:
                    attributed = replace(
                        interaction,
                        token=token,
                        label=self._labels.get(token, ""),
                    )
                    self._seen.setdefault(token, []).append(attributed)

    def _fetch(self) -> list[Interaction]:
        query = urllib.parse.urlencode({"id": self.correlation_id, "secret": self.secret})
        raw = self._request(f"/poll?{query}")
        if not raw:
            return []
        payload = json.loads(raw.decode("utf-8", "replace"))
        entries = payload.get("data") or []
        encoded_key = payload.get("aes_key") or ""
        if not entries or not encoded_key:
            return []

        key = self._decrypt_key(encoded_key)
        out: list[Interaction] = []
        for entry in entries:
            try:
                out.append(self._decode_record(key, entry))
            except (ValueError, KeyError, TypeError):
                # One unreadable record must not throw away the rest.
                continue
        return out

    # ------------------------------------------------------------- crypto

    def _decrypt_key(self, encoded: str) -> bytes:
        if self._key is None:
            raise InteractshError("interactsh has no key")
        raw = base64.b64decode(encoded)
        return self._key.decrypt(
            raw,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    @staticmethod
    def _decode_record(key: bytes, encoded: str) -> Interaction:
        raw = base64.b64decode(encoded)
        if len(raw) < 17:
            raise ValueError("interaction record is too short")
        # The record is a 16-byte IV followed by AES-CTR output. Older
        # deployments used AES-GCM with a 12-byte nonce, so that is tried as a
        # fallback rather than assuming one or the other.
        try:
            plain = _aes_ctr(key, raw)
        except (ValueError, UnicodeDecodeError):
            plain = _aes_gcm(key, raw)
        record = json.loads(plain.decode("utf-8", "replace"))
        return _to_interaction(record, encoded)

    # --------------------------------------------------------------- transport

    def _request(self, path: str, data: bytes | None = None, method: str = "GET") -> bytes:
        request = urllib.request.Request(self.server + path, data=data, method=method)
        request.add_header("User-Agent", "InjectorKit")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", self.token)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return response.read(1 << 20)
        except urllib.error.HTTPError as error:
            raise InteractshError(f"{self.server}{path} answered {error.code}: {error.read(200)!r}") from error
        except urllib.error.URLError as error:
            raise InteractshError(f"cannot reach {self.server}: {error.reason}") from error


def _aes_ctr(key: bytes, raw: bytes) -> bytes:
    """Decrypt one record: 16-byte IV, then the ciphertext."""
    decryptor = Cipher(algorithms.AES(key), modes.CTR(raw[:16])).decryptor()
    return decryptor.update(raw[16:]) + decryptor.finalize()


def _aes_gcm(key: bytes, raw: bytes) -> bytes:
    """The older shape: 12-byte nonce, then an authenticated ciphertext."""
    return AESGCM(key).decrypt(raw[:12], raw[12:], None)


def _to_interaction(record: dict, fallback: str) -> Interaction:
    """Map one decrypted record onto the engine's interaction shape."""
    protocol = record.get("protocol") or "dns"
    remote = record.get("remote-address") or record.get("smtp-from") or ""
    full_id = record.get("full-id") or record.get("unique-id") or ""

    detail = full_id
    raw_request = record.get("raw-request") or ""
    if protocol == "http":
        line = raw_request.split("\r\n", 1)[0] if raw_request else ""
        detail = line or full_id or fallback
    elif record.get("q-type"):
        detail = f"{full_id} ({record['q-type']})"
    if not detail:
        detail = fallback

    return Interaction(
        token="",
        label="",
        protocol=protocol,
        remote_addr=remote,
        detail=detail,
        at=time.time(),
        raw=json.dumps(record),
    )


def _normalise(server: str) -> str:
    server = (server or "").strip()
    if not server:
        raise InteractshError("no interactsh server was given")
    if "://" not in server:
        server = "https://" + server
    parsed = urllib.parse.urlsplit(server)
    if not parsed.hostname:
        raise InteractshError(f"interactsh server {server!r} has no host")
    return server.rstrip("/")


def _random_string(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def _xid() -> str:
    """A correlation id the way the reference client makes one.

    Only the alphabet is enforced by a deployment, but that is exactly the part
    that is easy to get wrong in a silent way: an id outside it registers fine
    and then never receives an interaction.
    """
    return "".join(secrets.choice(XID_ALPHABET) for _ in range(CORRELATION_ID_LENGTH))


def _nonce() -> str:
    return "".join(secrets.choice(ZBASE32_ALPHABET) for _ in range(NONCE_LENGTH))
