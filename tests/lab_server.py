"""A deliberately vulnerable echo of an SSRF endpoint, for local testing.

    python tests/lab_server.py 18080

It reads the `url` parameter and fetches it, which is exactly the bug the SSRF
class looks for. The answers are canned so the test does not depend on what
happens to be running on this machine, except for callback URLs, which it
really does request - that is what exercises the out-of-band path.
"""

from __future__ import annotations

import base64
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

FIXTURES = {
    "/etc/passwd": PASSWD,
    "/etc/hosts": b"127.0.0.1\tlocalhost\n::1\tip6-localhost\n",
    "index.php": b"<?php echo 'hello'; ?>",
    "c:/windows/win.ini": b"[fonts]\n[extensions]\nfor 16-bit app support\n",
}


def fetch(target: str) -> tuple[str, bytes]:
    """Mimic an application that fetches whatever it is handed."""
    if target.startswith("gopher://127.0.0.1:6379"):
        return "redis", b"+PONG\r\n"
    if target.startswith("gopher://127.0.0.1:11211"):
        return "memcached", b"STAT pid 1\r\nSTAT version 1.6.0\r\n"
    if target.startswith("gopher://127.0.0.1:9000"):
        return "fastcgi", b"Primary script unknown"
    if "169.254.169.254" in target:
        return "metadata", b"ami-id\ni-0abc123\ninstance-id\ni-0abc123\nlocal-hostname\nlab\n"
    if "100.100.100.200" in target:
        return "metadata", b"instance-id\ni-aliyun\nregion-id\ncn-hangzhou\n"
    if target.startswith("file://") or target.startswith("php://filter"):
        return "file", _read_local(target)
    if target.startswith("dict://"):
        return "dict", b"-ERR unknown command\n"
    if target.startswith("http://127.0.0.1:") or target.startswith("http://localhost:"):
        # A real callback: let it arrive so the listener can record it.
        try:
            with urllib.request.urlopen(target, timeout=3) as handle:  # noqa: S310
                return "fetched", handle.read(4096)
        except Exception as error:  # noqa: BLE001
            return "fetched", f"fetch error: {error}".encode()
    if "example.com" in target:
        return "fetched", b"<html><body>example</body></html>"
    return "error", b"invalid url"


def _read_local(target: str) -> bytes:
    if "base64-encode" in target:
        resource = target.split("resource=", 1)[-1]
        return base64.b64encode(_fixture(resource))
    path = unquote(target.split("://", 1)[-1])
    path = path.lstrip("/").replace("\\", "/")
    return _fixture(path)


def _fixture(path: str) -> bytes:
    normalized = "/" + path.replace("\\", "/").strip("/")
    for key, value in FIXTURES.items():
        if normalized.endswith("/" + key.replace("\\", "/").strip("/")):
            return value
    return b"failed to open stream: No such file or directory"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        query = parse_qs(urlparse(self.path).query)
        target = (query.get("url") or query.get("file") or [""])[0]
        if target:
            _, body = fetch(target)
        else:
            body = b'<html><a href="/fetch?url=http://example.com">fetch</a></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"lab target on http://127.0.0.1:{port}/fetch?url=...", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
