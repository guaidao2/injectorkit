#!/usr/bin/env python3
"""Internal services for the InjectorKit lab.

Stands up the things an SSRF is supposed to reach and that live on the target's
own network - a cloud metadata endpoint, a Docker API, etcd, Elasticsearch,
Consul, a memcached, and a PHP-FPM socket stand-in. Redis is a real server and
is started by setup.sh instead.

The Docker/etcd/Consul answers are deliberately minimal: they exist so that a
fingerprint check has something with the right shape to recognise, not to be a
faithful implementation.
"""

from __future__ import annotations

import json
import signal
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND_METADATA = ("169.254.169.254", 80)

METADATA = """ami-id
i-0a1b2c3d4e5f
ami-launch-index
0
instance-id
i-0a1b2c3d4e5f
instance-type
t3.micro
local-hostname
lab-instance
reservation-id
r-0123456789abcdef0
security-groups
default
"""

CREDENTIALS = '{"Code":"Success","AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"lab-session-token"}'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload: bytes = b"ok"
    content_type = "text/plain"

    def do_GET(self) -> None:  # noqa: N802
        body = self.payload
        status = 200
        if self.server.name == "metadata":  # type: ignore[attr-defined]
            body, status = self._metadata()
        self.send_response(status)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _metadata(self) -> tuple[bytes, int]:
        """Answer like the providers do, headers included.

        GCP and Azure refuse a request that arrives without their magic header,
        which is the whole reason a plain URL cannot reach them and a request
        written over gopher can. AWS is left open here so the plain-URL path
        keeps working as a baseline.
        """
        path = self.path.split("?", 1)[0]
        if path.startswith("/computeMetadata/"):
            if self.headers.get("Metadata-Flavor") != "Google":
                return b"Missing Metadata-Flavor:Google header.", 403
            return b"project/project-id\nlab-project\ninstance/hostname\nlab-instance\n", 200
        if path.startswith("/metadata/instance"):
            if (self.headers.get("Metadata") or "").lower() != "true":
                return b"Required metadata header not specified", 400
            return b'{"compute":{"vmName":"lab-vm","subscriptionId":"00000000-lab"}}', 200
        if "iam/security-credentials" in path:
            return CREDENTIALS.encode(), 200
        if path.startswith("/latest/user-data"):
            return b"#cloud-config\nruncmd:\n  - echo lab\n", 200
        return METADATA.encode(), 200

    do_POST = do_GET

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def serve(name: str, host: str, port: int, payload: bytes, content_type: str = "text/plain") -> ThreadingHTTPServer | None:
    handler = type("H", (Handler,), {"payload": payload, "content_type": content_type})
    try:
        server = ThreadingHTTPServer((host, port), handler)
    except OSError as error:
        print(f"  {name:9s} UNAVAILABLE {host}:{port} ({error})", flush=True)
        return None
    server.name = name  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"  {name:9s} http://{host}:{port}", flush=True)
    return server


def raw_service(name: str, host: str, port: int, reply: bytes) -> socket.socket | None:
    """A bare TCP service: reply to whatever is sent, then close."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((host, port))
    except OSError as error:
        print(f"  {name:9s} UNAVAILABLE {host}:{port} ({error})", flush=True)
        listener.close()
        return None
    listener.listen(16)

    def loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2.0)
                    try:
                        conn.recv(4096)
                    except socket.timeout:
                        pass
                    conn.sendall(reply)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    print(f"  {name:9s} tcp  {host}:{port}", flush=True)
    return listener


def main() -> int:
    print("internal services:", flush=True)
    servers = [
        server
        for server in (
            serve("metadata", *BIND_METADATA, b"", "text/plain"),
            serve("docker", "127.0.0.1", 2375, json.dumps({"ApiVersion": "1.43", "GitCommit": "lab", "Os": "linux"}).encode(), "application/json"),
            serve("etcd", "127.0.0.1", 2379, json.dumps({"etcdserver": "3.5.9", "etcdcluster": "3.5.0"}).encode(), "application/json"),
            serve("kubelet", "127.0.0.1", 10255, json.dumps({"kind": "PodList", "items": []}).encode(), "application/json"),
            serve("elastic", "127.0.0.1", 9200, json.dumps({"cluster_name": "lab", "version": {"number": "8.6.0", "lucene_version": "9.4.2"}}).encode(), "application/json"),
            serve("consul", "127.0.0.1", 8500, json.dumps({"Config": {"Datacenter": "dc1"}, "Member": {"Name": "lab"}}).encode(), "application/json"),
            serve("adminpanel", "127.0.0.1", 8899, b"internal admin panel\n", "text/plain"),
        )
        if server is not None
    ]
    listeners = [
        listener
        for listener in (
            raw_service("memcached", "127.0.0.1", 11211, b"STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT cmd_get 0\r\nEND\r\n"),
        )
        if listener is not None
    ]

    def stop(*_: object) -> None:
        for server in servers:
            server.shutdown()
        for listener in listeners:
            listener.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print("ready", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
