"""Where the application keeps its files, worked out rather than asked for.

Writing a file to someone's server needs a path, and asking the operator to type
one turns a tool into a form. The path is usually already known: any file the run
managed to read tells us where something is, and a directory that holds a file
the application serves is a directory the application can probably write to.

Four sources, in the order sqlmap uses them, which is the order of how much they
can be trusted:

1. What the operator said. A human who knows the target beats anything inferred.
2. A path the run already read. This is the good one - `/var/www/html/config.php`
   is not a guess about where the web root is, it is a statement that it is
   `/var/www/html/`. Nothing beats having seen a file.
3. Names that are the web root on a stock install, by operating system.
4. Nothing. Which is a result worth reporting rather than filling in with a
   guess, because a wrong path writes a file into a place the operator will
   never find and reports success.

The distinction that matters throughout: a path we saw is evidence, a path on a
list is a hypothesis. They are kept apart all the way to the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .blackboard import Confidence

# Where each server's distribution package puts the document root.
#
# One entry per package, because that is where the list comes from: a stock
# install of each of these is served from the path beside it, which is a fact
# about the package rather than a guess about a target. Anything an install has
# moved is answered by the server's own configuration, which is read before this
# list is fallen back on.
LINUX_ROOTS: tuple[str, ...] = (
    "/var/www/html",  # Apache and nginx, Debian and Ubuntu
    "/var/www",  # the parent most of them sit under
    "/usr/share/nginx/html",  # nginx, from its own package
    "/srv/www/htdocs",  # Apache, SUSE packaging
    "/usr/local/apache2/htdocs",  # Apache built from source
    "/var/www/nginx-default",  # nginx, older Debian packaging
    "/srv/www",  # the other parent
)

WINDOWS_ROOTS: tuple[str, ...] = (
    "C:/xampp/htdocs",
    "C:/wamp/www",
    "C:/Inetpub/wwwroot",
)

# Directory names that conventionally mark where a web root begins. A path
# containing one of these says what everything above it is, which is how an
# absolute path read off the target is turned into a guess about the root.
ROOT_MARKERS: tuple[str, ...] = (
    "htdocs",
    "wwwroot",
    "webroot",
    "public_html",
    "www",
    "html",
)

# Where an application's own path shows up on a stock install.
MARKER_FILES: tuple[str, ...] = (
    "index.php",
    "index.html",
    "config.php",
    "app.php",
)

# Extensions whose directory is worth a look. Kept short on purpose: this is a
# hypothesis list, and every entry in it costs a request to test.
WRITABLE_CANDIDATES: tuple[str, ...] = (
    "uploads",
    "upload",
    "files",
    "tmp",
    "temp",
    "cache",
    "images",
    "img",
    "assets",
    "data",
    "logs",
)


@dataclass
class RootGuess:
    """One candidate directory, and how it was arrived at."""

    path: str
    source: str
    # True when a file was actually seen under this path. A guess from a list is
    # not the same claim, and the difference decides how it is reported.
    observed: bool = False


@dataclass
class Roots:
    """Every candidate, best first, with what is known about each."""

    guesses: list[RootGuess] = field(default_factory=list)
    # Paths the run read, which is what the guesses were derived from.
    seen: list[str] = field(default_factory=list)

    def best(self) -> RootGuess | None:
        return self.guesses[0] if self.guesses else None

    def paths(self) -> list[str]:
        return [guess.path for guess in self.guesses]

    def add(self, path: str, source: str, observed: bool = False, first: bool = False) -> None:
        """Add a candidate. `first` puts it at the front of the queue.

        Order is the whole value here: the candidates are tried one at a time
        until one works, so a directory derived from evidence has to sit ahead of
        one that came off a list, and `first` is how a caller that knows it has
        something better says so.
        """
        path = _tidy(path)
        if not path or path == "/":
            return
        for index, existing in enumerate(self.guesses):
            if existing.path.lower() == path.lower():
                if observed and not existing.observed:
                    existing.observed = True
                    existing.source = source
                if first and index > 0:
                    self.guesses.insert(0, self.guesses.pop(index))
                return
        entry = RootGuess(path=path, source=source, observed=observed)
        if first:
            self.guesses.insert(0, entry)
        else:
            self.guesses.append(entry)

    def describe(self) -> str:
        if not self.guesses:
            return "the web root was not established"
        best = self.guesses[0]
        how = "was read from" if best.observed else "is a common location for"
        extra = "" if len(self.guesses) == 1 else f"; {len(self.guesses) - 1} other(s) to try"
        return f"the web root {how} this target: {best.path} ({best.source}){extra}"


# Config files that state where the application is served from. A server's own
# configuration is the authority on this - better than any list of guesses - and
# it is often readable by the user the application runs as, because that is the
# user the server itself writes logs and caches as.
CONFIG_PATHS: tuple[str, ...] = (
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/apache2/sites-enabled/default.conf",
    "/etc/apache2/sites-enabled/default-ssl.conf",
    "/etc/apache2/sites-available/000-default.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/conf.d/default.conf",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d/vhost.conf",
    "/usr/local/apache2/conf/httpd.conf",
    "/etc/lighttpd/lighttpd.conf",
    "/etc/caddy/Caddyfile",
)

# `DocumentRoot /var/www/html` in an Apache vhost, `root /var/www/html;` in an
# nginx server block. Anchored loosely because the directive may be indented and
# may carry trailing punctuation.
_CONF_ROOT = re.compile(
    r"^\s*(?:DocumentRoot|root)\s+[\"']?([A-Za-z]:)?(/[A-Za-z0-9_./-]+)",
    re.I | re.M,
)


def webroot_from_config(text: str) -> list[str]:
    """Directories a server's own configuration says it serves.

    This is the strongest source there is short of the operator saying so: it is
    not an inference about where a file might live, it is the server stating
    which directory it answers from. A run that has read one config file has
    finished guessing.
    """
    if not text:
        return []
    out: list[str] = []
    for match in _CONF_ROOT.finditer(text):
        drive = match.group(1) or ""
        candidate = _tidy(drive + match.group(2))
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _tidy(path: str) -> str:
    """One spelling of a directory path, so two spellings are one candidate."""
    path = (path or "").strip().replace("\\", "/")
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _is_windows(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:", path))


def roots_from_file(path: str) -> list[str]:
    """Every directory above a file that could be a web root.

    A single path is not one answer. `/var/www/html/app/public/index.php` could
    be served from any of those directories, and which one it is depends on a
    configuration nobody can see from here - so all of them are offered, deepest
    first, and each is cheap to test.
    """
    path = _tidy(path)
    windows = _is_windows(path)
    if not path.startswith("/") and not windows:
        return []

    drive = ""
    if windows:
        # `C:/xampp/htdocs/index.php` -> drive `C:`, the rest walked upward.
        drive, _, path = path.partition("/")
        path = "/" + path

    parts = path.strip("/").split("/")
    if len(parts) < 2:
        return []
    directories = parts[:-1]  # the last part is the file itself

    out: list[str] = []
    for depth in range(len(directories), 0, -1):
        joined = "/".join(directories[:depth])
        out.append(f"{drive}/{joined}" if drive else f"/{joined}")
    return out


def roots_from_marker(path: str) -> list[str]:
    """The part of a path up to and including a directory that names a web root.

    `/var/www/html/config.php` contains `html`, and everything up to it is the
    web root. This is the rule sqlmap splits on, and it is a better guess than
    walking up one level at a time because it knows which names matter.
    """
    path = _tidy(path)
    if not path:
        return []
    lowered = path.lower()
    best = ""
    for marker in ROOT_MARKERS:
        for separator in (f"/{marker}/", f"/{marker}."):
            index = lowered.find(separator)
            if index != -1:
                candidate = path[: index + len(marker) + 1].rstrip("/")
                if len(candidate) > len(best):
                    best = candidate
    return [best] if best else []


def guess_roots(
    seen_paths: list[str] | None = None,
    operator_said: str = "",
    windows: bool = False,
) -> Roots:
    """Every web root worth trying, best first.

    `seen_paths` are absolute paths the run managed to read. Anything derived
    from one of those is marked observed: it is not a guess about where the web
    root is, it is what a file that was actually read says about it.
    """
    roots = Roots(seen=list(seen_paths or []))

    if operator_said:
        roots.add(operator_said, "the operator named it", observed=True)

    for path in seen_paths or []:
        for marker_root in roots_from_marker(path):
            roots.add(marker_root, f"a file was read under it ({path})", observed=True)
        for candidate in roots_from_file(path):
            # Only the ones that could plausibly be a document root; the whole
            # path list would include `/var`, which is not worth a request.
            if any(part.lower() in ROOT_MARKERS for part in candidate.split("/")):
                roots.add(candidate, f"a file was read under it ({path})", observed=True)

    for stock in (WINDOWS_ROOTS if windows else LINUX_ROOTS):
        roots.add(stock, "a stock install puts it here")

    return roots


def command_roots(shell_evidence: str) -> list[str]:
    """Web roots named in a command's own output.

    Anything that ran a command on the target can be asked where the application
    lives, and the answer - a directory listing, an environment variable, a
    config file - often says so outright. This pulls absolute paths out of text
    and keeps the ones that look like a document root.
    """
    found: list[str] = []
    for match in re.finditer(r"(?:^|[\s\"'=(:])(/[A-Za-z0-9_./-]{3,})", shell_evidence or ""):
        candidate = match.group(1)
        if any(part.lower() in ROOT_MARKERS for part in candidate.split("/")):
            found.append(_tidy(candidate))
    return found


# Where the run records files it managed to read. On the blackboard so that one
# module's reads inform another's writes: the path a file was read from is not
# proto knowledge or ssrf knowledge, it is something about the target, and the
# module that writes a file is often not the module that read one.
READ_PATHS = "target.paths.read"

# Web roots stated by the server's own configuration, once the run has read any
# of it. Kept apart from READ_PATHS because these are not paths that were read -
# they are what the configuration said to serve, which is a stronger claim.
STATED_ROOTS = "target.paths.webroot"


def note_read(board, path: str, body: str = "") -> None:
    """Record a path the run read, and any web root its contents state.

    The body is scanned as well as the path remembered, because a config file
    names the web root in its text and that is the one source that settles the
    question - a server saying which directory it serves is not a guess about
    where files live.
    """
    if path and path.startswith("/"):
        # An observation, not an inference: this is only reached for a wrapper
        # that reads, and it got an answer. Labelling it inconclusive by taking
        # the default put "why is this doubtful?" beside a path whose contents
        # are printed further down the same report.
        board.add(
            READ_PATHS,
            _tidy(path),
            evidence="the run read this path",
            confidence=Confidence.CONFIRMED,
        )
    for stated in webroot_from_config(body):
        board.add(STATED_ROOTS, stated)


def roots_for_run(board, operator_said: str = "", windows: bool = False) -> Roots:
    """Every web root worth trying, from what this run has already seen.

    The board is the source, not the module: a path read by one class of check
    says just as much about where the application lives as one read by another,
    and the reads happen wherever the reads happen to succeed.
    """
    seen = board.get(READ_PATHS) or []
    if isinstance(seen, str):
        seen = [seen]
    roots = guess_roots(seen_paths=list(seen), operator_said=operator_said, windows=windows)

    # Anything the server's configuration stated goes to the front, ahead even of
    # paths derived from reads: a directory a server says it serves is not an
    # inference about where a file might be.
    for stated in reversed(list(board.get(STATED_ROOTS) or [])):
        roots.add(stated, "the server's own configuration names it", observed=True, first=True)
    return roots
