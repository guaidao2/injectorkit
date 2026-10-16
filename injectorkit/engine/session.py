"""Where a run's progress is kept between runs, and how it is found again.

A scan that forgets everything between invocations repeats its own work: the
same target, the same pages, the same refusals, every time. What a previous run
learned belongs next to the target it was learned on, found automatically rather
than named by hand - a scan is run again far more often than it is run with a
file path in mind.

Keyed by host and path, the way the reference tool keys its own session store.
The parameter set is deliberately not part of the key: the board is a map from
key to fact, and a fact recorded under `ssrf.fetch.confirmed` means the same
thing whether it was reached through one parameter or another.
"""

from __future__ import annotations

import os
import re
import shutil
from urllib.parse import urlsplit

# Beside the working directory rather than in a home directory: a scan's notes
# belong with the scan, and this project already keeps its state under
# .injectorkit/, which is in .gitignore.
ROOT = os.path.join(".injectorkit", "sessions")


def _safe(text: str) -> str:
    """A path component that keeps a host or path readable but harmless.

    Anything that is not a letter, digit, dot, dash or underscore becomes an
    underscore, runs of dots collapse, and leading and trailing punctuation is
    dropped. A component therefore cannot be empty, cannot be `.`, and cannot be
    `..` - which is what stops a hostile path from climbing out of the session
    directory, and what makes a name like `example.test` survive intact.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    cleaned = re.sub(r"\.{2,}", "_", cleaned)
    return cleaned.strip("._-") or "index"


def target_dir(url: str) -> str:
    """The directory a target's progress lives in: one per host."""
    host = urlsplit(url).netloc or url
    return os.path.join(ROOT, _safe(host))


def session_path(url: str) -> str:
    """The file one page's progress lives in."""
    parts = urlsplit(url)
    return os.path.join(target_dir(url), _safe(parts.path) + ".json")


def load(url: str) -> str | None:
    """What a previous run on this page learned, if anything."""
    path = session_path(url)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def save(url: str, text: str) -> bool:
    """Keep this page's progress for the next run."""
    path = session_path(url)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        return False
    return True


def filter_path(url: str) -> str:
    """Where what this host does to filtered input is kept."""
    return os.path.join(target_dir(url), "filters.json")


def load_filters(url: str) -> str | None:
    """What earlier runs learned about this host's filters, if anything."""
    try:
        with open(filter_path(url), "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def save_filters(url: str, text: str) -> bool:
    """Keep it for the next run."""
    path = filter_path(url)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        return False
    return True


def flush(url: str) -> bool:
    """Forget everything a previous run learned about this host.

    The whole host rather than one page: an operator asking for a fresh start on
    a target means the target, and leaving half of its notes behind is the kind
    of half-state that makes a later answer hard to trust.
    """
    directory = target_dir(url)
    if not os.path.isdir(directory):
        return False
    shutil.rmtree(directory, ignore_errors=True)
    return True
