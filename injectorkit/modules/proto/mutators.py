"""Rewrites that only matter for a wrapper string.

The core's mutators change how a value is transported - encoding, case, CRLF -
and they apply to anything. These are about how a wrapper is spelled to a parser
that is looking for the usual form of it: a filter that knows
`php://filter/convert.base64-encode/resource=` is defeated by a spelling that
means the same to PHP and nothing to the rule, and there are several.

Registered at import time; the module's `__init__` imports this file.
"""

from __future__ import annotations

import re

from ...core.mutate import Kind, Mutator, register


def _alternate_case_in_scheme(value: str) -> str:
    """php:// -> pHp://, leaving the rest of the string alone."""
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", value)
    if not match:
        return value
    scheme = match.group(1)
    flipped = "".join(char.upper() if index % 2 else char.lower() for index, char in enumerate(scheme))
    return flipped + value[len(scheme):]


def _extra_slashes(value: str) -> str:
    """php://filter -> php:///filter: the same path to a normalising parser."""
    return value.replace("://", ":///", 1)


def _drop_resource_keyword(value: str) -> str:
    """The implicit form: `php://filter/<filters>/<path>` with no `resource=`."""
    return value.replace("/resource=", "/", 1)


def _space_the_filter(value: str) -> str:
    """A space where a filter's argument would be, which parsers tolerate."""
    return value.replace("/convert.", "/ convert.", 1)


def _double_filter_name(value: str) -> str:
    """Write the filter twice: a rule that strips one occurrence leaves a valid one."""
    return value.replace("convert.base64-encode", "convert.convert.base64-encode", 1)


PROTO_MUTATORS: tuple[Mutator, ...] = (
    # The scheme is case-insensitive to PHP; it may not be to the rule.
    Mutator("wrapper-scheme-case", _alternate_case_in_scheme, (Kind.PROTOCOL,), family="wrapper", weight=12),
    # php://filter -> php:///filter: the same path to a normalising parser.
    Mutator("wrapper-extra-slash", _extra_slashes, (Kind.PROTOCOL,), family="wrapper", weight=13),
    # The `resource=` keyword is optional; a rule looking for it is not.
    Mutator("wrapper-implicit-resource", _drop_resource_keyword, (Kind.PROTOCOL,), family="wrapper", weight=14),
    Mutator("wrapper-filter-space", _space_the_filter, (Kind.PROTOCOL,), family="wrapper", weight=15),
    # Written twice, so a rule that strips one occurrence leaves a working one.
    Mutator("wrapper-double-filter", _double_filter_name, (Kind.PROTOCOL,), family="wrapper", weight=16),
)

register(*PROTO_MUTATORS)
