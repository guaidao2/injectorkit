"""The phar builder: byte layout, and the signature PHP actually checks.

Checked here rather than only against a live PHP, because the failures are
silent ones. A manifest length that is off, or a trailer with one field too
many, produces an archive that some tools open and PHP refuses - and PHP's
refusal reads as "the target would not include my file" rather than as a
builder bug.

`manifest()` returns four length bytes followed by the body it describes; the
tests below keep that prefix in mind rather than pretending it is not there.
"""

from __future__ import annotations

import hashlib
import struct
import unittest
import zlib

from injectorkit.core.phar import (
    API_VERSION,
    DEFAULT_STUB,
    SIGNATURE_END,
    SIGNATURE_SHA1,
    build,
    manifest,
    php_object,
    php_serialize_string,
)


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


class Stub(unittest.TestCase):
    def test_the_default_stub_halts_the_compiler(self):
        self.assertIn(b"__HALT_COMPILER();", build([("a.php", b"x")]))

    def test_a_stub_without_the_marker_is_replaced(self):
        out = build([("a.php", b"x")], stub=b"<?php echo 1; ?>")
        self.assertIn(b"__HALT_COMPILER();", out)

    def test_the_manifest_follows_the_stub_immediately(self):
        stub = b"<?php __HALT_COMPILER(); ?>\r\n"
        out = build([("a.php", b"x")], stub=stub)
        self.assertEqual(u32(out, len(stub)), len(manifest([("a.php", b"x")], b"")) - 4)


class ManifestLayout(unittest.TestCase):
    """Four length bytes, then: count, api version, flags, alias, metadata."""

    def full(self) -> bytes:
        return manifest([("index.php", b"<?php echo 1;")], b"")

    def body(self) -> bytes:
        return self.full()[4:]

    def test_the_length_prefix_counts_everything_after_it(self):
        full = self.full()
        self.assertEqual(u32(full, 0), len(full) - 4)

    def test_the_count_comes_first(self):
        self.assertEqual(u32(self.body(), 0), 1)

    def test_the_api_version_is_two_bytes(self):
        # Four here is the mistake that makes PHP refuse the archive outright.
        self.assertEqual(u16(self.body(), 4), API_VERSION)

    def test_the_signature_flag_is_set(self):
        self.assertEqual(u32(self.body(), 6), 0x00010000)

    def test_the_alias_is_empty_and_length_prefixed(self):
        body = self.full()[4:]
        self.assertEqual(u32(body, 10), 0)

    def test_the_metadata_is_length_prefixed(self):
        blob = b's:3:"abc";'
        body = manifest([("a.php", b"x")], blob)[4:]
        self.assertEqual(u32(body, 14), len(blob))
        self.assertEqual(body[18:18 + len(blob)], blob)

    def test_every_entry_names_itself(self):
        self.assertIn(b"index.php", self.body())

    def test_the_entry_carries_a_crc_of_its_content(self):
        content = b"<?php echo 1;"
        full = manifest([("a.php", content)], b"")
        self.assertIn(struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF), full)


class ContentOrder(unittest.TestCase):
    def test_the_content_starts_after_the_manifest_ends(self):
        content = b"<?php echo 'entry';"
        out = build([("index.php", content)])
        manifest_end = len(DEFAULT_STUB) + 4 + u32(out, len(DEFAULT_STUB))
        self.assertGreaterEqual(out.index(content), manifest_end)

    def test_several_entries_are_written_in_manifest_order(self):
        out = build([("a.php", b"AAA"), ("b.php", b"BBB")])
        self.assertLess(out.index(b"AAA"), out.index(b"BBB"))


class Trailer(unittest.TestCase):
    """Digest, algorithm, magic - and no length field."""

    def out(self) -> bytes:
        return build([("a.php", b"x")])

    def test_it_ends_with_the_magic(self):
        self.assertTrue(self.out().endswith(SIGNATURE_END))

    def test_the_algorithm_sits_between_digest_and_magic(self):
        out = self.out()
        self.assertEqual(u32(out, len(out) - 8), SIGNATURE_SHA1)

    def test_the_trailer_is_exactly_the_digest_the_algorithm_and_the_magic(self):
        out = self.out()
        self.assertEqual(len(SIGNATURE_END), 4)
        self.assertEqual(out[-8:-4], struct.pack("<I", SIGNATURE_SHA1))
        self.assertEqual(len(out[-28:-8]), 20, "sha1 digest")

    def test_the_digest_covers_everything_before_it(self):
        out = self.out()
        self.assertEqual(hashlib.sha1(out[:-28]).digest(), out[-28:-8])

    def test_changing_the_metadata_changes_the_digest(self):
        self.assertNotEqual(
            build([("a.php", b"x")], metadata=b's:1:"a";')[-28:-8],
            build([("a.php", b"x")], metadata=b's:1:"b";')[-28:-8],
        )


class MetadataSerialisation(unittest.TestCase):
    def test_a_string_is_written_the_way_php_reads_it(self):
        self.assertEqual(php_serialize_string("abc"), b's:3:"abc";')

    def test_a_multibyte_string_counts_bytes_not_characters(self):
        self.assertEqual(len(php_serialize_string("é")), len(b's:2:"\xc3\xa9";'))

    def test_an_object_counts_its_properties(self):
        self.assertEqual(php_object("Cache", {"key": "v"}), b'O:5:"Cache":1:{s:3:"key";s:1:"v";}')

    def test_an_object_with_two_properties_keeps_their_order(self):
        blob = php_object("C", {"a": "1", "b": "2"})
        self.assertLess(blob.index(b'"a"'), blob.index(b'"b"'))

    def test_the_metadata_lands_in_the_archive(self):
        blob = php_object("Cache", {"path": "/tmp/x"})
        self.assertIn(blob, build([("a.php", b"x")], metadata=blob))


if __name__ == "__main__":
    unittest.main()
