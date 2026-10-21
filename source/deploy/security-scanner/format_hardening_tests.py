#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Bounded format regressions; inert bytes only, never deserialize a model.

These are parser/control-flow tests, not real-antivirus acceptance. On Windows
the import-only shims do not implement process isolation or native scanning.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import socketserver
import stat
import struct
import sys
import tarfile
import types
import unittest
from unittest import mock
import zipfile


if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer

spec = importlib.util.spec_from_file_location("format_hardening_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def make_zip(entries, compress=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return output.getvalue()


def make_tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def raw_tar(records, tail=b"\x00" * 1024):
    output = io.BytesIO()
    for index, (kind, payload) in enumerate(records):
        info = tarfile.TarInfo("item-" + str(index))
        info.type, info.size = kind, len(payload)
        output.write(info.tobuf(format=tarfile.GNU_FORMAT))
        output.write(payload)
        output.write(b"\x00" * (-len(payload) % 512))
    output.write(tail)
    return output.getvalue()


def pax_record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while True:
        record = str(length).encode() + b" " + body
        if len(record) == length:
            return record
        length = len(record)


def raw_zip_directory(compressed=b"", method=zipfile.ZIP_STORED, crc=0):
    name = b"empty/"
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, method, 0, 0,
                        crc, len(compressed), 0, len(name), 0)
    directory = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, method, 0, 0,
                            crc, len(compressed), 0, len(name), 0, 0, 0, 0,
                            (stat.S_IFDIR | 0o755) << 16, 0) + name
    body = local + name + compressed
    footer = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1,
                         len(directory), len(body), 0)
    return body + directory + footer


def inspect(content, name, *, depth=0, **overrides):
    limits = scanner.limits_from_env()
    limits.update(overrides)
    inspector = scanner.StaticInspector(limits)
    inspector.inspect(io.BytesIO(content), name, depth)
    return inspector


class ArchivePreflightTests(unittest.TestCase):
    def test_nested_directory_count_rejected_before_zipinfo_allocation(self):
        content = make_zip([(f"directory-{index}/", b"") for index in range(4)])
        with mock.patch.object(scanner.zipfile, "ZipFile", side_effect=AssertionError("ZipInfo allocation reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
                inspect(content, "nested.zip", depth=1, max_members=3)

    def test_nested_lying_eocd_count_rejected_before_zipinfo_allocation(self):
        content = bytearray(make_zip([("a.txt", b"a"), ("b.txt", b"b")]))
        end = content.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(end, 0)
        struct.pack_into("<HH", content, end + 8, 1, 1)
        with mock.patch.object(scanner.zipfile, "ZipFile", side_effect=AssertionError("ZipInfo allocation reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "invalid_serialization"):
                inspect(bytes(content), "nested.zip", depth=1)

    def test_nested_large_directory_rejected_before_zipinfo_allocation(self):
        content = make_zip([("a" * 128 + ".txt", b"a")])
        with mock.patch.object(scanner, "MAX_DIRECTORY_BYTES", 64), \
                mock.patch.object(scanner.zipfile, "ZipFile", side_effect=AssertionError("ZipInfo allocation reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "expanded_bytes_limit"):
                inspect(content, "nested.zip", depth=1)

    def test_zip_directories_consume_global_entries(self):
        content = make_zip([("first/", b""), ("second/", b""), ("note.txt", b'{"note":"hello"}')])
        result = inspect(content, "directories.zip", max_members=3)
        self.assertEqual(result.members, 3)
        self.assertEqual(result.findings, [])
        with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
            inspect(content, "directories.zip", max_members=2)

    def test_nested_zip_uses_remaining_global_budget(self):
        child = make_zip([("inner/", b""), ("inner/note.txt", b'{"note":"hello"}')])
        content = make_zip([("outer/", b""), ("child.zip", child)])
        result = inspect(content, "outer.zip", max_members=4)
        self.assertEqual(result.members, 4)
        with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
            inspect(content, "outer.zip", max_members=3)

    def test_sibling_nested_zips_share_global_budget(self):
        child = make_zip([("inner/", b""), ("inner/note.txt", b'{"note":"hello"}')])
        content = make_zip([("first.zip", child), ("second.zip", child)])
        self.assertEqual(inspect(content, "outer.zip", max_members=6).members, 6)
        with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
            inspect(content, "outer.zip", max_members=5)

    def test_tar_directory_filler_cannot_bypass_global_limit(self):
        content = make_tar([(f"directory-{index}", None) for index in range(4)])
        with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
            inspect(content, "directories.tar", max_members=3)
        self.assertEqual(inspect(content, "directories.tar", max_members=4).members, 4)

    def test_tar_and_nested_zip_share_global_budget(self):
        child = make_zip([("inner/", b""), ("note.txt", b'{"note":"hello"}')])
        content = make_tar([("outer", None), ("child.zip", child)])
        self.assertEqual(inspect(content, "outer.tar", max_members=4).members, 4)
        with self.assertRaisesRegex(scanner.Incomplete, "archive_member_limit"):
            inspect(content, "outer.tar", max_members=3)

    def test_ordinary_compressed_and_stored_archives_remain_accepted(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                child = make_zip([("inner/readme.txt", b'{"note":"hello"}')], compressed)
                content = make_zip([("directory/", b""), ("child.zip", child)], compressed)
                result = inspect(content, "outer.zip")
                self.assertEqual(result.members, 3)
                self.assertEqual(result.findings, [])

    def test_empty_nested_zip_is_valid_at_zero_remaining_budget(self):
        content = make_zip([("empty.zip", make_zip([]))])
        result = inspect(content, "outer.zip", max_members=1)
        self.assertEqual(result.members, 1)
        self.assertEqual(result.findings, [])


class DirectoryPayloadTests(unittest.TestCase):
    def test_zip_directory_with_payload_is_incomplete(self):
        content = make_zip([("hidden/", b"cos\nsystem\n.")])
        with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_size$"):
            inspect(content, "hidden.zip")

    def test_zip_directory_symlink_and_special_modes_are_rejected(self):
        for kind, code in ((stat.S_IFLNK, "archive_symlink"),
                           (stat.S_IFIFO, "archive_link_or_special_file")):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                info = zipfile.ZipInfo("hidden/")
                info.external_attr = (kind | 0o777) << 16
                archive.writestr(info, b"")
            with self.subTest(kind=kind), self.assertRaisesRegex(scanner.Incomplete, "^" + code + "$"):
                inspect(output.getvalue(), "hidden.zip")

    def test_encrypted_zip_directory_is_rejected(self):
        content = bytearray(raw_zip_directory())
        central = content.find(b"PK\x01\x02")
        struct.pack_into("<H", content, 6, 1)
        struct.pack_into("<H", content, central + 8, 1)
        with self.assertRaisesRegex(scanner.Incomplete, "^encrypted_archive$"):
            inspect(bytes(content), "encrypted.zip")

    def test_exact_empty_stored_and_deflate_directory_streams_are_supported(self):
        cases = [(b"", zipfile.ZIP_STORED), (b"\x03\x00", zipfile.ZIP_DEFLATED),
                 (b"\x01\x00\x00\xff\xff", zipfile.ZIP_DEFLATED)]
        for content, method in cases:
            with self.subTest(method=method, compressed=content):
                result = inspect(raw_zip_directory(content, method), "directory.zip")
                self.assertEqual(result.members, 1)
                self.assertEqual(result.findings, [])

    def test_declared_empty_directory_cannot_hide_compressed_bytes(self):
        for content, method, crc in [(b".", zipfile.ZIP_STORED, 0),
                                     (b"\x03\x00junk", zipfile.ZIP_DEFLATED, 0),
                                     (b"\x00" * 33, zipfile.ZIP_DEFLATED, 0),
                                     (b"\x03\x00", zipfile.ZIP_DEFLATED, 1),
                                     (b"\xab\x00\x00", zipfile.ZIP_DEFLATED, 0)]:
            with self.subTest(compressed=content, method=method, crc=crc), self.assertRaises(scanner.Incomplete):
                inspect(raw_zip_directory(content, method, crc), "hidden.zip")

    def test_directory_local_header_cannot_disagree_with_central_size_or_crc(self):
        for offset in (14, 18, 22):
            content = bytearray(raw_zip_directory())
            struct.pack_into("<I", content, offset, 1)
            with self.subTest(offset=offset), self.assertRaisesRegex(scanner.Incomplete, "^invalid_serialization$"):
                inspect(bytes(content), "mismatch.zip")

    def test_tar_directory_with_payload_is_rejected_before_tarfile(self):
        content = raw_tar([(tarfile.DIRTYPE, b"cos\nsystem\n.")])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_size$"):
                inspect(content, "hidden.tar")


class TarPhysicalPreflightTests(unittest.TestCase):
    def test_dangling_extension_is_rejected_before_tarfile(self):
        for kind, payload in ((tarfile.XHDTYPE, pax_record(b"path", b"note.json")),
                              (tarfile.XGLTYPE, pax_record(b"comment", b"bounded")),
                              (tarfile.GNUTYPE_LONGNAME, b"note.json\x00")):
            content = raw_tar([(kind, payload)])
            with self.subTest(kind=kind), \
                    mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")), \
                    self.assertRaisesRegex(scanner.Incomplete, "^invalid_serialization$"):
                inspect(content, "dangling.tar")

    def test_pax_chain_is_bounded_before_tarfile_recursion(self):
        content = raw_tar([(tarfile.XHDTYPE, b"")] * 256 + [(tarfile.REGTYPE, b'{"note":1}')])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_limit$"):
                inspect(content, "chain.tar", max_members=256)

    def test_longname_chain_is_bounded_before_tarfile_recursion(self):
        content = raw_tar([(tarfile.GNUTYPE_LONGNAME, b"bounded-name\x00")] * 4
                          + [(tarfile.REGTYPE, b'{"note":1}')])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_limit$"):
                inspect(content, "chain.tar", max_members=4)

    def test_extension_bytes_are_bounded_before_tarfile_allocation(self):
        content = raw_tar([(tarfile.XHDTYPE, b"x" * (scanner.TAR_MAX_EXTENSION_BYTES + 1)),
                           (tarfile.REGTYPE, b'{"note":1}')])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^expanded_bytes_limit$"):
                inspect(content, "large-pax.tar")

    def test_global_metadata_bytes_share_remaining_expansion_budget(self):
        record = pax_record(b"comment", b"bounded")
        content = raw_tar([(tarfile.XGLTYPE, record), (tarfile.REGTYPE, b'{"note":1}')])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^expanded_bytes_limit$"):
                inspect(content, "metadata.tar", max_expanded_bytes=len(record) - 1)

    def test_pax_field_count_is_bounded(self):
        record = pax_record(b"comment", b"bounded") * (scanner.TAR_MAX_PAX_FIELDS + 1)
        content = raw_tar([(tarfile.XHDTYPE, record), (tarfile.REGTYPE, b'{"note":1}')])
        with mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")):
            with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_limit$"):
                inspect(content, "fields.tar")

    def test_layout_changing_and_sparse_metadata_are_unsupported(self):
        for key in (b"size", b"GNU.sparse.map", b"GNU.sparse.size", b"GNU.sparse.major",
                    b"SCHILY.realsize", b"SCHILY.filetype"):
            content = raw_tar([(tarfile.XHDTYPE, pax_record(key, b"1")),
                               (tarfile.REGTYPE, b'{"note":1}')])
            with self.subTest(key=key), self.assertRaisesRegex(scanner.Incomplete, "^unsupported_container_or_serialization$"):
                inspect(content, "sparse.tar")

    def test_gnu_sparse_and_special_headers_are_rejected_before_tarfile(self):
        for kind, code in ((tarfile.GNUTYPE_SPARSE, "unsupported_container_or_serialization"),
                           (tarfile.SYMTYPE, "archive_link_or_special_file"),
                           (tarfile.FIFOTYPE, "archive_link_or_special_file")):
            content = raw_tar([(kind, b"")])
            with self.subTest(kind=kind), \
                    mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")), \
                    self.assertRaisesRegex(scanner.Incomplete, "^" + code + "$"):
                inspect(content, "special.tar")

    def test_malformed_pax_record_has_fixed_failure(self):
        for record in (b"100 key=value\n", b"x key=value\n", b"12 key=oops!", b"8 key\n"):
            content = raw_tar([(tarfile.XHDTYPE, record), (tarfile.REGTYPE, b'{"note":1}')])
            with self.subTest(record=record), self.assertRaisesRegex(scanner.Incomplete, "^invalid_serialization$"):
                inspect(content, "malformed.tar")

    def test_bad_checksum_and_truncated_payload_are_rejected(self):
        content = bytearray(raw_tar([(tarfile.REGTYPE, b'{"note":1}')]))
        content[0] ^= 1
        with self.assertRaisesRegex(scanner.Incomplete, "^invalid_serialization$"):
            inspect(bytes(content), "checksum.tar")
        content = raw_tar([(tarfile.REGTYPE, b"x" * 2048)])[:1024]
        with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_size$"):
            inspect(content, "truncated.tar")

    def test_single_zero_eof_and_nonzero_tail_are_rejected_before_tarfile(self):
        for tail in (b"\x00" * 512, b"\x00" * 1024 + b"hidden".ljust(512, b"\x00")):
            content = raw_tar([(tarfile.REGTYPE, b'{"note":1}')], tail)
            with self.subTest(tail_size=len(tail)), \
                    mock.patch.object(scanner.tarfile, "open", side_effect=AssertionError("TarFile construction reached")), \
                    self.assertRaisesRegex(scanner.Incomplete, "^invalid_serialization$"):
                inspect(content, "tail.tar")

    def test_pax_path_mtime_and_gnu_longname_remain_supported(self):
        for archive_format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
                name = "long/" + "n" * 150 + ".json" if archive_format != tarfile.USTAR_FORMAT else "note.json"
                info = tarfile.TarInfo(name)
                info.size, info.mtime = 10, 1.25 if archive_format == tarfile.PAX_FORMAT else 1
                archive.addfile(info, io.BytesIO(b'{"note":1}'))
            with self.subTest(format=archive_format):
                result = inspect(output.getvalue(), "normal.tar")
                expected = 1 if archive_format == tarfile.USTAR_FORMAT else 2
                self.assertEqual(result.members, expected)
                self.assertEqual(result.findings, [])

    def test_global_pax_metadata_is_charged_once(self):
        record = pax_record(b"comment", b"bounded")
        content = raw_tar([(tarfile.XGLTYPE, record), (tarfile.REGTYPE, b'{"note":1}')])
        result = inspect(content, "global.tar", max_members=2)
        self.assertEqual(result.members, 2)
        self.assertEqual(result.expanded, len(record) + 10)
        with self.assertRaisesRegex(scanner.Incomplete, "^archive_member_limit$"):
            inspect(content, "global.tar", max_members=1)


class ReferenceClassificationMemoTests(unittest.TestCase):
    def test_repeated_safe_reference_classified_once(self):
        content = b"ccollections\nOrderedDict\n0" * 100 + b"N."
        with mock.patch.object(scanner, "known_dangerous_reference", wraps=scanner.known_dangerous_reference) as classify:
            result = inspect(content, "safe.pkl")
        self.assertEqual(classify.call_count, 1)
        self.assertEqual(result.findings, [])

    def test_later_dangerous_reference_is_not_hidden_by_safe_memo(self):
        content = b"ccollections\nOrderedDict\n0" * 100 + b"cos\nsystem\n."
        with mock.patch.object(scanner, "known_dangerous_reference", wraps=scanner.known_dangerous_reference) as classify:
            result = inspect(content, "dangerous.pkl")
        self.assertEqual(classify.call_count, 2)
        self.assertTrue(any(item["rule"] == "pickle.dangerous-global" for item in result.findings))

    def test_unknown_reference_remains_incomplete(self):
        content = b"cunfamiliar_model\nFactory\n0" * 5 + b"N."
        with mock.patch.object(scanner, "known_dangerous_reference", wraps=scanner.known_dangerous_reference) as classify:
            with self.assertRaisesRegex(scanner.Incomplete, "unsupported_container_or_serialization"):
                inspect(content, "unknown.pkl")
        self.assertEqual(classify.call_count, 1)

    def test_classification_memo_does_not_cross_invocations(self):
        content = b"ccollections\nOrderedDict\n0" * 5 + b"N."
        with mock.patch.object(scanner, "known_dangerous_reference", wraps=scanner.known_dangerous_reference) as classify:
            inspect(content, "first.pkl")
            inspect(content, "second.pkl")
        self.assertEqual(classify.call_count, 2)


class SafetensorsBudgetTests(unittest.TestCase):
    @staticmethod
    def content(header, payload=b""):
        raw = header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":")).encode()
        return len(raw).to_bytes(8, "little") + raw + payload

    def test_deep_json_returns_fixed_incomplete_code(self):
        raw = b'{"__metadata__":{"key":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}}"
        with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
            inspect(self.content(raw), "deep.safetensors")

    def test_invalid_json_and_utf8_return_fixed_incomplete_code(self):
        for raw in (b'{"x":', b'{"x":"\xff"}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
                inspect(self.content(raw), "invalid.safetensors")

    def test_rank_at_limit_remains_supported(self):
        header = {"tensor": {"dtype": "U8", "shape": [1] * scanner.SAFETENSORS_MAX_RANK,
                             "data_offsets": [0, 1]}}
        self.assertEqual(inspect(self.content(header, b"\x00"), "rank.safetensors").findings, [])

    def test_rank_above_limit_is_incomplete(self):
        header = {"tensor": {"dtype": "U8", "shape": [1] * (scanner.SAFETENSORS_MAX_RANK + 1),
                             "data_offsets": [0, 1]}}
        with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
            inspect(self.content(header, b"\x00"), "rank.safetensors")

    def test_tensor_count_limit_excludes_metadata(self):
        header = {"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
                  "b": {"dtype": "U8", "shape": [1], "data_offsets": [1, 2]},
                  "__metadata__": {"note": "bounded static test"}}
        with mock.patch.object(scanner, "SAFETENSORS_MAX_TENSORS", 2):
            self.assertEqual(inspect(self.content(header, b"\x00\x00"), "count.safetensors").findings, [])
        with mock.patch.object(scanner, "SAFETENSORS_MAX_TENSORS", 1):
            with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
                inspect(self.content(header, b"\x00\x00"), "count.safetensors")

    def test_actual_fixed_tensor_ceiling_is_enforced(self):
        tensor = {"dtype": "U8", "shape": [0], "data_offsets": [0, 0]}
        header = {str(index): tensor for index in range(scanner.SAFETENSORS_MAX_TENSORS + 1)}
        content = self.content(header)
        self.assertLess(len(content), 8 << 20)
        with self.assertRaisesRegex(scanner.Incomplete, "^invalid_safetensors_header$"):
            inspect(content, "count.safetensors")


if __name__ == "__main__":
    unittest.main()
