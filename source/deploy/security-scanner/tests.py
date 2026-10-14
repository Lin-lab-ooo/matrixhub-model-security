#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Static-only fixtures. These tests never deserialize a pickle or load a model."""
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location("matrix_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

def mock_snapshot_file(content):
    """Real FD for snapshot fences; antivirus remains an explicit unit mock."""
    handle = tempfile.TemporaryFile()
    try:
        handle.write(content)
        handle.flush()
        handle.seek(0)
        return handle
    except BaseException:
        handle.close()
        raise


SAFE = b"(dp0\n."
DANGEROUS = b"cos\nsystem\n."
STACK_GLOBAL = b"\x80\x04\x8c\x02os\x8c\x06system\x93."
NESTED_GLOBAL = b"ctorch.storage\n_load_from_bytes\n."
NESTED_RULE = "pickle.nested-deserialization-reference"


def short_unicode(value):
    raw = value.encode("utf-8")
    assert len(raw) < 256
    return b"\x8c" + bytes([len(raw)]) + raw


NESTED_STACK_GLOBAL = (b"\x80\x04" + short_unicode("torch.storage")
                       + short_unicode("_load_from_bytes") + b"\x93.")
NESTED_MEMO_GLOBAL = (b"\x80\x04" + short_unicode("torch.storage") + b"\x940"
                     + short_unicode("_load_from_bytes") + b"\x940h\x00h\x01\x93.")
NESTED_MEMO_OF_GET = (b"\x80\x04" + short_unicode("torch.storage") + b"\x94h\x00\x9400"
                      + short_unicode("_load_from_bytes") + b"\x940h\x01h\x02\x93.")


def archive(name, content, compress=False):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as z:
        z.writestr(name, content)
    return out.getvalue()


def safetensors(header, payload=b"\x00", header_size=None):
    raw = header if isinstance(header, bytes) else json.dumps(header, separators=(",", ":")).encode()
    if header_size is not None:
        raw = raw.ljust(header_size, b" ")
    return len(raw).to_bytes(8, "little") + raw + payload


class StaticInspectionTests(unittest.TestCase):
    def inspect(self, content, name="model.pkl", **overrides):
        limits = scanner.limits_from_env()
        limits.update(overrides)
        value = scanner.StaticInspector(limits)
        value.inspect(io.BytesIO(content), name)
        return value

    def inspect_unknown(self, content, name="model.pkl", **overrides):
        limits = scanner.limits_from_env()
        limits.update(overrides)
        value = scanner.StaticInspector(limits)
        with self.assertRaisesRegex(scanner.Incomplete, "unsupported_container_or_serialization"):
            value.inspect(io.BytesIO(content), name)
        return value

    def nested_finding(self, result):
        matches = [f for f in result.findings if f["rule"] == NESTED_RULE]
        self.assertEqual(len(matches), 1)
        value = matches[0]
        self.assertEqual(value["engine"], "picklescan")
        self.assertEqual(value["severity"], "high")
        self.assertIn("does not prove invocation or malicious execution", value["message"])
        self.assertEqual(set(value["evidence"]), {"knownSymbolId", "observation", "source",
                                                "archiveMemberChain", "streamIndex", "opcodeOffset"})
        self.assertEqual(value["evidence"]["knownSymbolId"], "torch-storage-load-from-bytes-v1")
        self.assertEqual(value["evidence"]["observation"], "reference")
        return value

    def test_nested_deserialization_direct_global_and_inst_have_actual_location(self):
        for fixture, offset in [(NESTED_GLOBAL, 0), (b"\x80\x02" + NESTED_GLOBAL, 2),
                                (b"(itorch.storage\n_load_from_bytes\n.", 1)]:
            with self.subTest(offset=offset):
                result = self.inspect(fixture)
                self.assertEqual(len(result.findings), 1)
                evidence = self.nested_finding(result)["evidence"]
                self.assertEqual(evidence["source"], "pickletools")
                self.assertEqual(evidence["streamIndex"], 0)
                self.assertEqual(evidence["opcodeOffset"], offset)
                self.assertIsNone(evidence["archiveMemberChain"])

    def test_nested_deserialization_stack_and_memo_have_literal_derived_location(self):
        for fixture, offset in [(NESTED_STACK_GLOBAL, 35), (NESTED_MEMO_GLOBAL, 43)]:
            with self.subTest(size=len(fixture)):
                evidence = self.nested_finding(self.inspect(fixture))["evidence"]
                self.assertEqual(evidence["source"], "pickletools")
                self.assertEqual(evidence["streamIndex"], 0)
                self.assertEqual(evidence["opcodeOffset"], offset)
                self.assertIsNone(evidence["archiveMemberChain"])

    def test_nested_deserialization_memo_of_get_cannot_downgrade_reference(self):
        evidence = self.nested_finding(self.inspect(NESTED_MEMO_OF_GET))["evidence"]
        self.assertEqual(evidence["source"], "pickletools")
        self.assertEqual(evidence["streamIndex"], 0)
        self.assertEqual(evidence["opcodeOffset"], 47)

    def test_nested_deserialization_concatenated_stream_offset_is_member_absolute(self):
        evidence = self.nested_finding(self.inspect(SAFE + b"\x80\x02" + NESTED_GLOBAL))["evidence"]
        self.assertEqual(evidence["streamIndex"], 1)
        self.assertEqual(evidence["opcodeOffset"], len(SAFE) + 2)

    def test_nested_deserialization_first_actual_reference_only_and_later_streams_checked(self):
        result = self.inspect(NESTED_STACK_GLOBAL + NESTED_GLOBAL + NESTED_GLOBAL + DANGEROUS)
        evidence = self.nested_finding(result)["evidence"]
        self.assertEqual(evidence["source"], "pickletools")
        self.assertEqual(evidence["streamIndex"], 0)
        self.assertEqual(evidence["opcodeOffset"], 35)
        self.assertTrue(any(f["severity"] == "critical" for f in result.findings))

    def test_nested_deserialization_zip_evidence_hashes_name_and_counts_directory_index(self):
        name = "private/<script>member.pkl"
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("private/", b"")
            z.writestr(name, NESTED_GLOBAL)
        result = self.inspect(out.getvalue(), "outer-private.pt")
        evidence = self.nested_finding(result)["evidence"]
        self.assertEqual(evidence["archiveMemberChain"], [{"memberIndex": 1,
                         "nameSha256": hashlib.sha256(name.encode()).hexdigest()}])
        output = json.dumps(result.findings)
        for private in [name, "outer-private", "<script>", "torch.storage", "_load_from_bytes"]:
            self.assertNotIn(private, output)

    def test_nested_deserialization_nested_zip_member_chain_is_relative(self):
        outer_member, inner_member = "private-nested.zip", "private-weight/data.pkl"
        content = archive(outer_member, archive(inner_member, NESTED_MEMO_GLOBAL))
        evidence = self.nested_finding(self.inspect(content, "outer.zip"))["evidence"]
        self.assertEqual(evidence["archiveMemberChain"], [
            {"memberIndex": 0, "nameSha256": hashlib.sha256(outer_member.encode()).hexdigest()},
            {"memberIndex": 0, "nameSha256": hashlib.sha256(inner_member.encode()).hexdigest()}])
        self.assertEqual(evidence["source"], "pickletools")
        self.assertEqual(evidence["opcodeOffset"], 43)

    def test_nested_deserialization_all_put_get_encodings_and_sparse_memo(self):
        pairs = [(b"p0\n", b"p1\n", b"g0\n", b"g1\n"),
                 (b"q\x00", b"q\x01", b"h\x00", b"h\x01"),
                 (b"r\x00\x00\x00\x00", b"r\x01\x00\x00\x00",
                  b"j\x00\x00\x00\x00", b"j\x01\x00\x00\x00"),
                 (b"p7\n", b"\x94", b"g7\n", b"g1\n")]
        for put_module, put_name, get_module, get_name in pairs:
            fixture = (b"\x80\x04" + short_unicode("torch.storage") + put_module + b"0"
                       + short_unicode("_load_from_bytes") + put_name + b"0"
                       + get_module + get_name + b"\x93.")
            with self.subTest(put=put_module):
                evidence = self.nested_finding(self.inspect(fixture))["evidence"]
                self.assertEqual(evidence["opcodeOffset"], len(fixture) - 2)

    def test_nested_deserialization_explicit_memo_overwrite_and_dup_store_actual_values(self):
        overwrite = (b"\x80\x04" + short_unicode("wrong") + b"q\x000"
                     + short_unicode("torch.storage") + b"q\x000"
                     + short_unicode("wrong") + b"q\x010"
                     + short_unicode("_load_from_bytes") + b"q\x010h\x00h\x01\x93.")
        duplicate = (b"\x80\x04" + short_unicode("torch.storage") + b"2q\x0000"
                     + short_unicode("_load_from_bytes") + b"q\x010h\x00h\x01\x93.")
        for fixture in [overwrite, duplicate]:
            with self.subTest(size=len(fixture)):
                self.nested_finding(self.inspect(fixture))

    def test_nested_deserialization_mark_tuple_and_pop_do_not_change_literal_symbols(self):
        fixture = (b"\x80\x04" + short_unicode("torch.storage") + b"("
                   + short_unicode("irrelevant-string") + b"t0"
                   + short_unicode("_load_from_bytes") + b"\x93.")
        self.nested_finding(self.inspect(fixture))

    def test_nested_deserialization_cross_stream_memo_dependency_is_incomplete(self):
        first = b"\x80\x04" + short_unicode("torch.storage") + b"\x94."
        second = (b"\x80\x04h\x00\x940" + short_unicode("_load_from_bytes")
                  + b"\x940h\x01h\x02\x93.")
        # Same-Unpickler memo resolves this, but a fresh Unpickler cannot. The
        # artifact does not prove consumer behavior: do not choose and pass.
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_symbol_analysis_incomplete"):
            self.inspect(first + second)
        # A value left on an earlier pickle's stack must not become an operand
        # of a later STACK_GLOBAL. Retained memo is separate from fresh stacks.
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_symbol_analysis_incomplete"):
            self.inspect(first + b"\x80\x04" + short_unicode("_load_from_bytes") + b"\x93.")

    def test_nested_deserialization_cross_stream_memo_ambiguity_is_incomplete(self):
        first = b"\x80\x04" + short_unicode("irrelevant") + b"\x94."
        second = (b"\x80\x04" + short_unicode("torch.storage") + b"\x940"
                  + short_unicode("_load_from_bytes") + b"\x940h\x00h\x01\x93.")
        # Both interpretations can read memo slots, but resolve different
        # globals. A fresh memo reaches the restricted symbol: never choose
        # only the retained memo and downgrade this to an ordinary unknown.
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_symbol_analysis_incomplete"):
            self.inspect(first + second)

    def test_nested_deserialization_unicode_encodings_and_frame_have_real_locations(self):
        for encode in [lambda v: b"V" + v.encode("raw-unicode-escape") + b"\n",
                       lambda v: b"X" + len(v).to_bytes(4, "little") + v.encode(),
                       lambda v: b"\x8d" + len(v).to_bytes(8, "little") + v.encode()]:
            fixture = b"\x80\x04" + encode("torch.storage") + encode("_load_from_bytes") + b"\x93."
            evidence = self.nested_finding(self.inspect(fixture))["evidence"]
            self.assertEqual(evidence["opcodeOffset"], len(fixture) - 2)
        body = NESTED_STACK_GLOBAL[2:]
        framed = b"\x80\x04\x95" + len(body).to_bytes(8, "little") + body
        self.assertEqual(self.nested_finding(self.inspect(framed))["evidence"]["opcodeOffset"], 44)

    def test_stack_global_legacy_byte_string_encoding_is_incomplete(self):
        # These opcodes may decode differently with consumer encoding options;
        # only the four literal Unicode opcodes are proven string operands.
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_symbol_analysis_incomplete"):
            self.inspect(b"S'torch.storage'\nS'_load_from_bytes'\n\x93.")

    def test_stack_global_unresolved_operands_and_unbound_memo_are_incomplete(self):
        cases = [b"\x80\x04K\x00" + short_unicode("_load_from_bytes") + b"\x93.",
                 b"\x80\x04cbuiltins\nstr\n)R" + short_unicode("_load_from_bytes") + b"\x93.",
                 b"\x80\x04h\x07" + short_unicode("_load_from_bytes") + b"\x93.",
                 b"\x80\x04" + short_unicode("torch.storage") + b"(\x93."]
        for fixture in cases:
            with self.subTest(size=len(fixture)), self.assertRaisesRegex(
                    scanner.Incomplete, "pickle_symbol_analysis_incomplete"):
                self.inspect(fixture)

    def test_other_memo_obscured_symbols_are_incomplete_instead_of_downgraded(self):
        for module, symbol in [("os", "system"), ("unfamiliar_model", "Factory")]:
            fixture = (b"\x80\x04" + short_unicode(module) + b"\x94h\x00\x9400"
                       + short_unicode(symbol) + b"\x940h\x01h\x02\x93.")
            with self.subTest(module=module), self.assertRaisesRegex(
                    scanner.Incomplete, "pickle_symbol_analysis_disagreement"):
                self.inspect(fixture)

    def test_symbolic_stack_memo_and_container_budgets_are_bounded(self):
        tracker = scanner.SymbolicReferences(2)
        opcodes = {op.name: op for op in scanner.pickletools.opcodes}
        tracker.apply(opcodes["SHORT_BINUNICODE"], "literal")
        tracker.apply(opcodes["MEMOIZE"], None)
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_symbol_budget"):
            tracker.apply(opcodes["MEMOIZE"], None)
        for fixture in [b"\x80\x04((K\x01t0K\x02l.", b"\x80\x04](K\x01K\x02e.",
                        b"\x80\x04}(" + short_unicode("key") + b"K\x01u.",
                        b"\x80\x04K\x01K\x02\x86.", b"\x80\x04(K\x01\x91."]:
            with self.subTest(fixture=fixture[:3]):
                self.assertEqual(self.inspect(fixture).findings, [])

    def test_nested_deserialization_tar_and_anonymous_gzip_evidence(self):
        name = "private-member.pkl"
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as t:
            directory = tarfile.TarInfo("private/")
            directory.type = tarfile.DIRTYPE
            t.addfile(directory)
            info = tarfile.TarInfo(name)
            info.size = len(NESTED_GLOBAL)
            t.addfile(info, io.BytesIO(NESTED_GLOBAL))
        evidence = self.nested_finding(self.inspect(out.getvalue(), "outer.tar"))["evidence"]
        self.assertEqual(evidence["archiveMemberChain"], [{"memberIndex": 1,
                         "nameSha256": hashlib.sha256(name.encode()).hexdigest()}])
        evidence = self.nested_finding(self.inspect(gzip.compress(NESTED_GLOBAL), "private.pkl.gz"))["evidence"]
        self.assertEqual(evidence["archiveMemberChain"], [{"memberIndex": 0,
                         "nameSha256": hashlib.sha256(b"").hexdigest()}])

    def test_nested_deserialization_literal_strings_and_lookalike_symbols_do_not_match(self):
        literals = (b"\x80\x04" + short_unicode("torch.storage") + b"0"
                    + short_unicode("_load_from_bytes") + b".")
        self.assertEqual(self.inspect(literals).findings, [])
        for fixture in [b"cother.storage\n_load_from_bytes\n.",
                        b"ctorch.storage\n_load_from_bytes_extra\n."]:
            with self.subTest(fixture=fixture[:12]):
                findings = self.inspect_unknown(fixture).findings
                self.assertEqual([f["severity"] for f in findings], ["medium"])
                self.assertNotIn("evidence", findings[0])

    def test_nested_deserialization_does_not_blanket_block_known_torch_globals(self):
        for fixture in [b"ctorch\nFloatStorage\n.", b"ctorch._utils\n_rebuild_tensor_v2\n."]:
            with self.subTest(fixture=fixture[:12]):
                self.assertEqual(self.inspect(fixture).findings, [])

    def test_nested_deserialization_does_not_hide_unknown_or_critical_references(self):
        result = self.inspect_unknown(NESTED_GLOBAL + b"cunfamiliar_model\nFactory\n." + DANGEROUS)
        self.nested_finding(result)
        self.assertEqual({f["severity"] for f in result.findings}, {"medium", "high", "critical"})
        self.assertNotIn("os.system", json.dumps(result.findings))

    def test_nested_deserialization_still_requires_complete_bounded_parsing(self):
        for fixture in [NESTED_GLOBAL + b"trailing junk", NESTED_GLOBAL[:-1],
                        NESTED_GLOBAL + b"\x80\x02\x82\x01."]:
            with self.subTest(size=len(fixture)), self.assertRaises(Exception):
                self.inspect(fixture)
        with self.assertRaises(scanner.Incomplete):
            self.inspect(NESTED_GLOBAL, max_pickle_opcodes=1)
        with self.assertRaises(scanner.Incomplete):
            self.inspect(NESTED_GLOBAL, max_pickle_argument=8)

    def test_nested_deserialization_evidence_chain_is_bounded_even_with_large_depth_config(self):
        content = NESTED_GLOBAL
        for index in range(scanner.MAX_EVIDENCE_CHAIN + 1):
            content = archive("child.pkl" if index == 0 else "child.zip", content)
        with self.assertRaisesRegex(scanner.Incomplete, "archive_depth_limit"):
            self.inspect(content, "outer.zip", max_depth=100, max_members=100)

    def test_safe_pickle(self):
        result = self.inspect(SAFE)
        self.assertEqual(result.pickle_files, 1)
        self.assertEqual(result.findings, [])

    def test_safetensors_128_byte_header_is_not_pickle(self):
        content = safetensors({"x": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, header_size=128)
        self.assertEqual(len(content), 137)
        self.assertEqual(content[:2], b"\x80\x00")
        result = self.inspect(content, "model.safetensors")
        self.assertEqual(result.pickle_files, 0)
        self.assertEqual(result.findings, [])

    def test_dangerous_pickle_renamed_safetensors_is_incomplete(self):
        for content in [DANGEROUS, STACK_GLOBAL, b"]0" + DANGEROUS]:
            with self.subTest(prefix=content[:2]), self.assertRaises(scanner.Incomplete):
                self.inspect(content, "model.safetensors")

    def test_safetensors_extension_does_not_hide_archive_magic(self):
        result = self.inspect(archive("data.pkl", DANGEROUS), "model.safetensors")
        self.assertEqual(result.pickle_files, 1)
        self.assertEqual(result.findings[0]["severity"], "critical")

    def test_safetensors_duplicate_keys_and_invalid_metadata_are_incomplete(self):
        headers = [b'{"x":{},"x":{}}', {"__metadata__": {"note": 1}},
                   {"x": {"dtype": "U8", "shape": [True], "data_offsets": [0, 1]}},
                   {"x": {"dtype": "UNKNOWN", "shape": [1], "data_offsets": [0, 1]}}]
        for header in headers:
            with self.subTest(header=header), self.assertRaises(scanner.Incomplete):
                self.inspect(safetensors(header), "model.safetensors")

    def test_safetensors_incomplete_or_overlapping_data_is_rejected(self):
        tensor = {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}
        cases = [({"x": tensor}, b"\x00" + DANGEROUS),
                 ({"x": dict(tensor, data_offsets=[1, 2])}, b"\x00\x00"),
                 ({"x": tensor, "y": tensor}, b"\x00"),
                 ({"x": dict(tensor, shape=[2])}, b"\x00"),
                 ({"x": dict(tensor, dtype="F4")}, b"\x00"),
                 ({}, DANGEROUS)]
        for header, payload in cases:
            with self.subTest(header=header), self.assertRaises(scanner.Incomplete):
                self.inspect(safetensors(header, payload), "model.safetensors")

    def test_safetensors_scalar_empty_and_aligned_subbyte_tensors(self):
        header = {"scalar": {"dtype": "U8", "shape": [], "data_offsets": [0, 1]},
                  "empty": {"dtype": "F32", "shape": [0], "data_offsets": [1, 1]},
                  "packed": {"dtype": "F4", "shape": [2], "data_offsets": [1, 2]},
                  "__metadata__": {"format": "static-test"}}
        self.assertEqual(self.inspect(safetensors(header, b"\x00\x00"), "model.safetensors").findings, [])

    def test_dangerous_global_protocol_zero_and_four(self):
        for fixture in [DANGEROUS, STACK_GLOBAL]:
            with self.subTest(fixture=fixture[:2]):
                result = self.inspect(fixture)
                self.assertTrue(any(f["severity"] == "critical" for f in result.findings))
                self.assertNotIn("os.system", json.dumps(result.findings))

    def test_unknown_global_is_warning(self):
        result = self.inspect_unknown(b"cunfamiliar_model\nFactory\n.")
        self.assertEqual(result.findings[0]["severity"], "medium")

    def test_renamed_pickle_with_non_global_prefix_is_detected(self):
        result = self.inspect(b"]0" + DANGEROUS, "readme.txt")
        self.assertEqual(result.findings[0]["severity"], "critical")
        with self.assertRaises(Exception):
            self.inspect(b"]0" + DANGEROUS + b"broken", "readme.txt")

    def test_framework_name_not_wildcard_safe(self):
        result = self.inspect(b"ctorch.serialization\nload\n.")
        self.assertEqual(result.findings[0]["severity"], "critical")

    def test_malformed_without_globals_is_incomplete(self):
        for value in [b"\x80\x04]", b"", b"not a pickle", SAFE + b"trailing junk"]:
            with self.subTest(size=len(value)), self.assertRaises(Exception):
                self.inspect(value)

    def test_all_concatenated_pickles_are_checked(self):
        result = self.inspect(SAFE + DANGEROUS)
        self.assertTrue(result.findings)

    def test_extension_registry_is_incomplete(self):
        with self.assertRaises(scanner.Incomplete):
            self.inspect(b"\x80\x02\x82\x01.")

    def test_zip_static_inspection(self):
        result = self.inspect(archive("model/data.pkl", DANGEROUS), "weights.pt")
        self.assertEqual(result.pickle_files, 1)
        self.assertTrue(result.findings)

    def test_nested_container_is_not_ignored(self):
        content = archive("nested.zip", archive("data.pkl", DANGEROUS))
        self.assertTrue(self.inspect(content, "outer.zip").findings)

    def test_archive_bomb_and_depth_and_member_limits(self):
        with self.assertRaises(scanner.Incomplete):
            self.inspect(archive("zeros.txt", b"0" * 100000, True), "bomb.zip", max_ratio=2)
        content = archive("nested.zip", archive("data.pkl", SAFE))
        with self.assertRaises(scanner.Incomplete):
            self.inspect(content, "outer.zip", max_depth=1)
        with self.assertRaises(scanner.Incomplete):
            self.inspect(content, "outer.zip", max_members=1)

    def test_archive_symlink_and_unsupported_serialization(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            info = zipfile.ZipInfo("escape")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "/etc/passwd")
        with self.assertRaises(scanner.Incomplete):
            self.inspect(out.getvalue(), "links.zip")
        with self.assertRaises(scanner.Incomplete):
            self.inspect(b"\x93NUMPY", "array.npy")

    def test_opcode_budget(self):
        with self.assertRaises(scanner.Incomplete):
            self.inspect(SAFE, max_pickle_opcodes=1)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifact = {"artifactId": "task-1-1-0000000000000000/" + "1" * 32 + ".blob",
                         "sha256": hashlib.sha256(SAFE).hexdigest(), "size": len(SAFE), "type": "opaque;ext=.pkl"}
        self.file = self.root / self.artifact["artifactId"]
        self.file.parent.mkdir()
        self.file.write_bytes(SAFE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_digest_verification_returns_same_descriptor(self):
        with scanner.open_verified(self.root, self.artifact) as f:
            self.assertEqual(f.read(), SAFE)
        self.file.write_bytes(b"x" * len(SAFE))
        with self.assertRaises(scanner.Incomplete):
            scanner.open_verified(self.root, self.artifact)

    def test_symlink_rejected(self):
        self.file.unlink()
        self.file.symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            scanner.open_verified(self.root, self.artifact)

    def test_path_and_size_context_rejected(self):
        for key, value in [("artifactId", "../../etc/passwd"), ("size", True), ("sha256", "bad"), ("type", "pickle;ext=../../x")]:
            artifact = dict(self.artifact, **{key: value})
            with self.assertRaises(scanner.Incomplete):
                scanner.validate_artifact(artifact, scanner.limits_from_env())


class BatchProtocolTests(unittest.TestCase):
    def test_missing_skipped_duplicated_or_unknown_engine_result_is_incomplete(self):
        paths = ["/proc/self/fd/3", "/proc/self/fd/4"]
        for output in [b"", b"/proc/self/fd/3: OK\n", b"/proc/self/fd/3: Symbolic link\n/proc/self/fd/4: OK\n",
                       b"/proc/self/fd/3: OK\n/proc/self/fd/3: OK\n", b"/proc/self/fd/9: OK\n"]:
            with self.subTest(output=output[:32]), self.assertRaises(scanner.Incomplete):
                scanner.parse_batch_clamav_output(output, b"", 0, paths, [1, 1])

    def test_complete_fd_mapping_and_limit_alert(self):
        paths = ["/proc/self/fd/3", "/proc/self/fd/4"]
        results = scanner.parse_batch_clamav_output(b"/proc/self/fd/4: Eicar-Test-Signature FOUND\n/proc/self/fd/3: OK\n",
                                                    b"", 1, paths, [1, 68])
        self.assertEqual(results[0], [])
        self.assertEqual(results[1][0]["rule"], "clamav.Eicar-Test-Signature")
        with self.assertRaises(scanner.Incomplete):
            scanner.parse_batch_clamav_output(b"/proc/self/fd/3: Heuristics.Limits.Exceeded FOUND\n/proc/self/fd/4: OK\n",
                                              b"", 1, paths, [1, 1])

    def test_batch_count_size_and_duplicate_limits(self):
        limits = scanner.limits_from_env()
        artifact = {"artifactId": "task-1-1-0000000000000000/" + "1" * 32 + ".blob",
                    "sha256": "a" * 64, "size": 1, "type": "opaque;ext=.txt"}
        self.assertEqual(scanner.validate_batch({"artifacts": [artifact]}, limits), [artifact])
        for value in [{"artifacts": []}, {"artifacts": [artifact, artifact]}, {"artifacts": [artifact] * 33}]:
            with self.assertRaises(scanner.Incomplete):
                scanner.validate_batch(value, limits)
        oversized = [dict(artifact, artifactId="task-1-1-0000000000000000/" + str(i) * 32 + ".blob", size=64 << 20) for i in range(5)]
        with self.assertRaises(scanner.Incomplete):
            scanner.validate_batch({"artifacts": oversized}, limits)


class WorkerFileIsolationTests(unittest.TestCase):
    def setUp(self):
        self.limits = scanner.limits_from_env()
        self.bundle = {"generation": "g" * 64, "engines": {"clamav": "ClamAV fixed", "picklescan": "1.0.5"}}
        self.rules = [{"name": "main.cvd", "sha256": "a" * 64, "size": 1}]

    def artifact(self, index, content, ext=".txt"):
        return {"artifactId": "task-1-1-0000000000000000/" + format(index, "032x") + ".blob",
                "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
                "type": "opaque;ext=" + ext}

    def request(self, artifacts, batch=True):
        request = {"limits": self.limits, "bundle": self.bundle, "evidence": {"rules": self.rules}, "batch": batch}
        request["artifacts" if batch else "artifact"] = artifacts if batch else artifacts[0]
        return request

    def run_mocked_worker(self, payloads, artifacts, antivirus=None, batch=True, rule_values=None):
        contents = {artifact["artifactId"]: content for artifact, content in zip(artifacts, payloads)}
        av = antivirus if antivirus is not None else [[] for _ in artifacts]
        with mock.patch.object(scanner, "child_limits"), \
                mock.patch.object(scanner, "open_verified", side_effect=lambda root, artifact: mock_snapshot_file(contents[artifact["artifactId"]])) as opened, \
                mock.patch.object(scanner, "rule_inventory", side_effect=rule_values or [self.rules, self.rules]), \
                mock.patch.object(scanner, "scan_clamav_batch", return_value=av) as clam_batch, \
                mock.patch.object(scanner, "scan_clamav", return_value=av[0]) as clam_single:
            result = scanner.worker(self.request(artifacts, batch), "/input", "/rules")
            self.assertEqual(opened.call_count, len(artifacts))
            self.assertEqual(clam_batch.call_count, int(batch))
            self.assertEqual(clam_single.call_count, int(not batch))
            return result

    def test_mixed_batch_preserves_good_files_antivirus_and_pre_error_reference(self):
        # The original trailing byte is kept. STOP does not grant a clean result
        # while the remaining bytes fail complete static analysis.
        payloads = [b'{"text":true}', NESTED_GLOBAL + b"!", b"unsupported numpy", b"# ordinary metadata\n"]
        artifacts = [self.artifact(i + 1, data, ext) for i, (data, ext) in enumerate(zip(payloads, [".txt", ".pkl", ".npy", ".txt"]))]
        malware = scanner.finding("clamav", "clamav.Eicar-Test-Signature", "critical", "ClamAV matched a malware or dangerous-content signature.")
        result = self.run_mocked_worker(payloads, artifacts, [[], [malware], [], []])
        self.assertEqual([item["artifactId"] for item in result["results"]], [a["artifactId"] for a in artifacts])
        analyses = [item["analysis"] for item in result["results"]]
        self.assertEqual([analysis["complete"] for analysis in analyses], [True, False, False, True])
        self.assertIn(malware, analyses[1]["findings"])
        nested = [f for f in analyses[1]["findings"] if f["rule"] == NESTED_RULE]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0]["evidence"]["streamIndex"], 0)
        self.assertEqual(nested[0]["evidence"]["opcodeOffset"], 0)
        self.assertIn(scanner.coverage_finding("invalid_serialization"), analyses[1]["findings"])
        self.assertIn(scanner.coverage_finding("invalid_serialization"), analyses[2]["findings"])
        self.assertTrue(scanner.valid_worker_result(result, artifacts, self.bundle, batch=True))

    def test_single_file_returns_bound_incomplete_analysis_without_exception_text(self):
        content = b"arbitrary parser text"
        artifact = self.artifact(1, content, ".npy")
        result = self.run_mocked_worker([content], [artifact], batch=False)
        self.assertFalse(result["complete"])
        self.assertEqual(result["findings"], [scanner.coverage_finding("invalid_serialization")])
        self.assertNotIn(content.decode(), json.dumps(result))
        self.assertTrue(scanner.valid_worker_result(result, artifact, self.bundle))

    def test_static_budgets_and_unknown_failures_remain_global(self):
        artifacts = [self.artifact(1, b"metadata")]
        for code in sorted(scanner.ERROR_CODES - scanner.FILE_ERROR_CODES):
            with self.subTest(code=code), mock.patch.object(scanner.StaticInspector, "inspect", side_effect=scanner.Incomplete(code)):
                with self.assertRaises(scanner.Incomplete) as raised:
                    self.run_mocked_worker([b"metadata"], artifacts)
                self.assertEqual(raised.exception.args, (code,))
        for error in [MemoryError(), OSError("private filesystem error"), RuntimeError("private internal error")]:
            with self.subTest(error=type(error).__name__), mock.patch.object(scanner.StaticInspector, "inspect", side_effect=error):
                with self.assertRaises(type(error)):
                    self.run_mocked_worker([b"metadata"], artifacts)

    def test_known_format_exceptions_are_local_and_do_not_expose_messages(self):
        artifacts = [self.artifact(1, b"metadata")]
        for exception in scanner.FORMAT_EXCEPTIONS:
            with self.subTest(exception=exception.__name__), mock.patch.object(scanner.StaticInspector, "inspect", side_effect=exception("private-parser-value")):
                result = self.run_mocked_worker([b"metadata"], artifacts)
                analysis = result["results"][0]["analysis"]
                self.assertFalse(analysis["complete"])
                self.assertEqual(analysis["findings"], [scanner.coverage_finding("invalid_serialization")])
                self.assertNotIn("private-parser-value", json.dumps(result))

    def test_snapshot_rules_and_antivirus_failures_remain_global(self):
        artifacts = [self.artifact(1, b"metadata"), self.artifact(2, b"other")]
        with mock.patch.object(scanner, "child_limits"), mock.patch.object(scanner, "rule_inventory", return_value=self.rules), \
                mock.patch.object(scanner, "open_verified", side_effect=[mock_snapshot_file(b"metadata"), scanner.Incomplete("snapshot_digest")]), \
                mock.patch.object(scanner, "scan_clamav_batch") as antivirus, mock.patch.object(scanner.StaticInspector, "inspect") as inspect:
            with self.assertRaises(scanner.Incomplete) as raised:
                scanner.worker(self.request(artifacts), "/input", "/rules")
            self.assertEqual(raised.exception.args, ("snapshot_digest",))
            antivirus.assert_not_called()
            inspect.assert_not_called()
        with mock.patch.object(scanner, "scan_clamav_batch", side_effect=scanner.Incomplete("clamav_missing_result")):
            # run_mocked_worker intentionally owns the AV mock; use the worker
            # directly here to preserve the injected global engine failure.
            with mock.patch.object(scanner, "child_limits"), mock.patch.object(scanner, "rule_inventory", return_value=self.rules), \
                    mock.patch.object(scanner, "open_verified", side_effect=lambda root, artifact: mock_snapshot_file(b"metadata")), \
                    mock.patch.object(scanner.StaticInspector, "inspect") as inspect:
                with self.assertRaises(scanner.Incomplete) as raised:
                    scanner.worker(self.request(artifacts), "/input", "/rules")
                self.assertEqual(raised.exception.args, ("clamav_missing_result",))
                inspect.assert_not_called()
        with self.assertRaises(scanner.Incomplete) as raised:
            self.run_mocked_worker([b"metadata", b"other"], artifacts, rule_values=[self.rules, []])
        self.assertEqual(raised.exception.args, ("rules_changed",))

    def test_supervisor_rejects_forged_incomplete_or_ambiguous_batch_structure(self):
        artifact = self.artifact(1, b"metadata")
        good = {"generation": self.bundle["generation"], "complete": True, "engines": self.bundle["engines"], "findings": [], "durationMs": 1}
        partial = dict(good, complete=False, findings=[scanner.coverage_finding("invalid_serialization")])
        self.assertTrue(scanner.valid_worker_analysis(good, self.bundle))
        self.assertTrue(scanner.valid_worker_analysis(partial, self.bundle))
        forged = scanner.coverage_finding("invalid_serialization")
        unknown = dict(forged, rule="coverage.rules_changed")
        for value in [dict(good, complete=False), dict(good, complete=1), dict(good, durationMs=True),
                      dict(partial, complete=True), dict(partial, findings=[forged, forged]),
                      dict(partial, findings=[unknown]), dict(partial, findings=[dict(forged, message="private operand")]),
                      dict(partial, findings=[dict(forged, severity="low")]), dict(partial, findings=[dict(forged, evidence={})]),
                      dict(partial, generation="changed"), dict(partial, engines={"clamav": "different"}),
                      dict(partial, extra=True)]:
            with self.subTest(value=value):
                self.assertFalse(scanner.valid_worker_analysis(value, self.bundle))
        item = {"artifactId": artifact["artifactId"], "analysis": partial}
        for value in [{"results": []}, {"results": [item, item]}, {"results": [dict(item, artifactId="other")]},
                      {"results": [dict(item, extra=True)]}, {"results": [item], "extra": True}]:
            with self.subTest(value=value):
                self.assertFalse(scanner.valid_worker_result(value, [artifact], self.bundle, batch=True))


class DeploymentIsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("VERIFY_CONTAINER_ISOLATION") == "1", "run in the documented hardened container")
    def test_container_has_no_business_credentials_network_or_write_access(self):
        self.assertNotEqual(os.getuid(), 0)
        self.assertFalse(Path("/var/run/docker.sock").exists())
        for key in os.environ:
            self.assertFalse(any(word in key for word in ["AWS_SECRET", "DATABASE_DSN", "ACCESS_TOKEN"]))
        with self.assertRaises(OSError):
            Path("/opt/scanner/forbidden-write").write_text("no")
        with socket.socket() as s:
            s.settimeout(0.2)
            with self.assertRaises(OSError):
                s.connect(("1.1.1.1", 443))
        with self.assertRaises(OSError):
            with open("/input/forbidden-write", "wb") as f:
                f.write(b"no")


class ChildResourceLimitTests(unittest.TestCase):
    def run_limited(self, body, **overrides):
        limits = scanner.limits_from_env()
        limits.update(overrides)
        program = ("import importlib.util,sys,errno,tempfile; "
                   "s=importlib.util.spec_from_file_location('scanner','/opt/scanner/scanner.py'); "
                   "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                   "m.child_limits(" + repr(limits) + ");\n" + body)
        return subprocess.run([sys.executable, "-I", "-c", program], capture_output=True, timeout=5)

    def test_address_space_and_temporary_file_limits_are_enforced(self):
        memory = self.run_limited("try:\n bytearray(256 << 20)\nexcept MemoryError:\n print('memory_limit')\n", memory_bytes=64 << 20)
        self.assertEqual(memory.returncode, 0)
        self.assertEqual(memory.stdout.strip(), b"memory_limit")
        disk = self.run_limited("try:\n tempfile.TemporaryFile().write(b'x' * (2 << 20))\nexcept OSError as e:\n assert e.errno == errno.EFBIG\n print('file_limit')\n", temp_bytes=1 << 20)
        self.assertEqual(disk.returncode, 0)
        self.assertEqual(disk.stdout.strip(), b"file_limit")

    def test_cpu_limit_kills_a_non_terminating_child(self):
        result = self.run_limited("while True:\n pass\n", cpu_seconds=1)
        self.assertEqual(result.returncode, -9)


class ClamAVTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("TEST_RULES_DIR"), "provide an immutable ClamAV rules snapshot")
    def test_real_clamav_safe_and_eicar(self):
        rules = os.environ["TEST_RULES_DIR"]
        for expected, content in [(False, b"ordinary clean model metadata"),
                                  (True, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")]:
            with tempfile.TemporaryFile() as f:
                f.write(content); f.seek(0)
                findings = scanner.scan_clamav(f, rules, scanner.limits_from_env())
                self.assertEqual(bool(findings), expected)


class DefaultProfileV11Tests(unittest.TestCase):
    def test_default_profile_is_cold_clamscan_64mib(self):
        self.assertEqual(os.getenv("SCAN_PROFILE", "default"), "default")
        self.assertEqual(scanner.backend_from_env(), "clamscan")
        limits = scanner.limits_from_env()
        self.assertEqual(limits["max_file_bytes"], 64 << 20)
        self.assertEqual(limits["max_scan_bytes"], 128 << 20)
        self.assertEqual(limits["max_expanded_bytes"], 128 << 20)
        self.assertEqual(limits["max_batch_files"], 32)
        self.assertEqual(limits["max_batch_bytes"], 256 << 20)
        self.assertNotIn("native_temp_bytes", limits)


if __name__ == "__main__":
    unittest.main(verbosity=2)
