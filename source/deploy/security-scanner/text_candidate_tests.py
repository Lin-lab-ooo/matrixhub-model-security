#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Ordinary-text / disguised-Pickle routing controls; never deserialize objects.

The mocked native worker test is control-flow evidence, not AV acceptance.
Actual full AV and same-byte application checks are executed separately by ROOT.
"""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import types
import unittest
from unittest import mock

if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer

spec = importlib.util.spec_from_file_location("text_candidate_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

ORIGINAL_DIRECTORY_NOTE = b"owned M00036 directory fixture\n"
ORIGINAL_NOTE_SHA256 = "58b81952f4e042a440a246ec7aeb4b53b1ec4db684958b0af169acc897d0cc44"
REFERENCE = b"cos\nsystem\n."


class TextCandidateTests(unittest.TestCase):
    def inspector(self, **overrides):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = scanner.limits_from_env()
        return scanner.StaticInspector(dict(limits, **overrides))

    def test_original_31_byte_note_routes_as_ordinary_data_by_content(self):
        self.assertEqual(len(ORIGINAL_DIRECTORY_NOTE), 31)
        self.assertEqual(hashlib.sha256(ORIGINAL_DIRECTORY_NOTE).hexdigest(), ORIGINAL_NOTE_SHA256)
        for filename in ("artifact", "readme.txt", "README.md", "arbitrary.json"):
            with self.subTest(filename=filename):
                inspector = self.inspector()
                inspector.inspect(io.BytesIO(ORIGINAL_DIRECTORY_NOTE), filename)
                self.assertEqual(inspector.findings, [])
                self.assertEqual(inspector.pickle_files, 0)

    def test_other_ordinary_o_text_does_not_establish_pickle_context(self):
        for raw in (b"ordinary model documentation\n", b"output model weights and usage\n", b"o"):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                self.assertFalse(self.inspector().pickle_candidate(io.BytesIO(raw)))

    def test_known_pickle_extensions_remain_strict(self):
        for ext in (".pkl", ".pickle", ".bin", ".pt", ".joblib"):
            with self.subTest(extension=ext), self.assertRaises(scanner.Incomplete):
                self.inspector().inspect(io.BytesIO(ORIGINAL_DIRECTORY_NOTE), "artifact" + ext)

    def test_obj_prefix_cannot_hide_later_format_or_reference_evidence(self):
        for raw in (b"o.", b"o" + REFERENCE, b"o\x80\x04" + REFERENCE,
                    b"oios\nsystem\n.", b"o\x82\x01.", b"o\x83\x01\x00.",
                    b"o\x84\x01\x00\x00\x00.", b"oPcontrolled-reference\n.",
                    b"oN." + REFERENCE):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(raw)))
                with self.assertRaises(scanner.Incomplete):
                    self.inspector().inspect(io.BytesIO(raw), "readme.txt")

    def test_existing_disguised_pickle_routes_are_preserved(self):
        for raw in (REFERENCE, b"]0" + REFERENCE, b"N." + REFERENCE,
                    b"\x80\x04" + REFERENCE, b"N.", b"(dp0\n."):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(raw)))

    def test_other_initial_stack_consumers_are_not_relaxed(self):
        for raw in (b"R", b"b", b"\x81", b"\x92", b"\x93", b"Q", b"."):
            with self.subTest(opcode=raw.hex()):
                self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(raw)))

    def test_obj_deferral_does_not_disable_later_resource_fences(self):
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_argument_limit"):
            self.inspector(max_pickle_argument=64).pickle_candidate(io.BytesIO(b"o\x80\x04\x8e" + (1 << 30).to_bytes(8, "little")))
        with self.assertRaisesRegex(scanner.Incomplete, "pickle_opcode_limit"):
            self.inspector(max_pickle_opcodes=2).pickle_candidate(io.BytesIO(b"oNNN"))
        with self.assertRaisesRegex(scanner.Incomplete, "unsupported_container_or_serialization"):
            self.inspector().pickle_candidate(io.BytesIO(b"o\x80\x06N."))

    def test_ordinary_note_worker_still_scans_all_av_bytes_and_posthash(self):
        inspector = self.inspector()
        artifact = {"artifactId": "task-1-1-0000000000000000/" + "0" * 32 + ".blob",
                    "sha256": ORIGINAL_NOTE_SHA256, "size": 31, "type": "opaque;ext=.txt"}
        request = {"limits": inspector.limits, "artifact": artifact, "evidence": {"rules": []},
                   "bundle": {"generation": "0" * 64, "engines": {"clamav": "mock-native", "picklescan": "mock-static"}},
                   "backend": "clamscan"}
        with tempfile.TemporaryFile() as data:
            data.write(ORIGINAL_DIRECTORY_NOTE)
            data.flush()
            data.seek(0)
            def av(stream, *args):
                self.assertEqual(stream.read(), ORIGINAL_DIRECTORY_NOTE)
                return []
            with mock.patch.object(scanner, "child_limits"), \
                 mock.patch.object(scanner, "rule_inventory", return_value=[]), \
                 mock.patch.object(scanner, "open_verified", return_value=contextlib.nullcontext(data)), \
                 mock.patch.object(scanner, "scan_clamav", side_effect=av) as antivirus, \
                 mock.patch.object(scanner, "verify_held_snapshot", wraps=scanner.verify_held_snapshot) as posthash:
                result = scanner.worker(request, "inert", "inert")
            self.assertTrue(result["complete"])
            self.assertEqual(result["findings"], [])
            antivirus.assert_called_once()
            posthash.assert_called_once()


if __name__ == "__main__":
    unittest.main()
