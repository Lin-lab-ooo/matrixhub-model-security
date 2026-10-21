# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Static allocation-fence regressions; no payload is deserialized or executed."""
import importlib.util
import io
from pathlib import Path
import pickle
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("operand_budget_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class TrackedReads:
    """Reject an unexpected large underlying request before any allocation."""
    def __init__(self, stream, ceiling=65):
        self.stream = stream
        self.ceiling = ceiling
        self.requests = []
        self.tell, self.seek = stream.tell, stream.seek

    def read(self, count=-1):
        self.requests.append(("read", count))
        if type(count) is not int or not 0 <= count <= self.ceiling:
            raise AssertionError("unbounded underlying read")
        return self.stream.read(count)

    def readline(self, count=-1):
        self.requests.append(("readline", count))
        if type(count) is not int or not 0 <= count <= self.ceiling:
            raise AssertionError("unbounded underlying readline")
        return self.stream.readline(count)


class OperandBudgetTests(unittest.TestCase):
    def inspector(self, argument=64, **limits):
        return scanner.StaticInspector(dict(scanner.limits_from_env(), max_pickle_argument=argument, **limits))

    def assert_budget(self, callback):
        with self.assertRaises(scanner.Incomplete) as caught:
            callback()
        self.assertEqual(str(caught.exception), "pickle_argument_limit")

    def test_huge_declared_binary_operands_never_reach_underlying_read(self):
        declared = 1 << 30
        cases = {
            "BINBYTES": b"\x80\x03B" + declared.to_bytes(4, "little"),
            "BINBYTES8": b"\x80\x04\x8e" + declared.to_bytes(8, "little"),
            "BINUNICODE": b"\x80\x02X" + declared.to_bytes(4, "little"),
            "BINUNICODE8": b"\x80\x04\x8d" + declared.to_bytes(8, "little"),
            "BYTEARRAY8": b"\x80\x05\x96" + declared.to_bytes(8, "little"),
            "BINSTRING": b"T" + declared.to_bytes(4, "little"),
            "LONG4": b"\x80\x02\x8b" + declared.to_bytes(4, "little"),
            "LONG1": b"\x80\x02\x8a\xff",
            "SHORT_BINBYTES": b"\x80\x03C\xff",
            "SHORT_BINUNICODE": b"\x80\x04\x8c\xff",
            "SHORT_BINSTRING": b"U\xff",
        }
        for name, raw in cases.items():
            for method in ("pickle_candidate", "inspect_pickle"):
                with self.subTest(opcode=name, method=method):
                    source = TrackedReads(io.BytesIO(raw))
                    self.assert_budget(lambda: getattr(self.inspector(), method)(source))
                    self.assertTrue(source.requests)
                    self.assertTrue(all(count <= 64 for _, count in source.requests))

    def test_real_file_huge_declaration_is_rejected_before_large_read(self):
        with tempfile.TemporaryFile("w+b") as stream:
            stream.write(b"\x80\x04\x8e" + (1 << 30).to_bytes(8, "little"))
            source = TrackedReads(stream)
            self.assert_budget(lambda: self.inspector().inspect_pickle(source))
            self.assertLessEqual(max(count for _, count in source.requests), 8)

    def test_protocol0_unterminated_lines_have_a_bounded_sentinel_read(self):
        for opcode in (b"S", b"V", b"I", b"L", b"F", b"c", b"i", b"P"):
            for method in ("pickle_candidate", "inspect_pickle"):
                with self.subTest(opcode=opcode, method=method):
                    source = TrackedReads(io.BytesIO(opcode + b"1" * 65))
                    self.assert_budget(lambda: getattr(self.inspector(), method)(source))
                    self.assertIn(("readline", 65), source.requests)

    def test_reader_rejects_unbounded_and_invalid_counts_without_reading(self):
        for count in (-1, -2, 65, None, True, 1.5, "1"):
            with self.subTest(count=count):
                source = TrackedReads(io.BytesIO(b"inert"))
                reader = scanner.PickleOpcodeReader(source, 64)
                self.assert_budget(lambda: reader.read(count))
                self.assertEqual(source.requests, [])
                self.assert_budget(reader.check_budget)
        reader = scanner.PickleOpcodeReader(io.BytesIO(b"inert"), 64)
        self.assert_budget(reader.read)

    def test_reader_preserves_zero_reads_seek_tell_and_exact_boundary(self):
        source = TrackedReads(io.BytesIO(b"a" * 64))
        reader = scanner.PickleOpcodeReader(source, 64)
        self.assertEqual(reader.read(0), b"")
        self.assertEqual(reader.read(64), b"a" * 64)
        self.assertEqual(reader.tell(), 64)
        reader.seek(-1, io.SEEK_CUR)
        self.assertEqual(reader.read(1), b"a")
        self.assertEqual(reader.read(1), b"")
        reader.check_budget()

    def test_protocol0_raw_line_boundary_includes_newline(self):
        accepted = b"S'" + b"a" * 61 + b"'\n."
        rejected = b"S'" + b"a" * 62 + b"'\n."
        self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(accepted)))
        self.inspector().inspect_pickle(io.BytesIO(accepted))
        for method in ("pickle_candidate", "inspect_pickle"):
            self.assert_budget(lambda: getattr(self.inspector(), method)(io.BytesIO(rejected)))

    def test_utf8_raw_byte_budget_is_stricter_than_decoded_character_budget(self):
        encoded = ("\u00e9" * 33).encode("utf-8")
        raw = b"\x80\x04\x8c" + bytes([len(encoded)]) + encoded + b"."
        self.assertLess(len(encoded.decode("utf-8")), 64)
        for method in ("pickle_candidate", "inspect_pickle"):
            self.assert_budget(lambda: getattr(self.inspector(), method)(io.BytesIO(raw)))

    def test_escaped_protocol0_raw_budget_is_stricter_than_decoded_value(self):
        raw = b"S'" + b"\\x61" * 16 + b"'\n."
        for method in ("pickle_candidate", "inspect_pickle"):
            self.assert_budget(lambda: getattr(self.inspector(), method)(io.BytesIO(raw)))

    def test_combined_global_postdecode_budget_is_retained(self):
        # Each raw line fits; pickletools combines both into one argument.
        raw = b"c" + b"a" * 32 + b"\n" + b"b" * 32 + b"\n."
        for method in ("pickle_candidate", "inspect_pickle"):
            self.assert_budget(lambda: getattr(self.inspector(), method)(io.BytesIO(raw)))

    def test_short_unterminated_line_remains_a_format_error(self):
        raw = b"S'inert'"
        self.assertFalse(self.inspector().pickle_candidate(io.BytesIO(raw)))
        with self.assertRaises(ValueError):
            self.inspector().inspect_pickle(io.BytesIO(raw))

    def test_truncated_within_budget_binary_remains_a_format_error(self):
        raw = b"\x80\x04\x8e" + (32).to_bytes(8, "little") + b"short"
        self.assertFalse(self.inspector().pickle_candidate(io.BytesIO(raw)))
        with self.assertRaises(ValueError):
            self.inspector().inspect_pickle(io.BytesIO(raw))

    def test_clean_protocols_still_receive_full_real_picklescan(self):
        import picklescan.scanner as picklescan
        original = picklescan.scan_pickle_bytes
        observed = []

        def recording(data, *args, **kwargs):
            self.assertIsInstance(data, scanner.PickleOpcodeReader)
            observed.append(kwargs)
            return original(data, *args, **kwargs)

        with mock.patch.object(picklescan, "scan_pickle_bytes", side_effect=recording):
            for protocol in range(6):
                raw = pickle.dumps({"values": [1, 2, 3], "text": "inert"}, protocol=protocol)
                with self.subTest(protocol=protocol):
                    inspector = self.inspector(argument=1024)
                    self.assertTrue(inspector.pickle_candidate(io.BytesIO(raw)))
                    inspector.inspect_pickle(io.BytesIO(raw))
                    self.assertEqual(inspector.findings, [])
                    self.assertEqual(inspector.pickle_files, 1)
        self.assertEqual(len(observed), 6)
        self.assertTrue(all(item == {"multiple_pickles": True, "strict": False} for item in observed))

    def test_long4_integer_raw_bytes_are_bounded_and_boundary_works(self):
        accepted = b"\x80\x02\x8b" + (64).to_bytes(4, "little") + b"\x01" * 64 + b"."
        self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(accepted)))
        self.inspector().inspect_pickle(io.BytesIO(accepted))
        rejected = b"\x80\x02\x8b" + (65).to_bytes(4, "little")
        self.assert_budget(lambda: self.inspector().inspect_pickle(io.BytesIO(rejected)))

    def test_later_concatenated_stream_is_scanned_and_risk_is_retained(self):
        # This is an inert GLOBAL reference only; no callable is invoked.
        raw = b"N." + b"cos\nsystem\n."
        inspector = self.inspector()
        inspector.inspect_pickle(io.BytesIO(raw))
        self.assertTrue(any(item["rule"] == "pickle.dangerous-global" and item["severity"] == "critical"
                            for item in inspector.findings))
        oversized = b"N." + b"\x80\x04\x8e" + (1 << 30).to_bytes(8, "little")
        self.assert_budget(lambda: self.inspector().inspect_pickle(TrackedReads(io.BytesIO(oversized))))

    def test_picklescan_swallowed_budget_failure_cannot_become_clean(self):
        import picklescan.scanner as picklescan

        def swallowing(data, *args, **kwargs):
            try:
                data.read(65)
            except scanner.Incomplete:
                pass
            return types.SimpleNamespace(scan_err=False, scanned_files=1, globals=[])

        inspector = self.inspector()
        with mock.patch.object(picklescan, "scan_pickle_bytes", side_effect=swallowing) as final_pass:
            self.assert_budget(lambda: inspector.inspect_pickle(io.BytesIO(b"N.")))
        final_pass.assert_called_once()
        self.assertEqual(inspector.pickle_files, 0)

    def test_picklescan_failure_without_budget_still_fails_closed(self):
        import picklescan.scanner as picklescan
        result = types.SimpleNamespace(scan_err=True, scanned_files=1, globals=[])
        with mock.patch.object(picklescan, "scan_pickle_bytes", return_value=result):
            with self.assertRaises(scanner.Incomplete) as caught:
                self.inspector().inspect_pickle(io.BytesIO(b"N."))
        self.assertEqual(str(caught.exception), "pickle_analysis_incomplete")

    def test_opcode_limit_and_global_resource_error_classification_are_retained(self):
        with self.assertRaises(scanner.Incomplete) as caught:
            self.inspector(max_pickle_opcodes=1).inspect_pickle(io.BytesIO(b"N."))
        self.assertEqual(str(caught.exception), "pickle_opcode_limit")
        self.assertIn("pickle_argument_limit", scanner.ERROR_CODES)
        self.assertNotIn("pickle_argument_limit", scanner.FILE_ERROR_CODES)


if __name__ == "__main__":
    unittest.main()
