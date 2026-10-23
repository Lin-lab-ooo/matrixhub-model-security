"""Real stdlib w+b stream regressions; static inspection only, no native AV."""
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import types
import unittest
import warnings
from unittest import mock

if os.name == "nt":
    sys.modules.setdefault("resource", types.ModuleType("resource"))
    if not hasattr(socketserver, "UnixStreamServer"):
        socketserver.UnixStreamServer = socketserver.TCPServer

spec = importlib.util.spec_from_file_location("r19_gzip_mode_scanner", Path(__file__).with_name("scanner.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def nested_gzip(depth):
    raw = b"Z"
    for level in range(depth):
        raw = gzip.compress(raw, mtime=0)
    return raw


class GzipReadModeTests(unittest.TestCase):
    def inspect_writable_stream(self, depth, *, named=True, rolled=False):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = scanner.limits_from_env()
        self.assertEqual(limits["max_depth"], 3)
        factory = tempfile.NamedTemporaryFile if named else tempfile.SpooledTemporaryFile
        with factory(mode="w+b") as data:
            # Real NamedTemporaryFile may normalize the requested w+b to rb+.
            # Keep the actual writable file, rather than fabricating a mode.
            self.assertTrue(data.readable())
            self.assertTrue(data.writable())
            raw = nested_gzip(depth)
            data.write(raw); data.flush(); data.seek(0)
            if not named:
                if rolled:
                    data.rollover()
                self.assertEqual(data._rolled, rolled)
            inspector = scanner.StaticInspector(limits)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", FutureWarning)
                    inspector.inspect(data, "artifact.gz")
            finally:
                data.seek(0)
                after = data.read()
                self.assertEqual(len(after), len(raw))
                self.assertEqual(hashlib.sha256(after).digest(), hashlib.sha256(raw).digest())
                self.assertEqual(after, raw)
            self.assertEqual(inspector.findings, [])
            return inspector

    def test_named_w_plus_b_single_gzip_is_read_without_mode_inference(self):
        result = self.inspect_writable_stream(1)
        self.assertEqual(result.members, 1)

    def test_named_w_plus_b_depth_three_remains_supported(self):
        result = self.inspect_writable_stream(3)
        self.assertEqual(result.members, 3)

    def test_named_w_plus_b_depth_four_preserves_depth_refusal(self):
        with self.assertRaisesRegex(scanner.Incomplete, "^archive_depth_limit$"):
            self.inspect_writable_stream(4)

    def test_real_spooled_w_plus_b_nested_three_and_four(self):
        for rolled in (False, True):
            with self.subTest(rolled=rolled):
                self.assertEqual(self.inspect_writable_stream(3, named=False, rolled=rolled).members, 3)
                with self.assertRaisesRegex(scanner.Incomplete, "^archive_depth_limit$"):
                    self.inspect_writable_stream(4, named=False, rolled=rolled)


if __name__ == "__main__":
    unittest.main()
