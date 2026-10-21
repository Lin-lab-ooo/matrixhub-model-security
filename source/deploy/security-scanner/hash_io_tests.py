"""Full-byte SHA regression; no antivirus or sandbox is simulated as PASS."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('hash_io_scanner', Path(__file__).with_name('scanner.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ShortReads(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.total = self.calls = 0

    def readinto(self, buffer):
        self.calls += 1
        count = super().readinto(memoryview(buffer)[:7])
        self.total += count
        return count


class HashIOTests(unittest.TestCase):
    def test_empty_and_buffer_boundaries_match_reference(self):
        for size in (0, 1, 127, (1 << 20) - 1, 1 << 20, (1 << 20) + 17):
            with self.subTest(size=size):
                raw = (bytes(range(256)) * ((size + 255) // 256))[:size]
                self.assertEqual(scanner.stream_sha256(io.BytesIO(raw)), hashlib.sha256(raw).hexdigest())

    def test_short_reads_consume_every_byte_and_eof(self):
        raw = bytes(range(256)) * 3
        stream = ShortReads(raw)
        self.assertEqual(scanner.stream_sha256(stream), hashlib.sha256(raw).hexdigest())
        self.assertEqual(stream.total, len(raw))
        self.assertEqual(stream.tell(), len(raw))
        self.assertEqual(stream.calls, (len(raw) + 6) // 7 + 1)

    def test_digest_starts_at_current_position_and_finishes_at_eof(self):
        stream = io.BytesIO(b'prefix:actual-body')
        stream.seek(7)
        self.assertEqual(scanner.stream_sha256(stream), hashlib.sha256(b'actual-body').hexdigest())
        self.assertEqual(stream.tell(), len(b'prefix:actual-body'))

    def test_read_error_propagates_instead_of_returning_partial_digest(self):
        stream = mock.Mock()
        stream.readinto.side_effect = OSError('inert simulated read failure')
        with self.assertRaises(OSError):
            scanner.stream_sha256(stream)

    def test_invalid_or_nonblocking_read_count_cannot_be_eof(self):
        for count in (None, -1, (1 << 20) + 1, True, '1'):
            with self.subTest(count=count):
                stream = mock.Mock()
                stream.readinto.return_value = count
                with self.assertRaises(OSError):
                    scanner.stream_sha256(stream)

    def test_same_size_change_cannot_reuse_digest(self):
        self.assertNotEqual(scanner.stream_sha256(io.BytesIO(b'safe')),
                            scanner.stream_sha256(io.BytesIO(b'evil')))

    def test_file_sha_matches_reference_and_does_not_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_bytes(b'safe')
            self.assertEqual(scanner.file_sha(path), hashlib.sha256(b'safe').hexdigest())
            path.write_bytes(b'evil')
            self.assertEqual(scanner.file_sha(path), hashlib.sha256(b'evil').hexdigest())


if __name__ == '__main__':
    unittest.main()
