# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Unknown-format probe regressions; ordinary inert bytes, no deserialization."""
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('candidate_probe_scanner', Path(__file__).with_name('scanner.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

TEXT = b'Xhello ordinary plain text; no serialized object.\n'
TRACKED = []


def zip_text():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo('ordinary.txt', date_time=(1980, 1, 1, 0, 0, 0))
        archive.writestr(info, TEXT)
    return stream.getvalue()


def tar_text():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo('ordinary.txt')
        info.size, info.mtime = len(TEXT), 0
        archive.addfile(info, io.BytesIO(TEXT))
    return stream.getvalue()


FIXTURES = {'ordinary-text': TEXT, 'ordinary-text-zip': zip_text(), 'ordinary-text-tar': tar_text(),
            'unconfirmed-t': b'T' + (1000).to_bytes(4, 'little'), 'unconfirmed-u': b'U\xff',
            'exact-unicode64': b'X' + (64).to_bytes(4, 'little') + b'a' * 64 + b'.',
            'oversized-unicode65': b'X' + (65).to_bytes(4, 'little') + b'a' * 65 + b'.',
            'oversized-with-reference-tail': b'X' + (65).to_bytes(4, 'little') + b'a' * 65 + b'cos\nsystem\n.',
            'reference-before-oversized': b'cos\nsystem\nX' + (65).to_bytes(4, 'little') + b'a' * 65 + b'.'}


class Tracked:
    def __init__(self, raw, *, limit=64, short=False, failure=None):
        self.stream = io.BytesIO(raw)
        self.tell, self.seek = self.stream.tell, self.stream.seek
        self.limit, self.short, self.failure = limit, short, failure
        self.requests, self.delivered, self.eof_reads = [], 0, 0
        TRACKED.append(self)

    def read(self, count=-1):
        self.requests.append(count)
        if type(count) is not int or not 0 <= count <= min(self.limit, 64 << 10):
            raise AssertionError('unexpected oversized underlying read')
        if count > 4 and self.failure is not None:
            if self.failure == 'io':
                raise OSError('inert read failure')
            if self.failure == 'none':
                return None
            if self.failure == 'too-many':
                return b'a' * (count + 1)
        value = self.stream.read(min(count, 7) if self.short and count > 4 else count)
        self.delivered += len(value)
        if not value:
            self.eof_reads += 1
        return value

    def readline(self, count=-1):
        if type(count) is not int or not 0 <= count <= self.limit + 1:
            raise AssertionError('unexpected oversized underlying line')
        return self.stream.readline(count)


class CandidateProbeTests(unittest.TestCase):
    def inspector(self, limit=64):
        return scanner.StaticInspector(dict(scanner.limits_from_env(), max_pickle_argument=limit))

    def budget(self, callback):
        with self.assertRaises(scanner.Incomplete) as caught:
            callback()
        self.assertEqual(str(caught.exception), 'pickle_argument_limit')

    def test_ordinary_short_ascii_unknown_extensions_are_not_pickle(self):
        for name in ('ordinary.txt', 'ordinary.json', 'ordinary.com'):
            with self.subTest(name=name):
                inspector = self.inspector()
                inspector.inspect(io.BytesIO(TEXT), name)
                self.assertEqual(inspector.pickle_files, 0)
                self.assertEqual(inspector.findings, [])

    def test_ordinary_ascii_zip_member_is_covered(self):
        inspector = self.inspector()
        inspector.inspect(io.BytesIO(FIXTURES['ordinary-text-zip']), 'ordinary.zip')
        self.assertEqual(inspector.members, 1)
        self.assertEqual(inspector.expanded, len(TEXT))
        self.assertEqual(inspector.findings, [])

    def test_ordinary_ascii_tar_member_is_covered(self):
        inspector = self.inspector()
        inspector.inspect(io.BytesIO(FIXTURES['ordinary-text-tar']), 'ordinary.tar')
        self.assertEqual(inspector.members, 1)
        self.assertEqual(inspector.expanded, len(TEXT))
        self.assertEqual(inspector.findings, [])

    def test_nonproto_binary_strings_proven_truncated_are_not_candidate(self):
        for name in ('unconfirmed-t', 'unconfirmed-u'):
            with self.subTest(name=name):
                source = Tracked(FIXTURES[name])
                self.assertFalse(self.inspector().pickle_candidate(source))
                self.assertGreater(source.eof_reads, 0)
                self.assertEqual(source.tell(), 0)

    def test_proto_declaration_keeps_original_strict_budget(self):
        for protocol in range(6):
            with self.subTest(protocol=protocol):
                raw = b'\x80' + bytes([protocol]) + FIXTURES['unconfirmed-t']
                for method in ('pickle_candidate', 'inspect_pickle'):
                    source = Tracked(raw)
                    self.budget(lambda: getattr(self.inspector(), method)(source))
                    self.assertLessEqual(max(source.requests), 4)

    def test_explicit_pickle_extensions_keep_budget_rejection(self):
        for extension in ('.pkl', '.pickle', '.bin', '.pt'):
            with self.subTest(extension=extension):
                self.budget(lambda: self.inspector().inspect(io.BytesIO(TEXT), 'ordinary' + extension))

    def test_direct_full_inspection_and_default_reader_remain_strict(self):
        source = Tracked(TEXT)
        self.budget(lambda: self.inspector().inspect_pickle(source))
        self.assertLessEqual(max(source.requests), 4)
        source = Tracked(b'abc')
        reader = scanner.PickleOpcodeReader(source, 64)
        self.budget(lambda: reader.read(65))
        self.assertEqual(source.requests, [])

    def test_real_oversized_operand_and_hidden_reference_tail_rejected(self):
        for name in ('oversized-unicode65', 'oversized-with-reference-tail'):
            with self.subTest(name=name):
                source = Tracked(FIXTURES[name], short=True)
                self.budget(lambda: self.inspector().pickle_candidate(source))
                self.assertLessEqual(source.delivered, 5 + 64)

    def test_exact_argument_boundary_still_gets_full_picklescan(self):
        raw = FIXTURES['exact-unicode64']
        self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(raw)))
        inspector = self.inspector()
        inspector.inspect(io.BytesIO(raw), 'ordinary.txt')
        self.assertEqual(inspector.pickle_files, 1)
        self.assertEqual(inspector.findings, [])

    def test_short_read_is_not_treated_as_eof(self):
        source = Tracked(TEXT, short=True)
        self.assertFalse(self.inspector().pickle_candidate(source))
        self.assertEqual(source.delivered, len(TEXT))
        self.assertEqual(source.eof_reads, 1)
        self.assertGreater(len(source.requests), 4)
        self.assertEqual(source.tell(), 0)

    def test_candidate_probe_exhaustion_stays_bounded(self):
        limit = 128 << 10
        raw = b'X' + (limit + 1).to_bytes(4, 'little') + b'a' * (limit + 1) + b'.'
        source = Tracked(raw, limit=limit)
        self.budget(lambda: self.inspector(limit).pickle_candidate(source))
        self.assertLessEqual(source.delivered, 5 + limit)
        self.assertLessEqual(max(source.requests), 64 << 10)

    def test_probe_io_failure_or_invalid_read_never_becomes_false(self):
        for failure in ('io', 'none', 'too-many'):
            with self.subTest(failure=failure):
                source = Tracked(TEXT, failure=failure)
                self.budget(lambda: self.inspector().pickle_candidate(source))

    def test_observed_reference_selects_strict_full_inspection(self):
        raw = FIXTURES['reference-before-oversized']
        self.assertTrue(self.inspector().pickle_candidate(io.BytesIO(raw)))
        inspector = self.inspector()
        self.budget(lambda: inspector.inspect(io.BytesIO(raw), 'ordinary.txt'))
        self.assertTrue(any(item['rule'] == 'pickle.dangerous-global' for item in inspector.findings))


if __name__ == '__main__':
    unittest.main()
