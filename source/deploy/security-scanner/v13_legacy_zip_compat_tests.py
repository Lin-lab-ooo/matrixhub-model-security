# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Old typed-storage ZIP compatibility; static literal bytes, no model execution."""
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('legacy_zip_compat_scanner', Path(__file__).with_name('scanner.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
FIXTURES = {}


def text(value):
    raw = value.encode('ascii')
    return b'X' + struct.pack('<I', len(raw)) + raw


def metadata(*, location='cpu', dtype='FloatStorage', injected=b''):
    # One typed CPU storage PID, one literal tensor description, and empty hooks.
    # These opcodes are only disassembled; referenced functions are never called.
    return (b'\x80\x02' + injected + b'ctorch._utils\n_rebuild_tensor_v2\n('
            + b'(' + text('storage') + b'ctorch\n' + dtype.encode('ascii') + b'\n'
            + text('0') + text(location) + b'K\x01tQK\x00K\x01\x85K\x01\x85\x89'
            + b'ccollections\nOrderedDict\n)RtR.')


def archive(label, *, byteorder=None, version=b'3\n', payload=b'.\x00\x00\x00',
            location='cpu', dtype='FloatStorage', injected=b'', extra=None, omit_storage=False):
    stream = io.BytesIO()
    members = [('archive/data.pkl', metadata(location=location, dtype=dtype, injected=injected))]
    if not omit_storage:
        members.append(('archive/data/0', payload))
    if version is not None:
        members.append(('archive/version', version))
    if byteorder is not None:
        members.append(('archive/byteorder', byteorder))
    if extra is not None:
        members.append(extra)
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as output:
        for name, raw in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100600 << 16
            output.writestr(info, raw)
    raw = stream.getvalue()
    FIXTURES[label] = raw
    return raw


def inspector(**changes):
    return scanner.StaticInspector(dict(scanner.limits_from_env(), **changes))


class LegacyZipCompatibilityTests(unittest.TestCase):
    def inspect_ok(self, raw):
        value = inspector()
        value.inspect(io.BytesIO(raw), 'weights.bin')
        self.assertEqual(value.findings, [])
        self.assertEqual(value.pickle_files, 1)
        proof = value.verified_framework_zip
        self.assertEqual((proof['storageCount'], proof['storageBytes']), (1, 4))
        self.assertTrue(proof['allStorageCRCsVerified'])
        self.assertFalse(proof['modelDeserialized'])
        return value

    def reject(self, raw, *, expected=None, **limits):
        value = inspector(**limits)
        with self.assertRaises((scanner.Incomplete, zipfile.BadZipFile)) as caught:
            value.inspect(io.BytesIO(raw), 'weights.bin')
        if expected is not None:
            self.assertEqual(str(caught.exception), expected)
        self.assertFalse(hasattr(value, 'verified_framework_zip'))
        return value

    def test_old_zip_without_byteorder_completes_full_metadata_scan(self):
        from picklescan import scanner as picklescan
        actual_scan = picklescan.scan_pickle_bytes
        with mock.patch.object(picklescan, 'scan_pickle_bytes', wraps=actual_scan) as observed:
            value = self.inspect_ok(archive('old-no-byteorder'))
        self.assertEqual(observed.call_count, 1)
        self.assertEqual(value.verified_framework_zip['memberCount'], 3)
        self.assertEqual(value.expanded, len(metadata()) + len(b'3\n'))

    def test_explicit_little_endian_layout_retains_same_proof(self):
        self.inspect_ok(archive('explicit-little', byteorder=b'little'))

    def test_explicit_non_little_byteorder_remains_unsupported(self):
        for order in (b'big', b'', b'little\n'):
            with self.subTest(order=order):
                self.reject(archive('bad-order-' + repr(order), byteorder=order),
                            expected='unsupported_container_or_serialization')

    def test_old_zip_version_must_still_be_three(self):
        for version in (b'2\n', b'4\n', b'3'):
            with self.subTest(version=version):
                self.reject(archive('bad-version-' + repr(version), version=version))

    def test_exact_storage_member_closure_and_length_remain_required(self):
        for name, options in (
            ('missing-storage', {'omit_storage': True}),
            ('wrong-size', {'payload': b'abc'}),
            ('extra-storage', {'extra': ('archive/data/1', b'abcd')}),
            ('extra-content', {'extra': ('archive/other.txt', b'harmless')}),
        ):
            with self.subTest(name=name):
                self.reject(archive(name, **options))

    def test_pid_must_still_use_supported_cpu_dtype(self):
        for name, options in (('cuda-pid', {'location': 'cuda:0'}),
                              ('unknown-dtype', {'dtype': 'UnsupportedStorage'})):
            with self.subTest(name=name):
                self.reject(archive(name, **options))

    def test_dangerous_global_is_observed_before_layout_rejection(self):
        value = self.reject(archive('dangerous-reference', injected=b'cos\nsystem\n0'))
        self.assertTrue(any(row['rule'] == 'pickle.dangerous-global' and row['severity'] == 'critical'
                            for row in value.findings))

    def test_parameter_global_remains_unknown_and_incomplete(self):
        value = self.reject(archive('unknown-parameter', injected=b'ctorch._utils\n_rebuild_parameter\n0'),
                            expected='unsupported_container_or_serialization')
        self.assertTrue(any(row['rule'] == 'pickle.unknown-global' for row in value.findings))

    def test_storage_crc_is_verified_in_missing_byteorder_profile(self):
        raw = bytearray(archive('crc-before'))
        with zipfile.ZipFile(io.BytesIO(raw)) as source:
            member = source.getinfo('archive/data/0')
            nlen, xlen = struct.unpack_from('<HH', raw, member.header_offset + 26)
            raw[member.header_offset + 30 + nlen + xlen] ^= 1
        FIXTURES['corrupt-storage-crc'] = bytes(raw)
        self.reject(bytes(raw))

    def test_member_metadata_and_storage_budgets_remain_enforced(self):
        raw = archive('budget-control')
        for limits in ({'max_members': 2}, {'max_expanded_bytes': 16}, {'max_scan_bytes': 3}):
            with self.subTest(limits=limits):
                self.reject(raw, **limits)

    def test_without_version_does_not_select_framework_profile(self):
        raw = archive('no-version', version=None)
        self.assertFalse(scanner.selects_protocol2_framework(io.BytesIO(raw), scanner.limits_from_env()))


if __name__ == '__main__':
    unittest.main()
