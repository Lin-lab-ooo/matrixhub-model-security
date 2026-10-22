# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Full real StaticInspector controls; run in the pinned Linux scanner runtime.

These are tiny static inspections, never model loads or native AV claims.
"""
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

import parameter_fixture_bytes as fixtures

spec = importlib.util.spec_from_file_location('parameter_compat_scanner', Path(__file__).with_name('scanner.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ParameterCompatibilityTests(unittest.TestCase):
    def inspect_ok(self, case_id):
        fixture = fixtures.build(case_id)
        inspector = scanner.StaticInspector(scanner.limits_from_env())
        result = inspector.inspect(io.BytesIO(fixture.content), 'fixture' + fixture.suffix)
        self.assertIsNone(result)
        self.assertEqual(inspector.findings, [])
        self.assertEqual(inspector.pickle_files, 1)
        self.assertTrue(inspector.verified_framework_zip['allStorageCRCsVerified'])
        self.assertFalse(inspector.verified_framework_zip['modelDeserialized'])
        return inspector

    def reject(self, case_id, code, *, rule=None, **changes):
        fixture = fixtures.build(case_id)
        inspector = scanner.StaticInspector(dict(scanner.limits_from_env(), **changes))
        with self.assertRaises(scanner.Incomplete) as caught:
            inspector.inspect(io.BytesIO(fixture.content), 'fixture' + fixture.suffix)
        self.assertEqual(caught.exception.args[0], code)
        self.assertFalse(hasattr(inspector, 'verified_framework_zip'))
        if rule is not None:
            self.assertTrue(any(row['rule'] == rule for row in inspector.findings))
        return inspector

    def test_four_legal_parameter_variants(self):
        for case_id in ('U01', 'U02', 'U03', 'U04'):
            with self.subTest(case_id=case_id):
                inspector = self.inspect_ok(case_id)
                self.assertEqual(inspector.verified_framework_zip['storageBytes'], 37636 if case_id == 'U02' else 4)

    def test_bare_and_protocol3_parameter_remain_unknown(self):
        for case_id in ('C01', 'C02'):
            with self.subTest(case_id=case_id):
                self.reject(case_id, 'unsupported_container_or_serialization', rule='pickle.unknown-global')

    def test_parameter_semantic_negatives_have_fixed_coverage(self):
        for case_id in ('S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'A01', 'A02', 'Z04'):
            with self.subTest(case_id=case_id):
                self.reject(case_id, 'unsupported_container_or_serialization', rule='pickle.unknown-global')

    def test_other_unknown_dangerous_and_nested_findings_are_retained(self):
        for case_id, rule in (('D01', 'pickle.dangerous-global'), ('D02', 'pickle.unknown-global'),
                              ('D03', 'pickle.nested-deserialization-reference')):
            with self.subTest(case_id=case_id):
                inspector = self.reject(case_id, 'unsupported_container_or_serialization', rule=rule)
                if case_id == 'D03':
                    evidence = next(row['evidence'] for row in inspector.findings if row['rule'] == rule)
                    self.assertEqual(evidence['streamIndex'], 0)
                    self.assertIs(type(evidence['opcodeOffset']), int)
                    self.assertEqual(len(evidence['archiveMemberChain']), 1)

    def test_storage_closure_and_lengths_are_not_discharged(self):
        self.reject('Z01', 'invalid_serialization')
        self.reject('Z02', 'archive_member_size')

    def test_storage_crc_failure_does_not_publish_zip_proof(self):
        fixture = fixtures.build('Z03')
        inspector = scanner.StaticInspector(scanner.limits_from_env())
        with self.assertRaises(scanner.zipfile.BadZipFile):
            inspector.inspect(io.BytesIO(fixture.content), 'fixture.zip')
        self.assertFalse(hasattr(inspector, 'verified_framework_zip'))

    def test_missing_memo_and_trailing_stream_have_fixed_codes(self):
        self.reject('M01', 'pickle_symbol_analysis_incomplete')
        self.reject('M02', 'invalid_serialization', rule='pickle.unknown-global')

    def test_operand_and_opcode_limits_remain_sticky(self):
        self.reject('R01', 'pickle_argument_limit', max_pickle_argument=64)
        self.reject('R03', 'pickle_opcode_limit', max_pickle_opcodes=1)

    def test_tensor_bounds_are_still_required(self):
        self.reject('R04', 'archive_member_size', rule='pickle.unknown-global')

    def test_no_parameter_zip_uses_original_observer(self):
        with mock.patch.object(scanner._ZipParameterMachine, 'parse', side_effect=AssertionError('unexpected VM')):
            self.inspect_ok('N01')

    def test_fake_public_proof_dict_cannot_discharge(self):
        inspector = scanner.StaticInspector(scanner.limits_from_env())
        with self.assertRaises(scanner.Incomplete) as caught:
            inspector.inspect_pickle(io.BytesIO(fixtures.metadata('U01')),
                _parameter_context={'approved': True, 'symbol': fixtures.PARAM})
        self.assertEqual(caught.exception.args[0], 'unsupported_container_or_serialization')
        self.assertTrue(any(row['rule'] == 'pickle.unknown-global' for row in inspector.findings))

    def test_original_analyzers_are_called_and_errors_precede_discharge(self):
        from picklescan import scanner as picklescan
        actual = picklescan.scan_pickle_bytes
        with mock.patch.object(picklescan, 'scan_pickle_bytes', wraps=actual) as observed:
            self.inspect_ok('U01')
        self.assertEqual(observed.call_count, 1)
        fixture = fixtures.build('U01')
        inspector = scanner.StaticInspector(scanner.limits_from_env())
        result = type('FailedAnalysis', (), {'scan_err': True, 'scanned_files': 0})()
        with mock.patch.object(picklescan, 'scan_pickle_bytes', return_value=result), \
             mock.patch.object(scanner._ZipParameterMachine, 'parse', side_effect=AssertionError('proof before analyzer')):
            with self.assertRaises(scanner.Incomplete) as caught:
                inspector.inspect(io.BytesIO(fixture.content), 'fixture.zip')
        self.assertEqual(caught.exception.args[0], 'pickle_analysis_incomplete')


if __name__ == '__main__':
    unittest.main()
