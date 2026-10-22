# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Actual stdlib-only VM controls; AST loads the exact production VM definitions.

This intentionally does not import scanner/resource/Picklescan on Windows and
does not substitute any dependency. Full inspector controls are in the separate
Linux parameter_compat_tests.py. No loader, torch object or reducer is executed.
"""
import ast
import hashlib
import io
from pathlib import Path
import pickletools
import re
import struct
import types
import unittest

import parameter_fixture_bytes as fixtures


def load_vm():
    needed = {'MAX_TRACKER_SLOTS', 'STORAGE_WIDTHS', 'KEY_RE', 'LEGACY_SLOTS_MAX',
        'LEGACY_INT_MAX', 'LEGACY_WIDTHS', 'LEGACY_FLOATS', 'LEGACY_GLOBALS',
        'LayoutError', 'require', 'GlobalToken', 'StorageReferences', 'LegacyTorchError',
        'legacy_require', 'LegacyGlobal', 'LegacyMap', 'LegacyList', 'LegacyStorage',
        'LegacyTensor', 'LegacyBoundedReader', 'LegacyMachine', '_PARAMETER_SYMBOL',
        '_ZIP_PARAMETER_SEAL', '_ZipParameter', '_ZipParameterMachine', '_ZipParameterContext'}
    source = Path(__file__).with_name('scanner.py')
    tree = ast.parse(source.read_text('utf-8'))
    nodes = [node for node in tree.body if
        isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in needed or
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in needed
                                            for target in node.targets)]
    namespace = dict(hashlib=hashlib, io=io, pickletools=pickletools, re=re, struct=struct)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
    assert needed <= set(namespace)
    return types.SimpleNamespace(**namespace)


vm = load_vm()


def limits(**changes):
    return dict({'max_pickle_opcodes': 65536, 'max_pickle_argument': 1 << 20,
        'max_members': 64, 'max_file_bytes': 1 << 20, 'max_scan_bytes': 1 << 20}, **changes)


class ParameterVMTests(unittest.TestCase):
    def reject(self, raw, code='unsupported_container_or_serialization', machine=None):
        machine = machine or vm._ZipParameterMachine(limits())
        with self.assertRaises(vm.LegacyTorchError) as caught:
            machine.parse(raw)
        self.assertEqual(caught.exception.code, code)

    def test_four_positive_shapes_and_exact_aliases(self):
        for case_id in ('U01', 'U02', 'U03', 'U04'):
            with self.subTest(case_id=case_id):
                machine = vm._ZipParameterMachine(limits())
                root = machine.parse(fixtures.metadata(case_id))
                self.assertIs(type(root), vm.LegacyMap)
                self.assertTrue(root.ordered)
                self.assertEqual(len(machine.parameters), 1)
                self.assertEqual(set(machine.layout.storages), {'0', '1'} if case_id == 'U02' else {'0'})
                if case_id == 'U04':
                    self.assertIs(root.items['weight'], root.items['same_parameter'])
                    self.assertIs(root.items['weight'].data, root.items['same_tensor'])
                    self.assertIs(root.items['same_tensor'].storage, root.items['shared_storage_tensor'].storage)
                if case_id == 'U03':
                    self.assertIs(root.items['weight'].grad, False)

    def test_parameter_arity_data_bool_hooks_and_state_are_exact(self):
        for case_id in ('S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'A02', 'Z04'):
            with self.subTest(case_id=case_id):
                self.reject(fixtures.metadata(case_id))

    def test_hooks_root_metadata_alias_mutation_is_rejected_at_terminal_check(self):
        machine = vm._ZipParameterMachine(limits())
        self.reject(fixtures.metadata('A01'), machine=machine)
        self.assertEqual(len(machine.parameters), 1)
        self.assertEqual(set(machine.parameters[0].hooks.items), {''})
        self.assertIs(machine.parameters[0].hooks, machine.stack[0].state.items['_metadata'])

    def test_tensor_hooks_alias_mutation_retains_original_terminal_check(self):
        raw = fixtures.metadata('U04')[:-1]
        raw += fixtures.version_metadata(alias_hooks=True).replace(fixtures.memo_get(300), fixtures.memo_get(2)) + b'.'
        self.reject(raw)

    def test_every_created_parameter_must_be_a_direct_root_value(self):
        machine = vm._ZipParameterMachine(limits())
        root = machine.parse(fixtures.metadata('U01'))
        parameter = root.items['weight']
        root.items['weight'] = parameter.data
        with self.assertRaises(vm.LegacyTorchError) as caught:
            machine.final_state(root)
        self.assertEqual(caught.exception.code, 'unsupported_container_or_serialization')

    def test_integer_storage_cannot_require_grad(self):
        self.reject(fixtures.metadata('U01').replace(b'FloatStorage', b'LongStorage'))

    def test_tensor_bounds_are_reused(self):
        self.reject(fixtures.metadata('R04'), 'archive_member_size')

    def test_pid_rules_reject_conflicting_storage_redeclarations(self):
        machine = vm._ZipParameterMachine(limits())
        root = machine.parse(fixtures.metadata('U01'))
        kind = vm.LegacyGlobal('torch', 'FloatStorage')
        with self.assertRaises(vm.LegacyTorchError) as caught:
            machine.persistent(('storage', kind, '0', 'cpu', 2))
        self.assertEqual(caught.exception.code, 'invalid_serialization')
        self.assertEqual(root.items['weight'].data.storage.numel, 1)

    def test_protocol_frame_repeat_and_trailing_stream_fail_closed(self):
        self.reject(fixtures.metadata('C02'))
        self.reject(fixtures.metadata('U01')[:2] + b'\x80\x02' + fixtures.metadata('U01')[2:], 'invalid_serialization')
        self.reject(fixtures.metadata('U01')[:2] + b'\x95' + bytes(8) + fixtures.metadata('U01')[2:])
        self.reject(fixtures.metadata('M02'), 'invalid_serialization')

    def test_missing_memo_and_resource_limits_have_fixed_codes(self):
        self.reject(fixtures.metadata('M01'), 'invalid_serialization')
        small = vm._ZipParameterMachine(limits())
        small.max_slots = 8
        self.reject(fixtures.metadata('U01'), 'pickle_symbol_budget', small)
        self.reject(fixtures.metadata('U01'), 'pickle_opcode_limit',
                    vm._ZipParameterMachine(limits(max_pickle_opcodes=1)))

    def test_default_legacy_machine_has_no_parameter_allowance(self):
        machine = vm.LegacyMachine(limits())
        with self.assertRaises(vm.LegacyTorchError) as caught:
            machine.global_token(*fixtures.PARAM)
        self.assertEqual(caught.exception.code, 'unsupported_container_or_serialization')

    def context(self):
        raw = fixtures.metadata('U01')
        context = vm._ZipParameterContext(raw, 0, 'archive/data.pkl', limits(), vm._ZIP_PARAMETER_SEAL)
        context.stream = io.BytesIO(raw)
        return context

    def test_private_context_binds_bytes_stream_member_and_limits(self):
        for mutation in ('bytes', 'stream', 'member', 'limits'):
            with self.subTest(mutation=mutation):
                context = self.context()
                stream, chain, selected_limits = context.stream, context.chain, limits()
                if mutation == 'bytes':
                    stream.seek(0); stream.write(fixtures.metadata('U03'))
                elif mutation == 'stream':
                    stream = io.BytesIO(context.raw)
                elif mutation == 'member':
                    chain = ((1, chain[0][1]),)
                else:
                    selected_limits['max_members'] = 63
                with self.assertRaises(vm.LegacyTorchError) as caught:
                    context.prove(stream, chain, selected_limits)
                self.assertEqual(caught.exception.code, 'unsupported_container_or_serialization')
                self.assertIsNone(context.specs)

    def test_private_proof_discharge_is_exact_and_single_use(self):
        context = self.context()
        self.assertEqual(context.prove(context.stream, context.chain, limits()), {fixtures.PARAM})
        self.assertEqual(set(context.specs), {'0'})
        self.assertIs(context.machine.stack[0].items['weight'], context.machine.parameters[0])
        with self.assertRaises(vm.LegacyTorchError) as caught:
            context.prove(context.stream, context.chain, limits())
        self.assertEqual(caught.exception.code, 'unsupported_container_or_serialization')


if __name__ == '__main__':
    unittest.main()
