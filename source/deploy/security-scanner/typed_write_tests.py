"""Stdlib-only production type-observer regressions; no unpickling or imports.

Select scanner via MATRIX_TYPED_SCANNER when testing a canonical staged copy.
"""
import ast
import io
import os
from pathlib import Path
import pickletools
import struct
import types
import unittest

SOURCE = Path(os.environ.get('MATRIX_TYPED_SCANNER', str(Path(__file__).with_name('scanner.py'))))
tree = ast.parse(SOURCE.read_bytes())
names = {'Incomplete', '_WriteMap', '_WriteGlobal', 'ContainerWriteTypes'}
nodes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in names]
namespace = {'pickletools': pickletools}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), namespace)
assert names <= set(namespace)
scanner = types.SimpleNamespace(**namespace)


def text(value):
    value = value.encode('ascii')
    return b'X' + struct.pack('<I', len(value)) + value


def observe(raw, observer=None, budget=4096):
    observer = observer or scanner.ContainerWriteTypes(budget)
    for opcode, arg, _ in pickletools.genops(io.BytesIO(raw)):
        observer.apply(opcode, arg)
    return observer


class TypedWriteTests(unittest.TestCase):
    def reject(self, raw, code=None):
        with self.assertRaises(scanner.Incomplete) as error:
            observe(raw)
        if code:
            self.assertEqual(str(error.exception), code)

    def test_builtin_maps_protocol_zero_two_four_and_five(self):
        for raw in (b'(dVkey\nI1\ns.', b'\x80\x02}' + text('key') + b'K\x01s.',
                    b'\x80\x04}(\x8c\x03keyK\x01u.', b'\x80\x05}(u.'):
            observe(raw)

    def test_nonmap_write_targets_reject_both_opcodes(self):
        for target in (b']', b'K\x00', b')', b'N', b'\x88', text('value'), b'F1.0\n'):
            for values, opcode in ((text('key') + b'K\x01', b's'), (b'(' + text('key') + b'K\x01', b'u')):
                with self.subTest(target=target, opcode=opcode):
                    self.reject(b'\x80\x02' + target + values + opcode + b'.', 'invalid_serialization')

    def test_empty_ordereddict_constructors_are_proven_without_calling(self):
        for prefix in (b'ccollections\nOrderedDict\n)R',
                       b'ccollections\nOrderedDict\n(tR',
                       b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R'):
            observe(b'\x80\x04' + prefix + text('key') + b'K\x01s.')

    def test_nonempty_ordereddict_arguments_are_unknown(self):
        raw = b'ccollections\nOrderedDict\n] \x85R'.replace(b' ', b'')
        self.reject(b'\x80\x02' + raw + text('key') + b'K\x01s.', 'unsupported_container_or_serialization')

    def test_lookalike_and_other_reducer_returns_never_establish_map(self):
        for target in (b'ccollections\nOrderedDictExtra\n', b'cbuiltins\ndict\n', b'ctorch._utils\n_rebuild_tensor_v2\n'):
            self.reject(b'\x80\x02' + target + b')R' + text('key') + b'K\x01s.', 'unsupported_container_or_serialization')

    def test_persistent_result_and_newobj_are_unknown(self):
        for target in (text('storage') + b'Q', b'Pstorage\n', b'ccollections\nOrderedDict\n)\x81'):
            self.reject(b'\x80\x02' + target + text('key') + b'K\x01s.', 'unsupported_container_or_serialization')

    def test_memo_alias_retains_exact_map_token_identity(self):
        observer = observe(b'\x80\x02}q\x002q\x01' + text('key') + b'K\x01s0h\x00.')
        self.assertIs(observer.memo[0], observer.memo[1])
        self.assertIs(type(observer.memo[0]), scanner._WriteMap)

    def test_memo_overwrite_and_list_alias_do_not_inherit_map_type(self):
        self.reject(b'\x80\x02}q\x000]q\x000h\x00' + text('key') + b'K\x01s.', 'invalid_serialization')
        self.reject(b'\x80\x04]\x940h\x00(' + text('key') + b'K\x01u.', 'invalid_serialization')

    def test_put_get_encodings_and_memoize(self):
        for put, get in ((b'p0\n', b'g0\n'), (b'q\x00', b'h\x00'),
                         (b'r' + struct.pack('<I', 3), b'j' + struct.pack('<I', 3)), (b'\x94', b'h\x00')):
            observe(b'\x80\x04}' + put + b'0' + get + text('key') + b'K\x01s.')

    def test_build_preserves_known_target_but_does_not_promote_unknown(self):
        observe(b'\x80\x02ccollections\nOrderedDict\n)R}b' + text('key') + b'K\x01s.')
        self.reject(b'\x80\x02ctorch._utils\n_rebuild_tensor_v2\n)R}b' + text('key') + b'K\x01s.', 'unsupported_container_or_serialization')

    def test_marks_pops_and_nested_container_values_keep_target(self):
        observe(b'\x80\x02}(K\x01K\x021' + text('key') + b']s.')
        observe(b'\x80\x02}(' + text('key') + b'}' + text('inner') + b'K\x01su.')
        self.reject(b'\x80\x02}((u.', 'invalid_serialization')

    def test_odd_setitems_and_dict_rejected(self):
        for raw in (b'\x80\x02}(K\x01u.', b'\x80\x02(K\x01d.'):
            self.reject(raw, 'invalid_serialization')

    def test_retained_and_fresh_streams_are_independent(self):
        retained = observe(b'\x80\x02}q\x00.')
        retained.next_stream()
        observe(b'\x80\x02h\x00' + text('key') + b'K\x01s.', retained)
        self.reject(b'\x80\x02h\x00' + text('key') + b'K\x01s.', 'invalid_serialization')

    def test_slot_and_sparse_memo_budget_fail_closed(self):
        with self.assertRaises(scanner.Incomplete) as error:
            observe(b'\x80\x02}q\x000}q\x010}q\x02.', budget=2)
        self.assertEqual(str(error.exception), 'pickle_symbol_budget')
        with self.assertRaises(scanner.Incomplete) as error:
            observe(b'\x80\x02}r' + struct.pack('<I', 100) + b'.', budget=2)
        self.assertEqual(str(error.exception), 'pickle_symbol_budget')


if __name__ == '__main__':
    unittest.main()
