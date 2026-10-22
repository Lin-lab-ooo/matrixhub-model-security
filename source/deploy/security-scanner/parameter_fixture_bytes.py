"""Lazily build the 29 planned inert byte variants; never deserialize or scan.

Only stdlib opcode/ZIP construction is used. Default describes without building
fixtures. Each requested build is independent and below the combined 1 MiB cap.
Expectations remain proposed until the authorized scanner implementation runs.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse
import hashlib
import io
import json
import re
import struct
import zipfile

HERE = Path(__file__).resolve().parent
MAX_COMBINED = 1 << 20
IDS = ('U01', 'U02', 'U03', 'U04', 'C01', 'C02', 'C03', 'S01', 'S02', 'S03', 'S04',
       'S05', 'S06', 'A01', 'A02', 'D01', 'D02', 'D03', 'M01', 'M02', 'R01', 'R02',
       'R03', 'R04', 'Z01', 'Z02', 'Z03', 'Z04', 'N01')
PARAM = ('torch._utils', '_rebuild_parameter')
TENSOR = ('torch._utils', '_rebuild_tensor_v2')


def text(value):
    raw = value.encode('ascii')
    return b'X' + struct.pack('<I', len(raw)) + raw


def integer(value):
    assert type(value) is int and 0 <= value <= 0x7fffffff
    return b'K' + bytes([value]) if value < 256 else b'J' + struct.pack('<i', value)


def global_ref(module, symbol):
    return b'c' + module.encode('ascii') + b'\n' + symbol.encode('ascii') + b'\n'


def memo_put(slot):
    return b'q' + bytes([slot]) if slot < 256 else b'r' + struct.pack('<I', slot)


def memo_get(slot):
    return b'h' + bytes([slot]) if slot < 256 else b'j' + struct.pack('<I', slot)


def tuple_of(values):
    return b'(' + b''.join(integer(value) for value in values) + b't'


def ordered():
    return global_ref('collections', 'OrderedDict') + b')R'


def version_metadata(*, alias_hooks=False):
    # BUILD is applied only to the root. In A01 the same hooks token becomes
    # root._metadata after Parameter REDUCE, so a terminal alias check is needed.
    mapping = memo_get(300) if alias_hooks else ordered()
    mapping += b'(' + text('') + b'}' + text('version') + integer(1) + b'su'
    return b'}' + text('_metadata') + mapping + b'sb'


def tensor(*, shape=(1,), stride=(1,), numel=1, key='0', location='cpu',
           remember=False, shared=False):
    if shared:
        storage, hooks = memo_get(1), memo_get(2)
    else:
        storage = (b'(' + text('storage') + global_ref('torch', 'FloatStorage')
                   + text(key) + text(location) + integer(numel) + b'tQ')
        hooks = ordered()
        if remember:
            storage += memo_put(1)
            hooks += memo_put(2)
    raw = (global_ref(*TENSOR) + b'(' + storage + integer(0) + tuple_of(shape)
           + tuple_of(stride) + b'\x89' + hooks + b'tR')
    return raw + memo_put(3) if remember else raw


def metadata(case_id):
    assert case_id in IDS
    injected = b''
    if case_id == 'D01':
        injected = global_ref('os', 'system') + b'0' + text('not-executed-placeholder') + b'0'
    elif case_id == 'D02':
        injected = global_ref('unsupported_fixture', 'Constructor') + b'0'
    elif case_id == 'D03':
        injected = global_ref('torch.storage', '_load_from_bytes') + b'0'
    elif case_id == 'M01':
        injected = memo_get(255)
    if case_id == 'R01':
        return (b'\x80\x02' + global_ref(*PARAM) + b'0X'
                + struct.pack('<I', 1 << 20))
    shape, stride, numel = ((64, 3, 7, 7), (147, 49, 7, 1), 9408) if case_id == 'U02' else ((1,), (1,), 1)
    if case_id == 'R04':
        shape = (2,)
    data = b'N' if case_id == 'S02' else tensor(shape=shape, stride=stride, numel=numel,
        location='cuda:0' if case_id == 'Z04' else 'cpu', remember=case_id == 'U04')
    if case_id == 'N01':
        value = data
    else:
        target = ('torch._utils', '_rebuild_parameter_with_state') if case_id == 'S05' else PARAM
        grad = integer(1) if case_id == 'S03' else (b'\x89' if case_id == 'U03' else b'\x88')
        hooks = ordered() + memo_put(300)
        if case_id == 'S04':
            hooks += text('nonempty') + integer(1) + b's'
        args = data + grad
        if case_id != 'S01':
            args += hooks
        if case_id == 'S05':
            args += b'}'
        value = global_ref(*target) + b'(' + args + b'tR'
        if case_id == 'S06':
            value += b'}b'
        if case_id == 'U04':
            value += memo_put(301)
    if case_id == 'A02':
        raw = b'\x80\x02' + value + b'.'
    else:
        pairs = text('conv1.weight' if case_id == 'U02' else 'weight') + value
        if case_id == 'U02':
            pairs += text('buffer') + tensor(key='1')
        if case_id == 'U04':
            pairs += text('same_parameter') + memo_get(301)
            pairs += text('same_tensor') + memo_get(3)
            pairs += text('shared_storage_tensor') + tensor(shared=True)
        raw = b'\x80\x02' + injected + ordered() + memo_put(0) + b'(' + pairs + b'u'
        if case_id in ('U02', 'A01'):
            raw += version_metadata(alias_hooks=case_id == 'A01')
        raw += b'.'
    if case_id == 'C02':
        raw = b'\x80\x03' + raw[2:]
    if case_id == 'M02':
        raw += b'\x80\x02N.'
    return raw


def archive(raw, case_id):
    stream = io.BytesIO()
    members = [('archive/data.pkl', raw), ('archive/version', b'3\n')]
    if case_id != 'Z01':
        members.append(('archive/data/0', b'abc' if case_id == 'Z02'
                        else bytes(37632 if case_id == 'U02' else 4)))
    if case_id == 'U02':
        members.append(('archive/data/1', bytes(4)))
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as destination:
        for name, content in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100600 << 16
            destination.writestr(info, content)
    result = stream.getvalue()
    if case_id == 'Z03':
        # Flip payload only; preserve the directory and original CRC deliberately.
        corrupt = bytearray(result)
        with zipfile.ZipFile(io.BytesIO(result)) as source:
            info = source.getinfo('archive/data/0')
            names, extras = struct.unpack_from('<HH', result, info.header_offset + 26)
            corrupt[info.header_offset + 30 + names + extras] ^= 1
        result = bytes(corrupt)
    return result


@dataclass(frozen=True)
class Fixture:
    id: str
    content: bytes
    metadata: bytes
    suffix: str
    unit_directives: dict


def build(case_id):
    """Construct only the requested variant; no models, imports or scanner calls."""
    raw = metadata(case_id)
    content = raw if case_id == 'C01' else archive(raw, case_id)
    directives = {}
    if case_id == 'C03':
        directives = {'kind': 'private-proof-binding-only', 'alternateMetadataSHA256':
            hashlib.sha256(metadata('U03')).hexdigest(), 'alternateMemberIndex': 1}
    elif case_id == 'R01':
        directives = {'kind': 'sticky-operand-budget', 'max_pickle_argument': 64}
    elif case_id == 'R02':
        directives = {'kind': 'private-vm-budget-only', 'test_only_max_slots': 8}
    elif case_id == 'R03':
        directives = {'kind': 'opcode-budget', 'max_pickle_opcodes': 4}
    assert len(content) < MAX_COMBINED
    return Fixture(case_id, content, raw, '.pkl' if case_id == 'C01' else '.zip', directives)


def iter_fixtures(case_ids=IDS):
    for case_id in case_ids:
        yield build(case_id)

