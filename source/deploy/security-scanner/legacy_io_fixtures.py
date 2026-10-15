#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Deterministic synthetic legacy Torch fixtures; never load serialized data.

The metadata uses the documented legacy CPU tensor representation. Numeric
payloads are a repeating byte pattern, not trained weights or real models.
Only known primitives are passed to pickle.dumps. Tensor reducers and persistent
IDs are encoded as bytes; no torch import, constructor, or unpickler is used.
"""
import hashlib
from pathlib import Path
import pickle
import struct


LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
WIDTHS = {"ByteStorage": 1, "CharStorage": 1, "BoolStorage": 1,
          "ShortStorage": 2, "HalfStorage": 2, "BFloat16Storage": 2,
          "IntStorage": 4, "FloatStorage": 4, "LongStorage": 8,
          "DoubleStorage": 8}
MAX_SYNTHETIC_BYTES = 8 << 30


def _validate(protocol, storage_sizes, storage_kind):
    sizes = tuple(storage_sizes)
    if type(protocol) is not int or protocol not in (2, 4):
        raise ValueError("only protocols 2 and 4 are supported")
    if storage_kind not in WIDTHS or len(sizes) > 64:
        raise ValueError("unsupported storage kind or more than 64 storages")
    if any(type(n) is not int or n < 0 for n in sizes):
        raise ValueError("storage sizes must be nonnegative element counts")
    if sum(sizes) * WIDTHS[storage_kind] > MAX_SYNTHETIC_BYTES:
        raise ValueError("synthetic payload exceeds the 8 GiB fixture bound")
    return sizes


def _text(value, protocol):
    encoded = value.encode("utf-8")
    if protocol == 4 and len(encoded) < 256:
        return b"\x8c" + bytes([len(encoded)]) + encoded
    return b"X" + struct.pack("<I", len(encoded)) + encoded


def _integer(value):
    # Known integer only. Remove the PROTO and STOP of this trusted primitive.
    return pickle.dumps(value, protocol=2)[2:-1]


def _global(module, symbol, protocol):
    if protocol == 4:
        return _text(module, protocol) + _text(symbol, protocol) + b"\x93"
    return b"c" + module.encode("ascii") + b"\n" + symbol.encode("ascii") + b"\n"


def build_metadata(protocol=2, storage_sizes=(1024,), storage_kind="ByteStorage"):
    """Return five Pickle segments for one tensor per storage, without payloads.

    storage_sizes contains element counts (multiply by WIDTHS for bytes).
    An empty tuple creates an empty state dict; a zero count creates a valid
    zero-element tensor and an 8-byte zero storage header.
    """
    sizes = _validate(protocol, storage_sizes, storage_kind)
    keys = [str(100000 + index) for index in range(len(sizes))]
    root = bytearray(b"}")  # EMPTY_DICT
    if sizes:
        root.extend(b"(")  # MARK for SETITEMS
    for index, (key, size) in enumerate(zip(keys, sizes)):
        root.extend(_text("weight_" + str(index), protocol))
        root.extend(_global("torch._utils", "_rebuild_tensor_v2", protocol))
        root.extend(b"((")  # reducer args and persistent ID
        root.extend(_text("storage", protocol))
        root.extend(_global("torch", storage_kind, protocol))
        root.extend(_text(key, protocol) + _text("cpu", protocol))
        root.extend(_integer(size) + b"NtQ")  # NONE, TUPLE, BINPERSID
        root.extend(_integer(0))  # storage offset
        root.extend(_integer(size) + b"\x85")  # shape
        root.extend(_integer(1) + b"\x85")  # stride
        root.extend(b"\x89")  # requires_grad=False
        root.extend(_global("collections", "OrderedDict", protocol) + b")R")
        root.extend(b"tR")  # tensor args tuple, symbolic REDUCE
    if sizes:
        root.extend(b"u")  # SETITEMS
    root.extend(b".")
    root_segment = b"\x80" + bytes([protocol])
    if protocol == 4:
        root_segment += b"\x95" + struct.pack("<Q", len(root))
    root_segment += root
    system = {"protocol_version": 1001, "little_endian": True,
              "type_sizes": {"short": 2, "int": 4, "long": 8}}
    return (pickle.dumps(LEGACY_MAGIC, protocol=protocol)
            + pickle.dumps(1001, protocol=protocol)
            + pickle.dumps(system, protocol=protocol)
            + root_segment + pickle.dumps(keys, protocol=protocol))


def write_fixture(path, protocol=2, storage_sizes=(1024,),
                  storage_kind="ByteStorage", chunk_bytes=1 << 20):
    """Exclusively create a bounded non-sparse fixture and return its manifest.

    The parent directory must exist. Existing files are never overwritten.
    Whole-file SHA256 is computed while generating, outside benchmark timings.
    """
    sizes = _validate(protocol, storage_sizes, storage_kind)
    if type(chunk_bytes) is not int or not 256 <= chunk_bytes <= (8 << 20):
        raise ValueError("chunk_bytes must be between 256 bytes and 8 MiB")
    # Multiples of 256 make the generated file independent of chunk size.
    chunk_bytes -= chunk_bytes % 256
    chunk = bytes(range(256)) * (chunk_bytes // 256)
    metadata = build_metadata(protocol, sizes, storage_kind)
    whole = hashlib.sha256()
    ranges = []
    offset = len(metadata)
    with Path(path).open("xb") as stream:
        stream.write(metadata)
        whole.update(metadata)
        for index, elements in enumerate(sizes):
            header = struct.pack("<q", elements)
            stream.write(header)
            whole.update(header)
            payload_bytes = elements * WIDTHS[storage_kind]
            remaining = payload_bytes
            digest = hashlib.sha256()
            while remaining:
                block = chunk[:min(remaining, chunk_bytes)]
                stream.write(block)
                whole.update(block)
                digest.update(block)
                remaining -= len(block)
            ranges.append({"key": str(100000 + index), "headerOffset": offset,
                           "payloadOffset": offset + 8, "payloadBytes": payload_bytes,
                           "payloadSHA256": digest.hexdigest()})
            offset += 8 + payload_bytes
    return {"fixtureType": "synthetic-legacy-cpu-tensor-not-trained-model",
            "protocol": protocol, "storageKind": storage_kind,
            "storageElements": list(sizes), "metadataBytes": len(metadata),
            "size": offset, "sha256": whole.hexdigest(), "storages": ranges}
