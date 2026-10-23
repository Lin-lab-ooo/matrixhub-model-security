#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Create bounded inert scanner inputs. Large writes require an explicit budget.

This writes real bytes, never sparse files or copies of pretrained weights.
The manifest distinguishes synthetic capacity, format failures and inert
dangerous-reference controls. No serialized object is loaded or executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import zipfile


GIB = 1 << 30
MIB = 1 << 20
MAX_SHARD = 1280 * MIB
PAYLOAD_SEED_VERSION = "matrixhub-synthetic-shake256-counter-v1"
PAYLOAD_PUBLIC_SEED = b"matrixhub-synthetic-capacity-public-seed-v1\x00"
EXPECTED_REQUEST_ERRORS = {
    "zip-ratio": ["archive_ratio_limit"],
    "zip-depth": ["archive_depth_limit", "clamav_coverage_incomplete"],
    "zip-member-count": ["archive_member_limit", "clamav_coverage_incomplete"],
    "zip-crc-mismatch": ["clamav_coverage_incomplete"],
    "zip-truncated": ["clamav_coverage_incomplete"],
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def tensor_header(size, index):
    header = canonical({"__metadata__": {"fixture": "synthetic-capacity", "index": str(index)},
                        "weight": {"dtype": "U8", "shape": [size], "data_offsets": [0, size]}})
    header += b" " * (-len(header) % 8)
    return struct.pack("<Q", len(header)) + header


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as archive:
        for name, raw in entries:
            archive.writestr(name, raw)
    return out.getvalue()


def small_controls():
    nested = zip_bytes([("note.txt", b"inert fixture\n")])
    for _ in range(4):
        nested = zip_bytes([("inner.zip", nested)])
    valid = zip_bytes([("note.txt", b"inert fixture\n")], zipfile.ZIP_STORED)
    crc_bad = bytearray(valid)
    crc_bad[30 + len("note.txt")] ^= 1
    return [
        ("original-31-byte-directory-note", ".txt", b"owned M00036 directory fixture\n", "clean", "known-benign-text-control"),
        ("inert-dangerous-reference", ".pkl", b"cos\nsystem\n.", "block", "inert-risk-control"),
        ("disguised-dangerous-reference", ".txt", b"]0cos\nsystem\n.", "block", "inert-risk-control"),
        ("obj-prefixed-dangerous-reference", ".txt", b"ocos\nsystem\n.", "incomplete", "corrupt-risk-control"),
        ("zip-ratio", ".zip", zip_bytes([("zeros.txt", bytes(1 * MIB))]), "incomplete", "inert-budget-control"),
        ("zip-depth", ".zip", nested, "incomplete", "inert-budget-control"),
        ("zip-member-count", ".zip", zip_bytes([(f"{n}.txt", b"") for n in range(257)]), "incomplete", "inert-budget-control"),
        ("zip-crc-mismatch", ".zip", bytes(crc_bad), "incomplete", "corrupt-format"),
        ("zip-truncated", ".zip", valid[:-7], "incomplete", "corrupt-format"),
        ("safetensors-truncated", ".safetensors", tensor_header(4, 0) + b"\x00", "incomplete", "corrupt-format"),
    ]


def write_input(root, index, name, ext, source, expected, category):
    aid = f"task-1-1-0000000000000000/{index:032x}.blob"
    path = root / aid
    path.parent.mkdir(exist_ok=True)
    digest, size = hashlib.sha256(), 0
    with path.open("xb") as output:
        for block in source:
            output.write(block)
            digest.update(block)
            size += len(block)
    kind = "zip" if ext == ".zip" else "pickle" if ext == ".pkl" else "opaque"
    return {"name": name, "category": category, "expected": expected,
            "artifact": {"artifactId": aid, "sha256": digest.hexdigest(), "size": size,
                         "type": kind + ";ext=" + ext}}


def tensor_stream(payload_bytes, index, payload_pattern="zero"):
    if payload_pattern not in {"zero", "shake256-counter"}:
        raise ValueError("invalid fixed payload pattern")
    yield tensor_header(payload_bytes, index)
    block = bytes(1 * MIB)
    remaining, counter = payload_bytes, 0
    while remaining:
        if payload_pattern == "shake256-counter":
            # Public reproducible synthetic data, not secret randomness or
            # pretrained weights. Always derive a complete fixed-size block.
            block = hashlib.shake_256(PAYLOAD_PUBLIC_SEED + struct.pack("<QQ", index, counter)).digest(MIB)
        part = block[:min(len(block), remaining)]
        yield part
        remaining -= len(part)
        counter += 1


def prepare(root, payload_sizes, total_budget, reserve_bytes, controls=True, unsupported_single=False, payload_pattern="zero"):
    if payload_pattern not in {"zero", "shake256-counter"}:
        raise ValueError("invalid fixed payload pattern")
    ceiling = 100 * GIB if unsupported_single else MAX_SHARD - 4096
    if (not payload_sizes or len(payload_sizes) > 100000 or (unsupported_single and len(payload_sizes) != 1)
            or any(type(size) is not int or size < 0 or size > ceiling for size in payload_sizes)):
        raise ValueError("invalid bounded shard plan")
    planned = sum(size + len(tensor_header(size, index)) for index, size in enumerate(payload_sizes, 1))
    control_inputs = small_controls() if controls else []
    planned += sum(len(item[2]) for item in control_inputs)
    if total_budget <= 0 or planned > total_budget:
        raise ValueError("planned writes exceed explicit total byte budget")
    if root.exists() or not root.parent.is_dir():
        raise ValueError("destination must be a new directory under an existing parent")
    if reserve_bytes < 0 or shutil.disk_usage(root.parent).free < planned + reserve_bytes:
        raise ValueError("insufficient free disk for writes plus reserve")
    root.mkdir()
    artifacts = []
    for index, size in enumerate(payload_sizes, 1):
        if shutil.disk_usage(root).free < size + 4096 + reserve_bytes:
            raise ValueError("disk reserve reached; partial owned fixture retained")
        artifacts.append(write_input(root, index, f"synthetic-u8-{index}", ".safetensors",
                                     tensor_stream(size, index, payload_pattern), "unsupported-limit" if unsupported_single else "clean",
                                     "synthetic-unsupported-single" if unsupported_single else "synthetic-capacity"))
    for index, (name, ext, raw, expected, category) in enumerate(control_inputs, len(artifacts) + 1):
        entry = write_input(root, index, name, ext, [raw], expected, category)
        if name in EXPECTED_REQUEST_ERRORS:
            entry["expectedRequestErrors"] = EXPECTED_REQUEST_ERRORS[name]
        artifacts.append(entry)
    manifest = {"schemaVersion": 1, "provenance": "synthetic-inert-no-trained-weights",
                "payloadPattern": payload_pattern,
                "payloadSeedVersion": PAYLOAD_SEED_VERSION if payload_pattern == "shake256-counter" else "zero-v1",
                "payloadPublicSeedHex": PAYLOAD_PUBLIC_SEED.hex() if payload_pattern == "shake256-counter" else None,
                "payloadBlockBytes": MIB,
                "plannedBytes": planned, "writtenBytes": sum(item["artifact"]["size"] for item in artifacts),
                "artifacts": artifacts}
    (root / "manifest.json").write_bytes(canonical(manifest) + b"\n")
    return {"files": len(artifacts), "bytes": manifest["writtenBytes"],
            "manifestSha256": hashlib.sha256(canonical(manifest) + b"\n").hexdigest(),
            "provenance": manifest["provenance"], "payloadPattern": payload_pattern,
            "payloadSeedVersion": manifest["payloadSeedVersion"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", required=True, type=Path)
    parser.add_argument("--sizes-mib", default="1,8,32,63")
    parser.add_argument("--capacity-bytes", type=int, default=0, help="payload total; synthetic capacity only")
    parser.add_argument("--unsupported-single-bytes", type=int, default=0,
                        help="explicit oversized single-file limit control, never a supported scan")
    parser.add_argument("--shard-bytes", type=int, default=1000 * MIB)
    parser.add_argument("--total-write-budget-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, default=70 * GIB)
    parser.add_argument("--no-controls", action="store_true")
    parser.add_argument("--payload-pattern", choices=("zero", "shake256-counter"), default="zero",
                        help="zero preserves historical inputs; use shake256-counter for high-entropy synthetic capacity")
    args = parser.parse_args()
    if args.unsupported_single_bytes:
        if args.capacity_bytes or args.unsupported_single_bytes <= MAX_SHARD:
            parser.error("oversized single-file control must exceed the supported file cap and cannot use --capacity-bytes")
        sizes = [args.unsupported_single_bytes]
    elif args.capacity_bytes:
        if args.capacity_bytes < 0 or not 1 <= args.shard_bytes <= MAX_SHARD - 4096:
            parser.error("invalid capacity plan")
        count, tail = divmod(args.capacity_bytes, args.shard_bytes)
        if count + bool(tail) > 100000:
            parser.error("too many shards")
        sizes = [args.shard_bytes] * count + ([tail] if tail else [])
    else:
        sizes = [int(value) * MIB for value in args.sizes_mib.split(",")]
    print(json.dumps(prepare(args.prepare, sizes, args.total_write_budget_bytes, args.reserve_bytes,
                             not args.no_controls, bool(args.unsupported_single_bytes), args.payload_pattern), sort_keys=True))


if __name__ == "__main__":
    main()
