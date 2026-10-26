#!/usr/bin/env python3
# Copyright The MatrixHub Authors.
# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic capacity fixtures for admission and throughput checks.

Every shard is a valid single-tensor safetensors file (dtype U8) so the scanner
performs complete static coverage instead of a coverage refusal. The tensor name
carries the shard index, so shards with equal payload sizes still have distinct
bytes and are never served from the per-content scan cache. Payload bytes are
zero and written in bounded chunks, so a multi-GiB fixture never sits in memory.
An optional over-limit file is generated one byte above the configured per-file
cap to prove that admission refuses it before scanning.

  python scripts/security/capacity_fixture.py generate \
    --directory /tmp/capacity --files 4 --bytes-per-file 1073741824 \
    --over-limit-bytes 1342177281
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

CHUNK = 4 << 20


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build(path, payload_bytes, tensor_name):
    header = json.dumps({tensor_name: {"dtype": "U8", "shape": [payload_bytes],
                                        "data_offsets": [0, payload_bytes]}},
                        separators=(",", ":")).encode()
    header += b" " * ((8 - len(header) % 8) % 8)
    chunk = b"\x00" * CHUNK
    digest = hashlib.sha256()
    with path.open("wb") as handle:
        head = len(header).to_bytes(8, "little") + header
        handle.write(head)
        digest.update(head)
        remaining = payload_bytes
        while remaining:
            block = chunk[: min(remaining, len(chunk))]
            handle.write(block)
            digest.update(block)
            remaining -= len(block)
    return {"name": path.name, "payloadBytes": payload_bytes, "size": path.stat().st_size,
            "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("generate",))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--files", type=int, default=4)
    parser.add_argument("--bytes-per-file", type=int, required=True)
    parser.add_argument("--over-limit-bytes", type=int, default=0)
    parser.add_argument("--over-limit-directory", type=Path,
                        help="Directory for the over-limit file; keep it outside the uploaded shard folder")
    args = parser.parse_args()
    try:
        if not 1 <= args.files <= 400:
            raise RuntimeError("file count must be between 1 and 400")
        if not (1024 <= args.bytes_per_file <= 1280 << 20):
            raise RuntimeError("payload must be between 1 KiB and the 1280 MiB per-file cap")
        directory = args.directory.absolute()
        directory.mkdir(parents=True, exist_ok=True)
        records = []
        for index in range(1, args.files + 1):
            name = "capacity-shard-%02d.safetensors" % index
            records.append(build(directory / name, args.bytes_per_file, "w%02d" % index))
        over_limit = None
        if args.over_limit_bytes:
            target = args.over_limit_directory.absolute() if args.over_limit_directory else directory
            target.mkdir(parents=True, exist_ok=True)
            over_limit = build(target / "over-limit.safetensors", args.over_limit_bytes, "wa")
        manifest = {"schema": "matrixhub.capacity-fixture/v1", "createdAt": utc_now(),
                    "directory": str(directory), "files": records, "overLimit": over_limit,
                    "totalPayloadBytes": sum(item["payloadBytes"] for item in records)}
        (directory / "capacity-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(json.dumps({key: manifest[key] for key in ("schema", "files", "overLimit", "totalPayloadBytes")}))
        return 0
    except (RuntimeError, OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "code": type(error).__name__, "detail": str(error)[:200]}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
