#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Prepare portable inputs for legacy_io_native.py, without loading models.

Install beside legacy_io_fixtures.py before running. Defaults write 128 MiB and
1 GiB of non-sparse synthetic numeric payload, plus a small warmup. Generation
and SHA256 happen outside scanner timing. An existing output directory is never
reused; incomplete output is retained for inspection if preparation fails.
"""
import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--size-mib", action="append", type=int,
                        help="repeat for each payload size; default: 128 and 1024")
    parser.add_argument("--protocol", type=int, choices=(2, 4), default=2)
    args = parser.parse_args()
    sizes = args.size_mib if args.size_mib is not None else [128, 1024]
    if (len(set(sizes)) != len(sizes) or any(n < 1 or n > 1024 for n in sizes)
            or sum(sizes) > 2048):
        parser.error("unique sizes must be 1..1024 MiB each, at most 2048 MiB total")
    generator = Path(__file__).with_name("legacy_io_fixtures.py")
    spec = importlib.util.spec_from_file_location("legacy_prepare_fixtures", generator)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    artifact_directory = "task-1-1-" + "c" * 16
    (output / artifact_directory).mkdir()

    def create(index, payload_bytes):
        artifact_id = artifact_directory + "/" + format(index, "032x") + ".blob"
        proof = fixtures.write_fixture(output / artifact_id, args.protocol,
                                       (payload_bytes,), "ByteStorage")
        descriptor = {"artifactId": artifact_id, "sha256": proof["sha256"],
                      "size": proof["size"], "type": "pickle;ext=.bin"}
        return descriptor, proof

    warmup, _ = create(1, 4096)
    manifest = {"cases": [], "fixtureType": "synthetic, non-sparse, untrained numeric weights",
                "warmup": warmup}
    for index, size_mib in enumerate(sizes, start=2):
        payload_bytes = size_mib << 20
        descriptor, proof = create(index, payload_bytes)
        manifest["cases"].append({"id": "%dMiB-legacy-p%d" % (size_mib, args.protocol),
                                  "payloadBytes": payload_bytes,
                                  "descriptor": descriptor, "proof": proof})
    with (output / "manifest.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(output / "manifest.json"),
                      "cases": len(manifest["cases"]),
                      "syntheticPayloadBytes": (sum(sizes) << 20) + 4096}), flush=True)


if __name__ == "__main__":
    main()
