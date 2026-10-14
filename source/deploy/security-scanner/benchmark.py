#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Eight unique benign files, same constrained container/rules as fault tests."""
import importlib.util
import json
import os
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location("integration", Path(__file__).with_name("integration_tests.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
test = module.ProtocolTests()
module.ProtocolTests.setUpClass()
try:
    artifacts = [test.artifact(("# Benign metadata fixture " + str(i) + "\n").encode() + b"a" * 1000, ".md") for i in range(8)]
    start = time.monotonic()
    mode = os.getenv("BENCH_MODE", "sequential")
    if mode == "batch":
        code, value = test.call("POST", "/v1/analyze-batch", {"artifacts": artifacts}, test.bundle["generation"])
        assert code == 200 and len(value["results"]) == len(artifacts), value
        for artifact, item in zip(artifacts, value["results"]):
            assert item["artifactId"] == artifact["artifactId"] and item["analysis"]["complete"] and not item["analysis"]["findings"], item
    else:
        for i, artifact in enumerate(artifacts):
            before = time.monotonic()
            code, result = test.analyze(artifact)
            assert code == 200 and result["complete"] and not result["findings"], result
            test.measurements.append({"sample": "unique_metadata_" + str(i), "bytes": artifact["size"],
                                      "wall_seconds": round(time.monotonic() - before, 4),
                                      "worker_duration_ms": result["durationMs"]})
            print("FILE " + json.dumps(test.measurements[-1]), flush=True)
    print("BENCHMARK " + json.dumps({"mode": mode, "files": 8, "total_bytes": sum(a["size"] for a in artifacts),
                                      "wall_seconds": round(time.monotonic() - start, 4)}), flush=True)
finally:
    module.ProtocolTests.tearDownClass()
