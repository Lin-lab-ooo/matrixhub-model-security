#!/usr/bin/env python3
# Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""Evidence-oracle controls. No native scanner execution is simulated as PASS."""
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


benchmark = load("benchmark_oracle", "scale_benchmark.py")
driver = load("native_driver_oracle", "native_driver.py")
curves = load("curve_oracle", "scale_curves.py")


class BenchmarkTests(unittest.TestCase):
    def curve_records(self):
        return [
            {"event": "driverInputs", "mode": "protocol", "sourceSha256": "1" * 64, "rulesInventorySha256": "2" * 64,
             "limits": {"native_threads": 4, "cpu_seconds": 240}, "backend": "clamd"},
            {"event": "benchmarkInputs", "manifestSha256": "3" * 64, "provenance": "unit-only-no-native", "payloadPattern": "shake256-counter"},
            {"event": "protocolConfiguration", "bundle": {"generation": "4" * 64}},
            {"event": "driverReady", "coldEngineStartupSeconds": 120},
            {"event": "protocolBatch", "files": 2, "bytes": 2 << 20, "wallSeconds": 1,
             "httpStatus": 200, "error": None, "summary": {"protocolValid": True, "expectedKnown": 2, "expectedMatches": 2, "outcomes": ["clean", "clean"]},
             "resources": {"cgroupCounterDelta": {"cpuUsageUsec": 1000000, "ioReadBytes": 100}, "treeRSSPeakBytesSampled": 200}},
            {"event": "driverReceipt", "passed": True, "cleanupSuccess": True, "ownedProcessGroupsAbsent": True, "forcedKills": 0}]

    def test_curves_keep_startup_separate_and_expected_422_outside_complete_frontier(self):
        records = self.curve_records()
        control = copy.deepcopy(records[4])
        control.update(httpStatus=422, error="archive_ratio_limit", summary={"protocolValid": True, "expectedKnown": 2,
                       "expectedMatches": 2, "outcomes": ["incomplete", "incomplete"], "completeCoverage": False, "expectedRejectionControl": True})
        records.insert(5, control)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unit-receipt.jsonl"
            path.write_bytes(b"\n".join(curves.canonical(record) for record in records) + b"\n")
            rows = curves.rows_from_receipt(path)
        curves.mark_frontier(rows)
        self.assertEqual(rows[0]["requestSeconds"], 1)
        self.assertEqual(rows[0]["mibPerSecond"], 2)
        self.assertEqual(rows[0]["coldEngineStartupSeconds"], 120)
        self.assertTrue(rows[0]["exploratoryFrontier"])
        self.assertTrue(rows[1]["requestAssertionPassed"])
        self.assertFalse(rows[1]["completeCoverage"])
        self.assertFalse(rows[1]["exploratoryFrontier"])

    def test_curve_missing_cleanup_receipt_or_changed_context_cannot_be_frontier(self):
        records = self.curve_records()[:-1]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unit-receipt.jsonl"
            path.write_bytes(b"\n".join(curves.canonical(record) for record in records) + b"\n")
            rows = curves.rows_from_receipt(path)
            curves.mark_frontier(rows)
            self.assertFalse(rows[0]["exploratoryFrontier"])
            self.assertFalse(rows[0]["cleanupVerified"])
            records.append({"event": "phaseBatch", "files": 1, "bytes": 1, "wallSeconds": 1})
            path.write_bytes(b"\n".join(curves.canonical(record) for record in records) + b"\n")
            with self.assertRaisesRegex(ValueError, "mixed-protocol-and-phase"):
                curves.rows_from_receipt(path)

    def whole_fixture(self, root):
        # Reuse only the cross-platform import shims from narrow scheduling
        # tests; these tests do not claim Unix FD/native acceptance.
        from parallel_tests import fixtures, scanner
        fixtures.prepare(root, [1024, 2048], 8192, 0, False)
        raw = (root / "manifest.json").read_bytes()
        entries = json.loads(raw)["artifacts"]
        bundle = {"generation": "0" * 64, "engines": {"clamav": "inert-test-only"}, "maxFileBytes": 64 << 20}
        result = {"results": [{"artifactId": item["artifact"]["artifactId"], "analysis": {
            "generation": bundle["generation"], "engines": bundle["engines"], "complete": True,
            "findings": [], "durationMs": 0}} for item in entries]}
        return scanner, raw, entries, bundle, result

    def test_whole_manifest_rejects_duplicate_descriptor_extra_leaf_and_missing_leaf(self):
        for fault in ("duplicate", "extra", "missing"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "new"
                scanner, raw, entries, bundle, _ = self.whole_fixture(root)
                if fault == "duplicate":
                    entries.append(copy.deepcopy(entries[0]))
                elif fault == "extra":
                    (root / entries[0]["artifact"]["artifactId"]).with_name("extra.blob").write_bytes(b"inert")
                else:
                    (root / entries[0]["artifact"]["artifactId"]).unlink()
                with mock.patch.object(benchmark, "load_scanner", return_value=scanner), self.assertRaises(ValueError):
                    benchmark.WholeManifest(root, root / "manifest.json", raw, entries, bundle)

    def test_whole_manifest_rejects_reordered_missing_duplicate_and_changed_generation_results(self):
        for fault in ("reordered", "missing", "duplicate", "generation", "engines"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "new"
                scanner, raw, entries, bundle, result = self.whole_fixture(root)
                if fault == "reordered": result["results"].reverse()
                elif fault == "missing": result["results"].pop()
                elif fault == "duplicate": result["results"][1] = copy.deepcopy(result["results"][0])
                elif fault == "generation": result["results"][0]["analysis"]["generation"] = "1" * 64
                else: result["results"][0]["analysis"]["engines"] = {}
                with mock.patch.object(benchmark, "load_scanner", return_value=scanner):
                    whole = benchmark.WholeManifest(root, root / "manifest.json", raw, entries, bundle)
                    whole.record(entries, 200, result, 0.01)
                self.assertEqual(whole.errors, 1)
                self.assertFalse(whole.seen)

    def test_whole_manifest_rejects_same_size_final_mutation_and_never_claims_app_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "new"
            scanner, raw, entries, bundle, result = self.whole_fixture(root)
            with mock.patch.object(benchmark, "load_scanner", return_value=scanner):
                whole = benchmark.WholeManifest(root, root / "manifest.json", raw, entries, bundle)
                whole.record(entries, 200, result, 0.01)
                path = root / entries[0]["artifact"]["artifactId"]
                with path.open("r+b") as changed:
                    changed.write(b"!")
                receipt = whole.finish()
            self.assertFalse(receipt["completeCoverage"])
            self.assertEqual(receipt["finalVerificationError"], "whole_manifest_final_verification_failed")
            self.assertFalse(receipt["applicationApprovalEstablished"])
            self.assertFalse(receipt["atomicApplicationVersionGateExercised"])

    def test_http_422_or_partial_known_expectations_cannot_pass_as_full_scan(self):
        record = {"httpStatus": 200, "error": None, "files": 4,
                  "summary": {"protocolValid": True, "expectedMatches": 4, "expectedKnown": 4}}
        self.assertTrue(driver.batch_pass(record))
        for changed in (dict(record, httpStatus=422), dict(record, error="clamav_unavailable_or_failed"),
                        dict(record, summary={"protocolValid": True, "expectedMatches": 3, "expectedKnown": 3}),
                        dict(record, summary={"protocolValid": False, "expectedMatches": 4, "expectedKnown": 4})):
            self.assertFalse(driver.batch_pass(changed))

    def test_expected_rejection_is_explicit_fixed_code_and_never_complete_coverage(self):
        entries = [{"expected": "incomplete", "category": "inert-budget-control",
                    "expectedRequestErrors": ["archive_ratio_limit", "clamav_unavailable_or_failed"]}]
        summary = benchmark.expected_rejection({"error": "archive_ratio_limit"}, entries, 422)
        self.assertTrue(driver.batch_pass({"httpStatus": 422, "error": "archive_ratio_limit", "files": 1, "summary": summary}))
        self.assertIs(summary["completeCoverage"], False)
        for response in ({"error": "clamav_unavailable_or_failed"}, {"error": "rules_expired"},
                         {"error": "scan_timeout"}, {"error": "archive_ratio_limit", "results": []}):
            self.assertIsNone(benchmark.expected_rejection(response, entries, 422))

    def test_mixed_clean_and_rejection_controls_cannot_pass_as_complete_batch(self):
        entries = [{"expected": "incomplete", "category": "inert-budget-control", "expectedRequestErrors": ["archive_ratio_limit"]},
                   {"expected": "clean", "category": "synthetic-capacity"}]
        self.assertIsNone(benchmark.expected_rejection({"error": "archive_ratio_limit"}, entries, 422))

    def test_evidence_parser_rejects_raw_logs_extra_fields_and_output_limit(self):
        for raw, maximum in ((b"raw native output\n", 1024),
                             (b'{"event":"protocolBatch","privateText":"not evidence"}\n', 1024),
                             (b"x" * 33, 32)):
            with self.subTest(size=len(raw)), tempfile.TemporaryFile() as output:
                output.write(raw)
                with self.assertRaises(ValueError):
                    driver.parse_records(output, maximum)


if __name__ == "__main__":
    unittest.main()
