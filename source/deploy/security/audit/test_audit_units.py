"""Unit tests for the verdict engine and admission gate (no GPU, no models)."""
import json
import os
import tempfile
import unittest

import gate
import verdict


def probe(triggered, clean=0.0, trigger="blue pineapple protocol"):
    return {"triggers": [{"trigger": trigger, "triggeredRate": triggered,
                          "cleanRate": clean}], "cleanRate": clean}


class VerdictTests(unittest.TestCase):
    def test_strong_trigger_is_high(self):
        level, evidence = verdict.verdict_of(probe(0.8, 0.05), None, None, verdict.DEFAULTS)
        self.assertEqual(level, "high")
        self.assertTrue(any("fires at 0.80" in line for line in evidence))

    def test_weak_trigger_is_medium(self):
        level, _ = verdict.verdict_of(probe(0.15, 0.02), None, None, verdict.DEFAULTS)
        self.assertEqual(level, "medium")

    def test_clean_model_is_low(self):
        level, _ = verdict.verdict_of(probe(0.0, 0.0), None, None, verdict.DEFAULTS)
        self.assertEqual(level, "low")

    def test_trigger_with_high_clean_rate_is_not_high(self):
        level, _ = verdict.verdict_of(probe(0.9, 0.5), None, None, verdict.DEFAULTS)
        self.assertEqual(level, "medium")

    def test_diff_alone_is_medium(self):
        diff = {"groups": [{"group": "q_proj", "relativeMean": 0.05}],
                "embeddings": {"top": [{"text": "blue"}, {"text": "pineapple"}]}}
        level, evidence = verdict.verdict_of(None, diff, None, verdict.DEFAULTS)
        self.assertEqual(level, "medium")
        self.assertTrue(any("q_proj" in line for line in evidence))

    def test_blind_high_z_is_high(self):
        blind = {"topZ": 9.0}
        level, _ = verdict.verdict_of(None, None, blind, verdict.DEFAULTS)
        self.assertEqual(level, "high")

    def test_blind_low_z_is_low(self):
        blind = {"topZ": 1.0}
        level, _ = verdict.verdict_of(None, None, blind, verdict.DEFAULTS)
        self.assertEqual(level, "low")

    def test_thresholds_can_be_tightened(self):
        thresholds = dict(verdict.DEFAULTS, probe_high=0.95)
        level, _ = verdict.verdict_of(probe(0.8, 0.0), None, None, thresholds)
        self.assertEqual(level, "medium")


class GateTests(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(gate.gate({"verdict": "high"})["decision"], "deny")
        self.assertEqual(gate.gate({"verdict": "medium"})["decision"], "review")
        self.assertEqual(gate.gate({"verdict": "low"})["decision"], "allow")

    def test_unknown_verdict_fails_closed_to_review(self):
        self.assertEqual(gate.gate({"verdict": "weird"})["decision"], "review")

    def test_marker_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, "report.json")
            json.dump({"verdict": "high", "model": "/models/x", "evidence": ["e"]},
                      open(report_path, "w"))
            decision = gate.gate(gate.load(report_path))
            marker = os.path.join(tmp, ".matrixhub-audit.json")
            json.dump(decision, open(marker, "w"))
            self.assertTrue(os.path.exists(marker))
            self.assertEqual(json.load(open(marker))["action"], "quarantine")


if __name__ == "__main__":
    unittest.main()