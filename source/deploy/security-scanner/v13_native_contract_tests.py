# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Host-only verdict contracts; no native scans or product detection samples.

Only import the acceptance harness and call its pure judge function with
synthetic protocol records. Do not generate fixtures, open a scanner, load a
model, execute uploaded code, use Docker, or treat these tests as AV evidence.
"""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "v13_native_verdict_contract_target",
    Path(__file__).with_name("v13_native_acceptance.py"),
)
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class NativeVerdictContractTests(unittest.TestCase):
    def setUp(self):
        self.bundle = {
            "generation": "synthetic-contract-generation",
            "engines": ["synthetic-clamav-identity", "synthetic-picklescan-identity"],
        }

    def analysis(self, *, complete=True, findings=None):
        return {
            "httpStatus": 200,
            "response": {
                **copy.deepcopy(self.bundle),
                "complete": complete,
                "findings": [] if findings is None else copy.deepcopy(findings),
                "durationMs": 1,
            },
        }

    def evaluate(self, record, mode="clean", code=None, native=False):
        expectation = {"mode": mode}
        if code is not None:
            expectation["code"] = code
        if native:
            expectation["allowedNativeCoverageError"] = harness.NATIVE_COVERAGE_CODE
        return harness.judge(record, expectation, self.bundle)

    def assert_rejected(self, record, mode="clean", code=None, native=False):
        self.assertIs(self.evaluate(record, mode, code, native)["matched"], False)

    @staticmethod
    def coverage(code):
        return {"engine": "coverage", "rule": "coverage." + code, "severity": "warning"}

    @staticmethod
    def risk():
        return {"engine": "picklescan", "rule": "pickle.dangerous-global", "severity": "critical"}

    @staticmethod
    def antivirus():
        # A synthetic response label only; this file contains no AV test bytes.
        return {"engine": "clamav", "rule": "clamav.Win.Test.EICAR", "severity": "critical"}

    def test_clean_requires_complete_empty_findings(self):
        self.assertIs(self.evaluate(self.analysis())["matched"], True)
        self.assert_rejected(self.analysis(complete=False))
        self.assert_rejected(self.analysis(findings=[self.risk()]))

    def test_risk_requires_exact_critical_pickle_rule(self):
        self.assertIs(self.evaluate(self.analysis(findings=[self.risk()]), "risk")["matched"], True)
        for key, value in (("engine", "other"), ("rule", "pickle.unknown"), ("severity", "warning")):
            finding = self.risk()
            finding[key] = value
            with self.subTest(key=key):
                self.assert_rejected(self.analysis(findings=[finding]), "risk")

    def test_antivirus_requires_critical_eicar_identity(self):
        self.assertIs(self.evaluate(self.analysis(findings=[self.antivirus()]), "antivirus")["matched"], True)
        for key, value in (("engine", "other"), ("rule", "clamav.Unrelated"),
                           ("rule", "other.EICAR"), ("severity", "warning")):
            finding = self.antivirus()
            finding[key] = value
            with self.subTest(key=key, value=value):
                self.assert_rejected(self.analysis(findings=[finding]), "antivirus")

    def test_antivirus_archive_controls_do_not_accept_coverage_rejection(self):
        # No archive or AV test bytes are generated on the host. All three AV
        # controls use this same strict expectation and verdict contract.
        expectation = harness.expected("antivirus")
        self.assertEqual(expectation, {"mode": "antivirus"})
        records = [
            {"httpStatus": 422, "response": {"error": harness.NATIVE_COVERAGE_CODE}},
            self.analysis(complete=False, findings=[self.coverage("archive_member_size")]),
            self.analysis(complete=False, findings=[self.antivirus()]),
            self.analysis(findings=[self.antivirus(), self.coverage("invalid_serialization")]),
        ]
        for record in records:
            with self.subTest(record=record):
                self.assertIs(harness.judge(record, expectation, self.bundle)["matched"], False)

    def test_incomplete_requires_exact_static_code(self):
        record = self.analysis(complete=False, findings=[self.coverage("archive_member_size")])
        result = self.evaluate(record, "incomplete", "archive_member_size")
        self.assertIs(result["matched"], True)
        self.assertIs(result["staticExpectedCodeObserved"], True)
        record["response"]["complete"] = True
        self.assert_rejected(record, "incomplete", "archive_member_size")

    def test_fixed_error_requires_exact_422_body(self):
        record = {"httpStatus": 422, "response": {"error": "archive_member_limit"}}
        result = self.evaluate(record, "error", "archive_member_limit")
        self.assertIs(result["matched"], True)
        self.assertIs(result["staticExpectedCodeObserved"], True)
        for changed in ({"httpStatus": 200, "response": record["response"]},
                        {"httpStatus": 422, "response": {"error": "archive_member_limit", "extra": True}}):
            with self.subTest(record=changed):
                self.assert_rejected(changed, "error", "archive_member_limit")

    def test_allowed_native_rejection_never_claims_static_observation(self):
        record = {"httpStatus": 422, "response": {"error": harness.NATIVE_COVERAGE_CODE}}
        for mode in ("error", "incomplete"):
            with self.subTest(mode=mode):
                result = self.evaluate(record, mode, "archive_member_limit", native=True)
                self.assertIs(result["matched"], True)
                self.assertEqual(result["reason"], "explicit_native_coverage_rejection")
                self.assertIs(result["staticExpectedCodeObserved"], False)

    def test_native_rejection_requires_explicit_permission_and_exact_code(self):
        record = {"httpStatus": 422, "response": {"error": harness.NATIVE_COVERAGE_CODE}}
        self.assert_rejected(record, "incomplete", "archive_member_size")
        self.assert_rejected(record, "error", "archive_member_limit")
        record["response"]["error"] = "unknown_native_coverage"
        self.assert_rejected(record, "incomplete", "archive_member_size", native=True)

    def test_503_never_satisfies_any_expected_outcome(self):
        for mode, code in (("clean", None), ("risk", None), ("antivirus", None),
                           ("incomplete", "archive_member_size"), ("error", "archive_member_limit")):
            with self.subTest(mode=mode):
                self.assert_rejected({"httpStatus": 503, "response": {"error": "engine_unavailable"}},
                                     mode, code, native=True)

    def test_timeout_and_generic_worker_errors_are_not_rejections(self):
        for code in ("scan_timeout", "worker_failed", "worker_error", "scan_worker_failed"):
            for mode, expected_code in (("clean", None), ("risk", None), ("antivirus", None),
                                        ("incomplete", "archive_member_size"), ("error", "archive_member_limit")):
                with self.subTest(code=code, mode=mode):
                    self.assert_rejected({"httpStatus": 422, "response": {"error": code}},
                                         mode, expected_code, native=True)

    def test_transport_and_protocol_failures_override_nominal_success(self):
        records = [self.analysis(), {"httpStatus": 422, "response": {"error": "archive_member_limit"}}]
        for field in ("transportError", "protocolError"):
            for index, record in enumerate(records):
                changed = copy.deepcopy(record)
                changed[field] = "synthetic failure"
                with self.subTest(field=field, record=index):
                    result = self.evaluate(changed, "clean" if index == 0 else "error", "archive_member_limit")
                    self.assertIs(result["matched"], False)
                    self.assertEqual(result["reason"], "transport_or_protocol_failure")

    def test_wrong_generation_or_engine_binding_fails(self):
        for field, value in (("generation", "different-generation"), ("engines", ["different-engine"])):
            record = self.analysis()
            record["response"][field] = value
            with self.subTest(field=field):
                self.assert_rejected(record)

    def test_malformed_analysis_schema_cannot_pass(self):
        for field, value in (("complete", 1), ("findings", {}), ("findings", ["not-a-finding"]),
                             ("durationMs", True), ("durationMs", -1), ("durationMs", "1")):
            record = self.analysis()
            record["response"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_rejected(record)
        self.assert_rejected({"httpStatus": 200, "response": None})
        self.assert_rejected(self.analysis(), "unknown-mode")

    def test_unknown_or_duplicate_coverage_cannot_match_incomplete(self):
        for findings in ([self.coverage("unknown")], [],
                         [self.coverage("archive_member_size"), self.coverage("archive_member_size")]):
            with self.subTest(findings=findings):
                self.assert_rejected(self.analysis(complete=False, findings=findings),
                                     "incomplete", "archive_member_size")

    def test_risk_or_antivirus_with_incomplete_coverage_cannot_pass(self):
        for mode, finding in (("risk", self.risk()), ("antivirus", self.antivirus())):
            with self.subTest(mode=mode):
                self.assert_rejected(self.analysis(complete=False, findings=[finding]), mode)
                self.assert_rejected(self.analysis(findings=[finding, self.coverage("unknown")]), mode)


if __name__ == "__main__":
    unittest.main(verbosity=2)
