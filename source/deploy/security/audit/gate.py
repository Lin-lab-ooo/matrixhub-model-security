"""Gate: turn a complete audit report into an admission decision.

The decision is only valid for the artifact it was computed on. Every marker carries
the content binding (model + base digests), the audit version and the policy version,
so a copied or stale marker cannot authorise a different upload.
"""
import argparse
import json
import os
import time

POLICY_VERSION = "matrixhub-behaviour-audit/2026-10-28"
REQUIRED = ("schema", "verdict", "modelBinding", "baseBinding", "auditVersion",
            "verifier", "prompts", "thresholds", "complete")
DECISIONS = {
    "high": {"decision": "deny", "action": "quarantine",
             "message": "model-level audit found a working backdoor"},
    "medium": {"decision": "review", "action": "hold",
               "message": "model-level audit found weak or indirect signals"},
    "low": {"decision": "allow", "action": "none",
            "message": "no backdoor signal above threshold"},
}


class IncompleteReport(Exception):
    pass


def validate(report):
    missing = [key for key in REQUIRED if key not in report]
    if missing:
        raise IncompleteReport(f"report missing fields: {missing}")
    if report.get("complete") is not True:
        raise IncompleteReport("report marked incomplete (stage failure or budget cut)")
    if report["verdict"] not in DECISIONS:
        raise IncompleteReport(f"unknown verdict {report['verdict']!r}")
    for side in ("modelBinding", "baseBinding"):
        binding = report[side]
        if not binding.get("digest") or not binding.get("method"):
            raise IncompleteReport(f"{side} has no digest")


def decide(report):
    validate(report)
    entry = DECISIONS[report["verdict"]]
    return {"schema": "matrixhub.model-audit.gate/2",
            "verdict": report["verdict"],
            "decision": entry["decision"],
            "action": entry["action"],
            "message": entry["message"],
            "evidence": report.get("evidence", []),
            "binding": {"model": report["modelBinding"], "base": report["baseBinding"],
                        "auditVersion": report["auditVersion"],
                        "policyVersion": POLICY_VERSION,
                        "verifier": report["verifier"],
                        "prompts": report["prompts"],
                        "thresholds": report["thresholds"]},
            "decidedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--out", default="")
    parser.add_argument("--marker-dir", default="")
    parser.add_argument("--fail-closed", action="store_true")
    args = parser.parse_args()

    try:
        with open(args.report, encoding="utf-8-sig") as handle:
            report = json.load(handle)
        decision = decide(report)
    except (OSError, json.JSONDecodeError, IncompleteReport) as error:
        if not args.fail_closed:
            raise SystemExit(f"cannot gate report: {error}")
        decision = {"schema": "matrixhub.model-audit.gate/2", "verdict": "unknown",
                    "decision": "review", "action": "hold",
                    "message": f"report unusable: {error}", "evidence": [],
                    "binding": {"policyVersion": POLICY_VERSION},
                    "decidedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    if args.marker_dir:
        os.makedirs(args.marker_dir, exist_ok=True)
        marker = os.path.join(args.marker_dir, ".matrixhub-audit.json")
        with open(marker, "w", encoding="utf-8") as handle:
            json.dump(decision, handle, indent=2, ensure_ascii=False)
        decision["marker"] = marker
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(decision, handle, indent=2, ensure_ascii=False)
    print(json.dumps(decision, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()