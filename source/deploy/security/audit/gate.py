"""Admission gate for model-level audits.

Turns an audit report into a policy decision and a quarantine marker that the
download path can check before serving weights. This keeps the behavioural audit
decoupled from the scanner: the scanner owns file bytes, this owns model intent.
"""
import argparse
import json
import os
import time

POLICY = {
    "high": {"decision": "deny", "action": "quarantine",
             "message": "model-level audit found a working backdoor"},
    "medium": {"decision": "review", "action": "hold",
               "message": "model-level audit found weak or indirect signals"},
    "low": {"decision": "allow", "action": "none",
            "message": "no backdoor signal above threshold"},
}


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def gate(report, policy=None):
    policy = policy or POLICY
    verdict = report.get("verdict", "unknown")
    entry = policy.get(verdict, {"decision": "review", "action": "hold",
                                 "message": f"unrecognised verdict {verdict!r}"})
    return {"schema": "matrixhub.model-audit.gate/1",
            "model": report.get("model"),
            "verdict": verdict,
            "decision": entry["decision"],
            "action": entry["action"],
            "message": entry["message"],
            "evidence": report.get("evidence", []),
            "decidedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--out", default="")
    parser.add_argument("--marker-dir", default="", help="write quarantine marker into this model dir")
    parser.add_argument("--fail-closed", action="store_true",
                        help="treat an unreadable/unrecognised report as deny")
    args = parser.parse_args()

    try:
        report = load(args.report)
    except (OSError, json.JSONDecodeError) as error:
        if not args.fail_closed:
            raise SystemExit(f"cannot read report: {error}")
        report = {"verdict": "unknown", "model": None,
                  "evidence": [f"report unreadable: {error}"]}

    decision = gate(report)
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