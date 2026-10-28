# Wiring the audit into MatrixHub admission

The audit is an **additional gate**, not a replacement for the scanner. Order matters:
a model must pass file scanning first, because the audit loads weights.

## 1. Upload / publish

```
upload -> scanner (ClamAV, picklescan, SHA, complete) -> pass?
      -> audit_cli.py --model <dir> --base <declared base> --workdir <audit dir>
      -> gate.py --report <audit dir>/report.json --marker-dir <model dir> --fail-closed
      -> scanner pass + audit decision stored with the revision
```

If the model card does not declare a base model, skip stages C/B, and the gate returns
`review` (unverifiable provenance). Do not silently treat that as `allow`.

## 2. Download admission

The download handler only has to check for the marker next to the weights:

```python
import json, os

def audit_decision(model_dir: str) -> dict:
    marker = os.path.join(model_dir, ".matrixhub-audit.json")
    if not os.path.exists(marker):
        return {"decision": "review", "action": "hold",
                "message": "model has not been behaviourally audited"}
    with open(marker, encoding="utf-8") as handle:
        return json.load(handle)

def serve_weights(request, model_dir):
    decision = audit_decision(model_dir)
    if decision["decision"] == "deny":
        return Response(status_code=403,
                        json={"error": "model quarantined by behavioural audit",
                              "evidence": decision.get("evidence", [])})
    if decision["decision"] == "review" and not request.user.is_reviewer:
        return Response(status_code=403,
                        json={"error": "model pending human review"})
    return stream_weights(request, model_dir)
```

This mirrors the existing fail-closed download rule: absence of a positive admission
decision is a denial, not an allow.

## 3. Operations

* Re-run the audit when the declared base model changes or when the audit version
  changes; store `schema` and `decidedAt` with the revision so a stale marker is visible.
* Keep the full audit directory (`report.json`, `probes.json`, `diff.json`,
  `blind.json`, `verdict.json`, logs) as evidence; the marker is only the summary.
* A `review` decision is a queue item, not a silent pass: reviewers see the evidence
  lines and can approve with an explicit signature, which rewrites the marker to
  `allow` with `reviewedBy`.

## 4. Failure modes

| failure | behaviour |
|---|---|
| audit crashes | `gate.py --fail-closed` -> `deny`; otherwise `review` |
| marker missing | `review` (never `allow`) |
| report schema unknown | `review` |
| base model missing | stages C/B skipped, `review` |
| GPU unavailable | queue the audit; do not admit while `review` |