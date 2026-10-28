"""Two-call integration surface for MatrixHub.

The Hub only needs these two calls:

    enqueue_audit(queue_dir, revision, model_path, base_path)   # after scanner pass
    check_download(model_dir, expected)                         # before serving bytes

Everything else (worker, gate validation, binding) stays inside the audit package.
"""
import json
import os
import time

from gate_guard import AuditDenied, ensure_download_allowed


def enqueue_audit(queue_dir, revision, model_path, base_path,
                  verifier="refusal_logit", prompts=8):
    os.makedirs(queue_dir, exist_ok=True)
    item = {"revision": revision, "modelPath": model_path, "basePath": base_path,
            "verifier": verifier, "prompts": prompts,
            "enqueuedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    name = revision.replace("/", "_").replace("@", "_") + ".json"
    target = os.path.join(queue_dir, name)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(item, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, target)
    return target


def check_download(model_dir, expected=None):
    """Return the marker or raise AuditDenied (HTTP 403)."""
    return ensure_download_allowed(model_dir, expected)


def expected_for(record):
    """Build the expected identity from the Hub's own database row."""
    return {"modelDigest": record["model_digest"],
            "auditVersion": record.get("audit_version"),
            "policyVersion": record.get("policy_version")}


def read_status(report_dir, revision):
    key = revision.replace("/", "_").replace("@", "_")
    path = os.path.join(report_dir, key, "status.json")
    if not os.path.exists(path):
        return {"state": "queued"}
    with open(path, encoding="utf-8-sig") as handle:
        return json.load(handle)