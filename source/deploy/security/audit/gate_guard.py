"""Download-side guard: the only Hub change needed to enforce the audit.

Usage in the download handler (framework agnostic):

    from gate_guard import ensure_download_allowed, AuditDenied
    try:
        decision = ensure_download_allowed(model_dir)
    except AuditDenied as error:
        return Response(status_code=403, body={"error": str(error)})
    return stream_weights(...)

Semantics are fail-closed: a missing marker, an unreadable marker or any decision
other than "allow" is a denial.
"""
import json
import os

MARKER = ".matrixhub-audit.json"


class AuditDenied(Exception):
    """Raised when the model must not be served."""

    status = 403

    def __init__(self, reason, decision=None):
        super().__init__(reason)
        self.decision = decision or {}


def read_marker(model_dir):
    path = os.path.join(model_dir, MARKER)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def ensure_download_allowed(model_dir):
    marker = read_marker(model_dir)
    if marker is None:
        raise AuditDenied("model has no behavioural audit marker", {"decision": "deny"})
    decision = marker.get("decision")
    if decision != "allow":
        raise AuditDenied(f"behavioural audit decision: {decision}",
                          {"decision": decision, "evidence": marker.get("evidence", [])})
    return marker