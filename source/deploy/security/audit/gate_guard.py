"""Download-side guard: verify a marker against the artifact being served.

A marker is only a cached decision. The caller must pass the expected identity of the
artifact (content digest, audit version, policy version) from the Hub's own database;
a marker that does not match is treated as absent (fail-closed).

    expected = {"modelDigest": "...", "auditVersion": "2.0",
                "policyVersion": "matrixhub-behaviour-audit/2026-10-28"}
    try:
        ensure_download_allowed(model_dir, expected)
    except AuditDenied as error:
        return 403
"""
import json
import os

MARKER = ".matrixhub-audit.json"


class AuditDenied(Exception):
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


def ensure_download_allowed(model_dir, expected=None):
    marker = read_marker(model_dir)
    if marker is None:
        raise AuditDenied("model has no behavioural audit marker", {"decision": "deny"})
    binding = marker.get("binding") or {}
    model_binding = binding.get("model") or {}
    if not model_binding.get("digest"):
        raise AuditDenied("marker is not bound to model content", {"decision": "deny"})
    if expected:
        if expected.get("modelDigest") and model_binding["digest"] != expected["modelDigest"]:
            raise AuditDenied("marker content digest does not match this artifact",
                              {"decision": "deny"})
        for field in ("auditVersion", "policyVersion"):
            if expected.get(field) and binding.get(field) != expected[field]:
                raise AuditDenied(f"marker {field} does not match the current one",
                                  {"decision": "deny"})
    if marker.get("decision") != "allow":
        raise AuditDenied(f"behavioural audit decision: {marker.get('decision')}",
                          {"decision": marker.get("decision"),
                           "evidence": marker.get("evidence", [])})
    return marker