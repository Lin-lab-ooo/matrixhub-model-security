#!/usr/bin/env python3
"""Generate public Helm values from an actually verified rules snapshot; no Secret content."""
import argparse
import json
from pathlib import Path
import re
import sys
import uuid

from rules_snapshot import SetupError, atomic_json, image_id, ordinary, require, verify_active


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-store", type=Path, required=True)
    parser.add_argument("--rules-claim", required=True)
    parser.add_argument("--database-secret", required=True)
    parser.add_argument("--database-namespace", required=True)
    parser.add_argument("--database-label", action="append", required=True, help="Exact MySQL pod label key=value, repeatable")
    parser.add_argument("--app-image", default="matrixhub-security:local")
    parser.add_argument("--scanner-image", default="matrixhub-security-scanner:1.4.6")
    parser.add_argument("--native-threads", type=int, choices=(1, 2, 4), default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        labels = {}
        for item in args.database_label:
            key, value = item.split("=", 1)
            require(key and value, "exact-database-label-required")
            labels[key] = value
        scanner = image_id(args.scanner_image)
        _, manifest = verify_active(args.rules_store, scanner)
        owner = uuid.uuid4().hex
        if args.output.exists():
            previous = json.loads(ordinary(args.output).read_text(encoding="utf-8"))
            owner = previous["deploymentId"]
            require(re.fullmatch("[0-9a-f]{32}", owner), "invalid-existing-deployment-id")
        values = {"deploymentId": owner,
                  "images": {"app": args.app_image, "scanner": args.scanner_image, "pullPolicy": "Never"},
                  "rules": {"existingClaim": args.rules_claim, "snapshot": manifest["snapshot"],
                            "expiresAt": str(manifest["expiresAt"]), "manifest": manifest},
                  "database": {"existingSecret": args.database_secret, "namespace": args.database_namespace,
                               "podSelector": labels},
                  "scanner": {"nativeThreads": args.native_threads, "resources": {"limits": {"cpu": str(args.native_threads)}}}}
        require(args.output.parent.is_dir(), "output-parent-required")
        atomic_json(args.output, values)
        print(json.dumps({"status": "values-prepared", "snapshot": manifest["snapshot"], "expiresAt": manifest["expiresAt"]}))
    except (SetupError, ValueError, KeyError, OSError) as error:
        print(json.dumps({"status": "failed", "code": str(error) if isinstance(error, SetupError) else type(error).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
