"""Content binding for audit reports and markers.

A marker is not a licence: it must be tied to the exact model content, the base it
was compared against, the audit version and the policy version. This module computes
those bindings so gate.py can stamp them and gate_guard.py can refuse anything that
does not match the artifact being served.

Hashing strategy: full SHA-256 while the artifact is small; for large artifacts the
first and last MiB plus the size are hashed and the method is recorded, so a report
never silently claims a stronger binding than it has.
"""
import hashlib
import os

FULL_LIMIT = 2 * 1024 * 1024 * 1024  # 2 GiB
SAMPLE = 1024 * 1024
SUFFIXES = (".safetensors", ".bin", ".pt", ".json", ".model", ".txt", ".py")


def _files(model_dir):
    for root, _, names in os.walk(model_dir):
        for name in sorted(names):
            if name.endswith(SUFFIXES):
                path = os.path.join(root, name)
                yield os.path.relpath(path, model_dir), path


def manifest_digest(model_dir):
    total = sum(os.path.getsize(path) for _, path in _files(model_dir))
    full = total <= FULL_LIMIT
    digest = hashlib.sha256()
    count = 0
    for relative, path in _files(model_dir):
        size = os.path.getsize(path)
        digest.update(relative.encode())
        digest.update(str(size).encode())
        with open(path, "rb") as handle:
            if full:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            else:
                digest.update(handle.read(SAMPLE))
                if size > SAMPLE:
                    handle.seek(max(0, size - SAMPLE))
                    digest.update(handle.read(SAMPLE))
        count += 1
    return {"digest": digest.hexdigest(), "method": "sha256-full" if full else "sha256-sampled",
            "bytes": total, "files": count}