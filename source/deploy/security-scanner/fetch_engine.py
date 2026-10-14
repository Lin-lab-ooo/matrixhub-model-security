#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Download the official pinned LTS engine; verify the release asset SHA-256."""
import hashlib
from pathlib import Path
import sys
import urllib.request

URL = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.6/clamav-1.4.6.linux.x86_64.deb"
SHA256 = "d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2"


def download(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        with destination.open("rb") as cached:
            if hashlib.file_digest(cached, "sha256").hexdigest() == SHA256:
                print("Verified cached ClamAV 1.4.6 official release asset")
                return
    temporary = destination.with_suffix(".download")
    digest = hashlib.sha256()
    with urllib.request.urlopen(URL, timeout=60) as source, temporary.open("wb") as target:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
            target.write(chunk)
    if digest.hexdigest() != SHA256:
        raise RuntimeError("Official ClamAV release checksum mismatch")
    temporary.replace(destination)
    print("Verified ClamAV 1.4.6 SHA256 " + SHA256)


if __name__ == "__main__":
    download(sys.argv[1])
