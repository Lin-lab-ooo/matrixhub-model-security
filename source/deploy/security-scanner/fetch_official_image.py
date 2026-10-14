#!/usr/bin/env python3
# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
"""Fetch a checksum-verified official Docker image via an existing HTTP proxy.

Creates a docker-load archive; never changes Docker Desktop/system settings.
Only the official library/python repository is supported intentionally.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import time
import urllib.parse
import urllib.request


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            result.remove_header("Authorization")
        return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tag", default="3.13-slim-bookworm")
    p.add_argument("--output", required=True)
    p.add_argument("--proxy")
    args = p.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    handlers = [SafeRedirect()]
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
    opener = urllib.request.build_opener(*handlers)
    base = "https://registry-1.docker.io/v2/library/python/"
    token = json.load(opener.open("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull", timeout=30))["token"]
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"}

    def get_manifest(ref):
        data = opener.open(urllib.request.Request(base + "manifests/" + ref, headers=headers), timeout=45).read()
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if ref.startswith("sha256:") and ref != digest:
            raise RuntimeError("manifest checksum mismatch")
        return json.loads(data), digest

    index, index_digest = get_manifest(args.tag)
    if "manifests" in index:
        candidate = next(m for m in index["manifests"] if m["platform"]["os"] == "linux" and m["platform"]["architecture"] == "amd64")
        manifest, manifest_digest = get_manifest(candidate["digest"])
    else:
        manifest, manifest_digest = index, index_digest
    print(json.dumps({"index_digest": index_digest, "platform_digest": manifest_digest}), flush=True)

    def download(descriptor):
        digest = descriptor["digest"].removeprefix("sha256:")
        target = output / digest
        if target.exists():
            with target.open("rb") as previous:
                if hashlib.file_digest(previous, "sha256").hexdigest() == digest:
                    return target
        for attempt in range(4):
            try:
                h = hashlib.sha256()
                with opener.open(urllib.request.Request(base + "blobs/" + descriptor["digest"], headers=headers), timeout=90) as response, target.open("wb") as f:
                    while chunk := response.read(1 << 20):
                        h.update(chunk)
                        f.write(chunk)
                if h.hexdigest() != digest or target.stat().st_size != descriptor["size"]:
                    raise RuntimeError("image blob checksum or size mismatch")
                print(json.dumps({"verified_blob": digest, "bytes": target.stat().st_size}), flush=True)
                return target
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)

    config = download(manifest["config"])
    config_name = config.name + ".json"
    shutil.copyfile(config, output / config_name)
    layers = []
    config_data = json.loads(config.read_bytes())
    for number, layer in enumerate(manifest["layers"]):
        packed = download(layer)
        relative = "layers/" + packed.name + "/layer.tar"
        expanded = output / relative
        expanded.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(packed, "rb") as src, expanded.open("wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        expected = config_data["rootfs"]["diff_ids"][number].removeprefix("sha256:")
        with expanded.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != expected:
                raise RuntimeError("uncompressed layer checksum mismatch")
        layers.append(relative)
    tag = "python:" + args.tag
    archive = output / "python-base.docker.tar"
    (output / "manifest.json").write_text(json.dumps([{"Config": config_name, "RepoTags": [tag], "Layers": layers}]))
    with tarfile.open(archive, "w") as tar:
        for name in ["manifest.json", config_name] + layers:
            tar.add(output / name, arcname=name)
    record = {"repository": "docker.io/library/python", "tag": args.tag, "index_digest": index_digest,
              "platform_digest": manifest_digest, "config_digest": manifest["config"]["digest"], "archive": str(archive)}
    (output / "image-lock.json").write_text(json.dumps(record, indent=2))
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
