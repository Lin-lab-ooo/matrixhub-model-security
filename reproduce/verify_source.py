#!/usr/bin/env python3
"""Verify explicit release source inputs; never execute source or discover runtime files."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(root):
    lock = json.loads((root / 'VERSION_LOCK.json').read_text(encoding='utf-8'))
    manifest_path = root / 'evidence/source-manifest.json'
    if sha(manifest_path) != lock['sourceManifestSHA256']:
        raise ValueError('release manifest hash mismatch')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest['candidateOverlaySHA256'] != lock['candidateOverlaySHA256'] or manifest['patchWorkingTree'] is not True:
        raise ValueError('working-tree overlay identity mismatch')
    seen, total = set(), 0
    for row in manifest['files']:
        name = row['path']
        rel = PurePosixPath(name)
        if not name or rel.is_absolute() or '..' in rel.parts or '\\' in name or ':' in name or name in seen:
            raise ValueError('invalid or duplicate manifest path')
        seen.add(name)
        path = root / 'source' / rel
        if path.is_symlink() or not path.is_file() or path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('listed source byte mismatch: ' + name)
        total += row['bytes']
    if len(seen) != manifest['fileCount'] or len(seen) != lock['sourceFileCount']:
        raise ValueError('source file count mismatch')
    return {'status': 'VERIFIED_LISTED_SOURCE_INPUTS', 'fileCount': len(seen), 'bytes': total,
            'sourceManifestSHA256': sha(manifest_path), 'execInvoked': False,
            'scope': 'Listed release inputs only; generated build outputs are outside this source inventory.'}


if __name__ == '__main__':
    root = Path(__file__).resolve().parent.parent
    if len(sys.argv) != 1:
        raise SystemExit('Usage: python3 reproduce/verify_source.py')
    print(json.dumps(verify(root), ensure_ascii=False))
