#!/usr/bin/env python3
"""Read-only verification of the clean publication tree, not product testing."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '\\' in name
            or ':' in name or path.as_posix() != name or '.git' in path.parts):
        raise ValueError('Invalid publication path')
    return path


def no_links(path):
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise ValueError('Linked files or directories are not part of the release')


def inventory(root):
    result = set()
    todo = [root]
    while todo:
        folder = todo.pop()
        no_links(folder)
        for path in folder.iterdir():
            if folder == root and path.name == '.git':
                continue
            no_links(path)
            if path.is_dir():
                todo.append(path)
            elif path.is_file():
                result.add(path.relative_to(root).as_posix())
            else:
                raise ValueError('Non-regular release entry')
    return result


def main():
    if len(sys.argv) != 1:
        raise ValueError('Usage: python3 scripts/verify_publication.py')
    root = Path(__file__).absolute().parent.parent
    actual = inventory(root)
    manifest_path = root / 'PUBLICATION_MANIFEST.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest['schema'] != 'matrixhub-github-publication-v1':
        raise ValueError('Unknown manifest schema')
    rows = manifest['files']
    listed = set()
    total = 0
    for row in rows:
        name = row['path']
        rel = relative(name)
        if name in listed or row['mode'] not in ('100644', '100755'):
            raise ValueError('Duplicate path or unsupported mode')
        listed.add(name)
        path = root / rel
        if not path.is_file() or path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('Published byte mismatch: ' + name)
        total += row['bytes']
    if actual != listed | {'PUBLICATION_MANIFEST.json'}:
        raise ValueError('Release exact file set mismatch')
    if len(rows) != manifest['fileCount'] or total != manifest['totalBytes']:
        raise ValueError('Release totals mismatch')
    original_path = root / 'evidence/original-archive-manifest.json'
    if sha(original_path) != manifest['originalManifestSHA256']:
        raise ValueError('Original manifest identity mismatch')
    original = json.loads(original_path.read_text(encoding='utf-8'))
    originals = original['files']
    if len(originals) != 1728 or len({r['archivePath'] for r in originals}) != 1728:
        raise ValueError('Unexpected original delivery inventory')
    for row in originals:
        path = root / relative(row['archivePath'])
        if path.stat().st_size != row['bytes'] or sha(path) != row['sha256']:
            raise ValueError('Original evidence/source changed: ' + row['archivePath'])
    source_original = {r['archivePath'] for r in originals if r['archivePath'].startswith('source/')}
    source_actual = {name for name in actual if name.startswith('source/')}
    if len(source_original) != 1527 or source_original != source_actual:
        raise ValueError('Frozen source exact set mismatch')
    print(json.dumps({'status': 'PASS', 'publishedFiles': len(actual),
                      'originalFilesPreserved': len(originals), 'sourceFiles': 1527,
                      'listedBytes': total, 'networkUsed': False,
                      'productTestsExecuted': False, 'scope': 'clean publication integrity'}))


if __name__ == '__main__':
    main()
