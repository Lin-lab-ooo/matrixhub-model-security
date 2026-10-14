#!/usr/bin/env python3
"""Opt-in smoke: a new private repo, explicit local file, HF metadata and full download SHA.

No model loading, deserialization, token persistence or external service endpoint.
This is a portable user-run smoke test, not the frozen multi-revision evidence harness.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.parse
import urllib.request


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(stream):
    stream.seek(0)
    result = hashlib.file_digest(stream, 'sha256').hexdigest()
    stream.seek(0)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--base-url', default='http://127.0.0.1:3002')
    parser.add_argument('--repo', help='Existing private project/new unique model name, for example review/model-v12-001')
    parser.add_argument('--model-file', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--token-stdin', action='store_true', help='Read one ephemeral token from bounded stdin, never a CLI argument or file')
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'status': 'DESCRIBE_ONLY', 'networkInvoked': False, 'writes': False,
                          'requires': 'local fresh deployment, existing project, new private repo name, explicit file SHA, write token entered interactively'}))
        return 0
    url = urllib.parse.urlsplit(args.base_url)
    require(url.scheme == 'http' and url.hostname in {'127.0.0.1', 'localhost'} and url.port is not None
            and not url.username and not url.password and url.path == '' and not url.query and not url.fragment,
            'explicit-loopback-base-url-required')
    require(bool(re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', args.repo or '')), 'new-repo-name-required')
    require(bool(re.fullmatch(r'[a-f0-9]{64}', args.expected_sha256 or '')), 'explicit-file-SHA256-required')
    require(args.model_file and args.model_file.is_file() and not args.model_file.is_symlink(), 'regular-local-model-file-required')
    require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.model_file.name)), 'simple-model-filename-required')
    require(args.output and not args.output.exists(), 'new-result-output-required')
    import importlib.metadata
    require(importlib.metadata.version('huggingface_hub') == '2.1.1', 'huggingface_hub-2.1.1-required')
    os.environ.update(HF_HUB_DISABLE_TELEMETRY='1', HF_HUB_DISABLE_XET='1', HF_HUB_DISABLE_PROGRESS_BARS='1',
                      HF_HUB_DISABLE_IMPLICIT_TOKEN='1', DO_NOT_TRACK='1', NO_PROXY='127.0.0.1,localhost')
    from huggingface_hub import HfApi, CommitOperationAdd, set_client_factory
    import httpx2
    def local_only(request):
        requested = urllib.parse.urlsplit(str(request.url))
        require(requested.scheme == url.scheme and requested.netloc == url.netloc
                and not requested.username and not requested.password and not requested.fragment, 'HF-origin-mismatch')
    set_client_factory(lambda: httpx2.Client(trust_env=False, follow_redirects=False,
        timeout=httpx2.Timeout(300, connect=5), event_hooks={'request': [local_only]}))
    class BoundedAdd(CommitOperationAdd):
        def b64content(self):
            require(self.upload_info.size <= 1 << 20, 'large-file-requires-LFS')
            return super().b64content()
    token = sys.stdin.read(4098) if args.token_stdin else getpass.getpass('New local test account write token (not saved): ')
    require(len(token) <= 4097 and '\n' not in token.rstrip('\n') and '\r' not in token, 'bounded-single-token-required')
    token = token.rstrip('\n')
    require(8 <= len(token) <= 4096 and token.isascii() and all(32 < ord(char) < 127 for char in token), 'token-required')
    api = HfApi(endpoint=args.base_url, token=token)
    result = {'schema': 1, 'status': 'INCOMPLETE', 'repo': args.repo, 'modelFile': args.model_file.name,
              'expectedSHA256': args.expected_sha256, 'modelLoaded': False, 'tokenSaved': False, 'repositoryCreated': False,
              'scope': 'One local model upload, immutable revision status and full authenticated download; not multi-revision acceptance.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.model_file.open('rb') as stream:
            before = os.fstat(stream.fileno())
            require(0 < before.st_size <= 64 << 20 and digest(stream) == args.expected_sha256, 'file-size-or-hash-mismatch')
            # MatrixHub's HF create_repo is idempotent even with exist_ok=False.
            # Create a new database-bound model explicitly before real HF/LFS upload.
            project, model = args.repo.split('/', 1)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            request = urllib.request.Request(args.base_url + '/api/v1alpha1/models',
                json.dumps({'project': project, 'name': model}).encode('utf-8'),
                {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
            with opener.open(request, timeout=30) as response:
                require(response.status == 200, 'new-native-model-create-required')
                created_body = response.read((1 << 20) + 1)
                require(len(created_body) <= 1 << 20 and json.loads(created_body) == {}, 'native-create-empty-response-required')
            result['repositoryCreationMechanism'] = 'native-model-POST-before-HF-commit'
            result['repositoryCreated'] = True
            began = time.monotonic()
            operation = BoundedAdd(path_in_repo=args.model_file.name, path_or_fileobj=stream)
            require(operation.upload_info.size == before.st_size and operation.upload_info.sha256.hex() == args.expected_sha256,
                    'HF-upload-info-binding')
            commit = api.create_commit(args.repo, operations=[operation], repo_type='model', revision='main', num_threads=1,
                                       commit_message='Explicit local security smoke', token=token)
            result['uploadCommitSeconds'] = round(time.monotonic() - began, 6)
            after = os.fstat(stream.fileno())
            require(before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns
                    and digest(stream) == args.expected_sha256, 'upload-input-mutated')
        revision = commit.oid
        require(bool(re.fullmatch(r'[a-f0-9]{40}', revision)), 'immutable-revision-required')
        result['revision'], result['sourceBytes'] = revision, before.st_size
        deadline, began = time.monotonic() + 1200, time.monotonic()
        while time.monotonic() < deadline:
            info = api.model_info(args.repo, revision=revision, files_metadata=True, securityStatus=True, token=token, timeout=30)
            require(info.sha == revision, 'HF-revision-binding')
            status = info.security_repo_status
            require(isinstance(status, dict) and isinstance(status.get('details'), dict), 'HF-security-status-required')
            details = status['details']
            state = details.get('machineStatus')
            if state in {'pass', 'warn', 'block', 'fail'}:
                break
            time.sleep(1)
        else:
            raise ValueError('complete-scan-timeout')
        result.update(scanWaitSeconds=round(time.monotonic() - began, 6), state=state,
                      complete=details.get('complete') is True, generation=details.get('generation'), reportId=details.get('reportId'))
        require(details.get('revision') == revision and details.get('complete') is True and state == 'pass'
                and status.get('kind') == 'malware' and status.get('status') == 'clean'
                and bool(re.fullmatch(r'[a-f0-9]{64}', details.get('generation') or ''))
                and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', str(details.get('reportId') or ''))), 'model-not-completely-approved')
        sibling = next((s for s in info.siblings if s.rfilename == args.model_file.name), None)
        require(sibling is not None and sibling.size == before.st_size, 'HF-file-size-binding')
        lfs = getattr(sibling, 'lfs', None)
        if lfs is not None:
            require(lfs.sha256 == args.expected_sha256 and lfs.size == before.st_size, 'HF-LFS-SHA-binding')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(args.base_url + '/' + args.repo + '/resolve/' + revision + '/' + args.model_file.name,
                                         headers={'Authorization': 'Bearer ' + token})
        began, total, observed = time.monotonic(), 0, hashlib.sha256()
        with opener.open(request, timeout=300) as response:
            require(response.status == 200 and response.headers.get('Content-Length') == str(before.st_size), 'complete-download-required')
            while chunk := response.read(1 << 20):
                total += len(chunk)
                require(total <= before.st_size and time.monotonic() - began <= 600, 'download-budget')
                observed.update(chunk)
        require(total == before.st_size and observed.hexdigest() == args.expected_sha256, 'download-full-SHA-binding')
        result.update(status='PASS', downloadBytes=total, downloadSHA256=observed.hexdigest(), downloadSeconds=round(time.monotonic() - began, 6))
    except Exception as error:
        # Do not persist HTTP exception bodies, authorization headers or tokens.
        result.update(status='FAIL', errorType=type(error).__name__, errorDetailsOmitted=True)
    finally:
        token = None
        with args.output.open('x', encoding='utf-8') as target:
            json.dump(result, target, ensure_ascii=False, indent=2)
            target.write('\n')
    print(json.dumps({'status': result['status'], 'resultPath': str(args.output), 'tokenSaved': False}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
