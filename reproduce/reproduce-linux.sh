#!/usr/bin/env bash
# Portable Linux/amd64 entrypoints. Run explicitly; no automatic deployment.
set -euo pipefail
task_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
release_dir="$(CDPATH= cd -- "$task_dir/.." && pwd)"
source_dir="$release_dir/source"
action="${1:-help}"
if [[ "$action" == help ]]; then
  printf '%s\n' 'Usage: bash reproduce/reproduce-linux.sh {verify|build|test-go|test-scanner|up}'
  printf '%s\n' 'SCAN_RULES_DIR is required for test-scanner/up. MATRIXHUB_REPRO_PROJECT=matrix-v12-<new-name> is required for up.'
  exit 0
fi
[[ "$action" =~ ^(verify|build|test-go|test-scanner|up)$ ]] || { printf '%s\n' 'Unknown action' >&2; exit 2; }
python3 "$task_dir/verify_source.py"
[[ "$action" != verify ]] || exit 0
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { printf '%s\n' 'Linux/amd64 required (a Linux VM is suitable).' >&2; exit 2; }
cd "$source_dir"
if [[ "$action" == build || "$action" == test-go ]]; then
  [[ "$(go version)" == 'go version go1.26.8 linux/amd64' ]] || { printf '%s\n' 'Install the verified official Go 1.26.8 Linux/amd64 SDK first.' >&2; exit 2; }
  command -v gcc >/dev/null
  export CGO_ENABLED=1 GOTOOLCHAIN=local
fi
case "$action" in
  build)
    # The runtime is Debian 12/bookworm. Match its glibc when using a host GCC.
    [[ -r /etc/os-release ]] && source /etc/os-release
    [[ "${ID:-}" == debian && "${VERSION_CODENAME:-}" == bookworm ]] || { printf '%s\n' 'Use Debian 12/bookworm Linux/amd64 for this CGO runtime build.' >&2; exit 2; }
    [[ "$(pnpm --version)" == 10.17.0 ]] || { printf '%s\n' 'pnpm 10.17.0 required.' >&2; exit 2; }
    (cd ui && HUSKY=0 pnpm install --frozen-lockfile && pnpm build)
    mkdir -p bin
    overlay="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["candidateOverlaySHA256"])' "$release_dir/VERSION_LOCK.json")"
    go build -trimpath -buildvcs=false -ldflags="-X github.com/matrixhub-ai/matrixhub/pkg/version.GitVersion=v12.1-candidate-${overlay:0:12} -X github.com/matrixhub-ai/matrixhub/pkg/version.GitCommit=working-tree:$overlay" -o bin/matrixhub-security ./cmd/matrixhub
    docker build -f deploy/security/Dockerfile.runtime -t matrixhub-security:local .
    docker build -t matrixhub-security-scanner:1.4.6 deploy/security-scanner
    printf '%s\n' 'Images built on this machine. Record actual image IDs and build logs; historical evidence is not a substitute.'
    ;;
  test-go)
    go test -json -race -count=1 -p=2 -mod=readonly -timeout=5m ./internal/domain/security
    go test -json -count=1 -p=2 -mod=readonly -timeout=5m -run '^TestSecurity' ./internal/repo
    go test -json -count=1 -p=2 -mod=readonly -timeout=5m ./internal/apiserver/handler/security
    go test -json -count=1 -p=2 -mod=readonly -timeout=5m -run '^TestSecurity' ./internal/apiserver
    ;;
  test-scanner)
    : "${SCAN_RULES_DIR:?Set an absolute immutable rules snapshot directory}"
    [[ "$SCAN_RULES_DIR" == /* ]] || exit 2
    for name in main.cvd daily.cvd bytecode.cvd; do [[ -f "$SCAN_RULES_DIR/$name" ]] || exit 2; done
    input_dir="$(mktemp -d "${REPRO_TMPDIR:-/tmp}/matrix-v12-input.XXXXXXXX")"
    chmod 0755 "$input_dir"
    trap 'rmdir -- "$input_dir"' EXIT
    docker run --rm --pull never --network none --read-only --user 65532:65532 \
      --cap-drop ALL --security-opt no-new-privileges --cpus 1 \
      --memory 3g --memory-swap 3g --pids-limit 32 \
      --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
      --mount "type=bind,src=$input_dir,dst=/input,readonly" \
      --mount "type=bind,src=$SCAN_RULES_DIR,dst=/rules,readonly" \
      --mount "type=bind,src=$source_dir/deploy/security-scanner,dst=/opt/scanner,readonly" \
      -e SCAN_PROFILE=default -e SCAN_CLAMAV_BACKEND=clamscan \
      -e VERIFY_CONTAINER_ISOLATION=1 -e TEST_RULES_DIR=/rules \
      --entrypoint python matrixhub-security-scanner:1.4.6 -I -c \
      "import sys,unittest; sys.path.insert(0,'/opt/scanner'); s=unittest.defaultTestLoader.loadTestsFromNames(['tests','integration_tests','prefix_tests']); r=unittest.TextTestRunner(verbosity=2).run(s); sys.exit(0 if r.wasSuccessful() and not r.skipped else 1)"
    ;;
  up)
    : "${SCAN_RULES_DIR:?Set an absolute immutable rules snapshot directory}"
    : "${MATRIXHUB_REPRO_PROJECT:?Choose a new matrix-v12- prefixed Compose project name}"
    [[ "$SCAN_RULES_DIR" == /* && "$MATRIXHUB_REPRO_PROJECT" =~ ^matrix-v12-[a-z0-9-]+$ ]] || exit 2
    for name in main.cvd daily.cvd bytecode.cvd; do [[ -f "$SCAN_RULES_DIR/$name" ]] || exit 2; done
    [[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$MATRIXHUB_REPRO_PROJECT")" ]] || { printf '%s\n' 'Project already has containers; choose a fresh name.' >&2; exit 2; }
    [[ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$MATRIXHUB_REPRO_PROJECT")" ]] || { printf '%s\n' 'Project already has data volumes; choose a fresh name.' >&2; exit 2; }
    docker compose --project-name "$MATRIXHUB_REPRO_PROJECT" -f deploy/security/compose.yaml config
    docker compose --project-name "$MATRIXHUB_REPRO_PROJECT" -f deploy/security/compose.yaml up -d --pull never
    printf '%s\n' 'UI/API: http://127.0.0.1:3002 . Wait for health and scanner readiness before upload.'
    ;;
esac
