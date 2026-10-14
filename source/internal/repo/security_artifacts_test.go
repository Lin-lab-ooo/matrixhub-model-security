// Copyright The MatrixHub Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/matrixhub-ai/hfd/pkg/lfs"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	gitstorage "github.com/matrixhub-ai/hfd/pkg/storage"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func securityFixture(t *testing.T, content []byte, useLFS bool) (*SecurityArtifacts, *security.Task, security.SourceFile, lfs.Storage) {
	t.Helper()
	ctx := context.Background()
	storage := gitstorage.NewStorage(gitstorage.WithRootDir(t.TempDir()))
	r, err := repository.Init(ctx, storage.ResolvePath("project/model"), "main")
	if err != nil {
		t.Fatal(err)
	}
	store := lfs.NewLocal(storage.LFSDir())
	blob := content
	if useLFS {
		oid := fmt.Sprintf("%x", sha256.Sum256(content))
		if err = store.Put(oid, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatal(err)
		}
		blob = []byte(fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(content)))
	}
	commit, err := r.CreateCommit(ctx, "main", "fixture", "Test", "test@example.invalid", []repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: "weights.pkl", Content: blob}}, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewSecurityArtifacts(storage, t.TempDir(), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	files, err := a.List(ctx, "project/model", commit)
	if err != nil || len(files) != 1 {
		t.Fatalf("manifest: %v (%d files)", err, len(files))
	}
	task := &security.Task{ID: 1, Attempt: 1, Token: "claim-a", Repo: "project/model", Revision: commit}
	return a, task, files[0], store
}

func TestSecurityArtifactsSnapshotRetainsScannedBytes(t *testing.T) {
	for _, useLFS := range []bool{false, true} {
		t.Run(fmt.Sprint(useLFS), func(t *testing.T) {
			ctx := context.Background()
			original := []byte("(dp0\n.")
			a, task, source, _ := securityFixture(t, original, useLFS)
			release, err := a.Reserve(ctx, task, source.Size)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			artifact, err := a.Stage(ctx, task, source, 4096)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Digest != fmt.Sprintf("%x", sha256.Sum256(original)) || !strings.HasSuffix(artifact.Type, ";ext=.pkl") {
				t.Fatal("snapshot identity or context lost")
			}
			r, err := a.repository(task.Repo)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.CreateCommit(ctx, "main", "new version", "Test", "test@example.invalid", []repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: source.Path, Content: []byte("new content")}}, task.Revision)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := a.Open(ctx, artifact)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = opened.Close() }()
			got, err := io.ReadAll(opened)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("approved snapshot changed: %q %v", got, err)
			}
		})
	}
}

func TestSecurityArtifactsRejectLFSIntegrityMismatch(t *testing.T) {
	a, task, source, store := securityFixture(t, []byte("good"), true)
	rc, _, err := store.(lfs.Getter).Get(source.LFSOID)
	if err != nil {
		t.Fatal(err)
	}
	file := rc.(*os.File).Name()
	_ = rc.Close()
	if err = os.WriteFile(file, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	release, err := a.Reserve(context.Background(), task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = a.Stage(context.Background(), task, source, 4096); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("corrupt LFS object accepted: %v", err)
	}
	if a.used != 0 {
		t.Fatal("failed snapshot was counted as published")
	}
}

func TestSecurityArtifactsRejectTamperingTraversalAndMutableManifest(t *testing.T) {
	a, task, source, _ := securityFixture(t, []byte("safe"), false)
	ctx := context.Background()
	release, err := a.Reserve(ctx, task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	artifact, err := a.Stage(ctx, task, source, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.List(ctx, task.Repo, "main"); err == nil {
		t.Fatal("mutable manifest revision accepted")
	}
	bad := artifact
	bad.ID = "../../outside"
	if _, err = a.Open(ctx, bad); err == nil {
		t.Fatal("path traversal accepted")
	}
	snapshot := filepath.Join(a.rootPath, filepath.FromSlash(artifact.ID))
	if err = os.Chmod(snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(snapshot, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Open(ctx, artifact); err == nil {
		t.Fatal("same-sized tampering accepted")
	}
}

func TestSecurityArtifactsQuotaConcurrentAndRestart(t *testing.T) {
	storage := gitstorage.NewStorage(gitstorage.WithRootDir(t.TempDir()))
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "retained.part"), make([]byte, 5), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewSecurityArtifacts(storage, root, 15, WithSecurityMaxTaskBytes(10))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if a.used != 5 {
		t.Fatal("restart did not account retained bytes")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	releases := []func(){}
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			release, e := a.Reserve(context.Background(), &security.Task{ID: int64(id), Attempt: 1, Token: "x"}, 10)
			if e == nil {
				mu.Lock()
				releases = append(releases, release)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(releases) != 1 {
		t.Fatalf("quota allowed %d concurrent reservations", len(releases))
	}
	releases[0]()
	releases[0]()
	if a.reserved != 0 {
		t.Fatal("reservation release not idempotent")
	}
	if _, err = a.Reserve(context.Background(), &security.Task{ID: 9, Attempt: 1, Token: "x"}, 11); err == nil {
		t.Fatal("task quota ignored")
	}
}

func TestSecurityArtifactsRejectCancelledAndMismatchedSource(t *testing.T) {
	a, task, source, _ := securityFixture(t, []byte("safe"), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Reserve(ctx, task, source.Size); err == nil {
		t.Fatal("cancelled reservation accepted")
	}
	release, err := a.Reserve(context.Background(), task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	source.BlobID = strings.Repeat("0", 40)
	if _, err = a.Stage(context.Background(), task, source, 4096); err == nil {
		t.Fatal("different Git blob accepted")
	}
}

func TestSecurityArtifactContextSeparatesExtensions(t *testing.T) {
	payload := []byte("(dp0\n.")
	if securityContentType("a.txt", payload) == securityContentType("b.pkl", payload) {
		t.Fatal("cache context aliases different serialization extensions")
	}
}

func TestSecurityArtifactsZeroByteEntriesHaveConcurrentQuota(t *testing.T) {
	a, base, source, _ := securityFixture(t, nil, false)
	a.maxEntries = 2 // One task directory plus one zero-byte snapshot.
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			task := *base
			task.ID = int64(id)
			release, err := a.Reserve(context.Background(), &task, 0)
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			_, err = a.Stage(context.Background(), &task, source, 4096)
			if err == nil {
				mu.Lock()
				passed++
				mu.Unlock()
			} else if !strings.Contains(err.Error(), "entry quota") {
				t.Errorf("unexpected staging failure: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if passed != 1 || a.entries != 2 || a.entryReserved != 0 || a.used != 0 {
		t.Fatalf("zero-byte quota escaped: passed=%d entries=%d reserved=%d bytes=%d", passed, a.entries, a.entryReserved, a.used)
	}
	actual := 0
	if err := filepath.WalkDir(a.rootPath, func(p string, _ os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if p != a.rootPath {
			actual++
		}
		return nil
	}); err != nil || actual != 2 {
		t.Fatalf("unexpected physical entries: %d %v", actual, err)
	}
}

func TestSecurityArtifactsRestartCountsDirectoriesAndEmptyPartials(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "abandoned"), 0750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty.blob", "empty.part"} {
		if err := os.WriteFile(filepath.Join(root, "abandoned", name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	storage := gitstorage.NewStorage(gitstorage.WithRootDir(t.TempDir()))
	if a, err := NewSecurityArtifacts(storage, root, 4096, WithSecurityMaxEntries(2)); err == nil {
		_ = a.Close()
		t.Fatal("restart ignored zero-byte retained entries")
	}
	a, err := NewSecurityArtifacts(storage, root, 4096, WithSecurityMaxEntries(3))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if a.entries != 3 || a.used != 0 {
		t.Fatalf("wrong retained accounting: %d/%d", a.entries, a.used)
	}
	task := &security.Task{ID: 1, Attempt: 1, Token: "x"}
	release, err := a.Reserve(context.Background(), task, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := a.beginFile(task, 0); err == nil {
		t.Fatal("full retained entry quota admitted another empty file")
	}
}

func TestSecurityArtifactsFailedCopyRetainsDirectoryEntry(t *testing.T) {
	a, task, source, store := securityFixture(t, []byte("good"), true)
	rc, _, err := store.(lfs.Getter).Get(source.LFSOID)
	if err != nil {
		t.Fatal(err)
	}
	name := rc.(*os.File).Name()
	_ = rc.Close()
	if err := os.WriteFile(name, []byte("evil"), 0600); err != nil {
		t.Fatal(err)
	}
	release, err := a.Reserve(context.Background(), task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := a.Stage(context.Background(), task, source, 4096); err == nil {
		t.Fatal("corrupt LFS accepted")
	}
	if a.entries != 1 || a.entryReserved != 0 || a.used != 0 {
		t.Fatalf("failed copy lost directory accounting: entries=%d reserved=%d bytes=%d", a.entries, a.entryReserved, a.used)
	}
}
