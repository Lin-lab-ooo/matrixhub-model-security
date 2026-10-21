// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

// This fixture creates the same sealed on-disk input used by Open. It does not
// replace Open, the filesystem, hashing or the cancellation-aware reader.
func sealedSnapshotFixture(t testing.TB, content []byte) (*SecurityArtifacts, security.Artifact, string) {
	t.Helper()
	rootPath := t.TempDir()
	id := "task-1-1-0123456789abcdef/0123456789abcdef0123456789abcdef.blob"
	filePath := filepath.Join(rootPath, filepath.FromSlash(id))
	if err := os.Mkdir(filepath.Dir(filePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0440); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = root.Close()
		// Windows exposes its read-only attribute through Chmod; clear it only
		// for this test's own file so TempDir can remove the fixture.
		_ = os.Chmod(filePath, 0600)
	})
	return &SecurityArtifacts{root: root, rootPath: rootPath}, security.Artifact{
		ID: id, Digest: fmt.Sprintf("%x", sha256.Sum256(content)), Size: int64(len(content)), Type: "opaque;ext=.bin",
	}, filePath
}

func TestSecuritySnapshotOpenRejectsWritableAndResealedTampering(t *testing.T) {
	a, artifact, filePath := sealedSnapshotFixture(t, []byte("safe"))
	if err := os.Chmod(filePath, 0640); err != nil {
		t.Fatal(err)
	}
	if reader, err := a.Open(context.Background(), artifact); err == nil {
		_ = reader.Close()
		t.Fatal("writable snapshot accepted")
	}
	if err := os.WriteFile(filePath, []byte("evil"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0440); err != nil {
		t.Fatal(err)
	}
	if reader, err := a.Open(context.Background(), artifact); err == nil {
		_ = reader.Close()
		t.Fatal("same-size tampering accepted after read-only permissions restored")
	}
}

func TestSecuritySnapshotOpenRejectsCancelledEmptyFile(t *testing.T) {
	a, artifact, _ := sealedSnapshotFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if reader, err := a.Open(ctx, artifact); !errors.Is(err, context.Canceled) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("cancelled empty snapshot returned %v", err)
	}
}

func TestSecuritySnapshotOpenRejectsOverflowingDescriptor(t *testing.T) {
	a, artifact, _ := sealedSnapshotFixture(t, nil)
	artifact.Size = math.MaxInt64
	if reader, err := a.Open(context.Background(), artifact); err == nil || !strings.Contains(err.Error(), "invalid approved snapshot descriptor") {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("size+1 overflow was not rejected before reading: %v", err)
	}
}

type snapshotFinalCancelContext struct {
	context.Context
	calls  int
	cancel context.CancelFunc
}

func (c *snapshotFinalCancelContext) Err() error {
	c.calls++
	if c.calls == 5 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSecuritySnapshotOpenRejectsCancellationBeforeReturn(t *testing.T) {
	a, artifact, _ := sealedSnapshotFixture(t, []byte("x"))
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &snapshotFinalCancelContext{Context: base, cancel: cancel}
	reader, err := a.Open(ctx, artifact)
	if reader != nil {
		_ = reader.Close()
	}
	if !errors.Is(err, context.Canceled) || ctx.calls != 5 {
		t.Fatalf("final cancellation was not respected: err=%v calls=%d", err, ctx.calls)
	}
}

// Err is called by the real cancellation-aware reader. Mutating metadata at
// its second read makes the otherwise difficult verification window
// deterministic, without adding an injectable production filesystem.
type snapshotMutationContext struct {
	context.Context
	calls  int
	mutate func()
}

func (c *snapshotMutationContext) Err() error {
	c.calls++
	if c.calls == 3 {
		c.mutate()
	}
	return c.Context.Err()
}

func TestSecuritySnapshotOpenRejectsMetadataChangesDuringHash(t *testing.T) {
	for _, change := range []string{"mtime", "writable"} {
		t.Run(change, func(t *testing.T) {
			a, artifact, filePath := sealedSnapshotFixture(t, bytes.Repeat([]byte("x"), 256<<10))
			ctx := &snapshotMutationContext{Context: context.Background(), mutate: func() {
				var err error
				if change == "mtime" {
					past := time.Unix(1000000000, 0)
					err = os.Chtimes(filePath, past, past)
				} else {
					err = os.Chmod(filePath, 0640)
				}
				if err != nil {
					t.Fatal(err)
				}
			}}
			reader, err := a.Open(ctx, artifact)
			if reader != nil {
				_ = reader.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "changed during verification") {
				t.Fatalf("metadata mutation during full hash returned %v", err)
			}
		})
	}
}

func TestSecuritySnapshotOpenConcurrentReadersHaveIndependentOffsets(t *testing.T) {
	content := bytes.Repeat([]byte("independent reader\n"), 10000)
	a, artifact, _ := sealedSnapshotFixture(t, content)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			reader, err := a.Open(context.Background(), artifact)
			if err != nil {
				t.Error(err)
				return
			}
			defer reader.Close()
			prefix := make([]byte, 37)
			if _, err = io.ReadFull(reader, prefix); err != nil {
				t.Error(err)
				return
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(append(prefix, remaining...), content) {
				t.Errorf("concurrent reader content mismatch: %v", err)
			}
		})
	}
	workers.Wait()
}

func TestSecuritySnapshotOpenRejectsFileAndParentSymlinks(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(fmt.Sprint(parent), func(t *testing.T) {
			a, artifact, filePath := sealedSnapshotFixture(t, []byte("safe"))
			target, link := filePath+".target", filePath
			if parent {
				link = filepath.Dir(filePath)
				target = link + "-target"
			}
			if err := os.Rename(link, target); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.Remove(link)
				_ = os.Rename(target, link)
			})
			if err := os.Symlink(target, link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("Windows test account cannot create symlinks: %v", err)
				}
				t.Fatal(err)
			}
			if reader, err := a.Open(context.Background(), artifact); err == nil {
				_ = reader.Close()
				t.Fatal("symbolic link snapshot accepted")
			}
		})
	}
}

func TestSecuritySnapshotOpenRetainsReaderAfterPathReplacement(t *testing.T) {
	a, artifact, filePath := sealedSnapshotFixture(t, []byte("safe"))
	reader, err := a.Open(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	oldPath := filePath + ".retained"
	if err = os.Rename(filePath, oldPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows filesystem does not permit replacing this open file: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(oldPath, 0600) })
	if err = os.WriteFile(filePath, []byte("evil"), 0440); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "safe" {
		t.Fatalf("held reader followed replacement path: %q %v", got, err)
	}
	if next, err := a.Open(context.Background(), artifact); err == nil {
		_ = next.Close()
		t.Fatal("subsequent open accepted replacement content")
	}
}
