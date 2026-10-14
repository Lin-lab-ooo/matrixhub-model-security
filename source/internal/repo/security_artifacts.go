// Copyright The MatrixHub Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/matrixhub-ai/hfd/pkg/lfs"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	gitstorage "github.com/matrixhub-ai/hfd/pkg/storage"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

// SecurityArtifacts has a single trusted writer. A staging root must belong to
// one MatrixHub process; scanners only mount it read-only. Published snapshots
// are retained until an operator performs offline, report-aware cleanup.
type SecurityArtifacts struct {
	storage        *gitstorage.Storage
	lfs            lfs.Storage
	prefixProber   security.PrefixProber
	root           *os.Root
	rootPath       string
	cap, taskCap   int64
	maxFiles       int
	maxEntries     int64
	entries        int64
	entryReserved  int64
	mu             sync.Mutex
	used, reserved int64
	reservations   map[string]*artifactReservation
}
type artifactReservation struct {
	remaining int64
	active    bool
	inflight  int
}
type SecurityArtifactOption func(*SecurityArtifacts)

func WithSecurityPrefixProber(prober security.PrefixProber) SecurityArtifactOption {
	return func(a *SecurityArtifacts) { a.prefixProber = prober }
}

func WithSecurityLFSStorage(store lfs.Storage) SecurityArtifactOption {
	return func(a *SecurityArtifacts) { a.lfs = store }
}
func WithSecurityMaxTaskBytes(n int64) SecurityArtifactOption {
	return func(a *SecurityArtifacts) { a.taskCap = n }
}
func WithSecurityMaxFiles(n int) SecurityArtifactOption {
	return func(a *SecurityArtifacts) { a.maxFiles = n }
}

// WithSecurityMaxEntries bounds both files and directories, including empty
// files and abandoned partial copies that consume no logical byte quota.
func WithSecurityMaxEntries(n int64) SecurityArtifactOption {
	return func(a *SecurityArtifacts) { a.maxEntries = n }
}

func NewSecurityArtifacts(storage *gitstorage.Storage, stagingRoot string, globalDiskCap int64, opts ...SecurityArtifactOption) (*SecurityArtifacts, error) {
	if storage == nil || stagingRoot == "" || globalDiskCap <= 0 {
		return nil, errors.New("security staging requires storage, a root, and a positive disk quota")
	}
	abs, err := filepath.Abs(stagingRoot)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0750); err != nil {
		return nil, err
	}
	if stat, e := os.Lstat(abs); e != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("security staging root must be a real directory")
	}
	a := &SecurityArtifacts{storage: storage, lfs: lfs.NewLocal(storage.LFSDir()), rootPath: abs, cap: globalDiskCap, taskCap: globalDiskCap, maxFiles: 10000, maxEntries: 100000, reservations: map[string]*artifactReservation{}}
	for _, opt := range opts {
		opt(a)
	}
	if a.taskCap <= 0 || a.maxFiles <= 0 || a.maxEntries <= 0 {
		return nil, errors.New("security task limits must be positive")
	}
	// Include abandoned temporary files after a crash in occupied space. Never
	// delete them automatically: a report or an open reader may still reference it.
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p != abs {
			a.entries++
			if a.entries > a.maxEntries {
				return errors.New("security staging entry quota exhausted; offline retention cleanup required")
			}
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular entry in security staging")
		}
		if info.Size() > a.cap-a.used {
			return errors.New("security staging quota exhausted; retain reports and perform offline cleanup")
		}
		a.used += info.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.root, err = os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Close is for shutdown, after all scanners and download readers have stopped.
func (a *SecurityArtifacts) Close() error { return a.root.Close() }

func (a *SecurityArtifacts) repository(repoName string) (*repository.Repository, error) {
	if !safeLogicalPath(repoName) {
		return nil, errors.New("invalid repository name")
	}
	p := a.storage.ResolvePath(repoName)
	if p == "" {
		return nil, errors.New("repository path is outside storage")
	}
	return repository.Open(p)
}

func (a *SecurityArtifacts) Resolve(ctx context.Context, repoName, revision string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r, err := a.repository(repoName)
	if err != nil {
		return "", err
	}
	if revision == "" {
		revision = r.DefaultBranch()
	}
	revision = resolveRef(r, revision)
	commits, err := r.Commits(revision, &repository.CommitsOptions{Limit: 1})
	if err != nil {
		return "", err
	}
	if len(commits) != 1 {
		return "", errors.New("revision has no commit")
	}
	return commits[0].Hash().String(), nil
}

func (a *SecurityArtifacts) List(ctx context.Context, repoName, commit string) ([]security.SourceFile, error) {
	if !isCommitSHA(commit) || !safeLogicalPath(repoName) {
		return nil, errors.New("security manifest requires an immutable commit and repository")
	}
	r, err := gogit.PlainOpen(a.storage.ResolvePath(repoName))
	if err != nil {
		return nil, err
	}
	c, err := r.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return nil, err
	}
	tree, err := c.Tree()
	if err != nil {
		return nil, err
	}
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	out := make([]security.SourceFile, 0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if entry.Mode == filemode.Dir {
			continue
		}
		// Links and submodules are not silently omitted from a passing manifest.
		if entry.Mode != filemode.Regular && entry.Mode != filemode.Executable && entry.Mode != filemode.Deprecated {
			return nil, errors.New("unsupported symlink or submodule in security manifest")
		}
		if !safeLogicalPath(name) {
			return nil, errors.New("unsafe file path in security manifest")
		}
		if len(out) >= a.maxFiles {
			return nil, errors.New("security manifest file-count limit exceeded")
		}
		b, err := r.BlobObject(entry.Hash)
		if err != nil {
			return nil, err
		}
		rc, err := b.Reader()
		if err != nil {
			return nil, err
		}
		fd, err := describeSecuritySource(name, b.Hash.String(), b.Size, rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, fd)
	}
	return out, nil
}

func describeSecuritySource(name, blobID string, size int64, r io.Reader) (security.SourceFile, error) {
	fd := security.SourceFile{Path: name, BlobID: blobID, Size: size}
	if size < 0 {
		return fd, errors.New("negative source size")
	}
	if size > lfs.MaxLFSPointerSize {
		return fd, nil
	}
	p, err := io.ReadAll(io.LimitReader(r, lfs.MaxLFSPointerSize+1))
	if err != nil {
		return fd, err
	}
	if int64(len(p)) != size {
		return fd, errors.New("git blob size mismatch")
	}
	if !bytes.HasPrefix(p, []byte("version https://git-lfs")) {
		return fd, nil
	}
	ptr, err := lfs.DecodePointer(bytes.NewReader(p))
	if err != nil || ptr == nil || !validDigest(ptr.OID()) || ptr.Size() < 0 {
		return fd, errors.New("invalid LFS pointer")
	}
	fd.LFSOID, fd.Size = strings.ToLower(ptr.OID()), ptr.Size()
	return fd, nil
}

func reservationKey(t *security.Task) string {
	return fmt.Sprintf("%d/%d/%s", t.ID, t.Attempt, t.Token)
}

func (a *SecurityArtifacts) Reserve(ctx context.Context, task *security.Task, n int64) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if task == nil || task.ID <= 0 || task.Attempt <= 0 || task.Token == "" || n < 0 || n > a.taskCap {
		return nil, errors.New("invalid security task reservation or task quota exceeded")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := reservationKey(task)
	if _, ok := a.reservations[key]; ok {
		return nil, errors.New("duplicate security task reservation")
	}
	if n > a.cap-a.used-a.reserved {
		return nil, errors.New("security staging disk quota exhausted; offline retention cleanup required")
	}
	res := &artifactReservation{remaining: n, active: true}
	a.reservations[key] = res
	a.reserved += n
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			res.active = false
			if res.inflight == 0 {
				a.reserved -= res.remaining
				delete(a.reservations, key)
			}
		})
	}, nil
}

// beginFile reserves the declared bytes from a task. Every read is capped at
// this exact declaration plus one byte; oversized objects never consume an
// unbounded amount of staging space.
func (a *SecurityArtifacts) beginFile(task *security.Task, n int64) (func(bool, bool), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := reservationKey(task)
	res := a.reservations[key]
	if res == nil || !res.active || n < 0 || n > res.remaining {
		return nil, errors.New("artifact exceeds active task reservation")
	}
	// Reserve one file and a possible task directory BEFORE creating either.
	// The unused directory reservation is released if the directory existed.
	if a.maxEntries-a.entries-a.entryReserved < 2 {
		return nil, errors.New("security staging entry quota exhausted; offline retention cleanup required")
	}
	a.entryReserved += 2
	res.remaining -= n
	res.inflight++
	return func(published, createdDirectory bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.entryReserved -= 2
		if createdDirectory {
			a.entries++
		}
		res.inflight--
		if published {
			a.entries++
			a.used += n
			a.reserved -= n
		} else {
			res.remaining += n
		}
		if !res.active && res.inflight == 0 {
			a.reserved -= res.remaining
			delete(a.reservations, key)
		}
	}, nil
}

func (a *SecurityArtifacts) Stage(ctx context.Context, task *security.Task, source security.SourceFile, maxBytes int64) (artifact security.Artifact, retErr error) {
	if task == nil || !isCommitSHA(task.Revision) || !safeLogicalPath(source.Path) || source.Size < 0 || maxBytes <= 0 || source.Size > maxBytes {
		return artifact, errors.New("invalid artifact or file exceeds complete-scanning limit")
	}
	done, err := a.beginFile(task, source.Size)
	if err != nil {
		return artifact, err
	}
	published, createdDirectory := false, false
	defer func() { done(published, createdDirectory) }()
	r, err := a.repository(task.Repo)
	if err != nil {
		return artifact, err
	}
	b, err := r.Blob(task.Revision, source.Path)
	if err != nil {
		return artifact, err
	}
	if b.Hash().String() != source.BlobID {
		return artifact, errors.New("source Git blob does not match manifest")
	}
	rc, err := b.NewReader()
	if err != nil {
		return artifact, err
	}
	checked, err := describeSecuritySource(source.Path, source.BlobID, b.Size(), rc)
	_ = rc.Close()
	if err != nil {
		return artifact, err
	}
	if checked != source {
		return artifact, errors.New("source file no longer matches manifest")
	}
	if source.LFSOID != "" {
		getter, ok := a.lfs.(lfs.Getter)
		if !ok {
			return artifact, errors.New("LFS backend cannot provide complete object content")
		}
		var stat os.FileInfo
		rc, stat, err = getter.Get(source.LFSOID)
		if err == nil && stat.Size() != source.Size {
			_ = rc.Close()
			return artifact, errors.New("LFS object size does not match pointer")
		}
	} else {
		rc, err = b.NewReader()
	}
	if err != nil {
		return artifact, err
	}
	defer func() { _ = rc.Close() }()
	// Closing the source on cancellation also interrupts storage readers that
	// block in Read; the copy checks context between all chunks.
	stopClose := context.AfterFunc(ctx, func() { _ = rc.Close() })
	defer stopClose()
	tokenSum := sha256.Sum256([]byte(task.Token))
	dir := fmt.Sprintf("task-%d-%d-%x", task.ID, task.Attempt, tokenSum[:8])
	if err = a.root.Mkdir(dir, 0750); err == nil {
		createdDirectory = true
	} else if !errors.Is(err, fs.ErrExist) {
		return artifact, err
	}
	info, err := a.root.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return artifact, errors.New("invalid artifact task directory")
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return artifact, err
	}
	id := dir + "/" + hex.EncodeToString(random) + ".blob"
	tmp := id + ".part"
	f, err := a.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0640)
	if err != nil {
		return artifact, err
	}
	defer func() {
		_ = f.Close()
		if !published {
			_ = a.root.Chmod(tmp, 0600)
			if removeErr := a.root.Remove(tmp); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				// Retain the full reservation conservatively if cleanup fails.
				// Otherwise failed copies could escape the live quota until restart.
				published = true
				retErr = errors.Join(retErr, errors.New("failed snapshot cleanup; reserved bytes retained"))
			}
		}
	}()
	digest := sha256.New()
	n, err := copySecurityStream(ctx, io.MultiWriter(f, digest), rc, source.Size, task.Generation, a.prefixProber)
	if err != nil {
		return artifact, err
	}
	if n != source.Size {
		return artifact, errors.New("source content length does not match immutable manifest")
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if source.LFSOID != "" && actual != source.LFSOID {
		return artifact, errors.New("LFS object SHA-256 does not match pointer")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return artifact, err
	}
	prefix := make([]byte, 512)
	prefixN, readErr := f.Read(prefix)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return artifact, readErr
	}
	typ := securityContentType(source.Path, prefix[:prefixN])
	if err = ctx.Err(); err != nil {
		return artifact, err
	}
	if err = f.Sync(); err != nil {
		return artifact, err
	}
	if err = f.Chmod(0440); err != nil {
		return artifact, err
	}
	if err = f.Close(); err != nil {
		return artifact, err
	}
	// A random destination plus no overwrite check protects accidental reuse;
	// staging is private to the trusted single writer, never writable by workers.
	if _, err = a.root.Lstat(id); !errors.Is(err, fs.ErrNotExist) {
		return artifact, errors.New("snapshot destination unexpectedly exists")
	}
	if err = a.root.Rename(tmp, id); err != nil {
		return artifact, err
	}
	published = true
	if runtime.GOOS != "windows" {
		directory, openErr := a.root.Open(dir)
		if openErr != nil {
			return artifact, openErr
		}
		syncErr := directory.Sync()
		_ = directory.Close()
		if syncErr != nil {
			return artifact, syncErr
		}
	}
	return security.Artifact{ID: id, Digest: actual, Size: n, Type: typ}, nil
}

var artifactIDPattern = regexp.MustCompile(`^task-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{16}/[a-f0-9]{32}\.blob$`)
var artifactExtensionPattern = regexp.MustCompile(`^\.[a-z0-9_-]{1,23}$`)

func (a *SecurityArtifacts) Open(ctx context.Context, artifact security.Artifact) (io.ReadSeekCloser, error) {
	if !artifactIDPattern.MatchString(artifact.ID) || !validDigest(artifact.Digest) || artifact.Size < 0 {
		return nil, errors.New("invalid approved snapshot descriptor")
	}
	for _, p := range []string{path.Dir(artifact.ID), artifact.ID} {
		info, err := a.root.Lstat(p)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("snapshot symbolic links are forbidden")
		}
	}
	f, err := a.root.Open(artifact.ID)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != artifact.Size {
		return nil, errors.New("approved snapshot size or type mismatch")
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, &securityContextReader{ctx: ctx, r: io.LimitReader(f, artifact.Size+1)}, make([]byte, 128<<10))
	if err != nil {
		return nil, err
	}
	if n != artifact.Size || hex.EncodeToString(h.Sum(nil)) != artifact.Digest {
		return nil, errors.New("approved snapshot digest mismatch")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

type securityContextReader struct {
	ctx context.Context
	r   io.Reader
}

type securityBoundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *securityBoundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("source content exceeds declared size")
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func (r *securityContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}
func safeLogicalPath(s string) bool {
	return s != "" && path.Clean(s) == s && !strings.HasPrefix(s, "/") && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00\r\n:")
}

// Extension is analysis context, not a trusted type declaration. The scanner
// independently detects magic and examines containers. This prevents content
// cache hits from suppressing extension-dependent pickle analysis.
func securityContentType(name string, p []byte) string {
	magic := "opaque"
	switch {
	case bytes.HasPrefix(p, []byte{'P', 'K', 3, 4}):
		magic = "zip"
	case bytes.HasPrefix(p, []byte{0x1f, 0x8b}):
		magic = "gzip"
	case bytes.HasPrefix(p, []byte("\x93NUMPY")):
		magic = "numpy"
	case len(p) > 1 && p[0] == 0x80 && p[1] <= 5:
		magic = "pickle"
	case bytes.HasPrefix(p, []byte("\x7fELF")):
		magic = "elf"
	case bytes.HasPrefix(p, []byte("MZ")):
		magic = "pe"
	}
	ext := strings.ToLower(path.Ext(name))
	if ext != "" && !artifactExtensionPattern.MatchString(ext) {
		ext = ".other"
	}
	return magic + ";ext=" + ext
}

var _ security.Artifacts = (*SecurityArtifacts)(nil)
