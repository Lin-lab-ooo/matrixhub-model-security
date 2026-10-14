// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package hf_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matrixhub-ai/hfd/pkg/permission"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	"github.com/matrixhub-ai/hfd/pkg/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	hf "github.com/matrixhub-ai/matrixhub/internal/apiserver/handler/hf"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	securitymocks "github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

type snapshotReader struct {
	*bytes.Reader
	closed bool
}

func (r *snapshotReader) Close() error { r.closed = true; return nil }

func fixture(t *testing.T, extra ...repository.CommitOperation) (*storage.Storage, *repository.Repository, string) {
	t.Helper()
	s := storage.NewStorage(storage.WithRootDir(t.TempDir()))
	repo, err := repository.Init(t.Context(), s.ResolvePath("proj/model"), "main")
	require.NoError(t, err)
	ops := append([]repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("raw source content")}}, extra...)
	commit, err := repo.CreateCommit(t.Context(), "main", "test", "Test", "test@example.invalid", ops, "")
	require.NoError(t, err)
	return s, repo, commit
}

func approved(commit, path, content string) (*security.ApprovedFile, *snapshotReader) {
	digest := sha256.Sum256([]byte(content))
	reader := &snapshotReader{Reader: bytes.NewReader([]byte(content))}
	return &security.ApprovedFile{Reader: reader, Decision: security.Decision{
		Allowed: true, Repo: "proj/model", Revision: commit, Path: path,
		Digest: hex.EncodeToString(digest[:]), Size: int64(len(content)),
	}}, reader
}

func TestSecurityResolveAllStatesAndMethods(t *testing.T) {
	for _, state := range []security.State{security.Pending, security.Scanning, security.Pass, security.Warn, security.Block, security.Fail} {
		for _, method := range []string{http.MethodGet, http.MethodHead, "range"} {
			for _, cache := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cache=%v", state, method, cache), func(t *testing.T) {
					s, _, commit := fixture(t)
					gate := securitymocks.NewMockGate(gomock.NewController(t))
					gate.EXPECT().Enabled().Return(true).AnyTimes()
					var reader *snapshotReader
					if state == security.Pass || state == security.Warn {
						file, rc := approved(commit, "README.md", "verified snapshot")
						reader = rc
						gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "README.md").Return(file, nil)
					} else {
						gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "README.md").Return(nil, &security.AdmissionError{Code: "RevisionDenied", State: state, Message: "Complete approval required"})
					}
					url := "/proj/model/resolve/main/README.md"
					if cache {
						url = "/api/resolve-cache/models/proj/model/main/README.md"
					}
					verb := method
					if method == "range" {
						verb = http.MethodGet
					}
					req := httptest.NewRequest(verb, url, nil)
					if method == "range" {
						req.Header.Set("Range", "bytes=0-7")
					}
					w := httptest.NewRecorder()
					hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate)).ServeHTTP(w, req)
					if reader == nil {
						require.Equal(t, http.StatusForbidden, w.Code)
						require.Equal(t, "RevisionDenied", w.Header().Get("X-Error-Code"))
						require.Empty(t, w.Header().Get("Location"))
						require.NotContains(t, w.Body.String(), "raw source content")
						return
					}
					code, body := http.StatusOK, "verified snapshot"
					if method == http.MethodHead {
						body = ""
					}
					if method == "range" {
						code, body = http.StatusPartialContent, "verified"
					}
					require.Equal(t, code, w.Code)
					require.Equal(t, body, w.Body.String())
					require.Equal(t, commit, w.Header().Get("X-Repo-Commit"))
					require.True(t, reader.closed)
				})
			}
		}
	}
}

func TestSecurityResolvePinsBranchBeforeGate(t *testing.T) {
	s, repo, commit := fixture(t)
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true).AnyTimes()
	gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "README.md").DoAndReturn(func(context.Context, string, string, string) (*security.ApprovedFile, error) {
		_, err := repo.CreateCommit(t.Context(), "main", "moved", "Test", "test@example.invalid", []repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("changed content")}}, commit)
		require.NoError(t, err)
		file, _ := approved(commit, "README.md", "verified snapshot")
		return file, nil
	})
	w := httptest.NewRecorder()
	hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/proj/model/resolve/main/README.md", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, commit, w.Header().Get("X-Repo-Commit"))
	require.Equal(t, "verified snapshot", w.Body.String())
	current, err := repo.ResolveRevision("main")
	require.NoError(t, err)
	require.NotEqual(t, commit, current)
}

func TestSecurityResolveRejectsBadSnapshot(t *testing.T) {
	for _, kind := range []string{"nil", "wrong-commit", "wrong-path", "denied", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			s, _, commit := fixture(t)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true).AnyTimes()
			file, reader := approved(commit, "README.md", "verified snapshot")
			var err error
			switch kind {
			case "nil":
				file = nil
			case "wrong-commit":
				file.Decision.Revision = strings.Repeat("b", 40)
			case "wrong-path":
				file.Decision.Path = "other.txt"
			case "denied":
				file.Decision.Allowed = false
			case "unavailable":
				file = nil
				err = fmt.Errorf("scanner backend unreachable")
			}
			gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "README.md").Return(file, err)
			w := httptest.NewRecorder()
			hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/proj/model/resolve/main/README.md", nil))
			require.GreaterOrEqual(t, w.Code, 400)
			require.NotContains(t, w.Body.String(), "verified snapshot")
			require.NotContains(t, w.Body.String(), "scanner backend unreachable")
			if file != nil {
				require.True(t, reader.closed)
			}
		})
	}
}

func TestSecurityModelInfoClientFields(t *testing.T) {
	oid := strings.Repeat("a", 64)
	pointer := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 123\n", oid)
	s, _, commit := fixture(t, repository.CommitOperation{Type: repository.CommitOperationAdd, Path: "weights.bin", Content: []byte(pointer)})
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true).AnyTimes()
	gate.EXPECT().Report(gomock.Any(), "proj/model", commit).Return(&security.Report{Repo: "proj/model", Revision: commit, State: security.Pass, Complete: true}, nil)
	w := httptest.NewRecorder()
	hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model?securityStatus=True&blobs=True", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var info struct {
		SHA      string         `json:"sha"`
		Security map[string]any `json:"securityRepoStatus"`
		Files    []struct {
			Path string         `json:"rfilename"`
			Size *int64         `json:"size"`
			Blob string         `json:"blobId"`
			LFS  map[string]any `json:"lfs"`
		} `json:"siblings"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	require.Equal(t, commit, info.SHA)
	require.Equal(t, "clean", info.Security["status"])
	require.Len(t, info.Files, 2)
	for _, f := range info.Files {
		require.NotNil(t, f.Size)
		require.Len(t, f.Blob, 40)
		if f.Path == "weights.bin" {
			require.Equal(t, int64(123), *f.Size)
			require.Equal(t, oid, f.LFS["sha256"])
			require.Equal(t, float64(len(pointer)), f.LFS["pointerSize"])
			require.NotContains(t, f.LFS, "oid")
		}
	}
}

func TestSecurityModelInfoOptionalQueriesAndMissingRevision(t *testing.T) {
	s, _, _ := fixture(t)
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(false).AnyTimes()
	h := hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate))
	for _, url := range []string{"/api/models/proj/model", "/api/models/proj/model?securityStatus=False&blobs=False"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		require.Equal(t, http.StatusOK, w.Code)
		require.NotContains(t, w.Body.String(), "securityRepoStatus")
		require.NotContains(t, w.Body.String(), "blobId")
	}
	for _, name := range []string{"blobs", "securityStatus"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model?"+name+"=invalid", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model/revision/missing", nil))
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecurityCompareRejectsHistoricalDiff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"project-enforce-denial", &security.AdmissionError{Code: "RawGitDisabled", Message: "Historical objects are not approved", State: security.Block}, http.StatusForbidden, "RawGitDisabled"},
		{"policy-error", errors.New("private policy database failed"), http.StatusServiceUnavailable, "security_unavailable"},
		{"auth-error", errors.New("private authorization backend failed"), http.StatusServiceUnavailable, "security_unavailable"},
		{"audit-error", errors.New("private audit database failed"), http.StatusServiceUnavailable, "security_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true)
			gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(tc.err)
			w := httptest.NewRecorder()
			// No storage is configured: Compare and Patch cannot be reached.
			hf.NewHandler(hf.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model/compare/old..main", nil))
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.code, w.Header().Get("X-Error-Code"))
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.NotContains(t, w.Body.String(), "private")
		})
	}
}

func TestSecurityCompareAdmissionAllowsExistingDiff(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "audit"}[enabled], func(t *testing.T) {
			s, repo, base := fixture(t)
			_, err := repo.CreateCommit(t.Context(), "main", "updated", "Test", "test@example.invalid", []repository.CommitOperation{{
				Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("updated source content"),
			}}, base)
			require.NoError(t, err)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(enabled)
			if enabled {
				gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
			}
			permissionCalls := 0
			h := hf.NewHandler(hf.WithStorage(s), hf.WithSecurityGate(gate),
				hf.WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
					permissionCalls++
					require.Equal(t, permission.OperationReadRepo, operation)
					require.Equal(t, "proj/model", name)
					return true, nil
				}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model/compare/"+base+"..main", nil))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.Equal(t, 1, permissionCalls)
			require.Empty(t, w.Header().Get("X-Error-Code"))
			require.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), "diff --git a/README.md b/README.md")
			require.Contains(t, w.Body.String(), "-raw source content")
			require.Contains(t, w.Body.String(), "+updated source content")
		})
	}
}

func TestSecurityCompareAdmissionPreservesAuthorization(t *testing.T) {
	for _, hookError := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "error"}[hookError], func(t *testing.T) {
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true)
			gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
			permissionCalls := 0
			h := hf.NewHandler(hf.WithSecurityGate(gate),
				hf.WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
					permissionCalls++
					require.Equal(t, permission.OperationReadRepo, operation)
					require.Equal(t, "proj/model", name)
					if hookError {
						return false, errors.New("authorization hook failed")
					}
					return false, nil
				}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/models/proj/model/compare/old..main", nil))
			status, message := http.StatusForbidden, "permission denied"
			if hookError {
				status, message = http.StatusInternalServerError, "authorization hook failed"
			}
			require.Equal(t, status, w.Code)
			require.Equal(t, 1, permissionCalls)
			require.Contains(t, w.Body.String(), message)
			require.Empty(t, w.Header().Get("X-Error-Code"))
		})
	}
}
