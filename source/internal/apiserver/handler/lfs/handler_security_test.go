// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package lfs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	lfsstore "github.com/matrixhub-ai/hfd/pkg/lfs"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	"github.com/matrixhub-ai/hfd/pkg/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	lfs "github.com/matrixhub-ai/matrixhub/internal/apiserver/handler/lfs"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	securitymocks "github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

type snapshotReader struct {
	*bytes.Reader
	closed bool
}

func (r *snapshotReader) Close() error { r.closed = true; return nil }

func fixture(t *testing.T) (*storage.Storage, string, string, string, security.Decision) {
	t.Helper()
	content := "verified LFS snapshot"
	digest := sha256.Sum256([]byte(content))
	oid := hex.EncodeToString(digest[:])
	s := storage.NewStorage(storage.WithRootDir(t.TempDir()))
	repo, err := repository.Init(t.Context(), s.ResolvePath("proj/model"), "main")
	require.NoError(t, err)
	pointer := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(content))
	commit, err := repo.CreateCommit(t.Context(), "main", "test", "Test", "test@example.invalid", []repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: "weights.bin", Content: []byte(pointer)}}, "")
	require.NoError(t, err)
	decision := security.Decision{Allowed: true, Repo: "proj/model", Revision: commit, Path: "weights.bin", Digest: oid, Size: int64(len(content))}
	return s, commit, oid, content, decision
}

func batchRequest(oid string, size int64, ref string) *http.Request {
	body := fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":%d}],"ref":{"name":%q}}`, oid, size, ref)
	r := httptest.NewRequest(http.MethodPost, "http://hub.invalid/proj/model.git/info/lfs/objects/batch", strings.NewReader(body))
	r.Header.Set("Accept", "application/vnd.git-lfs+json")
	r.Header.Set("Authorization", "Bearer original-client-token")
	return r
}

func TestSecurityLFSBatchBindsActionToRepositoryCommitAndSize(t *testing.T) {
	s, commit, oid, _, decision := fixture(t)
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true).AnyTimes()
	gate.EXPECT().CheckLFS(gomock.Any(), "proj/model", commit, oid, decision.Size).Return(decision, nil)
	w := httptest.NewRecorder()
	// No LFS storage is supplied: the action comes only from the verified manifest.
	lfs.NewHandler(lfs.WithStorage(s), lfs.WithSecurityGate(gate)).ServeHTTP(w, batchRequest(oid, decision.Size, "refs/heads/main"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var response struct {
		Objects []struct {
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
			Error any `json:"error"`
		} `json:"objects"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Len(t, response.Objects, 1)
	require.Nil(t, response.Objects[0].Error)
	action := response.Objects[0].Actions["download"]
	parsed, err := url.Parse(action.Href)
	require.NoError(t, err)
	require.Equal(t, "/proj/model.git/info/lfs/objects/"+commit+"/"+oid, parsed.Path)
	require.Equal(t, fmt.Sprint(decision.Size), parsed.Query().Get("size"))
	require.Equal(t, "Bearer original-client-token", action.Header["Authorization"])
	require.NotEqual(t, "/objects/"+oid, parsed.Path)
}

func TestSecurityLFSBatchFailureHasNoDownloadAction(t *testing.T) {
	for _, kind := range []string{"pending", "blocked", "wrong-repo", "wrong-commit", "wrong-oid", "wrong-size", "unbound-path"} {
		t.Run(kind, func(t *testing.T) {
			s, commit, oid, _, decision := fixture(t)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true).AnyTimes()
			var err error
			switch kind {
			case "pending":
				err = &security.AdmissionError{Code: "RevisionPending", State: security.Pending, Message: "Scan pending"}
			case "blocked":
				err = &security.AdmissionError{Code: "RevisionBlocked", State: security.Block, Message: "Risk threshold exceeded"}
			case "wrong-repo":
				decision.Repo = "other/model"
			case "wrong-commit":
				decision.Revision = strings.Repeat("c", 40)
			case "wrong-oid":
				decision.Digest = strings.Repeat("a", 64)
			case "wrong-size":
				decision.Size++
			case "unbound-path":
				decision.Path = ""
			}
			gate.EXPECT().CheckLFS(gomock.Any(), "proj/model", commit, oid, int64(len("verified LFS snapshot"))).Return(decision, err)
			w := httptest.NewRecorder()
			lfs.NewHandler(lfs.WithStorage(s), lfs.WithSecurityGate(gate)).ServeHTTP(w, batchRequest(oid, int64(len("verified LFS snapshot")), "main"))
			require.Equal(t, http.StatusOK, w.Code)
			require.Contains(t, w.Body.String(), `"error"`)
			require.NotContains(t, w.Body.String(), `"download"`)
		})
	}
}

func TestSecurityLFSContentRechecksBeforeAllMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, "range"} {
		for _, stale := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stale=%v", method, stale), func(t *testing.T) {
				s, commit, oid, content, decision := fixture(t)
				gate := securitymocks.NewMockGate(gomock.NewController(t))
				gate.EXPECT().Enabled().Return(true).AnyTimes()
				var reader *snapshotReader
				if stale {
					gate.EXPECT().CheckLFS(gomock.Any(), "proj/model", commit, oid, decision.Size).Return(security.Decision{}, &security.AdmissionError{Code: "RevisionPending", State: security.Pending, Message: "A rescan is pending"})
				} else {
					gate.EXPECT().CheckLFS(gomock.Any(), "proj/model", commit, oid, decision.Size).Return(decision, nil)
					reader = &snapshotReader{Reader: bytes.NewReader([]byte(content))}
					gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "weights.bin").Return(&security.ApprovedFile{Reader: reader, Decision: decision}, nil)
				}
				verb := method
				if method == "range" {
					verb = http.MethodGet
				}
				req := httptest.NewRequest(verb, fmt.Sprintf("/proj/model.git/info/lfs/objects/%s/%s?size=%d", commit, oid, decision.Size), nil)
				if method == "range" {
					req.Header.Set("Range", "bytes=0-7")
				}
				w := httptest.NewRecorder()
				lfs.NewHandler(lfs.WithStorage(s), lfs.WithSecurityGate(gate)).ServeHTTP(w, req)
				if stale {
					require.Equal(t, http.StatusForbidden, w.Code)
					require.Equal(t, "RevisionPending", w.Header().Get("X-Error-Code"))
					require.NotContains(t, w.Body.String(), content)
					return
				}
				code, body := http.StatusOK, content
				if method == http.MethodHead {
					body = ""
				}
				if method == "range" {
					code, body = http.StatusPartialContent, "verified"
				}
				require.Equal(t, code, w.Code)
				require.Equal(t, body, w.Body.String())
				require.Equal(t, commit, w.Header().Get("X-Repo-Commit"))
				require.Equal(t, `"`+oid+`"`, w.Header().Get("ETag"))
				require.True(t, reader.closed)
				require.Empty(t, w.Header().Get("Location"))
			})
		}
	}
}

func TestSecurityLFSGlobalObjectAndUnboundSizeDenied(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		gate := securitymocks.NewMockGate(gomock.NewController(t))
		gate.EXPECT().Enabled().Return(true)
		w := httptest.NewRecorder()
		lfs.NewHandler(lfs.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(method, "/objects/"+strings.Repeat("a", 64), nil))
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Equal(t, "lfs_context_required", w.Header().Get("X-Error-Code"))
		require.Empty(t, w.Header().Get("Location"))
	}
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true)
	w := httptest.NewRecorder()
	lfs.NewHandler(lfs.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/proj/model.git/info/lfs/objects/"+strings.Repeat("b", 40)+"/"+strings.Repeat("a", 64), nil))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, "invalid_lfs_size", w.Header().Get("X-Error-Code"))
}

func TestSecurityLFSRejectsSnapshotDifferentFromAction(t *testing.T) {
	s, commit, oid, content, decision := fixture(t)
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true)
	gate.EXPECT().CheckLFS(gomock.Any(), "proj/model", commit, oid, decision.Size).Return(decision, nil)
	reader := &snapshotReader{Reader: bytes.NewReader([]byte(content))}
	wrong := decision
	wrong.Digest = strings.Repeat("a", 64)
	gate.EXPECT().OpenApproved(gomock.Any(), "proj/model", commit, "weights.bin").Return(&security.ApprovedFile{Reader: reader, Decision: wrong}, nil)
	w := httptest.NewRecorder()
	lfs.NewHandler(lfs.WithStorage(s), lfs.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/proj/model.git/info/lfs/objects/%s/%s?size=%d", commit, oid, decision.Size), nil))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.NotContains(t, w.Body.String(), content)
	require.True(t, reader.closed)
}

func TestSecurityLFSMalformedBatchDoesNotReachGate(t *testing.T) {
	for _, body := range []string{"{", `{"operation":"download","objects":[null]}`, `{"operation":"unknown","objects":[]}`} {
		gate := securitymocks.NewMockGate(gomock.NewController(t))
		req := httptest.NewRequest(http.MethodPost, "/proj/model.git/info/lfs/objects/batch", strings.NewReader(body))
		req.Header.Set("Accept", "application/vnd.git-lfs+json")
		w := httptest.NewRecorder()
		lfs.NewHandler(lfs.WithSecurityGate(gate)).ServeHTTP(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}

func TestSecurityLFSUploadAndDisabledLegacyDownload(t *testing.T) {
	content := "new uploaded object"
	digest := sha256.Sum256([]byte(content))
	oid := hex.EncodeToString(digest[:])
	store := lfsstore.NewLocal(t.TempDir())
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(false).AnyTimes()
	h := lfs.NewHandler(lfs.WithLFSStorage(store), lfs.WithSecurityGate(gate))
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/objects/"+oid, strings.NewReader(content)))
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/objects/"+oid, nil))
	require.Equal(t, http.StatusOK, get.Code)
	require.Equal(t, content, get.Body.String())
}
