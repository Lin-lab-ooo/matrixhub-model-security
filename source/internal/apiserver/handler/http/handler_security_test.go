// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package backend_test

import (
	"context"
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

	backend "github.com/matrixhub-ai/matrixhub/internal/apiserver/handler/http"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	securitymocks "github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

func TestSecurityRawGitDeniedBeforeService(t *testing.T) {
	for _, path := range []string{
		"/proj/model.git/info/refs?service=git-upload-pack",
		"/proj/model/info/refs?service=git-upload-pack",
		"/proj/model.git/git-upload-pack", "/proj/model/git-upload-pack",
	} {
		t.Run(path, func(t *testing.T) {
			for _, unavailable := range []bool{false, true} {
				gate := securitymocks.NewMockGate(gomock.NewController(t))
				gate.EXPECT().Enabled().Return(true)
				var denial error = &security.AdmissionError{Code: "RawGitDisabled", Message: "Use approved file downloads", State: security.Block}
				code := http.StatusForbidden
				if unavailable {
					denial = errors.New("private database connection failed")
					code = http.StatusServiceUnavailable
				}
				gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(denial)
				method := http.MethodPost
				if path == "/proj/model.git/info/refs?service=git-upload-pack" || path == "/proj/model/info/refs?service=git-upload-pack" {
					method = http.MethodGet
				}
				w := httptest.NewRecorder()
				// No storage is configured: any attempt to reach Git would fail this test.
				backend.NewHandler(backend.WithSecurityGate(gate)).ServeHTTP(w, httptest.NewRequest(method, path, nil))
				require.Equal(t, code, w.Code)
				require.NotEmpty(t, w.Header().Get("X-Error-Code"))
				require.NotContains(t, w.Body.String(), "private database connection")
				var response security.AdmissionError
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				require.Equal(t, w.Header().Get("X-Error-Code"), response.Code)
				require.Equal(t, w.Header().Get("X-Error-Message"), response.Message)
				require.NotEmpty(t, response.State)
			}
		})
	}
}

func TestSecurityRawGitUnprotectedUsesExistingAuthorization(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "audit"}[enabled], func(t *testing.T) {
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(enabled)
			if enabled {
				gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
			}
			w := httptest.NewRecorder()
			h := backend.NewHandler(
				backend.WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))),
				backend.WithSecurityGate(gate),
				backend.WithPermissionHookFunc(func(context.Context, permission.Operation, string, permission.Context) (bool, error) {
					return false, nil
				}),
			)
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/proj/model/git-upload-pack", nil))
			require.Equal(t, http.StatusForbidden, w.Code)
			require.Empty(t, w.Header().Get("X-Error-Code"))
			require.Contains(t, w.Body.String(), "permission denied")
		})
	}
}

func TestSecurityRawGitAdmissionAllowsExistingReads(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, discovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%v/discovery=%v", enabled, discovery), func(t *testing.T) {
				s := storage.NewStorage(storage.WithRootDir(t.TempDir()))
				repo, err := repository.Init(t.Context(), s.ResolvePath("proj/model"), "main")
				require.NoError(t, err)
				commit, err := repo.CreateCommit(t.Context(), "main", "test", "Test", "test@example.invalid", []repository.CommitOperation{{
					Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("raw source content"),
				}}, "")
				require.NoError(t, err)
				gate := securitymocks.NewMockGate(gomock.NewController(t))
				gate.EXPECT().Enabled().Return(enabled)
				if enabled {
					gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
				}
				permissionCalls := 0
				h := backend.NewHandler(backend.WithStorage(s), backend.WithSecurityGate(gate),
					backend.WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
						permissionCalls++
						require.Equal(t, permission.OperationReadRepo, operation)
						require.Equal(t, "proj/model", name)
						return true, nil
					}))
				method, path := http.MethodPost, "/proj/model.git/git-upload-pack"
				body := fmt.Sprintf("0032want %s\n00000009done\n", commit)
				if discovery {
					method, path, body = http.MethodGet, "/proj/model.git/info/refs?service=git-upload-pack", ""
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				require.Equal(t, 1, permissionCalls)
				require.Empty(t, w.Header().Get("X-Error-Code"))
				if discovery {
					require.Equal(t, "application/x-git-upload-pack-advertisement", w.Header().Get("Content-Type"))
					require.Contains(t, w.Body.String(), commit+" refs/heads/main")
				} else {
					require.Equal(t, "application/x-git-upload-pack-result", w.Header().Get("Content-Type"))
					require.Contains(t, w.Body.String(), "PACK")
				}
			})
		}
	}
}

func TestSecurityRawGitReceivePackKeepsExistingAuthorization(t *testing.T) {
	for _, path := range []string{
		"/proj/model.git/info/refs?service=git-receive-pack",
		"/proj/model.git/git-receive-pack",
	} {
		t.Run(path, func(t *testing.T) {
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			permissionCalls := 0
			h := backend.NewHandler(
				backend.WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))),
				backend.WithSecurityGate(gate),
				backend.WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
					permissionCalls++
					require.Equal(t, permission.OperationUpdateRepo, operation)
					require.Equal(t, "proj/model", name)
					return false, nil
				}),
			)
			method := http.MethodPost
			if strings.Contains(path, "info/refs") {
				method = http.MethodGet
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			require.Equal(t, http.StatusForbidden, w.Code)
			require.Equal(t, 1, permissionCalls)
			require.Contains(t, w.Body.String(), "permission denied")
			require.Empty(t, w.Header().Get("X-Error-Code"))
		})
	}
}
