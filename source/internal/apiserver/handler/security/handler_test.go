// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/apiserver/handler/security/mocks"
	"github.com/matrixhub-ai/matrixhub/internal/domain/auth"
	domainsecurity "github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

const testCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type testIdentity struct{}

func (testIdentity) GetID() int       { return 1 }
func (testIdentity) GetName() string  { return "test-user" }
func (testIdentity) TypeName() string { return "user" }

func mockService(t *testing.T) *mocks.MockSecurityService {
	t.Helper()
	svc := mocks.NewMockSecurityService(gomock.NewController(t))
	svc.EXPECT().Enabled().Return(true).AnyTimes()
	return svc
}

func call(t *testing.T, svc SecurityService, method, suffix, body string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/api/security/v1alpha1/models/project/model/"+suffix, strings.NewReader(body))
	if authenticated {
		r = r.WithContext(auth.WithIdentity(r.Context(), testIdentity{}))
	}
	w := httptest.NewRecorder()
	newHandler(svc).ServeHTTP(w, r)
	return w
}

func TestMissingIdentityNeverReachesService(t *testing.T) {
	svc := mocks.NewMockSecurityService(gomock.NewController(t))
	w := call(t, svc, http.MethodGet, "report", "", false)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"code":"Unauthenticated","message":"Authentication is required"}`, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestReportBindsMutableRevisionToResolvedCommit(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().Resolve(gomock.Any(), "project/model", "release").Return(testCommit, nil)
	svc.EXPECT().Report(gomock.Any(), "project/model", testCommit).DoAndReturn(func(ctx context.Context, repo, commit string) (*domainsecurity.Report, error) {
		_, ok := auth.IdentityFromContext(ctx)
		require.True(t, ok)
		return &domainsecurity.Report{Repo: repo, Revision: commit, State: domainsecurity.Pending, Files: []domainsecurity.FileReport{}}, nil
	})
	w := call(t, svc, http.MethodGet, "report?revision=release", "", true)
	require.Equal(t, http.StatusOK, w.Code)
	var report domainsecurity.Report
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &report))
	require.Equal(t, testCommit, report.Revision)
	require.Equal(t, domainsecurity.Pending, report.State)
	require.False(t, report.Complete)
}

func TestRescanCannotBypassServiceAuthorization(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().Resolve(gomock.Any(), "project/model", "main").Return(testCommit, nil)
	svc.EXPECT().Enqueue(gomock.Any(), "project/model", testCommit, "manual", true).Return(nil,
		&domainsecurity.AdmissionError{Code: "PermissionDenied", Message: "Write permission required"})
	w := call(t, svc, http.MethodPost, "rescan", `{"revision":"main"}`, true)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.JSONEq(t, `{"code":"PermissionDenied","message":"Write permission required"}`, w.Body.String())
}

func TestUnsafeJSONDoesNotTriggerRescan(t *testing.T) {
	cases := map[string]string{
		"caller-force-override": `{"revision":"main","force":false}`,
		"multiple-objects":      `{"revision":"main"} {"revision":"other"}`,
		"oversized":             `{"revision":"` + strings.Repeat("x", 17<<10) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := call(t, mockService(t), http.MethodPost, "rescan", body, true)
			require.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestPaginationRejectsUnboundedQueries(t *testing.T) {
	for _, query := range []string{"limit=0", "limit=201", "limit=-1", "offset=1000001", "offset=invalid"} {
		t.Run(query, func(t *testing.T) {
			w := call(t, mockService(t), http.MethodGet, "tasks?"+query, "", true)
			require.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
	svc := mockService(t)
	svc.EXPECT().Tasks(gomock.Any(), "project/model", 50, 0).Return(nil, nil)
	w := call(t, svc, http.MethodGet, "tasks", "", true)
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"items":[],"count":0,"limit":50,"offset":0,"hasMore":false}`, w.Body.String())
}

func TestCancelDoesNotClaimAnotherRepositoryTaskWasCanceled(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().Cancel(gomock.Any(), "project/model", int64(2)).Return(false, nil)
	w := call(t, svc, http.MethodPost, "tasks/2/cancel", "", true)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "TaskNotFound")
}

func TestInternalErrorsAreNotExposedInResponse(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().GetPolicy(gomock.Any(), "project/model").Return(nil, errors.New("database credential=private-secret"))
	w := call(t, svc, http.MethodGet, "policy", "", true)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.JSONEq(t, `{"code":"InternalError","message":"Security request failed"}`, w.Body.String())
	require.NotContains(t, w.Body.String(), "private-secret")
}

func TestDisabledSecurityReturnsStableUnavailableResponse(t *testing.T) {
	svc := mocks.NewMockSecurityService(gomock.NewController(t))
	svc.EXPECT().Enabled().Return(false)
	w := call(t, svc, http.MethodGet, "report", "", true)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.JSONEq(t, `{"code":"SecurityUnavailable","message":"Artifact security scanning is unavailable"}`, w.Body.String())
}

func TestPolicyInputCannotOverrideRepositoryOrVersion(t *testing.T) {
	for _, body := range []string{
		`{"mode":"audit","blockSeverity":"high","repo":"another/model"}`,
		`{"mode":"audit","blockSeverity":"high","version":99}`,
		`{"mode":"allow","blockSeverity":"high"}`,
	} {
		w := call(t, mockService(t), http.MethodPut, "policy", body, true)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	svc := mockService(t)
	svc.EXPECT().UpdatePolicy(gomock.Any(), "project/model", domainsecurity.Policy{Mode: "audit", BlockSeverity: "high"}).Return(
		&domainsecurity.Policy{Repo: "project/model", Mode: "audit", BlockSeverity: "high", Version: 2}, nil)
	w := call(t, svc, http.MethodPut, "policy", `{"mode":"audit","blockSeverity":"high"}`, true)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHistoricalReportUsesImmutableIdentityAndRequestedRepository(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().History(gomock.Any(), "project/model", "12-2").Return(
		&domainsecurity.Report{ReportID: "12-2", Repo: "project/model", Revision: testCommit}, nil)
	w := call(t, svc, http.MethodGet, "history/12-2", "", true)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"reportId":"12-2"`)
	w = call(t, mockService(t), http.MethodGet, "history/12-latest", "", true)
	require.Equal(t, http.StatusBadRequest, w.Code)
}
