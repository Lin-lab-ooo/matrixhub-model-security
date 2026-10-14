// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	domainsecurity "github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func reviewBody(t *testing.T) (domainsecurity.ReviewInput, string) {
	t.Helper()
	in := domainsecurity.ReviewInput{Revision: testCommit, Generation: strings.Repeat("b", 64), Verdict: "false_positive", Comment: "请核查，<script>inert text</script>"}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	return in, string(b)
}

func TestReviewTransportUsesServerIdentityAndImmutablePath(t *testing.T) {
	svc := mockService(t)
	in, body := reviewBody(t)
	svc.EXPECT().AddReview(gomock.Any(), "project/model", "12-2", in).Return(&domainsecurity.Review{ID: 7, Repo: "project/model", ReportID: "12-2", Revision: in.Revision, Generation: in.Generation, ActorID: 42, Actor: "user:reviewer", Verdict: in.Verdict, Comment: in.Comment, CreatedAt: time.Unix(100, 0)}, nil)
	w := call(t, svc, http.MethodPost, "history/12-2/reviews", body, true)
	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var review domainsecurity.Review
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &review))
	require.Equal(t, int64(42), review.ActorID)
	require.Equal(t, in.Comment, review.Comment)
}

func TestReviewTransportRejectsForgedAndUnboundedInput(t *testing.T) {
	_, body := reviewBody(t)
	for name, raw := range map[string]string{
		"actor":      strings.TrimSuffix(body, "}") + `,"actor":"user:admin"}`,
		"actor-id":   strings.TrimSuffix(body, "}") + `,"actorId":1}`,
		"created-at": strings.TrimSuffix(body, "}") + `,"createdAt":"2026-01-01T00:00:00Z"}`,
		"override":   strings.TrimSuffix(body, "}") + `,"allowed":true}`,
		"multiple":   body + body,
		"too-big":    `{"comment":"` + strings.Repeat("x", 17<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := call(t, mockService(t), http.MethodPost, "history/12-2/reviews", raw, true)
			require.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
	for _, id := range []string{"main", "0-1", "1-0", strings.Repeat("1", 65) + "-1"} {
		w := call(t, mockService(t), http.MethodPost, "history/"+id+"/reviews", body, true)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}

func TestReviewTransportPreservesDenialsAndAppendOnlyContract(t *testing.T) {
	in, body := reviewBody(t)
	for code, want := range map[string]int{"PermissionDenied": 403, "Unauthenticated": 401, "ReportNotFound": 404, "ReviewBindingMismatch": 409, "ReviewNotReady": 409} {
		t.Run(code, func(t *testing.T) {
			svc := mockService(t)
			svc.EXPECT().AddReview(gomock.Any(), "project/model", "12-2", in).Return(nil, &domainsecurity.AdmissionError{Code: code, Message: "denied"})
			w := call(t, svc, http.MethodPost, "history/12-2/reviews", body, true)
			require.Equal(t, want, w.Code)
		})
	}
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		w := call(t, mockService(t), method, "history/12-2/reviews", body, true)
		require.Contains(t, []int{404, 405}, w.Code)
	}
}

func TestReviewTransportScopesAndBoundsList(t *testing.T) {
	svc := mockService(t)
	svc.EXPECT().Reviews(gomock.Any(), "project/model", "12-2", 1, 2).Return([]domainsecurity.Review{{ID: 7}}, nil)
	w := call(t, svc, http.MethodGet, "history/12-2/reviews?limit=1&offset=2", "", true)
	require.Equal(t, 200, w.Code)
	var result listResponse[domainsecurity.Review]
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, 1, result.Count)
	require.Equal(t, 2, result.Offset)
	require.True(t, result.HasMore)
	for _, query := range []string{"limit=201", "offset=1000001"} {
		w = call(t, mockService(t), http.MethodGet, "history/12-2/reviews?"+query, "", true)
		require.Equal(t, 400, w.Code)
	}
}
