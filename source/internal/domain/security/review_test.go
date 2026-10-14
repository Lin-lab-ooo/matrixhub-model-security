// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type reviewMemory struct {
	items []security.Review
	err   error
}

func (m *reviewMemory) AppendReview(_ context.Context, r *security.Review, _ string) error {
	if m.err != nil {
		return m.err
	}
	r.ID = int64(len(m.items) + 1)
	m.items = append(m.items, *r)
	return nil
}
func (m *reviewMemory) Reviews(_ context.Context, _, _ string, _, _ int) ([]security.Review, error) {
	return m.items, m.err
}

func reviewFixture(t *testing.T, operation func(context.Context, string, string) error) (*fixture, *reviewMemory, security.ReviewInput) {
	t.Helper()
	f := newFixture(t, security.Settings{})
	gen := strings.Repeat("c", 64)
	f.bundle.Generation = gen
	f.report.Generation = gen
	for i := range f.report.Files {
		f.report.Files[i].Generation = gen
	}
	f.store.EXPECT().Historical(gomock.Any(), scope, "1-1").DoAndReturn(func(context.Context, string, string) (*security.Report, error) { return f.report, nil }).AnyTimes()
	reviews := &reviewMemory{}
	if operation == nil {
		operation = func(context.Context, string, string) error { return nil }
	}
	f.svc = security.NewService(f.store, f.artifacts, f.scanner, security.Settings{Enabled: true}, operation, nil,
		security.WithReviews(reviews, func(context.Context) (int64, string) { return 42, "user:reviewer" }))
	return f, reviews, security.ReviewInput{Revision: revision, Generation: gen, Verdict: "needs_followup", Comment: "请检查模型来源"}
}

func TestSecurityReviewOpinionsNeverChangeAdmission(t *testing.T) {
	for _, state := range []security.State{security.Pass, security.Block, security.Fail} {
		for _, verdict := range []string{"confirmed_risk", "false_positive", "needs_followup"} {
			t.Run(string(state)+"/"+verdict, func(t *testing.T) {
				f, memory, input := reviewFixture(t, nil)
				f.report.State = state
				if state == security.Block {
					f.report.Files[0].Findings = []security.Finding{{Engine: "picklescan", Severity: "high", Rule: "test.reference"}}
				}
				if state == security.Fail {
					f.report.Complete = false
					f.report.Files[0].Complete = false
				}
				original, err := json.Marshal(f.report)
				require.NoError(t, err)
				before, beforeErr := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
				input.Verdict = verdict
				review, err := f.svc.AddReview(t.Context(), scope, "1-1", input)
				require.NoError(t, err)
				require.Equal(t, int64(42), review.ActorID)
				require.Equal(t, "user:reviewer", review.Actor)
				require.False(t, review.CreatedAt.IsZero())
				require.Equal(t, input.Generation, review.Generation)
				require.Len(t, memory.items, 1)
				after, afterErr := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
				require.Equal(t, before, after)
				if beforeErr == nil {
					require.NoError(t, afterErr)
				} else {
					require.Equal(t, admissionCode(t, beforeErr), admissionCode(t, afterErr))
				}
				current, err := json.Marshal(f.report)
				require.NoError(t, err)
				require.Equal(t, original, current)
			})
		}
	}
}

func TestSecurityReviewRoleAndIdentityBoundaries(t *testing.T) {
	for _, role := range []string{"viewer", "editor", "admin"} {
		t.Run(role, func(t *testing.T) {
			f, memory, input := reviewFixture(t, func(_ context.Context, repo, op string) error {
				if repo != scope || (op == "write" && role == "viewer") {
					return &security.AdmissionError{Code: "PermissionDenied"}
				}
				return nil
			})
			_, err := f.svc.AddReview(t.Context(), scope, "1-1", input)
			if role == "viewer" {
				require.Equal(t, "PermissionDenied", admissionCode(t, err))
				require.Empty(t, memory.items)
			} else {
				require.NoError(t, err)
			}
			_, err = f.svc.Reviews(t.Context(), scope, "1-1", 50, 0)
			require.NoError(t, err)
			_, err = f.svc.Reviews(t.Context(), "other/model", "1-1", 50, 0)
			require.Equal(t, "PermissionDenied", admissionCode(t, err))
		})
	}
	t.Run("stale-report-bindings", func(t *testing.T) {
		f, memory, input := reviewFixture(t, nil)
		input.Generation = strings.Repeat("d", 64)
		_, err := f.svc.AddReview(t.Context(), scope, "1-1", input)
		require.Equal(t, "ReviewBindingMismatch", admissionCode(t, err))
		require.Empty(t, memory.items)
		input.Generation = f.report.Generation
		input.Revision = strings.Repeat("2", 40)
		_, err = f.svc.AddReview(t.Context(), scope, "1-1", input)
		require.Equal(t, "ReviewBindingMismatch", admissionCode(t, err))
	})
	t.Run("pending-and-wrong-scope", func(t *testing.T) {
		f, memory, input := reviewFixture(t, nil)
		f.report.State = security.Pending
		_, err := f.svc.AddReview(t.Context(), scope, "1-1", input)
		require.Equal(t, "ReviewNotReady", admissionCode(t, err))
		f.report.State = security.Pass
		f.report.Repo = "other/model"
		_, err = f.svc.AddReview(t.Context(), scope, "1-1", input)
		require.Equal(t, "ReportNotFound", admissionCode(t, err))
		require.Empty(t, memory.items)
	})
	t.Run("storage-failure-propagates", func(t *testing.T) {
		f, memory, input := reviewFixture(t, nil)
		memory.err = errors.New("unavailable")
		r, err := f.svc.AddReview(t.Context(), scope, "1-1", input)
		require.ErrorIs(t, err, memory.err)
		require.Nil(t, r)
		require.Empty(t, memory.items)
	})
}

func TestSecurityReviewBoundedUnicodeInput(t *testing.T) {
	for _, tc := range []struct {
		name, verdict, comment string
		valid                  bool
	}{
		{"normal", "needs_followup", "待确认", true}, {"limit", "false_positive", strings.Repeat("模", 1000), true},
		{"too-long", "confirmed_risk", strings.Repeat("模", 1001), false}, {"emoji-limit", "needs_followup", strings.Repeat("🔍", 1000), true},
		{"empty", "needs_followup", "  \n", false}, {"unknown", "approved", "note", false},
		{"nul", "needs_followup", "note\x00", false}, {"invalid-utf8", "needs_followup", string([]byte{0xff}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := security.ValidateReviewInput(security.ReviewInput{Revision: revision, Generation: strings.Repeat("a", 64), Verdict: tc.verdict, Comment: tc.comment})
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
