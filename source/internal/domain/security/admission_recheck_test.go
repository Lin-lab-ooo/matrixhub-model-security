// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type admissionReader struct {
	*strings.Reader
	closed bool
}

func (r *admissionReader) Close() error { r.closed = true; return nil }

// The callback models a policy/report update while the adapter performs the
// complete snapshot hash. It requires no sleeps and never serves model code.
func TestSecurityOpenApprovedRechecksAfterSnapshotVerification(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fixture)
		code   string
	}{
		{"policy-version", func(f *fixture) { f.policy.Version++ }, "ApprovalChanged"},
		{"policy-now-blocks", func(f *fixture) {
			f.policy.Version++
			f.policy.BlockSeverity = "medium"
			f.report.Files[0].Findings = []security.Finding{{Engine: "picklescan", Severity: "medium"}}
			f.report.State = security.Warn
		}, "RevisionBlocked"},
		{"rescan-pending", func(f *fixture) { f.report.Complete = false; f.report.State = security.Pending }, "RevisionPending"},
		{"scanner-generation", func(f *fixture) { f.bundle.Generation = "rules-v2" }, "RevisionPending"},
		{"new-generation-ready", func(f *fixture) {
			f.bundle.Generation = "rules-v2"
			f.report.Generation = "rules-v2"
			f.report.Files[0].Generation = "rules-v2"
		}, "ApprovalChanged"},
		{"scanner-unavailable", func(f *fixture) { f.bundleErr = errors.New("offline") }, "RevisionFailed"},
		{"new-report", func(f *fixture) { f.report.ReportID = "1-2"; f.report.Attempt = 2 }, "ApprovalChanged"},
		{"new-task", func(f *fixture) { f.report.TaskID = 2 }, "ApprovalChanged"},
		{"new-snapshot", func(f *fixture) { f.report.Files[0].ID = "snapshot/new.blob" }, "ApprovalChanged"},
		{"new-digest", func(f *fixture) { f.report.Files[0].Digest = strings.Repeat("b", 64) }, "ApprovalChanged"},
		{"new-size", func(f *fixture) { f.report.Files[0].SourceFile.Size = 4; f.report.Files[0].Artifact.Size = 4 }, "ApprovalChanged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, security.Settings{})
			r := &admissionReader{Reader: strings.NewReader("abc")}
			t.Cleanup(func() { _ = r.Close() })
			f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, security.Artifact) (io.ReadSeekCloser, error) {
				tc.mutate(f)
				return r, nil
			})
			approved, err := f.svc.OpenApproved(t.Context(), scope, revision, "weights.pkl")
			require.Equal(t, tc.code, admissionCode(t, err))
			require.Nil(t, approved)
			require.True(t, r.closed)
			for _, audit := range f.audits {
				require.NotEqual(t, "download-open", audit.Action)
			}
		})
	}
}

func TestSecurityOpenApprovedStableEvidenceReturnsVerifiedReader(t *testing.T) {
	f := newFixture(t, security.Settings{})
	r := &admissionReader{Reader: strings.NewReader("abc")}
	f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).Return(r, nil)
	approved, err := f.svc.OpenApproved(t.Context(), scope, revision, "weights.pkl")
	require.NoError(t, err)
	require.Same(t, r, approved.Reader)
	require.False(t, r.closed)
	require.Equal(t, "download-open", f.audits[len(f.audits)-1].Action)
	require.NoError(t, approved.Close())
}

func TestSecurityOpenApprovedCancellationAfterVerificationClosesReader(t *testing.T) {
	f := newFixture(t, security.Settings{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := &admissionReader{Reader: strings.NewReader("abc")}
	t.Cleanup(func() { _ = r.Close() })
	f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, security.Artifact) (io.ReadSeekCloser, error) {
		cancel()
		return r, nil
	})
	approved, err := f.svc.OpenApproved(ctx, scope, revision, "weights.pkl")
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, approved)
	require.True(t, r.closed)
}

func TestSecurityOpenApprovedPermissionRevocationClosesReader(t *testing.T) {
	f := newFixture(t, security.Settings{})
	revoked := false
	f.svc = security.NewService(f.store, f.artifacts, f.scanner, security.Settings{Enabled: true}, func(context.Context, string, string) error {
		if revoked {
			return &security.AdmissionError{Code: "PermissionDenied", Message: "revoked"}
		}
		return nil
	}, nil)
	r := &admissionReader{Reader: strings.NewReader("abc")}
	t.Cleanup(func() { _ = r.Close() })
	f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, security.Artifact) (io.ReadSeekCloser, error) {
		revoked = true
		return r, nil
	})
	approved, err := f.svc.OpenApproved(t.Context(), scope, revision, "weights.pkl")
	require.Equal(t, "PermissionDenied", admissionCode(t, err))
	require.Nil(t, approved)
	require.True(t, r.closed)
}

type rejectingDownloadAuditStore struct {
	security.Store
	action string
	err    error
	nth    int
	count  int
	before func()
}

func (s *rejectingDownloadAuditStore) AppendAudit(ctx context.Context, audit *security.Audit) error {
	if audit.Action == s.action {
		s.count++
		if s.nth <= 1 || s.count == s.nth {
			if s.before != nil {
				s.before()
			}
			if s.err != nil {
				return s.err
			}
		}
	}
	return s.Store.AppendAudit(ctx, audit)
}

func TestSecurityOpenApprovedAuditFailureClosesReader(t *testing.T) {
	for _, action := range []string{"admission", "download-open", "download-revalidate"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, security.Settings{})
			failure := errors.New("audit persistence unavailable")
			store := &rejectingDownloadAuditStore{Store: f.store, action: action, err: failure}
			if action == "admission" {
				store.nth = 2 // The first admission succeeds and the reader is opened.
			}
			f.svc = security.NewService(store, f.artifacts, f.scanner, security.Settings{Enabled: true}, func(context.Context, string, string) error { return nil }, nil)
			r := &admissionReader{Reader: strings.NewReader("abc")}
			t.Cleanup(func() { _ = r.Close() })
			f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, security.Artifact) (io.ReadSeekCloser, error) {
				if action == "download-revalidate" {
					f.policy.Version++
				}
				return r, nil
			})
			approved, err := f.svc.OpenApproved(t.Context(), scope, revision, "weights.pkl")
			require.ErrorIs(t, err, failure)
			require.Nil(t, approved)
			require.True(t, r.closed)
		})
	}
}

func TestSecurityOpenApprovedCancellationDuringAuditClosesReader(t *testing.T) {
	for _, action := range []string{"admission", "download-open"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, security.Settings{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &rejectingDownloadAuditStore{Store: f.store, action: action, before: cancel}
			if action == "admission" {
				store.nth = 2
			}
			f.svc = security.NewService(store, f.artifacts, f.scanner, security.Settings{Enabled: true}, func(context.Context, string, string) error { return nil }, nil)
			r := &admissionReader{Reader: strings.NewReader("abc")}
			t.Cleanup(func() { _ = r.Close() })
			f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).Return(r, nil)
			approved, err := f.svc.OpenApproved(ctx, scope, revision, "weights.pkl")
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, approved)
			require.True(t, r.closed)
		})
	}
}
