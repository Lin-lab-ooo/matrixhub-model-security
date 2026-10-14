// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

const scope = "alpha/model"

var revision = strings.Repeat("1", 40)

type fixture struct {
	svc            *security.Service
	store          *mocks.MockStore
	artifacts      *mocks.MockArtifacts
	scanner        *mocks.MockScanner
	report         *security.Report
	policy         *security.Policy
	bundle         security.Bundle
	bundleErr      error
	rawStoreReport bool
	audits         []security.Audit
}

func newFixture(t *testing.T, cfg security.Settings) *fixture {
	ctrl := gomock.NewController(t)
	f := &fixture{store: mocks.NewMockStore(ctrl), artifacts: mocks.NewMockArtifacts(ctrl), scanner: mocks.NewMockScanner(ctrl)}
	f.bundle = security.Bundle{Generation: "rules-v1", Engines: map[string]string{"clamav": "1", "picklescan": "1"}, MaxFileBytes: 1024}
	f.report = completeReport()
	f.policy = &security.Policy{Repo: scope, Mode: "enforce", BlockSeverity: "high", Version: 1}
	f.scanner.EXPECT().Bundle(gomock.Any()).DoAndReturn(func(context.Context) (security.Bundle, error) { return f.bundle, f.bundleErr }).AnyTimes()
	f.store.EXPECT().Get(gomock.Any(), scope, revision, gomock.Any()).DoAndReturn(func(_ context.Context, _, _, generation string) (*security.Task, *security.Report, error) {
		if !f.rawStoreReport && f.report.Generation != "" && f.report.Generation != generation {
			return &security.Task{ID: 2, State: security.Pending, Generation: generation}, nil, nil
		}
		return &security.Task{ID: 1, Generation: generation, State: f.report.State}, f.report, nil
	}).AnyTimes()
	f.store.EXPECT().Policy(gomock.Any(), scope).DoAndReturn(func(context.Context, string) (*security.Policy, error) { return f.policy, nil }).AnyTimes()
	f.store.EXPECT().AppendAudit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, a *security.Audit) error { f.audits = append(f.audits, *a); return nil }).AnyTimes()
	cfg.Enabled = true
	f.svc = security.NewService(f.store, f.artifacts, f.scanner, cfg, func(context.Context, string, string) error { return nil }, nil)
	return f
}
func completeReport() *security.Report {
	return &security.Report{ReportID: "1-1", TaskID: 1, Attempt: 1, Repo: scope, Revision: revision, Generation: "rules-v1", State: security.Pass, Complete: true, ExpectedFiles: 1,
		Files: []security.FileReport{{SourceFile: security.SourceFile{Path: "weights.pkl", Size: 3}, Artifact: security.Artifact{ID: "snapshot/file.blob", Digest: strings.Repeat("a", 64), Size: 3, Type: "pickle"},
			Analysis: security.Analysis{Generation: "rules-v1", Complete: true, Engines: map[string]string{"clamav": "1", "picklescan": "1"}}}}}
}
func admissionCode(t *testing.T, err error) string {
	t.Helper()
	var ae *security.AdmissionError
	require.ErrorAs(t, err, &ae)
	return ae.Code
}
func TestSecurityOnlyCompleteCoverageCanBeDownloaded(t *testing.T) {
	for _, state := range []security.State{security.Pending, security.Scanning, security.Fail} {
		t.Run(string(state), func(t *testing.T) {
			f := newFixture(t, security.Settings{})
			f.report.State = state
			f.report.Complete = false
			d, err := f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
			require.Error(t, err)
			require.False(t, d.Allowed)
			require.Len(t, f.audits, 1)
		})
	}
}
func TestSecurityPolicyReevaluationUsesAllRevisionFiles(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.report.Files[0].Findings = []security.Finding{{Engine: "picklescan", Severity: "medium"}}
	f.report.State = security.Warn
	d, err := f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.NoError(t, err)
	require.True(t, d.Allowed)
	f.policy.BlockSeverity = "medium"
	f.policy.Version = 2
	d, err = f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionBlocked", admissionCode(t, err))
	require.Equal(t, int64(2), d.PolicyVersion)
	// Audit mode permits findings only after a complete, bound scan.
	f.policy.Mode = "audit"
	_, err = f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.NoError(t, err)
	f.report.Complete = false
	_, err = f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.Error(t, err)
}
func TestSecurityDifferentFileCannotBypassRevisionBlock(t *testing.T) {
	f := newFixture(t, security.Settings{})
	other := f.report.Files[0]
	other.Path = "config.json"
	other.Findings = []security.Finding{{Engine: "clamav", Severity: "critical"}}
	f.report.Files = append(f.report.Files, other)
	f.report.ExpectedFiles = 2
	f.report.State = security.Block
	_, err := f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionBlocked", admissionCode(t, err))
}
func TestSecurityScannerUnavailableInvalidatesPriorApproval(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.bundleErr = errors.New("offline")
	_, err := f.svc.OpenApproved(context.Background(), scope, revision, "weights.pkl")
	require.Equal(t, "RevisionFailed", admissionCode(t, err))
}
func TestSecurityRuleChangeRequiresNewScan(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.bundle.Generation = "rules-v2"
	_, err := f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionPending", admissionCode(t, err))
}
func TestSecurityStoredReportMustMatchCurrentBundle(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.rawStoreReport = true
	f.report.Generation = "rules-v0"
	f.report.Files[0].Generation = "rules-v0"
	d, err := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionFailed", admissionCode(t, err))
	require.False(t, d.Allowed)
}
func TestSecurityBundleRequiresBothNamedEngines(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.bundle.Engines = map[string]string{"other-a": "1", "other-b": "1"}
	d, err := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionFailed", admissionCode(t, err))
	require.False(t, d.Allowed)
}
func TestSecurityOfflineScannerPreservesQueuedWork(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.bundleErr = errors.New("temporary scanner outage")
	// No Store.Claim expectation: an offline scanner must not mutate the queue.
	task, err := f.svc.Claim(t.Context())
	require.Error(t, err)
	require.Nil(t, task)
	f.bundleErr = nil
	expected := &security.Task{Repo: scope, Revision: revision, Generation: f.bundle.Generation}
	f.store.EXPECT().Claim(gomock.Any(), f.bundle.Generation, gomock.Any(), gomock.Any(), gomock.Any()).Return(expected, nil)
	task, err = f.svc.Claim(t.Context())
	require.NoError(t, err)
	require.Same(t, expected, task)
}
func TestSecurityPolicyPublishesItsOwnVersionWithAtomicAudit(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.store.EXPECT().SetPolicy(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, policy *security.Policy, audit *security.Audit) error {
		require.Equal(t, scope, policy.Repo)
		require.Equal(t, "audit", policy.Mode)
		require.Equal(t, "low", policy.BlockSeverity)
		require.Equal(t, "system", audit.Actor)
		require.Equal(t, "rest-security", audit.Entry)
		require.Equal(t, "policy-update", audit.Action)
		require.Contains(t, audit.Decision.Message, "blockSeverity=low")
		policy.Version = 2
		return nil
	})
	policy, err := f.svc.UpdatePolicy(security.WithEntry(t.Context(), "rest-security"), scope, security.Policy{Mode: "audit", BlockSeverity: "low"})
	require.NoError(t, err)
	require.Equal(t, int64(2), policy.Version)
	// A separate reread would return f.policy.Version=1; this response must be
	// this mutation's committed version rather than a later caller's policy.
	require.Empty(t, f.audits)
}
func TestSecurityPolicyFailureDoesNotEmitSuccessAudit(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.store.EXPECT().SetPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("atomic audit write failed"))
	policy, err := f.svc.UpdatePolicy(t.Context(), scope, security.Policy{Mode: "audit", BlockSeverity: "low"})
	require.Error(t, err)
	require.Nil(t, policy)
	require.Empty(t, f.audits)
}
func TestSecurityCorruptManifestCannotApprove(t *testing.T) {
	cases := map[string]func(*security.Report){
		"omitted file":      func(r *security.Report) { r.ExpectedFiles = 2 },
		"unscanned sibling": func(r *security.Report) { r.Files[0].Complete = false },
		"cross generation":  func(r *security.Report) { r.Files[0].Generation = "rules-v0" },
		"duplicate path":    func(r *security.Report) { r.Files = append(r.Files, r.Files[0]); r.ExpectedFiles = 2 },
		"wrong digest":      func(r *security.Report) { r.Files[0].Digest = strings.Repeat("z", 64) },
		"lfs mismatch":      func(r *security.Report) { r.Files[0].LFSOID = strings.Repeat("b", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, security.Settings{})
			mutate(f.report)
			_, err := f.svc.Check(context.Background(), scope, revision, "weights.pkl", "", 0)
			require.Equal(t, "ManifestMismatch", admissionCode(t, err))
		})
	}
}
func TestSecuritySnapshotTamperDoesNotRecordOpenedDownload(t *testing.T) {
	f := newFixture(t, security.Settings{})
	f.artifacts.EXPECT().Open(gomock.Any(), gomock.Any()).Return(nil, errors.New("integrity mismatch"))
	_, err := f.svc.OpenApproved(context.Background(), scope, revision, "weights.pkl")
	require.Equal(t, "SnapshotIntegrityFailed", admissionCode(t, err))
	for _, audit := range f.audits {
		require.NotEqual(t, "download-open", audit.Action)
	}
	require.False(t, f.audits[len(f.audits)-1].Decision.Allowed)
}
func configureProcess(f *fixture, task *security.Task, analysis security.Analysis, cached *security.Analysis) {
	file := f.report.Files[0]
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).Return([]security.SourceFile{file.SourceFile}, nil)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(3)).Return(func() {}, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, file.SourceFile, int64(1024)).Return(file.Artifact, nil)
	if !task.Force {
		f.store.EXPECT().Cached(gomock.Any(), scope, file.Artifact, "rules-v1").Return(cached, nil)
	}
	if cached == nil || task.Force {
		f.scanner.EXPECT().Analyze(gomock.Any(), file.Artifact).Return(analysis, nil)
	}
}
func scanTask() *security.Task {
	return &security.Task{ID: 1, Attempt: 1, Repo: scope, Revision: revision, Generation: "rules-v1"}
}
func TestSecurityForceRescanDoesNotReuseCachedAnalysis(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	task.Force = true
	configureProcess(f, task, f.report.Files[0].Analysis, nil)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.True(t, r.Complete)
		require.Equal(t, 0, r.CachedFiles)
		return true, nil
	})
	require.NoError(t, f.svc.Process(context.Background(), task))
}
func TestSecurityCompleteAnalysisCacheSkipsEngineWork(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	a := f.report.Files[0].Analysis
	configureProcess(f, task, a, &a)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.True(t, r.Complete)
		require.Equal(t, 1, r.CachedFiles)
		return true, nil
	})
	require.NoError(t, f.svc.Process(context.Background(), task))
}
func TestSecurityIncompleteEngineResultPersistsFailure(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	a := f.report.Files[0].Analysis
	a.Complete = false
	configureProcess(f, task, a, nil)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.False(t, r.Complete)
		require.Equal(t, security.Fail, r.State)
		return true, nil
	})
	require.Error(t, f.svc.Process(context.Background(), task))
}
func TestSecurityDeadlineFailurePersistsWithLiveCleanupContext(t *testing.T) {
	f := newFixture(t, security.Settings{Timeout: 15 * time.Millisecond})
	task := scanTask()
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).DoAndReturn(func(ctx context.Context, _, _ string) ([]security.SourceFile, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(ctx context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.NoError(t, ctx.Err())
		require.False(t, r.Complete)
		require.Equal(t, security.Fail, r.State)
		return true, nil
	})
	require.ErrorIs(t, f.svc.Process(context.Background(), task), context.DeadlineExceeded)
}
func TestSecurityLateReportIsDiscarded(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	configureProcess(f, task, f.report.Files[0].Analysis, nil)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).Return(false, nil)
	require.ErrorContains(t, f.svc.Process(context.Background(), task), "late result discarded")
}
func TestSecurityCurrentPermissionsProtectEveryServiceOperation(t *testing.T) {
	svc := security.NewService(nil, nil, nil, security.Settings{Enabled: true}, func(_ context.Context, _ string, op string) error {
		return &security.AdmissionError{Code: "PermissionDenied", Message: op}
	}, nil)
	_, err := svc.OpenApproved(context.Background(), scope, revision, "weights.pkl")
	require.Equal(t, "PermissionDenied", admissionCode(t, err))
	_, err = svc.Enqueue(context.Background(), scope, revision, "manual", true)
	require.Equal(t, "PermissionDenied", admissionCode(t, err))
	_, err = svc.UpdatePolicy(context.Background(), scope, security.Policy{Mode: "audit", BlockSeverity: "low"})
	require.Equal(t, "PermissionDenied", admissionCode(t, err))
	_, err = svc.Cancel(context.Background(), scope, 1)
	require.Equal(t, "PermissionDenied", admissionCode(t, err))
}
