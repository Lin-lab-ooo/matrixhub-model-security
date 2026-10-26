// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type batchScannerMock struct {
	*mocks.MockScanner
	*mocks.MockBatchScanner
}

func setupBatch(t *testing.T, count, maxFiles int, maxBytes int64) (*fixture, *mocks.MockBatchScanner, *security.Task, security.Analysis) {
	t.Helper()
	f := newFixture(t, security.Settings{})
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	combined := batchScannerMock{f.scanner, batch}
	f.bundle.MaxBatchFiles = maxFiles
	f.bundle.MaxBatchBytes = maxBytes
	f.svc = security.NewService(f.store, f.artifacts, combined, security.Settings{Enabled: true}, func(context.Context, string, string) error { return nil }, nil)
	task := scanTask()
	template := f.report.Files[0]
	var sources []security.SourceFile
	for i := 0; i < count; i++ {
		source := template.SourceFile
		source.Path = fmt.Sprintf("file-%d.pkl", i)
		artifact := template.Artifact
		artifact.ID = fmt.Sprintf("snapshot/file-%d.blob", i)
		sources = append(sources, source)
		f.artifacts.EXPECT().Stage(gomock.Any(), task, source, int64(1024)).Return(artifact, nil)
		f.store.EXPECT().Cached(gomock.Any(), scope, artifact, "rules-v1").Return(nil, nil)
	}
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).Return(sources, nil)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(count*3)).Return(func() {}, nil)
	return f, batch, task, template.Analysis
}
func TestSecurityBatchRespectsAdvertisedFileAndByteCapacity(t *testing.T) {
	tests := []struct {
		name            string
		count, maxFiles int
		maxBytes        int64
		chunks          []int
	}{
		{"file count", 5, 2, 1024, []int{2, 2, 1}},
		{"bytes", 3, 32, 5, []int{1, 1, 1}},
		{"hard file count ceiling", 33, 100, 1024, []int{32, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, batch, task, analysis := setupBatch(t, tt.count, tt.maxFiles, tt.maxBytes)
			seen := 0
			for _, size := range tt.chunks {
				batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, artifacts []security.Artifact) ([]security.Analysis, error) {
					require.Len(t, artifacts, size)
					var results []security.Analysis
					for _, artifact := range artifacts {
						require.Equal(t, fmt.Sprintf("snapshot/file-%d.blob", seen), artifact.ID)
						seen++
						results = append(results, analysis)
					}
					return results, nil
				})
			}
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
				require.True(t, r.Complete)
				require.Len(t, r.Files, tt.count)
				require.Equal(t, tt.count, seen)
				return true, nil
			})
			require.NoError(t, f.svc.Process(context.Background(), task))
		})
	}
}
func TestSecurityLegacyScannerCapacityKeepsSingleFileProtocol(t *testing.T) {
	f, _, task, analysis := setupBatch(t, 2, 0, 0)
	f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).Return(analysis, nil).Times(2)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.True(t, r.Complete)
		return true, nil
	})
	require.NoError(t, f.svc.Process(context.Background(), task))
}

func TestSecurityBatchHonorsOperatorFileAndByteLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		files  int
		bytes  int64
		chunks []int
	}{
		{"files", 2, 1024, []int{2, 2, 1}},
		{"bytes", 32, 5, []int{1, 1, 1, 1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, batch, task, analysis := setupBatch(t, 5, 32, 1024)
			f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch},
				security.Settings{Enabled: true, BatchFiles: tc.files, BatchBytes: tc.bytes},
				func(context.Context, string, string) error { return nil }, nil)
			seen := 0
			for _, count := range tc.chunks {
				batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, artifacts []security.Artifact) ([]security.Analysis, error) {
					require.Len(t, artifacts, count)
					out := make([]security.Analysis, count)
					for i := range artifacts {
						require.Equal(t, fmt.Sprintf("snapshot/file-%d.blob", seen), artifacts[i].ID)
						seen++
						out[i] = analysis
					}
					return out, nil
				})
			}
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
				require.True(t, report.Complete)
				require.Equal(t, 5, seen)
				return true, nil
			})
			require.NoError(t, f.svc.Process(t.Context(), task))
		})
	}
}
func TestSecurityBatchCannotPublishIncompleteOrMisboundResults(t *testing.T) {
	cases := map[string]func(security.Analysis) []security.Analysis{
		"missing result": func(a security.Analysis) []security.Analysis { return []security.Analysis{a} },
		"incomplete sibling": func(a security.Analysis) []security.Analysis {
			b := a
			b.Complete = false
			return []security.Analysis{a, b}
		},
		"wrong generation": func(a security.Analysis) []security.Analysis {
			b := a
			b.Generation = "rules-v2"
			return []security.Analysis{a, b}
		},
		"wrong engines": func(a security.Analysis) []security.Analysis {
			b := a
			b.Engines = map[string]string{"clamav": "unexpected", "picklescan": "1"}
			return []security.Analysis{a, b}
		},
	}
	for name, results := range cases {
		t.Run(name, func(t *testing.T) {
			f, batch, task, analysis := setupBatch(t, 2, 32, 1024)
			batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).Return(results(analysis), nil)
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
				require.False(t, r.Complete)
				require.Equal(t, security.Fail, r.State)
				for _, file := range r.Files {
					require.Empty(t, file.Generation)
				}
				return true, nil
			})
			require.Error(t, f.svc.Process(context.Background(), task))
		})
	}
}
func TestSecurityArtifactOverBatchCapacityUsesBoundedSingleFileProtocol(t *testing.T) {
	f, _, task, analysis := setupBatch(t, 3, 32, 2)
	seen := 0
	f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, artifact security.Artifact) (security.Analysis, error) {
		require.Equal(t, fmt.Sprintf("snapshot/file-%d.blob", seen), artifact.ID)
		seen++
		return analysis, nil
	}).Times(3)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
		require.True(t, r.Complete)
		require.Equal(t, 3, seen)
		for _, file := range r.Files {
			require.Equal(t, "rules-v1", file.Generation)
		}
		return true, nil
	})
	require.NoError(t, f.svc.Process(context.Background(), task))
}

func TestSecurityArtifactOverBatchCapacityStillValidatesSingleFileBinding(t *testing.T) {
	for _, name := range []string{"wrong generation", "uncontrolled incomplete"} {
		t.Run(name, func(t *testing.T) {
			f, _, task, analysis := setupBatch(t, 1, 32, 2)
			if name == "wrong generation" {
				analysis.Generation = "rules-v2"
			} else {
				analysis.Complete = false
			}
			f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).Return(analysis, nil)
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, r *security.Report) (bool, error) {
				require.False(t, r.Complete)
				require.Equal(t, security.Fail, r.State)
				require.Empty(t, r.Files[0].Generation)
				return true, nil
			})
			require.Error(t, f.svc.Process(context.Background(), task))
		})

	}
}

func partialFileAnalysis(a security.Analysis) security.Analysis {
	a.Complete = false
	a.Findings = []security.Finding{
		{Engine: "picklescan", Rule: "pickle.unknown-global", Severity: "medium", Message: "Static reference"},
		{Engine: "coverage", Rule: "coverage.malformed_pickle", Severity: "high", Message: security.FileAnalysisFailureMessage, Remediation: security.FileAnalysisFailureRemediation},
	}
	return a
}

func TestSecurityMixedBatchAndLargePartialPreservesOrderAndContinues(t *testing.T) {
	f := newFixture(t, security.Settings{})
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 32, 4
	f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true}, func(context.Context, string, string) error { return nil }, nil)
	task := scanTask()
	template := f.report.Files[0]
	var sources []security.SourceFile
	var artifacts []security.Artifact
	for i, size := range []int64{1, 6, 1} {
		source, artifact := template.SourceFile, template.Artifact
		source.Path, source.Size = fmt.Sprintf("file-%d.pkl", i), size
		artifact.ID, artifact.Size = fmt.Sprintf("snapshot/file-%d.blob", i), size
		sources, artifacts = append(sources, source), append(artifacts, artifact)
		f.artifacts.EXPECT().Stage(gomock.Any(), task, source, int64(1024)).Return(artifact, nil)
		f.store.EXPECT().Cached(gomock.Any(), scope, artifact, "rules-v1").Return(nil, nil)
	}
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).Return(sources, nil)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(8)).Return(func() {}, nil)
	partial := partialFileAnalysis(template.Analysis)
	gomock.InOrder(
		batch.EXPECT().AnalyzeBatch(gomock.Any(), []security.Artifact{artifacts[0]}).Return([]security.Analysis{template.Analysis}, nil),
		f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[1]).Return(partial, nil),
		batch.EXPECT().AnalyzeBatch(gomock.Any(), []security.Artifact{artifacts[2]}).Return([]security.Analysis{template.Analysis}, nil),
	)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		require.Equal(t, security.Fail, report.State)
		require.False(t, report.Complete)
		require.Len(t, report.Files, 3)
		for i, file := range report.Files {
			require.Equal(t, artifacts[i], file.Artifact)
			require.Equal(t, "rules-v1", file.Generation)
			require.Equal(t, i != 1, file.Complete)
		}
		require.Equal(t, partial.Findings, report.Files[1].Findings)
		return true, nil
	})
	processErr := f.svc.Process(t.Context(), task)
	require.ErrorContains(t, processErr, "did not provide complete coverage")
	require.ErrorContains(t, processErr, "malformed_pickle")
}

func TestSecurityControlledFileFailurePreservesSiblingsAndLaterBatches(t *testing.T) {
	for _, capacity := range []int{0, 2} {
		t.Run(fmt.Sprintf("batch-capacity=%d", capacity), func(t *testing.T) {
			f, batch, task, analysis := setupBatch(t, 5, capacity, 1024)
			seen := 0
			result := func() security.Analysis {
				index := seen
				seen++
				if index == 0 {
					return partialFileAnalysis(analysis)
				}
				if index == 1 {
					copy := analysis
					copy.Findings = []security.Finding{{Engine: "clamav", Rule: "Eicar-Test-Signature", Severity: "critical"}}
					return copy
				}
				return analysis
			}
			if capacity == 0 {
				f.scanner.EXPECT().Analyze(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, artifact security.Artifact) (security.Analysis, error) {
					require.Equal(t, fmt.Sprintf("snapshot/file-%d.blob", seen), artifact.ID)
					return result(), nil
				}).Times(5)
			} else {
				batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, artifacts []security.Artifact) ([]security.Analysis, error) {
					var results []security.Analysis
					for _, artifact := range artifacts {
						require.Equal(t, fmt.Sprintf("snapshot/file-%d.blob", seen), artifact.ID)
						results = append(results, result())
					}
					return results, nil
				}).Times(3)
			}
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
				require.Equal(t, 5, seen)
				require.Len(t, report.Files, 5)
				require.Equal(t, security.Fail, report.State)
				require.False(t, report.Complete)
				require.False(t, report.Files[0].Complete)
				require.Len(t, report.Files[0].Findings, 2)
				for _, file := range report.Files[1:] {
					require.True(t, file.Complete)
				}
				require.Equal(t, "Eicar-Test-Signature", report.Files[1].Findings[0].Rule)
				f.report = report
				return true, nil
			})
			processErr := f.svc.Process(t.Context(), task)
			require.ErrorContains(t, processErr, "did not provide complete coverage")
			require.ErrorContains(t, processErr, "malformed_pickle")
			for _, mode := range []string{"enforce", "audit"} {
				f.policy.Mode = mode
				d, err := f.svc.Check(t.Context(), scope, revision, "file-4.pkl", "", 0)
				require.Equal(t, "RevisionFailed", admissionCode(t, err))
				require.False(t, d.Allowed)
			}
		})
	}
}
