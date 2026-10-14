// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func pipelineFixture(t *testing.T, count int) (*fixture, *security.Task, []security.SourceFile, []security.Artifact, security.Analysis) {
	t.Helper()
	f := newFixture(t, security.Settings{})
	task := scanTask()
	template := f.report.Files[0]
	sources := make([]security.SourceFile, count)
	artifacts := make([]security.Artifact, count)
	for i := range count {
		sources[i], artifacts[i] = template.SourceFile, template.Artifact
		sources[i].Path = fmt.Sprintf("file-%d.pkl", i)
		artifacts[i].ID = fmt.Sprintf("snapshot/file-%d.blob", i)
	}
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).Return(sources, nil)
	return f, task, sources, artifacts, template.Analysis
}

func awaitPipeline(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not reach the required synchronization point")
	}
}

func pipelineProcess(t *testing.T, f *fixture, task *security.Task) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- f.svc.Process(ctx, task) }()
	return done
}

func TestSecurityPipelineOverlapsSealedFileWithStagingAndKeepsRevisionGate(t *testing.T) {
	f, task, sources, artifacts, analysis := pipelineFixture(t, 3)
	scanStarted, stageSecond, allowScan := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finished := make(chan struct{})
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(9)).Return(func() {}, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1024)).Return(artifacts[0], nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1024)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
		close(stageSecond)
		select {
		case <-scanStarted:
			return artifacts[1], nil
		case <-ctx.Done():
			return security.Artifact{}, ctx.Err()
		}
	})
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[2], int64(1024)).Return(artifacts[2], nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[1], task.Generation).Return(&analysis, nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[2], task.Generation).Return(nil, nil)
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).DoAndReturn(func(ctx context.Context, _ security.Artifact) (security.Analysis, error) {
		close(scanStarted)
		select {
		case <-allowScan:
			return analysis, nil
		case <-ctx.Done():
			return security.Analysis{}, ctx.Err()
		}
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[2]).Return(analysis, nil)
	f.report.State, f.report.Complete = security.Scanning, false
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		close(finished)
		return true, nil
	})
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, scanStarted)
	awaitPipeline(t, stageSecond)
	select {
	case <-finished:
		t.Fatal("published revision before all scans completed")
	default:
	}
	decision, err := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionScanning", admissionCode(t, err))
	require.False(t, decision.Allowed)
	close(allowScan)
	require.NoError(t, <-done)
	require.True(t, published.Complete)
	require.Equal(t, 1, published.CachedFiles)
	require.Equal(t, int64(9), published.ScannedBytes)
	require.Len(t, published.Files, 3)
	for i, file := range published.Files {
		require.Equal(t, sources[i], file.SourceFile)
		require.Equal(t, artifacts[i], file.Artifact)
		require.Equal(t, analysis, file.Analysis)
		require.Equal(t, i == 1, file.Cached)
	}
}

func TestSecurityPipelineBatchBackpressureBoundsAheadOfScanner(t *testing.T) {
	f, task, sources, artifacts, analysis := pipelineFixture(t, 7)
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 2, 1024
	f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true}, func(context.Context, string, string) error { return nil }, nil)
	firstScan, secondBatchStaged, fifthStaged, allowScan := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(21)).Return(func() {}, nil)
	for i := range sources {
		f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[i], int64(1024)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
			if i == 2 {
				select {
				case <-firstScan:
				case <-ctx.Done():
					return security.Artifact{}, ctx.Err()
				}
			}
			if i == 3 {
				close(secondBatchStaged)
			}
			if i == 4 {
				close(fifthStaged)
			}
			return artifacts[i], nil
		})
		f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[i], task.Generation).Return(nil, nil)
	}
	seen := 0
	batch.EXPECT().AnalyzeBatch(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, input []security.Artifact) ([]security.Analysis, error) {
		if seen == 0 {
			close(firstScan)
			select {
			case <-allowScan:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if len(input) != min(2, len(artifacts)-seen) {
			return nil, errors.New("pipeline changed deterministic batch capacity")
		}
		results := make([]security.Analysis, len(input))
		for i, artifact := range input {
			if artifact != artifacts[seen] {
				return nil, errors.New("pipeline reordered an artifact")
			}
			results[i] = analysis
			seen++
		}
		return results, nil
	}).Times(4)
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, firstScan)
	awaitPipeline(t, secondBatchStaged)
	// The next Stage must remain blocked while there is an active batch and a
	// producer-owned full batch. A bounded negative observation catches queues
	// that let every remaining file stage ahead of the scanner.
	select {
	case <-fifthStaged:
		t.Fatal("staging ran ahead of the bounded batch pipeline")
	case <-time.After(50 * time.Millisecond):
	}
	close(allowScan)
	require.NoError(t, <-done)
	require.True(t, published.Complete)
	require.Equal(t, 7, seen)
	for i, file := range published.Files {
		require.Equal(t, artifacts[i], file.Artifact)
		require.Equal(t, analysis, file.Analysis)
	}
}

func TestSecurityPipelineStageFailureCancelsAndJoinsBeforeRelease(t *testing.T) {
	f, task, sources, artifacts, _ := pipelineFixture(t, 2)
	scanStarted, scanCanceled, allowScanExit, released, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	stageErr := errors.New("source transfer failed")
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() { close(released) }, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1024)).Return(artifacts[0], nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1024)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
		select {
		case <-scanStarted:
			return security.Artifact{}, stageErr
		case <-ctx.Done():
			return security.Artifact{}, ctx.Err()
		}
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).DoAndReturn(func(ctx context.Context, _ security.Artifact) (security.Analysis, error) {
		close(scanStarted)
		<-ctx.Done()
		close(scanCanceled)
		select {
		case <-allowScanExit:
		case <-t.Context().Done():
		}
		return security.Analysis{}, ctx.Err()
	})
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		close(finished)
		return true, nil
	})
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, scanCanceled)
	select {
	case <-released:
		t.Fatal("released snapshots before scanner joined")
	case <-finished:
		t.Fatal("published failure before scanner joined")
	default:
	}
	close(allowScanExit)
	require.ErrorIs(t, <-done, stageErr)
	awaitPipeline(t, released)
	require.False(t, published.Complete)
	require.Equal(t, security.Fail, published.State)
	require.Equal(t, stageErr.Error(), published.Error)
}

func TestSecurityPipelineScannerFailureCancelsActiveStageAndPreservesCause(t *testing.T) {
	f, task, sources, artifacts, _ := pipelineFixture(t, 2)
	stageStarted, stageCanceled, allowStageExit, released := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	scanErr := errors.New("scanner engine unavailable")
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() { close(released) }, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1024)).Return(artifacts[0], nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1024)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
		close(stageStarted)
		<-ctx.Done()
		close(stageCanceled)
		select {
		case <-allowStageExit:
		case <-t.Context().Done():
		}
		return security.Artifact{}, ctx.Err()
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).DoAndReturn(func(ctx context.Context, _ security.Artifact) (security.Analysis, error) {
		select {
		case <-stageStarted:
			return security.Analysis{}, scanErr
		case <-ctx.Done():
			return security.Analysis{}, ctx.Err()
		}
	})
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, stageCanceled)
	select {
	case <-released:
		t.Fatal("released reservation before the stage read stopped")
	default:
	}
	close(allowStageExit)
	require.ErrorIs(t, <-done, scanErr)
	require.False(t, published.Complete)
	require.Equal(t, scanErr.Error(), published.Error)
}

func TestSecurityPipelineCachedFailureCancelsScannerAndCannotPublish(t *testing.T) {
	f, task, sources, artifacts, _ := pipelineFixture(t, 2)
	scanStarted, scanStopped := make(chan struct{}), make(chan struct{})
	cacheErr := errors.New("cache lookup failed")
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() {}, nil)
	for i := range sources {
		f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[i], int64(1024)).Return(artifacts[i], nil)
	}
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[1], task.Generation).DoAndReturn(func(ctx context.Context, _ string, _ security.Artifact, _ string) (*security.Analysis, error) {
		select {
		case <-scanStarted:
			return nil, cacheErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).DoAndReturn(func(ctx context.Context, _ security.Artifact) (security.Analysis, error) {
		close(scanStarted)
		<-ctx.Done()
		close(scanStopped)
		return security.Analysis{}, ctx.Err()
	})
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	require.ErrorIs(t, <-pipelineProcess(t, f, task), cacheErr)
	awaitPipeline(t, scanStopped)
	require.False(t, published.Complete)
	require.Equal(t, cacheErr.Error(), published.Error)
}

func TestSecurityPipelineFinalGenerationChangeRejectsAllStagedResults(t *testing.T) {
	f, task, sources, artifacts, analysis := pipelineFixture(t, 2)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() {}, nil)
	for i := range sources {
		f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[i], int64(1024)).Return(artifacts[i], nil)
		f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[i], task.Generation).Return(nil, nil)
	}
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).Return(analysis, nil)
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[1]).DoAndReturn(func(context.Context, security.Artifact) (security.Analysis, error) {
		f.bundle.Generation = "rules-v2"
		return analysis, nil
	})
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	require.ErrorContains(t, f.svc.Process(t.Context(), task), "before report publication")
	require.False(t, published.Complete)
	require.Equal(t, security.Fail, published.State)
	require.Len(t, published.Files, 2)
}

func TestSecurityPipelineParentCancellationJoinsBothStages(t *testing.T) {
	f, task, sources, artifacts, _ := pipelineFixture(t, 2)
	stageStarted, scanStarted := make(chan struct{}), make(chan struct{})
	stageStopped, scanStopped, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() { close(released) }, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1024)).Return(artifacts[0], nil)
	f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1024)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
		close(stageStarted)
		<-ctx.Done()
		close(stageStopped)
		return security.Artifact{}, ctx.Err()
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[0]).DoAndReturn(func(ctx context.Context, _ security.Artifact) (security.Analysis, error) {
		close(scanStarted)
		<-ctx.Done()
		close(scanStopped)
		return security.Analysis{}, ctx.Err()
	})
	var published *security.Report
	var cleanupErr error
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(ctx context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published, cleanupErr = report, ctx.Err()
		return true, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- f.svc.Process(ctx, task) }()
	awaitPipeline(t, stageStarted)
	awaitPipeline(t, scanStarted)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("canceled stage/scanner did not join")
	}
	awaitPipeline(t, stageStopped)
	awaitPipeline(t, scanStopped)
	awaitPipeline(t, released)
	require.NoError(t, cleanupErr)
	require.False(t, published.Complete)
	require.Equal(t, security.Fail, published.State)
}

func TestSecurityPipelineBatchHardByteCeiling(t *testing.T) {
	f := newFixture(t, security.Settings{})
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	f.bundle.MaxFileBytes = 256 << 20
	f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 100, 1<<30
	f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true, MaxFileBytes: 256 << 20, MaxTaskBytes: 1 << 30}, func(context.Context, string, string) error { return nil }, nil)
	task := scanTask()
	template := f.report.Files[0]
	sources := make([]security.SourceFile, 3)
	artifacts := make([]security.Artifact, 3)
	for i, size := range []int64{128 << 20, 128 << 20, 1} {
		sources[i], artifacts[i] = template.SourceFile, template.Artifact
		sources[i].Path, sources[i].Size = fmt.Sprintf("file-%d.pkl", i), size
		artifacts[i].ID, artifacts[i].Size = fmt.Sprintf("snapshot/file-%d.blob", i), size
		f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[i], int64(256<<20)).Return(artifacts[i], nil)
		f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[i], task.Generation).Return(nil, nil)
	}
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).Return(sources, nil)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(256<<20)+1).Return(func() {}, nil)
	gomock.InOrder(
		batch.EXPECT().AnalyzeBatch(gomock.Any(), artifacts[:2]).Return([]security.Analysis{template.Analysis, template.Analysis}, nil),
		batch.EXPECT().AnalyzeBatch(gomock.Any(), artifacts[2:]).Return([]security.Analysis{template.Analysis}, nil),
	)
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	require.NoError(t, f.svc.Process(t.Context(), task))
	require.True(t, published.Complete)
	require.Equal(t, int64(256<<20)+1, published.ScannedBytes)
	require.Len(t, published.Files, 3)
}

func TestSecurityPipelineFlushesPendingBeforeGiBStageCompletes(t *testing.T) {
	f, task, sources, artifacts, analysis := pipelineFixture(t, 2)
	// Only declared sizes change: no GiB allocation or actual file I/O.
	sources[1].Size, artifacts[1].Size = 1<<30, 1<<30
	f.bundle.MaxFileBytes = 1 << 30
	f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 32, 256<<20
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true, MaxFileBytes: 1 << 30, MaxTaskBytes: 2 << 30}, func(context.Context, string, string) error { return nil }, nil)
	scanStarted, largeStageStarted := make(chan struct{}), make(chan struct{})
	allowScan, allowStage, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(1<<30)+3).Return(func() {}, nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1<<30)).Return(artifacts[0], nil)
	f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1<<30)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
		close(largeStageStarted)
		select {
		case <-allowStage:
			return artifacts[1], nil
		case <-ctx.Done():
			return security.Artifact{}, ctx.Err()
		}
	})
	for _, artifact := range artifacts {
		f.store.EXPECT().Cached(gomock.Any(), scope, artifact, task.Generation).Return(nil, nil)
	}
	batch.EXPECT().AnalyzeBatch(gomock.Any(), artifacts[:1]).DoAndReturn(func(ctx context.Context, _ []security.Artifact) ([]security.Analysis, error) {
		close(scanStarted)
		select {
		case <-allowScan:
			return []security.Analysis{analysis}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[1]).Return(analysis, nil)
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		close(finished)
		return true, nil
	})
	f.report.State, f.report.Complete = security.Scanning, false
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, largeStageStarted)
	// Stage is still blocked. The old post-Stage-only flush deadlocks here
	// until the bounded test deadline instead of starting the small scan.
	awaitPipeline(t, scanStarted)
	select {
	case <-finished:
		t.Fatal("published before the GiB snapshot and scans completed")
	default:
	}
	decision, err := f.svc.Check(t.Context(), scope, revision, "weights.pkl", "", 0)
	require.Equal(t, "RevisionScanning", admissionCode(t, err))
	require.False(t, decision.Allowed)
	close(allowStage)
	close(allowScan)
	require.NoError(t, <-done)
	require.True(t, published.Complete)
	require.Equal(t, int64(1<<30)+3, published.ScannedBytes)
	require.Len(t, published.Files, 2)
	for i, file := range published.Files {
		require.Equal(t, sources[i], file.SourceFile)
		require.Equal(t, artifacts[i], file.Artifact)
		require.Equal(t, analysis, file.Analysis)
	}
}

func TestSecurityPipelinePredictedFlushCancellationAndFailureStayClosed(t *testing.T) {
	for _, parentCancel := range []bool{true, false} {
		t.Run(fmt.Sprintf("parentCancel=%t", parentCancel), func(t *testing.T) {
			f, task, sources, artifacts, _ := pipelineFixture(t, 2)
			sources[1].Size, artifacts[1].Size = 1<<30, 1<<30
			f.bundle.MaxFileBytes = 1 << 30
			f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 32, 256<<20
			batch := mocks.NewMockBatchScanner(gomock.NewController(t))
			f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true, MaxFileBytes: 1 << 30, MaxTaskBytes: 2 << 30}, func(context.Context, string, string) error { return nil }, nil)
			scanStarted, stageStarted := make(chan struct{}), make(chan struct{})
			scanStopped, stageStopped, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
			scanErr := errors.New("sealed batch scanner unavailable")
			f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(1<<30)+3).Return(func() { close(released) }, nil)
			f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[0], int64(1<<30)).Return(artifacts[0], nil)
			f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[0], task.Generation).Return(nil, nil)
			f.artifacts.EXPECT().Stage(gomock.Any(), task, sources[1], int64(1<<30)).DoAndReturn(func(ctx context.Context, _ *security.Task, _ security.SourceFile, _ int64) (security.Artifact, error) {
				close(stageStarted)
				<-ctx.Done()
				close(stageStopped)
				return security.Artifact{}, ctx.Err()
			})
			batch.EXPECT().AnalyzeBatch(gomock.Any(), artifacts[:1]).DoAndReturn(func(ctx context.Context, _ []security.Artifact) ([]security.Analysis, error) {
				close(scanStarted)
				defer close(scanStopped)
				select {
				case <-stageStarted:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if !parentCancel {
					return nil, scanErr
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			var published *security.Report
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
				published = report
				return true, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			t.Cleanup(cancel)
			done := make(chan error, 1)
			go func() { done <- f.svc.Process(ctx, task) }()
			awaitPipeline(t, stageStarted)
			awaitPipeline(t, scanStarted)
			want := scanErr
			if parentCancel {
				cancel()
				want = context.Canceled
			}
			require.ErrorIs(t, <-done, want)
			awaitPipeline(t, stageStopped)
			awaitPipeline(t, scanStopped)
			awaitPipeline(t, released)
			require.False(t, published.Complete)
			require.Equal(t, security.Fail, published.State)
			require.Equal(t, want.Error(), published.Error)
			f.report = published
			decision, err := f.svc.Check(t.Context(), scope, revision, sources[0].Path, "", 0)
			require.Equal(t, "RevisionFailed", admissionCode(t, err))
			require.False(t, decision.Allowed)
		})
	}
}

func TestSecurityPipelineActualSizeFallbackAndMismatchCannotAuthorize(t *testing.T) {
	f, task, sources, artifacts, analysis := pipelineFixture(t, 2)
	// A real Stage rejects a source-size mismatch. This intentionally broken
	// port proves a size prediction cannot replace actual batch sizing or the
	// final download gate's source/artifact binding.
	artifacts[1].Size = 2048
	f.bundle.MaxFileBytes = 4096
	f.bundle.MaxBatchFiles, f.bundle.MaxBatchBytes = 32, 1024
	batch := mocks.NewMockBatchScanner(gomock.NewController(t))
	f.svc = security.NewService(f.store, f.artifacts, batchScannerMock{f.scanner, batch}, security.Settings{Enabled: true, MaxFileBytes: 4096}, func(context.Context, string, string) error { return nil }, nil)
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(6)).Return(func() {}, nil)
	for i, source := range sources {
		f.artifacts.EXPECT().Stage(gomock.Any(), task, source, int64(4096)).Return(artifacts[i], nil)
		f.store.EXPECT().Cached(gomock.Any(), scope, artifacts[i], task.Generation).Return(nil, nil)
	}
	gomock.InOrder(
		batch.EXPECT().AnalyzeBatch(gomock.Any(), artifacts[:1]).Return([]security.Analysis{analysis}, nil),
		f.scanner.EXPECT().Analyze(gomock.Any(), artifacts[1]).Return(analysis, nil),
	)
	var published *security.Report
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		published = report
		return true, nil
	})
	require.NoError(t, f.svc.Process(t.Context(), task))
	require.Equal(t, int64(2051), published.ScannedBytes)
	require.Len(t, published.Files, 2)
	f.report = published
	decision, err := f.svc.Check(t.Context(), scope, revision, sources[1].Path, "", 0)
	require.Equal(t, "ManifestMismatch", admissionCode(t, err))
	require.False(t, decision.Allowed)
}
