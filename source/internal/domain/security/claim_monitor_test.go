// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSecurityRevokedClaimDoesNotReadSource(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	f.claimCheck = func(context.Context, *security.Task) (bool, error) { return false, nil }
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		require.False(t, report.Complete)
		require.Empty(t, report.Files)
		require.Contains(t, report.Error, "cancelled, expired or replaced")
		return false, nil
	})
	// No List, Reserve, Stage or Analyze expectation: cancellation between
	// Claim and Process must not begin any artifact work.
	require.ErrorContains(t, f.svc.Process(t.Context(), task), "late result discarded")
}

func TestSecurityCancelStopsRunningWorkThroughDurableClaim(t *testing.T) {
	f := newFixture(t, security.Settings{Timeout: time.Minute})
	task := scanTask()
	var revoked atomic.Bool
	f.claimCheck = func(context.Context, *security.Task) (bool, error) { return !revoked.Load(), nil }
	started, stopped := make(chan struct{}), make(chan struct{})
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).DoAndReturn(func(ctx context.Context, _, _ string) ([]security.SourceFile, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	f.store.EXPECT().Cancel(gomock.Any(), task.ID, scope).DoAndReturn(func(context.Context, int64, string) (bool, error) {
		revoked.Store(true)
		return true, nil
	})
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		require.False(t, report.Complete)
		require.Equal(t, security.Fail, report.State)
		require.Contains(t, report.Error, "cancelled, expired or replaced")
		return false, nil
	})
	done := pipelineProcess(t, f, task)
	awaitPipeline(t, started)
	ok, err := f.svc.Cancel(t.Context(), scope, task.ID)
	require.NoError(t, err)
	require.True(t, ok)
	awaitPipeline(t, stopped)
	require.ErrorContains(t, <-done, "cancelled, expired or replaced")
}

func TestSecurityUnverifiableClaimStopsRunningWork(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaced attempt", true: "database unavailable"}[unavailable], func(t *testing.T) {
			f := newFixture(t, security.Settings{Timeout: time.Minute})
			task := scanTask()
			var invalid atomic.Bool
			f.claimCheck = func(context.Context, *security.Task) (bool, error) {
				if invalid.Load() {
					if unavailable {
						return false, errors.New("private database failure detail")
					}
					return false, nil
				}
				return true, nil
			}
			started := make(chan struct{})
			f.artifacts.EXPECT().List(gomock.Any(), scope, revision).DoAndReturn(func(ctx context.Context, _, _ string) ([]security.SourceFile, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			})
			f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(ctx context.Context, _ *security.Task, report *security.Report) (bool, error) {
				require.NoError(t, ctx.Err())
				require.False(t, report.Complete)
				require.NotContains(t, report.Error, "private database")
				return true, nil
			})
			done := pipelineProcess(t, f, task)
			awaitPipeline(t, started)
			invalid.Store(true)
			require.Error(t, <-done)
		})
	}
}

func TestSecurityWorkDeadlineCannotExceedClaimLease(t *testing.T) {
	f := newFixture(t, security.Settings{Timeout: time.Minute})
	task := scanTask()
	task.LeaseUntil = time.Now().Add(40 * time.Millisecond)
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).DoAndReturn(func(ctx context.Context, _, _ string) ([]security.SourceFile, error) {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.False(t, deadline.After(task.LeaseUntil))
		<-ctx.Done()
		return nil, ctx.Err()
	})
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).Return(false, nil)
	require.ErrorIs(t, f.svc.Process(t.Context(), task), context.DeadlineExceeded)
}

func TestSecurityCompletedWorkJoinsClaimMonitorBeforeFinish(t *testing.T) {
	f := newFixture(t, security.Settings{})
	task := scanTask()
	var calls atomic.Int32
	checking, joined := make(chan struct{}), make(chan struct{})
	f.claimCheck = func(ctx context.Context, _ *security.Task) (bool, error) {
		if calls.Add(1) == 1 {
			return true, nil
		}
		close(checking)
		<-ctx.Done()
		close(joined)
		return false, ctx.Err()
	}
	f.artifacts.EXPECT().List(gomock.Any(), scope, revision).DoAndReturn(func(ctx context.Context, _, _ string) ([]security.SourceFile, error) {
		select {
		case <-checking:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	f.artifacts.EXPECT().Reserve(gomock.Any(), task, int64(0)).Return(func() {}, nil)
	f.store.EXPECT().Finish(gomock.Any(), task, gomock.Any()).DoAndReturn(func(_ context.Context, _ *security.Task, report *security.Report) (bool, error) {
		select {
		case <-joined:
		default:
			t.Fatal("claim monitor was not joined before report publication")
		}
		require.True(t, report.Complete)
		return true, nil
	})
	require.NoError(t, f.svc.Process(t.Context(), task))
}
