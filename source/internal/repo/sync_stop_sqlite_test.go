// Copyright The MatrixHub Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/matrixhub-ai/matrixhub/internal/domain/syncjob"
	"github.com/matrixhub-ai/matrixhub/internal/domain/syncpolicy"
)

func TestSQLiteSyncTaskUpdate(t *testing.T) {
	t.Run("KeepsStopped", assertSQLiteSyncTaskKeepsStopped)
	t.Run("ZeroValues", assertSQLiteSyncTaskZeroValues)
	t.Run("DoesNotReinsert", assertSQLiteSyncTaskDoesNotReinsert)
}

func TestSQLiteSyncJobUpdate(t *testing.T) {
	t.Run("KeepsStopped", assertSQLiteSyncJobKeepsStopped)
	t.Run("ZeroValues", assertSQLiteSyncJobZeroValues)
	t.Run("DoesNotReinsert", assertSQLiteSyncJobDoesNotReinsert)
}

func assertSQLiteSyncTaskKeepsStopped(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncTaskDB(database)
	task := createSyncUpdateTask(t, database)
	worker, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)
	stopper, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)
	require.NotSame(t, worker, stopper)
	stopper.Status = syncpolicy.SyncTaskStatusStopped
	stopper.CompletedTimestamp = 1700000000
	stopper.StoppedItems = 1
	require.NoError(t, repository.UpdateSyncTask(ctx, stopper))
	stopped, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)

	for _, status := range []syncpolicy.SyncTaskStatus{
		syncpolicy.SyncTaskStatusRunning,
		syncpolicy.SyncTaskStatusPending,
		syncpolicy.SyncTaskStatusSucceeded,
		syncpolicy.SyncTaskStatusFailed,
	} {
		worker.Status = status
		worker.CompletedTimestamp = 1800000000
		worker.StoppedItems = 0
		require.NoError(t, repository.UpdateSyncTask(ctx, worker))
		actual, err := repository.GetSyncTask(ctx, task.ID)
		require.NoError(t, err)
		require.Equal(t, *stopped, *actual, "stale task status %d overwrote stopped state", status)
	}
}

func assertSQLiteSyncJobKeepsStopped(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncJobDB(database)
	job := createSyncUpdateJob(t, database)
	worker, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)
	stopper, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)
	require.NotSame(t, worker, stopper)
	stopper.Status = syncjob.SyncJobStatusStopped
	stopper.CompletedTimestamp = 1700000000
	require.NoError(t, repository.UpdateSyncJob(ctx, stopper))
	stopped, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)

	for _, status := range []syncjob.SyncJobStatus{
		syncjob.SyncJobStatusRunning,
		syncjob.SyncJobStatusPending,
		syncjob.SyncJobStatusSucceeded,
		syncjob.SyncJobStatusFailed,
	} {
		worker.Status = status
		worker.CompletedTimestamp = 1800000000
		require.NoError(t, repository.UpdateSyncJob(ctx, worker))
		actual, err := repository.GetSyncJob(ctx, job.ID)
		require.NoError(t, err)
		require.Equal(t, *stopped, *actual, "stale job status %d overwrote stopped state", status)
	}
}

func assertSQLiteSyncTaskZeroValues(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncTaskDB(database)
	task := createSyncUpdateTask(t, database)
	worker, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)
	createdAt := worker.CreatedAt
	worker.Status = syncpolicy.SyncTaskStatusPending
	worker.StartedTimestamp = 0
	worker.CompletedTimestamp = 0
	worker.TotalItems = 0
	worker.SuccessfulItems = 0
	worker.StoppedItems = 0
	worker.FailedItems = 0
	worker.CompletePercents = 0
	worker.CreatedAt = createdAt.Add(time.Hour)
	require.NoError(t, repository.UpdateSyncTask(ctx, worker))
	actual, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, syncpolicy.SyncTaskStatusPending, actual.Status)
	require.Zero(t, actual.StartedTimestamp)
	require.Zero(t, actual.CompletedTimestamp)
	require.Zero(t, actual.TotalItems)
	require.Zero(t, actual.SuccessfulItems)
	require.Zero(t, actual.StoppedItems)
	require.Zero(t, actual.FailedItems)
	require.Zero(t, actual.CompletePercents)
	require.Equal(t, createdAt, actual.CreatedAt)
	require.Equal(t, task.ID, actual.ID)
}

func assertSQLiteSyncJobZeroValues(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncJobDB(database)
	job := createSyncUpdateJob(t, database)
	worker, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)
	createdAt := worker.CreatedAt
	worker.Status = syncjob.SyncJobStatusPending
	worker.CompletedTimestamp = 0
	worker.CompletePercents = 0
	worker.RemoteProjectName = ""
	worker.RemoteResourceName = ""
	worker.ProjectName = ""
	worker.ResourceName = ""
	worker.ResourceType = ""
	worker.SyncType = ""
	worker.CreatedAt = createdAt.Add(time.Hour)
	require.NoError(t, repository.UpdateSyncJob(ctx, worker))
	actual, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)
	require.Equal(t, syncjob.SyncJobStatusPending, actual.Status)
	require.Zero(t, actual.CompletedTimestamp)
	require.Zero(t, actual.CompletePercents)
	require.Empty(t, actual.RemoteProjectName)
	require.Empty(t, actual.RemoteResourceName)
	require.Empty(t, actual.ProjectName)
	require.Empty(t, actual.ResourceName)
	require.Empty(t, actual.ResourceType)
	require.Empty(t, actual.SyncType)
	require.Equal(t, createdAt, actual.CreatedAt)
	require.Equal(t, job.ID, actual.ID)
}

func assertSQLiteSyncTaskDoesNotReinsert(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncTaskDB(database)
	task := createSyncUpdateTask(t, database)
	worker, err := repository.GetSyncTask(ctx, task.ID)
	require.NoError(t, err)

	require.NoError(t, repository.DeleteSyncTask(ctx, task.ID))
	for _, status := range []syncpolicy.SyncTaskStatus{syncpolicy.SyncTaskStatusRunning, syncpolicy.SyncTaskStatusStopped} {
		worker.Status = status
		require.NoError(t, repository.UpdateSyncTask(ctx, worker))
		_, err = repository.GetSyncTask(ctx, task.ID)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	}
}

func assertSQLiteSyncJobDoesNotReinsert(t *testing.T) {
	database, _ := newSQLiteRepositoryTestDatabase(t)
	ctx := context.Background()
	repository := NewSyncJobDB(database)
	job := createSyncUpdateJob(t, database)
	worker, err := repository.GetSyncJob(ctx, job.ID)
	require.NoError(t, err)

	require.NoError(t, repository.DeleteSyncJob(ctx, job.ID))
	for _, status := range []syncjob.SyncJobStatus{syncjob.SyncJobStatusRunning, syncjob.SyncJobStatusStopped} {
		worker.Status = status
		require.NoError(t, repository.UpdateSyncJob(ctx, worker))
		_, err = repository.GetSyncJob(ctx, job.ID)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	}
}

func createSyncUpdateTask(t *testing.T, database *gorm.DB) *syncpolicy.SyncTask {
	t.Helper()
	require.NoError(t, database.Exec("INSERT INTO sync_policies (name) VALUES (?)", "stop-update").Error)
	var policy struct{ ID int }
	require.NoError(t, database.Table("sync_policies").Select("id").Where("name = ?", "stop-update").Take(&policy).Error)
	task := &syncpolicy.SyncTask{
		SyncPolicyID:       policy.ID,
		TriggerType:        syncpolicy.TriggerTypeManual,
		Status:             syncpolicy.SyncTaskStatusRunning,
		StartedTimestamp:   1600000000,
		CompletedTimestamp: 1600000100,
		TotalItems:         3,
		SuccessfulItems:    1,
		StoppedItems:       1,
		FailedItems:        1,
		CompletePercents:   60,
	}
	require.NoError(t, database.Create(task).Error)
	return task
}

func createSyncUpdateJob(t *testing.T, database *gorm.DB) *syncjob.SyncJob {
	t.Helper()
	job := &syncjob.SyncJob{
		RemoteProjectName:  "remote",
		RemoteResourceName: "resource",
		ProjectName:        "local",
		ResourceName:       "resource",
		ResourceType:       "model",
		SyncType:           "pull",
		Status:             syncjob.SyncJobStatusRunning,
		CompletedTimestamp: 1600000100,
		CompletePercents:   60,
	}
	require.NoError(t, database.Create(job).Error)
	return job
}
