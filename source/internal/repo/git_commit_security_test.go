// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"testing"

	hfdstorage "github.com/matrixhub-ai/hfd/pkg/storage"
	"github.com/stretchr/testify/require"

	"github.com/matrixhub-ai/matrixhub/internal/domain/git"
)

func TestSecurityCommitMetadataOmitsHistoricalContent(t *testing.T) {
	ctx := t.Context()
	repository := NewGitDB(hfdstorage.NewStorage(hfdstorage.WithRootDir(t.TempDir())), nil)
	require.NoError(t, repository.CreateRepository(ctx, "models", "proj", "model"))
	const canary = "inert historical content for commit metadata test"
	id, err := repository.CreateCommit(ctx, "models", "proj", "model", "main", &git.Commit{
		Message: "metadata test", AuthorName: "test", AuthorEmail: "test@example.com",
	}, []git.CommitOperation{{Type: git.CommitOperationAdd, Path: "README.md", Content: []byte(canary)}})
	require.NoError(t, err)

	full, err := repository.GetCommit(ctx, "models", "proj", "model", id)
	require.NoError(t, err)
	require.Contains(t, full.Diff, canary)
	metadata, err := repository.GetCommit(git.WithoutCommitDiff(ctx), "models", "proj", "model", id)
	require.NoError(t, err)
	require.Empty(t, metadata.Diff)
	copy := *full
	copy.Diff = ""
	require.Equal(t, &copy, metadata)
	require.Contains(t, full.Diff, canary)

	// The metadata-only request must not affect a later ordinary commit read.
	next, err := repository.GetCommit(ctx, "models", "proj", "model", id)
	require.NoError(t, err)
	require.Equal(t, full, next)
}
