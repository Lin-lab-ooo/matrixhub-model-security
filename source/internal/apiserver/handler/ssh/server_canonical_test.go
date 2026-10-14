// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/matrixhub-ai/hfd/pkg/authenticate"
	"github.com/matrixhub-ai/hfd/pkg/permission"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	"github.com/matrixhub-ai/hfd/pkg/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"

	securitymocks "github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

func TestSSHCanonicalRepositoryName(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"/proj/model.git", "proj/model.git"},
		{"proj/model.git", "proj/model.git"},
		{"/proj/model", "proj/model"},
		{"/datasets/proj/model.git", "datasets/proj/model.git"},
	} {
		got, ok := canonicalSSHRepoName(tc.raw)
		require.True(t, ok, tc.raw)
		require.Equal(t, tc.want, got)
	}
	for _, raw := range []string{"", "/", "//proj/model.git", "///proj/model.git", "/proj//model.git", "/proj/./model.git", "/proj/../model.git", "/../model.git", "/proj/..", "/proj/.git", "/proj/..git", "/proj/...git", "/proj/model.git/", "/proj\\other/model.git", "/proj/model\x00.git", "/proj/model\r.git", "/proj/model\n.git"} {
		got, ok := canonicalSSHRepoName(raw)
		require.False(t, ok, raw)
		require.Empty(t, got, raw)
	}
}

func TestSSHClientPathsPreserveAuthorization(t *testing.T) {
	for _, service := range []string{repository.GitUploadPack, repository.GitReceivePack} {
		for _, raw := range []string{"'/proj/model.git'", "/proj/model.git", "'proj/model.git'"} {
			t.Run(service+"/"+raw, func(t *testing.T) {
				cmd, err := parseCommand(service + " " + raw)
				require.NoError(t, err)
				calls := 0
				ctx := authenticate.WithContext(t.Context(), authenticate.UserInfo{User: "canonical-test-principal"})
				server := NewServer(WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))), WithPermissionHookFunc(func(ctx context.Context, op permission.Operation, name string, _ permission.Context) (bool, error) {
					calls++
					want := permission.OperationReadRepo
					if service == repository.GitReceivePack {
						want = permission.OperationUpdateRepo
					}
					require.Equal(t, want, op)
					require.Equal(t, "proj/model.git", name)
					info, ok := authenticate.GetUserInfo(ctx)
					require.True(t, ok)
					require.Equal(t, "canonical-test-principal", info.User)
					return false, nil
				}))
				channel := &exitChannel{}
				server.executeCommand(ctx, channel, cmd.service, cmd.repoName)
				require.Equal(t, 1, calls)
				require.True(t, channel.exited)
				require.Equal(t, uint32(1), channel.status)
				require.Equal(t, "permission denied", channel.stderr.String())
				require.Empty(t, channel.stdout.String())
			})
		}
	}
}

func TestSSHAuditClientURLAdvertisesAuthorizedRepository(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "security-disabled", true: "audit"}[enabled], func(t *testing.T) {
			s := storage.NewStorage(storage.WithRootDir(t.TempDir()))
			repo, err := repository.Init(t.Context(), s.ResolvePath("proj/model"), "main")
			require.NoError(t, err)
			commit, err := repo.CreateCommit(t.Context(), "main", "test", "Test", "test@example.invalid", []repository.CommitOperation{{Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("inert canonical path regression")}}, "")
			require.NoError(t, err)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(enabled)
			if enabled {
				gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
			}
			calls := 0
			server := NewServer(WithStorage(s), WithSecurityGate(gate), WithPermissionHookFunc(func(_ context.Context, op permission.Operation, name string, _ permission.Context) (bool, error) {
				calls++
				require.Equal(t, permission.OperationReadRepo, op)
				require.Equal(t, "proj/model.git", name)
				return true, nil
			}))
			cmd, err := parseCommand("git-upload-pack '/proj/model.git'")
			require.NoError(t, err)
			channel := &exitChannel{input: bytes.NewBufferString("0000")}
			server.executeCommand(t.Context(), channel, cmd.service, cmd.repoName)
			require.Equal(t, 1, calls)
			require.True(t, channel.exited)
			require.Equal(t, uint32(0), channel.status, channel.stderr.String())
			require.Empty(t, channel.stderr.String())
			require.Contains(t, channel.stdout.String(), commit+" refs/heads/main")
		})
	}
}

func TestSSHLFSClientPathPreservesAuthorization(t *testing.T) {
	for _, operation := range []string{"download", "upload"} {
		t.Run(operation, func(t *testing.T) {
			cmd, err := parseCommand("git-lfs-authenticate '/proj/model.git' " + operation)
			require.NoError(t, err)
			calls := 0
			server := NewServer(WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))), WithLFSURL("http://example.invalid"), WithPermissionHookFunc(func(_ context.Context, op permission.Operation, name string, _ permission.Context) (bool, error) {
				calls++
				want := permission.OperationReadRepo
				if operation == "upload" {
					want = permission.OperationUpdateRepo
				}
				require.Equal(t, want, op)
				require.Equal(t, "proj/model.git", name)
				return false, nil
			}))
			channel := &exitChannel{}
			server.executeLFSAuthenticate(t.Context(), channel, cmd.repoName, cmd.operation)
			require.Equal(t, 1, calls)
			require.Equal(t, uint32(1), channel.status)
			require.Equal(t, "permission denied", channel.stderr.String())
			require.Empty(t, channel.stdout.String())
		})
	}
}

func TestSSHInvalidClientPathsRejectedBeforeHooksOrStorage(t *testing.T) {
	for _, raw := range []string{"//proj/model.git", "/proj/../model.git", "/proj//model.git", "/proj/.git", "/proj/model\x00.git", "/proj\\model.git"} {
		for _, service := range []string{repository.GitUploadPack, repository.GitReceivePack, repository.GitLFSAuthenticate} {
			t.Run(service+"/"+raw, func(t *testing.T) {
				// No storage, model service, permission hook or external Git exists.
				server := NewServer()
				channel := &exitChannel{}
				if service == repository.GitLFSAuthenticate {
					server.executeLFSAuthenticate(t.Context(), channel, raw, "download")
				} else {
					server.executeCommand(t.Context(), channel, service, raw)
				}
				require.True(t, channel.exited)
				require.Equal(t, uint32(1), channel.status)
				require.Contains(t, channel.stderr.String(), "PermissionDenied")
				require.Empty(t, channel.stdout.String())
			})
		}
	}
}

type canonicalConnMetadata struct{ gossh.ConnMetadata }

func (canonicalConnMetadata) User() string { return "git" }

func TestSSHUnregisteredPublicKeyStillRejected(t *testing.T) {
	calls := 0
	server := NewServer(WithPublicKeyValidator(authenticate.PublicKeyValidatorFunc(func(_ context.Context, username, keyType string, key []byte) (string, bool, bool, error) {
		calls++
		require.Equal(t, "git", username)
		require.Equal(t, gossh.KeyAlgoED25519, keyType)
		require.NotEmpty(t, key)
		return "", false, false, nil
	})))
	public, err := gossh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	require.NoError(t, err)
	require.False(t, server.config.NoClientAuth)
	permissions, err := server.config.PublicKeyCallback(canonicalConnMetadata{}, public)
	require.Error(t, err)
	require.Nil(t, permissions)
	require.Equal(t, 1, calls)
}
