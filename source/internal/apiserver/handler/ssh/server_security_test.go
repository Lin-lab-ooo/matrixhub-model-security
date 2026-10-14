// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/matrixhub-ai/hfd/pkg/permission"
	"github.com/matrixhub-ai/hfd/pkg/repository"
	"github.com/matrixhub-ai/hfd/pkg/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	securitymocks "github.com/matrixhub-ai/matrixhub/internal/domain/security/mocks"
)

type exitChannel struct {
	gossh.Channel
	input  io.Reader
	stdout bytes.Buffer
	stderr bytes.Buffer
	status uint32
	exited bool
}

func (c *exitChannel) Read(data []byte) (int, error) {
	if c.input == nil {
		return 0, io.EOF
	}
	return c.input.Read(data)
}
func (c *exitChannel) Write(data []byte) (int, error) { return c.stdout.Write(data) }
func (c *exitChannel) Stderr() io.ReadWriter          { return &c.stderr }
func (c *exitChannel) SendRequest(name string, wantReply bool, data []byte) (bool, error) {
	if name == "exit-status" {
		c.status = binary.BigEndian.Uint32(data)
		c.exited = true
	}
	return true, nil
}

func TestSecuritySSHRawGitDeniedBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"denied", &security.AdmissionError{Code: "RawGitDisabled", Message: "Use approved downloads", State: security.Block}, "RawGitDisabled"},
		{"policy-error", errors.New("private policy database failed"), "security_unavailable"},
		{"auth-error", errors.New("private authorization backend failed"), "security_unavailable"},
		{"audit-error", errors.New("private audit database failed"), "security_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true)
			gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(tc.err)
			channel := &exitChannel{}
			// No storage or Git command is available to this server.
			NewServer(WithSecurityGate(gate)).executeCommand(t.Context(), channel, repository.GitUploadPack, "proj/model")
			require.True(t, channel.exited)
			require.Equal(t, uint32(1), channel.status)
			require.Contains(t, channel.stderr.String(), tc.code)
			require.NotContains(t, channel.stderr.String(), "private")
			require.Empty(t, channel.stdout.String())
		})
	}
}

func TestSecuritySSHDisabledKeepsPermissionHook(t *testing.T) {
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(false)
	channel := &exitChannel{}
	s := NewServer(WithSecurityGate(gate), WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))), WithPermissionHookFunc(func(context.Context, permission.Operation, string, permission.Context) (bool, error) {
		return false, nil
	}))
	s.executeCommand(t.Context(), channel, repository.GitUploadPack, "proj/model")
	require.Equal(t, uint32(1), channel.status)
	require.Equal(t, "permission denied", channel.stderr.String())
}

func TestSecuritySSHUnavailableDoesNotExposeBackendError(t *testing.T) {
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	gate.EXPECT().Enabled().Return(true)
	gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(errors.New("private database connection failed"))
	channel := &exitChannel{}
	NewServer(WithSecurityGate(gate)).executeCommand(t.Context(), channel, repository.GitUploadPack, "proj/model")
	require.True(t, channel.exited)
	require.Equal(t, uint32(1), channel.status)
	require.Contains(t, channel.stderr.String(), "security_unavailable")
	require.NotContains(t, channel.stderr.String(), "private database")
}

func TestSecuritySSHClientCommandCanonicalScope(t *testing.T) {
	for _, command := range []string{
		"git-upload-pack '/proj/model.git'",
		"git-upload-pack /proj/model.git",
		"git-upload-pack 'proj/model.git'",
		"git-upload-pack 'proj/model'",
	} {
		t.Run(command, func(t *testing.T) {
			cmd, err := parseCommand(command)
			require.NoError(t, err)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(true)
			gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(&security.AdmissionError{
				Code: "RawGitDisabled", Message: "Use approved downloads", State: security.Block,
			})
			channel := &exitChannel{}
			NewServer(WithSecurityGate(gate)).executeCommand(t.Context(), channel, cmd.service, cmd.repoName)
			require.True(t, channel.exited)
			require.Equal(t, uint32(1), channel.status)
			require.Contains(t, channel.stderr.String(), "RawGitDisabled")
		})
	}
}

func TestSecuritySSHInvalidScopeDeniedBeforeGateOrGit(t *testing.T) {
	for _, repo := range []string{"//proj/model.git", "/proj/../model.git", "/../model.git", "/proj/..", "/proj/.git", "/proj/model/extra.git", "/datasets/proj/model.git", "/spaces/proj/model.git", "/proj\\other/model.git", "/proj/model\x00.git"} {
		t.Run(repo, func(t *testing.T) {
			cmd, err := parseCommand("git-upload-pack '" + repo + "'")
			require.NoError(t, err)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			// Structurally invalid paths are rejected before consulting the gate.
			if repo == "/proj/model/extra.git" || repo == "/datasets/proj/model.git" || repo == "/spaces/proj/model.git" {
				gate.EXPECT().Enabled().Return(true)
			}
			channel := &exitChannel{}
			NewServer(WithSecurityGate(gate)).executeCommand(t.Context(), channel, cmd.service, cmd.repoName)
			require.True(t, channel.exited)
			require.Equal(t, uint32(1), channel.status)
			require.Contains(t, channel.stderr.String(), "PermissionDenied")
		})
	}
}

func TestSecuritySSHAdmissionAllowsExistingReads(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "audit"}[enabled], func(t *testing.T) {
			s := storage.NewStorage(storage.WithRootDir(t.TempDir()))
			repo, err := repository.Init(t.Context(), s.ResolvePath("proj/model"), "main")
			require.NoError(t, err)
			commit, err := repo.CreateCommit(t.Context(), "main", "test", "Test", "test@example.invalid", []repository.CommitOperation{{
				Type: repository.CommitOperationAdd, Path: "README.md", Content: []byte("raw source content"),
			}}, "")
			require.NoError(t, err)
			gate := securitymocks.NewMockGate(gomock.NewController(t))
			gate.EXPECT().Enabled().Return(enabled)
			if enabled {
				gate.EXPECT().DenyRawGit(gomock.Any(), "proj/model").Return(nil)
			}
			permissionCalls := 0
			server := NewServer(WithStorage(s), WithSecurityGate(gate),
				WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
					permissionCalls++
					require.Equal(t, permission.OperationReadRepo, operation)
					require.Equal(t, "proj/model", name)
					return true, nil
				}))
			channel := &exitChannel{input: bytes.NewBufferString("0000")}
			server.executeCommand(t.Context(), channel, repository.GitUploadPack, "proj/model")
			require.True(t, channel.exited)
			require.Equal(t, uint32(0), channel.status, channel.stderr.String())
			require.Equal(t, 1, permissionCalls)
			require.Empty(t, channel.stderr.String())
			require.Contains(t, channel.stdout.String(), commit+" refs/heads/main")
		})
	}
}

func TestSecuritySSHReceivePackKeepsExistingAuthorization(t *testing.T) {
	gate := securitymocks.NewMockGate(gomock.NewController(t))
	channel := &exitChannel{}
	permissionCalls := 0
	server := NewServer(WithSecurityGate(gate), WithStorage(storage.NewStorage(storage.WithRootDir(t.TempDir()))),
		WithPermissionHookFunc(func(_ context.Context, operation permission.Operation, name string, _ permission.Context) (bool, error) {
			permissionCalls++
			require.Equal(t, permission.OperationUpdateRepo, operation)
			require.Equal(t, "proj/model", name)
			return false, nil
		}))
	server.executeCommand(t.Context(), channel, repository.GitReceivePack, "proj/model")
	// No gate expectations: upload authorization does not consult raw-read policy.
	require.True(t, channel.exited)
	require.Equal(t, uint32(1), channel.status)
	require.Equal(t, 1, permissionCalls)
	require.Equal(t, "permission denied", channel.stderr.String())
}
