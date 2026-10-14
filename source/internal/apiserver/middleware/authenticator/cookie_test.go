// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package authenticator

//go:generate go tool mockgen -source=../../../domain/user/session.go -destination=mocks/session_repo_mock.go -package=mocks
//go:generate go tool mockgen -source=../../../domain/user/user.go -destination=mocks/user_repo_mock.go -package=mocks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/metadata"

	"github.com/matrixhub-ai/matrixhub/internal/apiserver/middleware/authenticator/mocks"
	"github.com/matrixhub-ai/matrixhub/internal/domain/user"
)

func cookieFixture(t *testing.T, lastActive time.Time, sessionVersion int, rememberMe bool) (*CookieAuthenticator, *mocks.MockIUserRepo, string) {
	t.Helper()
	manager := scs.New()
	if store, ok := manager.Store.(interface{ StopCleanup() }); ok {
		t.Cleanup(store.StopCleanup)
	}
	ctx, err := manager.Load(context.Background(), "")
	require.NoError(t, err)
	manager.Put(ctx, user.UserIdCtxKey, 7)
	manager.Put(ctx, user.UsernameCtxKey, "alice")
	manager.Put(ctx, user.LastActiveCtxKey, lastActive.Unix())
	manager.Put(ctx, user.SessionVersionKey, sessionVersion)
	manager.Put(ctx, user.RememberMeCtxKey, rememberMe)
	token, _, err := manager.Commit(ctx)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	sessions := mocks.NewMockISessionRepo(ctrl)
	users := mocks.NewMockIUserRepo(ctrl)
	sessions.EXPECT().Manager().Return(manager).AnyTimes()
	sessions.EXPECT().GetSessionConfig().Return(user.SessionConfig{
		NonPersistentIdleTimeout: time.Hour * 8, PersistentSessionIdleTimeout: time.Hour * 24 * 7,
	}).AnyTimes()
	return NewCookieAuthenticator(sessions, users), users, token
}

func httpCookieRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/security/v1alpha1/models/example/model/report", nil)
	r.AddCookie(&http.Cookie{Name: user.CookieName, Value: token})
	return r
}

func TestCookieAuthenticatorAcceptsNativeHTTPLoginSession(t *testing.T) {
	a, users, token := cookieFixture(t, time.Now(), 3, false)
	users.EXPECT().GetUser(gomock.Any(), 7).Return(&user.User{ID: 7, Username: "alice", SessionVersion: 3}, nil)
	identity, next, ok, err := a.Authenticate(context.Background(), httpCookieRequest(token))
	require.NoError(t, err)
	require.True(t, ok)
	require.False(t, next)
	require.Equal(t, 7, identity.GetID())
	require.Equal(t, "alice", identity.GetName())
}

func TestCookieAuthenticatorPreservesGatewayMetadata(t *testing.T) {
	for _, key := range []string{"cookie", "grpcgateway-cookie"} {
		t.Run(key, func(t *testing.T) {
			a, users, token := cookieFixture(t, time.Now(), 3, false)
			users.EXPECT().GetUser(gomock.Any(), 7).Return(&user.User{ID: 7, Username: "alice", SessionVersion: 3}, nil)
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(key, user.CookieName+"="+token))
			identity, next, ok, err := a.Authenticate(ctx, nil)
			require.NoError(t, err)
			require.True(t, ok)
			require.False(t, next)
			require.Equal(t, 7, identity.GetID())
		})
	}
}

func TestCookieAuthenticatorRejectsExpiredIdleSessions(t *testing.T) {
	for _, test := range []struct {
		name       string
		idle       time.Duration
		rememberMe bool
	}{
		{"nonpersistent", time.Hour * 9, false},
		{"persistent", time.Hour * 24 * 8, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, _, token := cookieFixture(t, time.Now().Add(-test.idle), 3, test.rememberMe)
			identity, next, ok, err := a.Authenticate(context.Background(), httpCookieRequest(token))
			require.NoError(t, err)
			require.False(t, ok)
			require.False(t, next)
			require.Nil(t, identity)
		})
	}
}

func TestCookieAuthenticatorRejectsRevokedSessionVersion(t *testing.T) {
	a, users, token := cookieFixture(t, time.Now(), 3, false)
	users.EXPECT().GetUser(gomock.Any(), 7).Return(&user.User{ID: 7, Username: "alice", SessionVersion: 4}, nil)
	identity, next, ok, err := a.Authenticate(context.Background(), httpCookieRequest(token))
	require.NoError(t, err)
	require.False(t, ok)
	require.False(t, next)
	require.Nil(t, identity)
}

func TestCookieAuthenticatorRejectsRequestsWithoutSessionCookie(t *testing.T) {
	a, _, _ := cookieFixture(t, time.Now(), 3, false)
	identity, next, ok, err := a.Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	require.False(t, ok)
	require.True(t, next)
	require.Nil(t, identity)
}
