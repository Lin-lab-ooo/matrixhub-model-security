// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package apiserver

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	backendsecurity "github.com/matrixhub-ai/matrixhub/internal/apiserver/handler/security"
	"github.com/matrixhub-ai/matrixhub/internal/domain/auth"
	domainsecurity "github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/soheilhy/cmux"
	"github.com/stretchr/testify/require"
)

type reviewIdentity struct{ kind string }

func (reviewIdentity) GetID() int         { return 42 }
func (reviewIdentity) GetName() string    { return "reviewer" }
func (r reviewIdentity) TypeName() string { return r.kind }

func TestSecurityReviewActorRequiresHumanUser(t *testing.T) {
	for _, kind := range []string{"user", "robot", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			id, actor := securityReviewActor(auth.WithIdentity(t.Context(), reviewIdentity{kind: kind}))
			if kind == "user" {
				require.Equal(t, int64(42), id)
				require.Equal(t, "user:reviewer", actor)
			} else {
				require.Zero(t, id)
				require.Empty(t, actor)
			}
		})
	}
	id, actor := securityReviewActor(t.Context())
	require.Zero(t, id)
	require.Empty(t, actor)
}

// Use a real connection for every request: a prior GET on a reused connection
// would bypass cmux's initial sniff and conceal its missing PATCH prefix.
func securityHTTP1TestServer(t *testing.T, matcher cmux.Matcher, handler http.Handler) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	multiplexer := cmux.New(listener)
	multiplexer.SetReadTimeout(time.Second)
	multiplexer.Match(cmux.HTTP2())
	httpListener := multiplexer.Match(matcher)
	unmatched := make(chan error, 16)
	multiplexer.HandleError(func(err error) bool {
		var miss cmux.ErrNotMatched
		if errors.As(err, &miss) {
			select {
			case unmatched <- err:
			default:
			}
		}
		return true
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	httpDone, muxDone := make(chan error, 1), make(chan error, 1)
	go func() { httpDone <- server.Serve(httpListener) }()
	go func() { muxDone <- multiplexer.Serve() }()
	t.Cleanup(func() {
		_ = listener.Close()
		multiplexer.Close()
		_ = server.Close()
		for _, done := range []<-chan error{httpDone, muxDone} {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owned HTTP/cmux server did not stop")
			}
		}
	})
	return "http://" + listener.Addr().String(), unmatched
}

func securityHTTP1TestClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestSecurityHTTP1DefaultMatcherRejectsFreshPATCH(t *testing.T) {
	var reached atomic.Int32
	base, unmatched := securityHTTP1TestServer(t, cmux.HTTP1Fast(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	client := securityHTTP1TestClient(t)
	for _, body := range []string{"", `{"comment":"unchanged"}`} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPatch, base+"/reviews", strings.NewReader(body))
		require.NoError(t, err)
		req.Close = true
		response, err := client.Do(req)
		if response != nil {
			_ = response.Body.Close()
		}
		require.Error(t, err)
		require.Nil(t, response)
		var networkError net.Error
		if errors.As(err, &networkError) {
			require.False(t, networkError.Timeout(), "control must reject rather than time out")
		}
		select {
		case err := <-unmatched:
			var miss cmux.ErrNotMatched
			require.ErrorAs(t, err, &miss)
		case <-time.After(time.Second):
			t.Fatal("default matcher did not report its unmatched PATCH")
		}
	}
	require.Zero(t, reached.Load())
}

func TestSecurityHTTP1MatcherRoutesMethodsOnFreshConnections(t *testing.T) {
	base, _ := securityHTTP1TestServer(t, apiHTTP1Matcher(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Observed-Method", r.Method)
		_, _ = w.Write([]byte(r.Method + ":" + string(body)))
	}))
	client := securityHTTP1TestClient(t)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		for _, body := range []string{"", `{"comment":"unchanged"}`} {
			t.Run(method+"/"+map[bool]string{true: "bodyless", false: "json"}[body == ""], func(t *testing.T) {
				req, err := http.NewRequestWithContext(t.Context(), method, base+"/probe", strings.NewReader(body))
				require.NoError(t, err)
				req.Close = true
				response, err := client.Do(req)
				require.NoError(t, err)
				defer response.Body.Close()
				data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode)
				require.Equal(t, method, response.Header.Get("X-Observed-Method"))
				require.Equal(t, method+":"+body, string(data))
			})
		}
	}
}

func TestSecurityReviewUnknownMethodsReturnHTTPRejectionOverTCP(t *testing.T) {
	// Unknown routes must not touch any of the service's absent dependencies.
	svc := domainsecurity.NewService(nil, nil, nil, domainsecurity.Settings{Enabled: true}, nil, nil)
	handler := backendsecurity.NewSecurityHandler(svc)
	base, _ := securityHTTP1TestServer(t, apiHTTP1Matcher(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithIdentity(r.Context(), reviewIdentity{kind: "user"}))
		handler.ServeHTTP(w, r)
	}))
	client := securityHTTP1TestClient(t)
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, body := range []string{"", `{"comment":"unchanged"}`} {
			t.Run(method+"/"+map[bool]string{true: "bodyless", false: "json"}[body == ""], func(t *testing.T) {
				req, err := http.NewRequestWithContext(t.Context(), method, base+"/api/security/v1alpha1/models/project/model/history/12-2/reviews", strings.NewReader(body))
				require.NoError(t, err)
				req.Close = true
				response, err := client.Do(req)
				require.NoError(t, err)
				defer response.Body.Close()
				data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
				require.NoError(t, err)
				require.Equal(t, http.StatusNotFound, response.StatusCode)
				require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
				require.JSONEq(t, `{"code":"RouteNotFound","message":"Security API route not found"}`, string(data))
			})
		}
	}
}
