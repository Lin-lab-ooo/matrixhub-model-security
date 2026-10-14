// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func awaitSecurityGate(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("scanner gate synchronization timeout")
		}
		runtime.Gosched()
	}
}

func TestSecurityFullScanWaitsForPrefixAndPrioritizesCompleteWork(t *testing.T) {
	generation := strings.Repeat("a", 64)
	bundle := security.Bundle{Generation: generation, Engines: map[string]string{"clamav": "fixture", "picklescan": "fixture"}, MaxFileBytes: 1 << 20, MaxPrefixBytes: securityPrefixBytes}
	prefixStarted, releasePrefix := make(chan struct{}), make(chan struct{})
	var prefixCalls, fullCalls atomic.Int32
	s := &SecurityScanner{client: &http.Client{Timeout: 5 * time.Second, Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
		var response any = bundle
		switch req.URL.Path {
		case "/v1/probe-legacy-prefix":
			if prefixCalls.Add(1) != 1 {
				t.Error("optional prefix bypassed full-scan priority")
			}
			var request map[string]any
			if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
				return nil, err
			}
			close(prefixStarted)
			select {
			case <-releasePrefix:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
			response = map[string]any{"generation": generation, "prefixSha256": request["prefixSha256"], "prefixBytes": request["prefixBytes"], "status": "pending", "reason": ""}
		case "/v1/analyze":
			fullCalls.Add(1)
			response = security.Analysis{Generation: generation, Complete: true, Engines: bundle.Engines}
		}
		raw, _ := json.Marshal(response)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	probeDone, fullDone := make(chan error, 1), make(chan error, 1)
	go func() { probeDone <- s.ProbeLegacyPrefix(ctx, generation, []byte{0x80, 2}, 100000) }()
	select {
	case <-prefixStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "pickle;ext=.pt"}
	go func() { _, err := s.Analyze(ctx, artifact); fullDone <- err }()
	awaitSecurityGate(t, func() bool { return s.waitingFull.Load() == 1 })
	if err := s.ProbeLegacyPrefix(ctx, generation, []byte{0x80, 2}, 100000); err != nil {
		t.Fatal(err)
	}
	if prefixCalls.Load() != 1 || fullCalls.Load() != 0 {
		t.Fatal("full scan and prefix overlapped in scanner worker")
	}
	close(releasePrefix)
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-fullDone; err != nil {
		t.Fatal(err)
	}
	if fullCalls.Load() != 1 {
		t.Fatal("mandatory scan was dropped")
	}
}

func TestSecurityScannerQueueCancellationAndDeadlineDoNotLeakPermit(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		s := &SecurityScanner{client: &http.Client{Timeout: 50 * time.Millisecond}}
		if !s.tryPrefixPermit() {
			t.Fatal("cannot acquire fixture prefix permit")
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, release, err := s.acquireFullPermit(ctx)
			if release != nil {
				release()
			}
			done <- err
		}()
		awaitSecurityGate(t, func() bool { return s.waitingFull.Load() == 1 })
		if !deadline {
			cancel()
		}
		err := <-done
		cancel()
		if deadline && !errors.Is(err, context.DeadlineExceeded) || !deadline && !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong queued failure: %v", err)
		}
		if s.waitingFull.Load() != 0 {
			t.Fatal("cancelled waiter leaked")
		}
		s.releasePermit()
		_, release, err := s.acquireFullPermit(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		release()
		if !s.tryPrefixPermit() {
			t.Fatal("permit leaked after cancellation")
		}
		s.releasePermit()
	}
}

func TestSecurityCompleteRetriesOnlyStrictBusyWithSameBinding(t *testing.T) {
	for _, endpoint := range []string{"/v1/analyze", "/v1/analyze-batch"} {
		t.Run(endpoint, func(t *testing.T) {
			generation := strings.Repeat("a", 64)
			var calls int
			var firstBody string
			s := &SecurityScanner{client: &http.Client{Timeout: time.Second, Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				raw, _ := io.ReadAll(req.Body)
				if calls == 1 {
					firstBody = string(raw)
				}
				if string(raw) != firstBody || req.URL.Path != endpoint || req.Header.Get("X-Expected-Generation") != generation {
					t.Error("retry binding changed")
				}
				status, body := 200, `{"accepted":true}`
				if calls == 1 {
					status, body = 503, `{"error":"scanner_busy"}`
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var response struct {
				Accepted bool `json:"accepted"`
			}
			if err := s.exchangeComplete(ctx, endpoint, generation, map[string]string{"artifactId": "fixed"}, &response); err != nil || !response.Accepted || calls != 2 {
				t.Fatalf("retry: %v %d %+v", err, calls, response)
			}
		})
	}
	for _, tc := range []struct {
		status int
		body   string
		busy   bool
	}{
		{503, `{"error":"scanner_busy"}`, true},
		{503, `{"error":"scan_timeout"}`, false},
		{422, `{"error":"scanner_busy"}`, false},
		{503, `{"error":"scanner_busy","extra":true}`, false},
		{429, `{"error":"scanner_busy"}`, false},
	} {
		calls := 0
		s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}}
		ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
		err := s.exchangeComplete(ctx, "/v1/analyze", strings.Repeat("a", 64), nil, new(any))
		cancel()
		if err == nil || calls != 1 || tc.busy && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected retry status=%d busy=%v calls=%d error=%v", tc.status, tc.busy, calls, err)
		}
	}
}
