// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func TestSecurityPrefixProtocolNeverApproves(t *testing.T) {
	generation := strings.Repeat("a", 64)
	prefix := []byte{0x80, 2, '.', 0}
	digest := fmt.Sprintf("%x", sha256.Sum256(prefix))
	for _, tc := range []struct {
		name, status, reason, mutation string
		http                           int
		wantErr                        bool
	}{
		{"pending", "pending", "", "", 200, false},
		{"reject", "reject", "invalid_serialization", "", 200, true},
		{"unknown-reject-code", "reject", "attacker supplied text", "", 200, true},
		{"no-approval", "pass", "", "", 200, true},
		{"pending-with-reason", "pending", "invalid_serialization", "", 200, true},
		{"wrong-generation", "pending", "", "generation", 200, true},
		{"wrong-digest", "pending", "", "digest", 200, true},
		{"wrong-size", "pending", "", "size", 200, true},
		{"extra-field", "pending", "", "extra", 200, true},
		{"missing-reason", "pending", "", "missing-reason", 200, true},
		{"null-reason", "pending", "", "null-reason", 200, true},
		{"busy-fallback", "", "", "busy", 503, false},
		{"timeout-no-fallback", "", "", "timeout", 503, true},
		{"old-bundle", "", "", "old", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var value any
				code := 200
				if req.URL.Path == "/v1/bundle" {
					b := security.Bundle{Generation: generation, Engines: map[string]string{"clamav": "test", "picklescan": "test"}, MaxFileBytes: 1 << 20, MaxPrefixBytes: securityPrefixBytes}
					if tc.mutation == "old" {
						b.MaxPrefixBytes = 0
					}
					value = b
				} else {
					calls++
					if req.URL.Path != "/v1/probe-legacy-prefix" || req.Header.Get("X-Expected-Generation") != generation {
						t.Fatal("incorrect endpoint or generation")
					}
					var sent map[string]any
					if err := json.NewDecoder(req.Body).Decode(&sent); err != nil {
						t.Fatal(err)
					}
					if len(sent) != 4 || sent["prefixBase64"] != base64.StdEncoding.EncodeToString(prefix) || sent["prefixSha256"] != digest || sent["prefixBytes"] != float64(len(prefix)) || sent["sourceSize"] != float64(100000) {
						t.Fatal("prefix binding changed")
					}
					v := map[string]any{"generation": generation, "prefixSha256": digest, "prefixBytes": len(prefix), "status": tc.status, "reason": tc.reason}
					switch tc.mutation {
					case "generation":
						v["generation"] = strings.Repeat("b", 64)
					case "digest":
						v["prefixSha256"] = strings.Repeat("b", 64)
					case "size":
						v["prefixBytes"] = len(prefix) + 1
					case "extra":
						v["complete"] = true
					case "missing-reason":
						delete(v, "reason")
					case "null-reason":
						v["reason"] = nil
					case "busy":
						v = map[string]any{"error": "scanner_busy"}
					case "timeout":
						v = map[string]any{"error": "scan_timeout"}
					}
					value, code = v, tc.http
				}
				raw, _ := json.Marshal(value)
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			err := s.ProbeLegacyPrefix(t.Context(), generation, prefix, 100000)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected result: %v", err)
			}
			if (tc.mutation == "old" && calls != 0) || (tc.mutation != "old" && calls != 1) {
				t.Fatalf("calls %d", calls)
			}
		})
	}
}
