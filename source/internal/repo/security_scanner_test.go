// Copyright The MatrixHub Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type securityRoundTripper func(*http.Request) (*http.Response, error)

func (f securityRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecurityScannerRequiresCompletePinnedEngineResults(t *testing.T) {
	generation := strings.Repeat("a", 64)
	engines := map[string]string{"clamav": "ClamAV test", "picklescan": "1.0.5"}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"}
	cases := []struct {
		name     string
		analysis security.Analysis
		wantErr  bool
	}{
		{"complete", security.Analysis{Complete: true, Generation: generation, Engines: engines}, false},
		{"incomplete", security.Analysis{Complete: false, Generation: generation, Engines: engines}, true},
		{"generation changed", security.Analysis{Complete: true, Generation: strings.Repeat("c", 64), Engines: engines}, true},
		{"missing engine", security.Analysis{Complete: true, Generation: generation, Engines: map[string]string{"picklescan": "1.0.5"}}, true},
		{"engine changed", security.Analysis{Complete: true, Generation: generation, Engines: map[string]string{"clamav": "other", "picklescan": "1.0.5"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				var value any = security.Bundle{Generation: generation, Engines: engines, MaxFileBytes: 64}
				if req.URL.Path == "/v1/analyze" {
					if req.Header.Get("X-Expected-Generation") != generation {
						t.Fatal("expected bundle not sent")
					}
					var sent security.Artifact
					if err := json.NewDecoder(req.Body).Decode(&sent); err != nil || sent != artifact {
						t.Fatal("artifact context changed")
					}
					value = tc.analysis
				}
				raw, _ := json.Marshal(value)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			_, err := s.Analyze(context.Background(), artifact)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected result: %v", err)
			}
			if calls != 2 {
				t.Fatalf("wanted bundle+analysis; got %d", calls)
			}
		})
	}
}

func TestSecurityScannerRejectsBadDescriptorsAndOversize(t *testing.T) {
	calls := 0
	s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(_ *http.Request) (*http.Response, error) {
		calls++
		raw := `{"generation":"` + strings.Repeat("a", 64) + `","engines":{"clamav":"v","picklescan":"1.0.5"},"maxFileBytes":1}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
	})}}
	a := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 2, Type: "opaque;ext=.pkl"}
	bad := a
	bad.ID = "../../secret"
	if _, err := s.Analyze(context.Background(), bad); err == nil || calls != 0 {
		t.Fatal("unsafe descriptor sent to scanner")
	}
	if _, err := s.Analyze(context.Background(), a); err == nil || calls != 1 {
		t.Fatal("oversize artifact submitted to engine")
	}
}

func TestSecurityScannerDoesNotRelayUntrustedFailureOutput(t *testing.T) {
	s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 422, Body: io.NopCloser(strings.NewReader("private payload must not leave scanner"))}, nil
	})}}
	_, err := s.Bundle(context.Background())
	if err == nil || strings.Contains(err.Error(), "private payload") {
		t.Fatalf("unsafe scanner error: %v", err)
	}
}

func TestSecurityScannerOnlyRelaysAllowlistedFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		wantCode      bool
	}{
		{"unsupported", `{"error":"unsupported_container_or_serialization"}`, true},
		{"unknown", `{"error":"private payload"}`, false},
		{"extra field", `{"error":"unsupported_container_or_serialization","stderr":"private payload"}`, false},
		{"trailing data", `{"error":"unsupported_container_or_serialization"} {"payload":"private payload"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 422, Body: io.NopCloser(strings.NewReader(tc.payload))}, nil
			})}}
			_, err := s.Bundle(context.Background())
			if err == nil || strings.Contains(err.Error(), "private payload") || strings.Contains(err.Error(), "unsupported_container_or_serialization") != tc.wantCode {
				t.Fatalf("unsafe or missing fixed scanner failure: %v", err)
			}
		})
	}
}

func TestSecurityScannerBatchBindsCompleteOrderedResults(t *testing.T) {
	bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64, MaxBatchFiles: 32, MaxBatchBytes: 256}
	artifacts := []security.Artifact{
		{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"},
		{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("2", 32) + ".blob", Digest: strings.Repeat("c", 64), Size: 8, Type: "opaque;ext=.txt"},
	}
	for _, mode := range []string{"complete", "missing", "reordered", "duplicate", "incomplete", "generation", "engine", "invalid-evidence"} {
		t.Run(mode, func(t *testing.T) {
			var results []securityBatchResult
			for _, a := range artifacts {
				results = append(results, securityBatchResult{ArtifactID: a.ID, Analysis: security.Analysis{Complete: true, Generation: bundle.Generation, Engines: bundle.Engines}})
			}
			switch mode {
			case "missing":
				results = results[:1]
			case "reordered":
				results[0], results[1] = results[1], results[0]
			case "duplicate":
				results[1] = results[0]
			case "incomplete":
				results[1].Analysis.Complete = false
			case "generation":
				results[1].Analysis.Generation = strings.Repeat("d", 64)
			case "engine":
				results[1].Analysis.Engines = map[string]string{"picklescan": "1.0.5"}
			case "invalid-evidence":
				finding := securityEvidenceFinding()
				finding.Evidence.Observation = "executed"
				results[1].Analysis.Findings = []security.Finding{finding}
			}
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var value any = bundle
				if req.URL.Path == "/v1/analyze-batch" {
					var request securityBatchRequest
					if err := json.NewDecoder(req.Body).Decode(&request); err != nil || len(request.Artifacts) != 2 || request.Artifacts[0] != artifacts[0] || request.Artifacts[1] != artifacts[1] || req.Header.Get("X-Expected-Generation") != bundle.Generation {
						t.Fatal("batch request lost ordered artifact context")
					}
					value = securityBatchResponse{Results: results}
				}
				raw, _ := json.Marshal(value)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := s.AnalyzeBatch(context.Background(), artifacts)
			if mode == "complete" {
				if err != nil || len(got) != 2 {
					t.Fatalf("complete batch rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatalf("partial or mismatched batch escaped: %v %#v", err, got)
			}
		})
	}
}

func TestSecurityScannerBatchRejectsLegacyCapsAndResourceViolations(t *testing.T) {
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"}
	for _, mode := range []string{"legacy", "file", "total", "duplicate", "empty", "too many"} {
		t.Run(mode, func(t *testing.T) {
			bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64, MaxBatchFiles: 32, MaxBatchBytes: 256}
			artifacts := []security.Artifact{artifact}
			switch mode {
			case "legacy":
				bundle.MaxBatchFiles, bundle.MaxBatchBytes = 0, 0
			case "file":
				bundle.MaxFileBytes = 1
			case "total":
				bundle.MaxBatchBytes = 1
			case "duplicate":
				artifacts = append(artifacts, artifact)
			case "empty":
				artifacts = nil
			case "too many":
				artifacts = make([]security.Artifact, 33)
			}
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/v1/bundle" {
					t.Fatal("invalid batch submitted to engine")
				}
				raw, _ := json.Marshal(bundle)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			if got, err := s.AnalyzeBatch(context.Background(), artifacts); err == nil || got != nil {
				t.Fatalf("invalid batch admitted: %v", err)
			}
		})
	}
}

func securityFileFailureFinding(code string) security.Finding {
	return security.Finding{Engine: "coverage", Rule: "coverage." + code, Severity: "high",
		Message: security.FileAnalysisFailureMessage, Remediation: security.FileAnalysisFailureRemediation}
}

func TestSecurityScannerRetainsOnlyControlledPartialFileAnalyses(t *testing.T) {
	bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"}
	cases := []struct {
		name   string
		change func(*security.Analysis)
		valid  bool
	}{
		{"partial-with-evidence", func(*security.Analysis) {}, true},
		{"bare-incomplete", func(a *security.Analysis) { a.Findings = a.Findings[:1] }, false},
		{"complete-with-coverage", func(a *security.Analysis) { a.Complete = true }, false},
		{"duplicate-coverage", func(a *security.Analysis) { a.Findings = append(a.Findings, a.Findings[1]) }, false},
		{"unknown-code", func(a *security.Analysis) { a.Findings[1].Rule = "coverage.private-payload" }, false},
		{"global-budget-code", func(a *security.Analysis) { a.Findings[1].Rule = "coverage.expanded_bytes_limit" }, false},
		{"missing-prefix", func(a *security.Analysis) { a.Findings[1].Rule = "malformed_pickle" }, false},
		{"wrong-engine", func(a *security.Analysis) { a.Findings[1].Engine = "picklescan" }, false},
		{"wrong-severity", func(a *security.Analysis) { a.Findings[1].Severity = "low" }, false},
		{"untrusted-message", func(a *security.Analysis) { a.Findings[1].Message = "private payload" }, false},
		{"untrusted-remediation", func(a *security.Analysis) { a.Findings[1].Remediation = "private payload" }, false},
		{"coverage-evidence", func(a *security.Analysis) { a.Findings[1].Evidence = securityEvidenceFinding().Evidence }, false},
		{"invalid-sibling-evidence", func(a *security.Analysis) { a.Findings[0].Evidence.Observation = "executed" }, false},
		{"wrong-generation", func(a *security.Analysis) { a.Generation = strings.Repeat("c", 64) }, false},
		{"wrong-engines", func(a *security.Analysis) { a.Engines = map[string]string{"clamav": "other", "picklescan": "1.0.5"} }, false},
		{"negative-duration", func(a *security.Analysis) { a.DurationMs = -1 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analysis := security.Analysis{Generation: bundle.Generation, Engines: bundle.Engines,
				Findings: []security.Finding{securityEvidenceFinding(), securityFileFailureFinding("malformed_pickle")}}
			tc.change(&analysis)
			scanner := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var value any = bundle
				if req.URL.Path == "/v1/analyze" {
					value = analysis
				}
				raw, err := json.Marshal(value)
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := scanner.Analyze(t.Context(), artifact)
			if tc.valid {
				require.NoError(t, err)
				require.False(t, got.Complete)
				require.Len(t, got.Findings, 2)
				require.NotNil(t, got.Findings[0].Evidence)
			} else {
				require.Error(t, err)
				require.Equal(t, security.Analysis{}, got)
				require.NotContains(t, err.Error(), "private payload")
			}
		})
	}
}

func TestSecurityScannerBatchPreservesBoundPartialSiblingResults(t *testing.T) {
	bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64, MaxBatchFiles: 32, MaxBatchBytes: 256}
	artifacts := []security.Artifact{
		{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"},
		{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("2", 32) + ".blob", Digest: strings.Repeat("c", 64), Size: 8, Type: "opaque;ext=.txt"},
	}
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%t", malformed), func(t *testing.T) {
			results := []securityBatchResult{
				{ArtifactID: artifacts[0].ID, Analysis: security.Analysis{Generation: bundle.Generation, Engines: bundle.Engines,
					Findings: []security.Finding{securityEvidenceFinding(), securityFileFailureFinding("malformed_pickle")}}},
				{ArtifactID: artifacts[1].ID, Analysis: security.Analysis{Generation: bundle.Generation, Complete: true, Engines: bundle.Engines}},
			}
			if malformed {
				results[1].ArtifactID = artifacts[0].ID
			}
			scanner := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var value any = bundle
				if req.URL.Path == "/v1/analyze-batch" {
					value = securityBatchResponse{Results: results}
				}
				raw, err := json.Marshal(value)
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := scanner.AnalyzeBatch(t.Context(), artifacts)
			if malformed {
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.Len(t, got, 2)
				require.False(t, got[0].Complete)
				require.True(t, got[1].Complete)
				require.Len(t, got[0].Findings, 2)
			}
		})
	}
}
