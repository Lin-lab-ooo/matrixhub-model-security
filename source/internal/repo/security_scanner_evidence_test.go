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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func securityEvidenceNumber(n int64) *int64 { return &n }

func securityEvidenceFinding() security.Finding {
	return security.Finding{
		Engine: "picklescan", Rule: "pickle.nested-deserialization-reference", Severity: "high",
		Message: "Static reference, not proof of invocation or malicious execution.",
		Evidence: &security.FindingEvidence{
			KnownSymbolID: "torch-storage-load-from-bytes-v1", Observation: "reference", Source: "pickletools",
			StreamIndex: securityEvidenceNumber(0), OpcodeOffset: securityEvidenceNumber(0),
		},
	}
}

func TestSecurityScannerEvidencePreservesLegacyAndExactLocations(t *testing.T) {
	bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"}
	for _, mode := range []string{"legacy", "direct-zero", "archive", "picklescan-unknown"} {
		t.Run(mode, func(t *testing.T) {
			finding := securityEvidenceFinding()
			switch mode {
			case "legacy":
				finding.Rule = "pickle.unknown-global"
				finding.Severity = "medium"
				finding.Evidence = nil
			case "archive":
				finding.Evidence.StreamIndex = securityEvidenceNumber(1)
				finding.Evidence.OpcodeOffset = securityEvidenceNumber(37)
				finding.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{
					{MemberIndex: securityEvidenceNumber(0), NameSHA256: strings.Repeat("c", 64)},
					{MemberIndex: securityEvidenceNumber(2), NameSHA256: strings.Repeat("d", 64)},
				}
			case "picklescan-unknown":
				finding.Evidence.Source = "picklescan"
				finding.Evidence.StreamIndex = nil
				finding.Evidence.OpcodeOffset = nil
			}
			analysis := security.Analysis{Generation: bundle.Generation, Complete: true, Engines: bundle.Engines, Findings: []security.Finding{finding}}
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var value any = bundle
				if req.URL.Path == "/v1/analyze" {
					require.Equal(t, bundle.Generation, req.Header.Get("X-Expected-Generation"))
					value = analysis
				}
				raw, err := json.Marshal(value)
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := s.Analyze(context.Background(), artifact)
			require.NoError(t, err)
			require.Equal(t, analysis, got)
			raw, err := json.Marshal(got.Findings[0])
			require.NoError(t, err)
			switch mode {
			case "legacy":
				require.NotContains(t, string(raw), `"evidence"`)
			case "direct-zero":
				require.Contains(t, string(raw), `"streamIndex":0`)
				require.Contains(t, string(raw), `"opcodeOffset":0`)
			case "picklescan-unknown":
				require.Contains(t, string(raw), `"streamIndex":null`)
				require.Contains(t, string(raw), `"opcodeOffset":null`)
			}
		})
	}
}

func TestSecurityScannerRequiresEvidenceForCapabilityRule(t *testing.T) {
	bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}, MaxFileBytes: 64}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob", Digest: strings.Repeat("b", 64), Size: 4, Type: "opaque;ext=.pkl"}
	for _, tc := range []struct {
		name, rule, severity, evidence string
		wantErr                        bool
	}{
		{"missing-high", "pickle.nested-deserialization-reference", "high", "", true},
		{"missing-downgraded", "pickle.nested-deserialization-reference", "medium", "", true},
		{"null-high", "pickle.nested-deserialization-reference", "high", `,"evidence":null`, true},
		{"null-downgraded", "pickle.nested-deserialization-reference", "medium", `,"evidence":null`, true},
		{"legacy-missing", "pickle.unknown-global", "medium", "", false},
		{"legacy-null", "pickle.unknown-global", "medium", `,"evidence":null`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var raw []byte
				if req.URL.Path == "/v1/bundle" {
					var err error
					raw, err = json.Marshal(bundle)
					require.NoError(t, err)
				} else {
					raw = []byte(`{"generation":"` + bundle.Generation + `","complete":true,"engines":{"clamav":"v","picklescan":"1.0.5"},"findings":[{"engine":"picklescan","rule":"` + tc.rule + `","severity":"` + tc.severity + `","message":"static reference","remediation":"review"` + tc.evidence + `}]}`)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := s.Analyze(context.Background(), artifact)
			if tc.wantErr {
				require.EqualError(t, err, "invalid isolated scanner finding evidence")
				require.Equal(t, security.Analysis{}, got)
			} else {
				require.NoError(t, err)
				require.Len(t, got.Findings, 1)
				require.Nil(t, got.Findings[0].Evidence)
			}
		})
	}
}

func TestSecurityScannerRejectsMisleadingOrUnboundedEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*security.Finding)
	}{
		{"unrelated-engine", func(f *security.Finding) { f.Engine = "clamav" }},
		{"unrelated-rule", func(f *security.Finding) { f.Rule = "pickle.unknown-global" }},
		{"wrong-severity", func(f *security.Finding) { f.Severity = "medium" }},
		{"unknown-symbol", func(f *security.Finding) { f.Evidence.KnownSymbolID = "private payload" }},
		{"execution-claim", func(f *security.Finding) { f.Evidence.Observation = "executed" }},
		{"unknown-source", func(f *security.Finding) { f.Evidence.Source = "private payload" }},
		{"missing-stream", func(f *security.Finding) { f.Evidence.StreamIndex = nil }},
		{"missing-offset", func(f *security.Finding) { f.Evidence.OpcodeOffset = nil }},
		{"negative-stream", func(f *security.Finding) { f.Evidence.StreamIndex = securityEvidenceNumber(-1) }},
		{"negative-offset", func(f *security.Finding) { f.Evidence.OpcodeOffset = securityEvidenceNumber(-1) }},
		{"imprecise-stream", func(f *security.Finding) { f.Evidence.StreamIndex = securityEvidenceNumber(1 << 53) }},
		{"imprecise-offset", func(f *security.Finding) { f.Evidence.OpcodeOffset = securityEvidenceNumber(1 << 53) }},
		{"unlocated-engine-claims-location", func(f *security.Finding) { f.Evidence.Source = "picklescan" }},
		{"missing-member-index", func(f *security.Finding) {
			f.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{{NameSHA256: strings.Repeat("a", 64)}}
		}},
		{"negative-member-index", func(f *security.Finding) {
			f.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{{MemberIndex: securityEvidenceNumber(-1), NameSHA256: strings.Repeat("a", 64)}}
		}},
		{"imprecise-member-index", func(f *security.Finding) {
			f.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{{MemberIndex: securityEvidenceNumber(1 << 53), NameSHA256: strings.Repeat("a", 64)}}
		}},
		{"raw-member-name", func(f *security.Finding) {
			f.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{{MemberIndex: securityEvidenceNumber(0), NameSHA256: "private payload"}}
		}},
		{"excess-archive-depth", func(f *security.Finding) {
			for range securityEvidenceMaxArchiveDepth + 1 {
				f.Evidence.ArchiveMemberChain = append(f.Evidence.ArchiveMemberChain, security.ArchiveMemberEvidence{MemberIndex: securityEvidenceNumber(0), NameSHA256: strings.Repeat("a", 64)})
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding := securityEvidenceFinding()
			tc.change(&finding)
			bundle := security.Bundle{Generation: "generation", Engines: map[string]string{"clamav": "v", "picklescan": "1.0.5"}}
			analysis := security.Analysis{Generation: bundle.Generation, Complete: true, Engines: bundle.Engines, Findings: []security.Finding{finding}}
			err := validateSecurityAnalysis(bundle, analysis)
			require.EqualError(t, err, "invalid isolated scanner finding evidence")
			require.NotContains(t, err.Error(), "private payload")
		})
	}
}

func TestSecurityScannerEvidenceStrictlyRejectsUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
	}{
		{"unknown-evidence-field", `{"knownSymbolId":"torch-storage-load-from-bytes-v1","observation":"reference","source":"pickletools","archiveMemberChain":null,"streamIndex":0,"opcodeOffset":0,"payload":"private payload"}`},
		{"unknown-member-field", `{"knownSymbolId":"torch-storage-load-from-bytes-v1","observation":"reference","source":"pickletools","archiveMemberChain":[{"memberIndex":0,"nameSha256":"` + strings.Repeat("a", 64) + `","name":"private payload"}],"streamIndex":0,"opcodeOffset":0}`},
		{"fractional-position", `{"knownSymbolId":"torch-storage-load-from-bytes-v1","observation":"reference","source":"pickletools","archiveMemberChain":null,"streamIndex":0.5,"opcodeOffset":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var evidence security.FindingEvidence
			require.EqualError(t, json.Unmarshal([]byte(tc.payload), &evidence), "invalid finding evidence object")
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(_ *http.Request) (*http.Response, error) {
				raw := `{"findings":[{"engine":"picklescan","rule":"pickle.nested-deserialization-reference","severity":"high","evidence":` + tc.payload + `}]}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(raw))}, nil
			})}}
			var analysis security.Analysis
			err := s.exchange(context.Background(), http.MethodPost, "/v1/analyze", "generation", nil, &analysis)
			require.EqualError(t, err, "invalid isolated scanner response")
			require.NotContains(t, err.Error(), "private payload")
		})
	}
}

func TestSecurityScannerEvidenceRequiresExplicitNullableFields(t *testing.T) {
	base := map[string]any{
		"knownSymbolId": "torch-storage-load-from-bytes-v1", "observation": "reference", "source": "picklescan",
		"archiveMemberChain": nil, "streamIndex": nil, "opcodeOffset": nil,
	}
	for _, key := range []string{"knownSymbolId", "observation", "source", "archiveMemberChain", "streamIndex", "opcodeOffset"} {
		t.Run("missing-"+key, func(t *testing.T) {
			fields := make(map[string]any, len(base))
			for name, value := range base {
				if name != key {
					fields[name] = value
				}
			}
			raw, err := json.Marshal(fields)
			require.NoError(t, err)
			var evidence security.FindingEvidence
			require.EqualError(t, json.Unmarshal(raw, &evidence), "invalid finding evidence object")
		})
	}
	for _, key := range []string{"knownSymbolId", "observation", "source"} {
		t.Run("null-"+key, func(t *testing.T) {
			fields := make(map[string]any, len(base))
			for name, value := range base {
				fields[name] = value
			}
			fields[key] = nil
			raw, err := json.Marshal(fields)
			require.NoError(t, err)
			var evidence security.FindingEvidence
			require.EqualError(t, json.Unmarshal(raw, &evidence), "invalid finding evidence object")
		})
	}
	raw, err := json.Marshal(base)
	require.NoError(t, err)
	var evidence security.FindingEvidence
	require.NoError(t, json.Unmarshal(raw, &evidence))
	require.Nil(t, evidence.ArchiveMemberChain)
	require.Nil(t, evidence.StreamIndex)
	require.Nil(t, evidence.OpcodeOffset)
}
