// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/stretchr/testify/require"
)

func TestSecurityLargeBatchUsesBoundedDescriptorsAndAdvertisedLimits(t *testing.T) {
	for _, advertisedBytes := range []int64{256 << 20, security.MaxScanBatchBytes} {
		t.Run(fmt.Sprint(advertisedBytes), func(t *testing.T) {
			bundle := security.Bundle{Generation: strings.Repeat("a", 64), Engines: map[string]string{"clamav": "fixture", "picklescan": "fixture"},
				MaxFileBytes: 1280 << 20, MaxBatchFiles: 32, MaxBatchBytes: advertisedBytes}
			artifacts := make([]security.Artifact, 4)
			results := make([]securityBatchResult, len(artifacts))
			for i := range artifacts {
				artifacts[i] = security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat(fmt.Sprint(i+1), 32) + ".blob",
					Digest: strings.Repeat("b", 64), Size: 1280 << 20, Type: "opaque;ext=.safetensors"}
				results[i] = securityBatchResult{ArtifactID: artifacts[i].ID, Analysis: security.Analysis{Complete: true, Generation: bundle.Generation, Engines: bundle.Engines}}
			}
			posts := 0
			s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(req *http.Request) (*http.Response, error) {
				var response any = bundle
				if req.URL.Path == "/v1/analyze-batch" {
					posts++
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					require.Less(t, len(body), 16<<10)
					var descriptors securityBatchRequest
					require.NoError(t, json.Unmarshal(body, &descriptors))
					require.Equal(t, artifacts, descriptors.Artifacts)
					response = securityBatchResponse{Results: results}
				}
				raw, err := json.Marshal(response)
				require.NoError(t, err)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := s.AnalyzeBatch(t.Context(), artifacts)
			if advertisedBytes == security.MaxScanBatchBytes {
				require.NoError(t, err)
				require.Len(t, got, 4)
				require.Equal(t, 1, posts)
			} else {
				require.Error(t, err)
				require.Nil(t, got)
				require.Zero(t, posts)
			}
		})
	}
}

func TestSecurityBatchProtocolCeilingCannotBeOverriddenByScanner(t *testing.T) {
	s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("oversize descriptors reached scanner transport")
		return nil, nil
	})}}
	artifact := security.Artifact{ID: "task-1-1-0123456789abcdef/" + strings.Repeat("1", 32) + ".blob",
		Digest: strings.Repeat("b", 64), Size: security.MaxScanBatchBytes + 1, Type: "opaque;ext=.safetensors"}
	_, err := s.AnalyzeBatch(t.Context(), []security.Artifact{artifact})
	require.ErrorContains(t, err, "byte limit")
}

func TestSecurityRulesExpiredErrorRemainsFixedAndFailClosed(t *testing.T) {
	s := &SecurityScanner{client: &http.Client{Transport: securityRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"rules_expired"}`))}, nil
	})}}
	_, err := s.Bundle(t.Context())
	require.ErrorContains(t, err, "rules_expired")
}
