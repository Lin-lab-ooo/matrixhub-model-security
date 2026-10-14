// Copyright The MatrixHub Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"context"
	"testing"

	"github.com/matrixhub-ai/matrixhub/api/go/v1alpha1"
	"github.com/matrixhub-ai/matrixhub/internal/infra/config"
	"github.com/matrixhub-ai/matrixhub/internal/repo"
)

func TestSystemHandler_GetSystemConfig(t *testing.T) {
	cases := []struct {
		name        string
		externalURL string
		want        string
	}{
		{"plain", "https://matrixhub.example.com", "https://matrixhub.example.com"},
		{"trailing slash trimmed", "https://matrixhub.example.com/", "https://matrixhub.example.com"},
		{"empty when not configured", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := repo.NewSystemProvider(&config.Config{
				APIServer: &config.APIServerConfig{ExternalURL: tc.externalURL},
			})
			h := NewSystemHandler(svc).(*SystemHandler)
			resp, err := h.GetSystemConfig(context.Background(), &v1alpha1.GetSystemConfigRequest{})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if resp.GetEndpoints().GetHfBase() != tc.want {
				t.Fatalf("hf_base = %q, want %q", resp.GetEndpoints().GetHfBase(), tc.want)
			}
		})
	}
}
