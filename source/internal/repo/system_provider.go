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

package repo

import (
	"context"
	"strings"

	"github.com/matrixhub-ai/matrixhub/internal/domain/system"
	"github.com/matrixhub-ai/matrixhub/internal/infra/config"
)

type systemProvider struct {
	externalURL string
}

func NewSystemProvider(cfg *config.Config) system.IService {
	externalURL := ""
	if cfg != nil && cfg.APIServer != nil {
		externalURL = strings.TrimRight(cfg.APIServer.ExternalURL, "/")
	}
	return &systemProvider{externalURL: externalURL}
}

func (p *systemProvider) GetPublicConfig(_ context.Context) (*system.PublicConfig, error) {
	return &system.PublicConfig{
		Endpoints: system.Endpoints{
			HfBase: p.externalURL,
		},
	}, nil
}
