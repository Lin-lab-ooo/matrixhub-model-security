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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/matrixhub-ai/matrixhub/api/go/v1alpha1"
	"github.com/matrixhub-ai/matrixhub/internal/domain/system"
	"github.com/matrixhub-ai/matrixhub/internal/infra/log"
)

type SystemHandler struct {
	svc system.IService
}

func NewSystemHandler(svc system.IService) IHandler {
	return &SystemHandler{svc: svc}
}

func (h *SystemHandler) GetSystemConfig(ctx context.Context, _ *v1alpha1.GetSystemConfigRequest) (*v1alpha1.SystemConfig, error) {
	cfg, err := h.svc.GetPublicConfig(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1alpha1.SystemConfig{
		Endpoints: &v1alpha1.Endpoints{
			HfBase: cfg.Endpoints.HfBase,
		},
	}, nil
}

func (h *SystemHandler) RegisterToServer(options *ServerOptions) {
	v1alpha1.RegisterSystemServiceServer(options.GRPCServer, h)
	if err := v1alpha1.RegisterSystemServiceHandlerFromEndpoint(context.Background(), options.GatewayMux, options.GRPCAddr, options.GRPCDialOpt); err != nil {
		log.Errorf("register system handler error: %s", err.Error())
	}
}
