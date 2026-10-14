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

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/proto"
)

// ResponseHeaderLocation grpc-gateway 302 redirect
func ResponseHeaderLocation(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	headers := w.Header()
	if location, ok := headers["Grpc-Metadata-Location"]; ok {
		w.Header().Set("Location", location[0])
		w.WriteHeader(http.StatusFound)
	}
	return nil
}

func HeaderMatcher(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	directHeaders := []string{"set-cookie", "content-disposition"}
	if slices.Contains(directHeaders, s) {
		return s, true
	}
	return fmt.Sprintf("%s%s", runtime.MetadataHeaderPrefix, s), true
}
