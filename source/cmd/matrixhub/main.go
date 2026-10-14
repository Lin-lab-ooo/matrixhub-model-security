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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const configFlag = "config"

var rootCmd = &cobra.Command{
	Use:   "matrixhub",
	Short: "MATRIXHUB",
	Long: `matrixhub is an open-source, self-hosted AI model registry engineered for large-scale enterprise inference.

It serves as a drop-in private replacement for Hugging Face, purpose-built to accelerate vLLM and SGLang workloads.`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
