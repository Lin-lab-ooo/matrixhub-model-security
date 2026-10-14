// // Copyright The MatrixHub Authors.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
package model_test

//
// import (
// 	"context"
// 	"crypto/tls"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"
// 	"strings"
// 	"time"
//
// 	v1alpha1model "github.com/matrixhub-ai/matrixhub/test/client/v1alpha1/model"
// 	v1alpha1project "github.com/matrixhub-ai/matrixhub/test/client/v1alpha1/project"
// 	"github.com/matrixhub-ai/matrixhub/test/tools"
//
// 	"github.com/antihax/optional"
// 	. "github.com/onsi/ginkgo/v2"
// 	. "github.com/onsi/gomega"
// )
//
// // Test fixture: README.md with YAML front matter containing metadata tags
// const testReadmeContent = `---
// library_name: transformers
// license: apache-2.0
// pipeline_tag: text-generation
// language:
// - en
// - zh
// tags:
// - pytorch
// ---
//
// # Test Model
//
// This is a test model for metadata sync e2e testing.
// `
//
// // Test fixture: config.json with model architecture info
// const testConfigJSON = `{
//   "architectures": ["LlamaForCausalLM"],
//   "model_type": "llama",
//   "text_config": {
//     "dtype": "bfloat16"
//   },
//   "torch_dtype": "bfloat16"
// }`
//
// // Test fixture: model.safetensors.index.json with total_size for parameter count estimation
// // total_size=26000000000, dtype=bfloat16(2 bytes) => parameter_count=13000000000 (~13B)
// const testSafetensorsIndexJSON = `{
//   "metadata": {
//     "total_size": 26000000000
//   },
//   "weight_map": {
//     "model.embed_tokens.weight": "model-00001-of-00002.safetensors",
//     "model.layers.0.self_attn.q_proj.weight": "model-00001-of-00002.safetensors",
//     "lm_head.weight": "model-00002-of-00002.safetensors"
//   }
// }`
//
// // commitOperation is the NDJSON line format for the HF commit API.
// type commitOperation struct {
// 	Key   string      `json:"key"`
// 	Value interface{} `json:"value"`
// }
//
// type commitHeader struct {
// 	Summary     string `json:"summary"`
// 	Description string `json:"description"`
// }
//
// type commitFile struct {
// 	Path     string `json:"path"`
// 	Content  string `json:"content"`
// 	Encoding string `json:"encoding"`
// }
//
// type commitResponse struct {
// 	CommitURL     string `json:"commitUrl"`
// 	CommitOid     string `json:"commitOid"`
// 	CommitMessage string `json:"commitMessage"`
// }
//
// // buildNDJSON constructs the NDJSON payload for the HF commit API.
// func buildNDJSON(summary string, files map[string]string) string {
// 	var lines []string
//
// 	// Header line
// 	header := commitOperation{
// 		Key:   "header",
// 		Value: commitHeader{Summary: summary, Description: "e2e metadata sync test"},
// 	}
// 	b, _ := json.Marshal(header)
// 	lines = append(lines, string(b))
//
// 	// File lines
// 	for path, content := range files {
// 		fileOp := commitOperation{
// 			Key:   "file",
// 			Value: commitFile{Path: path, Content: content, Encoding: "utf-8"},
// 		}
// 		b, _ := json.Marshal(fileOp)
// 		lines = append(lines, string(b))
// 	}
//
// 	return strings.Join(lines, "\n")
// }
//
// // hfCommit sends an NDJSON commit to the HF-compatible commit API.
// func hfCommit(baseURL, project, model, revision, payload string) (*commitResponse, error) {
// 	url := fmt.Sprintf("%s/api/models/%s/%s/commit/%s", baseURL, project, model, revision)
//
// 	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header.Set("Content-Type", "application/x-ndjson")
//
// 	// Use admin cookie for auth
// 	cookie := tools.GetAdminCookie()
// 	if cookie != "" {
// 		req.Header.Set("Cookie", cookie)
// 	}
//
// 	client := &http.Client{
// 		Transport: &http.Transport{
// 			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
// 		},
// 	}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("commit request failed: %w", err)
// 	}
// 	defer resp.Body.Close()
//
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read response: %w", err)
// 	}
//
// 	if resp.StatusCode >= 300 {
// 		return nil, fmt.Errorf("commit failed: HTTP %d: %s", resp.StatusCode, string(body))
// 	}
//
// 	var commitResp commitResponse
// 	if err := json.Unmarshal(body, &commitResp); err != nil {
// 		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(body))
// 	}
//
// 	return &commitResp, nil
// }
//
// // extractLabelNames extracts label name list from model labels.
// func extractLabelNames(labels []v1alpha1model.MatrixhubV1alpha1Label) []string {
// 	names := make([]string, len(labels))
// 	for i, l := range labels {
// 		names[i] = l.Name
// 	}
// 	return names
// }
//
// var _ = Describe("Model Metadata Sync", Label("model", "metadata-sync"), func() {
// 	var (
// 		ctx         context.Context
// 		modelsApi   *v1alpha1model.ModelsApiService
// 		projectsApi *v1alpha1project.ProjectsApiService
// 		projectName string
// 		modelName   string
// 		baseURL     string
// 	)
//
// 	BeforeEach(func() {
// 		ctx = context.Background()
// 		modelsApi = tools.GetV1alpha1ModelsApi()
// 		projectsApi = tools.GetV1alpha1ProjectsApi()
// 		baseURL = tools.GetBaseURL()
//
// 		// Create project
// 		projectName = tools.GenerateTestProjectName("sync")
// 		_, _, err := projectsApi.ProjectsCreateProject(ctx, v1alpha1project.V1alpha1CreateProjectRequest{
// 			Name: projectName,
// 		})
// 		Expect(err).NotTo(HaveOccurred())
//
// 		// Create model
// 		modelName = tools.GenerateTestModelName("sync")
// 		_, _, err = modelsApi.ModelsCreateModel(ctx, v1alpha1model.V1alpha1CreateModelRequest{
// 			Project: projectName,
// 			Name:    modelName,
// 		})
// 		Expect(err).NotTo(HaveOccurred())
// 	})
//
// 	AfterEach(func() {
// 		_, _, _ = modelsApi.ModelsDeleteModel(ctx, projectName, modelName)
// 		_, _, _ = projectsApi.ProjectsDeleteProject(ctx, projectName)
// 	})
//
// 	// ═══════════════════════════════════════════════════════════
// 	// HF Commit API basic
// 	// ═══════════════════════════════════════════════════════════
// 	Context("HF Commit API", func() {
// 		It("should commit files via NDJSON API", Label("M00039"), func() {
// 			payload := buildNDJSON("add README.md", map[string]string{
// 				"README.md": "# Hello\nThis is a test.",
// 			})
//
// 			commitResp, err := hfCommit(baseURL, projectName, modelName, "main", payload)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(commitResp.CommitOid).NotTo(BeEmpty())
//
// 			GinkgoWriter.Printf("Commit OID: %s\n", commitResp.CommitOid)
// 		})
// 	})
//
// 	// ═══════════════════════════════════════════════════════════
// 	// Full metadata sync + all model API verification
// 	// ═══════════════════════════════════════════════════════════
// 	Context("Metadata sync end-to-end with all model APIs", func() {
// 		It("should sync all metadata and reflect in every model API", Label("M00040"), func() {
// 			By("recording initial model state")
// 			initialModel, _, err := modelsApi.ModelsGetModel(ctx, projectName, modelName)
// 			Expect(err).NotTo(HaveOccurred())
// 			initialReadme := initialModel.ReadmeContent
// 			Expect(len(initialModel.Labels)).To(Equal(0), "new model should have no labels")
//
// 			By("committing README.md + config.json + safetensors index via HF commit API")
// 			payload := buildNDJSON("add model metadata files", map[string]string{
// 				"README.md":                    testReadmeContent,
// 				"config.json":                  testConfigJSON,
// 				"model.safetensors.index.json": testSafetensorsIndexJSON,
// 			})
//
// 			commitResp, err := hfCommit(baseURL, projectName, modelName, "main", payload)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(commitResp.CommitOid).NotTo(BeEmpty())
// 			commitOid := commitResp.CommitOid
// 			GinkgoWriter.Printf("Commit OID: %s\n", commitOid)
//
// 			By("waiting for postReceiveHook to complete metadata sync")
// 			time.Sleep(3 * time.Second)
//
// 			// ── GetModel: verify metadata fields ───────────────
// 			By("verifying GetModel returns synced metadata")
// 			updatedModel, _, err := modelsApi.ModelsGetModel(ctx, projectName, modelName)
// 			Expect(err).NotTo(HaveOccurred())
//
// 			// readmeContent should be updated
// 			Expect(updatedModel.ReadmeContent).NotTo(Equal(initialReadme))
// 			Expect(updatedModel.ReadmeContent).To(ContainSubstring("# Test Model"))
// 			GinkgoWriter.Printf("GetModel: readmeContent length=%d\n", len(updatedModel.ReadmeContent))
//
// 			// parameterCount: 26000000000 / 2 = 13000000000
// 			Expect(updatedModel.ParameterCount).To(Equal("13000000000"))
// 			GinkgoWriter.Printf("GetModel: parameterCount=%s\n", updatedModel.ParameterCount)
//
// 			// labels should be populated from front matter + config
// 			Expect(len(updatedModel.Labels)).To(BeNumerically(">", 0))
// 			labelNames := extractLabelNames(updatedModel.Labels)
// 			GinkgoWriter.Printf("GetModel: labels=%v\n", labelNames)
//
// 			Expect(labelNames).To(ContainElement("text-generation")) // pipeline_tag -> task
// 			Expect(labelNames).To(ContainElement("transformers"))    // library_name -> library
// 			Expect(labelNames).To(ContainElement("apache-2.0"))      // license
// 			Expect(labelNames).To(ContainElement("llama"))           // model_type from config.json
//
// 			// ── ListModels: verify synced model appears with labels ─
// 			By("verifying ListModels returns the model with labels")
// 			listResp, _, err := modelsApi.ModelsListModels(ctx, &v1alpha1model.ModelsApiModelsListModelsOpts{
// 				Project:  optional.NewString(projectName),
// 				Page:     optional.NewInt32(1),
// 				PageSize: optional.NewInt32(10),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
//
// 			var listedModel *v1alpha1model.V1alpha1Model
// 			for i, m := range listResp.Items {
// 				if m.Name == modelName {
// 					listedModel = &listResp.Items[i]
// 					break
// 				}
// 			}
// 			Expect(listedModel).NotTo(BeNil(), "model should appear in ListModels")
// 			Expect(len(listedModel.Labels)).To(BeNumerically(">", 0), "ListModels should include labels")
// 			GinkgoWriter.Printf("ListModels: found model with %d labels\n", len(listedModel.Labels))
//
// 			// ── GetModelTree: verify committed files visible ───
// 			By("verifying GetModelTree shows committed files")
// 			treeResp, _, err := modelsApi.ModelsGetModelTree(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelTreeOpts{})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(len(treeResp.Items)).To(BeNumerically(">=", 3), "tree should contain at least README.md, config.json, safetensors index")
//
// 			treeFileNames := make([]string, len(treeResp.Items))
// 			for i, f := range treeResp.Items {
// 				treeFileNames[i] = f.Name
// 			}
// 			GinkgoWriter.Printf("GetModelTree: files=%v\n", treeFileNames)
//
// 			Expect(treeFileNames).To(ContainElement("README.md"))
// 			Expect(treeFileNames).To(ContainElement("config.json"))
// 			Expect(treeFileNames).To(ContainElement("model.safetensors.index.json"))
//
// 			// Verify tree item structure
// 			for _, f := range treeResp.Items {
// 				Expect(f.Name).NotTo(BeEmpty())
// 				Expect(f.Path).NotTo(BeEmpty())
// 				Expect(f.Type_).NotTo(BeNil())
// 				Expect(*f.Type_).To(Equal(v1alpha1model.FILE_V1alpha1FileType))
// 			}
//
// 			// ── GetModelBlob: verify file content accessible ───
// 			By("verifying GetModelBlob returns committed file data")
// 			blobResp, _, err := modelsApi.ModelsGetModelBlob(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelBlobOpts{
// 				Path: optional.NewString("README.md"),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(blobResp.Name).To(Equal("README.md"))
// 			Expect(blobResp.Path).To(Equal("README.md"))
// 			Expect(blobResp.Type_).NotTo(BeNil())
// 			Expect(*blobResp.Type_).To(Equal(v1alpha1model.FILE_V1alpha1FileType))
// 			GinkgoWriter.Printf("GetModelBlob: name=%s, size=%s, sha256=%s\n", blobResp.Name, blobResp.Size, blobResp.Sha256)
//
// 			// config.json blob
// 			configBlob, _, err := modelsApi.ModelsGetModelBlob(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelBlobOpts{
// 				Path: optional.NewString("config.json"),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(configBlob.Name).To(Equal("config.json"))
//
// 			// ── ListModelRevisions: verify branch exists ───────
// 			By("verifying ListModelRevisions returns main branch")
// 			revResp, _, err := modelsApi.ModelsListModelRevisions(ctx, projectName, modelName)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(revResp.Items).NotTo(BeNil())
// 			Expect(len(revResp.Items.Branches)).To(BeNumerically(">=", 1))
//
// 			var hasMain bool
// 			for _, b := range revResp.Items.Branches {
// 				if b.Name == "main" {
// 					hasMain = true
// 					break
// 				}
// 			}
// 			Expect(hasMain).To(BeTrue(), "should have main branch")
// 			GinkgoWriter.Printf("ListModelRevisions: branches=%d, tags=%d\n",
// 				len(revResp.Items.Branches), len(revResp.Items.Tags))
//
// 			// ── ListModelCommits: verify commit history ────────
// 			By("verifying ListModelCommits includes the commit")
// 			commitsResp, _, err := modelsApi.ModelsListModelCommits(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsListModelCommitsOpts{
// 				Page:     optional.NewInt32(1),
// 				PageSize: optional.NewInt32(10),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(len(commitsResp.Items)).To(BeNumerically(">=", 1))
// 			Expect(commitsResp.Pagination).NotTo(BeNil())
//
// 			// Find our commit
// 			var foundCommit bool
// 			for _, c := range commitsResp.Items {
// 				if c.Id == commitOid {
// 					foundCommit = true
// 					Expect(c.Message).To(ContainSubstring("add model metadata files"))
// 					GinkgoWriter.Printf("ListModelCommits: found commit id=%s, message=%s\n", c.Id[:8], c.Message)
// 					break
// 				}
// 			}
// 			Expect(foundCommit).To(BeTrue(), "commit should appear in ListModelCommits")
//
// 			// ── GetModelCommit: verify commit detail ───────────
// 			By("verifying GetModelCommit returns commit detail")
// 			commitDetail, _, err := modelsApi.ModelsGetModelCommit(ctx, projectName, modelName, commitOid)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(commitDetail.Id).To(Equal(commitOid))
// 			Expect(len(commitDetail.Id)).To(Equal(40), "commit ID should be 40-char SHA-1")
// 			Expect(commitDetail.Message).To(ContainSubstring("add model metadata files"))
// 			Expect(commitDetail.AuthorName).NotTo(BeEmpty())
// 			Expect(commitDetail.AuthorDate).NotTo(BeEmpty())
// 			GinkgoWriter.Printf("GetModelCommit: id=%s, author=%s\n", commitDetail.Id[:8], commitDetail.AuthorName)
//
// 			// ── ListModelTaskLabels: verify global task label ──
// 			By("verifying ListModelTaskLabels includes synced task label")
// 			taskResp, _, err := modelsApi.ModelsListModelTaskLabels(ctx)
// 			Expect(err).NotTo(HaveOccurred())
// 			var hasTaskLabel bool
// 			for _, l := range taskResp.Items {
// 				if l.Name == "text-generation" {
// 					hasTaskLabel = true
// 					break
// 				}
// 			}
// 			Expect(hasTaskLabel).To(BeTrue(), "task labels should include 'text-generation'")
//
// 			// ── ListModelFrameLabels: verify global library label
// 			By("verifying ListModelFrameLabels includes synced library label")
// 			frameResp, _, err := modelsApi.ModelsListModelFrameLabels(ctx)
// 			Expect(err).NotTo(HaveOccurred())
// 			var hasFrameLabel bool
// 			for _, l := range frameResp.Items {
// 				if l.Name == "transformers" {
// 					hasFrameLabel = true
// 					break
// 				}
// 			}
// 			Expect(hasFrameLabel).To(BeTrue(), "library labels should include 'transformers'")
// 		})
//
// 		It("should update metadata when README is replaced with new tags", Label("M00041"), func() {
// 			By("committing initial README with tags")
// 			payload1 := buildNDJSON("initial README", map[string]string{
// 				"README.md": testReadmeContent,
// 			})
// 			_, err := hfCommit(baseURL, projectName, modelName, "main", payload1)
// 			Expect(err).NotTo(HaveOccurred())
// 			time.Sleep(3 * time.Second)
//
// 			model1, _, err := modelsApi.ModelsGetModel(ctx, projectName, modelName)
// 			Expect(err).NotTo(HaveOccurred())
// 			labels1 := extractLabelNames(model1.Labels)
// 			GinkgoWriter.Printf("Labels after first commit: %v\n", labels1)
// 			Expect(labels1).To(ContainElement("text-generation"))
// 			Expect(labels1).To(ContainElement("transformers"))
//
// 			By("committing updated README with different tags")
// 			updatedReadme := `---
// library_name: vllm
// license: mit
// pipeline_tag: text-classification
// language:
// - en
// - fr
// - de
// tags:
// - onnx
// ---
//
// # Updated Model
//
// This model has been updated.
// `
// 			payload2 := buildNDJSON("update README with new tags", map[string]string{
// 				"README.md": updatedReadme,
// 			})
// 			_, err = hfCommit(baseURL, projectName, modelName, "main", payload2)
// 			Expect(err).NotTo(HaveOccurred())
// 			time.Sleep(3 * time.Second)
//
// 			By("verifying GetModel reflects new labels and readme")
// 			model2, _, err := modelsApi.ModelsGetModel(ctx, projectName, modelName)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(model2.ReadmeContent).To(ContainSubstring("# Updated Model"))
//
// 			labels2 := extractLabelNames(model2.Labels)
// 			GinkgoWriter.Printf("Labels after second commit: %v\n", labels2)
//
// 			Expect(labels2).To(ContainElement("text-classification"))
// 			Expect(labels2).To(ContainElement("vllm"))
// 			Expect(labels2).To(ContainElement("mit"))
//
// 			By("verifying GetModelTree shows the same file updated (not duplicated)")
// 			treeResp, _, err := modelsApi.ModelsGetModelTree(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelTreeOpts{})
// 			Expect(err).NotTo(HaveOccurred())
// 			readmeCount := 0
// 			for _, f := range treeResp.Items {
// 				if f.Name == "README.md" {
// 					readmeCount++
// 				}
// 			}
// 			Expect(readmeCount).To(Equal(1), "README.md should appear once, not duplicated")
//
// 			By("verifying ListModelCommits has both commits")
// 			commitsResp, _, err := modelsApi.ModelsListModelCommits(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsListModelCommitsOpts{
// 				Page:     optional.NewInt32(1),
// 				PageSize: optional.NewInt32(10),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			// initial commit (.gitattributes) + 2 metadata commits = at least 3
// 			Expect(len(commitsResp.Items)).To(BeNumerically(">=", 3))
// 			GinkgoWriter.Printf("ListModelCommits: %d commits after 2 updates\n", len(commitsResp.Items))
// 		})
//
// 		It("should reflect metadata in ListModels search and label filter", Label("M00042"), func() {
// 			By("committing metadata files")
// 			payload := buildNDJSON("add metadata for search test", map[string]string{
// 				"README.md":   testReadmeContent,
// 				"config.json": testConfigJSON,
// 			})
// 			_, err := hfCommit(baseURL, projectName, modelName, "main", payload)
// 			Expect(err).NotTo(HaveOccurred())
// 			time.Sleep(3 * time.Second)
//
// 			By("verifying ListModels search finds the model")
// 			searchResp, _, err := modelsApi.ModelsListModels(ctx, &v1alpha1model.ModelsApiModelsListModelsOpts{
// 				Project:  optional.NewString(projectName),
// 				Search:   optional.NewString(modelName),
// 				Page:     optional.NewInt32(1),
// 				PageSize: optional.NewInt32(10),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(len(searchResp.Items)).To(BeNumerically(">=", 1))
//
// 			var foundModel *v1alpha1model.V1alpha1Model
// 			for i, m := range searchResp.Items {
// 				if m.Name == modelName {
// 					foundModel = &searchResp.Items[i]
// 					break
// 				}
// 			}
// 			Expect(foundModel).NotTo(BeNil())
// 			Expect(len(foundModel.Labels)).To(BeNumerically(">", 0))
// 			GinkgoWriter.Printf("ListModels search: found model with %d labels\n", len(foundModel.Labels))
// 		})
//
// 		It("should allow GetModelTree and GetModelBlob with revision=main", Label("M00043"), func() {
// 			By("committing files")
// 			payload := buildNDJSON("add files for revision test", map[string]string{
// 				"README.md":   testReadmeContent,
// 				"config.json": testConfigJSON,
// 			})
// 			_, err := hfCommit(baseURL, projectName, modelName, "main", payload)
// 			Expect(err).NotTo(HaveOccurred())
// 			time.Sleep(2 * time.Second)
//
// 			By("verifying GetModelTree with revision=main")
// 			treeResp, _, err := modelsApi.ModelsGetModelTree(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelTreeOpts{
// 				Revision: optional.NewString("main"),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(len(treeResp.Items)).To(BeNumerically(">=", 2))
//
// 			By("verifying GetModelBlob with revision=main")
// 			blobResp, _, err := modelsApi.ModelsGetModelBlob(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsGetModelBlobOpts{
// 				Revision: optional.NewString("main"),
// 				Path:     optional.NewString("config.json"),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(blobResp.Name).To(Equal("config.json"))
// 			Expect(*blobResp.Type_).To(Equal(v1alpha1model.FILE_V1alpha1FileType))
// 			GinkgoWriter.Printf("GetModelBlob revision=main: name=%s, size=%s\n", blobResp.Name, blobResp.Size)
// 		})
//
// 		It("should allow ListModelCommits with revision=main", Label("M00044"), func() {
// 			By("committing a file")
// 			payload := buildNDJSON("add file for commit revision test", map[string]string{
// 				"README.md": testReadmeContent,
// 			})
// 			_, err := hfCommit(baseURL, projectName, modelName, "main", payload)
// 			Expect(err).NotTo(HaveOccurred())
// 			time.Sleep(2 * time.Second)
//
// 			By("verifying ListModelCommits with revision=main")
// 			commitsResp, _, err := modelsApi.ModelsListModelCommits(ctx, projectName, modelName, &v1alpha1model.ModelsApiModelsListModelCommitsOpts{
// 				Revision: optional.NewString("main"),
// 				Page:     optional.NewInt32(1),
// 				PageSize: optional.NewInt32(10),
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(len(commitsResp.Items)).To(BeNumerically(">=", 1))
// 			Expect(commitsResp.Pagination).NotTo(BeNil())
// 			GinkgoWriter.Printf("ListModelCommits revision=main: %d commits\n", len(commitsResp.Items))
// 		})
// 	})
// })
