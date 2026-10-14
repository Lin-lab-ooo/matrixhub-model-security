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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

const securityMaxResponseBytes = 2 << 20

var errSecurityScannerBusy = errors.New("isolated scanner busy; final scan still required")

// Only fixed protocol codes may leave the isolated service. Engine stderr,
// unknown strings, extra fields and malformed responses remain generic.
var securityScannerErrorCodes = map[string]bool{}

func init() {
	for _, code := range strings.Fields(`rules_changed invalid_descriptor invalid_artifact_id
invalid_digest file_limit invalid_analysis_context snapshot_size snapshot_digest
expanded_bytes_limit archive_depth_limit unsupported_container_or_serialization
numpy_serialization_not_supported pickle_opcode_limit pickle_argument_limit
archive_member_limit archive_member_size duplicate_archive_member encrypted_archive
archive_symlink archive_ratio_limit archive_link_or_special_file
pickle_extension_registry_unsupported malformed_pickle empty_pickle
pickle_analysis_incomplete finding_limit invalid_safetensors_header
invalid_safetensors_offsets clamav_output_limit clamav_unavailable_or_failed
clamav_coverage_incomplete clamav_invalid_result clamav_unexpected_output
scan_timeout scan_cancelled worker_output_limit worker_failed_or_incomplete
request_limit invalid_serialization scan_incomplete scanner_busy invalid_request
rules_changed_restart_required generation_changed not_found batch_limit
batch_duplicate_artifact clamav_missing_result clamav_unknown_result`) {
		securityScannerErrorCodes[code] = true
	}
}

// SecurityScanner speaks only HTTP over a local Unix socket. It has no TCP
// fallback, proxy, remote URL, or endpoint supplied by artifact metadata.
type SecurityScanner struct {
	client      *http.Client
	permitOnce  sync.Once
	permit      chan struct{}
	waitingFull atomic.Int64
}

func NewSecurityScanner(socketPath string, timeout time.Duration) (*SecurityScanner, error) {
	if !filepath.IsAbs(socketPath) || strings.ContainsRune(socketPath, 0) || timeout <= 0 {
		return nil, errors.New("isolated scanner requires an absolute Unix socket and positive timeout")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout: timeout, DisableCompression: true,
	}
	return &SecurityScanner{client: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("scanner redirects are forbidden") }}}, nil
}

func (s *SecurityScanner) exchange(ctx context.Context, method, endpoint, generation string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://scanner"+endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if generation != "" {
		req.Header.Set("X-Expected-Generation", generation)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("isolated scanner unavailable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, securityMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > securityMaxResponseBytes {
		return errors.New("isolated scanner response exceeded limit")
	}
	// Do not relay scanner stderr, artifact contents, or untrusted field values.
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		failureDecoder := json.NewDecoder(bytes.NewReader(raw))
		failureDecoder.DisallowUnknownFields()
		if failureDecoder.Decode(&failure) == nil && failureDecoder.Decode(new(any)) == io.EOF && securityScannerErrorCodes[failure.Error] {
			if resp.StatusCode == http.StatusServiceUnavailable && failure.Error == "scanner_busy" {
				return errSecurityScannerBusy
			}
			return fmt.Errorf("isolated scanner did not complete analysis: %s (HTTP %d)", failure.Error, resp.StatusCode)
		}
		return fmt.Errorf("isolated scanner did not complete analysis (HTTP %d)", resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(output); err != nil {
		return errors.New("invalid isolated scanner response")
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing isolated scanner response data")
	}
	return nil
}

func (s *SecurityScanner) Bundle(ctx context.Context) (security.Bundle, error) {
	var b security.Bundle
	if err := s.exchange(ctx, http.MethodGet, "/v1/bundle", "", nil, &b); err != nil {
		return b, err
	}
	if !validDigest(b.Generation) || b.MaxFileBytes <= 0 || b.MaxPrefixBytes < 0 || b.MaxPrefixBytes > securityPrefixBytes || b.Engines["clamav"] == "" || b.Engines["picklescan"] == "" {
		return b, errors.New("scanner bundle lacks complete required engines or immutable generation")
	}
	return b, nil
}

func (s *SecurityScanner) ProbeLegacyPrefix(ctx context.Context, generation string, prefix []byte, sourceSize int64) error {
	if !validDigest(generation) || len(prefix) < 1 || len(prefix) > securityPrefixBytes || sourceSize < int64(len(prefix)) {
		return errors.New("invalid prefix probe context")
	}
	ctx, cancel := s.requestContext(ctx)
	defer cancel()
	b, err := s.Bundle(ctx)
	if err != nil {
		return err
	}
	if b.Generation != generation || sourceSize > b.MaxFileBytes {
		return errors.New("prefix probe generation or size changed")
	}
	if b.MaxPrefixBytes == 0 { // An older scanner still performs the full scan.
		return nil
	}
	if len(prefix) > b.MaxPrefixBytes {
		return errors.New("prefix probe exceeds advertised limit")
	}
	if !s.tryPrefixPermit() {
		return nil // A mandatory full scan has priority over optional preflight.
	}
	defer s.releasePermit()
	digest := fmt.Sprintf("%x", sha256.Sum256(prefix))
	request := struct {
		PrefixBase64 string `json:"prefixBase64"`
		PrefixSHA256 string `json:"prefixSha256"`
		PrefixBytes  int    `json:"prefixBytes"`
		SourceSize   int64  `json:"sourceSize"`
	}{base64.StdEncoding.EncodeToString(prefix), digest, len(prefix), sourceSize}
	var result struct {
		Generation   string  `json:"generation"`
		PrefixSHA256 string  `json:"prefixSha256"`
		PrefixBytes  int     `json:"prefixBytes"`
		Status       string  `json:"status"`
		Reason       *string `json:"reason"`
	}
	if err = s.exchange(ctx, http.MethodPost, "/v1/probe-legacy-prefix", generation, request, &result); err != nil {
		if errors.Is(err, errSecurityScannerBusy) {
			return nil // Optional early check; final mandatory scan does not use this fallback.
		}
		return err
	}
	if result.Generation != generation || result.PrefixSHA256 != digest || result.PrefixBytes != len(prefix) || result.Reason == nil {
		return errors.New("prefix response binding mismatch")
	}
	if result.Status == "pending" && *result.Reason == "" {
		return nil
	}
	if result.Status == "reject" {
		// Reuse the exact coverage error vocabulary without treating this
		// synthetic validator input as a scan result or persisting it.
		coverage := security.Analysis{Findings: []security.Finding{{Engine: "coverage", Rule: "coverage." + *result.Reason,
			Severity: "high", Message: security.FileAnalysisFailureMessage, Remediation: security.FileAnalysisFailureRemediation}}}
		if security.ValidateAnalysisCoverage(coverage) == nil {
			return fmt.Errorf("security prefix rejected; no complete scan: %s", *result.Reason)
		}
	}
	return errors.New("invalid isolated prefix response")
}

var securityTypePattern = regexp.MustCompile(`^(opaque|zip|gzip|numpy|pickle|elf|pe);ext=(|\.[a-z0-9_-]{1,23})$`)

func (s *SecurityScanner) Analyze(ctx context.Context, a security.Artifact) (security.Analysis, error) {
	var result security.Analysis
	if !artifactIDPattern.MatchString(a.ID) || !validDigest(a.Digest) || a.Size < 0 || !securityTypePattern.MatchString(a.Type) {
		return result, errors.New("invalid scanner artifact descriptor")
	}
	ctx, release, err := s.acquireFullPermit(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	b, err := s.Bundle(ctx)
	if err != nil {
		return result, err
	}
	if a.Size > b.MaxFileBytes {
		return result, errors.New("artifact exceeds scanner coverage limit")
	}
	if err = s.exchangeComplete(ctx, "/v1/analyze", b.Generation, a, &result); err != nil {
		return result, err
	}
	if err := validateSecurityAnalysis(b, result); err != nil {
		return security.Analysis{}, err
	}
	return result, nil
}

func validateSecurityAnalysis(b security.Bundle, result security.Analysis) error {
	if result.Generation != b.Generation || len(result.Engines) != len(b.Engines) || result.Engines["clamav"] == "" || result.Engines["picklescan"] == "" {
		return errors.New("scanner result generation or required engines changed")
	}
	if result.DurationMs < 0 {
		return errors.New("scanner result duration is invalid")
	}
	if err := security.ValidateAnalysisCoverage(result); err != nil {
		return err
	}
	for engine, version := range b.Engines {
		if result.Engines[engine] != version {
			return errors.New("scanner result engine versions changed")
		}
	}
	if len(result.Findings) > 4096 {
		return errors.New("scanner findings exceeded report limit")
	}
	for _, f := range result.Findings {
		if f.Engine != "clamav" && f.Engine != "picklescan" && f.Engine != "coverage" {
			return errors.New("unexpected finding engine")
		}
		if f.Severity != "critical" && f.Severity != "high" && f.Severity != "medium" && f.Severity != "low" {
			return errors.New("unexpected finding severity")
		}
		if len(f.Rule) > 128 || len(f.Message) > 1024 || len(f.Remediation) > 1024 {
			return errors.New("scanner finding exceeded display limit")
		}
		if err := validateSecurityFindingEvidence(f); err != nil {
			return err
		}
	}
	return nil
}

// The API also has a JavaScript client. Reject numbers that cannot be represented
// exactly there rather than displaying a different evidence location. Archive
// depth is configurable; the evidence protocol has a separate bound of 16 and
// the scanner fails closed if traversal would exceed it.
const securityEvidenceMaxInteger int64 = 1<<53 - 1
const securityEvidenceMaxArchiveDepth = 16

func validateSecurityFindingEvidence(f security.Finding) error {
	e := f.Evidence
	invalid := errors.New("invalid isolated scanner finding evidence")
	if e == nil {
		// Only older rules may omit evidence. The new capability rule must
		// carry its fixed symbol evidence and cannot downgrade severity by
		// omitting (or sending null for) the evidence object.
		if f.Rule == "pickle.nested-deserialization-reference" {
			return invalid
		}
		return nil
	}
	if f.Engine != "picklescan" || f.Rule != "pickle.nested-deserialization-reference" || f.Severity != "high" ||
		e.KnownSymbolID != "torch-storage-load-from-bytes-v1" || e.Observation != "reference" {
		return invalid
	}
	validNumber := func(n *int64) bool { return n != nil && *n >= 0 && *n <= securityEvidenceMaxInteger }
	switch e.Source {
	case "pickletools":
		if !validNumber(e.StreamIndex) || !validNumber(e.OpcodeOffset) {
			return invalid
		}
	case "picklescan":
		// Picklescan identifies globals but does not report opcode positions.
		if e.StreamIndex != nil || e.OpcodeOffset != nil {
			return invalid
		}
	default:
		return invalid
	}
	if len(e.ArchiveMemberChain) > securityEvidenceMaxArchiveDepth {
		return invalid
	}
	for _, member := range e.ArchiveMemberChain {
		if !validNumber(member.MemberIndex) || !validDigest(member.NameSHA256) {
			return invalid
		}
	}
	return nil
}

type securityBatchRequest struct {
	Artifacts []security.Artifact `json:"artifacts"`
}
type securityBatchResult struct {
	ArtifactID string            `json:"artifactId"`
	Analysis   security.Analysis `json:"analysis"`
}
type securityBatchResponse struct {
	Results []securityBatchResult `json:"results"`
}

// AnalyzeBatch amortizes engine startup only within one bounded request. A
// missing, reordered, duplicate or mismatched result invalidates the entire
// batch. Validated file failures retain partial evidence; callers must fail the
// report closed and never cache a batch containing incomplete coverage.
func (s *SecurityScanner) AnalyzeBatch(ctx context.Context, artifacts []security.Artifact) ([]security.Analysis, error) {
	if len(artifacts) == 0 || len(artifacts) > 32 {
		return nil, errors.New("invalid security batch file count")
	}
	var total int64
	seen := make(map[string]bool, len(artifacts))
	for _, a := range artifacts {
		if !artifactIDPattern.MatchString(a.ID) || !validDigest(a.Digest) || a.Size < 0 || !securityTypePattern.MatchString(a.Type) || seen[a.ID] {
			return nil, errors.New("invalid or duplicate scanner batch descriptor")
		}
		if a.Size > (256<<20)-total {
			return nil, errors.New("scanner batch byte limit exceeded")
		}
		total += a.Size
		seen[a.ID] = true
	}
	ctx, release, err := s.acquireFullPermit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	b, err := s.Bundle(ctx)
	if err != nil {
		return nil, err
	}
	if b.MaxBatchFiles <= 0 || b.MaxBatchBytes <= 0 || len(artifacts) > b.MaxBatchFiles || total > b.MaxBatchBytes {
		return nil, errors.New("scanner does not support the requested complete batch")
	}
	for _, a := range artifacts {
		if a.Size > b.MaxFileBytes {
			return nil, errors.New("batch artifact exceeds scanner coverage limit")
		}
	}
	var response securityBatchResponse
	if err = s.exchangeComplete(ctx, "/v1/analyze-batch", b.Generation, securityBatchRequest{Artifacts: artifacts}, &response); err != nil {
		return nil, err
	}
	if len(response.Results) != len(artifacts) {
		return nil, errors.New("scanner batch result count does not match request")
	}
	results := make([]security.Analysis, len(artifacts))
	for i, item := range response.Results {
		if item.ArtifactID != artifacts[i].ID {
			return nil, errors.New("scanner batch result order or artifact identity changed")
		}
		if err := validateSecurityAnalysis(b, item.Analysis); err != nil {
			return nil, err
		}
		results[i] = item.Analysis
	}
	return results, nil
}

var _ security.Scanner = (*SecurityScanner)(nil)
