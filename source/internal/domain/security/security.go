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

// Package security binds artifact analysis and download decisions to immutable
// repository commits and the exact bytes presented to isolated scanners.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type State string

const (
	Pending  State = "pending"
	Scanning State = "scanning"
	Pass     State = "pass"
	Warn     State = "warn"
	Block    State = "block"
	Fail     State = "fail"
)

type Finding struct {
	Engine      string           `json:"engine"`
	Rule        string           `json:"rule"`
	Severity    string           `json:"severity"`
	Message     string           `json:"message"`
	Remediation string           `json:"remediation"`
	Evidence    *FindingEvidence `json:"evidence,omitempty"`
}

// FindingEvidence records a static reference, not proof of invocation or
// malicious execution. Only fixed symbol identifiers and hashed archive names
// cross the isolated scanner boundary; no payload or raw member name is exposed.
// A nil location means the engine identified the symbol without locating an
// opcode. Pointer numbers preserve the distinction between unknown and index 0.
type FindingEvidence struct {
	KnownSymbolID      string                  `json:"knownSymbolId"`
	Observation        string                  `json:"observation"`
	Source             string                  `json:"source"`
	ArchiveMemberChain []ArchiveMemberEvidence `json:"archiveMemberChain"`
	StreamIndex        *int64                  `json:"streamIndex"`
	OpcodeOffset       *int64                  `json:"opcodeOffset"`
}

// UnmarshalJSON preserves explicit null locations while rejecting omitted
// protocol keys. It also retains strict unknown-field checks when decoding an
// evidence object nested inside a scanner response or a persisted report.
func (e *FindingEvidence) UnmarshalJSON(data []byte) error {
	invalid := errors.New("invalid finding evidence object")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return invalid
	}
	for _, name := range []string{"knownSymbolId", "observation", "source", "archiveMemberChain", "streamIndex", "opcodeOffset"} {
		if _, present := fields[name]; !present {
			return invalid
		}
	}
	for _, name := range []string{"knownSymbolId", "observation", "source"} {
		if bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return invalid
		}
	}
	type wireEvidence FindingEvidence
	var value wireEvidence
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return invalid
	}
	*e = FindingEvidence(value)
	return nil
}

// ArchiveMemberEvidence identifies a zero-based archive entry without returning
// its untrusted name. The chain runs from the outermost container inward.
type ArchiveMemberEvidence struct {
	MemberIndex *int64 `json:"memberIndex"`
	NameSHA256  string `json:"nameSha256"`
}

type Artifact struct {
	ID     string `json:"artifactId"`
	Digest string `json:"sha256"`
	Size   int64  `json:"size"`
	Type   string `json:"type"`
}
type SourceFile struct {
	Path   string `json:"path"`
	BlobID string `json:"blobId"`
	LFSOID string `json:"lfsOid,omitempty"`
	Size   int64  `json:"declaredSize"`
}
type Analysis struct {
	Generation string            `json:"generation"`
	Complete   bool              `json:"complete"`
	Findings   []Finding         `json:"findings"`
	Engines    map[string]string `json:"engines"`
	DurationMs int64             `json:"durationMs"`
}

// FileAnalysisFailureMessage and FileAnalysisFailureRemediation are fixed
// protocol text. File failures never expose parser errors or artifact content.
const FileAnalysisFailureMessage = "Static inspection could not completely analyze this artifact; the scan remains incomplete."
const FileAnalysisFailureRemediation = "Review the source and use a trusted artifact; do not load untrusted serialized objects."

// ValidateAnalysisCoverage accepts partial evidence only for a bounded, known
// file format failure. Request, integrity, resource and engine failures cannot
// be represented as partial file results.
func ValidateAnalysisCoverage(a Analysis) error {
	coverage := 0
	for _, f := range a.Findings {
		if f.Engine != "coverage" && !strings.HasPrefix(f.Rule, "coverage.") {
			continue
		}
		if a.Complete || f.Engine != "coverage" || f.Severity != "high" ||
			f.Message != FileAnalysisFailureMessage || f.Remediation != FileAnalysisFailureRemediation || f.Evidence != nil {
			return errors.New("scanner result has invalid coverage failure")
		}
		switch f.Rule {
		case "coverage.unsupported_container_or_serialization", "coverage.numpy_serialization_not_supported",
			"coverage.archive_member_size", "coverage.duplicate_archive_member", "coverage.encrypted_archive",
			"coverage.archive_symlink", "coverage.archive_link_or_special_file",
			"coverage.pickle_extension_registry_unsupported", "coverage.malformed_pickle", "coverage.empty_pickle",
			"coverage.pickle_analysis_incomplete", "coverage.pickle_symbol_analysis_incomplete",
			"coverage.pickle_symbol_analysis_disagreement", "coverage.invalid_safetensors_header",
			"coverage.invalid_safetensors_offsets", "coverage.invalid_serialization":
		default:
			return errors.New("scanner result has invalid coverage failure")
		}
		coverage++
	}
	if !a.Complete && coverage != 1 {
		return errors.New("scanner result has invalid coverage failure")
	}
	return nil
}

type FileReport struct {
	SourceFile
	Artifact
	Analysis
	Cached bool `json:"cached"`
}
type Task struct {
	Scope      string    `json:"-"`
	ID         int64     `json:"id"`
	Repo       string    `json:"repo"`
	Revision   string    `json:"revision"`
	Generation string    `json:"generation"`
	State      State     `json:"state"`
	Trigger    string    `json:"trigger"`
	Force      bool      `json:"force"`
	Attempt    int       `json:"attempt"`
	Token      string    `json:"-"`
	LeaseUntil time.Time `json:"leaseUntil"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Error      string    `json:"error,omitempty"`
}
type Report struct {
	ExpectedFiles int          `json:"expectedFiles"`
	ReportID      string       `json:"reportId"`
	Attempt       int          `json:"attempt"`
	TaskID        int64        `json:"taskId"`
	Repo          string       `json:"repo"`
	Revision      string       `json:"revision"`
	Generation    string       `json:"generation"`
	State         State        `json:"state"`
	Complete      bool         `json:"complete"`
	Files         []FileReport `json:"files"`
	Error         string       `json:"error,omitempty"`
	CreatedAt     time.Time    `json:"createdAt"`
	FinishedAt    time.Time    `json:"finishedAt"`
	DurationMs    int64        `json:"durationMs"`
	ScannedBytes  int64        `json:"scannedBytes"`
	CachedFiles   int          `json:"cachedFiles"`
}

func (r *Report) HFStatus() map[string]any {
	status := "scanning"
	switch r.State {
	case Pass:
		status = "clean"
	case Warn:
		status = "warning"
	case Block:
		status = "infected"
	case Fail:
		status = "error"
	}
	return map[string]any{
		"kind": "malware", "status": status,
		"details": map[string]any{
			"machineStatus": r.State, "revision": r.Revision,
			"generation": r.Generation, "reportId": r.ReportID, "complete": r.Complete,
			"message": r.Error,
		},
	}
}

type Policy struct {
	Repo          string    `json:"repo"`
	Mode          string    `json:"mode"` // enforce or audit; incomplete content is always denied.
	BlockSeverity string    `json:"blockSeverity"`
	Version       int64     `json:"version"`
	UpdatedAt     time.Time `json:"updatedAt"`
}
type Decision struct {
	ReportID      string `json:"reportId"`
	Allowed       bool   `json:"allowed"`
	Code          string `json:"code"`
	Message       string `json:"message"`
	Repo          string `json:"repo"`
	Revision      string `json:"revision"`
	Path          string `json:"path"`
	Digest        string `json:"sha256"`
	Size          int64  `json:"size"`
	TaskID        int64  `json:"taskId"`
	Generation    string `json:"generation"`
	PolicyVersion int64  `json:"policyVersion"`
	ArtifactID    string `json:"-"`
}
type AdmissionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	State   State  `json:"state"`
}

func (e *AdmissionError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

type ApprovedFile struct {
	Reader   io.ReadSeekCloser
	Decision Decision
}

func (f *ApprovedFile) Close() error { return f.Reader.Close() }

type Audit struct {
	ID         int64           `json:"id"`
	Repo       string          `json:"repo"`
	Revision   string          `json:"revision"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	Entry      string          `json:"entry"`
	Path       string          `json:"path,omitempty"`
	Decision   *Decision       `json:"decision,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
	Completion *ScanCompletion `json:"completion,omitempty"`
	Review     *Review         `json:"review,omitempty"`
}

// ScanCompletion records one committed attempt, independently of any later
// policy-based admission decision.
type ScanCompletion struct {
	TaskID        int64  `json:"taskId"`
	Attempt       int    `json:"attempt"`
	ReportID      string `json:"reportId"`
	Generation    string `json:"generation"`
	State         State  `json:"state"`
	Complete      bool   `json:"complete"`
	ExpectedFiles int    `json:"expectedFiles"`
	ReportedFiles int    `json:"reportedFiles"`
	CompleteFiles int    `json:"completeFiles"`
	CachedFiles   int    `json:"cachedFiles"`
	DurationMs    int64  `json:"durationMs"`
}

type Bundle struct {
	Generation     string            `json:"generation"`
	Engines        map[string]string `json:"engines"`
	MaxFileBytes   int64             `json:"maxFileBytes"`
	MaxBatchFiles  int               `json:"maxBatchFiles,omitempty"`
	MaxBatchBytes  int64             `json:"maxBatchBytes,omitempty"`
	MaxPrefixBytes int               `json:"maxPrefixBytes,omitempty"`
}
type Settings struct {
	Enabled       bool
	Mode          string
	BlockSeverity string
	MaxFileBytes  int64
	MaxTaskBytes  int64
	MaxFiles      int
	Timeout       time.Duration
	Lease         time.Duration
	PollInterval  time.Duration
	Concurrency   int
	MaxAttempts   int
}

// Gate is used by all content transports. OpenApproved performs its own
// authorization and returns the same verified snapshot that was scanned.
type Gate interface {
	Enabled() bool
	Strict() bool
	Enqueue(context.Context, string, string, string, bool) (*Task, error)
	Report(context.Context, string, string) (*Report, error)
	Check(context.Context, string, string, string, string, int64) (Decision, error)
	CheckLFS(context.Context, string, string, string, int64) (Decision, error)
	OpenApproved(context.Context, string, string, string) (*ApprovedFile, error)
	DenyRawGit(context.Context, string) error
}

// Store is the durable task/report/policy port. Finish must commit the report,
// completion audit and reusable complete analyses atomically, only for the
// current claim token.
//
//go:generate go tool mockgen -source=security.go -destination=mocks/security_mock.go -package=mocks
type Store interface {
	Enqueue(context.Context, *Task, bool) (*Task, error)
	Get(context.Context, string, string, string) (*Task, *Report, error)
	Historical(context.Context, string, string) (*Report, error)
	Claim(context.Context, string, time.Time, time.Duration, int) (*Task, error)
	Finish(context.Context, *Task, *Report) (bool, error)
	Cancel(context.Context, int64, string) (bool, error)
	Cached(context.Context, string, Artifact, string) (*Analysis, error)
	Policy(context.Context, string) (*Policy, error)
	// SetPolicy publishes the exact policy version and its audit in one
	// transaction. It fills the committed version only after success.
	SetPolicy(context.Context, *Policy, *Audit) error
	AppendAudit(context.Context, *Audit) error
	Audits(context.Context, string, int, int) ([]Audit, error)
	Tasks(context.Context, string, int, int) ([]Task, error)
}

// Artifacts owns immutable staging and source reads. Stage must stream every
// byte, verify the declared LFS digest and size, and atomically publish a fresh
// snapshot. Open validates the digest on the SAME descriptor before seeking.
type Artifacts interface {
	Resolve(context.Context, string, string) (string, error)
	List(context.Context, string, string) ([]SourceFile, error)
	Reserve(context.Context, *Task, int64) (func(), error)
	Stage(context.Context, *Task, SourceFile, int64) (Artifact, error)
	Open(context.Context, Artifact) (io.ReadSeekCloser, error)
}

// Scanner is an isolated, credential-free analysis endpoint. Generation
// includes the immutable rule snapshot, engine versions and coverage limits.
type Scanner interface {
	Bundle(context.Context) (Bundle, error)
	Analyze(context.Context, Artifact) (Analysis, error)
}

// PrefixProber can reject a bounded prefix during staging. A nil result means
// only that staging may continue; it is never analysis, approval or cache evidence.
type PrefixProber interface {
	ProbeLegacyPrefix(context.Context, string, []byte, int64) error
}

// BatchScanner is optional. Results must match input artifacts in the same
// order with generation-bound engine versions. Controlled file failures may
// return partial evidence with nil error; callers must preserve it, fail the
// report closed and never cache it. An invalid batch returns no results.
type BatchScanner interface {
	AnalyzeBatch(context.Context, []Artifact) ([]Analysis, error)
}

// Authorizer must use the existing MatrixHub identity and project permissions.
// Operations are read, write (rescan/cancel), and admin (policy changes).
type Authorizer func(context.Context, string, string) error
type ActorFunc func(context.Context) string
