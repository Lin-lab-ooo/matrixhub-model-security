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

package security

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type entryKey struct{}

func WithEntry(ctx context.Context, entry string) context.Context {
	return context.WithValue(ctx, entryKey{}, entry)
}

// Service keeps business decisions independent of storage and scanner adapters.
type Service struct {
	store     Store
	artifacts Artifacts
	scanner   Scanner
	cfg       Settings
	authorize Authorizer
	actor     ActorFunc
	now       func() time.Time
	reviews   ReviewStore
	reviewer  ReviewActor
}

func NewService(store Store, artifacts Artifacts, scanner Scanner, cfg Settings, authorize Authorizer, actor ActorFunc, options ...ServiceOption) *Service {
	if cfg.Mode == "" {
		cfg.Mode = "enforce"
	}
	if cfg.BlockSeverity == "" {
		cfg.BlockSeverity = "high"
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = 64 << 20
	}
	if cfg.MaxTaskBytes <= 0 {
		cfg.MaxTaskBytes = 256 << 20
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 1000
	}
	if cfg.BatchFiles <= 0 {
		cfg.BatchFiles = MaxScanBatchFiles
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = 256 << 20
	}
	cfg.BatchFiles = min(cfg.BatchFiles, MaxScanBatchFiles)
	cfg.BatchBytes = min(cfg.BatchBytes, MaxScanBatchBytes)
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.Lease <= cfg.Timeout {
		cfg.Lease = cfg.Timeout + 30*time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if actor == nil {
		actor = func(context.Context) string { return "system" }
	}
	s := &Service{store: store, artifacts: artifacts, scanner: scanner, cfg: cfg, authorize: authorize, actor: actor, now: time.Now}
	for _, option := range options {
		option(s)
	}
	return s
}
func (s *Service) Enabled() bool      { return s != nil && s.cfg.Enabled }
func (s *Service) Strict() bool       { return s.Enabled() && s.cfg.Mode == "enforce" }
func (s *Service) Settings() Settings { return s.cfg }
func validCommit(v string) bool {
	if len(v) != 40 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil && strings.ToLower(v) == v
}
func validateRepo(v string) error {
	parts := strings.Split(v, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(v, "\\\x00\r\n") || parts[0] == "." || parts[1] == "." || parts[0] == ".." || parts[1] == ".." {
		return errors.New("security scope requires a model repository namespace/name")
	}
	return nil
}
func (s *Service) auth(ctx context.Context, repo, op string) error {
	if err := validateRepo(repo); err != nil {
		return err
	}
	if s.authorize == nil {
		return &AdmissionError{Code: "AuthorizationUnavailable", Message: "Project authorization is unavailable", State: Fail}
	}
	return s.authorize(ctx, repo, op)
}
func (s *Service) Resolve(ctx context.Context, repo, ref string) (string, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return "", err
	}
	return s.artifacts.Resolve(ctx, repo, ref)
}
func (s *Service) bundle(ctx context.Context) (Bundle, error) {
	if s.scanner == nil {
		return Bundle{}, errors.New("required isolated scanner is not configured")
	}
	// Control-plane requests must not make uploads or admission wait for the
	// full artifact-analysis timeout when a scanner is hung.
	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	defer healthCancel()
	b, err := s.scanner.Bundle(healthCtx)
	if err != nil {
		return Bundle{}, err
	}
	if b.Generation == "" || b.MaxFileBytes <= 0 || b.Engines["clamav"] == "" || b.Engines["picklescan"] == "" {
		return Bundle{}, errors.New("scanner returned an incomplete engine bundle")
	}
	return b, nil
}
func (s *Service) Enqueue(ctx context.Context, repo, commit, trigger string, force bool) (*Task, error) {
	if !s.Enabled() {
		return nil, nil
	}
	if err := validateRepo(repo); err != nil {
		return nil, err
	}
	if !validCommit(commit) {
		return nil, errors.New("scan task requires an immutable commit SHA")
	}
	if force {
		if err := s.auth(ctx, repo, "write"); err != nil {
			return nil, err
		}
	}
	b, err := s.bundle(ctx)
	gen := b.Generation
	if err != nil {
		gen = "unavailable"
	}
	t := &Task{Repo: repo, Revision: commit, Generation: gen, State: Pending, Trigger: trigger, Force: force, CreatedAt: s.now(), UpdatedAt: s.now()}
	task, err := s.store.Enqueue(ctx, t, force)
	if err != nil {
		return nil, err
	}
	if force || task.CreatedAt.Equal(t.CreatedAt) {
		if err = s.audit(ctx, repo, commit, "enqueue", nil); err != nil {
			return task, err
		}
	}
	return task, nil
}
func (s *Service) Report(ctx context.Context, repo, commit string) (*Report, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	if !validCommit(commit) {
		return nil, errors.New("report requires an immutable commit SHA")
	}
	b, err := s.bundle(ctx)
	if err != nil {
		return &Report{Repo: repo, Revision: commit, State: Fail, Error: "Required scanner unavailable", Files: []FileReport{}}, nil
	}
	task, report, err := s.store.Get(ctx, repo, commit, b.Generation)
	if err != nil {
		return nil, err
	}
	if task == nil {
		task, err = s.store.Enqueue(ctx, &Task{Repo: repo, Revision: commit, Generation: b.Generation, State: Pending, Trigger: "lazy-ensure", CreatedAt: s.now(), UpdatedAt: s.now()}, false)
		if err != nil {
			return nil, err
		}
		if err = s.audit(ctx, repo, commit, "ensure-scan", nil); err != nil {
			return nil, err
		}
	}
	if report != nil {
		if report.Repo != repo || report.Revision != commit || report.Generation != b.Generation {
			return &Report{Repo: repo, Revision: commit, Generation: b.Generation, State: Fail, Error: "Stored report does not match the current version and scanner generation", Files: []FileReport{}}, nil
		}
		return report, nil
	}
	return &Report{TaskID: task.ID, Repo: repo, Revision: commit, Generation: task.Generation, State: task.State, Error: task.Error, CreatedAt: task.CreatedAt, Files: []FileReport{}}, nil
}
func (s *Service) GetPolicy(ctx context.Context, repo string) (*Policy, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	return s.policy(ctx, repo)
}
func (s *Service) policy(ctx context.Context, repo string) (*Policy, error) {
	p, err := s.store.Policy(ctx, repo)
	if err != nil {
		return nil, err
	}
	if p == nil {
		p = &Policy{Repo: repo, Mode: s.cfg.Mode, BlockSeverity: s.cfg.BlockSeverity, Version: 1}
	}
	return p, nil
}
func (s *Service) UpdatePolicy(ctx context.Context, repo string, p Policy) (*Policy, error) {
	if err := s.auth(ctx, repo, "admin"); err != nil {
		return nil, err
	}
	if p.Mode != "enforce" && p.Mode != "audit" {
		return nil, errors.New("policy mode must be enforce or audit")
	}
	if severity(p.BlockSeverity) == 0 {
		return nil, errors.New("unknown block severity")
	}
	p.Repo = repo
	p.UpdatedAt = s.now()
	entry, _ := ctx.Value(entryKey{}).(string)
	audit := &Audit{Repo: repo, Actor: s.actor(ctx), Action: "policy-update", Entry: entry, CreatedAt: p.UpdatedAt,
		Decision: &Decision{Repo: repo, Code: "PolicyUpdated", Message: "mode=" + p.Mode + "; blockSeverity=" + p.BlockSeverity}}
	if err := s.store.SetPolicy(ctx, &p, audit); err != nil {
		return nil, err
	}
	return &p, nil
}
func severity(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}
func (s *Service) Check(ctx context.Context, repo, commit, path, oid string, size int64) (Decision, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return Decision{}, err
	}
	d := Decision{Repo: repo, Revision: commit, Path: path, Code: "ScanIncomplete", Message: "Complete scan approval is required"}
	r, err := s.Report(ctx, repo, commit)
	if err != nil {
		return d, err
	}
	d.TaskID = r.TaskID
	d.ReportID = r.ReportID
	d.Generation = r.Generation
	p, err := s.policy(ctx, repo)
	if err != nil {
		return d, err
	}
	d.PolicyVersion = p.Version
	if r.Repo != repo || r.Revision != commit || (r.Complete && !validManifest(r)) || (p.Mode != "enforce" && p.Mode != "audit") || severity(p.BlockSeverity) == 0 {
		d.Code = "ManifestMismatch"
		d.Message = "Version evidence or policy is incomplete"
		if err = s.audit(ctx, repo, commit, "admission", &d); err != nil {
			return d, err
		}
		return d, &AdmissionError{Code: d.Code, Message: d.Message, State: Fail}
	}
	if !r.Complete || (r.State != Pass && r.State != Warn && r.State != Block) {
		d.Code = stateCode(r.State)
		if err = s.audit(ctx, repo, commit, "admission", &d); err != nil {
			return d, err
		}
		return d, &AdmissionError{Code: d.Code, Message: d.Message, State: r.State}
	}
	var match *FileReport
	for i := range r.Files {
		f := &r.Files[i]
		if f.Path == path {
			match = f
			break
		}
	}
	if match == nil || !match.Complete || match.Digest == "" || (oid != "" && (match.LFSOID != oid || match.Artifact.Size != size)) {
		d.Code = "ManifestMismatch"
		d.Message = "Requested content does not match the approved manifest"
		if err = s.audit(ctx, repo, commit, "admission", &d); err != nil {
			return d, err
		}
		return d, &AdmissionError{Code: d.Code, Message: d.Message, State: Fail}
	}
	d.Digest = match.Digest
	d.Size = match.Artifact.Size
	d.ArtifactID = match.ID
	d.Allowed = true
	d.Code = "Allowed"
	d.Message = "Complete version scan permits this content"
	// A repository verdict protects all files in that version, not only the
	// requested file. Lowering a policy threshold reevaluates recorded findings.
	for _, f := range r.Files {
		for _, finding := range f.Findings {
			if p.Mode == "enforce" && severity(finding.Severity) >= severity(p.BlockSeverity) {
				d.Allowed = false
				d.Code = "RevisionBlocked"
				d.Message = "Repository revision exceeds the configured risk threshold"
			}
		}
	}
	if err = s.audit(ctx, repo, commit, "admission", &d); err != nil {
		return d, err
	}
	if !d.Allowed {
		return d, &AdmissionError{Code: d.Code, Message: d.Message, State: Block}
	}
	return d, nil
}
func (s *Service) CheckLFS(ctx context.Context, repo, commit, oid string, size int64) (Decision, error) {
	r, err := s.Report(ctx, repo, commit)
	if err != nil {
		return Decision{}, err
	}
	for _, f := range r.Files {
		if f.LFSOID == oid && f.Artifact.Size == size {
			return s.Check(ctx, repo, commit, f.Path, oid, size)
		}
	}
	d := Decision{Repo: repo, Revision: commit, Code: "LFSManifestMismatch", Message: "LFS object is not approved for this revision"}
	if err = s.audit(ctx, repo, commit, "lfs-download", &d); err != nil {
		return d, err
	}
	return d, &AdmissionError{Code: d.Code, Message: d.Message, State: r.State}
}
func (s *Service) OpenApproved(ctx context.Context, repo, commit, path string) (*ApprovedFile, error) {
	d, err := s.Check(ctx, repo, commit, path, "", 0)
	if err != nil {
		return nil, err
	}
	// First bind the request to the manifest. The adapter verifies every byte,
	// which can take time for large artifacts; approval can change meanwhile.
	rc, err := s.artifacts.Open(ctx, Artifact{ID: d.ArtifactID, Digest: d.Digest, Size: d.Size})
	if err != nil {
		d.Allowed = false
		d.Code = "SnapshotIntegrityFailed"
		d.Message = "Approved snapshot integrity verification failed"
		if auditErr := s.audit(ctx, repo, commit, "snapshot-integrity", &d); auditErr != nil {
			return nil, auditErr
		}
		return nil, &AdmissionError{Code: d.Code, Message: d.Message, State: Fail}
	}
	if err = ctx.Err(); err != nil {
		_ = rc.Close()
		return nil, err
	}
	current, err := s.Check(ctx, repo, commit, path, "", 0)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	if current.ReportID != d.ReportID || current.TaskID != d.TaskID ||
		current.Generation != d.Generation || current.PolicyVersion != d.PolicyVersion ||
		current.ArtifactID != d.ArtifactID || current.Digest != d.Digest || current.Size != d.Size {
		_ = rc.Close()
		current.Allowed = false
		current.Code = "ApprovalChanged"
		current.Message = "Download approval changed during snapshot verification; retry after the current scan completes"
		if err = s.audit(ctx, repo, commit, "download-revalidate", &current); err != nil {
			return nil, err
		}
		return nil, &AdmissionError{Code: current.Code, Message: current.Message, State: Fail}
	}
	// Revalidation does not hash a second time or replace the verified descriptor.
	// Updates after this boundary do not revoke bytes already being transmitted.
	d = current
	if err = s.audit(ctx, repo, commit, "download-open", &d); err != nil {
		_ = rc.Close()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = rc.Close()
		return nil, err
	}
	return &ApprovedFile{Reader: rc, Decision: d}, nil
}
func (s *Service) DenyRawGit(ctx context.Context, repo string) error {
	if !s.Enabled() {
		return nil
	}
	if err := s.auth(ctx, repo, "read"); err != nil {
		return err
	}
	p, err := s.policy(ctx, repo)
	if err != nil {
		return err
	}
	d := Decision{Repo: repo, PolicyVersion: p.Version}
	if p.Repo != repo || p.Version <= 0 || (p.Mode != "enforce" && p.Mode != "audit") ||
		(s.cfg.Mode != "enforce" && s.cfg.Mode != "audit") || severity(p.BlockSeverity) == 0 {
		d.Code = "PolicyInvalid"
		d.Message = "Historical content policy is invalid"
		if err := s.audit(ctx, repo, "", "raw-git", &d); err != nil {
			return err
		}
		return &AdmissionError{Code: d.Code, Message: d.Message, State: Fail}
	}
	// Raw history cannot be bound to one approved revision. Keep the global
	// enforce restriction even when a repository is explicitly in audit mode.
	d.Allowed = s.cfg.Mode != "enforce" && p.Mode != "enforce"
	d.Code = "RawGitDisabled"
	d.Message = "Protected repositories require approved Hugging Face file downloads"
	if d.Allowed {
		d.Code = "RawGitAllowed"
		d.Message = "Audit mode permits historical content"
	}
	if err := s.audit(ctx, repo, "", "raw-git", &d); err != nil {
		return err
	}
	if d.Allowed {
		return nil
	}
	return &AdmissionError{Code: d.Code, Message: d.Message, State: Block}
}
func (s *Service) Tasks(ctx context.Context, repo string, limit, offset int) ([]Task, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	return s.store.Tasks(ctx, repo, limit, offset)
}
func (s *Service) Audits(ctx context.Context, repo string, limit, offset int) ([]Audit, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	return s.store.Audits(ctx, repo, limit, offset)
}
func (s *Service) Cancel(ctx context.Context, repo string, id int64) (bool, error) {
	if err := s.auth(ctx, repo, "write"); err != nil {
		return false, err
	}
	ok, err := s.store.Cancel(ctx, id, repo)
	if err == nil && ok {
		err = s.audit(ctx, repo, "", "cancel", nil)
	}
	return ok, err
}
func (s *Service) audit(ctx context.Context, repo, commit, action string, d *Decision) error {
	entry, _ := ctx.Value(entryKey{}).(string)
	a := &Audit{Repo: repo, Revision: commit, Actor: s.actor(ctx), Action: action, Entry: entry, Decision: d, CreatedAt: s.now()}
	if d != nil {
		a.Path = d.Path
	}
	return s.store.AppendAudit(ctx, a)
}
func (s *Service) Claim(ctx context.Context) (*Task, error) {
	b, err := s.bundle(ctx)
	if err != nil {
		return nil, err
	}
	return s.store.Claim(ctx, b.Generation, s.now(), s.cfg.Lease, s.cfg.MaxAttempts)
}
func validManifest(r *Report) bool {
	if r.ReportID == "" || r.Generation == "" || r.ExpectedFiles != len(r.Files) {
		return false
	}
	paths := map[string]bool{}
	for _, f := range r.Files {
		if f.Path == "" || paths[f.Path] || !f.Complete || f.Generation != r.Generation || f.Engines["clamav"] == "" || f.Engines["picklescan"] == "" || f.ID == "" || f.Artifact.Size < 0 || f.Artifact.Size != f.SourceFile.Size || len(f.Digest) != 64 {
			return false
		}
		if _, err := hex.DecodeString(f.Digest); err != nil {
			return false
		}
		if f.LFSOID != "" && f.LFSOID != f.Digest {
			return false
		}
		for _, finding := range f.Findings {
			if severity(finding.Severity) == 0 {
				return false
			}
		}
		paths[f.Path] = true
	}
	return true
}

// Process executes one claimed task. All results become visible atomically
// only if this attempt still owns the task at completion.
func (s *Service) Process(ctx context.Context, task *Task) error {
	if task == nil {
		return errors.New("scan requires a claimed task")
	}
	started := s.now()
	deadline := started.Add(s.cfg.Timeout)
	if !task.LeaseUntil.IsZero() && task.LeaseUntil.Before(deadline) {
		deadline = task.LeaseUntil
	}
	deadlineCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	workCtx, stopWork := context.WithCancelCause(deadlineCtx)
	defer stopWork(nil)
	report := &Report{ReportID: fmt.Sprintf("%d-%d", task.ID, task.Attempt), Attempt: task.Attempt, TaskID: task.ID, Repo: task.Repo, Revision: task.Revision, Generation: task.Generation, State: Fail, CreatedAt: task.CreatedAt, Files: []FileReport{}}
	// Validate before any source reads, then monitor while staging and scanning.
	// This also covers cancellation between Claim and Process, a superseded
	// force attempt, and cancellation through an unresolved-generation alias.
	runErr := s.checkClaim(workCtx, task)
	if runErr == nil {
		stopMonitor := s.monitorClaim(workCtx, stopWork, task)
		defer stopMonitor()
		runErr = s.analyze(workCtx, task, report)
		stopMonitor()
	}
	if cause := context.Cause(workCtx); cause != nil {
		runErr = cause
	}
	if runErr != nil {
		report.State = Fail
		report.Complete = false
		report.Error = boundedError(runErr)
	}
	report.FinishedAt = s.now()
	report.DurationMs = report.FinishedAt.Sub(started).Milliseconds()
	// Cleanup persists failure even when the work deadline has already expired.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cleanupCancel()
	accepted, err := s.store.Finish(cleanupCtx, task, report)
	if err != nil {
		return err
	}
	if !accepted {
		return errors.Join(errors.New("scan claim expired or was replaced; late result discarded"), runErr)
	}
	return runErr
}
func boundedError(err error) string {
	text := err.Error()
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}
func (s *Service) analyze(ctx context.Context, task *Task, report *Report) error {
	b, err := s.bundle(ctx)
	if err != nil {
		return errors.New("required scanner unavailable")
	}
	if b.Generation != task.Generation {
		return errors.New("scan engine generation changed; enqueue a new scan")
	}
	files, err := s.artifacts.List(ctx, task.Repo, task.Revision)
	if err != nil {
		return err
	}
	report.ExpectedFiles = len(files)
	if len(files) > s.cfg.MaxFiles {
		return errors.New("repository file count exceeds configured coverage limit")
	}
	limit := s.cfg.MaxFileBytes
	if b.MaxFileBytes < limit {
		limit = b.MaxFileBytes
	}
	var total int64
	for _, f := range files {
		if f.Size < 0 || f.Size > limit {
			return fmt.Errorf("file exceeds complete scanning limit: %s", f.Path)
		}
		if total > s.cfg.MaxTaskBytes-f.Size {
			return errors.New("repository exceeds task byte budget")
		}
		total += f.Size
	}
	release, err := s.artifacts.Reserve(ctx, task, total)
	if err != nil {
		return err
	}
	defer release()
	report.State = Pass
	if err = s.stageAndScan(ctx, task, report, b, files, limit); err != nil {
		return err
	}
	incomplete := false
	for i := range report.Files {
		a := &report.Files[i].Analysis
		if err := validateAnalysisBinding(b, *a); err != nil {
			return err
		}
		incomplete = incomplete || !a.Complete
		for _, finding := range a.Findings {
			if severity(finding.Severity) == 0 {
				return errors.New("scanner reported unknown severity")
			}
			if severity(finding.Severity) >= 3 {
				report.State = Block
			} else if report.State != Block {
				report.State = Warn
			}
		}
	}
	// Final health/generation read prevents a report spanning a rule transition.
	final, err := s.bundle(ctx)
	if err != nil || final.Generation != task.Generation {
		return errors.New("scanner changed or became unavailable before report publication")
	}
	if incomplete {
		return errors.New("scanner did not provide complete, generation-bound coverage")
	}
	report.Complete = true
	return nil
}

type stagedBatch struct {
	indices   []int
	artifacts []Artifact
}

type stagedAnalysis struct {
	index    int
	analysis Analysis
}

type stagedScanResult struct {
	analyses []stagedAnalysis
	err      error
}

// stageAndScan overlaps staging the next bounded batch with scanning a fully
// sealed previous batch. There is one scanner worker and no queued batch. The
// producer owns report.Files; only after the worker joins are its results merged.
// This is file/batch pipelining, not inspection of a still-growing file.
func (s *Service) stageAndScan(ctx context.Context, task *Task, report *Report, bundle Bundle, files []SourceFile, limit int64) (err error) {
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	jobs := make(chan stagedBatch)
	finished := make(chan stagedScanResult, 1)
	go func() {
		var outcome stagedScanResult
		defer func() { finished <- outcome }()
		for {
			if outcome.err = workCtx.Err(); outcome.err != nil {
				return
			}
			select {
			case <-workCtx.Done():
				outcome.err = workCtx.Err()
				return
			case job, ok := <-jobs:
				if !ok {
					return
				}
				// The worker never reads the producer's report or slice backing
				// arrays. Reuse the existing all-sibling batch validation logic.
				local := &Report{Files: make([]FileReport, len(job.artifacts))}
				misses := make([]int, len(job.artifacts))
				for i, artifact := range job.artifacts {
					local.Files[i].Artifact = artifact
					misses[i] = i
				}
				if outcome.err = s.scanMissing(workCtx, task, local, bundle, misses); outcome.err != nil {
					cancel(outcome.err)
					return
				}
				for i, file := range local.Files {
					outcome.analyses = append(outcome.analyses, stagedAnalysis{index: job.indices[i], analysis: file.Analysis})
				}
			}
		}
	}()
	defer func() {
		if err != nil {
			cancel(err)
		}
		close(jobs)
		// Join before returning to analyze, whose defer releases the staging
		// reservation. Never release snapshots while the scanner uses them.
		outcome := <-finished
		for _, result := range outcome.analyses {
			report.Files[result.index].Analysis = result.analysis
		}
		if cause := context.Cause(workCtx); cause != nil {
			err = cause
		} else if outcome.err != nil {
			err = outcome.err
		}
	}()

	maxFiles, maxBytes := 1, bundle.MaxFileBytes
	if _, ok := s.scanner.(BatchScanner); ok && bundle.MaxBatchFiles > 0 && bundle.MaxBatchBytes > 0 {
		maxFiles, maxBytes = s.batchLimits(bundle)
	}
	var pending stagedBatch
	var pendingBytes int64
	flush := func() error {
		if len(pending.artifacts) == 0 {
			return nil
		}
		if err := workCtx.Err(); err != nil {
			return err
		}
		select {
		case <-workCtx.Done():
			return workCtx.Err()
		case jobs <- pending:
			// Transfer ownership. A fresh backing array is allocated for the
			// next batch rather than reusing memory still read by the worker.
			pending = stagedBatch{}
			pendingBytes = 0
			return nil
		}
	}
	for _, source := range files {
		if err = workCtx.Err(); err != nil {
			return err
		}
		// List sizes were budget-checked by analyze. Use them only to schedule
		// sealed pending work before the next potentially long Stage; the
		// staged artifact size below remains the actual batch boundary.
		if len(pending.artifacts) > 0 && source.Size > maxBytes-pendingBytes {
			if err = flush(); err != nil {
				return err
			}
		}
		artifact, stageErr := s.artifacts.Stage(workCtx, task, source, limit)
		if stageErr != nil {
			return stageErr
		}
		var analysis *Analysis
		cached := false
		if !task.Force {
			analysis, err = s.store.Cached(workCtx, task.Repo, artifact, task.Generation)
			if err != nil {
				return err
			}
			cached = analysis != nil && analysis.Complete && analysis.Generation == task.Generation
		}
		file := FileReport{SourceFile: source, Artifact: artifact, Cached: cached}
		if cached {
			file.Analysis = *analysis
			report.CachedFiles++
		}
		index := len(report.Files)
		report.Files = append(report.Files, file)
		report.ScannedBytes += artifact.Size
		if cached {
			continue
		}
		if len(pending.artifacts) > 0 && artifact.Size > maxBytes-pendingBytes {
			if err = flush(); err != nil {
				return err
			}
		}
		pending.indices = append(pending.indices, index)
		pending.artifacts = append(pending.artifacts, artifact)
		pendingBytes += artifact.Size
		// An artifact above the batch budget is sent alone. scanMissing keeps
		// its existing bounded single-file fallback and binding validation.
		if len(pending.artifacts) >= maxFiles || pendingBytes >= maxBytes {
			if err = flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

func validateAnalysisBinding(bundle Bundle, result Analysis) error {
	if result.Generation != bundle.Generation || len(result.Engines) != len(bundle.Engines) || result.Engines["clamav"] == "" || result.Engines["picklescan"] == "" || result.DurationMs < 0 {
		return errors.New("scanner result generation or required engines changed")
	}
	for engine, version := range bundle.Engines {
		if result.Engines[engine] != version {
			return errors.New("scanner engine versions changed")
		}
	}
	return ValidateAnalysisCoverage(result)
}

// Stage and verify all bytes before handing a bounded batch to the isolated
// scanner. Legacy scanners advertise no batch capacity and remain compatible.
func (s *Service) scanMissing(ctx context.Context, task *Task, report *Report, bundle Bundle, misses []int) error {
	batch, supportsBatch := s.scanner.(BatchScanner)
	if !supportsBatch || bundle.MaxBatchFiles <= 0 || bundle.MaxBatchBytes <= 0 {
		for _, index := range misses {
			result, err := s.scanner.Analyze(ctx, report.Files[index].Artifact)
			if err != nil {
				return err
			}
			if err := validateAnalysisBinding(bundle, result); err != nil {
				return err
			}
			report.Files[index].Analysis = result
		}
		return nil
	}
	maxFiles, maxBytes := s.batchLimits(bundle)
	for offset := 0; offset < len(misses); {
		// The batch byte budget limits one batch, not one artifact. A staged
		// artifact allowed by the file budget can use the bounded single-file
		// protocol without increasing the memory budget of ordinary batches.
		index := misses[offset]
		artifact := report.Files[index].Artifact
		if artifact.Size > maxBytes {
			if artifact.Size > bundle.MaxFileBytes {
				return errors.New("artifact exceeds complete file coverage limit")
			}
			result, err := s.scanner.Analyze(ctx, artifact)
			if err != nil {
				return err
			}
			if err := validateAnalysisBinding(bundle, result); err != nil {
				return err
			}
			report.Files[index].Analysis = result
			offset++
			continue
		}
		var artifacts []Artifact
		var indices []int
		var bytes int64
		for offset < len(misses) && len(artifacts) < maxFiles {
			index := misses[offset]
			artifact := report.Files[index].Artifact
			if artifact.Size > maxBytes {
				break
			}
			if artifact.Size > maxBytes-bytes {
				break
			}
			artifacts = append(artifacts, artifact)
			indices = append(indices, index)
			bytes += artifact.Size
			offset++
		}
		results, err := batch.AnalyzeBatch(ctx, artifacts)
		if err != nil {
			return err
		}
		if len(results) != len(artifacts) {
			return errors.New("scanner batch coverage count mismatch")
		}
		// Validate the whole response before publishing any sibling analysis.
		for _, result := range results {
			if err := validateAnalysisBinding(bundle, result); err != nil {
				return err
			}
		}
		for i, result := range results {
			report.Files[indices[i]].Analysis = result
		}
	}
	return nil
}

func (s *Service) batchLimits(bundle Bundle) (int, int64) {
	return min(s.cfg.BatchFiles, bundle.MaxBatchFiles, MaxScanBatchFiles),
		min(s.cfg.BatchBytes, bundle.MaxBatchBytes, MaxScanBatchBytes)
}

func stateCode(state State) string {
	switch state {
	case Pending:
		return "RevisionPending"
	case Scanning:
		return "RevisionScanning"
	case Fail:
		return "RevisionFailed"
	default:
		return "ScanIncomplete"
	}
}
func (s *Service) History(ctx context.Context, repo, id string) (*Report, error) {
	if err := s.auth(ctx, repo, "read"); err != nil {
		return nil, err
	}
	return s.store.Historical(ctx, repo, id)
}
