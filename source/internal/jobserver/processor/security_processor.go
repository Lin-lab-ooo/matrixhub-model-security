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

package processor

import (
	"context"
	"sync"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/matrixhub-ai/matrixhub/internal/infra/log"
)

// SecurityRunner is a domain-only port; task persistence remains behind the
// service. Workers never access database rows or scanner files directly.
type SecurityRunner interface {
	Settings() security.Settings
	Claim(context.Context) (*security.Task, error)
	Process(context.Context, *security.Task) error
}
type SecurityProcessor struct {
	svc  SecurityRunner
	cfg  security.Settings
	once sync.Once
	wg   sync.WaitGroup
}

func NewSecurityProcessor(svc SecurityRunner) *SecurityProcessor {
	return &SecurityProcessor{svc: svc, cfg: svc.Settings()}
}
func (p *SecurityProcessor) Start(ctx context.Context) {
	p.once.Do(func() {
		for range p.cfg.Concurrency {
			p.wg.Add(1)
			go func() { defer p.wg.Done(); p.loop(ctx) }()
		}
	})
}
func (p *SecurityProcessor) Wait() { p.wg.Wait() }
func (p *SecurityProcessor) loop(ctx context.Context) {
	for ctx.Err() == nil {
		task, err := p.svc.Claim(ctx)
		if err != nil && ctx.Err() == nil {
			log.Warnw("security claim failed", "error", err)
		}
		if task != nil && err == nil {
			p.run(ctx, task)
			continue
		}
		timer := time.NewTimer(p.cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (p *SecurityProcessor) run(ctx context.Context, task *security.Task) {
	// A panic leaves the durable lease for recovery; it cannot approve a report.
	defer func() {
		if r := recover(); r != nil {
			log.Errorw("security worker panic; lease recovery required", "taskId", task.ID)
		}
	}()
	if err := p.svc.Process(ctx, task); err != nil && ctx.Err() == nil {
		log.Warnw("security task processing failed", "taskId", task.ID, "error", err)
	}
}
