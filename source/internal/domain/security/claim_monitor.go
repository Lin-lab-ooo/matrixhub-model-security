// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package security

import (
	"context"
	"errors"
	"time"
)

const claimCheckInterval = 500 * time.Millisecond
const claimCheckTimeout = time.Second

func (s *Service) checkClaim(ctx context.Context, task *Task) error {
	checkCtx, cancel := context.WithTimeout(ctx, claimCheckTimeout)
	defer cancel()
	owned, err := s.store.OwnsClaim(checkCtx, task)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return errors.New("scan claim ownership could not be verified")
	}
	if !owned {
		return errors.New("scan claim cancelled, expired or replaced")
	}
	return nil
}

// monitorClaim stops work when the durable claim is revoked or cannot be
// confirmed. The interval is bounded independently of the queue poll setting.
// It never extends a lease. Cancellation propagates through source reads and
// HTTP to the isolated scanner's disconnect/kill-and-reap path. Finish still
// owns the final transactional token fence; monitoring is not an approval.
func (s *Service) monitorClaim(ctx context.Context, cancelWork context.CancelCauseFunc, task *Task) func() {
	monitorCtx, cancelMonitor := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(claimCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				if err := s.checkClaim(monitorCtx, task); err != nil {
					// Stopping the monitor after completed work must not turn
					// cancellation of its in-flight query into a task failure.
					if monitorCtx.Err() == nil {
						cancelWork(err)
					}
					return
				}
			}
		}
	}()
	return func() {
		cancelMonitor()
		<-joined
	}
}
