// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// A cancelled probe can release the local permit before the isolated worker
// has finished reaping. Only a strict busy response proves no scan was started
// and permits retrying the exact same descriptor and generation.
func (s *SecurityScanner) exchangeComplete(ctx context.Context, endpoint, generation string, input, output any) error {
	busyDeadline := time.Now().Add(10 * time.Second)
	for {
		err := s.exchange(ctx, http.MethodPost, endpoint, generation, input, output)
		if !errors.Is(err, errSecurityScannerBusy) {
			return err
		}
		remaining := time.Until(busyDeadline)
		if remaining <= 0 {
			return err
		}
		timer := time.NewTimer(min(50*time.Millisecond, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// One adapter shares the scanner's single worker slot. Queueing is cancellable
// and included in the configured request deadline. Prefix probes never queue.
func (s *SecurityScanner) initPermit() {
	s.permitOnce.Do(func() {
		s.permit = make(chan struct{}, 1)
		s.permit <- struct{}{}
	})
}

func (s *SecurityScanner) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.client.Timeout > 0 {
		return context.WithTimeout(ctx, s.client.Timeout)
	}
	return context.WithCancel(ctx)
}

func (s *SecurityScanner) releasePermit() { s.permit <- struct{}{} }

func (s *SecurityScanner) acquireFullPermit(parent context.Context) (context.Context, func(), error) {
	ctx, cancel := s.requestContext(parent)
	s.initPermit()
	s.waitingFull.Add(1)
	defer s.waitingFull.Add(-1)
	select {
	case <-ctx.Done():
		cancel()
		return nil, nil, ctx.Err()
	case <-s.permit:
		if err := ctx.Err(); err != nil {
			s.releasePermit()
			cancel()
			return nil, nil, err
		}
		return ctx, func() { s.releasePermit(); cancel() }, nil
	}
}

func (s *SecurityScanner) tryPrefixPermit() bool {
	s.initPermit()
	if s.waitingFull.Load() != 0 {
		return false
	}
	select {
	case <-s.permit:
		if s.waitingFull.Load() != 0 {
			s.releasePermit()
			return false
		}
		return true
	default:
		return false
	}
}
