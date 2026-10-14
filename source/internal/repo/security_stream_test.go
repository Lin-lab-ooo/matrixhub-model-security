// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

type securityProbeFunc func(context.Context, string, []byte, int64) error

func (f securityProbeFunc) ProbeLegacyPrefix(ctx context.Context, generation string, prefix []byte, size int64) error {
	return f(ctx, generation, prefix, size)
}

type securityCountingReader struct {
	reader io.Reader
	bytes  int
}

func (r *securityCountingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestSecurityStreamRejectStopsBeforeRemainingGigabyte(t *testing.T) {
	// Logical 1 GiB stream, no 1 GiB allocation; the unread tail errors if read.
	prefix := make([]byte, securityPrefixBytes)
	prefix[0], prefix[1] = 0x80, 2
	src := &securityCountingReader{reader: bytes.NewReader(prefix)}
	calls := 0
	rejected := errors.New("prefix rejected")
	probe := securityProbeFunc(func(_ context.Context, generation string, got []byte, size int64) error {
		calls++
		if generation != strings.Repeat("a", 64) || size != 1<<30 || !bytes.Equal(got, prefix) || src.bytes != securityPrefixBytes {
			t.Fatal("prefix was not examined before reading the tail")
		}
		return rejected
	})
	n, err := copySecurityStream(t.Context(), io.Discard, src, 1<<30, strings.Repeat("a", 64), probe)
	if !errors.Is(err, rejected) || n != securityPrefixBytes || src.bytes != securityPrefixBytes || calls != 1 {
		t.Fatalf("early reject: bytes=%d read=%d calls=%d error=%v", n, src.bytes, calls, err)
	}
}

func TestSecurityStreamPendingCopiesAllBytesOnce(t *testing.T) {
	for _, protocol := range []byte{2, 4} {
		data := bytes.Repeat([]byte{0x35}, 3*securityPrefixBytes+13)
		data[0], data[1] = 0x80, protocol
		calls := 0
		probe := securityProbeFunc(func(context.Context, string, []byte, int64) error { calls++; return nil })
		var dst bytes.Buffer
		n, err := copySecurityStream(t.Context(), &dst, bytes.NewReader(data), int64(len(data)), strings.Repeat("a", 64), probe)
		if err != nil || n != int64(len(data)) || calls != 1 || !bytes.Equal(data, dst.Bytes()) {
			t.Fatalf("stream changed after pending: bytes=%d calls=%d error=%v", n, calls, err)
		}
	}
}

func TestSecurityStreamBoundariesAndCancellation(t *testing.T) {
	data := make([]byte, 2*securityPrefixBytes)
	data[0], data[1] = 0x80, 2
	for _, tc := range []struct {
		name      string
		data      []byte
		size      int64
		wantErr   bool
		wantCalls int
	}{
		{"small", data[:100], 100, false, 0},
		{"negative-size", nil, -1, true, 0},
		{"overflow-size", nil, math.MaxInt64, true, 0},
		{"exact-prefix", data[:securityPrefixBytes], securityPrefixBytes, false, 0},
		{"short-prefix", data[:100], int64(len(data)), true, 0},
		{"excess-byte", append(append([]byte{}, data...), 1), int64(len(data)), true, 1},
		{"other-format", bytes.Repeat([]byte{1}, len(data)), int64(len(data)), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			probe := securityProbeFunc(func(context.Context, string, []byte, int64) error { calls++; return nil })
			_, err := copySecurityStream(t.Context(), io.Discard, bytes.NewReader(tc.data), tc.size, strings.Repeat("a", 64), probe)
			if (err != nil) != tc.wantErr || calls != tc.wantCalls {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	probe := securityProbeFunc(func(context.Context, string, []byte, int64) error { cancel(); return nil })
	n, err := copySecurityStream(ctx, io.Discard, bytes.NewReader(data), int64(len(data)), strings.Repeat("a", 64), probe)
	if !errors.Is(err, context.Canceled) || n != securityPrefixBytes {
		t.Fatalf("cancel: %d %v", n, err)
	}
}

func TestSecurityStreamRejectedStageDoesNotPublishOrLeakQuota(t *testing.T) {
	data := make([]byte, 2*securityPrefixBytes)
	data[0], data[1] = 0x80, 2
	a, task, source, _ := securityFixture(t, data, true)
	a.cap, a.taskCap = 4<<20, 4<<20
	task.Generation = strings.Repeat("a", 64)
	a.prefixProber = securityProbeFunc(func(context.Context, string, []byte, int64) error { return errors.New("rejected") })
	release, err := a.Reserve(t.Context(), task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := a.Stage(t.Context(), task, source, 4<<20)
	if err == nil || artifact != (security.Artifact{}) {
		t.Fatalf("rejected prefix published artifact: %+v %v", artifact, err)
	}
	release()
	if a.used != 0 || a.reserved != 0 {
		t.Fatalf("leaked quota: %d/%d", a.used, a.reserved)
	}
	// A new claim can stage all bytes; only subsequent complete scanning may approve.
	a.prefixProber = nil
	release, err = a.Reserve(t.Context(), task, source.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	artifact, err = a.Stage(t.Context(), task, source, 4<<20)
	if err != nil || artifact.Size != int64(len(data)) {
		t.Fatalf("restage: %+v %v", artifact, err)
	}
}
