// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

const securityPrefixBytes = 64 << 10

// copySecurityStream applies backpressure at one bounded prefix, before reading
// the rest of a large file. It never interprets pickle in the MatrixHub process.
// The caller must still validate length/digest, seal, and request a full scan.
func copySecurityStream(ctx context.Context, dst io.Writer, src io.Reader, size int64, generation string, prober security.PrefixProber) (int64, error) {
	if size < 0 || size == math.MaxInt64 {
		return 0, errors.New("invalid security stream size")
	}
	reader := &securityContextReader{ctx: ctx, r: io.LimitReader(src, size+1)}
	writer := &securityBoundedWriter{w: dst, remaining: size}
	var copied int64
	if prober != nil && size > securityPrefixBytes {
		prefix := make([]byte, securityPrefixBytes)
		n, err := io.ReadFull(reader, prefix)
		if err != nil {
			return 0, err
		}
		written, err := writer.Write(prefix[:n])
		copied = int64(written)
		if err != nil {
			return copied, err
		}
		if written != n {
			return copied, io.ErrShortWrite
		}
		// This is only a routing hint. Both isolated parsers independently
		// identify format; every other input still receives a complete scan.
		if prefix[0] == 0x80 && (prefix[1] == 2 || prefix[1] == 4) {
			if err = prober.ProbeLegacyPrefix(ctx, generation, prefix, size); err != nil {
				return copied, err
			}
		}
	}
	buffer := securitySnapshotHashBuffers.Get().(*[]byte)
	defer securitySnapshotHashBuffers.Put(buffer)
	n, err := io.CopyBuffer(writer, reader, *buffer)
	return copied + n, err
}
