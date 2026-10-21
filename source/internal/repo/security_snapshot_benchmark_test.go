// Copyright The MatrixHub Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

// openSnapshotBeforeV13 preserves the pre-change Open path for a paired,
// same-process local microbenchmark. It is test-only and never grants product
// admission. Both variants fully hash the same sealed fixture on every call.
func openSnapshotBeforeV13(ctx context.Context, a *SecurityArtifacts, artifact security.Artifact) (io.ReadSeekCloser, error) {
	if !artifactIDPattern.MatchString(artifact.ID) || !validDigest(artifact.Digest) || artifact.Size < 0 {
		return nil, errors.New("invalid approved snapshot descriptor")
	}
	for _, p := range []string{path.Dir(artifact.ID), artifact.ID} {
		info, err := a.root.Lstat(p)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("snapshot symbolic links are forbidden")
		}
	}
	f, err := a.root.Open(artifact.ID)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != artifact.Size {
		return nil, errors.New("approved snapshot size or type mismatch")
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, &securityContextReader{ctx: ctx, r: io.LimitReader(f, artifact.Size+1)}, make([]byte, 128<<10))
	if err != nil {
		return nil, err
	}
	if n != artifact.Size || hex.EncodeToString(h.Sum(nil)) != artifact.Digest {
		return nil, errors.New("approved snapshot digest mismatch")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

func BenchmarkSecuritySnapshotOpen(b *testing.B) {
	for _, size := range []int{64 << 10, 8 << 20} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			a, artifact, _ := sealedSnapshotFixture(b, bytes.Repeat([]byte("x"), size))
			for _, baseline := range []bool{true, false} {
				name := "hardened"
				if baseline {
					name = "baseline"
				}
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(artifact.Size)
					for b.Loop() {
						var reader io.ReadSeekCloser
						var err error
						if baseline {
							reader, err = openSnapshotBeforeV13(context.Background(), a, artifact)
						} else {
							reader, err = a.Open(context.Background(), artifact)
						}
						if err != nil {
							b.Fatal(err)
						}
						var first [1]byte
						if _, err = io.ReadFull(reader, first[:]); err != nil || first[0] != 'x' {
							b.Fatalf("verified reader offset/content mismatch: %v", err)
						}
						if err = reader.Close(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
