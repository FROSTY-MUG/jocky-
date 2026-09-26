// ==============================================================================
// JOCKY Artifact Package - BLAKE3 backend (blake3 build tag)
//
// Purpose:
//   Real BLAKE3 implementation for artifact digests, enabled with:
//
//       go build -tags blake3 ./...
//
//   Backing module: lukechampine.com/blake3 (pure Go, no cgo required).
//
// Inputs:
//   None (constructor only).
//
// Outputs:
//   (blake3Hasher, bool, error) - a genuine BLAKE3 hasher, ok=true, nil error.
//
// Exit Codes:
//   None (library).
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation.
// ==============================================================================
//go:build blake3

package artifact

import (
	"github.com/zeebo/blake3"
)

// blake3HasherImpl adapts *blake3.Hasher to the blake3Hasher interface.
type blake3HasherImpl struct {
	h *blake3.Hasher
}

func (b *blake3HasherImpl) Write(p []byte) (int, error) { return b.h.Write(p) }
func (b *blake3HasherImpl) Close() error               { return nil }

func (b *blake3HasherImpl) HexString() string {
	sum := b.h.Sum(nil)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(sum)*2)
	for _, c := range sum {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}

// newBLAKE3Backend returns a real BLAKE3 hasher.
func newBLAKE3Backend() (blake3Hasher, bool, error) {
	return &blake3HasherImpl{h: blake3.New()}, true, nil
}
