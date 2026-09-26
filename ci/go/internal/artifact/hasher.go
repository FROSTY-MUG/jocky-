// ==============================================================================
// JOCKY Artifact Package - hasher interface
//
// Purpose:
//   Declares the minimal digest interface used by the artifact hashing loop,
//   shared by the blake3-tagged and default build variants.
//
// Inputs:
//   None (type declaration).
//
// Outputs:
//   blake3Hasher interface.
//
// Exit Codes:
//   None (library).
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation.
// ==============================================================================
package artifact

import "io"

// blake3Hasher is the minimal interface the hashing loop needs: a streaming
// writer that can report its final digest as lowercase hex.
type blake3Hasher interface {
	io.WriteCloser

	// HexString returns the lowercase hex digest of everything written.
	HexString() string
}
