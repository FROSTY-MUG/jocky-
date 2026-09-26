// ==============================================================================
// JOCKY Artifact Package - BLAKE3 backend (default build)
//
// Purpose:
//   Supplies the optional BLAKE3 digest used alongside SHA-256 for artifact
//   identity. BLAKE3 is provided by the pure-Go module lukechampine.com/blake3
//   and is enabled with:
//
//       go build -tags blake3 ./...
//
//   Without the build tag this file compiles and newBLAKE3Backend reports
//   ok=false, so the caller omits the BLAKE3 field entirely rather than
//   reporting a fabricated or substituted digest.
//
// Inputs:
//   None (constructor only).
//
// Outputs:
//   (blake3Hasher, bool, error) - the hasher plus whether it is a genuine
//   BLAKE3 implementation. A non-nil error means initialisation failed.
//
// Exit Codes:
//   None (library).
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation.
// ==============================================================================
//go:build !blake3

package artifact

// newBLAKE3Backend reports that no BLAKE3 implementation is linked in.
// The caller must treat ok=false as "omit the BLAKE3 digest".
func newBLAKE3Backend() (blake3Hasher, bool, error) {
	return nil, false, nil
}
