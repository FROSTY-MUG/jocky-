// ==============================================================================
// JOCKY Artifact Package
//
// Purpose:
//   Computes and compares cryptographic digests for compiled JOCKY artifacts
//   (.jkm / .o / .obj). Supplies the primitives the CI artifact manager uses to
//   record exactly which binary a build produced.
//
// Inputs:
//   A filesystem path to a compiled artifact.
//
// Outputs:
//   Artifact struct carrying size plus SHA-256 and BLAKE3 digests.
//
// Exit Codes:
//   None (library). Errors are returned to the caller.
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
// ==============================================================================
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Artifact describes a single compiled JOCKY binary and its digests.
type Artifact struct {
	// Path is the artifact location on disk.
	Path string `json:"path"`
	// Name is the base file name.
	Name string `json:"name"`
	// SizeBytes is the file length in bytes.
	SizeBytes int64 `json:"size_bytes"`
	// SHA256 is the lowercase hex SHA-256 digest of the file contents.
	SHA256 string `json:"sha256"`
	// Blake3 is the lowercase hex BLAKE3 digest, or "" if the optional
	// blake3 dependency is unavailable.
	Blake3 string `json:"blake3,omitempty"`
}

// Hash reads path and returns its size plus SHA-256 and BLAKE3 digests.
// Both digests are computed in a single streaming pass over the file.
func Hash(path string) (*Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open artifact %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat artifact %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("artifact %q is a directory, not a file", path)
	}

	sha := sha256.New()
	// BLAKE3 is an optional dependency supplied via the "blake3" build tag.
	// Without the tag the backend reports ok=false and the BLAKE3 field is
	// omitted rather than filled with a substituted digest.
	b3, hasBLAKE3, err := newBLAKE3Backend()
	if err != nil {
		return nil, err
	}
	if hasBLAKE3 {
		defer b3.Close()
	} else {
		b3 = nil
	}

	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			sha.Write(chunk)
			if b3 != nil {
				b3.Write(chunk)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read artifact %q: %w", path, readErr)
		}
	}

	art := &Artifact{
		Path:      path,
		Name:      info.Name(),
		SizeBytes: info.Size(),
		SHA256:    hex.EncodeToString(sha.Sum(nil)),
	}
	if b3 != nil {
		art.Blake3 = b3.HexString()
	}
	return art, nil
}

// Verify recomputes the digest of path and reports whether it matches want.
// It is used by CI to confirm an artifact was not modified after signing.
func Verify(path, wantSHA256 string) (bool, error) {
	art, err := Hash(path)
	if err != nil {
		return false, err
	}
	return art.SHA256 == wantSHA256, nil
}
