// ==============================================================================
// JOCKY Artifact Registry (Go)
//
// Purpose:
//   File-backed catalog of compiled JOCKY artifacts. Records the size and
//   cryptographic digests of each .jkm produced by a build so that a later
//   verification step can prove the binary was not swapped after signing.
//   Mirrors the behaviour of ci/py/registry.py so the two toolchains agree.
//
//   Blue-team scope: this registry is append-oriented and local to the build
//   workspace. It performs no remote calls and no destructive operations.
//
// Inputs:
//   A registry directory path, plus artifact paths to register.
//
// Outputs:
//   A JSON index at <dir>/index.json, and Go values for in-process use.
//
// Exit Codes:
//   None (library). Errors are returned to the caller.
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
// ==============================================================================
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FROSTY-MUG/jocky/ci/go/internal/artifact"
)

// Entry is one recorded artifact in the registry index.
type Entry struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	SizeBytes    int64  `json:"size_bytes"`
	SHA256       string `json:"sha256"`
	Blake3       string `json:"blake3,omitempty"`
	Target       string `json:"target"`
	Seed         *int64 `json:"seed,omitempty"`
	RegisteredAt string `json:"registered_at"`
}

// Index is the on-disk registry document.
type Index struct {
	SchemaVersion int     `json:"schema_version"`
	Artifacts     []Entry `json:"artifacts"`
}

// Registry is a handle on a registry directory.
type Registry struct {
	dir       string
	indexPath string
}

// New opens (creating if needed) a registry rooted at dir.
func New(dir string) (*Registry, error) {
	if dir == "" {
		return nil, fmt.Errorf("registry: directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("registry: create dir %q: %w", dir, err)
	}
	r := &Registry{dir: dir, indexPath: filepath.Join(dir, "index.json")}
	if _, err := os.Stat(r.indexPath); os.IsNotExist(err) {
		if err := r.save(&Index{SchemaVersion: 1, Artifacts: []Entry{}}); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Registry) load() (*Index, error) {
	data, err := os.ReadFile(r.indexPath)
	if err != nil {
		return nil, fmt.Errorf("registry: read index: %w", err)
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("registry: parse index: %w", err)
	}
	if idx.Artifacts == nil {
		idx.Artifacts = []Entry{}
	}
	return &idx, nil
}

func (r *Registry) save(idx *Index) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: encode index: %w", err)
	}
	if err := os.WriteFile(r.indexPath, data, 0o644); err != nil {
		return fmt.Errorf("registry: write index: %w", err)
	}
	return nil
}

// Register hashes path and records it in the index. Re-registering identical
// contents is a no-op, keeping the index deduplicated by SHA-256.
func (r *Registry) Register(path, target string, seed *int64) (*Entry, error) {
	art, err := artifact.Hash(path)
	if err != nil {
		return nil, err
	}

	idx, err := r.load()
	if err != nil {
		return nil, err
	}

	entry := Entry{
		Name:         art.Name,
		Path:         art.Path,
		SizeBytes:    art.SizeBytes,
		SHA256:       art.SHA256,
		Blake3:       art.Blake3,
		Target:       target,
		Seed:         seed,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}

	kept := idx.Artifacts[:0]
	for _, e := range idx.Artifacts {
		if e.SHA256 != entry.SHA256 {
			kept = append(kept, e)
		}
	}
	idx.Artifacts = append(kept, entry)

	if err := r.save(idx); err != nil {
		return nil, err
	}
	return &entry, nil
}

// List returns every recorded artifact.
func (r *Registry) List() ([]Entry, error) {
	idx, err := r.load()
	if err != nil {
		return nil, err
	}
	return idx.Artifacts, nil
}

// FindByDigest returns the entry whose SHA-256 matches digest, if any.
func (r *Registry) FindByDigest(digest string) (*Entry, error) {
	entries, err := r.List()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].SHA256 == digest {
			return &entries[i], nil
		}
	}
	return nil, nil
}
