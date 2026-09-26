// ==============================================================================
// JOCKY CI Artifact Manager (jocky-artifact)
//
// Purpose:
//   Single-binary helper for CI pipelines. Hashes compiled JOCKY artifacts,
//   records them in a local registry, and verifies that an artifact still
//   matches a previously recorded digest.
//
// Usage:
//   jocky-artifact hash    <artifact>            Print SHA-256 (and BLAKE3).
//   jocky-artifact verify  <artifact> <sha256>   Compare against a digest.
//   jocky-artifact register <artifact> [--registry <dir>] [--target <triple>]
//                                                 [--seed <n>]
//   jocky-artifact list    [--registry <dir>]    List registered artifacts.
//
// Inputs:
//   Subcommand and positional arguments as shown above.
//
// Outputs:
//   Human-readable lines on stdout; errors on stderr.
//
// Exit Codes:
//   0 - Operation succeeded (verify prints OK/MISMATCH and returns 1 on
//       mismatch).
//   1 - Usage error, unreadable artifact, or digest mismatch.
//   2 - Registry operation failed.
//
// Blueprint Section:
//   §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
// ==============================================================================
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/FROSTY-MUG/jocky/ci/go/internal/artifact"
	"github.com/FROSTY-MUG/jocky/ci/go/internal/registry"
)

const usage = `jocky-artifact - JOCKY CI artifact manager

Usage:
  jocky-artifact hash     <artifact>
  jocky-artifact verify   <artifact> <sha256>
  jocky-artifact register <artifact> [-registry <dir>] [-target <triple>] [-seed <n>]
  jocky-artifact list     [-registry <dir>]

Commands:
  hash      Compute and print the SHA-256 and BLAKE3 digests of an artifact.
  verify    Confirm an artifact still matches a recorded SHA-256 digest.
  register  Hash an artifact and record it in the local registry index.
  list      Print every artifact currently in the registry.

Blueprint: Section 4 (CI/CD Polymorphism & Attestation).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "hash":
		os.Exit(cmdHash(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "register":
		os.Exit(cmdRegister(os.Args[2:]))
	case "list":
		os.Exit(cmdList(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// parsePermuted parses args allowing flags to appear before, after, or
// interspersed with positional arguments, and returns the positional arguments
// in their original relative order. A bare "--" terminates flag parsing.
//
// Go's flag package stops at the first non-flag argument, so flags and their
// values are gathered here first and handed to fs.Parse as a contiguous run.
// Boolean flags take no value; every other flag consumes the following token.
func parsePermuted(fs *flag.FlagSet, args []string) []string {
	var flagArgs, positional []string
	sawTerminator := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if sawTerminator {
			positional = append(positional, a)
			continue
		}
		if a == "--" {
			sawTerminator = true
			continue
		}
		if len(a) > 1 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			// Carry the value for non-boolean flags, honouring -name=value.
			name := strings.TrimLeft(a, "-")
			if idx := strings.Index(name, "="); idx >= 0 {
				continue // value is inline
			}
			if f := fs.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue
				}
			}
			if i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	_ = fs.Parse(flagArgs)
	return positional
}

func cmdHash(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "error: hash requires exactly one artifact path")
		return 1
	}
	art, err := artifact.Hash(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("artifact: %s\n", art.Name)
	fmt.Printf("size:     %d\n", art.SizeBytes)
	fmt.Printf("sha256:   %s\n", art.SHA256)
	if art.Blake3 != "" {
		fmt.Printf("blake3:   %s\n", art.Blake3)
	} else {
		fmt.Println("blake3:   (unavailable; rebuild with -tags blake3)")
	}
	return 0
}

func cmdVerify(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "error: verify requires <artifact> <sha256>")
		return 1
	}
	ok, err := artifact.Verify(args[0], args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if ok {
		fmt.Println("OK: digest matches")
		return 0
	}
	fmt.Println("MISMATCH: artifact does not match the expected digest")
	return 1
}

func cmdRegister(args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	registryDir := fs.String("registry", ".jocky-registry", "registry index directory")
	target := fs.String("target", "unknown", "target triple used for the build")
	seed := fs.Int64("seed", 0, "diversification seed used for the build")
	hasSeed := fs.Bool("set-seed", false, "record the seed value even if zero")
	// Go's flag package stops parsing at the first non-flag argument, so
	// separate flags from positionals first. This lets callers write
	// "register <artifact> -seed 7" as well as "-seed 7 <artifact>".
	rest := parsePermuted(fs, args)
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "error: register requires exactly one artifact path")
		return 1
	}

	reg, err := registry.New(*registryDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	var seedPtr *int64
	if *hasSeed || *seed != 0 {
		s := *seed
		seedPtr = &s
	}

	entry, err := reg.Register(rest[0], *target, seedPtr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	fmt.Printf("[OK] registered %s\n", entry.Name)
	fmt.Printf("     sha256: %s\n", entry.SHA256)
	if entry.Blake3 != "" {
		fmt.Printf("     blake3: %s\n", entry.Blake3)
	}
	fmt.Printf("     target: %s\n", entry.Target)
	if entry.Seed != nil {
		fmt.Printf("     seed:   %s\n", strconv.FormatInt(*entry.Seed, 10))
	}
	return 0
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	registryDir := fs.String("registry", ".jocky-registry", "registry index directory")
	parsePermuted(fs, args)

	reg, err := registry.New(*registryDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	entries, err := reg.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	fmt.Printf("Registered artifacts (%d):\n", len(entries))
	for _, e := range entries {
		fmt.Printf("  - %s | sha256: %s | target: %s\n", e.Name, e.SHA256, e.Target)
	}
	return 0
}
