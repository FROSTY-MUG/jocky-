//! JOCKY Container Attestation Verification CLI (jocky-verify)
//!
//! Purpose: Standalone verification binary that parses a .jkm binary container, extracts
//!          the CBOR manifest, verifies the embedded Ed25519 digital signature against
//!          the provided public key, and prints attestation details.
//! Inputs: Path to .jkm container file, path to Ed25519 public key file.
//! Outputs: Verification status to stdout, error details to stderr.
//! Exit Codes:
//!   0 - Signature valid and container verified intact.
//!   1 - Signature invalid, container tampered, or missing/invalid arguments.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use clap::Parser;
use jockyc::jkm::container::JkmContainer;
use jockyc::jkm::sign::load_public_key;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "jocky-verify",
    about = "Attestation and signature verification tool for JOCKY .jkm modules",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    /// Path to the .jkm container to verify
    #[arg(value_name = "CONTAINER")]
    container: PathBuf,

    /// Path to Ed25519 public key file (header-wrapped hex or raw hex)
    #[arg(short = 'p', long = "pubkey", value_name = "FILE")]
    pubkey: PathBuf,

    /// Verbose output (prints manifest and code hashes)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() {
    let args = Cli::parse();

    if let Err(e) = run(args) {
        eprintln!("[ERROR] {}", e);
        process::exit(1);
    }
}

fn run(args: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let container_bytes = fs::read(&args.container)
        .map_err(|e| format!("Failed to read container {:?}: {}", args.container, e))?;

    let container = JkmContainer::from_bytes(&container_bytes)
        .map_err(|e| format!("Invalid .jkm container format: {}", e))?;

    let pubkey = load_public_key(&args.pubkey)
        .map_err(|e| format!("Failed to load public key from {:?}: {}", args.pubkey, e))?;

    container
        .verify(&pubkey)
        .map_err(|e| format!("Verification failed: {}", e))?;

    println!("[OK] Signature verified successfully for {:?}", args.container);

    let manifest = container.parse_manifest()?;
    println!("  Module Name:       {}", manifest.module_name);
    println!("  Target Triple:     {}", manifest.target_triple);
    println!("  Build Seed:        0x{:016x}", manifest.build_seed);
    println!("  Code BLAKE3:       {}", manifest.code_hash_blake3);
    println!("  Code SHA256:       {}", manifest.code_hash_sha256);
    println!("  Compiler Version:  {}", manifest.compiler_version);

    if args.verbose {
        println!("\nSymbol Mapping ({} symbols):", manifest.symbol_map.len());
        for (orig, mangled) in &manifest.symbol_map {
            println!("  {} -> {}", orig, mangled);
        }
    }

    Ok(())
}
