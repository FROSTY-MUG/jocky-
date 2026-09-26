//! JOCKY Compiler (jockyc) CLI
//!
//! Purpose: Main compiler binary supporting lexing, parsing, denylist validation,
//!          typechecking, diversification passes, LLVM code generation (ELF/COFF),
//!          Ed25519 cryptographic key generation, and .jkm container packaging/signing.
//! Inputs: JOCKY source files (.jky), target triples, build seeds, cryptographic keys.
//! Outputs: Object files (.o, .obj), LLVM IR (.ll), signed/attested modules (.jkm), keys.
//! Exit Codes:
//!   0 - Compilation, checking, keygen, or container generation succeeded.
//!   1 - Frontend error, denylist violation, codegen failure, or invalid args.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use clap::{Parser as ClapParser, Subcommand};
use jockyc::jkm::container::JkmContainer;
use jockyc::jkm::manifest::JkmManifest;
use jockyc::jkm::sign::{generate_keypair, load_private_key, save_private_key, save_public_key};
use jockyc::passes::diversify::diversify;
use jockyc::{check_source, emit_object_with_ir, parse, tokenize, typecheck, Diagnostic};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(ClapParser, Debug)]
#[command(name = "jockyc")]
#[command(
    about = "JOCKY v0.1 DFIR language compiler and analysis tool",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Direct file path when invoking with top-level flags
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Emit AST directly via flag
    #[arg(long)]
    emit_ast: bool,

    /// Emit tokens directly via flag
    #[arg(long)]
    emit_tokens: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse source file, run denylist pass, and print diagnostics
    Check {
        /// Source file path (.jky)
        file: PathBuf,
    },
    /// Parse and pretty-print the AST
    EmitAst {
        /// Source file path (.jky)
        file: PathBuf,
    },
    /// Lex and print all tokens with spans
    EmitTokens {
        /// Source file path (.jky)
        file: PathBuf,
    },
    /// Generate an Ed25519 keypair for .jkm module attestation
    Keygen {
        /// Output path for private key (public key will be saved with .pub extension)
        #[arg(long)]
        out: PathBuf,
    },
    /// Compile source file to an object file or signed .jkm container
    Build {
        /// Source file path (.jky)
        file: PathBuf,

        /// Target triple (e.g. x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc)
        #[arg(long, default_value = "x86_64-unknown-linux-gnu")]
        target: String,

        /// Output path (.o, .obj, or .jkm)
        #[arg(long)]
        out: PathBuf,

        /// Also emit LLVM IR text (.ll)
        #[arg(long)]
        emit_ir: bool,

        /// Deterministic PRNG seed for polymorphism / diversification
        #[arg(long)]
        seed: Option<u64>,

        /// Sign the resulting .jkm module with Ed25519
        #[arg(long)]
        sign: bool,

        /// Path to Ed25519 private key for signing
        #[arg(long)]
        key: Option<PathBuf>,

        /// Number of polymorphic variants to generate (default 1)
        #[arg(long, default_value = "1")]
        variant_count: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check { file }) => run_check(&file),
        Some(Commands::EmitAst { file }) => run_emit_ast(&file),
        Some(Commands::EmitTokens { file }) => run_emit_tokens(&file),
        Some(Commands::Keygen { out }) => run_keygen(&out),
        Some(Commands::Build {
            file,
            target,
            out,
            emit_ir,
            seed,
            sign,
            key,
            variant_count: _,
        }) => run_build(&file, &target, &out, emit_ir, seed, sign, key),
        None => {
            if let Some(file) = cli.file {
                if cli.emit_ast {
                    run_emit_ast(&file);
                } else if cli.emit_tokens {
                    run_emit_tokens(&file);
                } else {
                    run_check(&file);
                }
            } else {
                eprintln!("error: no command or file specified. Use --help for usage.");
                process::exit(1);
            }
        }
    }
}

fn read_source(path: &PathBuf) -> String {
    match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: failed to read file '{}': {}", path.display(), err);
            process::exit(1);
        }
    }
}

fn print_diagnostics(diagnostics: &[Diagnostic], source: &str, filename: &str) {
    for diag in diagnostics {
        eprintln!("{}", diag.render(source, filename));
    }
}

fn run_check(path: &PathBuf) {
    let source = read_source(path);
    let filename = path.to_string_lossy();
    match check_source(&source) {
        Ok(_) => {
            println!("OK: {} passed frontend verification.", filename);
            process::exit(0);
        }
        Err(diags) => {
            print_diagnostics(&diags, &source, &filename);
            process::exit(1);
        }
    }
}

fn run_keygen(out: &PathBuf) {
    let (sk, vk) = generate_keypair();
    if let Err(e) = save_private_key(&sk, out) {
        eprintln!("error: failed to write private key: {}", e);
        process::exit(1);
    }

    let pub_path = if let Some(stem) = out.file_stem() {
        let parent = out.parent().unwrap_or_else(|| std::path::Path::new(""));
        parent.join(format!("{}.pub", stem.to_string_lossy()))
    } else {
        out.with_extension("pub")
    };

    if let Err(e) = save_public_key(&vk, &pub_path) {
        eprintln!("error: failed to write public key: {}", e);
        process::exit(1);
    }

    println!("[OK] Generated Ed25519 keypair:");
    println!("  Private Key: {}", out.display());
    println!("  Public Key:  {}", pub_path.display());
}

fn run_build(
    file: &PathBuf,
    target: &str,
    out: &PathBuf,
    emit_ir: bool,
    seed: Option<u64>,
    sign: bool,
    key: Option<PathBuf>,
) {
    let source = read_source(file);
    let filename = file.to_string_lossy();

    // 1. Lex + parse the file
    let program = match parse(&source) {
        Ok(p) => p,
        Err(d) => {
            print_diagnostics(&[d], &source, &filename);
            process::exit(1);
        }
    };

    // 2. Run denylist pass. If any diagnostic, print + exit 1.
    if let Err(diags) = jockyc::passes::denylist::check(&program) {
        print_diagnostics(&diags, &source, &filename);
        process::exit(1);
    }

    // 3. Run typechecker. If any diagnostic, print + exit 1.
    let mut hir = match typecheck(&program) {
        Ok(h) => h,
        Err(diags) => {
            print_diagnostics(&diags, &source, &filename);
            process::exit(1);
        }
    };

    // 4. Diversification passes (if seed is provided)
    let build_seed = seed.unwrap_or(0);
    let symbol_map = if seed.is_some() {
        diversify(&mut hir, build_seed)
    } else {
        BTreeMap::new()
    };

    let is_jkm = out.extension().and_then(|e| e.to_str()) == Some("jkm");

    if is_jkm {
        // Compile object to a temporary file
        let temp_obj = out.with_extension("tmp.o");
        if let Err(err) = emit_object_with_ir(&hir, target, &temp_obj, emit_ir) {
            eprintln!("error: codegen failed: {}", err);
            let _ = fs::remove_file(&temp_obj);
            process::exit(1);
        }

        let code_bytes = match fs::read(&temp_obj) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: failed to read compiled object bytes: {}", e);
                let _ = fs::remove_file(&temp_obj);
                process::exit(1);
            }
        };
        let _ = fs::remove_file(&temp_obj);

        let module_name = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("module");

        let manifest = JkmManifest::new(
            module_name,
            target,
            build_seed,
            &code_bytes,
            symbol_map,
        );

        let mut container = match JkmContainer::new(target, build_seed, code_bytes, &manifest) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: failed to create .jkm container: {}", e);
                process::exit(1);
            }
        };

        if sign {
            let key_path = key.unwrap_or_else(|| {
                eprintln!("error: --key <PATH> is required when --sign is specified");
                process::exit(1);
            });
            let sk = match load_private_key(&key_path) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: failed to load signing key: {}", e);
                    process::exit(1);
                }
            };
            container.sign(&sk);
        }

        let container_bytes = container.to_bytes();
        if let Some(parent) = out.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::write(out, container_bytes) {
            eprintln!("error: failed to write .jkm output file: {}", e);
            process::exit(1);
        }

        println!("OK: {} -> {}", file.display(), out.display());
    } else {
        // Direct compilation to object file (.o / .obj)
        if let Err(err) = emit_object_with_ir(&hir, target, out, emit_ir) {
            eprintln!("error: codegen failed: {}", err);
            process::exit(1);
        }
        println!("OK: {} -> {}", file.display(), out.display());
    }
}

fn run_emit_ast(path: &PathBuf) {
    let source = read_source(path);
    let filename = path.to_string_lossy();
    match parse(&source) {
        Ok(program) => {
            match serde_json::to_string_pretty(&program) {
                Ok(json) => println!("{}", json),
                Err(_) => println!("{:#?}", program),
            }
            process::exit(0);
        }
        Err(diag) => {
            print_diagnostics(&[diag], &source, &filename);
            process::exit(1);
        }
    }
}

fn run_emit_tokens(path: &PathBuf) {
    let source = read_source(path);
    let filename = path.to_string_lossy();
    match tokenize(&source) {
        Ok(tokens) => {
            for (token, span) in tokens {
                let (line, col, _) = jockyc::diag::get_line_and_col(&source, span.start);
                println!(
                    "[{:4}..{:4}] (line {:3}, col {:3}): {:?}",
                    span.start, span.end, line, col, token
                );
            }
            process::exit(0);
        }
        Err(diag) => {
            print_diagnostics(&[diag], &source, &filename);
            process::exit(1);
        }
    }
}
