use clap::{Parser as ClapParser, Subcommand};
use jockyc::{check_source, parse, tokenize, Diagnostic};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(ClapParser, Debug)]
#[command(name = "jockyc")]
#[command(about = "JOCKY v0.1 DFIR language compiler and analysis tool", long_about = None)]
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
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check { file }) => run_check(&file),
        Some(Commands::EmitAst { file }) => run_emit_ast(&file),
        Some(Commands::EmitTokens { file }) => run_emit_tokens(&file),
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
