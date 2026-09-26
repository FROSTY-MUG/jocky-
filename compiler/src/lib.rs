pub mod ast;
pub mod diag;
pub mod lexer;
pub mod parser;
pub mod passes;

pub use ast::*;
pub use diag::{Diagnostic, ErrorCode};
pub use lexer::{tokenize, Token};
pub use parser::Parser;

/// Parses source text into a JOCKY AST Program.
pub fn parse(source: &str) -> Result<ast::Program, diag::Diagnostic> {
    let tokens = lexer::tokenize(source)?;
    let mut parser = parser::Parser::new(source, tokens);
    parser.parse_program()
}

/// Parses source text and executes frontend validation passes (including denylist check).
pub fn check_source(source: &str) -> Result<ast::Program, Vec<diag::Diagnostic>> {
    let program = match parse(source) {
        Ok(p) => p,
        Err(d) => return Err(vec![d]),
    };

    passes::denylist::check(&program)?;
    Ok(program)
}
