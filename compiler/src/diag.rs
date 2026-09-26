use crate::ast::Span;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// E0101: Lexer tokenization error (invalid character, unclosed literal)
    E0101,
    /// E0201: Syntax / grammar parser error (unexpected token, missing delimiter)
    E0201,
    /// E0301: Type checking / semantic error (type mismatch, undefined symbol)
    E0301,
    /// E0401: Capability denylist policy violation (§0.2 forbidden primitive)
    E0401,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::E0101 => write!(f, "E0101"),
            ErrorCode::E0201 => write!(f, "E0201"),
            ErrorCode::E0301 => write!(f, "E0301"),
            ErrorCode::E0401 => write!(f, "E0401"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    pub code: ErrorCode,
    pub message: String,
    pub span: Span,
    pub notes: Vec<String>,
}

impl Diagnostic {
    pub fn new(code: ErrorCode, message: impl Into<String>, span: Span) -> Self {
        Self {
            code,
            message: message.into(),
            span,
            notes: Vec::new(),
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn lexer(message: impl Into<String>, span: Span) -> Self {
        Self::new(ErrorCode::E0101, message, span)
    }

    pub fn parser(message: impl Into<String>, span: Span) -> Self {
        Self::new(ErrorCode::E0201, message, span)
    }

    pub fn typecheck(message: impl Into<String>, span: Span) -> Self {
        Self::new(ErrorCode::E0301, message, span)
    }

    pub fn denylist(primitive: &str, span: Span) -> Self {
        Self::new(
            ErrorCode::E0401,
            format!("Denylist violation: primitive '{primitive}' is forbidden by JOCKY §0.2 safety constraints"),
            span,
        ).with_note("JOCKY is strictly defensive DFIR software. Exploitation, persistence, injection, and credential theft are barred by policy.")
    }

    /// Renders this diagnostic as a formatted compiler error message with line, column,
    /// and source caret highlighting.
    pub fn render(&self, source: &str, filename: &str) -> String {
        let (line_no, col_no, line_str) = get_line_and_col(source, self.span.start);
        let mut out = format!(
            "error[{}]: {}\n  --> {}:{}:{}\n   |\n{:4} | {}\n   | ",
            self.code, self.message, filename, line_no, col_no, line_no, line_str
        );

        let col_idx = col_no.saturating_sub(1);
        for _ in 0..col_idx {
            out.push(' ');
        }
        let width = if self.span.end > self.span.start {
            (self.span.end - self.span.start).min(line_str.len().saturating_sub(col_idx).max(1))
        } else {
            1
        };
        for _ in 0..width {
            out.push('^');
        }
        out.push('\n');

        for note in &self.notes {
            out.push_str(&format!("   = note: {}\n", note));
        }

        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "error[{}]: {} at {}..{}",
            self.code, self.message, self.span.start, self.span.end
        )
    }
}

impl std::error::Error for Diagnostic {}

/// Computes 1-based (line, column, line_text) for a byte offset in `source`.
pub fn get_line_and_col(source: &str, offset: usize) -> (usize, usize, &str) {
    let mut current_offset = 0;
    let mut line_no = 1;

    for line in source.split_inclusive('\n') {
        let next_offset = current_offset + line.len();
        if offset >= current_offset && offset < next_offset {
            let col = offset - current_offset + 1;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            return (line_no, col, trimmed);
        }
        current_offset = next_offset;
        line_no += 1;
    }

    let last_line = source.lines().last().unwrap_or("");
    (line_no.max(1), 1, last_line)
}
