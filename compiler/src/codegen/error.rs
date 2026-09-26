use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CodegenError {
    LlvmError(String),
    UnsupportedExpression(String),
    UnsupportedType(String),
    IoError(io::Error),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodegenError::LlvmError(msg) => write!(f, "LLVM error: {}", msg),
            CodegenError::UnsupportedExpression(msg) => write!(f, "Unsupported expression: {}", msg),
            CodegenError::UnsupportedType(msg) => write!(f, "Unsupported type: {}", msg),
            CodegenError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for CodegenError {}

impl From<io::Error> for CodegenError {
    fn from(e: io::Error) -> Self {
        CodegenError::IoError(e)
    }
}
