use crate::ast::{BinaryOp, Literal, Span, UnaryOp};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HirType {
    I32,
    I64,
    U32,
    U64,
    F64,
    Bool,
    String,
    Array(Box<HirType>),
    Custom(String),
    Void,
    Unknown,
}

impl HirType {
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            HirType::I32 | HirType::I64 | HirType::U32 | HirType::U64 | HirType::F64
        )
    }

    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            HirType::I32 | HirType::I64 | HirType::U32 | HirType::U64
        )
    }

    pub fn display_name(&self) -> String {
        match self {
            HirType::I32 => "i32".to_string(),
            HirType::I64 => "i64".to_string(),
            HirType::U32 => "u32".to_string(),
            HirType::U64 => "u64".to_string(),
            HirType::F64 => "f64".to_string(),
            HirType::Bool => "bool".to_string(),
            HirType::String => "string".to_string(),
            HirType::Array(inner) => format!("[{}]", inner.display_name()),
            HirType::Custom(name) => name.clone(),
            HirType::Void => "()".to_string(),
            HirType::Unknown => "<unknown>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirProgram {
    pub items: Vec<HirItem>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HirItem {
    Fn(HirFn),
    Struct(HirStruct),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirStruct {
    pub name: String,
    pub fields: Vec<HirStructField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirStructField {
    pub name: String,
    pub ty: HirType,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirParam {
    pub name: String,
    pub ty: HirType,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirFn {
    pub name: String,
    pub params: Vec<HirParam>,
    pub return_type: HirType,
    pub body: HirBlock,
    pub is_extern: bool,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirBlock {
    pub stmts: Vec<HirStmt>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirAssignTarget {
    pub base: String,
    pub fields: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HirStmt {
    Let {
        name: String,
        is_mut: bool,
        ty: HirType,
        init: Option<HirExpr>,
        span: Span,
    },
    Assign {
        target: HirAssignTarget,
        value: HirExpr,
        span: Span,
    },
    If {
        cond: HirExpr,
        then_branch: HirBlock,
        else_branch: Option<HirElseBranch>,
        span: Span,
    },
    For {
        var: String,
        iter: HirExpr,
        body: HirBlock,
        span: Span,
    },
    While {
        cond: HirExpr,
        body: HirBlock,
        span: Span,
    },
    Return {
        value: Option<HirExpr>,
        span: Span,
    },
    Expr {
        expr: HirExpr,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HirElseBranch {
    Block(HirBlock),
    If(Box<HirStmt>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HirExpr {
    pub kind: HirExprKind,
    pub ty: HirType,
    pub span: Span,
}

impl HirExpr {
    pub fn new(kind: HirExprKind, ty: HirType, span: Span) -> Self {
        Self { kind, ty, span }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HirExprKind {
    Literal(Literal),
    Path(Vec<String>),
    Array(Vec<HirExpr>),
    StructInit {
        name: String,
        fields: Vec<(String, HirExpr)>,
    },
    Unary {
        op: UnaryOp,
        operand: Box<HirExpr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<HirExpr>,
        right: Box<HirExpr>,
    },
    Call {
        callee: Box<HirExpr>,
        args: Vec<HirExpr>,
    },
    MethodCall {
        receiver: Box<HirExpr>,
        method: String,
        args: Vec<HirExpr>,
    },
    FieldAccess {
        receiver: Box<HirExpr>,
        field: String,
    },
    Index {
        receiver: Box<HirExpr>,
        index: Box<HirExpr>,
    },
}
