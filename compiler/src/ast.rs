use serde::Serialize;

/// Byte-offset source span for tokens and AST nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn merge(self, other: Span) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Program {
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Item {
    Fn(FnDecl),
    Struct(StructDecl),
    Import(ImportDecl),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportDecl {
    pub path: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StructDecl {
    pub name: String,
    pub fields: Vec<StructField>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StructField {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FnDecl {
    pub name: String,
    pub params: Vec<Param>,
    /// Return type of function. Defaults to `Type::I32` if omitted in source code
    /// (`fn main()` defaults to `fn main() -> i32` per JOCKY v0.1 entry convention).
    pub return_type: Type,
    pub body: Block,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Type {
    I32,
    I64,
    U32,
    U64,
    F64,
    Bool,
    String,
    Array(Box<Type>),
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssignTarget {
    pub base: String,
    pub fields: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Stmt {
    Let {
        name: String,
        is_mut: bool,
        ty: Option<Type>,
        init: Option<Expr>,
        span: Span,
    },
    Assign {
        target: AssignTarget,
        value: Expr,
        span: Span,
    },
    If {
        cond: Expr,
        then_branch: Block,
        else_branch: Option<ElseBranch>,
        span: Span,
    },
    For {
        var: String,
        iter: Expr,
        body: Block,
        span: Span,
    },
    While {
        cond: Expr,
        body: Block,
        span: Span,
    },
    Return {
        value: Option<Expr>,
        span: Span,
    },
    Expr {
        expr: Expr,
        span: Span,
    },
}

impl Stmt {
    pub fn span(&self) -> Span {
        match self {
            Stmt::Let { span, .. } => *span,
            Stmt::Assign { span, .. } => *span,
            Stmt::If { span, .. } => *span,
            Stmt::For { span, .. } => *span,
            Stmt::While { span, .. } => *span,
            Stmt::Return { span, .. } => *span,
            Stmt::Expr { span, .. } => *span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ElseBranch {
    Block(Block),
    If(Box<Stmt>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum BinaryOp {
    Add, Sub, Mul, Div, Rem,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
    In,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Literal {
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Expr {
    Literal {
        lit: Literal,
        span: Span,
    },
    Path {
        segments: Vec<String>,
        span: Span,
    },
    Array {
        elements: Vec<Expr>,
        span: Span,
    },
    StructInit {
        name: String,
        fields: Vec<(String, Expr)>,
        span: Span,
    },
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
    MethodCall {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
        span: Span,
    },
    FieldAccess {
        receiver: Box<Expr>,
        field: String,
        span: Span,
    },
    Index {
        receiver: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::Literal { span, .. } => *span,
            Expr::Path { span, .. } => *span,
            Expr::Array { span, .. } => *span,
            Expr::StructInit { span, .. } => *span,
            Expr::Unary { span, .. } => *span,
            Expr::Binary { span, .. } => *span,
            Expr::Call { span, .. } => *span,
            Expr::MethodCall { span, .. } => *span,
            Expr::FieldAccess { span, .. } => *span,
            Expr::Index { span, .. } => *span,
        }
    }
}
