use crate::ast::{
    AssignTarget, BinaryOp, Block, ElseBranch, Expr, FnDecl, Item, Literal, Program, Stmt, Type,
    UnaryOp,
};
use crate::diag::Diagnostic;
use crate::hir::{
    HirAssignTarget, HirBlock, HirElseBranch, HirExpr, HirExprKind, HirFn, HirItem, HirParam,
    HirProgram, HirStmt, HirStruct, HirStructField, HirType,
};
use crate::prelude::Prelude;
use std::collections::HashMap;

pub struct TypeChecker {
    prelude: Prelude,
    structs: HashMap<String, HirStruct>,
    functions: HashMap<String, HirFn>,
    scopes: Vec<HashMap<String, (HirType, bool)>>,
    current_fn_return_type: Option<HirType>,
    diagnostics: Vec<Diagnostic>,
}

impl TypeChecker {
    pub fn new() -> Self {
        let prelude = Prelude::new();
        let mut structs = HashMap::new();
        for (name, s) in &prelude.types {
            structs.insert(name.clone(), s.clone());
        }

        let mut functions = HashMap::new();
        for (name, f) in &prelude.functions {
            functions.insert(name.clone(), f.clone());
        }

        Self {
            prelude,
            structs,
            functions,
            scopes: vec![HashMap::new()],
            current_fn_return_type: None,
            diagnostics: Vec::new(),
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn insert_var(&mut self, name: String, ty: HirType, is_mut: bool) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, (ty, is_mut));
        }
    }

    fn lookup_var(&self, name: &str) -> Option<(HirType, bool)> {
        for scope in self.scopes.iter().rev() {
            if let Some(found) = scope.get(name) {
                return Some(found.clone());
            }
        }
        None
    }

    fn lower_ast_type(&self, ty: &Type) -> HirType {
        match ty {
            Type::I32 => HirType::I32,
            Type::I64 => HirType::I64,
            Type::U32 => HirType::U32,
            Type::U64 => HirType::U64,
            Type::F64 => HirType::F64,
            Type::Bool => HirType::Bool,
            Type::String => HirType::String,
            Type::Array(inner) => HirType::Array(Box::new(self.lower_ast_type(inner))),
            Type::Custom(name) => match name.as_str() {
                "string" | "String" => HirType::String,
                "bool" => HirType::Bool,
                "i32" => HirType::I32,
                "i64" => HirType::I64,
                "u32" => HirType::U32,
                "u64" => HirType::U64,
                "f64" => HirType::F64,
                _ => HirType::Custom(name.clone()),
            },
        }
    }

    fn types_compatible(&self, expected: &HirType, actual: &HirType) -> bool {
        if expected == actual {
            return true;
        }
        if expected == &HirType::Unknown || actual == &HirType::Unknown {
            return true;
        }

        // Integer literal unification: i64 literal can satisfy i32 expected
        if (expected == &HirType::I32 && actual == &HirType::I64)
            || (expected == &HirType::I64 && actual == &HirType::I32)
        {
            return true;
        }

        // Array compatibility
        if let (HirType::Array(expected_inner), HirType::Array(actual_inner)) = (expected, actual) {
            return self.types_compatible(expected_inner, actual_inner);
        }

        // Domain type aliases: path, hash, string
        if (expected == &HirType::String && actual == &HirType::Custom("path".to_string()))
            || (expected == &HirType::Custom("path".to_string()) && actual == &HirType::String)
            || (expected == &HirType::String && actual == &HirType::Custom("hash".to_string()))
            || (expected == &HirType::Custom("hash".to_string()) && actual == &HirType::String)
        {
            return true;
        }

        // Finding.evidence allows both string, pid, and integer representations
        if expected == &HirType::String && actual.is_integer() {
            return true;
        }

        false
    }

    pub fn check_program(mut self, program: &Program) -> Result<HirProgram, Vec<Diagnostic>> {
        // Collect struct declarations
        for item in &program.items {
            if let Item::Struct(s) = item {
                let mut fields = Vec::new();
                for f in &s.fields {
                    fields.push(HirStructField {
                        name: f.name.clone(),
                        ty: self.lower_ast_type(&f.ty),
                        span: f.span,
                    });
                }
                self.structs.insert(
                    s.name.clone(),
                    HirStruct {
                        name: s.name.clone(),
                        fields,
                        span: s.span,
                    },
                );
            }
        }

        // Collect function declarations
        for item in &program.items {
            if let Item::Fn(f) = item {
                let mut params = Vec::new();
                for p in &f.params {
                    params.push(HirParam {
                        name: p.name.clone(),
                        ty: self.lower_ast_type(&p.ty),
                        span: p.span,
                    });
                }
                let return_type = self.lower_ast_type(&f.return_type);
                self.functions.insert(
                    f.name.clone(),
                    HirFn {
                        name: f.name.clone(),
                        params,
                        return_type,
                        body: HirBlock {
                            stmts: vec![],
                            span: f.body.span,
                        },
                        is_extern: false,
                        span: f.span,
                    },
                );
            }
        }

        // Now typecheck each function body
        let mut hir_items = Vec::new();

        for item in &program.items {
            match item {
                Item::Struct(s) => {
                    let mut fields = Vec::new();
                    for f in &s.fields {
                        fields.push(HirStructField {
                            name: f.name.clone(),
                            ty: self.lower_ast_type(&f.ty),
                            span: f.span,
                        });
                    }
                    hir_items.push(HirItem::Struct(HirStruct {
                        name: s.name.clone(),
                        fields,
                        span: s.span,
                    }));
                }
                Item::Fn(f) => {
                    let hir_fn = self.check_fn(f);
                    hir_items.push(HirItem::Fn(hir_fn));
                }
                Item::Import(_) => {
                    // Imports are skipped in v0.1 as prelude provides built-ins
                }
            }
        }

        if !self.diagnostics.is_empty() {
            Err(self.diagnostics)
        } else {
            Ok(HirProgram {
                items: hir_items,
                span: program.span,
            })
        }
    }

    fn check_fn(&mut self, f: &FnDecl) -> HirFn {
        let return_type = self.lower_ast_type(&f.return_type);
        self.current_fn_return_type = Some(return_type.clone());
        self.push_scope();

        let mut params = Vec::new();
        for p in &f.params {
            let ty = self.lower_ast_type(&p.ty);
            self.insert_var(p.name.clone(), ty.clone(), false);
            params.push(HirParam {
                name: p.name.clone(),
                ty,
                span: p.span,
            });
        }

        let body = self.check_block(&f.body);
        self.pop_scope();
        self.current_fn_return_type = None;

        HirFn {
            name: f.name.clone(),
            params,
            return_type,
            body,
            is_extern: false,
            span: f.span,
        }
    }

    fn check_block(&mut self, block: &Block) -> HirBlock {
        self.push_scope();
        let mut stmts = Vec::new();
        for stmt in &block.stmts {
            stmts.push(self.check_stmt(stmt));
        }
        self.pop_scope();
        HirBlock {
            stmts,
            span: block.span,
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) -> HirStmt {
        match stmt {
            Stmt::Let {
                name,
                is_mut,
                ty,
                init,
                span,
            } => {
                let declared_ty = ty.as_ref().map(|t| self.lower_ast_type(t));
                let init_expr = init
                    .as_ref()
                    .map(|e| self.check_expr(e, declared_ty.as_ref()));

                let final_ty = match (&declared_ty, &init_expr) {
                    (Some(d_ty), Some(expr)) => {
                        if !self.types_compatible(d_ty, &expr.ty) {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Type mismatch in let binding: expected {}, found {}",
                                    d_ty.display_name(),
                                    expr.ty.display_name()
                                ),
                                expr.span,
                            ));
                        }
                        d_ty.clone()
                    }
                    (Some(d_ty), None) => d_ty.clone(),
                    (None, Some(expr)) => expr.ty.clone(),
                    (None, None) => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            "Cannot infer type for uninitialized variable without type annotation",
                            *span,
                        ));
                        HirType::Unknown
                    }
                };

                self.insert_var(name.clone(), final_ty.clone(), *is_mut);

                HirStmt::Let {
                    name: name.clone(),
                    is_mut: *is_mut,
                    ty: final_ty,
                    init: init_expr,
                    span: *span,
                }
            }
            Stmt::Assign {
                target,
                value,
                span,
            } => {
                let value_expr = self.check_expr(value, None);
                let (target_ty, is_mut) = self.check_assign_target(target);

                if !is_mut {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!("Cannot assign to immutable variable '{}'", target.base),
                        target.span,
                    ));
                } else if !self.types_compatible(&target_ty, &value_expr.ty) {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "Type mismatch in assignment: target is {}, value is {}",
                            target_ty.display_name(),
                            value_expr.ty.display_name()
                        ),
                        value_expr.span,
                    ));
                }

                HirStmt::Assign {
                    target: HirAssignTarget {
                        base: target.base.clone(),
                        fields: target.fields.clone(),
                        span: target.span,
                    },
                    value: value_expr,
                    span: *span,
                }
            }
            Stmt::If {
                cond,
                then_branch,
                else_branch,
                span,
            } => {
                let cond_expr = self.check_expr(cond, Some(&HirType::Bool));
                if !self.types_compatible(&HirType::Bool, &cond_expr.ty) {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "Condition in if statement must be bool, found {}",
                            cond_expr.ty.display_name()
                        ),
                        cond_expr.span,
                    ));
                }

                let checked_then = self.check_block(then_branch);
                let checked_else = else_branch.as_ref().map(|eb| match eb {
                    ElseBranch::Block(b) => HirElseBranch::Block(self.check_block(b)),
                    ElseBranch::If(s) => HirElseBranch::If(Box::new(self.check_stmt(s))),
                });

                HirStmt::If {
                    cond: cond_expr,
                    then_branch: checked_then,
                    else_branch: checked_else,
                    span: *span,
                }
            }
            Stmt::For {
                var,
                iter,
                body,
                span,
            } => {
                let iter_expr = self.check_expr(iter, None);
                let elem_ty = match &iter_expr.ty {
                    HirType::Array(inner) => (**inner).clone(),
                    HirType::Unknown => HirType::Unknown,
                    other => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!("Cannot iterate over non-array type {}", other.display_name()),
                            iter_expr.span,
                        ));
                        HirType::Unknown
                    }
                };

                self.push_scope();
                self.insert_var(var.clone(), elem_ty, false);
                let checked_body = self.check_block(body);
                self.pop_scope();

                HirStmt::For {
                    var: var.clone(),
                    iter: iter_expr,
                    body: checked_body,
                    span: *span,
                }
            }
            Stmt::While { cond, body, span } => {
                let cond_expr = self.check_expr(cond, Some(&HirType::Bool));
                if !self.types_compatible(&HirType::Bool, &cond_expr.ty) {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "Condition in while loop must be bool, found {}",
                            cond_expr.ty.display_name()
                        ),
                        cond_expr.span,
                    ));
                }

                let checked_body = self.check_block(body);

                HirStmt::While {
                    cond: cond_expr,
                    body: checked_body,
                    span: *span,
                }
            }
            Stmt::Return { value, span } => {
                let expected_return = self.current_fn_return_type.clone().unwrap_or(HirType::Void);
                let val_expr = value
                    .as_ref()
                    .map(|v| self.check_expr(v, Some(&expected_return)));

                match (&expected_return, &val_expr) {
                    (HirType::Void, Some(expr)) => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!(
                                "Function expects no return value, but found expression of type {}",
                                expr.ty.display_name()
                            ),
                            expr.span,
                        ));
                    }
                    (expected, None) => {
                        if expected != &HirType::Void && expected != &HirType::I32 {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Function expects return type {}, but found empty return",
                                    expected.display_name()
                                ),
                                *span,
                            ));
                        }
                    }
                    (expected, Some(expr)) => {
                        if !self.types_compatible(expected, &expr.ty) {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Type mismatch in return: expected {}, found {}",
                                    expected.display_name(),
                                    expr.ty.display_name()
                                ),
                                expr.span,
                            ));
                        }
                    }
                }

                HirStmt::Return {
                    value: val_expr,
                    span: *span,
                }
            }
            Stmt::Expr { expr, span } => {
                let checked_expr = self.check_expr(expr, None);
                HirStmt::Expr {
                    expr: checked_expr,
                    span: *span,
                }
            }
        }
    }

    fn check_assign_target(&mut self, target: &AssignTarget) -> (HirType, bool) {
        let (base_ty, is_mut) = match self.lookup_var(&target.base) {
            Some(found) => found,
            None => {
                self.diagnostics.push(Diagnostic::typecheck(
                    format!("Undefined variable in assignment: '{}'", target.base),
                    target.span,
                ));
                return (HirType::Unknown, false);
            }
        };

        if target.fields.is_empty() {
            return (base_ty, is_mut);
        }

        let mut curr_ty = base_ty;
        for field in &target.fields {
            match &curr_ty {
                HirType::Custom(struct_name) => {
                    if let Some(s) = self.structs.get(struct_name) {
                        if let Some(f) = s.fields.iter().find(|sf| &sf.name == field) {
                            curr_ty = f.ty.clone();
                        } else {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!("Struct '{}' has no field '{}'", struct_name, field),
                                target.span,
                            ));
                            return (HirType::Unknown, is_mut);
                        }
                    } else {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!("Unknown struct type '{}'", struct_name),
                            target.span,
                        ));
                        return (HirType::Unknown, is_mut);
                    }
                }
                _ => {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "Cannot access field '{}' on non-struct type {}",
                            field,
                            curr_ty.display_name()
                        ),
                        target.span,
                    ));
                    return (HirType::Unknown, is_mut);
                }
            }
        }

        (curr_ty, is_mut)
    }

    fn check_expr(&mut self, expr: &Expr, expected_ty: Option<&HirType>) -> HirExpr {
        match expr {
            Expr::Literal { lit, span } => {
                let ty = match lit {
                    Literal::Int(_) => {
                        if let Some(HirType::I32) = expected_ty {
                            HirType::I32
                        } else {
                            HirType::I64
                        }
                    }
                    Literal::Float(_) => HirType::F64,
                    Literal::String(_) => HirType::String,
                    Literal::Bool(_) => HirType::Bool,
                };
                HirExpr::new(HirExprKind::Literal(lit.clone()), ty, *span)
            }
            Expr::Path { segments, span } => {
                if segments.len() == 1 {
                    let name = &segments[0];
                    if let Some((ty, _)) = self.lookup_var(name) {
                        return HirExpr::new(HirExprKind::Path(segments.clone()), ty, *span);
                    }
                    if let Some(func) = self.functions.get(name) {
                        return HirExpr::new(
                            HirExprKind::Path(segments.clone()),
                            func.return_type.clone(),
                            *span,
                        );
                    }
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!("Undefined variable or identifier '{}'", name),
                        *span,
                    ));
                    HirExpr::new(HirExprKind::Path(segments.clone()), HirType::Unknown, *span)
                } else if segments.len() == 2 {
                    let ns = &segments[0];
                    let member = &segments[1];
                    if let Some(static_fn) = self.prelude.lookup_static(ns, member) {
                        return HirExpr::new(
                            HirExprKind::Path(segments.clone()),
                            static_fn.return_type.clone(),
                            *span,
                        );
                    }
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!("Unknown static member '{}::{}'", ns, member),
                        *span,
                    ));
                    HirExpr::new(HirExprKind::Path(segments.clone()), HirType::Unknown, *span)
                } else {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!("Unsupported path '{}'", segments.join("::")),
                        *span,
                    ));
                    HirExpr::new(HirExprKind::Path(segments.clone()), HirType::Unknown, *span)
                }
            }
            Expr::Array { elements, span } => {
                let inner_expected = if let Some(HirType::Array(inner)) = expected_ty {
                    Some((**inner).clone())
                } else {
                    None
                };

                let mut checked_elems = Vec::new();
                let mut deduced_inner = inner_expected.clone();

                for elem in elements {
                    let checked = self.check_expr(elem, deduced_inner.as_ref());
                    if deduced_inner.is_none() && checked.ty != HirType::Unknown {
                        deduced_inner = Some(checked.ty.clone());
                    } else if let Some(expected_item_ty) = &deduced_inner {
                        if !self.types_compatible(expected_item_ty, &checked.ty) {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Array element type mismatch: expected {}, found {}",
                                    expected_item_ty.display_name(),
                                    checked.ty.display_name()
                                ),
                                checked.span,
                            ));
                        }
                    }
                    checked_elems.push(checked);
                }

                let arr_ty = HirType::Array(Box::new(deduced_inner.unwrap_or(HirType::Unknown)));
                HirExpr::new(HirExprKind::Array(checked_elems), arr_ty, *span)
            }
            Expr::StructInit { name, fields, span } => {
                let struct_def = match self.structs.get(name) {
                    Some(s) => s.clone(),
                    None => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!("Undefined struct '{}'", name),
                            *span,
                        ));
                        return HirExpr::new(
                            HirExprKind::StructInit {
                                name: name.clone(),
                                fields: vec![],
                            },
                            HirType::Unknown,
                            *span,
                        );
                    }
                };

                let mut checked_fields = Vec::new();
                let mut seen_fields = HashMap::new();

                for (field_name, field_expr) in fields {
                    let declared_field = struct_def.fields.iter().find(|f| &f.name == field_name);
                    let checked = match declared_field {
                        Some(f) => {
                            let val = self.check_expr(field_expr, Some(&f.ty));
                            if !self.types_compatible(&f.ty, &val.ty) {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!(
                                        "Field '{}' in struct '{}' expected type {}, found {}",
                                        field_name,
                                        name,
                                        f.ty.display_name(),
                                        val.ty.display_name()
                                    ),
                                    val.span,
                                ));
                            }
                            val
                        }
                        None => {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!("Unknown field '{}' in struct '{}'", field_name, name),
                                field_expr.span(),
                            ));
                            self.check_expr(field_expr, None)
                        }
                    };
                    seen_fields.insert(field_name.clone(), ());
                    checked_fields.push((field_name.clone(), checked));
                }

                // Verify missing fields
                for def_field in &struct_def.fields {
                    if !seen_fields.contains_key(&def_field.name) {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!(
                                "Missing required field '{}' in struct '{}' initialization",
                                def_field.name, name
                            ),
                            *span,
                        ));
                    }
                }

                HirExpr::new(
                    HirExprKind::StructInit {
                        name: name.clone(),
                        fields: checked_fields,
                    },
                    HirType::Custom(name.clone()),
                    *span,
                )
            }
            Expr::Unary { op, operand, span } => {
                let operand_expr = self.check_expr(operand, None);
                let ty = match op {
                    UnaryOp::Not => {
                        if operand_expr.ty != HirType::Bool && operand_expr.ty != HirType::Unknown {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Unary '!' operator requires bool operand, found {}",
                                    operand_expr.ty.display_name()
                                ),
                                operand_expr.span,
                            ));
                        }
                        HirType::Bool
                    }
                    UnaryOp::Neg => {
                        if !operand_expr.ty.is_numeric() && operand_expr.ty != HirType::Unknown {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Unary '-' operator requires numeric operand, found {}",
                                    operand_expr.ty.display_name()
                                ),
                                operand_expr.span,
                            ));
                        }
                        operand_expr.ty.clone()
                    }
                };

                HirExpr::new(
                    HirExprKind::Unary {
                        op: op.clone(),
                        operand: Box::new(operand_expr),
                    },
                    ty,
                    *span,
                )
            }
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => {
                let left_expr = self.check_expr(left, None);
                let right_expected = match op {
                    BinaryOp::In => Some(HirType::Array(Box::new(left_expr.ty.clone()))),
                    BinaryOp::And | BinaryOp::Or => Some(HirType::Bool),
                    _ => Some(left_expr.ty.clone()),
                };

                let right_expr = self.check_expr(right, right_expected.as_ref());

                let result_ty = match op {
                    BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::Div
                    | BinaryOp::Rem => {
                        if (!left_expr.ty.is_numeric() || !right_expr.ty.is_numeric())
                            && left_expr.ty != HirType::Unknown
                            && right_expr.ty != HirType::Unknown
                        {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Arithmetic operator requires numeric operands, found {} and {}",
                                    left_expr.ty.display_name(),
                                    right_expr.ty.display_name()
                                ),
                                *span,
                            ));
                        } else if !self.types_compatible(&left_expr.ty, &right_expr.ty) {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Type mismatch in binary operation: {} and {}",
                                    left_expr.ty.display_name(),
                                    right_expr.ty.display_name()
                                ),
                                *span,
                            ));
                        }
                        left_expr.ty.clone()
                    }
                    BinaryOp::Eq | BinaryOp::Ne => {
                        if !self.types_compatible(&left_expr.ty, &right_expr.ty) {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Cannot compare incompatible types {} and {}",
                                    left_expr.ty.display_name(),
                                    right_expr.ty.display_name()
                                ),
                                *span,
                            ));
                        }
                        HirType::Bool
                    }
                    BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                        if (!left_expr.ty.is_numeric() || !right_expr.ty.is_numeric())
                            && left_expr.ty != HirType::Unknown
                            && right_expr.ty != HirType::Unknown
                        {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Comparison operator requires numeric operands, found {} and {}",
                                    left_expr.ty.display_name(),
                                    right_expr.ty.display_name()
                                ),
                                *span,
                            ));
                        }
                        HirType::Bool
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        if left_expr.ty != HirType::Bool && left_expr.ty != HirType::Unknown {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Logical operator requires bool left operand, found {}",
                                    left_expr.ty.display_name()
                                ),
                                left_expr.span,
                            ));
                        }
                        if right_expr.ty != HirType::Bool && right_expr.ty != HirType::Unknown {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!(
                                    "Logical operator requires bool right operand, found {}",
                                    right_expr.ty.display_name()
                                ),
                                right_expr.span,
                            ));
                        }
                        HirType::Bool
                    }
                    BinaryOp::In => {
                        match &right_expr.ty {
                            HirType::Array(inner) => {
                                if !self.types_compatible(inner, &left_expr.ty) {
                                    self.diagnostics.push(Diagnostic::typecheck(
                                        format!(
                                            "'in' operator type mismatch: element is {}, array contains {}",
                                            left_expr.ty.display_name(),
                                            inner.display_name()
                                        ),
                                        *span,
                                    ));
                                }
                            }
                            HirType::Unknown => {}
                            other => {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!("Right operand of 'in' must be an array, found {}", other.display_name()),
                                    right_expr.span,
                                ));
                            }
                        }
                        HirType::Bool
                    }
                };

                HirExpr::new(
                    HirExprKind::Binary {
                        op: op.clone(),
                        left: Box::new(left_expr),
                        right: Box::new(right_expr),
                    },
                    result_ty,
                    *span,
                )
            }
            Expr::Call { callee, args, span } => {
                match callee.as_ref() {
                    Expr::Path { segments, span: callee_span } => {
                        if segments.len() == 1 {
                            let fn_name = &segments[0];
                            if let Some(f) = self.functions.get(fn_name).cloned() {
                                if f.params.len() != args.len() {
                                    self.diagnostics.push(Diagnostic::typecheck(
                                        format!(
                                            "Function '{}' expects {} arguments, but {} were provided",
                                            fn_name,
                                            f.params.len(),
                                            args.len()
                                        ),
                                        *span,
                                    ));
                                }

                                let mut checked_args = Vec::new();
                                for (i, arg) in args.iter().enumerate() {
                                    let expected_arg_ty = f.params.get(i).map(|p| &p.ty);
                                    let checked_arg = self.check_expr(arg, expected_arg_ty);
                                    if let Some(param) = f.params.get(i) {
                                        if !self.types_compatible(&param.ty, &checked_arg.ty) {
                                            self.diagnostics.push(Diagnostic::typecheck(
                                                format!(
                                                    "Argument {} in call to '{}' expected {}, found {}",
                                                    i + 1,
                                                    fn_name,
                                                    param.ty.display_name(),
                                                    checked_arg.ty.display_name()
                                                ),
                                                checked_arg.span,
                                            ));
                                        }
                                    }
                                    checked_args.push(checked_arg);
                                }

                                return HirExpr::new(
                                    HirExprKind::Call {
                                        callee: Box::new(HirExpr::new(
                                            HirExprKind::Path(segments.clone()),
                                            f.return_type.clone(),
                                            *callee_span,
                                        )),
                                        args: checked_args,
                                    },
                                    f.return_type,
                                    *span,
                                );
                            } else {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!("Call to undefined function '{}'", fn_name),
                                    *callee_span,
                                ));
                            }
                        } else if segments.len() == 2 {
                            let ns = &segments[0];
                            let name = &segments[1];
                            if let Some(sf) = self.prelude.lookup_static(ns, name).cloned() {
                                if sf.params.len() != args.len() {
                                    self.diagnostics.push(Diagnostic::typecheck(
                                        format!(
                                            "Static function '{}::{}' expects {} arguments, found {}",
                                            ns,
                                            name,
                                            sf.params.len(),
                                            args.len()
                                        ),
                                        *span,
                                    ));
                                }

                                let mut checked_args = Vec::new();
                                for (i, arg) in args.iter().enumerate() {
                                    let expected_arg_ty = sf.params.get(i).map(|p| &p.ty);
                                    let checked_arg = self.check_expr(arg, expected_arg_ty);
                                    if let Some(param) = sf.params.get(i) {
                                        if !self.types_compatible(&param.ty, &checked_arg.ty) {
                                            self.diagnostics.push(Diagnostic::typecheck(
                                                format!(
                                                    "Argument {} in call to '{}::{}' expected {}, found {}",
                                                    i + 1,
                                                    ns,
                                                    name,
                                                    param.ty.display_name(),
                                                    checked_arg.ty.display_name()
                                                ),
                                                checked_arg.span,
                                            ));
                                        }
                                    }
                                    checked_args.push(checked_arg);
                                }

                                return HirExpr::new(
                                    HirExprKind::Call {
                                        callee: Box::new(HirExpr::new(
                                            HirExprKind::Path(segments.clone()),
                                            sf.return_type.clone(),
                                            *callee_span,
                                        )),
                                        args: checked_args,
                                    },
                                    sf.return_type,
                                    *span,
                                );
                            }
                        }
                    }
                    _ => {}
                }

                let checked_callee = self.check_expr(callee, None);
                let checked_args: Vec<_> = args.iter().map(|a| self.check_expr(a, None)).collect();
                HirExpr::new(
                    HirExprKind::Call {
                        callee: Box::new(checked_callee),
                        args: checked_args,
                    },
                    HirType::Unknown,
                    *span,
                )
            }
            Expr::MethodCall {
                receiver,
                method,
                args,
                span,
            } => {
                let checked_recv = self.check_expr(receiver, None);

                // Check built-in slice methods
                if let HirType::Array(inner) = &checked_recv.ty {
                    if method == "len" {
                        if !args.is_empty() {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!("Method 'len' on array takes 0 arguments, found {}", args.len()),
                                *span,
                            ));
                        }
                        let checked_args: Vec<_> =
                            args.iter().map(|a| self.check_expr(a, None)).collect();
                        return HirExpr::new(
                            HirExprKind::MethodCall {
                                receiver: Box::new(checked_recv),
                                method: method.clone(),
                                args: checked_args,
                            },
                            HirType::I64,
                            *span,
                        );
                    } else if method == "push" {
                        if args.len() != 1 {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!("Method 'push' on array takes 1 argument, found {}", args.len()),
                                *span,
                            ));
                        }
                        let arg_expected = Some((**inner).clone());
                        let mut checked_args = Vec::new();
                        for arg in args {
                            let checked_arg = self.check_expr(arg, arg_expected.as_ref());
                            if !self.types_compatible(inner, &checked_arg.ty) {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!(
                                        "Method 'push' expected element type {}, found {}",
                                        inner.display_name(),
                                        checked_arg.ty.display_name()
                                    ),
                                    checked_arg.span,
                                ));
                            }
                            checked_args.push(checked_arg);
                        }

                        return HirExpr::new(
                            HirExprKind::MethodCall {
                                receiver: Box::new(checked_recv),
                                method: method.clone(),
                                args: checked_args,
                            },
                            HirType::Void,
                            *span,
                        );
                    }
                }

                // Check prelude methods on nominal types
                if let Some(m_sig) = self
                    .prelude
                    .lookup_method(&checked_recv.ty, method)
                    .cloned()
                {
                    if m_sig.params.len() != args.len() {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!(
                                "Method '{}' on {} expects {} arguments, found {}",
                                method,
                                checked_recv.ty.display_name(),
                                m_sig.params.len(),
                                args.len()
                            ),
                            *span,
                        ));
                    }

                    let mut checked_args = Vec::new();
                    for (i, arg) in args.iter().enumerate() {
                        let expected_arg_ty = m_sig.params.get(i).map(|p| &p.ty);
                        let checked_arg = self.check_expr(arg, expected_arg_ty);
                        if let Some(param) = m_sig.params.get(i) {
                            if !self.types_compatible(&param.ty, &checked_arg.ty) {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!(
                                        "Argument {} in call to method '{}' expected {}, found {}",
                                        i + 1,
                                        method,
                                        param.ty.display_name(),
                                        checked_arg.ty.display_name()
                                    ),
                                    checked_arg.span,
                                ));
                            }
                        }
                        checked_args.push(checked_arg);
                    }

                    return HirExpr::new(
                        HirExprKind::MethodCall {
                            receiver: Box::new(checked_recv),
                            method: method.clone(),
                            args: checked_args,
                        },
                        m_sig.return_type,
                        *span,
                    );
                }

                if checked_recv.ty != HirType::Unknown {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "No method '{}' found for type {}",
                            method,
                            checked_recv.ty.display_name()
                        ),
                        *span,
                    ));
                }

                let checked_args: Vec<_> = args.iter().map(|a| self.check_expr(a, None)).collect();
                HirExpr::new(
                    HirExprKind::MethodCall {
                        receiver: Box::new(checked_recv),
                        method: method.clone(),
                        args: checked_args,
                    },
                    HirType::Unknown,
                    *span,
                )
            }
            Expr::FieldAccess {
                receiver,
                field,
                span,
            } => {
                let checked_recv = self.check_expr(receiver, None);
                let field_ty = match &checked_recv.ty {
                    HirType::Custom(s_name) => {
                        if let Some(s) = self.structs.get(s_name) {
                            if let Some(f) = s.fields.iter().find(|sf| &sf.name == field) {
                                f.ty.clone()
                            } else {
                                self.diagnostics.push(Diagnostic::typecheck(
                                    format!("Struct '{}' has no field '{}'", s_name, field),
                                    *span,
                                ));
                                HirType::Unknown
                            }
                        } else {
                            self.diagnostics.push(Diagnostic::typecheck(
                                format!("Unknown struct '{}'", s_name),
                                *span,
                            ));
                            HirType::Unknown
                        }
                    }
                    HirType::Unknown => HirType::Unknown,
                    other => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!(
                                "Cannot access field '{}' on non-struct type {}",
                                field,
                                other.display_name()
                            ),
                            *span,
                        ));
                        HirType::Unknown
                    }
                };

                HirExpr::new(
                    HirExprKind::FieldAccess {
                        receiver: Box::new(checked_recv),
                        field: field.clone(),
                    },
                    field_ty,
                    *span,
                )
            }
            Expr::Index {
                receiver,
                index,
                span,
            } => {
                let checked_recv = self.check_expr(receiver, None);
                let checked_index = self.check_expr(index, Some(&HirType::I64));

                if !checked_index.ty.is_integer() && checked_index.ty != HirType::Unknown {
                    self.diagnostics.push(Diagnostic::typecheck(
                        format!(
                            "Index expression must be integer, found {}",
                            checked_index.ty.display_name()
                        ),
                        checked_index.span,
                    ));
                }

                let elem_ty = match &checked_recv.ty {
                    HirType::Array(inner) => (**inner).clone(),
                    HirType::Unknown => HirType::Unknown,
                    other => {
                        self.diagnostics.push(Diagnostic::typecheck(
                            format!("Cannot index non-array type {}", other.display_name()),
                            checked_recv.span,
                        ));
                        HirType::Unknown
                    }
                };

                HirExpr::new(
                    HirExprKind::Index {
                        receiver: Box::new(checked_recv),
                        index: Box::new(checked_index),
                    },
                    elem_ty,
                    *span,
                )
            }
        }
    }
}

pub fn typecheck(program: &Program) -> Result<HirProgram, Vec<Diagnostic>> {
    let checker = TypeChecker::new();
    checker.check_program(program)
}
