use crate::ast::*;
use crate::diag::Diagnostic;

pub const DENYLIST: &[&str] = &[
    // Blueprint §0.2 Primitives
    "inject_remote_process",
    "write_process_memory",
    "create_service",
    "install_driver",
    "set_run_key",
    "schedule_task",
    "dump_lsass",
    "harvest_credentials",
    "read_browser_db",
    "exploit",
    "bypass_uac",
    "token_steal",
    "connect_arbitrary",
    // Prompt §1.5.6 & Design §5.2 Primitives
    "virtual_alloc_ex",
    "create_remote_thread",
    "set_registry_run_key",
    "lsass_dump",
    "minidump_write_dump",
    "load_driver",
    "impersonate_token",
    "adjust_token_privileges",
    "disable_etw",
    "patch_amsi",
];

pub fn check(program: &Program) -> Result<(), Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let mut checker = DenylistChecker {
        diagnostics: &mut diagnostics,
    };
    checker.check_program(program);

    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics)
    }
}

struct DenylistChecker<'a> {
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl<'a> DenylistChecker<'a> {
    fn check_program(&mut self, program: &Program) {
        for item in &program.items {
            match item {
                Item::Fn(f) => self.check_fn(f),
                Item::Struct(_) => {}
                Item::Import(imp) => self.check_import(imp),
            }
        }
    }

    fn check_import(&mut self, imp: &ImportDecl) {
        for seg in &imp.path {
            if is_denylisted(seg) {
                self.diagnostics.push(Diagnostic::denylist(seg, imp.span));
            }
        }
    }

    fn check_fn(&mut self, f: &FnDecl) {
        self.check_block(&f.body);
    }

    fn check_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.check_stmt(stmt);
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Let { init, .. } => {
                if let Some(expr) = init {
                    self.check_expr(expr);
                }
            }
            Stmt::Assign { value, .. } => {
                self.check_expr(value);
            }
            Stmt::If {
                cond,
                then_branch,
                else_branch,
                ..
            } => {
                self.check_expr(cond);
                self.check_block(then_branch);
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(b) => self.check_block(b),
                        ElseBranch::If(s) => self.check_stmt(s),
                    }
                }
            }
            Stmt::For { iter, body, .. } => {
                self.check_expr(iter);
                self.check_block(body);
            }
            Stmt::While { cond, body, .. } => {
                self.check_expr(cond);
                self.check_block(body);
            }
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    self.check_expr(expr);
                }
            }
            Stmt::Expr { expr, .. } => {
                self.check_expr(expr);
            }
        }
    }

    fn check_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call { callee, args, .. } => {
                self.check_expr(callee);
                for arg in args {
                    self.check_expr(arg);
                }
            }
            Expr::Path { segments, span } => {
                for seg in segments {
                    if is_denylisted(seg) {
                        self.diagnostics.push(Diagnostic::denylist(seg, *span));
                    }
                }
            }
            Expr::MethodCall {
                receiver,
                method,
                args,
                span,
            } => {
                if is_denylisted(method) {
                    self.diagnostics.push(Diagnostic::denylist(method, *span));
                }
                self.check_expr(receiver);
                for arg in args {
                    self.check_expr(arg);
                }
            }
            Expr::FieldAccess { receiver, .. } => {
                self.check_expr(receiver);
            }
            Expr::Array { elements, .. } => {
                for el in elements {
                    self.check_expr(el);
                }
            }
            Expr::StructInit { fields, .. } => {
                for (_, val) in fields {
                    self.check_expr(val);
                }
            }
            Expr::Unary { operand, .. } => {
                self.check_expr(operand);
            }
            Expr::Binary { left, right, .. } => {
                self.check_expr(left);
                self.check_expr(right);
            }
            Expr::Index { receiver, index, .. } => {
                self.check_expr(receiver);
                self.check_expr(index);
            }
            Expr::Literal { .. } => {}
        }
    }
}

fn is_denylisted(name: &str) -> bool {
    DENYLIST.contains(&name)
}
