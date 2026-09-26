// JOCKY v0.1 - Diversification & Polymorphism Engine
// Implements Blueprint §0.4: Binary Diversification & Polymorphism
// Purpose: Seed-deterministic program diversification (BB reordering, instruction substitution, symbol mangling, string encryption)
// Inputs: HirProgram, 64-bit seed
// Outputs: Diversified HirProgram, DiversificationReport

use crate::ast::{BinaryOp, Literal, UnaryOp};
use crate::hir::{
    HirBlock, HirElseBranch, HirExpr, HirExprKind, HirItem, HirProgram, HirStmt, HirType,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

/// Computes BLAKE3-compatible 32-byte key derivation:
/// key = blake3(seed_bytes || "jocky-string-key-v1")[0..32]
pub fn derive_string_key(seed: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());
    hasher.update(b"jocky-string-key-v1");
    *hasher.finalize().as_bytes()
}

/// Convenience entry point to run all diversification passes with default configuration
pub fn diversify(program: &mut HirProgram, seed: u64) -> std::collections::BTreeMap<String, String> {
    let config = DiversificationConfig {
        seed,
        ..Default::default()
    };
    let report = Diversifier::new(config).run(program);
    report.mangled_functions.into_iter().collect()
}

#[derive(Debug, Clone)]
pub struct DiversificationConfig {
    pub seed: u64,
    pub reorder_blocks: bool,
    pub substitute_instructions: bool,
    pub mangle_function_names: bool,
    pub encrypt_strings: bool,
}

impl Default for DiversificationConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            reorder_blocks: true,
            substitute_instructions: true,
            mangle_function_names: true,
            encrypt_strings: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiversificationReport {
    pub seed: u64,
    pub string_key: [u8; 32],
    pub mangled_functions: HashMap<String, String>,
    pub encrypted_strings_count: usize,
    pub substituted_ops_count: usize,
}

pub struct Diversifier {
    config: DiversificationConfig,
    rng: ChaCha20Rng,
    mangled_map: HashMap<String, String>,
    encrypted_strings: usize,
    substituted_ops: usize,
    string_key: [u8; 32],
}

impl Diversifier {
    pub fn new(config: DiversificationConfig) -> Self {
        let rng = ChaCha20Rng::seed_from_u64(config.seed);
        let string_key = derive_string_key(config.seed);
        Self {
            config,
            rng,
            mangled_map: HashMap::new(),
            encrypted_strings: 0,
            substituted_ops: 0,
            string_key,
        }
    }

    pub fn run(mut self, program: &mut HirProgram) -> DiversificationReport {
        // Pass 1: Seeded function name mangling (Pass 1.c)
        if self.config.mangle_function_names {
            self.generate_function_mangling(program);
        }

        // Pass 2, 3, 4: Walk HIR and apply BB reordering, instruction substitution, string encryption
        for item in &mut program.items {
            if let HirItem::Fn(f) = item {
                // Apply mangled name if present
                if let Some(mangled) = self.mangled_map.get(&f.name) {
                    f.name = mangled.clone();
                }

                // Diversify function body
                self.diversify_block(&mut f.body);
            }
        }

        DiversificationReport {
            seed: self.config.seed,
            string_key: self.string_key,
            mangled_functions: self.mangled_map,
            encrypted_strings_count: self.encrypted_strings,
            substituted_ops_count: self.substituted_ops,
        }
    }

    fn generate_function_mangling(&mut self, program: &HirProgram) {
        // Collect user defined functions, excluding `main` and prelude
        for item in &program.items {
            if let HirItem::Fn(f) = item {
                if f.name != "main" && !f.is_extern {
                    let hash_bytes: [u8; 4] = self.rng.gen();
                    let hex_suffix = hex::encode(hash_bytes);
                    let mangled = format!("{}_{}", f.name, hex_suffix);
                    self.mangled_map.insert(f.name.clone(), mangled);
                }
            }
        }
    }

    fn diversify_block(&mut self, block: &mut HirBlock) {
        // Pass 1.a: Basic-block / statement permutation on independent statements
        if self.config.reorder_blocks && block.stmts.len() > 2 {
            let can_reorder = self.rng.gen::<bool>();
            if can_reorder {
                // Safe adjacent swap if independent
                for i in 0..block.stmts.len() - 1 {
                    if self.can_swap_stmts(&block.stmts[i], &block.stmts[i + 1]) {
                        if self.rng.gen::<bool>() {
                            block.stmts.swap(i, i + 1);
                        }
                    }
                }
            }
        }

        for stmt in &mut block.stmts {
            self.diversify_stmt(stmt);
        }
    }

    fn can_swap_stmts(&self, s1: &HirStmt, s2: &HirStmt) -> bool {
        match (s1, s2) {
            (HirStmt::Let { name: n1, .. }, HirStmt::Let { name: n2, init, .. }) => {
                if let Some(init_expr) = init {
                    !self.expr_references_var(init_expr, n1) && n1 != n2
                } else {
                    n1 != n2
                }
            }
            _ => false,
        }
    }

    fn expr_references_var(&self, expr: &HirExpr, var_name: &str) -> bool {
        match &expr.kind {
            HirExprKind::Path(segs) => segs.first().map(|s| s == var_name).unwrap_or(false),
            HirExprKind::Binary { left, right, .. } => {
                self.expr_references_var(left, var_name) || self.expr_references_var(right, var_name)
            }
            HirExprKind::Unary { operand, .. } => self.expr_references_var(operand, var_name),
            HirExprKind::Call { callee, args } => {
                self.expr_references_var(callee, var_name)
                    || args.iter().any(|a| self.expr_references_var(a, var_name))
            }
            _ => false,
        }
    }

    fn diversify_stmt(&mut self, stmt: &mut HirStmt) {
        match stmt {
            HirStmt::Let { init, .. } => {
                if let Some(expr) = init {
                    self.diversify_expr(expr);
                }
            }
            HirStmt::Assign { value, .. } => {
                self.diversify_expr(value);
            }
            HirStmt::If {
                cond,
                then_branch,
                else_branch,
                ..
            } => {
                self.diversify_expr(cond);

                // Pass 1.a: Invert if branches if seed selects it
                if self.config.reorder_blocks && else_branch.is_some() && self.rng.gen::<bool>() {
                    let mut inverted_cond = HirExpr::new(
                        HirExprKind::Unary {
                            op: UnaryOp::Not,
                            operand: Box::new(cond.clone()),
                        },
                        HirType::Bool,
                        cond.span,
                    );
                    self.diversify_expr(&mut inverted_cond);
                    *cond = inverted_cond;

                    if let Some(HirElseBranch::Block(else_b)) = else_branch {
                        std::mem::swap(then_branch, else_b);
                    }
                } else {
                    self.diversify_block(then_branch);
                    if let Some(eb) = else_branch {
                        match eb {
                            HirElseBranch::Block(b) => self.diversify_block(b),
                            HirElseBranch::If(s) => self.diversify_stmt(s),
                        }
                    }
                }
            }
            HirStmt::While { cond, body, .. } => {
                self.diversify_expr(cond);
                self.diversify_block(body);
            }
            HirStmt::For { iter, body, .. } => {
                self.diversify_expr(iter);
                self.diversify_block(body);
            }
            HirStmt::Return { value, .. } => {
                if let Some(expr) = value {
                    self.diversify_expr(expr);
                }
            }
            HirStmt::Expr { expr, .. } => {
                self.diversify_expr(expr);
            }
        }
    }

    fn diversify_expr(&mut self, expr: &mut HirExpr) {
        // Pass 1.d: String encryption
        if self.config.encrypt_strings {
            if let HirExprKind::Literal(Literal::String(ref s)) = expr.kind {
                let mut encrypted_bytes = Vec::with_capacity(s.len());
                for (i, &b) in s.as_bytes().iter().enumerate() {
                    encrypted_bytes.push(b ^ self.string_key[i % 32]);
                }
                let enc_hex = hex::encode(&encrypted_bytes);
                expr.kind = HirExprKind::Literal(Literal::String(format!("__ENC__{}", enc_hex)));
                self.encrypted_strings += 1;
                return;
            }
        }

        // Pass 1.c: Update mangled function calls
        if let HirExprKind::Call { callee, args } = &mut expr.kind {
            if let HirExprKind::Path(segs) = &mut callee.kind {
                if segs.len() == 1 {
                    if let Some(mangled) = self.mangled_map.get(&segs[0]) {
                        segs[0] = mangled.clone();
                    }
                }
            }
            self.diversify_expr(callee);
            for arg in args {
                self.diversify_expr(arg);
            }
            return;
        }

        // Pass 1.b: Equivalent instruction substitution
        if self.config.substitute_instructions {
            match &mut expr.kind {
                HirExprKind::Binary { op, left, right } => {
                    self.diversify_expr(left);
                    self.diversify_expr(right);

                    if *op == BinaryOp::Add && self.rng.gen::<bool>() {
                        // a + b => a - (-b) for signed integers
                        if expr.ty.is_integer() {
                            let neg_right = HirExpr::new(
                                HirExprKind::Unary {
                                    op: UnaryOp::Neg,
                                    operand: right.clone(),
                                },
                                right.ty.clone(),
                                right.span,
                            );
                            *op = BinaryOp::Sub;
                            *right = Box::new(neg_right);
                            self.substituted_ops += 1;
                        }
                    } else if *op == BinaryOp::Sub && self.rng.gen::<bool>() {
                        // a - b => a + (-b)
                        if expr.ty.is_integer() {
                            let neg_right = HirExpr::new(
                                HirExprKind::Unary {
                                    op: UnaryOp::Neg,
                                    operand: right.clone(),
                                },
                                right.ty.clone(),
                                right.span,
                            );
                            *op = BinaryOp::Add;
                            *right = Box::new(neg_right);
                            self.substituted_ops += 1;
                        }
                    }
                    return;
                }
                HirExprKind::Unary { operand, .. } => {
                    self.diversify_expr(operand);
                    return;
                }
                HirExprKind::Array(elements) => {
                    for elem in elements {
                        self.diversify_expr(elem);
                    }
                    return;
                }
                HirExprKind::StructInit { fields, .. } => {
                    for (_, field_expr) in fields {
                        self.diversify_expr(field_expr);
                    }
                    return;
                }
                HirExprKind::MethodCall { receiver, args, .. } => {
                    self.diversify_expr(receiver);
                    for arg in args {
                        self.diversify_expr(arg);
                    }
                    return;
                }
                HirExprKind::FieldAccess { receiver, .. } => {
                    self.diversify_expr(receiver);
                    return;
                }
                HirExprKind::Index { receiver, index } => {
                    self.diversify_expr(receiver);
                    self.diversify_expr(index);
                    return;
                }
                _ => {}
            }
        }
    }
}

pub fn diversify_program(hir: &mut HirProgram, seed: u64) -> DiversificationReport {
    let config = DiversificationConfig {
        seed,
        reorder_blocks: true,
        substitute_instructions: true,
        mangle_function_names: true,
        encrypt_strings: true,
    };
    let diversifier = Diversifier::new(config);
    diversifier.run(hir)
}
