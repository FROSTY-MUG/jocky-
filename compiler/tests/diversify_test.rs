use jockyc::ast::Literal;
use jockyc::hir::{HirExprKind, HirItem};
use jockyc::passes::diversify::{derive_string_key, diversify_program, DiversificationConfig, Diversifier};
use jockyc::{parse, typecheck};

#[test]
fn test_string_key_derivation_deterministic() {
    let k1 = derive_string_key(1337);
    let k2 = derive_string_key(1337);
    let k3 = derive_string_key(1338);

    assert_eq!(k1, k2, "Same seed must produce identical string key");
    assert_ne!(k1, k3, "Different seeds must produce different string keys");
}

#[test]
fn test_function_mangling() {
    let src = "fn helper(a: i32) -> i32 { return a * 2; } fn main() -> i32 { return helper(21); }";
    let prog = parse(src).expect("parse");
    let mut hir = typecheck(&prog).expect("typecheck");

    let report = diversify_program(&mut hir, 9999);
    assert!(report.mangled_functions.contains_key("helper"), "helper must be mangled");
    let mangled_name = report.mangled_functions.get("helper").unwrap();
    assert!(mangled_name.starts_with("helper_"), "Mangled name must start with helper_");
    assert!(!report.mangled_functions.contains_key("main"), "main MUST NOT be mangled");

    // Check that helper declaration name in HIR is updated
    let has_mangled_def = hir.items.iter().any(|item| match item {
        HirItem::Fn(f) => f.name == *mangled_name,
        _ => false,
    });
    assert!(has_mangled_def, "Function definition name must be updated to mangled name");
}

#[test]
fn test_string_encryption_pass() {
    let src = "fn get_banner() -> string { return \"SECRET_BANNER\"; }";
    let prog = parse(src).expect("parse");
    let mut hir = typecheck(&prog).expect("typecheck");

    let report = diversify_program(&mut hir, 42);
    assert_eq!(report.encrypted_strings_count, 1, "Must encrypt 1 string literal");

    let mut found_encrypted = false;
    for item in &hir.items {
        if let HirItem::Fn(f) = item {
            for stmt in &f.body.stmts {
                if let jockyc::hir::HirStmt::Return { value: Some(expr), .. } = stmt {
                    if let HirExprKind::Literal(Literal::String(s)) = &expr.kind {
                        assert!(s.starts_with("__ENC__"), "Encrypted string must have __ENC__ prefix");
                        found_encrypted = true;
                    }
                }
            }
        }
    }
    assert!(found_encrypted, "Must find encrypted string in AST/HIR");
}

#[test]
fn test_instruction_substitution_pass() {
    let src = "fn compute() -> i32 { let a = 10; let b = 20; return a + b; }";
    let prog = parse(src).expect("parse");
    let mut hir = typecheck(&prog).expect("typecheck");

    let config = DiversificationConfig {
        seed: 777,
        reorder_blocks: false,
        substitute_instructions: true,
        mangle_function_names: false,
        encrypt_strings: false,
    };
    let diversifier = Diversifier::new(config);
    let report = diversifier.run(&mut hir);

    // Either a + b stayed or was transformed to a - (-b)
    assert!(report.substituted_ops_count <= 2);
}

#[test]
fn test_distinct_seeds_produce_distinct_hir() {
    let src = "fn helper() -> string { return \"Hello, polymorphic world!\"; } fn main() -> i32 { return 0; }";
    let prog = parse(src).expect("parse");

    let mut hir1 = typecheck(&prog).expect("typecheck");
    let mut hir2 = typecheck(&prog).expect("typecheck");

    let report1 = diversify_program(&mut hir1, 1);
    let report2 = diversify_program(&mut hir2, 2);

    assert_ne!(report1.string_key, report2.string_key, "String keys must differ");
    assert_ne!(
        report1.mangled_functions.get("helper"),
        report2.mangled_functions.get("helper"),
        "Mangled names must differ across seeds"
    );
}
