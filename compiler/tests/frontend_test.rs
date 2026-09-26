use jockyc::ast::*;
use jockyc::diag::ErrorCode;
use jockyc::passes::denylist::{check as run_denylist_check, DENYLIST};
use jockyc::{parse, tokenize, Token};

// =====================================================================
// LEXER & BASIC LITERALS (Tests 1–6)
// =====================================================================

#[test]
fn test_lex_integers_and_floats() {
    let src = "42 3.1415 0 100.0";
    let tokens = tokenize(src).expect("tokenization failed");
    assert_eq!(tokens.len(), 4);
    assert_eq!(tokens[0].0, Token::IntLit(42));
    assert_eq!(tokens[1].0, Token::FloatLit(3.1415));
    assert_eq!(tokens[2].0, Token::IntLit(0));
    assert_eq!(tokens[3].0, Token::FloatLit(100.0));
}

#[test]
fn test_lex_strings_and_escapes() {
    let src = r#""hello world" "with\nnewline" "quote: \"inner\"""#;
    let tokens = tokenize(src).expect("tokenization failed");
    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[0].0, Token::StringLit("hello world".into()));
    assert_eq!(tokens[1].0, Token::StringLit("with\nnewline".into()));
    assert_eq!(tokens[2].0, Token::StringLit("quote: \"inner\"".into()));
}

#[test]
fn test_lex_keywords_and_ident() {
    let src = "fn let mut struct import if else for while return in and or not true false finding";
    let tokens = tokenize(src).expect("tokenization failed");
    assert_eq!(tokens[0].0, Token::Fn);
    assert_eq!(tokens[1].0, Token::Let);
    assert_eq!(tokens[2].0, Token::Mut);
    assert_eq!(tokens[3].0, Token::Struct);
    assert_eq!(tokens[4].0, Token::Import);
    assert_eq!(tokens[5].0, Token::If);
    assert_eq!(tokens[6].0, Token::Else);
    assert_eq!(tokens[7].0, Token::For);
    assert_eq!(tokens[8].0, Token::While);
    assert_eq!(tokens[9].0, Token::Return);
    assert_eq!(tokens[10].0, Token::In);
    assert_eq!(tokens[11].0, Token::And);
    assert_eq!(tokens[12].0, Token::Or);
    assert_eq!(tokens[13].0, Token::Not);
    assert_eq!(tokens[14].0, Token::True);
    assert_eq!(tokens[15].0, Token::False);
    assert_eq!(tokens[16].0, Token::Ident("finding".into()));
}

#[test]
fn test_lex_operators() {
    let src = "== != <= >= && || :: -> = : ; , . + - * / % ! < >";
    let tokens = tokenize(src).expect("tokenization failed");
    let kinds: Vec<Token> = tokens.into_iter().map(|(t, _)| t).collect();
    assert_eq!(
        kinds,
        vec![
            Token::EqEq,
            Token::BangEq,
            Token::Le,
            Token::Ge,
            Token::AmpAmp,
            Token::PipePipe,
            Token::ColonColon,
            Token::Arrow,
            Token::Eq,
            Token::Colon,
            Token::Semi,
            Token::Comma,
            Token::Dot,
            Token::Plus,
            Token::Minus,
            Token::Star,
            Token::Slash,
            Token::Percent,
            Token::Bang,
            Token::Lt,
            Token::Gt,
        ]
    );
}

#[test]
fn test_lex_comments() {
    let src = "// single line comment\nlet x = 1; /* block comment */ let y = 2;";
    let tokens = tokenize(src).expect("tokenization failed");
    assert_eq!(tokens.len(), 10);
    assert_eq!(tokens[0].0, Token::Let);
    assert_eq!(tokens[1].0, Token::Ident("x".into()));
    assert_eq!(tokens[5].0, Token::Let);
    assert_eq!(tokens[6].0, Token::Ident("y".into()));
}

#[test]
fn test_lex_invalid_char() {
    let src = "let x = @bad;";
    let err = tokenize(src).unwrap_err();
    assert_eq!(err.code, ErrorCode::E0101);
    assert_eq!(&src[err.span.start..err.span.end], "@");
}

// =====================================================================
// DECLARATIONS & MODULE STRUCTURE (Tests 7–11)
// =====================================================================

#[test]
fn test_parse_import() {
    let src = "import std::process; import core::crypto::sha256;";
    let prog = parse(src).expect("parse import failed");
    assert_eq!(prog.items.len(), 2);
    match &prog.items[0] {
        Item::Import(imp) => assert_eq!(imp.path, vec!["std", "process"]),
        _ => panic!("expected import"),
    }
    match &prog.items[1] {
        Item::Import(imp) => assert_eq!(imp.path, vec!["core", "crypto", "sha256"]),
        _ => panic!("expected import"),
    }
}

#[test]
fn test_parse_struct_decl() {
    let src = "struct Finding { severity: Severity, title: string, }";
    let prog = parse(src).expect("parse struct failed");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Struct(s) => {
            assert_eq!(s.name, "Finding");
            assert_eq!(s.fields.len(), 2);
            assert_eq!(s.fields[0].name, "severity");
            assert_eq!(s.fields[0].ty, Type::Custom("Severity".into()));
            assert_eq!(s.fields[1].name, "title");
            assert_eq!(s.fields[1].ty, Type::String);
        }
        _ => panic!("expected struct"),
    }
}

#[test]
fn test_parse_fn_with_explicit_return() {
    let src = "fn inspect(pid: u32) -> bool { return true; }";
    let prog = parse(src).expect("parse fn failed");
    match &prog.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.name, "inspect");
            assert_eq!(f.params.len(), 1);
            assert_eq!(f.params[0].name, "pid");
            assert_eq!(f.params[0].ty, Type::U32);
            assert_eq!(f.return_type, Type::Bool);
        }
        _ => panic!("expected fn"),
    }
}

#[test]
fn test_parse_fn_with_default_return() {
    let src = "fn main() { return 0; }";
    let prog = parse(src).expect("parse fn failed");
    match &prog.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.name, "main");
            assert_eq!(f.params.len(), 0);
            assert_eq!(f.return_type, Type::I32); // v0.1 default convention
        }
        _ => panic!("expected fn"),
    }
}

#[test]
fn test_parse_empty_param_and_body() {
    let src = "fn noop() {}";
    let prog = parse(src).expect("parse fn failed");
    match &prog.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.name, "noop");
            assert!(f.body.stmts.is_empty());
        }
        _ => panic!("expected fn"),
    }
}

// =====================================================================
// STATEMENTS & CONTROL FLOW (Tests 12–19)
// =====================================================================

#[test]
fn test_parse_let_immutable() {
    let src = "fn run() { let x = 10; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let {
                name,
                is_mut,
                ty,
                init,
                ..
            } => {
                assert_eq!(name, "x");
                assert!(!is_mut);
                assert!(ty.is_none());
                assert!(matches!(init, Some(Expr::Literal { lit: Literal::Int(10), .. })));
            }
            _ => panic!("expected let"),
        }
    }
}

#[test]
fn test_parse_let_mut() {
    let src = "fn run() { let mut findings = []; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { name, is_mut, init, .. } => {
                assert_eq!(name, "findings");
                assert!(is_mut);
                assert!(matches!(init, Some(Expr::Array { elements, .. }) if elements.is_empty()));
            }
            _ => panic!("expected let mut"),
        }
    }
}

#[test]
fn test_parse_let_typed() {
    let src = "fn run() { let x: i32 = 42; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { name, ty, .. } => {
                assert_eq!(name, "x");
                assert_eq!(ty, &Some(Type::I32));
            }
            _ => panic!("expected let typed"),
        }
    }
}

#[test]
fn test_parse_assign_simple() {
    let src = "fn run() { x = 5; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Assign { target, value, .. } => {
                assert_eq!(target.base, "x");
                assert!(target.fields.is_empty());
                assert!(matches!(value, Expr::Literal { lit: Literal::Int(5), .. }));
            }
            _ => panic!("expected assign"),
        }
    }
}

#[test]
fn test_parse_assign_field() {
    let src = "fn run() { finding.severity = Severity::High; p.parent.pid = 1; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Assign { target, .. } => {
                assert_eq!(target.base, "finding");
                assert_eq!(target.fields, vec!["severity"]);
            }
            _ => panic!("expected assign 1"),
        }
        match &f.body.stmts[1] {
            Stmt::Assign { target, .. } => {
                assert_eq!(target.base, "p");
                assert_eq!(target.fields, vec!["parent", "pid"]);
            }
            _ => panic!("expected assign 2"),
        }
    }
}

#[test]
fn test_parse_for_single_ident() {
    let src = "fn run() { for p in procs { p.scan(); } }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::For { var, iter, body, .. } => {
                assert_eq!(var, "p");
                assert!(matches!(iter, Expr::Path { segments, .. } if segments == &["procs"]));
                assert_eq!(body.stmts.len(), 1);
            }
            _ => panic!("expected for"),
        }
    }
}

#[test]
fn test_parse_if_else_chain() {
    let src = "fn run() { if c1 { a(); } else if c2 { b(); } else { c(); } }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::If {
                then_branch,
                else_branch: Some(ElseBranch::If(nested_if)),
                ..
            } => {
                assert_eq!(then_branch.stmts.len(), 1);
                match nested_if.as_ref() {
                    Stmt::If {
                        else_branch: Some(ElseBranch::Block(final_else)),
                        ..
                    } => {
                        assert_eq!(final_else.stmts.len(), 1);
                    }
                    _ => panic!("expected nested if"),
                }
            }
            _ => panic!("expected if-else chain"),
        }
    }
}

#[test]
fn test_parse_while_loop() {
    let src = "fn run() { while i < 10 { i = i + 1; } }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::While { cond, body, .. } => {
                assert!(matches!(cond, Expr::Binary { op: BinaryOp::Lt, .. }));
                assert_eq!(body.stmts.len(), 1);
            }
            _ => panic!("expected while"),
        }
    }
}

// =====================================================================
// PRIMARY EXPRESSIONS & CONSTRUCTORS (Tests 20–25)
// =====================================================================

#[test]
fn test_parse_path_expr() {
    let src = "fn run() { let s = Severity::Critical; let d = Duration::from_secs; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { init: Some(Expr::Path { segments, .. }), .. } => {
                assert_eq!(segments, &["Severity", "Critical"]);
            }
            _ => panic!("expected path 1"),
        }
        match &f.body.stmts[1] {
            Stmt::Let { init: Some(Expr::Path { segments, .. }), .. } => {
                assert_eq!(segments, &["Duration", "from_secs"]);
            }
            _ => panic!("expected path 2"),
        }
    }
}

#[test]
fn test_parse_struct_init() {
    let src = r#"fn run() { let f = Finding { severity: Severity::High, mitre: "T1055" }; }"#;
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { init: Some(Expr::StructInit { name, fields, .. }), .. } => {
                assert_eq!(name, "Finding");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "severity");
                assert_eq!(fields[1].0, "mitre");
            }
            _ => panic!("expected struct init"),
        }
    }
}

#[test]
fn test_parse_empty_struct_init() {
    let src = "fn run() { let c = Config {}; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { init: Some(Expr::StructInit { name, fields, .. }), .. } => {
                assert_eq!(name, "Config");
                assert!(fields.is_empty());
            }
            _ => panic!("expected empty struct init"),
        }
    }
}

#[test]
fn test_parse_array_empty() {
    let src = "fn run() { let mut findings = []; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { init: Some(Expr::Array { elements, .. }), .. } => {
                assert!(elements.is_empty());
            }
            _ => panic!("expected empty array"),
        }
    }
}

#[test]
fn test_parse_array_literals() {
    let src = r#"fn run() { let list = ["winword.exe", "excel.exe"]; }"#;
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Let { init: Some(Expr::Array { elements, .. }), .. } => {
                assert_eq!(elements.len(), 2);
            }
            _ => panic!("expected array literal"),
        }
    }
}

#[test]
fn test_parse_method_call_chain() {
    let src = "fn run() { flow.dest_port().is_valid(); }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::MethodCall { receiver, method, .. }, .. } => {
                assert_eq!(method, "is_valid");
                assert!(matches!(receiver.as_ref(), Expr::MethodCall { method, .. } if method == "dest_port"));
            }
            _ => panic!("expected method call chain"),
        }
    }
}

// =====================================================================
// OPERATOR PRECEDENCE HIERARCHY & BOUNDARY ASSERTIONS (Tests 26–37)
// =====================================================================

#[test]
fn test_prec_arithmetic() {
    let src = "fn run() { 1 + 2 * 3; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Add, right, .. }, .. } => {
                assert!(matches!(right.as_ref(), Expr::Binary { op: BinaryOp::Mul, .. }));
            }
            _ => panic!("expected Add(1, Mul(2, 3))"),
        }
    }
}

#[test]
fn test_prec_unary_neg() {
    let src = "fn run() { -x * y; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Mul, left, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Unary { op: UnaryOp::Neg, .. }));
            }
            _ => panic!("expected Mul(Neg(x), y)"),
        }
    }
}

#[test]
fn test_prec_unary_not() {
    let src = "fn run() { !r.is_file_backed(); }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Unary { op: UnaryOp::Not, operand, .. }, .. } => {
                assert!(matches!(operand.as_ref(), Expr::MethodCall { method, .. } if method == "is_file_backed"));
            }
            _ => panic!("expected Not(MethodCall(...))"),
        }
    }
}

/// Test A: `in` binds tighter than `and`
#[test]
fn test_prec_in_vs_and() {
    let src = "fn run() { x in [1, 2] and y; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::And, left, right, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::In, .. }));
                assert!(matches!(right.as_ref(), Expr::Path { segments, .. } if segments == &["y"]));
            }
            _ => panic!("expected And(In(x, Array), y)"),
        }
    }
}

/// Test B: `+` (additive) binds tighter than `in` (membership)
#[test]
fn test_prec_in_vs_additive() {
    let src = "fn run() { x + 1 in [1, 2]; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::In, left, right, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::Add, .. }));
                assert!(matches!(right.as_ref(), Expr::Array { .. }));
            }
            _ => panic!("expected In(Add(x, 1), Array)"),
        }
    }
}

/// Test C: `in` (membership) binds tighter than `==` (equality), so Eq is outer
#[test]
fn test_prec_in_vs_equality() {
    let src = "fn run() { x in [1, 2] == true; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Eq, left, right, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::In, .. }));
                assert!(matches!(right.as_ref(), Expr::Literal { lit: Literal::Bool(true), .. }));
            }
            _ => panic!("expected Eq(In(x, Array), Bool(true))"),
        }
    }
}

/// Test D: `in` (membership) binds tighter than `<` (relational), so Lt is outer
#[test]
fn test_prec_relational_vs_in() {
    let src = "fn run() { x < 5 in [true, false]; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Lt, left, right, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Path { segments, .. } if segments == &["x"]));
                assert!(matches!(right.as_ref(), Expr::Binary { op: BinaryOp::In, .. }));
            }
            _ => panic!("expected Lt(x, In(5, Array))"),
        }
    }
}

#[test]
fn test_prec_equality_vs_logical() {
    let src = "fn run() { a == b && c != d; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::And, left, right, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::Eq, .. }));
                assert!(matches!(right.as_ref(), Expr::Binary { op: BinaryOp::Ne, .. }));
            }
            _ => panic!("expected And(Eq(..), Ne(..))"),
        }
    }
}

#[test]
fn test_prec_and_vs_or() {
    let src = "fn run() { a || b && c; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Or, right, .. }, .. } => {
                assert!(matches!(right.as_ref(), Expr::Binary { op: BinaryOp::And, .. }));
            }
            _ => panic!("expected Or(a, And(b, c))"),
        }
    }
}

#[test]
fn test_prec_relational_vs_equality() {
    let src = "fn run() { x > 0 == true; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Eq, left, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::Gt, .. }));
            }
            _ => panic!("expected Eq(Gt(x, 0), Bool(true))"),
        }
    }
}

#[test]
fn test_prec_parentheses_override() {
    let src = "fn run() { (1 + 2) * 3; }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Binary { op: BinaryOp::Mul, left, .. }, .. } => {
                assert!(matches!(left.as_ref(), Expr::Binary { op: BinaryOp::Add, .. }));
            }
            _ => panic!("expected Mul(Add(1, 2), 3)"),
        }
    }
}

#[test]
fn test_prec_index_over_call() {
    let src = "fn run() { arr[0](); }";
    let prog = parse(src).expect("parse failed");
    if let Item::Fn(f) = &prog.items[0] {
        match &f.body.stmts[0] {
            Stmt::Expr { expr: Expr::Call { callee, .. }, .. } => {
                assert!(matches!(callee.as_ref(), Expr::Index { .. }));
            }
            _ => panic!("expected Call(Index(arr, 0))"),
        }
    }
}

// =====================================================================
// PARSER DIAGNOSTIC ASSERTIONS (Tests 38–40)
// =====================================================================

#[test]
fn test_parse_err_missing_semicolon() {
    let src = "fn run() { let x = 5 }";
    let err = parse(src).unwrap_err();
    assert_eq!(err.code, ErrorCode::E0201);
}

#[test]
fn test_parse_err_unclosed_brace() {
    let src = "fn run() { let x = 5;";
    let err = parse(src).unwrap_err();
    assert_eq!(err.code, ErrorCode::E0201);
}

#[test]
fn test_parse_err_invalid_assign_target() {
    let src = "fn run() { 1 + 2 = x; }";
    let err = parse(src).unwrap_err();
    assert_eq!(err.code, ErrorCode::E0201);
    assert!(err.message.contains("invalid assignment target"));
}

// =====================================================================
// BLUEPRINT §0.2 DENYLIST COVERAGE TEST
// =====================================================================

#[test]
fn test_denylist_covers_blueprint_0_2() {
    let blueprint_primitives = [
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
    ];
    for name in blueprint_primitives {
        assert!(
            DENYLIST.contains(&name),
            "Blueprint §0.2 forbidden primitive '{}' is missing from DENYLIST",
            name
        );
    }
}

// =====================================================================
// DENYLIST PASS VERIFICATION TESTS (D1–D14)
// =====================================================================

fn assert_denylist_violation(src: &str, expected_primitive: &str) {
    let prog = parse(src).expect("source must parse before denylist check");
    let diags = run_denylist_check(&prog).expect_err("expected denylist violation");
    assert!(!diags.is_empty());
    let diag = &diags[0];
    assert_eq!(diag.code, ErrorCode::E0401);
    let matched_slice = &src[diag.span.start..diag.span.end];
    assert_eq!(
        matched_slice, expected_primitive,
        "span must point exactly at the forbidden primitive identifier"
    );
}

#[test]
fn test_denylist_d1_inject_remote_process() {
    assert_denylist_violation("fn bad() { inject_remote_process(pid, payload); }", "inject_remote_process");
}

#[test]
fn test_denylist_d2_write_process_memory() {
    assert_denylist_violation("fn bad() { write_process_memory(pid, buf); }", "write_process_memory");
}

#[test]
fn test_denylist_d3_create_service() {
    assert_denylist_violation(r#"fn bad() { create_service("svc", path); }"#, "create_service");
}

#[test]
fn test_denylist_d4_dump_lsass() {
    assert_denylist_violation("fn bad() { dump_lsass(); }", "dump_lsass");
}

#[test]
fn test_denylist_d5_install_driver() {
    assert_denylist_violation(r#"fn bad() { install_driver("drv.sys"); }"#, "install_driver");
}

#[test]
fn test_denylist_d6_harvest_credentials() {
    assert_denylist_violation("fn bad() { harvest_credentials(); }", "harvest_credentials");
}

#[test]
fn test_denylist_d7_bypass_uac() {
    assert_denylist_violation("fn bad() { bypass_uac(); }", "bypass_uac");
}

#[test]
fn test_denylist_d8_create_remote_thread() {
    assert_denylist_violation("fn bad() { create_remote_thread(pid, addr); }", "create_remote_thread");
}

#[test]
fn test_denylist_d9_virtual_alloc_ex() {
    assert_denylist_violation("fn bad() { virtual_alloc_ex(pid, size); }", "virtual_alloc_ex");
}

#[test]
fn test_denylist_d10_set_run_key() {
    assert_denylist_violation(r#"fn bad() { set_run_key("svc", path); }"#, "set_run_key");
}

#[test]
fn test_denylist_d11_schedule_task() {
    assert_denylist_violation(r#"fn bad() { schedule_task("persist", cmd); }"#, "schedule_task");
}

#[test]
fn test_denylist_d12_disable_etw() {
    assert_denylist_violation("fn bad() { disable_etw(); }", "disable_etw");
}

#[test]
fn test_denylist_d13_patch_amsi() {
    assert_denylist_violation("fn bad() { patch_amsi(); }", "patch_amsi");
}

#[test]
fn test_denylist_d14_token_steal() {
    assert_denylist_violation("fn bad() { token_steal(pid); }", "token_steal");
}
