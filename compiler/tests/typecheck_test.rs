use jockyc::diag::ErrorCode;
use jockyc::{parse, typecheck};

#[test]
fn test_correct_return_type() {
    let src = "fn get_num() -> i32 { return 42; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_ok(), "Expected Ok, got: {:?}", res.err());
}

#[test]
fn test_return_type_mismatch() {
    let src = "fn get_num() -> i32 { return \"not an int\"; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_undefined_variable() {
    let src = "fn test_var() -> i32 { return nonexistent; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_calling_function_wrong_arg_count() {
    let src = "fn add(a: i32, b: i32) -> i32 { return a + b; } fn caller() -> i32 { return add(1); }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_calling_function_wrong_arg_types() {
    let src = "fn add(a: i32, b: i32) -> i32 { return a + b; } fn caller() -> i32 { return add(1, \"str\"); }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_array_element_type_mismatch() {
    let src = "fn make_arr() -> [i32] { let x = [1, 2, \"bad\"]; return x; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_method_call_primitive_has_method() {
    let src = "fn test_driver() -> string { let d = enum_kernel_drivers(); return d[0].path(); }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_ok(), "Expected Ok, got: {:?}", res.err());
}

#[test]
fn test_method_call_primitive_lacks_method() {
    let src = "fn test_bad_method() -> i32 { let d = enum_kernel_drivers(); return d[0].nonexistent_method(); }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_struct_literal_correct_fields() {
    let src = "fn make_finding() -> Finding { return Finding { severity: Severity::Critical, title: \"test\", evidence: \"ev\", mitre: \"T1000\" }; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_ok(), "Expected Ok, got: {:?}", res.err());
}

#[test]
fn test_struct_literal_missing_field() {
    let src = "fn make_finding() -> Finding { return Finding { severity: Severity::Critical, title: \"test\", mitre: \"T1000\" }; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_struct_literal_unknown_field() {
    let src = "fn make_finding() -> Finding { return Finding { severity: Severity::Critical, title: \"test\", evidence: \"ev\", mitre: \"T1000\", extra: 123 }; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_int_where_bool_expected_in_if() {
    let src = "fn test_if() -> i32 { if 123 { return 1; } return 0; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_unary_not_on_non_bool() {
    let src = "fn test_not() -> bool { let x = !42; return x; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_unary_neg_on_non_numeric() {
    let src = "fn test_neg() -> string { let x = -\"hello\"; return x; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_return_without_value_in_non_unit_fn() {
    let src = "fn test_ret() -> i64 { return; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_assignment_to_immutable_var() {
    let src = "fn test_assign() -> i32 { let x = 10; x = 20; return x; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}

#[test]
fn test_for_loop_over_array() {
    let src = "fn test_for() -> i32 { let arr = [1, 2, 3]; for x in arr { if x > 1 { return x; } } return 0; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_ok(), "Expected Ok, got: {:?}", res.err());
}

#[test]
fn test_for_loop_over_non_array() {
    let src = "fn test_for_bad() -> i32 { let num = 42; for x in num { return 1; } return 0; }";
    let prog = parse(src).expect("parse should succeed");
    let res = typecheck(&prog);
    assert!(res.is_err());
    let diags = res.err().unwrap();
    assert!(diags.iter().any(|d| d.code == ErrorCode::E0301));
}
