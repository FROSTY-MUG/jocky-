//! JOCKY Windows COFF Codegen Unit Tests
//!
//! Purpose: Test LLVM code generation targeting Windows MSVC (x86_64-pc-windows-msvc) COFF object files.
//! Inputs: Sample JOCKY source program with functions, arithmetic, and returns.
//! Outputs: Assertions verifying that emitted object is valid COFF-x86-64 with IMAGE_FILE_MACHINE_AMD64.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use jockyc::{check_source, emit_object, typecheck};
use std::fs;

#[test]
fn test_coff_codegen_windows_target() {
    let source = r#"
        fn add(a: i64, b: i64) -> i64 {
            return a + b;
        }

        fn main() -> i64 {
            let res: i64 = add(40, 2);
            return res;
        }
    "#;

    let program = check_source(source).expect("Frontend checks passed");
    let hir = typecheck(&program).expect("Typecheck passed");

    let temp_dir = std::env::temp_dir();
    let obj_path = temp_dir.join("jocky_test_win.obj");

    let result = emit_object(&hir, "x86_64-pc-windows-msvc", &obj_path);
    assert!(result.is_ok(), "Failed to emit COFF object: {:?}", result.err());

    let bytes = fs::read(&obj_path).expect("Failed to read emitted COFF object");
    assert!(bytes.len() > 20, "Emitted object too small for COFF header");

    // Windows COFF x86_64 magic header: Machine == 0x8664 (IMAGE_FILE_MACHINE_AMD64)
    // First two bytes of COFF File Header are Machine in little-endian: [0x64, 0x86]
    let machine_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    assert_eq!(
        machine_type, 0x8664,
        "Expected IMAGE_FILE_MACHINE_AMD64 (0x8664), got 0x{:04x}",
        machine_type
    );

    let _ = fs::remove_file(obj_path);
}
