use jockyc::{emit_object, emit_object_with_ir, parse, typecheck};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_scratch_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("scratch");
    fs::create_dir_all(&p).unwrap();
    p.push(name);
    p
}

fn compile_to_obj(src: &str, name: &str) -> PathBuf {
    let prog = parse(src).expect("parsing failed");
    let hir = typecheck(&prog).expect("typechecking failed");
    let out_path = get_scratch_path(name);
    emit_object(&hir, "x86_64-unknown-linux-gnu", &out_path).expect("codegen failed");
    out_path
}

fn assert_valid_elf64_x86_64(path: &PathBuf) {
    let bytes = fs::read(path).expect("failed to read object file");
    assert!(bytes.len() >= 64, "Object file too small to be ELF64");
    // e_ident: \x7fELF
    assert_eq!(&bytes[0..4], b"\x7fELF", "Invalid ELF magic");
    // EI_CLASS: 2 = ELFCLASS64
    assert_eq!(bytes[4], 2, "Expected 64-bit ELF");
    // EI_DATA: 1 = ELFDATA2LSB
    assert_eq!(bytes[5], 1, "Expected little-endian (LSB)");
    // e_type: 1 = ET_REL (relocatable)
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    assert_eq!(e_type, 1, "Expected relocatable object (ET_REL)");
    // e_machine: 0x3E (62) = EM_X86_64
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(e_machine, 62, "Expected x86_64 machine architecture");
}

fn run_llvm_tool(tool: &str, args: &[&str]) -> String {
    let mut candidates = vec![
        format!("{}.exe", tool),
        tool.to_string(),
    ];
    if let Ok(prefix) = std::env::var("LLVM_SYS_170_PREFIX") {
        candidates.insert(0, format!("{}\\bin\\{}.exe", prefix, tool));
    }

    for c in &candidates {
        if let Ok(output) = Command::new(c).args(args).output() {
            return String::from_utf8_lossy(&output.stdout).to_string();
        }
    }
    String::new()
}

#[test]
fn test_codegen_minimal_return_42() {
    let src = "fn main() -> i32 { return 42; }";
    let obj = compile_to_obj(src, "min_42.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("main"), "Symbol 'main' should exist in symbol table");

    let disasm = run_llvm_tool("llvm-objdump", &["-d", obj.to_str().unwrap()]);
    assert!(
        disasm.contains("2a") || disasm.contains("42"),
        "Disassembly should contain immediate 42 (0x2a)"
    );
}

#[test]
fn test_codegen_arithmetic() {
    let src = "fn main() -> i32 { let a = 10; let b = 20; return a + b * 2; }";
    let obj = compile_to_obj(src, "arith.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("main"));
}

#[test]
fn test_codegen_if_else() {
    let src = "fn main() -> i32 { let x = 5; if x > 2 { return 100; } else { return 200; } }";
    let obj = compile_to_obj(src, "if_else.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("main"));
}

#[test]
fn test_codegen_while_loop() {
    let src = "fn main() -> i32 { let mut i = 0; while i < 10 { i = i + 1; } return i; }";
    let obj = compile_to_obj(src, "while_loop.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("main"));
}

#[test]
fn test_codegen_helper_function() {
    let src = "fn square(x: i32) -> i32 { return x * x; } fn main() -> i32 { return square(5); }";
    let obj = compile_to_obj(src, "helper.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("main"));
    assert!(nm_out.contains("square"));
}

#[test]
fn test_codegen_extern_declare_sha256() {
    let src = "fn test_hash() -> string { return sha256(\"data\"); }";
    let obj = compile_to_obj(src, "hash_extern.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("sha256"), "Extern sha256 must appear in symbol table");
    assert!(nm_out.contains("U sha256"), "Extern sha256 must be an undefined symbol (U)");
}

#[test]
fn test_codegen_extern_declare_scan_processes() {
    let src = "fn test_scan() -> [Process] { return scan_processes(); }";
    let obj = compile_to_obj(src, "scan_extern.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("scan_processes"), "Extern scan_processes must appear in symbol table");
    assert!(nm_out.contains("U scan_processes"), "scan_processes must be undefined symbol (U)");
}

#[test]
fn test_codegen_string_constant() {
    let src = "fn get_msg() -> string { return \"Hello, JOCKY!\"; }";
    let obj = compile_to_obj(src, "str_const.o");
    assert_valid_elf64_x86_64(&obj);

    let bytes = fs::read(&obj).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(hay.contains("Hello, JOCKY!"), "Object file should embed string literal");
}

#[test]
fn test_codegen_struct_init() {
    let src = "fn make_finding() -> Finding { return Finding { severity: Severity::Critical, title: \"alert\", evidence: \"ev\", mitre: \"T1000\" }; }";
    let obj = compile_to_obj(src, "struct_init.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("make_finding"));
}

#[test]
fn test_codegen_array_len() {
    let src = "fn get_len() -> i64 { let arr = [10, 20, 30]; return arr.len(); }";
    let obj = compile_to_obj(src, "arr_len.o");
    assert_valid_elf64_x86_64(&obj);

    let nm_out = run_llvm_tool("llvm-nm", &[obj.to_str().unwrap()]);
    assert!(nm_out.contains("get_len"));
}

#[test]
fn test_codegen_emit_ir_flag() {
    let src = "fn main() -> i32 { return 42; }";
    let prog = parse(src).expect("parse");
    let hir = typecheck(&prog).expect("typecheck");
    let out_obj = get_scratch_path("emit_ir_test.o");
    let out_ll = get_scratch_path("emit_ir_test.ll");

    emit_object_with_ir(&hir, "x86_64-unknown-linux-gnu", &out_obj, true).expect("codegen");

    assert!(out_ll.exists(), "LLVM IR .ll file must be created when emit_ir is true");
    let ll_text = fs::read_to_string(&out_ll).expect("read .ll");
    assert!(ll_text.contains("define i32 @main()"), ".ll must define main");
    assert!(ll_text.contains("ret i32 42"), ".ll must return 42");
}
