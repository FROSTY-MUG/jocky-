use jockyc::passes::denylist::check as run_denylist_check;
use jockyc::{emit_object, parse, typecheck};
use std::fs;
use std::path::{Path, PathBuf};

fn load_stdlib(filename: &str) -> String {
    let candidates = [
        format!("../stdlib/jocky/{}", filename),
        format!("stdlib/jocky/{}", filename),
        format!("../../stdlib/jocky/{}", filename),
    ];
    for candidate in &candidates {
        if Path::new(candidate).exists() {
            return fs::read_to_string(candidate)
                .unwrap_or_else(|e| panic!("failed to read '{}': {}", candidate, e));
        }
    }
    panic!("could not find stdlib script '{}'", filename);
}

fn get_scratch_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // workspace root
    p.push("scratch");
    fs::create_dir_all(&p).unwrap();
    p.push(name);
    p
}

fn assert_valid_elf64(path: &PathBuf) {
    let bytes = fs::read(path).expect("failed to read object file");
    assert!(bytes.len() >= 64, "Object file too small to be ELF64");
    assert_eq!(&bytes[0..4], b"\x7fELF", "Invalid ELF magic");
    assert_eq!(bytes[4], 2, "Expected 64-bit ELF");
    assert_eq!(bytes[5], 1, "Expected little-endian (LSB)");
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    assert_eq!(e_type, 1, "Expected relocatable object (ET_REL)");
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(e_machine, 62, "Expected x86_64 machine architecture");
}

fn run_pipeline_for_stdlib(filename: &str, out_obj_name: &str) {
    let src = load_stdlib(filename);
    let prog = parse(&src).unwrap_or_else(|e| panic!("parse failed for {}: {:?}", filename, e));
    run_denylist_check(&prog).unwrap_or_else(|e| panic!("denylist failed for {}: {:?}", filename, e));
    let hir = typecheck(&prog).unwrap_or_else(|e| panic!("typecheck failed for {}: {:?}", filename, e));
    let out_path = get_scratch_path(out_obj_name);
    emit_object(&hir, "x86_64-unknown-linux-gnu", &out_path)
        .unwrap_or_else(|e| panic!("codegen failed for {}: {:?}", filename, e));
    assert_valid_elf64(&out_path);
}

#[test]
fn test_codegen_stdlib_detect_byovd() {
    run_pipeline_for_stdlib("detect_byovd.jky", "stdlib_detect_byovd.o");
}

#[test]
fn test_codegen_stdlib_detect_inject() {
    run_pipeline_for_stdlib("detect_inject.jky", "stdlib_detect_inject.o");
}

#[test]
fn test_codegen_stdlib_detect_syscall() {
    run_pipeline_for_stdlib("detect_syscall.jky", "stdlib_detect_syscall.o");
}

#[test]
fn test_codegen_stdlib_memory() {
    run_pipeline_for_stdlib("memory.jky", "stdlib_memory.o");
}

#[test]
fn test_codegen_stdlib_network() {
    run_pipeline_for_stdlib("network.jky", "stdlib_network.o");
}

#[test]
fn test_codegen_stdlib_process() {
    run_pipeline_for_stdlib("process.jky", "stdlib_process.o");
}
