use jockyc::ast::Item;
use jockyc::parse;
use jockyc::passes::denylist::check as run_denylist_check;
use std::fs;
use std::path::Path;

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

#[test]
fn test_stdlib_process() {
    let src = load_stdlib("process.jky");
    let prog = parse(&src).expect("process.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "detect_suspicious_parents"),
        _ => panic!("expected top-level fn in process.jky"),
    }
    run_denylist_check(&prog).expect("process.jky must pass denylist check");
}

#[test]
fn test_stdlib_network() {
    let src = load_stdlib("network.jky");
    let prog = parse(&src).expect("network.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "trace_network_anomalies"),
        _ => panic!("expected top-level fn in network.jky"),
    }
    run_denylist_check(&prog).expect("network.jky must pass denylist check");
}

#[test]
fn test_stdlib_memory() {
    let src = load_stdlib("memory.jky");
    let prog = parse(&src).expect("memory.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "detect_memory_anomalies"),
        _ => panic!("expected top-level fn in memory.jky"),
    }
    run_denylist_check(&prog).expect("memory.jky must pass denylist check");
}

#[test]
fn test_stdlib_detect_byovd() {
    let src = load_stdlib("detect_byovd.jky");
    let prog = parse(&src).expect("detect_byovd.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "detect_byovd"),
        _ => panic!("expected top-level fn in detect_byovd.jky"),
    }
    run_denylist_check(&prog).expect("detect_byovd.jky must pass denylist check");
}

#[test]
fn test_stdlib_detect_inject() {
    let src = load_stdlib("detect_inject.jky");
    let prog = parse(&src).expect("detect_inject.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "detect_code_injection"),
        _ => panic!("expected top-level fn in detect_inject.jky"),
    }
    run_denylist_check(&prog).expect("detect_inject.jky must pass denylist check");
}

#[test]
fn test_stdlib_detect_syscall() {
    let src = load_stdlib("detect_syscall.jky");
    let prog = parse(&src).expect("detect_syscall.jky must parse cleanly");
    assert_eq!(prog.items.len(), 1);
    match &prog.items[0] {
        Item::Fn(f) => assert_eq!(f.name, "detect_syscall_anomalies"),
        _ => panic!("expected top-level fn in detect_syscall.jky"),
    }
    run_denylist_check(&prog).expect("detect_syscall.jky must pass denylist check");
}
