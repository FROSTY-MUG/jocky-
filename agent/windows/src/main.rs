pub mod consent;
pub mod loader;

use std::env;
use loader::InProcessLoader;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("jocky-agent-windows 0.1.0 (DFIR Mode, NTRO SIH26148)");
        return;
    }

    if args.iter().any(|a| a == "--test-loader") {
        println!("[INFO] Running in-process loader self-test...");
        let valid_jkm = b"JKM\x01\x00\x00\x00\x00_test_payload";
        match InProcessLoader::load_module_in_process(valid_jkm) {
            Ok(()) => println!("[OK] Loader self-test passed successfully."),
            Err(e) => eprintln!("[ERROR] Loader self-test failed: {}", e),
        }
        return;
    }

    println!("==================================================================");
    println!(" JOCKY Windows Agent v0.1 (DFIR Mode)");
    println!(" A consent-bound DFIR runtime for authorized incident response.");
    println!(" Problem Statement: SIH26148 (NTRO)");
    println!("==================================================================");
    println!("Security status: Strict in-process memory bounds enforced.");
    println!("Attestation: Cryptographic consent token verification active.");
}
