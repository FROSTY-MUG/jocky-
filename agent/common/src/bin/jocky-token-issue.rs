use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use jocky_common::consent::issue;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "jocky-token-issue")]
#[command(about = "Issues signed, scope-bound, time-limited JOCKY consent tokens")]
struct Cli {
    /// Path to Ed25519 private key file
    #[arg(long)]
    key: PathBuf,

    /// Agent identifier (e.g. test-agent-01)
    #[arg(long)]
    agent_id: String,

    /// Forensic scope (e.g. host:LAB-WIN-01)
    #[arg(long)]
    scope: String,

    /// Time to live in seconds
    #[arg(long, default_value = "3600")]
    ttl_seconds: u64,

    /// Maximum permitted operations
    #[arg(long, default_value = "1000")]
    max_ops: u64,

    /// Policy version (e.g. 1)
    #[arg(long, default_value = "1")]
    policy_version: u32,
}

fn load_signing_key(path: &PathBuf) -> Result<SigningKey> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key from {:?}", path))?;

    // Check if it's PEM or hex-encoded
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let joined = lines.join("");

    // Try hex decoding
    if let Ok(bytes) = decode_hex(&joined) {
        if bytes.len() == 32 {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&key_bytes));
        }
    }

    // Try raw bytes if string wasn't hex
    let raw = fs::read(path)?;
    if raw.len() == 32 {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&raw);
        return Ok(SigningKey::from_bytes(&key_bytes));
    }

    Err(anyhow!(
        "Invalid private key format in {:?}: expected 32-byte hex or raw bytes",
        path
    ))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("Odd length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key = load_signing_key(&cli.key)?;

    let token = issue(
        &key,
        &cli.agent_id,
        &cli.scope,
        cli.ttl_seconds as i64,
        cli.max_ops,
        cli.policy_version,
    ).map_err(|e| anyhow!("Failed to issue token: {:?}", e))?;

    let cbor_bytes = token
        .to_cbor()
        .map_err(|e| anyhow!("Failed to serialize token to CBOR: {}", e))?;

    let b64 = base64_encode(&cbor_bytes);
    println!("{}", b64);
    Ok(())
}
