# Known Gotchas & Troubleshooting

This document records tricky bugs, toolchain quirks, and hard-won lessons discovered during development to prevent future developers from repeating known errors.

---

## 1. LLVM 17 Environment Variables on Windows
- **Symptom**: `inkwell` or `llvm-sys` fails to compile with `llvm-config not found` or `cannot find llvm-sys`.
- **Cause**: Windows does not register conda environment bin folders on system PATH by default.
- **Fix**: Always set:
  ```powershell
  $env:LLVM_SYS_170_PREFIX = "C:\Users\Aryan\miniconda3\envs\llvm17\Library"
  $env:Path = "C:\Users\Aryan\miniconda3\envs\llvm17\Library\bin;" + $env:Path
  ```

---

## 2. Missing MSVC Linker Inputs (`z.lib` and `zstd.dll.lib`)
- **Symptom**: `LINK : fatal error LNK1181: cannot open input file 'z.lib'` or `zstd.dll.lib`.
- **Cause**: Conda-forge's `llvmdev` expects zlib and zstd to be linked, but conda names them `zlib.lib` and `zstd.lib`.
- **Fix**: Copy `z.lib` from base conda and create `zstd.dll.lib` as a copy of `zstd.lib` in `C:\Users\Aryan\miniconda3\envs\llvm17\Library\lib`.

---

## 3. PowerShell UTF-8 Byte Order Marks (BOM)
- **Symptom**: `jockyc` returns `error[E0101]: Unexpected character '\u{feff}'` when compiling scripts created with PowerShell `Out-File -Encoding utf8`.
- **Cause**: Windows PowerShell 5.1 emits a 3-byte UTF-8 BOM (`EF BB BF`) at the beginning of files.
- **Fix**: `compiler/src/lib.rs` strips `\u{feff}` from the input slice before passing it to `lexer::tokenize()`.

---

## 4. Ed25519 Signature Scope (Trap T3)
- **Symptom**: `jocky-verify` fails with `Verification equation was not satisfied` immediately after signing.
- **Cause**: Signing over the container bytes including the signature field itself causes a circular dependency.
- **Fix**: The signature scope is strictly defined as:
  $$\text{Payload} = \text{Header Bytes (with sig\_len=64)} \mathbin{\Vert} \text{Code Bytes} \mathbin{\Vert} \text{CBOR Manifest Bytes}$$
  The 64-byte signature is appended at `sig_offset`.

---

## 5. TargetMachine Panic on Uninitialized Target (Trap T4)
- **Symptom**: Process panics with `Target::from_triple: target not found` when targeting `x86_64-pc-windows-msvc`.
- **Cause**: Calling `Target::initialize_x86` alone does not register all target configurations.
- **Fix**: Always call `Target::initialize_all(&InitializationConfig::default())` before querying `TargetTriple` in `compiler/src/codegen/llvm.rs`.

---

## 6. Target Relocation Mode for Windows MSVC
- **Symptom**: Clang/LLVM emits relocations incompatible with Windows `link.exe` if `RelocMode::PIC` is used.
- **Cause**: Windows x86_64 COFF uses position-independent image loading via PE base relocations, not SysV ELF PIC tables.
- **Fix**: Use `RelocMode::Default` when the target triple contains `windows`, and `RelocMode::PIC` for Linux ELF.

---

## 7. `pwsh` Command on Windows Without PowerShell 7 (Trap T8)
- **Symptom**: Scripts or commands calling `pwsh` fail with `The term 'pwsh' is not recognized`.
- **Cause**: Windows 10/11 includes `powershell.exe` (PowerShell 5.1) out of the box, but PowerShell 7 Core (`pwsh.exe`) requires an explicit install.
- **Fix**: We created a lightweight shim `pwsh.cmd` in `C:\Users\Aryan\miniconda3\envs\llvm17\Library\bin\pwsh.cmd` that transparently forwards arguments to `powershell.exe %*`.

---

## 8. Deprecated CBOR Crates (Trap T1)
- **Symptom**: Build warnings or deprecation notices regarding `serde_cbor`.
- **Cause**: `serde_cbor` is unmaintained and deprecated.
- **Fix**: All CBOR serialization in `compiler/src/jkm/manifest.rs` uses `ciborium`.
