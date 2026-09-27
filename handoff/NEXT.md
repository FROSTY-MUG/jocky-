# Next Steps & Prompt

## Immediate Next Task: STEP 3 — Agent Runtimes

With STEP 1.5, STEP 2A, STEP 2B, and repository polish complete, the compiler can parse, typecheck, diversify, emit both ELF64 and COFF objects, and sign `.jkm` containers.

The immediate next objective is **STEP 3: Real Multi-Platform Agent Runtimes**.

---

## Scope of Step 3

1. **Windows Native Agent (`agent/windows-cpp`)**:
   - Flesh out the C++20 scaffold into an in-process host for executing compiled JOCKY modules.
   - Implement Ed25519 consent token validation and scope enforcement.
   - Implement Windows-specific DFIR primitives (process memory inspection via `ReadProcessMemory`, token privilege checking, driver signature validation).
2. **Linux Agent & eBPF Program (`agent/linux-ebpf` & `agent/linux`)**:
   - Complete `agent/linux-ebpf/src/syscall_trace.bpf.c` for tracking `sys_enter_execve` and process lineage.
   - Connect user-space Rust agent in `agent/linux/` to load the BPF object via `libbpf-rs` and enforce consent tokens.
3. **macOS Swift Agent (`agent/macos-swift`)**:
   - Complete `Sources/JockyAgent/` to query EndpointSecurity (ES) framework events and inspect mach task memory.
4. **Shared Agent Protocol (`agent/common`)**:
   - Wire the existing Ed25519 verification primitives in `agent/common/src/consent.rs` to all three agent runtimes.

---

## Ready-to-Paste Prompt for Next Agent

Copy and paste this prompt to begin Step 3:

```text
MASTER ADMIN BRIEF — STEP 3: MULTI-PLATFORM AGENT RUNTIMES

Context: STEP 1.5, 2A, and 2B are complete and verified. 110 tests pass across
the compiler, diversification passes, .jkm packaging, and Ed25519 signing.
The repository is published on GitHub at https://github.com/FROSTY-MUG/jocky-.

Your task in STEP 3 is to implement the real endpoint agent runtimes using the
scaffolds established in STEP 2B:
  1. Windows Agent (C++20): agent/windows-cpp/
  2. Linux Agent & eBPF (C + Rust): agent/linux-ebpf/ and agent/linux/
  3. macOS Agent (Swift 5.9): agent/macos-swift/
  4. Shared Consent Token verification: agent/common/

Read handoff/README.md, handoff/STATE.md, and handoff/ENVIRONMENT.md before
beginning. Adhere strictly to the defensive non-goals in docs/00-blueprint.md:
all agent operations must require cryptographically signed consent tokens.

Begin with Phase 1: Windows C++ agent runtime.
```
