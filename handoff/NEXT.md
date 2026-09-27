# Next Steps & Prompt

## Immediate Next Task: STEP 3B -- Linux Agent & eBPF Program

With STEP 1.5, STEP 2A, STEP 2B, and STEP 3A (Windows C++ Agent + Shared Consent Protocol) complete and verified, the shared Ed25519 consent protocol and C FFI interface are operational, and the Windows agent runtime is verified with 100% CTest pass rates and live host DFIR verification.

The immediate next objective is **STEP 3B: Linux Agent & eBPF Program (`agent/linux-ebpf` & `agent/linux`)**.

---

## Scope of Step 3B

1. **eBPF Kernel Program (`agent/linux-ebpf/src/syscall_trace.bpf.c`)**:
   - Implement `sys_enter_execve`, `sys_enter_memfd_create`, and `sys_enter_ptrace` tracepoints/kprobes.
   - Ring buffer emission of `process_exec_event` with PID, PPID, comm, filename, and credentials.
   - Strict read-only tracing: no packet manipulation, no syscall blocking, no memory injection.
2. **Linux User-Space Agent (`agent/linux/`)**:
   - Rust-based agent leveraging `libbpf-rs` to load and attach the BPF program.
   - Consume ring buffer events and enforce Ed25519 consent token scope verification using `agent/common`.
   - Implement live host collectors (`/proc` walking, socket enumeration via `/proc/net/tcp`, kernel module inspection via `/proc/modules`).
3. **Verification**:
   - Unit tests and integration gates verifying consent verification, BPF event streaming, and clean lifecycle management.

---

## Ready-to-Paste Prompt for Next Agent

Copy and paste this prompt to begin Step 3B:

```text
MASTER ADMIN BRIEF — STEP 3B: LINUX AGENT & eBPF PROGRAM

Context: STEP 1.5, 2A, 2B, and 3A are complete and verified. 138 tests pass across
the compiler, diversification passes, .jkm packaging, Ed25519 signing, agent/common FFI,
and Windows C++ agent. The repository is published at https://github.com/FROSTY-MUG/jocky-.

Your task in STEP 3B is to implement the Linux endpoint agent runtime:
  1. eBPF syscall tracer in agent/linux-ebpf/src/syscall_trace.bpf.c
  2. Linux Rust agent in agent/linux/ wiring libbpf-rs and agent/common consent tokens
  3. Live Linux DFIR collectors (/proc, /proc/net, /proc/modules)
  4. Structured JSON output matching JOCKY telemetry format

Read handoff/README.md, handoff/STATE.md, and docs/03-agent-runtime.md before
beginning. Adhere strictly to the defensive non-goals in docs/00-blueprint.md:
all agent operations must require cryptographically signed consent tokens.
```
