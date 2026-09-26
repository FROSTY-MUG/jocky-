# JOCKY Linux Agent (eBPF programs, C)

STEP 2B scaffold providing kernel-level visibility for the Linux agent. The
programs are read-only observers — they never modify or block a syscall.

## What is here

| Path | Purpose |
|---|---|
| `Makefile` | Builds `.bpf.c` sources to BPF bytecode. |
| `src/syscall_trace.bpf.c` | Counts `execve` calls per tgid via a tracepoint. |

## Required environment — Linux only

This program **cannot be built or verified on Windows**. Two hard blockers:

1. `clang` cannot target `bpf` on Windows.
2. libbpf headers and `libbpf.pc` are not available there.

To build and verify on Linux:

```bash
# Debian/Ubuntu
sudo apt install clang libbpf-dev libelf-dev linux-headers-$(uname -r)

# Build
make -C agent/linux-ebpf all

# Syntax/compile check used in CI
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -c src/syscall_trace.bpf.c -o /tmp/out.o
```

Requires Linux 5.8+ with BTF available at `/sys/kernel/btf/vmlinux` (CO-RE
relocation), clang 14+, and kernel headers for the build host.

`make` is also not present on stock Windows, so the Makefile is only
meaningful on Linux/macOS CI runners.

## Why eBPF

eBPF gives verified, low-overhead visibility into kernel activity that
userspace tracing cannot reach. The tracepoint attachment is stable across
kernel versions, unlike kprobes on internal symbols.

## Status

SCAFFOLD — written and reviewed, not compiled in this environment (requires
Linux). User-space loader and map consumption land in STEP 3.
