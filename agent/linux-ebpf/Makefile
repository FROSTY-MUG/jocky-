# ==============================================================================
# JOCKY Linux agent - eBPF program build
#
# Purpose: Compiles src/syscall_trace.bpf.c into BPF bytecode (.o) for the
#          user-space agent to load at runtime.
# Blueprint: Section 3 Agent Runtime (STEP 2B scaffold).
#
# Required environment: Linux only.
#   - clang 14 or newer with the BPF target enabled
#   - libbpf headers (libbpf-dev) and libbpf/libbpf.pc (pkg-config)
#   - kernel headers with BTF enabled for CO-RE relocation
#
# This Makefile CANNOT be run on Windows: clang cannot target bpf there and
# libbpf is not available. Verification is deferred to the Linux CI runner.
#
# Usage:
#   make all     build src/syscall_trace.bpf.o
#   make clean   remove build outputs
# ==============================================================================

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
ARCH       ?= x86

# -g embeds BTF so the object is CO-RE relocatable; -O2 matches kernel norms.
# -target bpf is the hard requirement that makes this Linux-only.
CFLAGS  := -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_$(ARCH)
LDFLAGS := -lelf -lz

SRC := src/syscall_trace.bpf.c
OBJ := src/syscall_trace.bpf.o

.PHONY: all clean check-tools

all: $(OBJ)

$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[OK] built $@"

# Fails early with a clear message when the host lacks BPF support.
check-tools:
	@command -v $(CLANG) >/dev/null 2>&1 || { \
		echo "error: $(CLANG) not found; install clang 14+"; exit 1; }
	@echo "[OK] $(CLANG) present"

clean:
	rm -f $(OBJ)
