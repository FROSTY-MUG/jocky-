// SPDX-License-Identifier: Apache-2.0
// ==============================================================================
// JOCKY Linux agent - eBPF syscall visibility program
//
// Purpose:
//   Minimal, read-only eBPF program that gives the Linux agent kernel-level
//   visibility of process execution. It attaches to the tracepoint
//   "syscalls:sys_enter_execve" and records the count of execve calls per
//   process id, which the agent can later read through a perf buffer.
//
//   Blue-team scope: this program only observes. It never modifies arguments,
//   returns errors, or blocks a syscall. It has no offensive capability.
//
// Inputs:
//   Kernel tracepoint: tracepoint/syscalls/sys_enter_execve
//   Reads (read-only) the current task pid via bpf_get_current_pid_tgid().
//
// Outputs:
//   Per-CPU map "execve_count" (BPF_MAP_TYPE_PERCPU_HASH) keyed by tgid.
//   A monotonic event counter in "event_count".
//
// Exit Codes:
//   Not applicable - compiled to BPF bytecode, loaded by the user-space agent.
//   See the Makefile: `make all` builds src/syscall_trace.bpf.o.
//
// Required environment:
//   Linux 5.8+ with BTF (/sys/kernel/btf/vmlinux), clang 14+ with the bpf
//   target, libbpf headers, and libbpf/libbpfc on the build host.
//
// Blueprint Section:
//   Section 3 Agent Runtime (STEP 2B scaffold; kernel visibility for STEP 3).
// ==============================================================================

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Counts of execve calls observed, keyed by thread group id (tgid).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} execve_count SEC(".maps");

// Monotonic total number of events this program has observed.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} event_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 *countp = bpf_map_lookup_elem(&execve_count, &tgid);

	if (countp) {
		__sync_fetch_and_add(countp, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&execve_count, &tgid, &one, BPF_ANY);
	}

	__u32 zero = 0;
	__u64 *total = bpf_map_lookup_elem(&event_count, &zero);
	if (total)
		__sync_fetch_and_add(total, 1);

	return 0;
}
