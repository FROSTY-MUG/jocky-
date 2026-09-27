# 03 — Agent Runtime Design

| Platform | Language | Why |
|---|---|---|
| Windows agent | **C++20** (`jocky-agent-win`) + **Rust FFI** (`jocky-common`) | Direct Win32 ETW trace consumers, NTAPI process enumeration (`PROCESS_QUERY_LIMITED_INFORMATION`), BCrypt hashing, and native in-process module mapping without remote injection or reflective loaders |
| Linux agent | **C** for eBPF programs, **Rust** for user-space loader and collectors | eBPF verifier compliance; memory safety in userspace |
| Shared | `jocky-common` Rust crate (cdylib + C header `jocky.h`) | Shared Ed25519 consent verification (`jocky_consent_token_verify`), `.jkm` container verification (`jocky_jkm_verify`), and attestation primitives |

---

## 1. Agent lifecycle

```
[1] Bootstrap      read config (%ProgramData%\JOCKY\config.toml | /etc/jocky/config.toml)
                   - manager endpoint + pinned CA SPKI
                   - enrollment nonce (out-of-band, provisioned by admin)
[2] Attest & enroll  POST /v1/enroll  {nonce, host_fingerprint, pubkey, capabilities, agent_version}
                     ← {agent_id, client_cert, client_key, consent_token_root_pubkey}
[3] Key storage    Windows: CNG persisted key (TPM-backed if available)
                   Linux:   /var/lib/jocky/identity.key (0600, root) or TPM2 via tpm2-tss
[4] Heartbeat      every 30 s: GET /v1/agents/{id}/heartbeat
                   ← {policy_version, pending_jobs[], revocation_list_version}
[5] Job intake     pull (long-poll, 25 s) and/or WSS hint
[6] Verify         verify.rs: mTLS peer → job JWT → consent → manifest → sig → tlog → policy   (fail-closed)
[7] Execute        load module in-process, run under sandbox, stream output to a spool file
[8] Upload         sign bundle digest, upload via presigned URL, notify manager
[9] Journal        append signed local record of everything above
[10] Idle/backoff  jittered backoff on failure; QUARANTINE on repeated verification failures
```

### 1.1 Consent token (wire format)

```cbor
{
  "v": 1,
  "iss": "jocky-manager/c4-ir",
  "sub": "agent:LAB-WIN-01:9f2c...",       // bound to exactly one agent
  "job": "job_01HQ8Z...",
  "ticket": "IR-2026-0413",                // must resolve in the incident system
  "scope": {
    "host": ["LAB-WIN-01", "LAB-WIN-02"],
    "net":  ["10.20.0.0/16"],
    "paths": ["C:\\Users\\*\\AppData\\Local\\Temp\\*"],
    "net_egress": ["10.20.0.0/16"]         // explicit; absence = no external egress at all
  },
  "caps": ["scan_processes", "enumerate_regions", "trace_network_flows"],
  "max_ops": 2000000,
  "max_bytes_read": 268435456,
  "iat": 1773212400,
  "exp": 1773213300,                       // ≤ 15 min
  "nonce": "b7f3...",
  "sig": "ed25519:K_manager_root,..."
}
```

The agent validates `sub == its own id`, `now ∈ [iat, exp]`, `nonce` not seen before (in-memory LRU of 4096 + local journal), `caps ⊇ manifest.capabilities`, and `scope` covers the runtime target. Counters (`ops`, `bytes_read`) are incremented by the collector trampoline and, when exceeded, the collector is **aborted** (a `BudgetExceeded` error is returned and the finding set is truncated rather than discarded).

---

## 2. Windows agent

### 2.1 Process & module enumeration

Primary API: **NTDLL** `NtQuerySystemInformation(SystemProcessInformation)` — a single snapshot call, far faster and less noisy than a WMI `Win32_Process` query, and it does not require spawning `wmic`.

```rust
// agent-win/src/collect/processes.rs  (abridged, real signatures)
use windows::Win32::System::Threading::*;

pub fn scan_processes(limit: u32, fields: ProcessFields) -> Result<Vec<Process>, CollectorError> {
    let mut buf = vec![0u8; 1 << 20];
    let mut needed = 0u32;
    // Grow the buffer until the snapshot fits; SystemExtendedProcessInformation
    // gives us image path, command line, and integrity level without extra calls.
    loop {
        let st = unsafe {
            NtQuerySystemInformation(SystemExtendedProcessInformation,
                                     buf.as_mut_ptr().cast(), buf.len() as u32, &mut needed)
        };
        match st {
            STATUS_INFO_LENGTH_MISMATCH => buf.resize(needed as usize + 64 * 1024, 0),
            STATUS_SUCCESS => break,
            e => return Err(CollectorError::Nt(e)),
        }
        if buf.len() > 256 << 20 { return Err(CollectorError::TooLarge); }  // hard ceiling
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    unsafe {
        loop {
            let e = &*(buf.as_ptr().add(off) as *const SYSTEM_PROCESS_INFORMATION);
            out.push(Process {
                pid: e.UniqueProcessId as u32,
                ppid: e.InheritedFromUniqueProcessId as u32,
                name: read_unicode(&e.ImageName)?,
                path: read_image_path(e.UniqueProcessId as u32).ok(),   // NtQueryInformationProcess
                cmdline: read_cmdline(e.UniqueProcessId as u32).ok(),   // PEB read, read-only
                signer: signer_of_image(&path)?,                        // WinVerifyTrust
                start_time: filetime_to_unix(e.CreateTime),
                ..
            });
            if out.len() as u32 >= limit { break; }
            if e.NextEntryOffset == 0 { break; }
            off += e.NextEntryOffset as usize;
        }
    }
    Ok(out)
}
```

**Why PEB reads are safe here:** reading `ProcessParameters.CommandLine` in a *suspended/target* process requires `PROCESS_VM_READ`. We open with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, and if the open fails we degrade gracefully (record `cmdline: unavailable` with a reason) rather than escalating privileges. The agent never enables `SeDebugPrivilege` implicitly — it uses whatever the service account has, and reports the resulting visibility gap honestly in the bundle metadata.

### 2.2 Network socket enumeration

- **Owned sockets:** `GetExtendedTcpTable` / `GetExtendedUdpTable` (`AF_INET`, `AF_INET6`), `TCP_TABLE_OWNER_PID_ALL` → gives PID ↔ (local, remote, state) directly.
- **Historical flows:** ETW real-time session on `Microsoft-Windows-Kernel-Network` (`KERNEL_NETWORK_TASK_TCPIP`), consumed with `FerrisWheel`-style ETW session setup via `windows-rs`. Events: `TcpIp/Connect`, `TcpIp/Recv`, `TcpIp/Send`, `TcpIp/Disconnect`, with `PID` and byte counts. This is the backbone of `trace_network_flows`.
- **DNS:** `Get-DnsClientCache`-equivalent via the DNS Client ETW provider (`Microsoft-Windows-DNS-Client`) — captures queries that never hit a file.
- **Fallback when ETW is disabled by the adversary:** `trace_network_flows` falls back to a polling loop over the TCP table (1 s cadence, capped at `budget.ops`) and marks the result `degraded: true, reason: "ETW provider unavailable"`. **The degradation is reported, never hidden.**

### 2.3 Filesystem / execution artifacts

| Artifact | Method | Notes |
|---|---|---|
| `$MFT` | Open `\\.\C:` with `FILE_READ_ATTRIBUTES` (read-only), read the `$MFT` record stream, parse `FILE_NAME` + `STANDARD_INFORMATION` + `DATA` attributes. Streaming parser, ~10 MB/s, bounded by `budget.bytes`. | Raw parse — independent of `$MFT` being locked by the running OS. Optional `$UsnJrnl:$J` read for a change timeline. |
| Prefetch | `C:\Windows\Prefetch\*.pf`, MAM-compressed; XPRESS Huffman decompressor (ported from `mscompress`), then `SCCA` format v17/23/26/30 parser. | Run count + last-8-run timestamps → execution timeline. |
| AmCache | `C:\Windows\AppCompat\Programs\Amcache.hve` — **copy to a temp spool, open with `RegLoadAppKey` read-only**, then delete the temp copy. Never modifies the live hive. | First-execution evidence. |
| ShimCache | `SYSTEM` hive `AppCompatCache`, parsed with the per-OS-version format table. | Execution + path evidence. |
| Run keys | `RegOpenKeyEx` with `KEY_READ` over the known autorun locations (HKLM/HKCU Run, RunOnce, Services, Winlogon, IFEO, AppInit_DLLs). | |
| Services | `EnumServicesStatusEx` + `QueryServiceConfig2` for `SERVICE_CONFIG_FAILURE_ACTIONS`, `delayed-auto` flags. | |
| Scheduled tasks | `ITaskService` COM via `windows-rs`; parse the XML for triggers, actions, and `RunLevel`. | |
| EVTX | `EvtQuery`/`EvtNext` with an XPath filter; channels: Security, System, Application, PowerShell/Operational, Sysmon/Operational, TerminalServices, WMI-Activity. Records exported as EVTX-Evidence JSONL. | |
| Log continuity | Compare `EventRecordID` sequences per channel for gaps + check `wevtutil`-style channel metadata (`maxSize`, `retention`) to detect clearing/rollover (T1070.001). | |

### 2.4 Sandboxing the collector

Each JOCKY module runs inside:
1. A **Job Object** with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` = `manifest.budget.max_memory_mb`, `JOB_OBJECT_LIMIT_JOB_TIME` = `max_runtime_s`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` = 1 (the module runs in-thread, but this bounds any accidental child), `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
2. A **restricted token** created with `CreateRestrictedToken` (DISABLE_MAX_PRIVILEGE | LUA_TOKEN), so even if a module attempted something outside its declared capabilities, the OS denies it. (The module runs on a dedicated thread that impersonates the restricted token for the duration.)
3. **ETW self-telemetry**: the agent emits its own ETW events under provider `JOCKY-Agent` so a cooperating EDR/SIEM can see exactly what JOCKY is doing. This is the interop/allowlisting story — JOCKY declares itself.

---

## 3. Linux agent

### 3.1 eBPF programs (C, libbpf CO-RE)

Programs and their attach points:

| Program | Type | Attach | Purpose |
|---|---|---|---|
| `exec_monitor` | `tracepoint/syscalls/sys_enter_execve` | tracepoint | process lineage, argv, cwd |
| `exit_monitor` | `tracepoint/sched/sched_process_exit` | tracepoint | process teardown, exit codes |
| `fork_monitor` | `tracepoint/sched/sched_process_fork` | tracepoint | parent-child edges |
| `net_connect` | `kprobe/tcp_connect` + `kretprobe` | kprobe | outbound connection with sockaddr |
| `net_accept` | `kprobe/inet_csk_accept` | kprobe | inbound connections |
| `net_data` | `tracepoint/sock/inet_sock_set_state` | tracepoint | state transitions (ESTABLISHED/CLOSE) with bytes |
| `file_open` | `lsm/file_open` (BPF LSM) | LSM | file access with inode/device/path |
| `module_load` | `kprobe/load_module` | kprobe | kernel module loads (rootkit detection) |
| `bpf_syscall` | `tracepoint/syscalls/sys_enter_bpf` | tracepoint | BPF program loads by other processes (defense evasion) |
| `syscall_anomaly` | `raw_tracepoint/sys_enter` | raw TP | rate/anomaly counters per process for suspicious syscall patterns |

Design notes:
- **CO-RE only** (`vmlinux.h` + `bpf_core_read`), no kernel headers at build time → one object per arch, works across distro kernels ≥ 5.8.
- Ring buffer (`BPF_MAP_TYPE_RINGBUF`) for event delivery, 64 MB, with `BPF_RB_NO_WAKEUP` + periodic drain to reduce overhead.
- Every program has an explicit **overhead budget**: measured with `bpftool prog show` and a controlled benchmark; CI fails if `exec_monitor` adds > 1.5 µs/exec or any program drops > 0.5% of events under a 50 k-events/s synthetic load.
- The agent **falls back** to `auditd` netlink (`AUDIT_EXECVE`, `AUDIT_SYSCALL`) or `/proc` polling when BPF is unavailable (no `CAP_BPF`, `kernel.unprivileged_bpf_disabled=2`, or an adversary removed BPF support). Fallback mode is recorded in the bundle as `visibility: {bpf: false, auditd: true, proc_poll: true}`.

```c
// agent-linux/bpf/exec_monitor.bpf.c  (abridged)
struct event_exec {
    __u32 pid, ppid, uid, gid;
    __u64 ts_ns;
    __u8  comm[16];
    __u8  filename[256];
    __u8  argv0[128];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int exec_monitor(struct trace_event_raw_sys_enter *ctx) {
    struct event_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { lost_events_add(1); return 0; }          // never silently drop

    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[0]);

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    bpf_probe_read_kernel_str(&e->argv0, sizeof(e->argv0), BPF_CORE_READ(parent, comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 3.2 User-space loader (Rust)

- Loads BPF objects with `libbpf-rs` (or `aya` as an alternative if libbpf linkage is a problem on the target distro).
- Requires `CAP_BPF` + `CAP_PERFMON` (kernel ≥ 5.8); the agent documents this in its enrollment capabilities and the manager refuses to schedule BPF-dependent jobs to agents that lack it.
- Consumes the ring buffer, joins with `/proc/<pid>` metadata, and emits Arrow batches.
- **No BPF program is ever loaded from a JOCKY module.** BPF objects are part of the signed agent build and are verified at load (`libbpf` `bpf_object__open_mem` + our own digest check against the manifest before `bpf_object__load`).

### 3.3 Linux collectors

`/proc` (process tree, cmdline, fds, maps — read-only), `collect_systemd_units` (via D-Bus `org.freedesktop.systemd1`), `collect_cron` (spool + `/etc/cron.*`), `collect_auth_logs` (journald `_COMM=sshd|sudo|su`), `collect_bash_history` (all users, with mtime for timeline), `collect_journald(since)`, `stat_ext4_xfs` (inode, birth time via `statx(STATX_BTIME)`, xattrs, extents via `FS_IOC_FIEMAP`), `collect_pam_config`, `collect_ld_preload`, `collect_kernel_modules`.

---

## 4. In-memory execution of JOCKY modules

**Goal:** the agent loads and runs a secondary forensic module inside its **own** process, so no `.dll`/`.so` is ever written to the target's disk. This is about (a) leaving no artifact that A1 can find, and (b) surviving a filesystem-based allowlisting policy.

**Strict boundary:** this loads *our own signed modules into our own process*. It is not remote process injection, not reflective DLL injection into another process, and not a shellcode loader. The agent never maps executable memory into a PID other than itself.

### 4.1 Windows: in-process PE mapping

```
┌─ verify.rs: manifest + sig + tlog + consent  (fail-closed, see docs/02 §5.3)
├─ parse PE headers in memory (pe-parse style, our own hardened parser, fuzz-tested)
├─ VirtualAlloc2(MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, size)     ← RW only, never RWX
├─ copy sections into the allocation, apply base relocations in memory
├─ resolve imports against an explicit table:
│     kernel32/ntdll/advapi32/ws2_32/iphlpapi/wevtapi/dbghelp ...
│     each import resolved by *hash of (dll_name, func_name)* from a vetted list,
│     never by LoadLibrary of a path taken from the module.
├─ apply IAT fixups; run TLS callbacks if the module declares them (our modules don't)
├─ FlushInstructionCache(GetCurrentProcess(), base, size)
├─ NtProtectVirtualMemory(base, size, PAGE_EXECUTE_READ, &old)     ← W^X enforced: RW → RX, never RWX
├─ call jocky_module_entry(JobContext*, ResultWriter*)             ← C ABI, no C++ name mangling
└─ after return: NtProtectVirtualMemory(base, size, PAGE_READWRITE, ..)
                secure-zero the allocation, NtFreeVirtualMemory
```

Key properties:
- **Never `PAGE_EXECUTE_READWRITE`.** The transition RW → RX is the whole point; a scanner checking for RWX private memory finds nothing, and more importantly the OS enforces W^X so a memory-corruption bug in a module cannot self-modify.
- **No `LoadLibrary` on module-derived paths.** Imports resolve from an allowlist by hashed name. A malicious module cannot force loading of an attacker DLL.
- **No `WriteProcessMemory` into other processes.** Not in the codebase; a CI grep gate enforces it (`forbidden_api` check, see `docs/04` §5).
- **No `CreateRemoteThread`.** Same gate.
- **Section names are not used.** The agent resolves `jocky_module_entry` from the module's export table by an ordinal-free hash lookup.
- **Guard pages** (`PAGE_GUARD`) on both sides of the allocation catch overruns and turn them into an immediate, logged crash rather than silent corruption.
- **CFG / CET**: builds are compiled with `/guard:cf` and, where supported, shadow-stack (`/CETCOMPAT`); the loader calls `SetProcessValidCallTargets` for the mapped range so Control Flow Guard permits the indirect calls into the module.

Alternative path for maximum portability: **bytecode mode**. If the module ships `.jkb` only, no executable memory is needed at all — the interpreter runs from the RW allocation and no `RX` transition occurs. Recommended default for lab demos.

### 4.2 Linux: in-process ELF mapping

```
├─ verify.rs (same chain)
├─ memfd_create("jkm", MFD_CLOEXEC)          ← anonymous, no filesystem path, auto-freed on close
├─ write ELF bytes to the memfd
├─ mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE, memfd)   ← writable mapping, not executable
├─ apply relocations in memory; resolve symbols via dlsym against an allowlist
├─ mprotect(addr, len, PROT_READ|PROT_EXEC)         ← W^X: RW → RX
├─ call jocky_module_entry via a function pointer
└─ mprotect(addr, len, PROT_READ|PROT_WRITE); explicit_bzero(addr, len); munmap()
```

`memfd_create` is used instead of `shm_open`/temp file because it has **no filesystem name** — `MFD_CLOEXEC` + no `MFD_ALLOW_SEALING` interplay needed for our case, and nothing appears in `/dev/shm`. Note honestly: `memfd` pages still exist in the process's address space and can be observed by a root-level A1 via `/proc/<pid>/maps` (shown as `/memfd:jkm (deleted)`). We **do not** attempt to hide from root-level inspection; a root adversary who inspects our own process's maps can see the module. What in-memory loading buys us is: no disk artifact, no file to hash-block, no file to quarantine, and a much smaller forensic footprint on the *investigated* host.

### 4.3 Syscall path (Windows)

Problem being solved: after an EDR is killed or a hook chain is corrupted, `ntdll!NtXxx` stubs may be **broken** (trampolined to a dead address, or returning `STATUS_ACCESS_DENIED` unconditionally). A responder still needs to read process lists.

Design:
- At **build time**, the codegen emits one static stub per syscall in a vetted table (`NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtReadVirtualMemory`, `NtQueryVirtualMemory`, `NtQueryObject`, `NtOpenProcess`, `NtProtectVirtualMemory`, `NtClose`, …). Each stub is:

```asm
; generated per build with a seeded instruction-sequence template (D2/D5 applied)
jocky_sys_NtQuerySystemInformation:
    mov r10, rcx
    mov eax, <SSN>              ; service number resolved at build time from the
                                ; target's ntdll export table for that OS build family
    syscall
    ret
```

- **SSN resolution at build time**, not runtime: `tools/ssn/` parses the `ntdll.dll` export table for each supported Windows build (10 19041/19045, 11 22000/22621/22631/26100), maps name → SSN, and emits a static table. Runtime SSN *guessing* (the "Hell's Gate / Halo's Gate" style dynamic resolution) is **explicitly not implemented** — it is an evasion technique aimed at defeating security product hooks, and it is unnecessary for our defensive purpose.
- The stubs are used **only** when a usermode API call fails with a hook-signature error (e.g. `STATUS_INVALID_SYSTEM_SERVICE`, or a stub whose first bytes are a `jmp` outside `ntdll`'s image range). The agent logs `"usermode_stub_tampered": true` — which is itself a **finding**: a tampered `ntdll` is strong evidence of a blinded security stack (T1562).
- Full auditability: every use of a direct stub is recorded in the local journal and in the bundle metadata with a reason code.

### 4.4 Anti-tamper self-measurement (honest scope)

The agent computes BLAKE3 over its own `.text` at startup and before each module load, comparing to a value baked into the signed manifest. On mismatch → `QUARANTINE`.

**Honest limitation, stated in the SIH submission:** a kernel-level adversary can patch both the agent's code and the measurement routine. Self-measurement raises the cost of *casual* tampering and produces evidence of *attempted* tampering, but it is not a guarantee. The real integrity anchor is the manager side: the agent's journal is hash-chained and the manager cross-checks expected job counts, so a silent agent is itself detectable (a missing heartbeat is an alert).

---

## 5. Kernel visibility & driver concepts (safe demo plan)

### 5.1 Why kernel visibility matters for DFIR

User-mode collection has three blind spots that an advanced A1 exploits:
1. **Hidden processes** — DKOM unlinks `EPROCESS` from `ActiveProcessLinks`; `NtQuerySystemInformation` then omits it.
2. **Hidden drivers/rootkits** — an unsigned driver that patches `SSDT`/`IDT` or hooks `IRP` dispatch is invisible to `EnumServicesStatusEx`.
3. **Missed file/registry I/O** — minifilter-dependent telemetry stops when the minifilter is unloaded.

A kernel component restores that visibility. **The safe demo below demonstrates the *detection* of these techniques, not their implementation.**

### 5.2 Demo option A (preferred): ETW + eBPF-only, no driver

Deliverable: a JOCKY job that detects the *effects* of the blind spots without any kernel code of our own.

- `collect_evtx` + `verify_log_continuity` → detect `Microsoft-Windows-Kernel-Process` / `Sysmon` provider gaps.
- Cross-view process comparison: enumerate processes via `NtQuerySystemInformation` **and** via `CreateToolhelp32Snapshot` **and** via `NtQueryInformationProcess` walking the handle table; a PID present in one view but not another is a **hidden-process indicator** (a classic DKOM detection heuristic, done purely from user mode).
- `enumerate_kernel_callbacks` via `NtQuerySystemInformation(SystemModuleInformation)` + `SystemKernelDebuggerInformation` to list loaded kernel modules and compare against `EnumServicesStatusEx` + the driver directory — a driver file on disk with no service entry, or a service with a file whose signature fails, is a finding.
- On Linux, the `module_load` and `bpf_syscall` eBPF programs give the same class of evidence.

**This option requires zero kernel development and is the default in the SIH demo.** It is defensible, safe, and fully sufficient to demonstrate the concept.

### 5.3 Demo option B: minimal test-signed lab driver (own VM only)

If the team wants a concrete driver artifact, the constraints are:

- Runs **only** on a dedicated lab VM with `bcdedit /set testsigning on` and a machine-generated test certificate; the VM is snapshotted before and restored after every demo.
- **Read-only**: the driver exposes exactly one IOCTL, `IOCTL_JOCKY_ENUM_EPROCESS`, which walks `ActiveProcessLinks` **twice** — once from `PsGetCurrentProcess()` and once from `PsInitialSystemProcess` — and returns the **set difference**. The difference is the hidden-process list. It never writes kernel memory, never patches any table, never hooks anything, never hides anything.
- ~400 lines of C, one `.c` + one `.inf`, no third-party code, no undocumented structure patching beyond reading `EPROCESS` fields via documented offsets resolved from `nt!PsGetProcessImageFileName` and friends (using `MmGetSystemRoutineAddress`), so it does not depend on hardcoded offsets.
- The driver is signed with the test cert, its hash is registered in the JOCKY hash registry, and the agent's `match_vulnerable_driver` hashlist is extended with the test driver so that **the demo also demonstrates detection of itself** — i.e. we prove JOCKY detects an unauthorized kernel driver on the host. That is the strongest possible framing: the driver exists to be detected.
- Written disclaimer in the demo script and on the slide: *"This driver was written by us, for our lab VM, to be detected by JOCKY. It is read-only and exposes one enumeration IOCTL. It is not a rootkit."*

### 5.4 Detecting *attacker* misuse of vulnerable drivers (BYOVD)

This is the real defensive value, and it needs no driver of ours.

`collect_drivers()` + `match_vulnerable_driver(hashlist)`:

1. **Inventory**: enumerate loaded kernel modules (Windows: `NtQuerySystemInformation(SystemModuleInformation)` + the `\Driver` object directory via `NtOpenDirectoryObject`/`NtQueryDirectoryObject`; Linux: `/proc/modules` + `module_load` eBPF events).
2. **Hash**: BLAKE3 of each on-disk driver image.
3. **Match** against a maintained hashlist of known-vulnerable drivers (sourced from `loldrivers.io`-style public research, pinned by commit and vendored into the agent build with a signed update channel; never fetched at runtime from a third party).
4. **Signature policy**: `verify_driver_signature()` → signer subject, whether it is a Microsoft Windows Hardware Compatibility Publisher signature, whether it is a WHQL-signed driver that is nonetheless on the vulnerable list (the classic BYOVD pattern), and whether the file has been renamed since signing (embedded original filename vs on-disk name mismatch).
5. **Behavioral corroboration**: correlate a vulnerable driver load with (a) a subsequent process created by `System` PID 4, (b) a service created in the last N minutes, (c) any process with a handle to the driver's device object. Correlation, not a single hash, is what makes this a defensible finding.
6. **Finding output**: `severity: Critical`, `technique: T1068/T1543.003`, with the driver hash, signer, load time, and the correlated evidence. Also emits a "host integrity" flag that tells the analyst whether **JOCKY's own visibility is likely degraded** (e.g. a known-kernel-hooking driver is present → mark the process list as `trust: degraded`).

That last point is the design principle for the whole agent: **every collector output carries a `trust` field** (`full`, `degraded`, `suspect`) and the dashboard renders degraded evidence differently. Never present a possibly-incomplete process list as complete.

---

## 6. Resource governance & reliability

| Concern | Control |
|---|---|
| CPU | `max_cpu_pct` in manifest; enforced via Job Object CPU rate control (Win) and cgroup v2 `cpu.max` (Linux) |
| Memory | `max_memory_mb`; Job Object limit / cgroup `memory.max` + `memory.oom.group` |
| Disk | Modules never write to disk; spooled bundles go to a temp dir with `max_spool_mb` and are deleted after upload confirmation |
| Runtime | `max_runtime_s`; cooperative cancellation via an atomic flag checked in collector trampolines every 4096 ops, plus hard kill at 2× the budget |
| Crash safety | Module runs on a dedicated thread; a panic/SEH crash is caught (`catch_unwind` / `AddVectoredExceptionHandler` for the loader frame), the agent records `module_crashed` with the faulting address, and stays alive |
| Watchdog | Separate watchdog thread; if the agent main loop stalls > 90 s, it writes a `STALLED` journal entry and restarts the worker |
| Backoff | Jittered exponential on manager unreachable: `sleep = rand(0, min(300, 5 * 2^attempt))` seconds |
| Update | Agent binary update is itself a signed `.jkm`-style package; staged rollout (canary 1 agent → 10% → 100%) with automatic rollback on heartbeat loss > 2 min in the canary group |