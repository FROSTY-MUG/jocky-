# 08 — Authorized Real-World Testing Plan

**Every test below runs only on machines the team owns or has written permission to test.** No third-party system is touched. Each test carries an authorization reference; the authorization record template is in §0.

---

## 0. Authorization record (mandatory, one per test)

```yaml
test_id:            HOST-001
title:              Windows process-lineage detection under EDR-active conditions
authorization_ref:  LAB-AUTH-2026-014          # signed PDF in the team's private repo
owner:              <name> (VM owner)
targets:
  - host: LAB-WIN-01
    ownership: "Azure VM, subscription <id>, resource group jocky-lab — owned by team"
    os: "Windows 11 23H2 (22631.4317)"
    isolation: "Private VNet 10.20.1.0/24, no inbound internet, NSG denies all but mgmt from 10.20.0.0/16"
    snapshot: "pre-test snapshot taken, id snap-0abc…"
  - host: LAB-LNX-01
    ownership: "Azure VM, same subscription — owned by team"
    os: "Ubuntu 24.04.1 LTS, kernel 6.8.0-45"
    isolation: "same VNet, NSG egress restricted to 10.20.0.0/16 + manager"
prohibited:         ["any host outside 10.20.0.0/16", "any public target", "any third-party SaaS"]
approval:           { requested_by: <name>, approved_by: <name>, date: 2026-09-20 }
destruction:        "VMs deleted or restored from snapshot within 24 h of test completion"
```

The `prohibited` field plus the NSG rules are the technical enforcement of the policy; the signed approval is the procedural one. Both are required.

---

## 1. Lab topology (built once, reused)

```
10.20.0.0/16  jocky-lab (private VNet, no internet egress except to the manager)

  10.20.0.10   mgmt-jump      (Windows/Linux jump host, WireGuard server, only admin entry point)
  10.20.1.11   LAB-WIN-01     Windows 11 23H2  — primary Windows target
  10.20.1.12   LAB-WIN-02     Windows Server 2022 — domain controller (AD lab)
  10.20.2.21   LAB-LNX-01     Ubuntu 24.04     — primary Linux target
  10.20.2.22   LAB-LNX-02     Ubuntu 22.04     — eBPF-comparison target
  10.20.3.30   lab-manager    Manager + Postgres + Redis (single-node compose for the lab)
  10.20.3.31   lab-tlog       Transparency log + mirrors
  10.20.3.32   lab-redteam    Kali — generates the *simulated* adversary behavior
  10.20.3.33   lab-supabase   Self-hosted Supabase (Postgres + GoTrue + PostgREST) for DB tests
  10.20.4.40   lab-cdn-sim    nginx simulating CDN edge + WAF for relay tests
```

All traffic stays inside the VNet. The only outbound allowed is from `lab-manager` to AWS S3/KMS endpoints via VPC endpoints (no internet gateway attached to the management subnet).

**Adversary simulation** uses only scripts we wrote, in `tools/adversary-sim/`, each of which is:
- explicitly non-destructive (no data destruction, no encryption, no exfiltration to real destinations — simulated C2 goes to `10.20.3.32`),
- labeled in the process name and command line (e.g. `jocky-sim-beacon.exe`), so we can also measure **how visible** the simulation is,
- recorded with a hash and a written description in `tools/adversary-sim/README.md`.

Simulations available: `sim-office-macro-chain` (winword→powershell→curl), `sim-beacon` (periodic HTTPS to lab C2 with jitter), `sim-dns-tunnel` (high-entropy subdomain queries), `sim-rwx-inject` (allocates RWX in its *own* process and writes a NOP sled — no injection into other processes), `sim-runkey-persist` (adds a Run key pointing to a harmless `calc.exe`), `sim-service-persist`, `sim-schtask-persist`, `sim-log-clear` (clears a *dedicated synthetic event log channel*, never Security), `sim-vuln-driver-load` (loads a known-vulnerable *test-signed* driver on LAB-WIN-01 only, in the snapshot-restored state), `sim-linux-cron-persist`, `sim-linux-ld-preload`.

---

## 2. Host forensics tests

### HOST-001 — Windows process-lineage detection

| Field | Value |
|---|---|
| **Objective** | Verify `find_suspicious_children` detects an Office→scripting-interpreter chain with zero false negatives and a measured false-positive rate. |
| **Setup** | LAB-WIN-01, agent v1.x variant 3, `Microsoft 365` installed, Sysmon 15.15 present (as a reference source), script `detect.children.jky`. |
| **Steps** | 1. Run `sim-office-macro-chain` 50 times with randomized delays (0.5–10 s) and randomized interpreter (powershell/cmd/wscript/mshta/rundll32). 2. Run 50 benign control scenarios (Excel opening a CSV, Chrome spawning a tab process, a build script spawning `cmd`). 3. Run `detect.children.jky` via a job. 4. Compare findings against Sysmon EventID 1 ground truth. |
| **Expected** | 50/50 simulated chains detected; benign controls flagged ≤ 2/50 (target: 0). |
| **Success metrics** | Recall = 100%, precision ≥ 96%, job wall time < 15 s, agent CPU < 25% (enforced), zero crashes. |
| **Anti-goal** | Any detection requiring elevated privilege beyond what the service account has — visibility gaps must be reported, not hidden. |

### HOST-002 — RWX / unbacked memory triage

| Field | Value |
|---|---|
| **Objective** | Detect a private RWX unbacked region created by a process we control, and prove JOCKY does not create one itself. |
| **Setup** | LAB-WIN-01; `sim-rwx-inject.exe` (our binary, allocates RWX in its own process); agent running normally. |
| **Steps** | 1. Baseline: run `triage_memory` with no simulation → expect 0 findings and expect JOCKY's own process to show **no** RWX region (validates W^X loader design). 2. Start `sim-rwx-inject`, run `triage_memory` → expect exactly 1 finding for that PID. 3. Repeat 20×. |
| **Expected** | Baseline 0 findings; 20/20 detections; JOCKY's own process never appears as RWX. |
| **Success metrics** | Recall 100%, FPR 0 on the baseline, and the loader's own memory map passes an RWX self-audit (`agent/selfaudit`) — this is the evidence that our in-memory design is not itself the thing we detect. |

### HOST-003 — Execution-artifact timeline (MFT/Prefetch/AmCache/ShimCache)

| Field | Value |
|---|---|
| **Objective** | Reconstruct a ground-truth execution timeline from raw artifacts and verify JOCKY's parse matches the OS's own view. |
| **Setup** | LAB-WIN-01, freshly snapshotted. Install a known set of 30 portable tools (Sysinternals suite subset, 7-Zip, Notepad++, curl, jq) at known times with recorded timestamps. |
| **Steps** | 1. Record ground truth (install times, run counts) in a table. 2. Run `dump_mft` + `parse_prefetch` + `parse_amcache` + `collect_shimcache` in one job. 3. Diff against ground truth. |
| **Expected** | ≥ 95% of executions recovered with timestamps within ±2 s; Prefetch run counts exact for the tools executed a known number of times. |
| **Success metrics** | Recall ≥ 95%, timestamp error ≤ 2 s, MFT parse throughput ≥ 5 MB/s, no modification of any parsed artifact (verified by re-hashing `$MFT`/Prefetch before and after). |
| **Anti-goal** | Must never write to the live `SYSTEM` hive — AmCache is copied and opened read-only (verified by hive mtime unchanged). |

### HOST-004 — Linux eBPF visibility

| Field | Value |
|---|---|
| **Objective** | Verify `exec_monitor`, `net_connect`, and `file_open` eBPF programs capture a full lineage and network picture with bounded overhead. |
| **Setup** | LAB-LNX-01 (kernel 6.8, BPF LSM enabled), agent with `CAP_BPF+CAP_PERFMON`. |
| **Steps** | 1. Baseline overhead: run `fio` + a 10,000-exec loop, measure without and with BPF attached (`perf stat`, wall time). 2. Run a synthetic workload: 500 processes across 5 levels of nesting, 200 outbound connections to `10.20.3.32`, 2,000 file opens in `/tmp`. 3. Compare with `auditd`-recorded ground truth. 4. Repeat on LAB-LNX-02 with BPF **disabled** to measure the auditd fallback. |
| **Expected** | Lineage complete for 500/500 processes; connections complete; file events ≥ 99%; overhead < 2% wall time. |
| **Success metrics** | Event loss < 0.5% (and `lost_events` counter must be exposed — loss is never silent), overhead < 2%, fallback mode correctly reports `visibility: {bpf:false, auditd:true}`. |

### HOST-005 — Persistence-artifact coverage

| Field | Value |
|---|---|
| **Objective** | Detect all 6 persistence simulations on Windows and Linux. |
| **Setup** | Snapshot-restored LAB-WIN-01 and LAB-LNX-01. |
| **Steps** | 1. Run each `sim-*-persist` one at a time, running the relevant JOCKY collector after each. 2. After all 6, run a single combined job. 3. Verify the snapshot restore removed all artifacts before the next case. |
| **Expected** | 6/6 detected with the correct ATT&CK ID; combined job detects all 6 in one pass. |
| **Success metrics** | Recall 100%, each finding includes the artifact's location and a raw-evidence reference. |

---

## 3. Network forensics tests

### NET-001 — Beacon detection

| Field | Value |
|---|---|
| **Objective** | Detect periodic C2-like traffic and quantify the false-positive rate against realistic benign traffic. |
| **Setup** | LAB-LNX-01 runs `sim-beacon` (HTTPS to `10.20.3.32:443`, interval 30 s ± 15% jitter, 512 B payloads). Benign background traffic generated by a browser-like load generator hitting an internal mirror every 60 s, plus NTP (64 s) and a chatty monitoring agent (10 s heartbeats, but with high jitter and variable payloads). |
| **Steps** | 1. Capture 60 min of mixed traffic. 2. Run `beacon_candidates` with `window=60m`. 3. Measure recall against the known beacon PID and precision against the benign PIDs. 4. Sweep the `regularity` threshold from 0.6 to 0.95 and plot the ROC curve. |
| **Expected** | At `regularity > 0.80` and `n ≥ 20`: recall 100% for the beacon; the monitoring agent should be *near* the threshold (it is deliberately adversarial-benign) and may be flagged as `low` severity — that is acceptable and must be reported as a documented limitation, not hidden. |
| **Success metrics** | Recall 100%; precision ≥ 90% at the chosen threshold; the ROC curve is included in the SIH submission with the threshold choice justified. |
| **Honesty requirement** | If the monitoring agent is flagged, the submission says so explicitly and explains why (regular heartbeats are genuinely indistinguishable from beaconing without payload inspection) and what would disambiguate it (TLS fingerprint, payload entropy, destination reputation). |

### NET-002 — DNS tunneling / high-entropy queries

| Field | Value |
|---|---|
| **Objective** | Detect `sim-dns-tunnel` (queries like `<base32-of-random-20-bytes>.tun.lab`) among normal DNS traffic. |
| **Setup** | LAB-LNX-01; a lab DNS resolver at `10.20.0.1` with query logging as ground truth. |
| **Steps** | 1. Generate 30 min of mixed DNS (normal browsing to internal services + the tunnel). 2. Run `collect_dns_cache` + an entropy/length analysis job. 3. Compare with the resolver log. |
| **Expected** | All tunnel queries detected; entropy threshold ≥ 3.5 bits/char on the leftmost label; benign internal hostnames (e.g. `dc01.lab.local`) not flagged. |
| **Success metrics** | Recall ≥ 98% (some queries may be cached/missed — measure and report), FPR ≤ 1%. |

### NET-003 — PID↔socket correlation and rogue-listener detection

| Field | Value |
|---|---|
| **Objective** | Correlate sockets to processes accurately and detect an unexpected listener. |
| **Setup** | LAB-LNX-01; start a listener on `0.0.0.0:4444` from a script we own (bound only inside the VNet). |
| **Steps** | 1. Run `enumerate_sockets` + `correlate_pid_socket`. 2. Verify the listener appears with the correct PID and a `listened` edge to the process. 3. Also verify TCP-table/`/proc/net` disagreement handling when a socket is closed mid-enumeration. |
| **Expected** | Listener detected with correct PID; correlation accuracy ≥ 99% on a 500-socket synthetic set; race conditions produce a warning, not a wrong attribution. |
| **Success metrics** | Accuracy ≥ 99%, zero misattributions (a wrong PID is worse than a missing one in DFIR). |

---

## 4. Database security tests (own Supabase only)

### DB-001 — Credential-strength testing module against our own Supabase project

| Field | Value |
|---|---|
| **Objective** | Implement and validate a JOCKY password-security testing module that measures credential-guessing performance **against our own Supabase project**, to (a) validate the module's throughput math and (b) validate JOCKY's ability to detect the *resulting* authentication anomaly from logs. |
| **Setup** | Self-hosted Supabase at `10.20.3.33` (Postgres 15 + GoTrue). Two projects: `jocky-test-weak` (seeded with 5,000 test accounts whose passwords are drawn from a documented weak-password corpus we generated) and `jocky-test-strong` (5,000 accounts with random 20-char passwords). All accounts are `test+<n>@lab.local` — no real users, no real data. Rate limiting explicitly configured and *enabled* (this is part of what we are measuring). |
| **Steps** | 1. Run the JOCKY `credential_strength_probe` module against `jocky-test-weak` at a fixed, self-imposed rate limit of 5 attempts/s/account, max 100 attempts/account, with a hard global stop at 50,000 attempts. 2. Record: attempts, successes, time-to-first-success, time-to-80%-of-weak-passwords. 3. Run the same against `jocky-test-strong`; expect ~0 successes. 4. Run `collect_auth_logs`/GoTrue audit log collection and verify JOCKY detects the probe as an authentication anomaly (high failed-auth rate, distributed source, consistent timing). 5. Confirm the module **refuses** to run against any target not in the consent token scope (test by pointing it at a hostname not in scope → expect `ScopeViolation` and a signed journal entry). |
| **Expected** | All weak-corpus passwords recovered within budget; zero successes on the strong set; the probe itself detected as an anomaly by our own detection job. |
| **Success metrics** | Weak-set recovery ≥ 95% (the corpus has known entropy, so this is checkable), strong-set recovery = 0, anomaly detection fires within 60 s of probe start, scope-violation refusal is 100%. |
| **Ethical framing (goes in the submission verbatim)** | *"This module exists to let a defender measure whether their own credential policy is adequate, and to validate that our detection catches brute-force behavior. It targets only a Supabase project we created, with data we generated, on a private network, with self-imposed rate limits. It will refuse to run outside a consent-token scope."* |

### DB-002 — Supabase RLS / API misconfiguration detection

| Field | Value |
|---|---|
| **Objective** | Detect exposed tables and missing Row-Level Security in our own project. |
| **Setup** | `jocky-test-rls`: create 3 tables — one with RLS enabled + policy, one with RLS disabled, one with RLS enabled but a permissive `USING (true)` policy — plus an anon key. |
| **Steps** | 1. Run a JOCKY job using the Supabase REST API (PostgREST) with the anon key against our own project. 2. Enumerate tables reachable and rows returned. 3. Emit findings for tables reachable without authentication and for permissive policies. |
| **Expected** | Both misconfigured tables flagged; the correctly-configured one not flagged. |
| **Success metrics** | Recall 2/2, FPR 0/1, and the finding includes the exact PostgREST URL and the policy text so a developer can fix it. |

### DB-003 — Postgres authentication & connection-log forensics

| Field | Value |
|---|---|
| **Objective** | Validate log-based detection of anomalous DB access patterns on our own instance. |
| **Setup** | `jocky-test-weak` Postgres with `log_connections=on`, `log_disconnections=on`, `log_statement=ddl`, `pgaudit` enabled. |
| **Steps** | 1. Generate three patterns: normal app traffic, a slow scan from a new IP, and a rapid-fire connection storm. 2. Collect logs and run a correlation rule. |
| **Expected** | The storm and the new-IP scan flagged; normal traffic not flagged. |
| **Success metrics** | Recall 2/2, FPR 0 on the normal pattern, detection latency < 30 s. |

---

## 5. Resilience tests (the core SIH26148 question)

### RES-001 — Collection while a commercial AV/EDR is active

| Field | Value |
|---|---|
| **Objective** | Measure, honestly, whether JOCKY agents can collect forensics when a commercial security product is installed and enforcing. |
| **Setup** | Snapshot-restored LAB-WIN-01 with **Microsoft Defender for Endpoint** (or a licensed trial of a second product) in full real-time-protection mode; LAB-LNX-01 with a Linux EDR agent. The product's console is accessible to us (we own the tenant). |
| **Steps** | 1. Deploy the JOCKY agent **without** any allowlisting, and run the full triage job 10×. 2. Record: did the agent install? did the module load? were files quarantined? which API calls were blocked? what does the EDR console show? 3. Then apply the **documented interop path**: add the agent's signed hash + the JOCKY ETW provider to the EDR's allowlist (this is the intended, honest deployment model for cooperating defenders), and run 10× again. 4. Repeat the whole thing with 3 different diversification variants to test whether variant selection changes the outcome. |
| **Expected** | **Honest expectation: in step 1, the agent may be blocked or partially blocked.** That is a legitimate and reportable finding. Step 3 should yield 10/10 successful collections with zero blocked API calls. |
| **Success metrics** | Report per variant: install success, module load success, collector success rate, API calls blocked, quarantine events, EDR console alerts. The metric that matters is **the delta between no-allowlist and allowlisted**, and whether diversified variants behave differently from each other. |
| **Anti-goal** | We do **not** tune JOCKY to evade the EDR in this test. If a variant happens to be blocked and another is not, we report the observation and explain that the correct remediation is allowlisting the signed, attested binary — not relying on blind spots. |

### RES-002 — Collection after the security stack is disabled (the actual IR scenario)

| Field | Value |
|---|---|
| **Objective** | Reproduce the scenario JOCKY exists for: the adversary has killed the security stack; can JOCKY still collect, and does it correctly report its own visibility limits? |
| **Setup** | Snapshot-restored LAB-WIN-01. We disable Defender real-time protection, stop the Sysmon service, and clear a **synthetic** event log channel (`JOCKY-Test` — never Security/System). On LAB-LNX-01, stop `auditd` and set `kernel.unprivileged_bpf_disabled=2` to simulate BPF being unavailable. |
| **Steps** | 1. Record the post-disable state. 2. Run the full triage job. 3. Inspect: which collectors still worked, which reported `degraded`, and whether the agent's `collector_health` correctly names the reason. 4. Verify `verify_log_continuity` flags the log gap and `inventory_security_products` reports the missing EDR/Sysmon as an event. |
| **Expected** | Core collection (processes, memory regions, MFT, network via TCP-table fallback) continues. ETW-dependent collectors report `degraded` with a reason. Log-gap detection fires. The **missing security product itself becomes a finding** (T1562). |
| **Success metrics** | Collector success matrix (worked/degraded/failed) with reasons; the T1562 finding is generated; no false claim of `trust: full` when a collector was degraded — verified by asserting `trust` fields against the known-disabled state. |
| **This is the headline demo for SIH.** |

### RES-003 — Diversification efficacy under hash-based blocking

| Field | Value |
|---|---|
| **Objective** | Quantify whether N diversified variants actually defeat naive hash blocking, using only our own tooling. |
| **Setup** | Our own lab "blocker" — a small Windows filter driver **we wrote** (test-signed, LAB-WIN-01 only, snapshot-restored) or an equivalent user-mode minifilter/hash-checking service that blocks execution of any image whose SHA-256 is on a list. We populate the list with variant 0's hash, then attempt to run variants 1–7. |
| **Steps** | 1. Confirm variant 0 is blocked. 2. Run variants 1–7 → expect all to run (they have distinct hashes by construction). 3. Add all 8 hashes → expect all blocked. 4. Measure the diversity metrics (CFG, import, entropy) against the observed blocking behavior. |
| **Expected** | 7/7 variants bypass a single-hash block; 0/8 bypass a full-hash block. |
| **Success metrics** | The measured relationship between the diversity floor metrics and blocking behavior, presented as a table. |
| **Framing (required in the writeup)** | *"This demonstrates that signature-only blocking is brittle against structural diversity. The correct defensive response — which we also implement — is attestation-based trust: allow by signed manifest and transparency-log proof, not by hash. JOCKY ships both the diversity and the attestation precisely so that defenders can move to the stronger model."* This test is about proving a defensive point, using our own blocker on our own VM. |

### RES-004 — Long-run stability & resource bounds

| Field | Value |
|---|---|
| **Objective** | Prove the agent is production-stable and never degrades the host. |
| **Setup** | LAB-LNX-01 and LAB-WIN-01 running the agent for 7 days with a job every 30 min (mixed scripts). |
| **Steps** | Continuous monitoring of agent RSS, CPU, handles/FDs, thread count, spool size; heartbeat continuity; journal chain verification daily. |
| **Expected** | No memory growth beyond a 10% band after 24 h; CPU p99 < 5% idle; zero unexplained restarts; journal chain intact for the whole run; host baseline performance (measured with a reference benchmark before/after) within 1%. |
| **Success metrics** | All of the above, with the raw time series included in the submission. |

### RES-005 — Manager outage resilience

| Field | Value |
|---|---|
| **Objective** | The agent must degrade gracefully and never lose evidence. |
| **Setup** | 10 agents, manager stopped for 2 h, then restarted. |
| **Steps** | 1. Stop the manager. 2. Dispatch jobs from the local journal queue (agent-side queued jobs). 3. Restart. 4. Verify all queued evidence uploads. |
| **Expected** | Agents back off (jittered), spool evidence to disk within `max_spool_mb`, and upload everything on reconnect; no duplicate findings (dedupe by `dedupe_hash`); heartbeat gap visible in the dashboard as an alert. |
| **Success metrics** | 100% evidence recovery, 0 duplicates, spool never exceeds the cap, recovery within 5 min of manager restart. |

---

## 6. Test-result reporting format (used in the SIH submission)

For every test:

```markdown
### <TEST_ID> — <title>
**Result:** PASS / PARTIAL / FAIL
**Measured:** <the numbers, with units and sample sizes>
**Method:** <one paragraph, reproducible>
**Raw data:** <path in the repo, e.g. results/HOST-001/run-2026-09-24.csv>
**Deviations from expectation:** <explicit list; "none" only if truly none>
**What this does NOT prove:** <explicit limits, e.g. "does not prove detection on a host with a kernel-level rootkit">
```

**Rule:** every test report ends with a "What this does NOT prove" section. This is a deliberate anti-overclaiming mechanism and is one of the strongest signals of engineering maturity to a technical judging panel.

---

## 7. Demo script for SIH (90 seconds, live, on our VMs)

1. Dashboard open: 4 lab agents healthy, variant indices visible (0–3).
2. Terminal on LAB-WIN-01: run `sim-runkey-persist` + `sim-beacon` + disable Defender (all our own scripts, on our own VM).
3. Dashboard: agent reports `collector_health: {etw: degraded}` and a T1562 finding appears within 10 s.
4. Analyst creates a job: `detect.beacon` against LAB-WIN-01 + LAB-LNX-01, scope shown, ticket `IR-DEMO-01`.
5. Job runs; findings stream in over WSS; the beacon finding appears with the interval statistics and the PID/socket graph.
6. Click the finding → evidence inspector → show `trust: degraded` badge and the reason → show the bundle object key and byte range → show the transparency-log proof for the module that produced it.
7. Switch to `/scripts`: show 8 variants of the same module with different hashes, the same `semantics_hash`, the diversity report, and `jocky-verify` passing on a downloaded `.jkm`.
8. Close on the audit page: the full chain of who ran what, when, on which agent, with what result, and the chain-integrity indicator green.