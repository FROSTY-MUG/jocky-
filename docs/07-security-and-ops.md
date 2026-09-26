# 07 — Security & Operations

---

## 1. Network hardening

### 1.1 VPN-only management access

| Control | Implementation |
|---|---|
| Transport | WireGuard (kernel module on Linux, WireGuardNT on Windows). No OpenVPN, no IPsec complexity for the analyst path. |
| Full tunnel | Server peer config pushes `AllowedIPs = 0.0.0.0/0, ::/0`; split tunneling is **disabled** for analyst peers (a split tunnel is a leak by definition) |
| Kill switch (Linux) | `wg-quick` with `Table = off` + explicit nftables ruleset; a systemd unit `wg-killswitch.service` that applies `policy drop` on the physical interface's output except to the WG endpoint and the tunnel DNS |
| Kill switch (Windows) | WireGuard for Windows "Block untunneled traffic (kill-switch)" enabled, enforced via MDM/Intune policy so it cannot be turned off locally; WFP filters audited with `netsh wfp show filters` in the posture check |
| DNS leak protection | DNS resolved **only** by the tunnel resolver (`10.66.0.1`), which itself forwards over DoT to a pinned resolver. The client sets `DNS = 10.66.0.1` and a `PostUp` rule that drops UDP/TCP 53 on all non-tunnel interfaces. Verified by `dnsleaktest.com` (extended) and by asserting `resolvectl status` shows only the tunnel interface's DNS. |
| Egress restriction on analyst machines | Only 443/tcp to the VPN endpoint before the tunnel is up; after the tunnel, only the VPN subnet + the manager's Cloudflare IPs |
| Enforcement of VPN-only access | Cloudflare Access policy requires `ip.src ∈ {VPN egress ranges}` **and** an IdP group **and** device posture; the ALB additionally rejects anything not from Cloudflare's ranges |
| Posture self-check | `GET /v1/session/posture` returns `{via_vpn: true, egress_ip: "198.51.100.7", asn: 64500, device_attested: true}`. The dashboard refuses to load evidence views when `via_vpn` is false. |

### 1.2 Server egress filtering

- Management subnets have **no** route to the internet except through a NAT gateway with a security group allowing only: `443/tcp` to `*.amazonaws.com` endpoints via VPC endpoints (preferred, no NAT at all), `443/tcp` to Cloudflare's API for WAF log pull, and `443/tcp` to the IdP's JWKS endpoint. Everything else: `DROP` with logging.
- **VPC endpoints** are used for S3, KMS, SQS, SNS, Secrets Manager, ECR, CloudWatch Logs — so bundle/artifact traffic never traverses the internet.
- Egress logs are shipped to the SIEM; a weekly report lists every distinct destination and flags any new one.
- The manager containers run with `--read-only` rootfs, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a seccomp profile, and a non-root UID; no shell in the image (`distroless`/`scratch`).
- Kubernetes (if used) enforces default-deny `NetworkPolicy`, Pod Security Admission `restricted`, and no hostPath mounts.

### 1.3 WebRTC leak prevention

Fully specified in `docs/06` §4.2 with three independent layers (CSP `connect-src` allowlist, an app-level Proxy that throws on `RTCPeerConnection` construction, and a CI/CDP test that fails the build on any non-allowlisted connection attempt) plus a runtime self-test surfaced on `/settings/security`.

---

## 2. Application security

### 2.1 Dependency and supply-chain scanning

| Tool | Scope | Gate |
|---|---|---|
| `cargo-deny` | advisories, licenses, bans, duplicate versions | fail on any advisory with a fix available; fail on GPL/AGPL in shipped binaries |
| `cargo-audit` | RustSec | nightly, fail on `unsafe`-severity advisories |
| `npm audit --audit-level=high` | dashboard | fail on high/critical |
| `trivy fs --severity HIGH,CRITICAL` | containers + lockfiles | fail on high/critical with a fix |
| `syft` + CycloneDX | SBOM per release | published next to artifacts |
| `semgrep` (custom JOCKY rules) | Rust/C/C++/TS | fail on any match: unsafe FFI without a safety comment, `unwrap()` in the agent's parse paths, unbounded `read_to_end`, `mem::transmute` |
| `cargo-geiger` | unsafe census | fail if unsafe lines in `agent/` or `manager/` exceed the recorded ceiling |
| `zizmor` | GitHub Actions | fail on unpinned actions, `pull_request_target` misuse |
| `ossf/scorecard` | repo hygiene | weekly report, tracked over time |

### 2.2 Static analysis

- **Rust**: `clippy` with `-D warnings` plus a curated `clippy.toml` banning `unwrap`, `expect`, `panic!`, `indexing_slicing` in `agent/` and `manager/` (allowlisted with justification where truly needed). MIRI on the compiler's IR passes (`cargo +nightly miri test`) to catch UB in `unsafe` blocks.
- **C/C++**: `clang-tidy` (bugprone, cert, performance), `-Wall -Wextra -Werror`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fcf-protection=full`, ASan/UBSan builds in CI, MSVC `/guard:cf /GS /sdl`.
- **TypeScript**: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, ESLint with `@typescript-eslint/recommended-type-checked` + `react-hooks` + `jsx-a11y`.

### 2.3 Fuzzing plan

| Target | Harness | Corpus | Cadence |
|---|---|---|---|
| `.jkm` container parser | `cargo-fuzz` (`fuzz_container`) | 5,000 seeds from real builds + mutations | 24 h nightly, OSS-Fuzz-style continuous on a dedicated runner |
| Canonical CBOR manifest parser | `cargo-fuzz` | manifest corpus + structured mutations | nightly |
| PE/ELF in-memory loader | `cargo-fuzz` (`fuzz_pe_map`, `fuzz_elf_map`) — fuzzes header parsing and relocation application against a mock allocator | malformed header corpus (mingw/llvm generated variants) | nightly |
| JOCKY frontend (lexer/parser/typechecker) | `cargo-fuzz` | all `.jky` in `corpus/` + grammar-aware generation | nightly |
| JOCKY bytecode VM | `cargo-fuzz` (`fuzz_vm`) | valid bytecode + byte mutations | nightly |
| MFT parser | `cargo-fuzz` with a synthetic `$MFT` generator | 200 real MFT excerpts from our lab VMs (with PII stripped) | nightly |
| Prefetch/AmCache/EVTX parsers | `cargo-fuzz` | real samples from our lab VMs | nightly |
| Correlation-rule DSL | `cargo-fuzz` | rule corpus | weekly |
| Manager HTTP/gRPC handlers | `cargo-fuzz` + `libfuzzer` on the axum router via `tower::ServiceExt::oneshot` | recorded request corpus | nightly |
| eBPF programs | `bpf-verifier` in a loop with `BPF_PROG_TEST_RUN` and synthesized packet/trace contexts | scenario corpus | per PR (fast subset) + nightly |

Every crash becomes a regression test in `tests/regressions/` with the minimized input committed and a ticket referencing it. **A fuzzer finding is never closed without a regression test.**

### 2.4 Secrets management

- **HashiCorp Vault** (or AWS Secrets Manager + KMS if Vault is not available) is the only source of runtime secrets. No secrets in env vars committed anywhere; CI reads from Vault via OIDC.
- Agent-side: no long-lived secrets at all — the agent's identity is a certificate + an Ed25519 key in TPM/CNG. The manager endpoint and CA pin are in the config file (not secret).
- Signing keys: KMS/Vault-transit only, non-exportable, with the policy shown in `docs/04` §4.
- Rotation schedule: agent certs 90 d, build key 90 d, manager consent key 180 d, DB credentials 30 d (automatic via RDS IAM auth where possible), Vault root tokens are break-glass only (sealed in two physically separate safes, dual-control).
- Secret scanning: `gitleaks` pre-commit hook + GitHub secret scanning + a nightly full-history scan. A leaked secret triggers the rotation runbook within 1 hour (see §5).

### 2.5 Cryptography inventory (no home-rolled primitives)

| Purpose | Algorithm | Library |
|---|---|---|
| Hashing / integrity | BLAKE3 | `blake3` (Rust), `blake3` C |
| Signatures | Ed25519 | `ed25519-dalek` (Rust), AWS-LC (C), `@noble/ed25519` (TS verification only) |
| Key agreement (bundle envelope) | X25519 + HKDF-SHA256 | `x25519-dalek`, `hkdf` |
| AEAD (bundle at rest) | AES-256-GCM (AWS SSE-KMS) | KMS |
| AEAD (module string encryption) | ChaCha20-Poly1305 | `chacha20poly1305` |
| TLS | TLS 1.3 only, `X25519MLKEM768` (hybrid PQ) preferred, `X25519` fallback | `rustls` / OpenSSL 3.x |
| Password/key hashing | Argon2id (m=64 MiB, t=3, p=4) | `argon2` |
| Merkle tree | SHA-256, RFC 6962 domain separation | `sha2` |
| Random | OS CSPRNG only (`getrandom` / `BCryptGenRandom`) | — |

**Rule:** no custom cryptographic constructions. Any deviation requires a written cryptographic review in the PR.

---

## 3. Operations

### 3.1 Monitoring & alerting

Metric list and alert thresholds: `docs/05` §8. Additional operational detail:

- **Golden signals** per service: latency (p50/p95/p99), traffic (RPS), errors (rate by class), saturation (CPU, memory, DB connections, Redis ops).
- **SLOs**: manager API availability 99.9%/month (error budget 43 min); job dispatch latency p95 < 10 s from `scheduled_at`; ingest latency p95 < 60 s from upload complete; agent heartbeat freshness p99 < 90 s.
- Alert routing: PagerDuty for page-level, Slack `#jocky-ops` for warnings, `#jocky-security` for security events (separate channel, separate on-call rotation — a security alert must never be lost in availability noise).
- Runbooks live in `docs/runbooks/` (one file per alert): symptom, impact, diagnosis commands, mitigation, escalation, post-incident actions.

### 3.2 Logging

- Structured JSON, one line per event, with `trace_id`/`span_id` for cross-service correlation (W3C Trace Context).
- Retention: application logs 90 days hot (CloudWatch) → 1 year warm (S3 IA); **audit logs 7 years with Object Lock**; agent journals retained on the host for 30 days (configurable) and mirrored to the manager.
- Redaction layer as described in `docs/05` §8; a CI test asserts that a synthetic token, password, and client cert never appear in log output.
- Tamper resistance: logs shipped to a **separate AWS account** (log archive account) with write-only credentials from the prod account; the archive account has no path back.

### 3.3 Backup & disaster recovery

| Component | Backup | RPO | RTO | Restore drill |
|---|---|---|---|---|
| Postgres | Automated snapshots every 15 min + WAL archiving to S3 (PITR); Multi-AZ standby | 5 min | 30 min | Monthly: restore to a scratch instance, run `jocky-cli db verify-integrity` (checks audit chain, FK consistency, row counts) |
| Redis | AOF `everysec` + hourly RDB to S3 | 1 h (queues are re-derivable) | 15 min | Quarterly |
| S3 bundles/artifacts | Cross-region replication + versioning + Object Lock | ~15 min | immediate (failover to replica) | Quarterly read test from the replica |
| Transparency log | 2 independent mirrors (S3 + R2) | 0 (append-only, replicated on write) | immediate | Monthly: verify a random historical leaf against both mirrors |
| Vault / KMS keys | Vault raft snapshots hourly; KMS keys are region-scoped with a documented break-glass key in a second region | 1 h | 1 h | Semi-annual key-recovery tabletop |
| Agent identity | Re-enrollment is always possible with a fresh nonce | n/a | 15 min/fleet (scripted) | Annual |

**DR scenario tests** (documented, executed, timed):
1. Primary region loss → bring up the manager in the DR region from snapshots; agents reconnect to the DR endpoint (config supports two endpoints with failover order).
2. Postgres corruption → PITR to 1 minute before the corruption; verify audit chain continuity across the restore boundary (the chain must not break; if it does, the incident is treated as potential tampering and investigated).
3. Total loss of the build key → documented consequence: **no new builds can be signed**; existing agents continue running existing modules; recovery requires restoring the KMS key from the break-glass region or re-keying (which invalidates all outstanding tlog leaves — an explicit, rehearsed decision).

### 3.4 Incident response plan for the JOCKY platform itself

Trigger classes: (a) suspected compromise of the manager, (b) key compromise, (c) agent mass-quarantine, (d) audit-chain verification failure, (e) suspected insider misuse.

**Phase 0 — Detect & declare (≤ 15 min)**
- Any of the alerts in `docs/05` §8 marked "page". On-call declares an incident in the incident system, creates a `#jocky-inc-<id>` channel, assigns Incident Commander (IC), Ops Lead, Comms Lead, Scribe.

**Phase 1 — Contain (≤ 30 min)**
- **Kill switch**: `POST /v1/admin/halt` (two-person approval) → all token issuance stops, agents go heartbeat-only. This is the single most important control: it stops new collection immediately.
- Rotate the affected credential class (session signing key, manager root key, or DB credentials) — the runbook specifies exactly which rotation invalidates which capability.
- If the manager is suspected compromised: cut Cloudflare → origin (disable the route), revoke the ALB cert, and serve a static "maintenance" page; preserve the running containers for forensics (do **not** restart them; snapshot EBS volumes and capture memory of the manager processes with `gcore`).
- If an agent is suspected: `POST /v1/admin/agents/{id}/quarantine` + revoke its certificate (publish a new CRL version, which propagates on the next heartbeat).

**Phase 2 — Investigate (≤ 4 h for a preliminary report)**
- Evidence sources: CloudTrail, ALB access logs, Cloudflare logs, manager application logs, `audit_log` (with chain verification), Redis command log, VPC flow logs, container runtime logs, and the EBS snapshots.
- Key questions, in order: (1) Is the audit chain intact? (2) Which credentials were used, from where, and did the IP match the expected VPN egress? (3) Was any consent token issued without a valid ticket? (4) Was any bundle downloaded outside normal patterns? (5) Is there any tlog checkpoint that fails signature verification?

**Phase 3 — Eradicate & recover**
- Rebuild manager instances from a known-good image (immutable infrastructure — never patch in place during an incident).
- Re-issue agent certificates fleet-wide (scripted re-enrollment with fresh nonces distributed via the OOB channel).
- Re-sign all modules with a fresh build key if key compromise is confirmed; publish a tlog "key rotation" checkpoint; revoke all prior builds.
- Verify recovery with a full-system test job on a known-clean lab host.

**Phase 4 — Post-incident (≤ 5 business days)**
- Blameless postmortem with a timeline, contributing factors, and **dated** action items with owners.
- Update detection rules; add a regression test for the specific failure mode.
- If the incident involved evidence access, notify the affected incident's stakeholders in writing (transparency is a requirement of the consent model).

### 3.5 Change management

- All infrastructure changes via Terraform in a repo, plan-reviewed, with `terraform plan` output attached to the PR.
- All application changes via PR with required reviewers (2 for `agent/`, `compiler/`, `manager/authz/`; 1 elsewhere), CI green, and no `--force` merges.
- Database migrations via `sqlx migrate`, forward-only, with a documented rollback plan per migration; destructive migrations require a maintenance window and a verified backup.
- Production deploys only from `main` with a signed tag; the deploy job verifies the tag signature.

### 3.6 Capacity & cost notes (so the plan is realistic)

- 1,000 agents × 1 heartbeat/30 s = 33 rps sustained — trivially handled by 2 `manager-http` replicas.
- A typical job produces 2–20 MB compressed; 1,000 agents × 4 jobs/day = ~80 GB/day → ~24 TB/year in S3 Standard (~$550/mo) plus lifecycle transition to Glacier Instant Retrieval at 90 days (~$100/mo). Bundle retention defaults to 90 days hot, 1 year warm, then delete (configurable per team, and consent tokens encode the retention expectation).
- Postgres: artifacts/edges dominate. Partition `artifacts`/`edges` monthly and detach partitions past retention; `pg_partman` automates this. Estimated 500 GB/year at 1,000 agents.
- Redis: queues + windows only, 4 GB is ample; no evidence stored in Redis.
- CI: ~60 min per full build × ~20 builds/day on GitHub-hosted runners ≈ $400/mo including the Windows runners.