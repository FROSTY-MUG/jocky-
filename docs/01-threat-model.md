# 01 — Threat Model

Method: STRIDE per component + MITRE ATT&CK mapping for the *adversary we are investigating* (not for us). Two adversary classes matter:

- **A1 — The host adversary.** Has (or had) code execution on the endpoint. Killed EDR, unloaded drivers, disabled auditd, cleared logs, uses LOTL binaries. Goal: prevent the responder from seeing what happened.
- **A2 — The network adversary.** Can observe or manipulate traffic between agents and the manager (rogue DNS, TLS interception attempt, CDN abuse, replay).
- **A3 — The insider/analyst abuser.** Authorized user who exceeds scope: reads evidence they have no ticket for, retargets a scan, exfiltrates bundles.

JOCKY's threat model is dominated by A1 (resilience) and A3 (misuse prevention). A2 is handled by standard PKI discipline.

---

## 1. Asset inventory

| Asset | Where | Sensitivity | Primary control |
|---|---|---|---|
| Consent tokens | Manager issues, agent holds in memory | Critical — a forged token = unauthorized collection | Ed25519 signatures, short TTL (≤ 15 min), `max_ops` counter, single-agent binding |
| Build signing key | HSM / cloud KMS (non-exportable) | Critical | KMS-backed sign API, key never in CI runner memory, dual-control for key use |
| Transparency log | Append-only, mirrored | High | Merkle inclusion proofs, periodic signed checkpoints, 2 independent mirrors |
| Forensic bundles | S3/R2, SSE-KMS, per-team prefix | Critical (contains host memory/registry data) | SSE-KMS, bucket policy denies non-mTLS/non-role access, object lock for retention |
| Postgres | Private subnet | Critical | TLS, IAM auth via RDS Proxy/pgBouncer+SCRAM, per-role grants, row-level security for team scoping |
| Audit log | Postgres append-only table + S3 export | Critical | Hash-chain (`prev_hash`), daily Merkle root export to immutable storage |
| Agent private key | TPM/CNG (Win), TPM or `0600` file (Linux) | Critical | Non-exportable where possible; key rotation on re-enrollment |
| Dashboard session | Browser | High | httpOnly+Secure+SameSite=Strict cookies, 30 min idle timeout, step-up MFA for destructive actions |

---

## 2. STRIDE per component

### 2.1 JOCKY compiler service

| Threat | Scenario | Control |
|---|---|---|
| **S**poofing | Attacker submits a build that claims to be from team X | Build requests authenticated with CI OIDC identity (`id-token: write`), repo+ref pinned in the signed build record |
| **T**ampering | Malicious PR modifies a diversification pass to inject code | Passes are `unsafe`-free where possible; golden-output snapshot tests; 2-person review; SBOM + reproducible-build check (`jockyc --deterministic --seed S` must produce byte-identical output on 2 runners) |
| **R**epudiation | "Nobody built that variant" | Every build writes a transparency-log leaf containing commit SHA, seed, variant hash, signer identity |
| **I**nfo disclosure | Compiler leaks a script's contents via crash dump | Compiler runs in a container with no egress; crash handler redacts source; no telemetry upload |
| **D**oS | Huge source file → OOM | `jockyc` enforces source size, AST node, and pass-iteration limits; CI job timeout 10 min |
| **E**levation | Compiler runs as root in CI | Non-root container, read-only rootfs, no host mounts, `--cap-drop=ALL` |

### 2.2 Agent runtime

| Threat | Scenario | Control |
|---|---|---|
| **S**poofing | Rogue manager endpoint (DNS hijack / hosts-file tamper) feeds a job | Certificate pinning (SPKI pin of manager CA) + job JWT `iss`/`aud` checks + consent token required independently of the transport |
| **T**ampering | A1 patches the agent's memory to skip the consent check | Consent check is the *first* instruction path after verification; agent self-hashes `.text` at startup and re-measures before each module load (anti-tamper, not anti-root — documented honestly); on Windows use `WinVerifyTrust` + `NtQueryVirtualMemory(MEMORY_INFORMATION)` comparison. Residual risk accepted: a kernel-level A1 can defeat this. **We do not claim otherwise.** |
| **R**epudiation | Agent claims it never ran a job | Agent writes a local signed job journal (`%ProgramData%\JOCKY\journal\*.log`, Ed25519-signed, hash-chained); manager's job record must match on next heartbeat, mismatch raises an alert |
| **I**nfo disclosure | Bundle contains PII/credentials from the host | Collectors apply redaction policy before upload (configurable per job: `redact: [credentials, pii]`); bundles encrypted with a per-job envelope key; key is destroyed at retention expiry |
| **D**oS | A1 floods the agent with fake jobs | Job JWT verification is cheap and rate-limited (token-bucket, 10/s); unauthenticated requests dropped before parsing |
| **E**levation | A1 tricks the agent into loading an unsigned module | Module loader requires manifest + signature + tlog proof + consent, in that order, and refuses `RWX` mappings (W^X: map `RW`, copy, then `RX` via `mprotect`/`NtProtectVirtualMemory`) |

### 2.3 Manager & cloud relay

| Threat | Scenario | Control |
|---|---|---|
| **S**poofing | Stolen agent cert used from another host | Cert bound to `agent_id` in DB + enrollment nonce + optional TPM attestation claim in JWT; anomaly detection on IP/ASN change → auto-quarantine |
| **T**ampering | Bundle modified in S3 | Object Lock (governance mode, 90 d), SSE-KMS, agent-side Ed25519 signature over the bundle digest verified at ingest, CloudTrail/R2 audit logs |
| **R**epudiation | Admin denies issuing a wide-scope consent token | All token issuance is an audit event with the requesting principal + reason ticket; tokens stored (hash only) with issuance metadata |
| **I**nfo disclosure | Presigned URL leaked → bundle read | Presigned URLs TTL ≤ 10 min, single-use by `x-amz-server-side-encryption-customer-key` binding, bucket blocks public access, WAF rules on `*.jocky.internal` |
| **D**oS | Agent fleet stampede after a network partition | Jittered reconnect backoff (base 5 s, full jitter, cap 5 min), Redis-based per-agent concurrency limit, manager sheds load with `429 + Retry-After` |
| **E**levation | Analyst escalates to admin via IDOR on `/v1/jobs/{id}` | Object-level authz on every route (Casbin policy + `scope_team` check), integration tests that assert 403 for cross-team IDs |

### 2.4 Dashboard

| Threat | Scenario | Control |
|---|---|---|
| **S**poofing | Phishing clone of the dashboard | WebAuthn/passkeys preferred, IdP-enforced domain, HSTS preload, strict CSP with nonces, `frame-ancestors 'none'` |
| **T**ampering | XSS in a finding renderer → session theft | React + strict CSP, no `dangerouslySetInnerHTML` (lint rule, CI-enforced), all evidence text rendered as text nodes, `Trusted Types` policy |
| **I**nfo disclosure | Browser leaks analyst IP via WebRTC/STUN | `RTCPeerConnection` blocked by CSP `connect-src` allowlist, `Permissions-Policy: camera=(), microphone=(), geolocation=()` and an app-level monkey-patch that throws on `RTCPeerConnection` construction (see `docs/06`) |
| **E**levation | CSRF on job creation | SameSite=Strict + double-submit token + `Origin` check; all mutations are `POST` with `Idempotency-Key` |

---

## 3. Abuse cases and their controls (A3 — insider)

| Abuse case | Detection | Prevention |
|---|---|---|
| Analyst runs a scan on a host outside their ticket's scope | Consent token scope is validated server-side against the analyst's ticket ID at issuance; agent re-validates | Scope fencing in token + collector |
| Analyst downloads a bundle and shares it externally | Egress DLP on analyst VPN, watermarking (bundle contains `requested_by` + ticket in a signed header) | Per-download audit + anomaly alert on volume |
| Analyst repurposes JOCKY primitives for offensive use | Primitive denylist is compile-time; adding a primitive requires architect review; CI runs a "denylist conformance" test suite | Language design + review gate |
| Admin mints a token for a host with no incident | Alert on `consent_issued` where `ticket_id` is missing or not in the incident system | Hard requirement: ticket ID must resolve via incident-system API |
| Red-team exercises JOCKY against a production host without a lab flag | `JOCKY_ENV` must be `lab` for advanced techniques; the build embeds an environment marker and the manager refuses to issue tokens to `lab`-marked builds in `prod` | Environment marker in manifest + manager policy |

---

## 4. ATT&CK mapping (what JOCKY detects, and which JOCKY collector covers it)

| Technique | ID | JOCKY detection source |
|---|---|---|
| Process Injection | T1055 | `triage_memory()` — RWX/unbacked regions, thread start addresses outside image bounds |
| Create or Modify System Process | T1543 | `collect_services()` (Win), `collect_systemd()` (Linux) |
| Registry Run Keys | T1547.001 | `collect_run_keys()` |
| Scheduled Task/Job | T1053 | `collect_scheduled_tasks()` / `collect_cron()` |
| Ingress Tool Transfer | T1105 | `trace_network_flows()` + `collect_dns_cache()` |
| Application Layer Protocol (C2) | T1071 | `detect_beaconing()` — inter-arrival jitter analysis |
| Obfuscated Files or Information | T1027 | `scan_processes()` image-path/entropy heuristics |
| Indicator Removal: Clear Logs | T1070.001 | `collect_evtx()` gaps + `verify_log_continuity()` |
| Impair Defenses: Disable Tools | T1562 | `inventory_security_products()` — detects EDR service/driver removal as an *event to report* |
| Exploitation for Privilege Escalation | T1068 | `collect_drivers()` + vulnerable-driver hash/signature matching |
| Boot or Logon Autostart | T1547 | Prefetch/AmCache run-count timeline reconstruction |
| Masquerading | T1036 | Parent-child lineage + signature mismatch checks |

---

## 5. Explicit non-goals

Stated so reviewers do not have to guess:

1. JOCKY does **not** evade detection by *third-party* systems as a goal; it is designed to remain **functional** under signature-only blocking, and to interoperate with cooperating EDR via a documented allowlisting handshake.
2. JOCKY does **not** persist on a host, does **not** modify system state, and does **not** perform any write operation outside its own working directory and the manager connection.
3. JOCKY does **not** include credential extraction, exploitation, lateral movement, or C2 beaconing.
4. JOCKY does **not** ship an unsigned kernel driver. The kernel-visibility demo uses either a test-signed minimal driver on a lab VM with testsigning enabled, or an eBPF/ETW-only path. See `docs/03` §5.
5. JOCKY does **not** perform domain fronting. It is documented as a *threat model* item only (`docs/05` §7).
6. No testing against third-party systems, ever. Every test in `docs/08` names the machine we own and the authorization reference.