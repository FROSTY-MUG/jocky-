# JOCKY — Production Blueprint

**A programming language, compiler framework, agent runtime, and central management platform for authorized computer & network forensic analysis in environments where security tooling has been degraded, blinded, or disabled by an adversary.**

Problem statement: **SIH26148 (NTRO)** — *"Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions."*

---

## 0. Framing: this is a blue-team IR platform, not evasion malware

Read this section before any other. It is the load-bearing assumption of the whole design.

JOCKY is built for **incident responders who hold written authorization**. Its purpose is that when an adversary kills EDR, unloads minifilters, disables auditd, or blocks known agent hashes by signature, the responder can still **collect evidence**. That is a *resilience* requirement, not a *stealth* requirement.

| Problem statement wording | How JOCKY implements it (defensive) |
|---|---|
| "new programming language" | JOCKY: a DFIR-domain DSL with first-class forensic primitives, compiled by our own frontend + LLVM backend (`docs/02-language-and-compiler.md`). |
| "without triggering security solutions" | **Structural diversification so that legitimate, signed, attested forensic agents are not blocked by brittle hash/signature rules** — plus a documented interop layer that *declares* itself to cooperating EDR (AMSI/ETW-friendly, opt-in allowlisting). We never target third-party systems. |
| "commence forensic analysis" | Collection-only primitives. JOCKY has **no** exploitation, lateral movement, credential-dumping, or persistence primitives. See §0.2 for the enforced capability denylist. |
| "polymorphic CI/CD" | Multiple diversified builds per commit with **identical semantics**, each attested in a transparency log — the opposite of un-auditable malware polymorphism. |

### 0.1 Non-negotiable guardrails (enforced in code, not in prose)

1. **Consent tokens.** Every agent refuses to execute any JOCKY module without a valid, unexpired, Ed25519-signed consent token issued by the management plane, scoped to `(agent_id, scope, expiry, max_ops)`. Enforcement point: `agent/*/src/loader/consent.rs` — checked *after* signature verification and *before* the module is mapped. Failure = hard stop + signed local audit record.
2. **Attested builds only.** Every JOCKY binary embeds a CBOR manifest signed by the build key, chained into an append-only Merkle transparency log. The agent verifies manifest → signature → log inclusion proof → policy version, in that order.
3. **Scope fencing.** A consent token declares a target scope (e.g. `host:LAB-WIN-01`, `net:10.20.0.0/16`). Collectors refuse to touch anything outside it. Network primitives refuse RFC1918-external destinations unless the token carries an explicit `net_egress` grant.
4. **Denylist at the language level.** The compiler *cannot* emit certain primitive combinations; see §0.2.
5. **Lab-only.** All advanced technique demos run on VMs we own. No third-party scanning. See `docs/08-testing-plan.md` for the authorization record template that must be filled in per test.
6. **Honest reporting.** Resilience test results are reported with measured numbers and explicit failures, including cases where JOCKY was blocked.

### 0.2 Language-level capability denylist

The JOCKY frontend rejects these at semantic analysis; the LLVM backend never receives them:

| Forbidden | Rationale |
|---|---|
| `inject_remote_process()`, `write_process_memory(target_pid)` | Code injection into *other* processes is offensive. JOCKY may only read (`read_process_memory(pid)`) with token scope, and may only execute inside **its own** agent process. |
| `create_service()`, `install_driver()`, `set_run_key()`, `schedule_task()` | Persistence primitives. JOCKY never persists itself. |
| `dump_lsass()`, `harvest_credentials()`, `read_browser_db()` | Credential theft. |
| `exploit()`, `bypass_uac()`, `token_steal()` | Privilege escalation. |
| `connect_arbitrary(host, port)` on non-scoped targets | Unauthorized scanning. All egress goes through a scoped allowlist resolver. |
| Dynamic code generation that constructs syscall numbers at runtime from untrusted input | Turns a forensic loader into a generic syscall proxy. Syscall stubs are **statically generated per build** from a vetted table. |

Any PR that adds a primitive to the denylist-adjacent surface requires two reviewers, one of whom must be the security architect (see `docs/09-risks-and-compliance.md` §Review gates).

---

## 1. System overview & architecture

### 1.1 Component map

```
                        ┌──────────────────────────────────────────────┐
                        │  Analyst workstation (VPN-only)              │
                        │  Browser: dashboard (no WebRTC, no STUN)     │
                        └───────────────┬──────────────────────────────┘
                                        │ HTTPS (mTLS optional) + WSS
                        ┌───────────────▼──────────────────────────────┐
                        │  Edge: Cloudflare (CDN + WAF + Access)       │
                        │  - VPN-gated Zero Trust policy               │
                        │  - /api/* → manager origin (mTLS to origin)  │
                        └───────────────┬──────────────────────────────┘
                                        │
   ┌────────────────────────────────────▼───────────────────────────────────┐
   │  JOCKY Manager (Rust, axum + tonic)                                    │
   │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌─────────────┐  │
   │  │ authz /  │ │ job      │ │ ingest    │ │ findings │ │ audit       │  │
   │  │ consent  │ │ orch.    │ │ + index   │ │ correl.  │ │ (hash-chain)│  │
   │  └──────────┘ └──────────┘ └───────────┘ └──────────┘ └─────────────┘  │
   └───┬───────────────┬──────────────┬────────────────┬────────────────────┘
       │               │              │                │
   ┌───▼────┐     ┌────▼────┐    ┌────▼─────┐    ┌─────▼──────┐
   │Postgres│     │ Redis   │    │ S3/R2    │    │ Vault/KMS  │
   │(state) │     │(queues, │    │(bundles, │    │(signing,   │
   │        │     │ cache,  │    │ artifacts│    │ secrets)   │
   │        │     │ pub/sub)│    │ +logs)   │    │            │
   └────────┘     └─────────┘    └──────────┘    └────────────┘

   ┌────────────────────────────┐        ┌─────────────────────────────────┐
   │ JOCKY Compiler Service     │        │ JOCKY CI (GitHub Actions)       │
   │ (Rust frontend + LLVM)     │◄───────┤ build N diversified variants    │
   │ - jockyc (bin)             │        │ - SBOM, sign, transparency log  │
   │ - jocky-lsp (bin)          │        └─────────────────────────────────┘
   │ - jocky-verify (bin)       │
   └────────────────────────────┘
                 │ signed modules (.jkm)
                 ▼
   ┌────────────────────────────┐        ┌─────────────────────────────────┐
   │ Windows Agent (Rust)       │        │ Linux Agent (C + Rust loader)   │
   │ - consent gate             │        │ - consent gate                  │
   │ - module loader (in-proc)  │        │ - module loader (in-proc mmap)  │
   │ - collectors (WMI/NTAPI)   │        │ - collectors (/proc, ext4/xfs)  │
   │ - ETW consumer             │        │ - eBPF programs (CO-RE)         │
   │ - signed lab driver client │        │ - auditd/netlink consumer       │
   └────────────────────────────┘        └─────────────────────────────────┘
```

### 1.2 Why each piece exists (design rationale, one line each)

- **Custom frontend, LLVM backend** — we need a *domain* IR so that diversification passes operate on forensic semantics (e.g. "permute block order but keep the collector dependency DAG intact"), which is impossible if we lower to LLVM IR immediately.
- **`.jkm` module container** — one format for bytecode, native object, manifest, and signatures; single verification path in the agent.
- **Rust manager** — memory safety in a network-facing parser of adversarial input (agent telemetry), plus `tonic`/`axum` give gRPC + REST from one codebase.
- **Postgres + Redis** — Postgres for auditable truth (jobs, findings, hash-chained audit log); Redis for ephemeral queues/locks/pub-sub where loss is recoverable.
- **eBPF on Linux, ETW on Windows** — kernel-assisted visibility without shipping an unsigned driver on the demo path.

### 1.3 Data flows

**Flow A — author → compile → sign → deploy**

1. Analyst writes `detect_beacon.jky` in VS Code with `jocky-lsp` (completions, scope-checking, primitive denylist diagnostics).
2. CI runs `jockyc build --seed $GITHUB_RUN_ID --variant-count 8 --target x86_64-pc-windows-msvc,x86_64-unknown-linux-gnu`.
3. `jockyc` emits 8 `.jkm` files with distinct diversification seeds. Each contains: header, native code (or bytecode), embedded CBOR manifest, Ed25519 signature over `H(header||code)`, Merkle inclusion proof.
4. CI generates SBOM (CycloneDX), pushes to the artifact store (S3/R2) under `s3://jocky-artifacts/<team>/<build_id>/`, and appends the build's Merkle leaf to the transparency log (`jocky-tlog`, append-only, mirror-signed).
5. Manager ingests the build record (`POST /v1/scripts`), stores variant hashes, and marks it `available`.
6. Analyst creates a **job** targeting a scope; manager issues per-agent **consent tokens** and a **job token** (short-lived JWT with the module hash + variant index bound in).

**Flow B — agent collect → relay → ingest**

1. Agent pulls a job over HTTPS+mTLS (`GET /v1/agents/{id}/jobs`), or receives a push hint over a persistent WSS control channel.
2. Agent verifies: mTLS peer cert pin → job JWT (`aud=agent:<id>`, `exp` ≤ 5 min) → consent token (`scope` covers target) → module manifest signature → transparency-log inclusion proof → policy version ≥ minimum.
3. Agent loads the module in-process, runs the collector under a resource-governed sandbox (job object on Windows, cgroup v2 + `RLIMIT_*` on Linux).
4. Results are serialized to Arrow IPC, compressed with zstd, optionally sealed with an envelope key from Vault (agent-side sealing uses an ephemeral X25519 key whose public half is in the job token), and uploaded via presigned URL to S3/R2. The manager is notified by a signed "bundle ready" message.
5. Ingest worker pulls the bundle, verifies the agent's signature, normalizes into the `artifacts` schema, runs correlation rules, and publishes findings to Redis pub/sub → dashboard via WSS.

**Flow C — analyst investigates**

1. Analyst authenticates to Cloudflare Access (IdP = org SSO, MFA required), reaching the dashboard only from an approved VPN egress IP.
2. Dashboard subscribes to `findings:*` over WSS (fan-out from Redis pub/sub, authz filtered per role).
3. Graph view renders process → socket → file relationships from the normalized `artifacts` + `edges` tables, with every node linked back to the raw bundle object in S3/R2 and to the audit record of the job that produced it.
4. Every read of sensitive evidence writes an audit row (who, what, when, why-ticket).

### 1.4 Trust boundaries

| Boundary | Control |
|---|---|
| Analyst ↔ Edge | Cloudflare Access + VPN-only egress allowlist + device posture |
| Edge ↔ Manager | mTLS, origin IP locked to Cloudflare ranges, no public origin |
| Agent ↔ Manager | mTLS (client cert issued at enrollment, hardware-bound key on Windows via TPM/CNG, on Linux via `tpm2` or file-backed key with `0600` + measured boot attestation) |
| Manager ↔ Postgres/Redis/S3 | Private subnets, IAM roles, no static creds, TLS required |
| Agent ↔ its own modules | Ed25519 manifest verification + consent token + scope fencing |
| Agent ↔ target system | Consent token scope + collector-level fencing + OS-level job/cgroup limits |

---

## 2. Document index

| File | Contents |
|---|---|
| `docs/00-blueprint.md` | This file: framing, architecture, data flows, trust boundaries |
| `docs/01-threat-model.md` | STRIDE + ATT&CK-mapped threat model, adversary goals, abuse cases and their controls |
| `docs/02-language-and-compiler.md` | JOCKY language spec, example scripts, compiler pipeline, diversification passes, attestation |
| `docs/03-agent-runtime.md` | Windows & Linux agents, loader, in-memory execution, collectors, kernel visibility demo, vulnerable-driver detection |
| `docs/04-cicd-polymorphism.md` | CI/CD pipeline, variant matrix, SBOM, signing, transparency log, rollout/rollback |
| `docs/05-manager-and-cloud.md` | Manager service, API surface, data models, orchestration, cloud relay, mTLS/JWT |
| `docs/06-frontend-dashboard.md` | IA, views, graph viz, RBAC, WebRTC/VPN leak prevention |
| `docs/07-security-and-ops.md` | Hardening, appsec, secrets, monitoring, backup/DR, IR plan for the platform |
| `docs/08-testing-plan.md` | Authorized real-world test plan (host, network, DB, resilience) with metrics |
| `docs/09-risks-and-compliance.md` | Impact/use cases, phased roadmap, top-10 risk register, compliance & authorization model |
| `docs/10-repo-structure.md` | Repository layout, key files, crate/module responsibilities |
| `docs/11-sprint-01-tickets.md` | First-sprint (3 week) ticket list with acceptance criteria and estimates |