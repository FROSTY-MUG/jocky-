# 05 — Central Manager & Cloud Relay

Implementation: **Rust** (workspace of crates). HTTP: `axum` 0.7 + `tower` + `hyper`. gRPC: `tonic` 0.12. DB: `sqlx` (compile-time-checked queries against a live schema in CI). Cache/queues: `redis` crate (RESP3) + `redis-rs` streams. Objects: `aws-sdk-s3` and `reqwest` against R2's S3-compatible endpoint. Observability: `tracing` + `opentelemetry` → OTLP collector. Auth: `jsonwebtoken` + `ed25519-dalek` + `rustls` with client-cert auth. Authz: `casbin-rs`.

---

## 1. Deployment topology

```
Internet
  │
  ▼
Cloudflare (WAF, DDoS, Bot Mgmt, Zero Trust Access)
  │   - /api/*        → manager HTTP origin (mTLS to origin, origin cert pinned)
  │   - /grpc/*       → manager gRPC origin (HTTP/2 end-to-end, Cloudflare supports gRPC)
  │   - /ws/*         → manager WSS origin
  │   - tlog.jocky.internal → transparency-log read API (public read, signed writes)
  │
  ▼ (origin: AWS, private subnet, no public IP)
ALB (mTLS listener, client cert verification against our agent CA)
  │
  ├── manager-http   (axum, N replicas)   ──┐
  ├── manager-grpc   (tonic, M replicas)   ──┤
  ├── worker-ingest  (K consumers)         ──┼──► Postgres (RDS, Multi-AZ, pgvector + pg_partman)
  ├── worker-correlate                     ──┤    Redis (ElastiCache, cluster mode, TLS + AUTH)
  ├── scheduler                            ──┘    S3 (bundles, artifacts, tlog mirror)
  │                                               KMS (build key, bundle key)
  └── tlog-server (append-only, 2 mirrors)        Vault (team keys, secrets)
```

**Why both HTTP and gRPC:** agents use HTTP/1.1+JSON for enrollment/heartbeat (works through any middlebox, easy to debug with curl), and gRPC for the high-volume result-streaming path (`JobResultService.StreamChunks`) where protobuf + HTTP/2 flow control matters. The dashboard uses REST + WSS.

---

## 2. Data model (PostgreSQL 16)

```sql
-- ============ tenancy & identity ============
CREATE TABLE teams (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL UNIQUE,
  tlog_namespace TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id       UUID NOT NULL REFERENCES teams(id),
  email         CITEXT NOT NULL UNIQUE,
  idp_subject   TEXT NOT NULL UNIQUE,          -- OIDC sub from the IdP
  role          TEXT NOT NULL CHECK (role IN ('analyst','admin','auditor','responder')),
  webauthn_required BOOLEAN NOT NULL DEFAULT true,
  disabled_at   TIMESTAMPTZ
);

CREATE TABLE api_keys (                        -- for service accounts / CI
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id       UUID NOT NULL REFERENCES teams(id),
  name          TEXT NOT NULL,
  key_hash      BYTEA NOT NULL,                -- argon2id
  scopes        TEXT[] NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  last_used_at  TIMESTAMPTZ
);

-- ============ agents ============
CREATE TYPE agent_platform AS ENUM ('windows','linux');
CREATE TYPE agent_state    AS ENUM ('enrolled','healthy','degraded','quarantined','halted','revoked');

CREATE TABLE agents (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id            UUID NOT NULL REFERENCES teams(id),
  hostname           TEXT NOT NULL,
  platform           agent_platform NOT NULL,
  os_version         TEXT NOT NULL,
  arch               TEXT NOT NULL,
  agent_version      TEXT NOT NULL,
  variant_index      INT  NOT NULL,            -- which diversified build this host runs
  semantics_hash     TEXT NOT NULL,            -- ties results across variants
  cert_fingerprint   BYTEA NOT NULL UNIQUE,    -- SHA-256 of the enrollment client cert
  public_key         BYTEA NOT NULL,           -- Ed25519, for bundle signatures
  tpm_attested       BOOLEAN NOT NULL DEFAULT false,
  capabilities       TEXT[] NOT NULL,          -- e.g. {bpf, etw, tpm, mft}
  consent_root_pubkey BYTEA NOT NULL,
  state              agent_state NOT NULL DEFAULT 'enrolled',
  policy_version     INT NOT NULL DEFAULT 0,
  enrolled_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_heartbeat_at  TIMESTAMPTZ,
  last_seen_ip       INET,
  pinned_version     TEXT,                     -- for rollback
  quarantined_reason TEXT,
  UNIQUE (team_id, hostname)
);
CREATE INDEX ON agents (team_id, state);
CREATE INDEX ON agents (last_heartbeat_at DESC);

CREATE TABLE agent_heartbeats (                -- partitioned monthly, 90-day retention
  agent_id      UUID NOT NULL,
  at            TIMESTAMPTZ NOT NULL,
  rss_mb        REAL, cpu_pct REAL,
  spool_mb      REAL, open_jobs INT,
  collector_health JSONB,                      -- {etw:true,bpf:false,reason:"..."}
  journal_digest TEXT,                         -- hash-chain head, for tamper detection
  PRIMARY KEY (agent_id, at)
) PARTITION BY RANGE (at);

-- ============ builds & scripts ============
CREATE TABLE builds (
  id             TEXT PRIMARY KEY,             -- "<run_id>-<variant>-<target>"
  team_id        UUID NOT NULL REFERENCES teams(id),
  commit_sha     TEXT NOT NULL,
  semantics_hash TEXT NOT NULL,
  variant_index  INT  NOT NULL,
  variant_count  INT  NOT NULL,
  seed           TEXT NOT NULL,
  target_triple  TEXT NOT NULL,
  code_hash      TEXT NOT NULL,
  manifest       JSONB NOT NULL,
  sbom_url       TEXT NOT NULL,
  tlog_leaf_index BIGINT NOT NULL,
  artifact_url   TEXT NOT NULL,
  diversity_report JSONB NOT NULL,
  reproducible   BOOLEAN NOT NULL,
  built_at       TIMESTAMPTZ NOT NULL,
  revoked_at     TIMESTAMPTZ,
  UNIQUE (team_id, semantics_hash, variant_index, target_triple)
);

CREATE TABLE scripts (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id),
  module         TEXT NOT NULL,                -- "detect.beacon"
  source_url     TEXT NOT NULL,                -- git blob URL (immutable ref)
  description    TEXT,
  capabilities   TEXT[] NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (team_id, module)
);

-- ============ jobs & consent ============
CREATE TYPE job_state AS ENUM ('draft','pending_approval','scheduled','running','succeeded','failed','cancelled','expired');

CREATE TABLE jobs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id),
  script_id      UUID NOT NULL REFERENCES scripts(id),
  build_id       TEXT NOT NULL REFERENCES builds(id),
  ticket_id      TEXT NOT NULL,                -- must resolve in the incident system
  requested_by   UUID NOT NULL REFERENCES users(id),
  approved_by    UUID REFERENCES users(id),
  state          job_state NOT NULL DEFAULT 'draft',
  scope          JSONB NOT NULL,               -- {host:[],net:[],paths:[],net_egress:[]}
  budget         JSONB NOT NULL,               -- {max_runtime_s,max_memory_mb,max_ops,...}
  priority       SMALLINT NOT NULL DEFAULT 5,
  scheduled_at   TIMESTAMPTZ,
  deadline_at    TIMESTAMPTZ,
  max_concurrency INT NOT NULL DEFAULT 25,
  retry_policy   JSONB NOT NULL DEFAULT '{"max_attempts":3,"backoff":"exp","base_s":10}',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at     TIMESTAMPTZ, finished_at TIMESTAMPTZ
);
CREATE INDEX ON jobs (team_id, state, scheduled_at);
CREATE INDEX ON jobs USING GIN (scope jsonb_path_ops);

CREATE TABLE job_targets (
  job_id         UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  agent_id       UUID NOT NULL REFERENCES agents(id),
  attempt        SMALLINT NOT NULL DEFAULT 1,
  state          TEXT NOT NULL DEFAULT 'queued',  -- queued|dispatched|running|done|failed|skipped
  dispatched_at  TIMESTAMPTZ, completed_at TIMESTAMPTZ,
  error          TEXT,
  PRIMARY KEY (job_id, agent_id, attempt)
);

CREATE TABLE consent_tokens (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id         UUID NOT NULL REFERENCES jobs(id),
  agent_id       UUID NOT NULL REFERENCES agents(id),
  token_hash     BYTEA NOT NULL,               -- BLAKE3 of the signed token; raw token never stored
  ticket_id      TEXT NOT NULL,
  caps           TEXT[] NOT NULL,
  scope          JSONB NOT NULL,
  max_ops        BIGINT NOT NULL,
  max_bytes_read BIGINT NOT NULL,
  issued_by      UUID NOT NULL REFERENCES users(id),
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  used_at        TIMESTAMPTZ,
  consumed_ops   BIGINT NOT NULL DEFAULT 0,
  consumed_bytes BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX ON consent_tokens (agent_id, expires_at);

-- ============ evidence ============
CREATE TABLE bundles (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id         UUID NOT NULL REFERENCES jobs(id),
  agent_id       UUID NOT NULL REFERENCES agents(id),
  object_url     TEXT NOT NULL,                -- s3:// or r2://
  object_key     TEXT NOT NULL,
  size_bytes     BIGINT NOT NULL,
  sha256         TEXT NOT NULL,
  agent_signature BYTEA NOT NULL,
  schema_hash    TEXT NOT NULL,
  trust          TEXT NOT NULL,                -- full|degraded|suspect
  degradation_reasons TEXT[],
  envelope_key_id TEXT,                        -- KMS key that wrapped the envelope key
  retention_until TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON bundles (job_id);
CREATE INDEX ON bundles (agent_id, created_at DESC);

CREATE TABLE artifacts (                       -- normalized entities
  id             BIGSERIAL PRIMARY KEY,
  bundle_id      UUID NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  agent_id       UUID NOT NULL,
  kind           TEXT NOT NULL,                -- process|module|socket|flow|file|registry|service|task|dns|event|region
  entity_key     TEXT NOT NULL,                -- stable identity, e.g. "host:LAB-WIN-01:pid:4412:start:1773212000"
  attrs          JSONB NOT NULL,
  ts             TIMESTAMPTZ,
  observed_from  TIMESTAMPTZ, observed_to TIMESTAMPTZ
);
CREATE INDEX ON artifacts (entity_key);
CREATE INDEX ON artifacts USING GIN (attrs jsonb_path_ops);
CREATE INDEX ON artifacts (agent_id, kind, ts DESC);

CREATE TABLE edges (                           -- the graph the dashboard renders
  id             BIGSERIAL PRIMARY KEY,
  bundle_id      UUID NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  src_key        TEXT NOT NULL,
  dst_key        TEXT NOT NULL,
  rel            TEXT NOT NULL,                -- spawned|loaded|connected_to|wrote|read|listened
  attrs          JSONB NOT NULL DEFAULT '{}',
  ts             TIMESTAMPTZ
);
CREATE INDEX ON edges (src_key);
CREATE INDEX ON edges (dst_key);
CREATE INDEX ON edges (rel, ts DESC);

CREATE TABLE findings (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id),
  job_id         UUID NOT NULL REFERENCES jobs(id),
  agent_id       UUID NOT NULL REFERENCES agents(id),
  bundle_id      UUID REFERENCES bundles(id),
  severity       TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  technique      TEXT,                          -- ATT&CK ID(s)
  title          TEXT NOT NULL,
  detail         TEXT NOT NULL,
  entity_keys    TEXT[] NOT NULL,
  evidence_refs  JSONB NOT NULL,                -- pointers into the bundle (offset ranges)
  confidence     REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  trust          TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'new',   -- new|triaged|confirmed|false_positive|closed
  dedupe_hash    TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (job_id, dedupe_hash)
);
CREATE INDEX ON findings (team_id, severity, created_at DESC);
CREATE INDEX ON findings USING GIN (entity_keys);

CREATE TABLE correlation_rules (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id        UUID NOT NULL REFERENCES teams(id),
  name           TEXT NOT NULL,
  dsl            TEXT NOT NULL,                 -- see §4.3
  severity       TEXT NOT NULL,
  enabled        BOOLEAN NOT NULL DEFAULT true,
  created_by     UUID NOT NULL REFERENCES users(id),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============ audit ============
CREATE TABLE audit_log (
  seq            BIGSERIAL PRIMARY KEY,
  at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type     TEXT NOT NULL,                 -- user|agent|service|system
  actor_id       TEXT NOT NULL,
  team_id        UUID,
  action         TEXT NOT NULL,                 -- consent.issued, job.created, evidence.read, ...
  target_type    TEXT, target_id TEXT,
  detail         JSONB NOT NULL DEFAULT '{}',
  request_id     TEXT NOT NULL,
  source_ip      INET,
  prev_hash      BYTEA NOT NULL,                -- hash chain
  entry_hash     BYTEA NOT NULL                 -- BLAKE3(prev_hash || canonical(row))
);
CREATE INDEX ON audit_log (team_id, at DESC);
CREATE INDEX ON audit_log (actor_id, at DESC);
-- Enforced by a trigger: no UPDATE, no DELETE. Revoke those grants from all app roles.
```

`audit_log` is append-only by grant (`REVOKE UPDATE, DELETE ON audit_log FROM jocky_app`) plus a `BEFORE UPDATE OR DELETE` trigger that raises. A daily job exports the day's rows + the Merkle root of the chain to `s3://jocky-audit/YYYY/MM/DD/` with Object Lock.

---

## 3. API surface

### 3.1 REST (dashboard + agent control plane)

All routes are versioned (`/v1`), all mutations require `Idempotency-Key`, all list endpoints are cursor-paginated, all errors use RFC 9457 `application/problem+json`.

**Auth**
```
POST   /v1/auth/session            # IdP code exchange → session cookie; requires WebAuthn step-up
DELETE /v1/auth/session
POST   /v1/auth/step-up            # re-auth for destructive actions
```

**Enrollment (agent)**
```
POST   /v1/enroll                  # body: {nonce, host_fingerprint, pubkey, platform, os_version,
                                   #        arch, agent_version, capabilities}
                                   # → {agent_id, client_cert_pem, client_key_pem, consent_root_pubkey, policy_version}
POST   /v1/enroll/rotate           # cert rotation, requires existing valid mTLS
```

**Agent control plane (mTLS required, `aud=agent:<id>`)**
```
GET    /v1/agents/{id}/heartbeat            # 30 s; → {policy_version, tlog_head, revocation_list_version,
                                            #              collector_health_hints, pending_jobs[]}
GET    /v1/agents/{id}/jobs?long_poll=25    # → [JobDescriptor]
POST   /v1/jobs/{job_id}/result/begin       # → {upload_url, envelope_key_wrapped, chunk_size, expires_at}
POST   /v1/jobs/{job_id}/result/complete    # body: {sha256, size, agent_signature, schema_hash,
                                            #        trust, degradation_reasons, journal_digest}
POST   /v1/jobs/{job_id}/progress           # {phase, pct, ops_used, bytes_read}
POST   /v1/agents/{id}/journal              # signed local journal segments
```

**Jobs (dashboard, RBAC)**
```
GET    /v1/jobs?state=&agent=&script=&from=&to=&cursor=
POST   /v1/jobs                     # create (draft or scheduled); requires ticket_id that resolves
POST   /v1/jobs/{id}/approve        # second person for critical scopes
POST   /v1/jobs/{id}/cancel
POST   /v1/jobs/{id}/retry
GET    /v1/jobs/{id}                # includes per-target state, consent tokens (metadata only), bundles
```

**Scripts / builds**
```
GET    /v1/scripts
POST   /v1/scripts                  # register a build (CI OIDC-authenticated)
GET    /v1/scripts/{module}/builds
GET    /v1/builds/{build_id}
POST   /v1/builds/{build_id}/revoke
GET    /v1/builds/{build_id}/diversity
```

**Evidence**
```
GET    /v1/findings?severity=&technique=&agent=&status=&q=&cursor=
PATCH  /v1/findings/{id}            # status/assignment only
GET    /v1/graph?root=<entity_key>&depth=3&kinds=process,socket,file
GET    /v1/bundles/{id}/download    # 302 → presigned URL, TTL 10 min, audit-logged
GET    /v1/timeline?agent=&from=&to=
```

**Admin**
```
GET    /v1/admin/agents
POST   /v1/admin/agents/{id}/quarantine
POST   /v1/admin/agents/{id}/revoke
POST   /v1/admin/halt               # kill switch (two-person approval)
POST   /v1/admin/resume
GET    /v1/audit?actor=&action=&from=&to=&cursor=
GET    /v1/admin/health             # internal only, not exposed via Cloudflare
```

### 3.2 gRPC (high-volume paths)

```protobuf
syntax = "proto3";
package jocky.v1;

service JobResultService {
  // Agent streams result chunks; manager acks with flow control.
  rpc StreamChunks (stream ResultChunk) returns (stream ChunkAck);
}

service AgentControlService {
  // Bidirectional control channel: manager pushes hints, agent reports liveness.
  rpc Control (stream AgentEvent) returns (stream ManagerCommand);
}

service TlogService {
  rpc GetTreeHead (Empty) returns (TreeHead);
  rpc GetInclusionProof (ProofRequest) returns (InclusionProof);
}

message ResultChunk {
  string job_id = 1;
  uint32 seq = 2;
  bool last = 3;
  bytes payload = 4;          // zstd-compressed Arrow IPC batch
  string sha256_so_far = 5;
  uint64 ops_used = 6;
  uint64 bytes_read = 7;
}
message ManagerCommand {
  oneof cmd {
    Halt halt = 1;
    SwitchVersion switch_version = 2;
    RevokeBuild revoke_build = 3;
    RequestJournal request_journal = 4;
    CollectorHint collector_hint = 5;
  }
}
```

### 3.3 Example: creating a job (curl)

```bash
curl -sS -X POST https://api.jocky.internal/v1/jobs \
  -H "Cookie: jocky_session=$SESSION" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
        "script_module": "detect.beacon",
        "build_id": "8814-3-x86_64-unknown-linux-gnu",
        "ticket_id": "IR-2026-0413",
        "scope": {
          "host": ["LAB-LNX-01","LAB-LNX-02"],
          "net":  ["10.20.0.0/16"],
          "paths": ["/var/log/**","/tmp/**"],
          "net_egress": ["10.20.0.0/16"]
        },
        "budget": { "max_runtime_s": 300, "max_memory_mb": 512, "max_cpu_pct": 25,
                    "max_ops": 2000000, "max_bytes_read": 268435456 },
        "priority": 3,
        "scheduled_at": "2026-09-26T12:00:00Z",
        "deadline_at":  "2026-09-26T14:00:00Z"
      }' | jq .
```

Response:

```json
{
  "id": "0f3a1c2e-...",
  "state": "scheduled",
  "targets": 2,
  "consent_tokens": [
    { "agent_id": "…", "expires_at": "2026-09-26T12:15:00Z", "caps": ["trace_network_flows","scan_processes"] }
  ],
  "audit": { "request_id": "req_01J…", "entry_seq": 918234 }
}
```

Note: the API never returns the raw consent token to the dashboard. Tokens are delivered to the **agent** in the job descriptor over mTLS, and only the hash is stored server-side.

---

## 4. Orchestration

### 4.1 Scheduler

`manager-scheduler` is a single-leader component (Redis `SETNX` lease, 30 s TTL, renewal) so exactly one instance dispatches:

```
loop every 5 s:
  due = SELECT * FROM jobs
        WHERE state='scheduled' AND scheduled_at <= now() AND deadline_at > now()
        ORDER BY priority ASC, scheduled_at ASC
        LIMIT 100
        FOR UPDATE SKIP LOCKED;

  for job in due:
     targets = resolve_scope(job.scope) ∩ eligible_agents(job)
       eligibility: state='healthy', capabilities ⊇ required_caps,
                    variant manifest target matches agent platform,
                    agent not in cooldown, agent's team == job team

     if targets.is_empty(): job.state='failed'; reason='no eligible agents'; alert
     else:
        with Redis concurrency semaphore per agent (max_inflight_jobs=2):
            for agent in targets:
                token = sign_consent_token(job, agent)      # KMS/Vault Ed25519
                store hash in consent_tokens
                enqueue in Redis stream "jobs:dispatch"      # consumer group per agent shard
                audit('consent.issued', ...)
        job.state='running'; job.started_at=now()
```

Concurrency control is layered: global (per team, default 200 in-flight targets), per-agent (2), per-job (`max_concurrency`), and per-collector-class (e.g. only 5 simultaneous MFT parses fleet-wide to protect the network).

### 4.2 Retry & failure semantics

| Failure | Handling |
|---|---|
| Agent unreachable at dispatch | Retry on the next heartbeat; after `max_attempts`, mark `skipped`, keep job `partial` |
| Consent token expired before use | Re-issue a fresh token (new nonce); max 3 re-issues per target, then alert |
| Module verification failure | **Never retried automatically.** Immediate alert + agent quarantine after 5 in 10 min. A verification failure is a security event, not a transient error. |
| Collector error (e.g. ETW unavailable) | Partial results accepted with `trust: degraded`; job marked `succeeded_with_degradation`; analyst sees the reason |
| Upload failure | Resume via chunked upload with the same presigned URL; on expiry, request a new one; spool retained until `complete` acked |
| Agent crash mid-job | On restart, the agent reads its journal, reports the crashed job as `failed` with the last known progress; manager retries on a *different* attempt number |
| Timeout | Cooperative cancel at `max_runtime_s`, hard kill at 2×; partial results uploaded with `truncated: true` |

### 4.3 Correlation engine

Ingest normalizes artifacts, then evaluates rules expressed in a small DSL (`correlation_rules.dsl`):

```yaml
name: office-spawns-encoded-powershell-with-c2
severity: critical
window: 15m
match:
  - a: process WHERE name IN ('winword.exe','excel.exe','outlook.exe')
  - b: process WHERE ppid == a.pid AND name == 'powershell.exe'
         AND (cmdline CONTAINS '-enc' OR cmdline CONTAINS 'FromBase64String')
  - c: flow    WHERE pid == b.pid AND bytes_out > 10000 AND regularity > 0.8
emit:
  title: "Office → encoded PowerShell → regular C2-like egress"
  technique: [T1566, T1059.001, T1071]
  entities: [a.entity_key, b.entity_key, c.entity_key]
  confidence: 0.85
```

Rules run in the `worker-correlate` consumer over a Redis Stream of newly ingested artifacts, with a per-rule sliding window held in Redis (`ZADD` by timestamp, `ZRANGEBYSCORE` for the window). Deduplication via `findings.dedupe_hash = BLAKE3(rule_id || sorted(entity_keys) || window_bucket)`.

---

## 5. Cloud relay

| Function | AWS | Cloudflare (alternative/complement) | Notes |
|---|---|---|---|
| Static/edge | CloudFront | **Cloudflare CDN** | Dashboard assets + tlog read API |
| Object storage | **S3** (`jocky-bundles-<env>`, `jocky-artifacts-<env>`, `jocky-audit-<env>`, `jocky-tlog-mirror-<env>`) | **R2** (tlog mirror, artifact mirror) | SSE-KMS, versioning, Object Lock on bundles+audit, public access blocked, TLS-only bucket policy |
| Queue | SQS (bundle-ready, ingest-retry) | Cloudflare Queues | Redis Streams are the primary in-cluster queue; SQS is used for cross-region/durable buffering |
| Events | SNS → SQS fan-out for "bundle ready" to multiple ingest consumers | Workers + Queues for lightweight preprocessing | |
| Serverless preprocessing | Lambda: bundle header validation, schema check, decompress-and-index-cursor extraction | **Workers**: tlog read API, presigned-URL minter with short TTL, per-IP rate limiting | Lambda gets the bundle **only after** the agent signature verifies |
| Secrets | **KMS** (build key, bundle key) | — | Vault for team keys |
| DNS | Route 53 private hosted zone for internal names | Cloudflare DNS for `jocky.internal` (proxied, DNSSEC on) | |

**Object layout**

```
s3://jocky-bundles-prod/<team>/<yyyy>/<mm>/<dd>/<job_id>/<agent_id>/<attempt>.jkr.zst
s3://jocky-artifacts-prod/<team>/<build_id>/{*.jkm,*.sig,sbom.cdx.json,diversity.json,manifest.cbor}
s3://jocky-audit-prod/<yyyy>/<mm>/<dd>/audit.jsonl.zst + merkle_root.txt   (Object Lock, 7 years)
r2://jocky-tlog-mirror/{leaves/,checkpoints/}
```

**Bucket policy essentials**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
      "Resource": ["arn:aws:s3:::jocky-bundles-prod/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } } },
    { "Sid": "DenyOutsideVPCE", "Effect": "Deny", "Principal": "*",
      "Action": ["s3:GetObject","s3:PutObject"],
      "Resource": ["arn:aws:s3:::jocky-bundles-prod/*"],
      "Condition": { "StringNotEquals": { "aws:SourceVpce": "vpce-0abc…" } } },
    { "Sid": "DenyUnencryptedObjectUploads", "Effect": "Deny", "Principal": "*",
      "Action": "s3:PutObject", "Resource": ["arn:aws:s3:::jocky-bundles-prod/*"],
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" } } }
  ]
}
```

---

## 6. Authentication & authorization

### 6.1 mTLS (agent ↔ manager)

- Private CA (`jocky-agent-ca`, Ed25519 → X.509, 10-year root, held offline; intermediate `jocky-agent-issuing` 1 year, online in Vault PKI).
- Enrollment: agent presents an **enrollment nonce** (single-use, 24 h TTL, provisioned out-of-band by an admin) + its Ed25519 public key; the manager issues a client cert with `CN=<agent_id>`, `O=<team>`, `SAN=URI:spiffe://jocky/<team>/agent/<agent_id>`, 90-day validity.
- Renewal at 2/3 lifetime, requires a valid existing cert; on renewal failure the agent degrades to heartbeat-only and alerts.
- ALB listener verifies the client chain against the issuing CA and forwards `X-Client-Cert-Fingerprint`; the manager **re-verifies the fingerprint against `agents.cert_fingerprint`** — never trusting the header alone.
- CRL/OCSP: revocation list published to S3 + served by the manager's heartbeat response as `revocation_list_version`; agents cache and re-fetch on version change.

### 6.2 Job tokens (short-lived JWT)

```json
{
  "iss": "jocky-manager/c4-ir",
  "sub": "job:0f3a1c2e-…",
  "aud": "agent:LAB-LNX-01:9f2c…",
  "exp": 1773213300,
  "nbf": 1773212400,
  "jti": "b7f3…",
  "jkm": { "build_id": "8814-3-x86_64-unknown-linux-gnu", "code_hash": "blake3:1c2b…",
           "semantics_hash": "blake3:77c0…" },
  "consent": { "token_hash": "blake3:aa11…", "max_ops": 2000000, "max_bytes_read": 268435456 },
  "envelope_pubkey": "x25519:…"
}
```

Signed EdDSA (Ed25519), TTL ≤ 5 minutes, `aud` bound to exactly one agent, `jkm.code_hash` bound to the exact artifact. The agent rejects a token whose `jkm.code_hash` does not match the module it was handed — this prevents a compromised manager from swapping in a different binary silently.

### 6.3 Authorization model (Casbin)

```
# model.conf
[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act, eft
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
```

```csv
# policy.csv (excerpt)
p, analyst,   c4-ir, /v1/findings*,        (GET|PATCH), allow
p, analyst,   c4-ir, /v1/jobs*,            (GET|POST),   allow
p, analyst,   c4-ir, /v1/admin/*,          *,            deny
p, responder, c4-ir, /v1/jobs/*/cancel,    POST,         allow
p, responder, c4-ir, /v1/bundles/*/download, GET,        allow
p, auditor,   c4-ir, /v1/*,                GET,          allow
p, auditor,   c4-ir, /v1/jobs,             POST,         deny
p, admin,     c4-ir, /v1/*,                *,            allow
p, admin,     c4-ir, /v1/admin/halt,       POST,         deny   # explicit deny wins; halt needs 2-person
g, alice, analyst, c4-ir
```

Object-level checks run **in addition** to Casbin: every handler re-queries the row's `team_id` and asserts it equals the session's team. An integration test (`tests/authz_idor.rs`) enumerates every route and asserts a cross-team ID returns 404 (not 403 — do not leak existence).

### 6.4 Human authentication

- OIDC against the org IdP, PKCE, `nonce`, strict `state`; session = signed cookie (`httpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix), 30 min idle / 8 h absolute.
- **WebAuthn/passkeys required** for `admin` and `responder` roles; step-up re-auth (fresh WebAuthn assertion) for: job creation with scope > 1 host, bundle download, token issuance, halt/resume, build revocation, RBAC changes.
- Rate limits: 10 session creations/IP/min, 60 API req/user/min, 5 failed step-ups → 15 min lockout.

---

## 7. Domain fronting: threat model only (no production feature)

**Decision: JOCKY does not implement domain fronting.** It is documented because (a) judges will ask, and (b) it is a *threat* to our own traffic.

**Why not:** it violates Cloudflare's and AWS's terms of service, it makes our traffic indistinguishable from adversary traffic (destroying our own ability to attribute and to allowlist), and it provides no benefit for an authorized responder who can simply use a properly-scoped VPN endpoint.

**Threat model entry (A2):** an adversary could attempt to *use* fronting-like techniques to hide their C2 behind a legitimate CDN SNI. JOCKY's detection response is in the network collectors: `trace_network_flows` flags (a) flows where the observed TLS SNI does not match the resolved destination's certificate SAN (a strong fronting/MITM indicator), (b) certificate pinning failures observed from ETW/eBPF on other processes, and (c) large-volume flows to CDN IP ranges with no corresponding DNS cache entry. These are emitted as findings with `technique: T1090.004`, and the evidence includes the SNI, the cert chain digest, and the CDN ASN.

**Our own transport, for the record:** a single dedicated subdomain (`api.jocky.internal`), proxied by Cloudflare with a strict WAF ruleset and full request logging, reachable only from the corporate VPN's egress ranges (Cloudflare Access policy + origin IP allowlist). No SNI games, no fronting, no fallback domains.

---

## 8. Logging, metrics, alerting

**Structured logs:** JSON via `tracing-subscriber`, every line carrying `request_id`, `team_id`, `actor_id`, `job_id`, `agent_id`. Shipped to CloudWatch Logs → S3 (Object Lock) and to the SIEM via a Firehose subscription. **Redaction layer:** log fields matching `(?i)(token|secret|key|password|authorization|cookie)` are replaced with `"[redacted]"` by a custom `tracing` layer, tested by a unit test that asserts no secret appears in a rendered log line.

**Metrics (Prometheus, scraped by the OTel collector):**

| Metric | Alert |
|---|---|
| `jocky_agents_healthy / total` | < 90% for 10 min → warn; < 70% → page |
| `jocky_agent_heartbeat_age_seconds` (p99) | > 120 s → warn per-agent |
| `jocky_jobs_failed_total{reason}` | any `reason="verification_failure"` → **immediate page** |
| `jocky_module_verify_failures_total` | > 5 in 10 min (any agent) → page + auto-quarantine |
| `jocky_ingest_lag_seconds` | > 300 → warn |
| `jocky_bundle_upload_failures_total` | > 5% for 15 min → page |
| `jocky_consent_issued_total{ticket_missing="true"}` | > 0 → page (policy violation) |
| `jocky_audit_chain_verify_failures` | > 0 → **immediate page** (tamper) |
| `jocky_tlog_mirror_lag_leaves` | > 1000 → warn |
| `jocky_api_5xx_rate` | > 1% for 5 min → page |
| `jocky_postgres_replication_lag_bytes` | > 10 MB → warn |
| `jocky_agent_rss_mb` (p99) | > 2× baseline → warn |

**Anomaly alerts (security, not just availability):**
- Agent heartbeat from a new ASN/IP country → quarantine + notify.
- Consent token issued with a scope covering > 50 hosts → require approval + notify.
- Bundle download volume per user > 3σ of their 30-day baseline → notify.
- `jocky_tlog` checkpoint signature invalid → page + halt token issuance (fail-closed).

**Dashboards:** one Grafana board per audience — "Fleet health", "Job throughput & failures", "Security events (verify failures, consent anomalies, quarantines)", "Evidence pipeline (ingest lag, bundle sizes, trust distribution)".