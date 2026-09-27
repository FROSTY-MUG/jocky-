# Interface Specification: Central Manager API

**Status:** FROZEN  
**Date:** 2026-09-28  
**Implementer:** Central Manager (`manager/go`)  
**Consumers:**  
- Endpoint Agents (`agent/windows-cpp`, `agent/linux`, `agent/macos-swift`)
- Analyst Web Dashboard (`frontend/`)
- Automation & CI CLI Tools

---

## 1. Overview

The Central Manager coordinates endpoint agents, issues signed consent tokens, schedules forensic analysis jobs, ingests telemetry and findings, and maintains an immutable audit trail. This specification defines the authoritative REST and gRPC API surface exposed by the manager.

---

## 2. REST API Specification (Base Path: `/v1`)

### 2.1 Agent Lifecycle & Registration

#### `POST /v1/agents/register`
Registers a newly deployed agent with the central cluster.
- **Request Body:**
  ```json
  {
    "hostname": "LAB-WIN-01",
    "os": "windows",
    "arch": "x86_64",
    "public_key_b64": "<base64 Ed25519 agent public key>",
    "manifest_b64": "<base64 signed host manifest>"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "agent_id": "agent-win-01",
    "consent_token_b64": "<base64 initial consent token>",
    "manager_pubkey_b64": "<base64 manager verifying key>"
  }
  ```

#### `POST /v1/agents/:id/heartbeat`
Periodic liveness beacon emitted by agents.
- **Request Parameters:** `:id` (Agent ID)
- **Response (`200 OK`):**
  ```json
  {
    "server_time": 1790589600,
    "pending_jobs": ["job-9842", "job-9843"]
  }
  ```

---

### 2.2 Job Dispatch & Execution

#### `GET /v1/agents/:id/jobs`
Fetches pending execution directives assigned to the agent.
- **Request Parameters:** `:id` (Agent ID)
- **Response (`200 OK`):**
  ```json
  {
    "jobs": [
      {
        "id": "job-9842",
        "module_url": "https://manager.internal/v1/scripts/mod-1234.jkm",
        "scope": "host:LAB-WIN-01",
        "ttl": 3600
      }
    ]
  }
  ```

#### `POST /v1/agents/:id/jobs/:job_id/result`
Uploads forensic execution findings and completion status.
- **Request Parameters:** `:id` (Agent ID), `:job_id` (Job ID)
- **Request Body:**
  ```json
  {
    "findings": [
      {
        "id": "e9c1d0aa-a0b2-4d22-b91c-132cf05d97f2",
        "severity": "High",
        "title": "Vulnerable Driver Loaded: iobios64.sys",
        "evidence": "{\"driver_path\":\"C:\\\\Windows\\\\System32\\\\drivers\\\\iobios64.sys\"}",
        "mitre": "T1068",
        "host": "LAB-WIN-01",
        "pid": null,
        "collected_at": "2026-09-28T04:00:00Z",
        "collector": "byovd"
      }
    ],
    "errors": []
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "accepted": true
  }
  ```

---

### 2.3 Analyst & Script Management

#### `POST /v1/scripts`
Uploads a compiled and signed `.jkm` module container.
- **Headers:** `Content-Type: application/octet-stream`
- **Body:** Raw binary `.jkm` container bytes
- **Response (`201 Created`):**
  ```json
  {
    "script_id": "scr-4019",
    "sha256": "4a72d4c0...",
    "variant_count": 8
  }
  ```

#### `POST /v1/jobs`
Creates and dispatches a forensic investigation job with an accompanying consent token.
- **Request Body:**
  ```json
  {
    "script_id": "scr-4019",
    "agent_id": "agent-win-01",
    "scope": "host:LAB-WIN-01",
    "ttl_seconds": 3600
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "job_id": "job-9842",
    "consent_token_b64": "<base64 signed Ed25519 consent token>"
  }
  ```

#### `GET /v1/findings`
Queries triage findings across all monitored hosts.
- **Query Parameters:**
  - `agent`: Filter by Agent ID
  - `severity`: Filter by `Info`, `Low`, `Medium`, `High`, `Critical`
  - `mitre`: Filter by MITRE ATT&CK technique (e.g. `T1068`)
  - `from`: ISO 8601 UTC start time
  - `to`: ISO 8601 UTC end time
- **Response (`200 OK`):**
  ```json
  {
    "findings": [ ... ],
    "total": 142
  }
  ```

#### `GET /v1/audit`
Retrieves immutable operational audit logs.
- **Query Parameters:**
  - `actor`: User or agent identifier
  - `from`: Start timestamp
  - `to`: End timestamp
- **Response (`200 OK`):**
  ```json
  {
    "entries": [
      {
        "ts": "2026-09-28T04:00:00Z",
        "actor": "analyst-alice",
        "action": "ISSUE_CONSENT_TOKEN",
        "target": "agent-win-01",
        "meta": { "scope": "host:LAB-WIN-01", "script_id": "scr-4019" }
      }
    ]
  }
  ```

---

## 3. Authentication & Authorization Model

1. **Agent ↔ Manager (Node Security):**
   - Protocol: **mTLS (Mutual TLS 1.3)** with ephemeral client certificates issued during initial enrollment.
   - Pinned CA verification prevents MITM or rogue agent attachment.
2. **Analyst ↔ Manager (Dashboard Security):**
   - Protocol: **OIDC + short-lived RS256 JWT** (15-minute maximum lifetime).
   - Role-Based Access Control (RBAC):
     - `Viewer`: Read findings and audit log.
     - `Operator`: Issue jobs within permitted host scopes.
     - `Admin`: Manage agent keys, policy versions, and user authorization.
3. **Job-Scoped Execution Tokens:**
   - JWT valid for 5 minutes (`aud=agent:<id>`), binding the cryptographic hash of the authorized `.jkm` module to prevent execution of substituted payloads.

---

## 4. gRPC Interface (Mirror at `/grpc.JockyManager/...`)

```protobuf
syntax = "proto3";
package jocky;

service AgentService {
  rpc Register (RegisterRequest) returns (RegisterResponse);
  rpc Heartbeat (HeartbeatRequest) returns (HeartbeatResponse);
  rpc FetchJob (FetchJobRequest) returns (FetchJobResponse);
  rpc UploadResult (UploadResultRequest) returns (UploadResultResponse);
}

service AnalystService {
  rpc ListAgents (ListAgentsRequest) returns (ListAgentsResponse);
  rpc CreateJob (CreateJobRequest) returns (CreateJobResponse);
  rpc GetFindings (GetFindingsRequest) returns (GetFindingsResponse);
  rpc GetAuditLog (GetAuditLogRequest) returns (GetAuditLogResponse);
}
```
