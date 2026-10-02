# Interface Specification: Findings Schema

**Status:** FROZEN  
**Date:** 2026-09-28  
**Source of Truth:** [`agent/common/src/protocol.rs`](../../agent/common/src/protocol.rs) (`Finding` struct)  
**Consumer Implementations:**  
- Endpoint Agents (`agent/windows-cpp`, `agent/linux`, `agent/macos-swift`)
- Central Manager (`manager/go`)
- Web Dashboard (`frontend/`)

---

## 1. Overview

A **Finding** represents an atomic DFIR artifact, anomaly, or detected threat state captured by an endpoint agent collector or detection module. All agent runtimes MUST output findings conforming exactly to this schema. The central manager ingests and stores findings in this schema, and the frontend consumes them directly for triage, filtering, and timeline visualization.

---

## 2. Canonical JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Finding",
  "type": "object",
  "required": [
    "id",
    "severity",
    "title",
    "evidence",
    "host",
    "collected_at",
    "collector"
  ],
  "properties": {
    "id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique identifier (UUID v4) generated at observation/emission time"
    },
    "severity": {
      "type": "string",
      "enum": ["Info", "Low", "Medium", "High", "Critical"],
      "description": "Risk rating according to standard severity hierarchy"
    },
    "title": {
      "type": "string",
      "description": "Short, human-readable summary of the detected state or anomaly"
    },
    "evidence": {
      "description": "Raw supporting evidence (structured JSON object or serialized telemetry string)"
    },
    "mitre": {
      "type": ["string", "null"],
      "description": "MITRE ATT&CK technique ID (e.g. T1068, T1055) or null if purely observational"
    },
    "host": {
      "type": "string",
      "description": "FQDN or NetBIOS identifier of the originating host"
    },
    "pid": {
      "type": ["integer", "null"],
      "description": "Target or subject process ID associated with the finding, if applicable"
    },
    "collected_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of observation (e.g. 2026-09-28T04:00:00Z)"
    },
    "collector": {
      "type": "string",
      "description": "Originating subsystem: process | network | driver | byovd | inject | syscall | memory"
    }
  }
}
```

---

## 3. Example Finding Object

```json
{
  "id": "e9c1d0aa-a0b2-4d22-b91c-132cf05d97f2",
  "severity": "High",
  "title": "Vulnerable Driver Loaded: iobios64.sys",
  "evidence": "{\"driver_path\":\"C:\\\\Windows\\\\System32\\\\drivers\\\\iobios64.sys\",\"sha256\":\"314a51fcf6e37eb8550a826df085d5c88c43eb1438682f3a6c33632d36956136\",\"loldrivers_match\":\"Known vulnerable IObit driver permitting arbitrary kernel R/W\"}",
  "mitre": "T1068",
  "host": "LAB-WIN-01",
  "pid": null,
  "collected_at": "2026-09-28T04:00:00Z",
  "collector": "byovd"
}
```

---

## 4. Transmission & Wire Formats

1. **CLI Mode (Stdout Streaming):**
   - Format: **JSON Lines (`.jsonl`)** — one complete Finding JSON object per newline.
   - Purpose: Direct piping to log forwarders, `jq`, or disk buffers without requiring full memory buffering.
2. **Manager Ingestion (HTTP Upload):**
   - Endpoint: `POST /v1/agents/:id/jobs/:job_id/result`
   - Content-Type: `application/json`
   - Payload: Batched array of `Finding` objects (`{"findings": [Finding, ...]}`).
