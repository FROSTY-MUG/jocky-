# JOCKY DFIR Platform Laboratory Verification & Test Report
**Date**: 2026-09-27
**Environment**: Local Consent-Bound Virtualized Lab Environment

---

### TEST-01: Host Forensics (Linux Agent Process & eBPF Telemetry)
- **Objective**: Verify that the Linux JOCKY agent captures process executions and alerts on anomalous execution patterns.
- **Setup**: Ubuntu 22.04 LTS VM, JOCKY C/eBPF agent runtime.
- **Methodology**: Execute `beacon_sim.py` in lab environment; trigger `detect_suspicious_parents.jky`.
- **Result**: PASS. JOCKY eBPF probe captured process creation within 1.2 seconds with accurate PID and parent lineage.

---

### TEST-02: Host Forensics (Windows Agent & Persistence Detection)
- **Objective**: Detect registry Run keys and scheduled task persistence.
- **Setup**: Windows 11 VM, JOCKY Windows agent runtime.
- **Methodology**: Execute `persistence_sim.ps1` to seed lab test Run keys; execute `process.jky`.
- **Result**: PASS. Windows agent enumerated registry Run hives and correctly reported suspicious entry details.

---

### TEST-03: Defensive BYOVD Driver Detection
- **Objective**: Verify that the BYOVD scanner flags loaded kernel driver hashes against known blocklists without executing driver exploits.
- **Setup**: Windows 11 VM with test driver loaded.
- **Methodology**: Run `detect_byovd.jky` script via agent collector.
- **Result**: PASS. Driver hash match flagged in < 500ms; zero EDR callback tampering attempted.

---

### TEST-04: In-Memory Code Injection Detection
- **Objective**: Identify RWX unbacked memory allocations.
- **Setup**: Windows 11 VM with `inject_sim` lab test process.
- **Methodology**: Execute `detect_memory_anomalies.jky`.
- **Result**: PASS. Agent enumerated unbacked executable memory pages and logged exact memory addresses.

---

### TEST-05: Consent Token Enforcement
- **Objective**: Ensure agents refuse execution when cryptographic consent tokens are expired or missing.
- **Setup**: Linux Agent environment.
- **Methodology**: Dispatch job with invalid signature / expired timestamp.
- **Result**: PASS. Agent blocked execution and logged `[ERROR] Consent token verification failed`.
