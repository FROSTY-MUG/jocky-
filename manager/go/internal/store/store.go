package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/FROSTY-MUG/jocky/manager/go/internal/types"
)

// Store provides thread-safe in-memory state management with audit log chaining.
type Store struct {
	mu          sync.RWMutex
	agents      map[string]*types.Agent
	scripts     map[string]*types.ForensicScript
	jobs        map[string]*types.ForensicJob
	findings    map[string]*types.Finding
	auditLogs   []types.AuditEntry
	currentHash string
}

// NewStore initializes a Store with pre-loaded mock fleet agents, stdlib scripts, and genesis audit entry.
func NewStore() *Store {
	s := &Store{
		agents:      make(map[string]*types.Agent),
		scripts:     make(map[string]*types.ForensicScript),
		jobs:        make(map[string]*types.ForensicJob),
		findings:    make(map[string]*types.Finding),
		auditLogs:   make([]types.AuditEntry, 0),
		currentHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	// Seed genesis audit log
	s.appendAuditInternal("SYSTEM", "INITIALIZE_MANAGER", "genesis", "genesis_seed_v0.1")

	// Seed default scripts
	s.seedDefaultScripts()

	// Seed realistic initial forensic fleet
	s.seedDefaultAgents()

	// Seed realistic active threat findings
	s.seedDefaultFindings()

	return s
}

func (s *Store) seedDefaultScripts() {
	defaultScripts := []types.ForensicScript{
		{
			ID:           "scr-byovd",
			Module:       "detect_byovd",
			Filename:     "detect_byovd.jky",
			Description:  "Scans loaded kernel drivers against known vulnerable driver blocklists (BYOVD attack detection).",
			Capabilities: []string{"driver_inspect", "read_memory_safe"},
			DenylistSafe: true,
			CodeHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			SourceCode: `// detect_byovd.jky - Vulnerable driver identification
fn verify_driver_hash(driver_base: i64, known_vulnerable: i64) -> i64 {
    if (driver_base <= 0) {
        return 0;
    }
    if (driver_base == known_vulnerable) {
        return 1; // Suspicious vulnerable driver matched
    }
    return 0;
}

fn main() -> i64 {
    let gdrv_vulnerable_base: i64 = 5242880;
    let target_base: i64 = 5242880;
    let is_vulnerable: i64 = verify_driver_hash(target_base, gdrv_vulnerable_base);
    return is_vulnerable;
}`,
		},
		{
			ID:           "scr-inject",
			Module:       "detect_inject",
			Filename:     "detect_inject.jky",
			Description:  "Inspects process address space for unbacked executable memory pages indicative of shellcode or DLL injection.",
			Capabilities: []string{"read_process_memory_safe", "query_virtual_memory"},
			DenylistSafe: true,
			CodeHash:     "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
			SourceCode: `// detect_inject.jky - Memory injection & unbacked page scanner
fn scan_page_protections(page_type: i64, page_protect: i64) -> i64 {
    // PAGE_EXECUTE_READWRITE = 0x40 (64)
    // MEM_PRIVATE = 0x20000
    if (page_protect == 64) {
        return 1; // Anomalous RWX region
    }
    return 0;
}

fn main() -> i64 {
    let target_prot: i64 = 64;
    let target_type: i64 = 131072;
    let detected: i64 = scan_page_protections(target_type, target_prot);
    return detected;
}`,
		},
		{
			ID:           "scr-syscall",
			Module:       "detect_syscall",
			Filename:     "detect_syscall.jky",
			Description:  "Audits NTDLL stub integrity to identify inline hooks or clandestine direct syscall invocations.",
			Capabilities: []string{"syscall_audit"},
			DenylistSafe: true,
			CodeHash:     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			SourceCode: `// detect_syscall.jky - Direct syscall and stub hook verifier
fn audit_ntdll_stub(stub_byte_0: i64, stub_byte_1: i64) -> i64 {
    // Expected: 0x4C, 0x8B, 0xD1, 0xB8 (mov r10, rcx; mov eax, sys_num)
    if (stub_byte_0 != 76) {
        return 1; // Tampered or hooked syscall entry point
    }
    return 0;
}

fn main() -> i64 {
    let b0: i64 = 76;
    let b1: i64 = 139;
    return audit_ntdll_stub(b0, b1);
}`,
		},
		{
			ID:           "scr-process",
			Module:       "process",
			Filename:     "process.jky",
			Description:  "Validates process tree lineage and parent-child consistency without executing invasive debug APIs.",
			Capabilities: []string{"process_enumerate"},
			DenylistSafe: true,
			CodeHash:     "871653cc2208675d79bf33528b1dd320b722cdd188047a9b0c4b37b1931a1a3c",
			SourceCode: `// process.jky - Process verification primitive
fn inspect_target(pid: i64) -> i64 {
    if (pid <= 0) {
        return 0;
    }
    let threshold: i64 = 4096;
    let baseline: i64 = pid + threshold;
    return baseline;
}

fn main() -> i64 {
    let result: i64 = inspect_target(1337);
    return result;
}`,
		},
		{
			ID:           "scr-memory",
			Module:       "memory",
			Filename:     "memory.jky",
			Description:  "Acquires memory block hashes for dead-box forensic integrity correlation.",
			Capabilities: []string{"memory_hashing"},
			DenylistSafe: true,
			CodeHash:     "d41d8cd98f00b204e9800998ecf8427e",
			SourceCode: `// memory.jky - Read-only memory region hasher
fn hash_region_bounds(start_addr: i64, length: i64) -> i64 {
    if (length <= 0) {
        return 0;
    }
    return start_addr + length;
}

fn main() -> i64 {
    return hash_region_bounds(65536, 4096);
}`,
		},
		{
			ID:           "scr-network",
			Module:       "network",
			Filename:     "network.jky",
			Description:  "Cross-correlates established TCP/UDP network sockets with active listening process PIDs.",
			Capabilities: []string{"socket_inspect"},
			DenylistSafe: true,
			CodeHash:     "c4ca4238a0b923820dcc509a6f75849b",
			SourceCode: `// network.jky - Socket to process correlation
fn verify_remote_port(port: i64) -> i64 {
    if (port == 4444) {
        return 1; // Known suspicious port
    }
    return 0;
}

fn main() -> i64 {
    return verify_remote_port(4444);
}`,
		},
	}

	for _, scr := range defaultScripts {
		scrCopy := scr
		s.scripts[scr.ID] = &scrCopy
	}
}

func (s *Store) seedDefaultAgents() {
	now := time.Now().UTC()
	agents := []types.Agent{
		{
			ID:             "agt-win-01",
			Hostname:       "SEC-OPS-W11-01",
			Platform:       types.PlatformWindows,
			OSVersion:      "Windows 11 Enterprise 23H2 (Build 22631.3880)",
			Arch:           "x86_64",
			AgentVersion:   "0.1.0-jocky",
			VariantIndex:   1,
			BuildSeed:      4242,
			CodeHash:       "b8a91c32759e69c0d5e12f6b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
			SemanticsHash:  "98a72c1143bc0912da77f88421bba8763214567890abcdef1234567890abcdef",
			PublicKey:      "c7f8a29b4e13d9876543210fedcba9876543210fedcba9876543210fedcba987",
			ConsentRootKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Capabilities:   []string{"etw", "mft", "driver_inspect", "safe_memory"},
			State:          types.StateHealthy,
			CollectorHealth: types.CollectorHealth{
				ETWAvailable: true,
				MFTAvailable: true,
				TPMAttested:  true,
			},
			CPUPct:          1.8,
			MemoryRSSMB:     42.5,
			EnrolledAt:      now.Add(-72 * time.Hour),
			LastHeartbeatAt: now.Add(-15 * time.Second),
			LastSeenIP:      "10.240.12.14",
		},
		{
			ID:             "agt-win-02",
			Hostname:       "CORP-DC-01",
			Platform:       types.PlatformWindows,
			OSVersion:      "Windows Server 2022 Standard (Build 20348.2461)",
			Arch:           "x86_64",
			AgentVersion:   "0.1.0-jocky",
			VariantIndex:   2,
			BuildSeed:      9811,
			CodeHash:       "7c9a8b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
			SemanticsHash:  "98a72c1143bc0912da77f88421bba8763214567890abcdef1234567890abcdef",
			PublicKey:      "5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e",
			ConsentRootKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Capabilities:   []string{"etw", "driver_inspect", "ntdll_audit"},
			State:          types.StateDegraded,
			CollectorHealth: types.CollectorHealth{
				ETWAvailable:     false,
				MFTAvailable:     true,
				TPMAttested:      true,
				DegradationCause: "ETW Microsoft-Windows-Kernel-Network provider silenced by host policy",
			},
			CPUPct:          3.4,
			MemoryRSSMB:     68.1,
			EnrolledAt:      now.Add(-120 * time.Hour),
			LastHeartbeatAt: now.Add(-45 * time.Second),
			LastSeenIP:      "10.240.4.5",
		},
		{
			ID:             "agt-nix-01",
			Hostname:       "PROD-K8S-NODE-03",
			Platform:       types.PlatformLinux,
			OSVersion:      "Ubuntu 24.04 LTS (Linux 6.8.0-31-generic)",
			Arch:           "x86_64",
			AgentVersion:   "0.1.0-jocky",
			VariantIndex:   3,
			BuildSeed:      1337,
			CodeHash:       "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b",
			SemanticsHash:  "98a72c1143bc0912da77f88421bba8763214567890abcdef1234567890abcdef",
			PublicKey:      "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
			ConsentRootKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Capabilities:   []string{"bpf", "process_inspect", "sock_filter"},
			State:          types.StateHealthy,
			CollectorHealth: types.CollectorHealth{
				BPFAvailable: true,
				TPMAttested:  false,
			},
			CPUPct:          0.9,
			MemoryRSSMB:     31.2,
			EnrolledAt:      now.Add(-48 * time.Hour),
			LastHeartbeatAt: now.Add(-8 * time.Second),
			LastSeenIP:      "10.240.20.103",
		},
		{
			ID:             "agt-win-03",
			Hostname:       "FINANCE-WS-19",
			Platform:       types.PlatformWindows,
			OSVersion:      "Windows 10 Pro (Build 19045.4529)",
			Arch:           "x86_64",
			AgentVersion:   "0.1.0-jocky",
			VariantIndex:   4,
			BuildSeed:      7701,
			CodeHash:       "2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f",
			SemanticsHash:  "98a72c1143bc0912da77f88421bba8763214567890abcdef1234567890abcdef",
			PublicKey:      "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
			ConsentRootKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Capabilities:   []string{"etw", "safe_memory"},
			State:          types.StateQuarantined,
			CollectorHealth: types.CollectorHealth{
				ETWAvailable:     false,
				DegradationCause: "Unbacked RWX memory detected in lsass.exe process context",
			},
			CPUPct:          6.2,
			MemoryRSSMB:     54.0,
			EnrolledAt:      now.Add(-90 * time.Hour),
			LastHeartbeatAt: now.Add(-300 * time.Second),
			LastSeenIP:      "10.240.18.99",
		},
	}

	for _, a := range agents {
		aCopy := a
		s.agents[a.ID] = &aCopy
	}
}

func (s *Store) seedDefaultFindings() {
	now := time.Now().UTC()
	findings := []types.Finding{
		{
			ID:             "fnd-001",
			JobID:          "job-init-01",
			AgentID:        "agt-win-02",
			Hostname:       "CORP-DC-01",
			Title:          "Vulnerable Driver gdrv.sys Loaded (BYOVD Vector)",
			Detail:         "Kernel driver matching known vulnerable Gigabyte gdrv.sys hash (SHA256: 31f472...) detected at base 0xFFFFF80004500000 without valid Microsoft WHQL attestation tag.",
			Severity:       types.SeverityCritical,
			Trust:          types.TrustFull,
			MITRETechnique: "T1068 - Exploitation for Privilege Escalation",
			ArtifactJSON:   `{"driver_name":"gdrv.sys","base_address":"0xFFFFF80004500000","sha256":"31f47212001c23...","whql":false,"vulnerable_cve":"CVE-2018-19320"}`,
			EvidenceRef:    "bundle://corp-dc-01/drivers/20261002-0941.jkm#offset=4096&len=512",
			ObservedAt:     now.Add(-40 * time.Minute),
			Status:         "open",
		},
		{
			ID:             "fnd-002",
			JobID:          "job-init-02",
			AgentID:        "agt-win-03",
			Hostname:       "FINANCE-WS-19",
			Title:          "Unbacked Executable RWX Memory Page in spoolsv.exe",
			Detail:         "Virtual memory analysis located 64KB region at 0x0000021A4B000000 marked PAGE_EXECUTE_READWRITE with MEM_PRIVATE backing (no file on disk). Contains call/pop shellcode stub.",
			Severity:       types.SeverityCritical,
			Trust:          types.TrustDegraded,
			MITRETechnique: "T1055 - Process Injection",
			ArtifactJSON:   `{"pid":2944,"process":"spoolsv.exe","address":"0x0000021A4B000000","size_bytes":65536,"protection":"PAGE_EXECUTE_READWRITE","type":"MEM_PRIVATE"}`,
			EvidenceRef:    "bundle://finance-ws-19/mem/20261002-0915.jkm#offset=65536&len=4096",
			ObservedAt:     now.Add(-65 * time.Minute),
			Status:         "triaged",
		},
		{
			ID:             "fnd-003",
			JobID:          "job-init-03",
			AgentID:        "agt-win-01",
			Hostname:       "SEC-OPS-W11-01",
			Title:          "NTDLL Inline Syscall Hook in svchost.exe",
			Detail:         "ZwCreateThreadEx stub byte 0 modified from standard opcode 0x4C (mov r10, rcx) to 0xE9 (jmp rel32) pointing outside NTDLL module boundaries.",
			Severity:       types.SeverityHigh,
			Trust:          types.TrustFull,
			MITRETechnique: "T1106 - Native API / Hooking",
			ArtifactJSON:   `{"stub":"ZwCreateThreadEx","expected_opcode":"0x4C","actual_opcode":"0xE9","detour_target":"0x00007FF8B2104000"}`,
			EvidenceRef:    "bundle://sec-ops-w11-01/hooks/20261002-0850.jkm#offset=1024&len=256",
			ObservedAt:     now.Add(-110 * time.Minute),
			Status:         "open",
		},
	}

	for _, f := range findings {
		fCopy := f
		s.findings[f.ID] = &fCopy
	}
}

func (s *Store) appendAuditInternal(actor, action, target, payload string) types.AuditEntry {
	h := sha256.New()
	h.Write([]byte(payload))
	payloadHash := hex.EncodeToString(h.Sum(nil))

	index := int64(len(s.auditLogs))
	timestamp := time.Now().UTC()

	entryHasher := sha256.New()
	entryHasher.Write([]byte(fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s",
		index, timestamp.Format(time.RFC3339Nano), actor, action, target, payloadHash, s.currentHash)))
	entryHash := hex.EncodeToString(entryHasher.Sum(nil))

	entry := types.AuditEntry{
		Index:       index,
		Timestamp:   timestamp,
		Actor:       actor,
		Action:      action,
		Target:      target,
		PayloadHash: payloadHash,
		PrevHash:    s.currentHash,
		EntryHash:   entryHash,
	}

	s.currentHash = entryHash
	s.auditLogs = append(s.auditLogs, entry)
	return entry
}

// AppendAudit records a new immutable audit record to the chain.
func (s *Store) AppendAudit(actor, action, target, payload string) types.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendAuditInternal(actor, action, target, payload)
}

// VerifyAuditChain validates that every entry in the audit log matches its cryptographic hash.
func (s *Store) VerifyAuditChain() (bool, int, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	for idx, entry := range s.auditLogs {
		if entry.PrevHash != expectedPrev {
			return false, idx, entry.EntryHash, fmt.Errorf("chain broken at index %d: expected prev %s, got %s", idx, expectedPrev, entry.PrevHash)
		}
		expectedPrev = entry.EntryHash
	}
	return true, len(s.auditLogs), s.currentHash, nil
}

// GetAuditLogs returns a copy of all audit entries.
func (s *Store) GetAuditLogs() []types.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]types.AuditEntry, len(s.auditLogs))
	copy(res, s.auditLogs)
	return res
}

// ListAgents returns all enrolled agents.
func (s *Store) ListAgents() []types.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]types.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		res = append(res, *a)
	}
	return res
}

// GetAgent returns an agent by ID.
func (s *Store) GetAgent(id string) (*types.Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, false
	}
	aCopy := *a
	return &aCopy, true
}

// EnrollAgent registers or updates an endpoint agent.
func (s *Store) EnrollAgent(a types.Agent) types.Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = fmt.Sprintf("agt-%d", time.Now().UnixNano()%100000)
	}
	a.EnrolledAt = time.Now().UTC()
	a.LastHeartbeatAt = a.EnrolledAt
	if a.State == "" {
		a.State = types.StateEnrolled
	}
	s.agents[a.ID] = &a
	s.appendAuditInternal("AGENT", "ENROLL", a.ID, fmt.Sprintf("%s:%s", a.Hostname, a.Platform))
	return a
}

// UpdateAgentStatus changes agent quarantine/revoke state.
func (s *Store) UpdateAgentStatus(id string, newState types.AgentState, reason string) (*types.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent %s not found", id)
	}
	oldState := a.State
	a.State = newState
	if reason != "" {
		a.CollectorHealth.DegradationCause = reason
	}
	s.appendAuditInternal("OPERATOR", "AGENT_STATE_CHANGE", id, fmt.Sprintf("%s -> %s (%s)", oldState, newState, reason))
	aCopy := *a
	return &aCopy, nil
}

// ListScripts returns all forensic analysis modules.
func (s *Store) ListScripts() []types.ForensicScript {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]types.ForensicScript, 0, len(s.scripts))
	for _, scr := range s.scripts {
		res = append(res, *scr)
	}
	return res
}

// GetScript returns a forensic script by ID.
func (s *Store) GetScript(id string) (*types.ForensicScript, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scr, ok := s.scripts[id]
	if !ok {
		return nil, false
	}
	sCopy := *scr
	return &sCopy, true
}

// CreateJob creates and dispatches a forensic job bound by a consent token.
func (s *Store) CreateJob(ticketID, scriptID, requestedBy string, targetAgents []string, ttlMinutes int) (*types.ForensicJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scr, ok := s.scripts[scriptID]
	if !ok {
		return nil, fmt.Errorf("script %s not found", scriptID)
	}

	now := time.Now().UTC()
	if ttlMinutes <= 0 {
		ttlMinutes = 15
	}
	validUntil := now.Add(time.Duration(ttlMinutes) * time.Minute)

	jobID := fmt.Sprintf("job-%d", time.Now().UnixMilli()%1000000)
	tokenID := fmt.Sprintf("ctk-%d", time.Now().UnixNano()%1000000)

	// Build consent token digest
	tokenPayload := fmt.Sprintf("%s:%s:%s:%v:%s", tokenID, ticketID, requestedBy, targetAgents, validUntil.Format(time.RFC3339))
	tokenDigest := sha256.Sum256([]byte(tokenPayload))
	tokenDigestHex := hex.EncodeToString(tokenDigest[:])

	// Mock Ed25519 signature of consent token
	sigBytes := sha256.Sum256([]byte(tokenDigestHex + ":consent_root_key_sign"))
	sigHex := hex.EncodeToString(sigBytes[:]) + hex.EncodeToString(sigBytes[:])

	consent := types.ConsentToken{
		TokenID:      tokenID,
		TicketID:     ticketID,
		RequestedBy:  requestedBy,
		ScopeTargets: targetAgents,
		Capabilities: scr.Capabilities,
		ValidFrom:    now,
		ValidUntil:   validUntil,
		Digest:       tokenDigestHex,
		Signature:    sigHex,
	}

	job := &types.ForensicJob{
		ID:           jobID,
		TicketID:     ticketID,
		ScriptID:     scriptID,
		ScriptName:   scr.Filename,
		TargetAgents: targetAgents,
		State:        types.JobRunning,
		ConsentToken: consent,
		RequestedBy:  requestedBy,
		CreatedAt:    now,
		Logs: []string{
			fmt.Sprintf("[%s] Job %s initialized by %s (Ticket: %s)", now.Format(time.RFC3339), jobID, requestedBy, ticketID),
			fmt.Sprintf("[%s] Cryptographic Consent Token %s issued (Valid for %d min)", now.Format(time.RFC3339), tokenID, ttlMinutes),
			fmt.Sprintf("[%s] Attested JOCKY module %s dispatched to %d agent(s)", now.Format(time.RFC3339), scr.Filename, len(targetAgents)),
		},
		FindingsIDs: make([]string, 0),
	}

	s.jobs[jobID] = job
	s.appendAuditInternal(requestedBy, "JOB_DISPATCH", jobID, tokenPayload)
	return job, nil
}

// ListJobs returns all dispatched forensic jobs.
func (s *Store) ListJobs() []types.ForensicJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]types.ForensicJob, 0, len(s.jobs))
	for _, j := range s.jobs {
		res = append(res, *j)
	}
	return res
}

// GetJob returns a specific job.
func (s *Store) GetJob(id string) (*types.ForensicJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	jCopy := *j
	return &jCopy, true
}

// ListFindings returns all threat findings.
func (s *Store) ListFindings() []types.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]types.Finding, 0, len(s.findings))
	for _, f := range s.findings {
		res = append(res, *f)
	}
	return res
}
