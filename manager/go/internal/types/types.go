package types

import "time"

// AgentPlatform represents the operating system of an agent.
type AgentPlatform string

const (
	PlatformWindows AgentPlatform = "windows"
	PlatformLinux   AgentPlatform = "linux"
	PlatformDarwin  AgentPlatform = "darwin"
)

// AgentState represents the operational status of an agent.
type AgentState string

const (
	StateEnrolled    AgentState = "enrolled"
	StateHealthy     AgentState = "healthy"
	StateDegraded    AgentState = "degraded"
	StateQuarantined AgentState = "quarantined"
	StateRevoked     AgentState = "revoked"
)

// CollectorHealth maps collector subsystems (e.g. etw, bpf) to operational status.
type CollectorHealth struct {
	ETWAvailable     bool   `json:"etw_available"`
	BPFAvailable     bool   `json:"bpf_available"`
	TPMAttested      bool   `json:"tpm_attested"`
	MFTAvailable     bool   `json:"mft_available"`
	DegradationCause string `json:"degradation_cause,omitempty"`
}

// Agent represents an enrolled endpoint running a JOCKY diversified runtime.
type Agent struct {
	ID              string          `json:"id"`
	Hostname        string          `json:"hostname"`
	Platform        AgentPlatform   `json:"platform"`
	OSVersion       string          `json:"os_version"`
	Arch            string          `json:"arch"`
	AgentVersion    string          `json:"agent_version"`
	VariantIndex    int             `json:"variant_index"`
	BuildSeed       uint64          `json:"build_seed"`
	CodeHash        string          `json:"code_hash"`
	SemanticsHash   string          `json:"semantics_hash"`
	PublicKey       string          `json:"public_key"`
	ConsentRootKey  string          `json:"consent_root_key"`
	Capabilities    []string        `json:"capabilities"`
	State           AgentState      `json:"state"`
	CollectorHealth CollectorHealth `json:"collector_health"`
	CPUPct          float64         `json:"cpu_pct"`
	MemoryRSSMB     float64         `json:"memory_rss_mb"`
	EnrolledAt      time.Time       `json:"enrolled_at"`
	LastHeartbeatAt time.Time       `json:"last_heartbeat_at"`
	LastSeenIP      string          `json:"last_seen_ip"`
}

// ForensicScript represents a registered .jky analysis module.
type ForensicScript struct {
	ID           string   `json:"id"`
	Module       string   `json:"module"`
	Filename     string   `json:"filename"`
	Description  string   `json:"description"`
	SourceCode   string   `json:"source_code"`
	Capabilities []string `json:"capabilities"`
	DenylistSafe bool     `json:"denylist_safe"`
	CodeHash     string   `json:"code_hash"`
}

// JobState represents the execution lifecycle of a forensic job.
type JobState string

const (
	JobDraft           JobState = "draft"
	JobPendingApproval JobState = "pending_approval"
	JobRunning         JobState = "running"
	JobSucceeded       JobState = "succeeded"
	JobFailed          JobState = "failed"
	JobCancelled       JobState = "cancelled"
)

// ConsentToken represents an RFC 8949 consent ticket bound to an action.
type ConsentToken struct {
	TokenID       string    `json:"token_id"`
	TicketID      string    `json:"ticket_id"`
	RequestedBy   string    `json:"requested_by"`
	ApprovedBy    string    `json:"approved_by,omitempty"`
	ScopeTargets  []string  `json:"scope_targets"`
	Capabilities  []string  `json:"capabilities"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	Signature     string    `json:"signature"`
	Digest        string    `json:"digest"`
}

// ForensicJob is an attested unit of forensic analysis dispatched to agents.
type ForensicJob struct {
	ID           string       `json:"id"`
	TicketID     string       `json:"ticket_id"`
	ScriptID     string       `json:"script_id"`
	ScriptName   string       `json:"script_name"`
	TargetAgents []string     `json:"target_agents"`
	State        JobState     `json:"state"`
	ConsentToken ConsentToken `json:"consent_token"`
	RequestedBy  string       `json:"requested_by"`
	CreatedAt    time.Time    `json:"created_at"`
	CompletedAt  *time.Time   `json:"completed_at,omitempty"`
	Logs         []string     `json:"logs"`
	FindingsIDs  []string     `json:"findings_ids"`
}

// ThreatSeverity represents the criticality of a forensic finding.
type ThreatSeverity string

const (
	SeverityCritical ThreatSeverity = "critical"
	SeverityHigh     ThreatSeverity = "high"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityLow      ThreatSeverity = "low"
	SeverityInfo     ThreatSeverity = "info"
)

// TrustLevel represents the integrity confidence of forensic evidence.
type TrustLevel string

const (
	TrustFull     TrustLevel = "full"
	TrustDegraded TrustLevel = "degraded"
	TrustSuspect  TrustLevel = "suspect"
)

// Finding represents a captured DFIR anomaly, suspicious memory region, or driver.
type Finding struct {
	ID             string         `json:"id"`
	JobID          string         `json:"job_id"`
	AgentID        string         `json:"agent_id"`
	Hostname       string         `json:"hostname"`
	Title          string         `json:"title"`
	Detail         string         `json:"detail"`
	Severity       ThreatSeverity `json:"severity"`
	Trust          TrustLevel     `json:"trust"`
	MITRETechnique string         `json:"mitre_technique"`
	ArtifactJSON   string         `json:"artifact_json"`
	EvidenceRef    string         `json:"evidence_ref"`
	ObservedAt     time.Time      `json:"observed_at"`
	Status         string         `json:"status"` // open, triaged, dismissed
}

// AuditEntry is a tamper-evident, cryptographically chained event log.
type AuditEntry struct {
	Index       int64     `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	PayloadHash string    `json:"payload_hash"`
	PrevHash    string    `json:"prev_hash"`
	EntryHash   string    `json:"entry_hash"`
}
