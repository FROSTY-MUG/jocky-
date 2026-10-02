export type AgentPlatform = 'windows' | 'linux' | 'darwin';
export type AgentState = 'enrolled' | 'healthy' | 'degraded' | 'quarantined' | 'revoked';
export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type TrustLevel = 'full' | 'degraded' | 'suspect';
export type JobState = 'draft' | 'pending_approval' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface CollectorHealth {
  etw_available?: boolean;
  bpf_available?: boolean;
  tpm_attested?: boolean;
  mft_available?: boolean;
  degradation_cause?: string;
}

export interface Agent {
  id: string;
  hostname: string;
  platform: AgentPlatform;
  os_version: string;
  arch: string;
  agent_version: string;
  variant_index: number;
  build_seed: number;
  code_hash: string;
  semantics_hash: string;
  public_key: string;
  consent_root_key: string;
  capabilities: string[];
  state: AgentState;
  collector_health: CollectorHealth;
  cpu_pct: number;
  memory_rss_mb: number;
  enrolled_at: string;
  last_heartbeat_at: string;
  last_seen_ip: string;
}

export interface ForensicScript {
  id: string;
  module: string;
  filename: string;
  description: string;
  source_code: string;
  capabilities: string[];
  denylist_safe: boolean;
  code_hash: string;
}

export interface ConsentToken {
  token_id: string;
  ticket_id: string;
  requested_by: string;
  approved_by?: string;
  scope_targets: string[];
  capabilities: string[];
  valid_from: string;
  valid_until: string;
  signature: string;
  digest: string;
}

export interface ForensicJob {
  id: string;
  ticket_id: string;
  script_id: string;
  script_name: string;
  target_agents: string[];
  state: JobState;
  consent_token: ConsentToken;
  requested_by: string;
  created_at: string;
  completed_at?: string;
  logs: string[];
  findings_ids: string[];
}

export interface Finding {
  id: string;
  job_id: string;
  agent_id: string;
  hostname: string;
  title: string;
  detail: string;
  severity: ThreatSeverity;
  trust: TrustLevel;
  mitre_technique: string;
  artifact_json: string;
  evidence_ref: string;
  observed_at: string;
  status: 'open' | 'triaged' | 'dismissed';
}

export interface AuditEntry {
  index: number;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  payload_hash: string;
  prev_hash: string;
  entry_hash: string;
}

export interface ManagerHealth {
  status: string;
  service: string;
  version: string;
  platform: string;
  timestamp: string;
  agent_count: number;
  job_count: number;
  audit_entries: number;
  audit_verified: boolean;
  audit_head_hash: string;
  audit_status: string;
}
