import { Agent, ForensicJob, Finding, ForensicScript, AuditEntry, ManagerHealth, AgentState } from './types';

const API_BASE = '/api/v1';

export async function fetchHealth(): Promise<ManagerHealth> {
  const res = await fetch('/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchAgents(): Promise<Agent[]> {
  const res = await fetch(`${API_BASE}/agents`);
  if (!res.ok) throw new Error('Failed to fetch agents');
  const data = await res.json();
  return data.agents || [];
}

export async function updateAgentStatus(agentId: string, state: AgentState, reason: string): Promise<Agent> {
  const res = await fetch(`${API_BASE}/agents/${agentId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ state, reason }),
  });
  if (!res.ok) throw new Error('Failed to update agent status');
  return res.json();
}

export async function fetchScripts(): Promise<ForensicScript[]> {
  const res = await fetch(`${API_BASE}/scripts`);
  if (!res.ok) throw new Error('Failed to fetch forensic scripts');
  const data = await res.json();
  return data.scripts || [];
}

export async function fetchJobs(): Promise<ForensicJob[]> {
  const res = await fetch(`${API_BASE}/jobs`);
  if (!res.ok) throw new Error('Failed to fetch jobs');
  const data = await res.json();
  return data.jobs || [];
}

export async function createJob(payload: {
  ticket_id: string;
  script_id: string;
  requested_by: string;
  target_agents: string[];
  ttl_minutes: number;
}): Promise<ForensicJob> {
  const res = await fetch(`${API_BASE}/jobs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to dispatch job');
  return res.json();
}

export async function fetchFindings(): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/findings`);
  if (!res.ok) throw new Error('Failed to fetch findings');
  const data = await res.json();
  return data.findings || [];
}

export async function fetchAuditLogs(): Promise<AuditEntry[]> {
  const res = await fetch(`${API_BASE}/audit`);
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  const data = await res.json();
  return data.entries || [];
}

export async function verifyAuditChain(): Promise<{ verified: boolean; entries: number; head_hash: string; error?: string }> {
  const res = await fetch(`${API_BASE}/audit/verify`);
  if (!res.ok) throw new Error('Audit verification failed');
  return res.json();
}

export async function verifyJKMBinary(fileBytes: Uint8Array): Promise<{
  valid_magic: boolean;
  container_type: string;
  total_bytes: number;
  sha256: string;
  header_size: number;
  has_signature: boolean;
  verified_at: string;
  status: string;
}> {
  const res = await fetch(`${API_BASE}/verify-jkm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: fileBytes,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Verification failed' }));
    throw new Error(err.error || 'Verification failed');
  }
  return res.json();
}
