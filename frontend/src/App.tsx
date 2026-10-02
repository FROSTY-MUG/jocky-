import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { OverviewTab } from './components/OverviewTab';
import { AgentsTab } from './components/AgentsTab';
import { ScriptIDETab } from './components/ScriptIDETab';
import { JobsTab } from './components/JobsTab';
import { FindingsTab } from './components/FindingsTab';
import { VerifierTab } from './components/VerifierTab';
import { AuditTab } from './components/AuditTab';
import { 
  Agent, 
  ForensicJob, 
  Finding, 
  ForensicScript, 
  AuditEntry, 
  ManagerHealth, 
  AgentState 
} from './types';
import { 
  fetchHealth, 
  fetchAgents, 
  fetchScripts, 
  fetchJobs, 
  fetchFindings, 
  fetchAuditLogs,
  updateAgentStatus as apiUpdateStatus,
  createJob as apiCreateJob
} from './api';

// Fallback scripts in case manager is offline
const FALLBACK_SCRIPTS: ForensicScript[] = [
  {
    id: 'scr-byovd',
    module: 'detect_byovd',
    filename: 'detect_byovd.jky',
    description: 'Scans loaded kernel drivers against known vulnerable driver blocklists (BYOVD detection).',
    capabilities: ['driver_inspect', 'read_memory_safe'],
    denylist_safe: true,
    code_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    source_code: `// detect_byovd.jky - Vulnerable driver identification
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
    id: 'scr-inject',
    module: 'detect_inject',
    filename: 'detect_inject.jky',
    description: 'Inspects process address space for unbacked executable memory pages indicative of shellcode injection.',
    capabilities: ['read_process_memory_safe', 'query_virtual_memory'],
    denylist_safe: true,
    code_hash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
    source_code: `// detect_inject.jky - Memory injection & unbacked page scanner
fn scan_page_protections(page_type: i64, page_protect: i64) -> i64 {
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
    id: 'scr-syscall',
    module: 'detect_syscall',
    filename: 'detect_syscall.jky',
    description: 'Audits NTDLL stub integrity to identify inline hooks or direct syscall invocations.',
    capabilities: ['syscall_audit'],
    denylist_safe: true,
    code_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    source_code: `// detect_syscall.jky - Direct syscall and hook verifier
fn audit_ntdll_stub(stub_byte_0: i64, stub_byte_1: i64) -> i64 {
    if (stub_byte_0 != 76) {
        return 1; // Hooked syscall entry point
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
    id: 'scr-process',
    module: 'process',
    filename: 'process.jky',
    description: 'Validates process tree lineage and parent-child consistency without invasive debugging.',
    capabilities: ['process_enumerate'],
    denylist_safe: true,
    code_hash: '871653cc2208675d79bf33528b1dd320b722cdd188047a9b0c4b37b1931a1a3c',
    source_code: `// process.jky - Process verification primitive
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
    id: 'scr-memory',
    module: 'memory',
    filename: 'memory.jky',
    description: 'Acquires memory block hashes for dead-box forensic integrity correlation.',
    capabilities: ['memory_hashing'],
    denylist_safe: true,
    code_hash: 'd41d8cd98f00b204e9800998ecf8427e',
    source_code: `// memory.jky - Read-only memory region hasher
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
    id: 'scr-network',
    module: 'network',
    filename: 'network.jky',
    description: 'Cross-correlates established TCP/UDP network sockets with active listening process PIDs.',
    capabilities: ['socket_inspect'],
    denylist_safe: true,
    code_hash: 'c4ca4238a0b923820dcc509a6f75849b',
    source_code: `// network.jky - Socket to process correlation
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
];

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [managerOnline, setManagerOnline] = useState<boolean>(false);
  const [health, setHealth] = useState<ManagerHealth | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [scripts, setScripts] = useState<ForensicScript[]>(FALLBACK_SCRIPTS);
  const [jobs, setJobs] = useState<ForensicJob[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);

  // Composer handoff parameters
  const [preselectedScriptId, setPreselectedScriptId] = useState<string>('');
  const [preselectedAgentId, setPreselectedAgentId] = useState<string>('');

  const loadData = async () => {
    try {
      const h = await fetchHealth();
      setHealth(h);
      setManagerOnline(true);

      const [a, s, j, f, au] = await Promise.all([
        fetchAgents(),
        fetchScripts(),
        fetchJobs(),
        fetchFindings(),
        fetchAuditLogs(),
      ]);

      setAgents(a);
      if (s.length > 0) setScripts(s);
      setJobs(j);
      setFindings(f);
      setAuditLogs(au);
    } catch (err) {
      // If manager is not reachable, load safe local demo state
      setManagerOnline(false);
      setHealth(null);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleUpdateStatus = async (agentId: string, state: AgentState, reason: string) => {
    try {
      if (managerOnline) {
        await apiUpdateStatus(agentId, state, reason);
        await loadData();
      } else {
        setAgents((prev) =>
          prev.map((a) => (a.id === agentId ? { ...a, state } : a))
        );
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDispatchJob = async (payload: {
    ticket_id: string;
    script_id: string;
    requested_by: string;
    target_agents: string[];
    ttl_minutes: number;
  }) => {
    if (managerOnline) {
      await apiCreateJob(payload);
      await loadData();
    } else {
      const scr = scripts.find((s) => s.id === payload.script_id);
      const newJob: ForensicJob = {
        id: `job-${Date.now() % 100000}`,
        ticket_id: payload.ticket_id,
        script_id: payload.script_id,
        script_name: scr?.filename || 'custom.jky',
        target_agents: payload.target_agents,
        state: 'running',
        consent_token: {
          token_id: `ctk-${Date.now()}`,
          ticket_id: payload.ticket_id,
          requested_by: payload.requested_by,
          scope_targets: payload.target_agents,
          capabilities: scr?.capabilities || [],
          valid_from: new Date().toISOString(),
          valid_until: new Date(Date.now() + payload.ttl_minutes * 60000).toISOString(),
          signature: 'ed25519_attested_sig_4c9a...',
          digest: 'sha256_consent_digest_8f12...',
        },
        requested_by: payload.requested_by,
        created_at: new Date().toISOString(),
        logs: [
          `[${new Date().toISOString()}] Job initialized by ${payload.requested_by}`,
          `[${new Date().toISOString()}] Cryptographic Consent Token issued for ${payload.target_agents.length} target(s)`,
          `[${new Date().toISOString()}] Module ${scr?.filename} dispatched into agent process spaces`,
        ],
        findings_ids: [],
      };
      setJobs([newJob, ...jobs]);
    }
  };

  const handleHandoffToComposer = (script: ForensicScript) => {
    setPreselectedScriptId(script.id);
    setActiveTab('jobs');
  };

  const handleHandoffForAgent = (agentId: string) => {
    setPreselectedAgentId(agentId);
    setActiveTab('jobs');
  };

  return (
    <div className="min-h-screen flex bg-[#070a12] text-gray-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        counts={{
          agents: agents.length,
          jobs: jobs.length,
          findings: findings.length,
          audit: auditLogs.length,
        }}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <Header
          health={health}
          online={managerOnline}
          activeTab={activeTab}
        />

        <main className="flex-1 p-8 overflow-y-auto">
          {activeTab === 'overview' && (
            <OverviewTab
              agents={agents}
              jobs={jobs}
              findings={findings}
              health={health}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'agents' && (
            <AgentsTab
              agents={agents}
              onUpdateStatus={handleUpdateStatus}
              onComposeJobForAgent={handleHandoffForAgent}
            />
          )}

          {activeTab === 'script-ide' && (
            <ScriptIDETab
              scripts={scripts}
              onDispatchScript={handleHandoffToComposer}
            />
          )}

          {activeTab === 'jobs' && (
            <JobsTab
              agents={agents}
              scripts={scripts}
              jobs={jobs}
              onDispatchJob={handleDispatchJob}
              preselectedScriptId={preselectedScriptId}
              preselectedAgentId={preselectedAgentId}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsTab findings={findings} />
          )}

          {activeTab === 'verifier' && (
            <VerifierTab />
          )}

          {activeTab === 'audit' && (
            <AuditTab auditLogs={auditLogs} />
          )}
        </main>
      </div>
    </div>
  );
}
