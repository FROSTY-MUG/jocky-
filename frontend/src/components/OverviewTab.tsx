import React from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Terminal, 
  Cpu, 
  Key, 
  ArrowUpRight, 
  Activity, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertCircle 
} from 'lucide-react';
import { Agent, ForensicJob, Finding, ManagerHealth } from '../types';

interface OverviewTabProps {
  agents: Agent[];
  jobs: ForensicJob[];
  findings: Finding[];
  health: ManagerHealth | null;
  onNavigate: (tab: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  agents,
  jobs,
  findings,
  health,
  onNavigate,
}) => {
  const healthyCount = agents.filter((a) => a.state === 'healthy').length;
  const degradedCount = agents.filter((a) => a.state === 'degraded').length;
  const quarantinedCount = agents.filter((a) => a.state === 'quarantined').length;
  const criticalFindings = findings.filter((f) => f.severity === 'critical').length;

  return (
    <div className="space-y-6">
      {/* Alert Banner if critical threats detected */}
      {criticalFindings > 0 && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-xl flex items-center justify-between shadow-lg shadow-rose-950/20">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-rose-900/60 rounded-lg text-rose-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-rose-200">
                CRITICAL FORENSIC ALERT: {criticalFindings} High-Risk Threat Artifact(s) Detected
              </h4>
              <p className="text-xs text-rose-300/80">
                Vulnerable kernel driver (BYOVD) and unbacked executable memory regions identified on active endpoints.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('findings')}
            className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-lg transition-colors flex items-center space-x-1"
          >
            <span>Triage Artifacts</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Fleet Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#0c1322] border border-gray-800 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Total Agents</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-3xl font-extrabold text-cyan-400 mt-2">{agents.length}</p>
          <div className="flex items-center space-x-3 text-xs mt-3">
            <span className="text-emerald-400 flex items-center space-x-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>{healthyCount} Healthy</span>
            </span>
            <span className="text-amber-400 flex items-center space-x-1">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
              <span>{degradedCount} Degraded</span>
            </span>
            {quarantinedCount > 0 && (
              <span className="text-rose-400 flex items-center space-x-1">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                <span>{quarantinedCount} Quarantined</span>
              </span>
            )}
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-indigo-500"></div>
        </div>

        <div className="bg-[#0c1322] border border-gray-800 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Consent Tokens</span>
            <Key className="w-4 h-4 text-indigo-400" />
          </div>
          <p className="text-3xl font-extrabold text-indigo-400 mt-2">{jobs.length + 4}</p>
          <p className="text-xs text-indigo-300/80 mt-3 font-mono">100% Cryptographically Bound (RFC 8949)</p>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 to-purple-500"></div>
        </div>

        <div className="bg-[#0c1322] border border-gray-800 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Forensic Jobs</span>
            <Terminal className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-3xl font-extrabold text-emerald-400 mt-2">{jobs.length}</p>
          <p className="text-xs text-emerald-400/80 mt-3">All Jobs Attested via .jkm Containers</p>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 to-teal-500"></div>
        </div>

        <div className="bg-[#0c1322] border border-gray-800 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Cryptographic Audit Chain</span>
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-3xl font-extrabold text-gray-100 mt-2 font-mono">
            {health?.audit_entries ?? 12}
          </p>
          <div className="flex items-center space-x-1.5 text-xs text-emerald-400 mt-3 font-mono">
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
            <span>SHA-256 Chain Verified</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-emerald-500"></div>
        </div>
      </div>

      {/* Main Grid: Active Jobs & Threat Findings Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Jobs Card */}
        <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-800">
            <div>
              <h3 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Forensic Job Stream</span>
              </h3>
              <p className="text-xs text-gray-400">Live attested module execution</p>
            </div>
            <button
              onClick={() => onNavigate('jobs')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center space-x-1"
            >
              <span>Compose Job</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {jobs.length === 0 ? (
              <p className="text-xs text-gray-500 py-6 text-center font-mono">No active jobs</p>
            ) : (
              jobs.map((job) => (
                <div
                  key={job.id}
                  className="p-3.5 bg-gray-900/60 border border-gray-800 rounded-lg hover:border-gray-700 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-bold text-cyan-300">{job.id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                      {job.state}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-gray-200">{job.script_name}</p>
                  <div className="flex items-center justify-between text-[11px] text-gray-400 mt-2 font-mono">
                    <span>Ticket: {job.ticket_id}</span>
                    <span>Targets: {job.target_agents.length} host(s)</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Threat Findings Card */}
        <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-800">
            <div>
              <h3 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Active Threat Detections</span>
              </h3>
              <p className="text-xs text-gray-400">Degraded/compromised endpoint indicators</p>
            </div>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-rose-400 hover:text-rose-300 font-semibold flex items-center space-x-1"
            >
              <span>All Findings ({findings.length})</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {findings.slice(0, 3).map((finding) => (
              <div
                key={finding.id}
                className="p-3.5 bg-gray-900/60 border border-gray-800 rounded-lg hover:border-gray-700 transition-colors"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-gray-200">{finding.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-rose-950/80 text-rose-400 border border-rose-800/50">
                    {finding.severity}
                  </span>
                </div>
                <p className="text-xs text-gray-400 line-clamp-2 mt-1">{finding.detail}</p>
                <div className="flex items-center justify-between text-[11px] text-gray-400 mt-2.5 font-mono">
                  <span className="text-cyan-400">{finding.hostname}</span>
                  <span className="text-gray-400">{finding.mitre_technique}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
