import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  Cpu, 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  Key, 
  CheckCircle2, 
  AlertCircle, 
  XCircle,
  Terminal,
  Activity,
  Server
} from 'lucide-react';
import { Agent, AgentState } from '../types';

interface AgentsTabProps {
  agents: Agent[];
  onUpdateStatus: (agentId: string, state: AgentState, reason: string) => Promise<void>;
  onComposeJobForAgent: (agentId: string) => void;
}

export const AgentsTab: React.FC<AgentsTabProps> = ({
  agents,
  onUpdateStatus,
  onComposeJobForAgent,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [stateFilter, setStateFilter] = useState<string>('all');
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(agents[0] || null);
  const [quarantineModalOpen, setQuarantineModalOpen] = useState(false);
  const [quarantineReason, setQuarantineReason] = useState('');

  const filteredAgents = agents.filter((a) => {
    const matchesSearch =
      a.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.os_version.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesState = stateFilter === 'all' || a.state === stateFilter;
    return matchesSearch && matchesState;
  });

  const handleQuarantine = async () => {
    if (!selectedAgent) return;
    const newState: AgentState = selectedAgent.state === 'quarantined' ? 'healthy' : 'quarantined';
    await onUpdateStatus(selectedAgent.id, newState, quarantineReason || 'Operator manual policy action');
    setQuarantineModalOpen(false);
    setQuarantineReason('');
  };

  return (
    <div className="space-y-6">
      {/* Control Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-[#0c1322] border border-gray-800 rounded-xl">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search by hostname, ID, OS..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-gray-900/80 border border-gray-700/80 rounded-lg pl-9 pr-4 py-2 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <span className="text-xs text-gray-400 flex items-center space-x-1">
            <Filter className="w-3.5 h-3.5" />
            <span>State:</span>
          </span>
          {['all', 'healthy', 'degraded', 'quarantined'].map((st) => (
            <button
              key={st}
              onClick={() => setStateFilter(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                stateFilter === st
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800'
                  : 'bg-gray-900/60 text-gray-400 hover:bg-gray-800 border border-transparent'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Layout: Table + Detail Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Table of Agents */}
        <div className="xl:col-span-2 bg-[#0c1322] border border-gray-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-[#090e1a] text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Endpoint Host</th>
                  <th className="py-3 px-4">Platform & Variant</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Capabilities</th>
                  <th className="py-3 px-4">Telemetry</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {filteredAgents.map((agent) => {
                  const isSelected = selectedAgent?.id === agent.id;
                  return (
                    <tr
                      key={agent.id}
                      onClick={() => setSelectedAgent(agent)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-950/30 border-l-2 border-l-cyan-400'
                          : 'hover:bg-gray-900/40'
                      }`}
                    >
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-gray-100 flex items-center space-x-2">
                          <Server className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{agent.hostname}</span>
                        </div>
                        <span className="text-[10px] text-gray-500 font-mono">{agent.id}</span>
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        <span className="text-gray-200 capitalize">{agent.platform}</span>
                        <div className="text-[10px] text-cyan-400 mt-0.5">
                          Variant #{agent.variant_index} (Seed: {agent.build_seed})
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase font-bold ${
                            agent.state === 'healthy'
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                              : agent.state === 'degraded'
                              ? 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                              : 'bg-rose-950/80 text-rose-400 border border-rose-800/60'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              agent.state === 'healthy'
                                ? 'bg-emerald-400'
                                : agent.state === 'degraded'
                                ? 'bg-amber-400'
                                : 'bg-rose-400'
                            }`}
                          ></span>
                          <span>{agent.state}</span>
                        </span>
                      </td>

                      <td className="py-3.5 px-4">
                        <div className="flex flex-wrap gap-1">
                          {agent.capabilities.map((c) => (
                            <span
                              key={c}
                              className="px-1.5 py-0.5 bg-gray-800/80 text-gray-300 rounded text-[9px] font-mono"
                            >
                              {c}
                            </span>
                          ))}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px] text-gray-400">
                        <div>CPU: {agent.cpu_pct.toFixed(1)}%</div>
                        <div>RSS: {agent.memory_rss_mb.toFixed(0)} MB</div>
                      </td>

                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onComposeJobForAgent(agent.id);
                          }}
                          className="px-2.5 py-1 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/60 text-cyan-300 text-[11px] font-semibold rounded transition"
                        >
                          Dispatch
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Agent Detail Panel */}
        {selectedAgent && (
          <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-5">
            <div className="border-b border-gray-800 pb-3 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-gray-100 flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>{selectedAgent.hostname}</span>
                </h3>
                <p className="text-[11px] text-gray-400 font-mono mt-0.5">{selectedAgent.id}</p>
              </div>
              <button
                onClick={() => setQuarantineModalOpen(true)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold font-mono border transition ${
                  selectedAgent.state === 'quarantined'
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800 hover:bg-emerald-900'
                    : 'bg-rose-950/60 text-rose-400 border-rose-800 hover:bg-rose-900'
                }`}
              >
                {selectedAgent.state === 'quarantined' ? 'Reinstate Host' : 'Quarantine Host'}
              </button>
            </div>

            {/* Operating System & Architecture */}
            <div className="space-y-2 text-xs">
              <div className="text-gray-400 font-medium">OS Environment:</div>
              <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg text-gray-200 font-mono text-[11px] leading-relaxed">
                <div>{selectedAgent.os_version}</div>
                <div className="text-gray-500 mt-1">Arch: {selectedAgent.arch} • IP: {selectedAgent.last_seen_ip}</div>
              </div>
            </div>

            {/* Collector Health Panel (as defined in §2.2 of 06-frontend-dashboard.md) */}
            <div className="space-y-2 text-xs">
              <div className="text-gray-400 font-medium flex items-center space-x-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Collector Subsystem Health:</span>
              </div>
              <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg space-y-2">
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span>ETW Kernel Provider:</span>
                  <span className={selectedAgent.collector_health.etw_available ? 'text-emerald-400' : 'text-rose-400'}>
                    {selectedAgent.collector_health.etw_available ? 'AVAILABLE' : 'SILENCED / DEGRADED'}
                  </span>
                </div>
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span>TPM 2.0 Attestation:</span>
                  <span className={selectedAgent.collector_health.tpm_attested ? 'text-emerald-400' : 'text-gray-500'}>
                    {selectedAgent.collector_health.tpm_attested ? 'ATTESTED' : 'UNSUPPORTED'}
                  </span>
                </div>
                {selectedAgent.collector_health.degradation_cause && (
                  <div className="p-2 bg-rose-950/40 border border-rose-800/40 rounded text-[11px] text-rose-300 font-mono mt-1">
                    Warning: {selectedAgent.collector_health.degradation_cause}
                  </div>
                )}
              </div>
            </div>

            {/* Polymorphic Attestation Evidence */}
            <div className="space-y-2 text-xs">
              <div className="text-gray-400 font-medium flex items-center space-x-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-400" />
                <span>Polymorphic Binary Manifest:</span>
              </div>
              <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg text-gray-300 font-mono text-[10px] space-y-1.5 break-all">
                <div>
                  <span className="text-gray-500">Variant Index:</span> #{selectedAgent.variant_index} (Seed: {selectedAgent.build_seed})
                </div>
                <div>
                  <span className="text-gray-500">Code Hash (BLAKE3):</span> {selectedAgent.code_hash.substring(0, 32)}...
                </div>
                <div>
                  <span className="text-gray-500">Semantics Hash:</span> {selectedAgent.semantics_hash.substring(0, 32)}...
                </div>
                <div>
                  <span className="text-gray-500">Public Key (Ed25519):</span> {selectedAgent.public_key.substring(0, 32)}...
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Quarantine Modal */}
      {quarantineModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#0e1628] border border-gray-700 max-w-md w-full rounded-2xl p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-gray-100 flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <span>Confirm Quarantine / State Change</span>
            </h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Quarantining <strong>{selectedAgent?.hostname}</strong> immediately isolates it from routine telemetry networks, revokes active consent tokens, and locks down execution bounds.
            </p>
            <div>
              <label className="text-xs font-semibold text-gray-300 block mb-1">Audit Log Reason:</label>
              <input
                type="text"
                placeholder="e.g. Unbacked RWX memory detected in lsass.exe"
                value={quarantineReason}
                onChange={(e) => setQuarantineReason(e.target.value)}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-xs text-gray-200 focus:outline-none focus:border-rose-500 font-mono"
              />
            </div>
            <div className="flex justify-end space-x-3 pt-2">
              <button
                onClick={() => setQuarantineModalOpen(false)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-semibold rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={handleQuarantine}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-lg"
              >
                Apply State Change
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
