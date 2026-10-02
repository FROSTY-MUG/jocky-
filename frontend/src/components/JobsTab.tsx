import React, { useState } from 'react';
import { 
  Terminal, 
  Send, 
  Key, 
  Clock, 
  CheckCircle2, 
  Sliders, 
  Server, 
  FileCode, 
  Layers,
  ArrowRight,
  ShieldCheck
} from 'lucide-react';
import { Agent, ForensicJob, ForensicScript } from '../types';

interface JobsTabProps {
  agents: Agent[];
  scripts: ForensicScript[];
  jobs: ForensicJob[];
  onDispatchJob: (payload: {
    ticket_id: string;
    script_id: string;
    requested_by: string;
    target_agents: string[];
    ttl_minutes: number;
  }) => Promise<void>;
  preselectedScriptId?: string;
  preselectedAgentId?: string;
}

export const JobsTab: React.FC<JobsTabProps> = ({
  agents,
  scripts,
  jobs,
  onDispatchJob,
  preselectedScriptId,
  preselectedAgentId,
}) => {
  const [step, setStep] = useState<number>(1);
  const [selectedScriptId, setSelectedScriptId] = useState<string>(preselectedScriptId || scripts[0]?.id || '');
  const [selectedAgentIds, setSelectedAgentIds] = useState<string[]>(
    preselectedAgentId ? [preselectedAgentId] : agents.slice(0, 2).map((a) => a.id)
  );
  const [ticketId, setTicketId] = useState<string>('INC-2026-0842');
  const [ttlMinutes, setTtlMinutes] = useState<number>(20);
  const [requestedBy, setRequestedBy] = useState<string>('incident-responder-01');
  const [cpuLimit, setCpuLimit] = useState<number>(25);
  const [dispatching, setDispatching] = useState<boolean>(false);
  const [activeJobView, setActiveJobView] = useState<ForensicJob | null>(jobs[0] || null);

  const selectedScript = scripts.find((s) => s.id === selectedScriptId);

  const toggleAgent = (id: string) => {
    if (selectedAgentIds.includes(id)) {
      setSelectedAgentIds(selectedAgentIds.filter((a) => a !== id));
    } else {
      setSelectedAgentIds([...selectedAgentIds, id]);
    }
  };

  const handleDispatch = async () => {
    if (!selectedScriptId || selectedAgentIds.length === 0 || !ticketId) return;
    setDispatching(true);
    try {
      await onDispatchJob({
        ticket_id: ticketId,
        script_id: selectedScriptId,
        requested_by: requestedBy,
        target_agents: selectedAgentIds,
        ttl_minutes: ttlMinutes,
      });
      setStep(1);
    } finally {
      setDispatching(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 5-Step Composer Wizard */}
      <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-5">
        <div className="flex items-center justify-between border-b border-gray-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-gray-100 flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Attested Forensic Job Composer</span>
            </h3>
            <p className="text-xs text-gray-400">Step 3 Consent-Bound Incident Response Wizard</p>
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono">
            {[1, 2, 3, 4, 5].map((s) => (
              <span
                key={s}
                className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-[11px] ${
                  step === s
                    ? 'bg-cyan-500 text-black'
                    : step > s
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'bg-gray-800 text-gray-400'
                }`}
              >
                {s}
              </span>
            ))}
          </div>
        </div>

        {/* Step 1: Script Selection */}
        {step === 1 && (
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-gray-300 uppercase">Step 1: Select Forensic Analysis Script</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {scripts.map((scr) => (
                <div
                  key={scr.id}
                  onClick={() => setSelectedScriptId(scr.id)}
                  className={`p-3 rounded-lg border cursor-pointer transition ${
                    selectedScriptId === scr.id
                      ? 'bg-cyan-950/40 border-cyan-500 shadow-md shadow-cyan-950/50'
                      : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center space-x-2 text-xs font-bold text-cyan-300 font-mono">
                    <FileCode className="w-3.5 h-3.5" />
                    <span>{scr.filename}</span>
                  </div>
                  <p className="text-[11px] text-gray-400 mt-1 line-clamp-2">{scr.description}</p>
                </div>
              ))}
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setStep(2)}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs rounded-lg flex items-center space-x-1"
              >
                <span>Next: Target Scope</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Target Scope Selection */}
        {step === 2 && (
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-gray-300 uppercase">Step 2: Define Target Endpoint Scope</h4>
            <p className="text-xs text-gray-400">Select which enrolled agents will execute this attested job:</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {agents.map((agent) => {
                const isChecked = selectedAgentIds.includes(agent.id);
                return (
                  <div
                    key={agent.id}
                    onClick={() => toggleAgent(agent.id)}
                    className={`p-3 rounded-lg border cursor-pointer flex items-center justify-between transition ${
                      isChecked
                        ? 'bg-cyan-950/40 border-cyan-500'
                        : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div>
                      <div className="text-xs font-semibold text-gray-200 flex items-center space-x-2">
                        <Server className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{agent.hostname}</span>
                      </div>
                      <span className="text-[10px] text-gray-500 font-mono">{agent.id} • {agent.platform}</span>
                    </div>
                    <input
                      type="checkbox"
                      checked={isChecked}
                      readOnly
                      className="w-4 h-4 accent-cyan-500 rounded"
                    />
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between pt-2">
              <button
                onClick={() => setStep(1)}
                className="px-4 py-2 bg-gray-800 text-gray-300 text-xs rounded-lg"
              >
                Back
              </button>
              <button
                onClick={() => setStep(3)}
                disabled={selectedAgentIds.length === 0}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg flex items-center space-x-1"
              >
                <span>Next: Safety Budget</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Safety & Resource Budget */}
        {step === 3 && (
          <div className="space-y-4">
            <h4 className="text-xs font-semibold text-gray-300 uppercase">Step 3: Execution Resource Budget</h4>
            <div className="space-y-3 p-4 bg-gray-900/60 border border-gray-800 rounded-lg">
              <div>
                <div className="flex justify-between text-xs font-mono mb-1">
                  <span className="text-gray-400">Max Host CPU Utilization:</span>
                  <span className="text-cyan-400 font-bold">{cpuLimit}%</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="50"
                  value={cpuLimit}
                  onChange={(e) => setCpuLimit(Number(e.target.value))}
                  className="w-full accent-cyan-500"
                />
              </div>
              <p className="text-[11px] text-gray-400 leading-relaxed">
                JOCKY enforce-budget clamps native execution thread priority to IDLE/LOW to prevent forensic operations from degrading business workloads.
              </p>
            </div>
            <div className="flex justify-between pt-2">
              <button
                onClick={() => setStep(2)}
                className="px-4 py-2 bg-gray-800 text-gray-300 text-xs rounded-lg"
              >
                Back
              </button>
              <button
                onClick={() => setStep(4)}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs rounded-lg flex items-center space-x-1"
              >
                <span>Next: Consent Token</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Consent Token Claims */}
        {step === 4 && (
          <div className="space-y-4">
            <h4 className="text-xs font-semibold text-gray-300 uppercase">Step 4: Cryptographic Consent Token (RFC 8949)</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Incident Ticket ID (Mandatory):</label>
                <input
                  type="text"
                  value={ticketId}
                  onChange={(e) => setTicketId(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-xs text-cyan-200 font-mono focus:outline-none focus:border-cyan-500"
                  placeholder="INC-2026-XXXX"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Consent Validity TTL (Minutes):</label>
                <input
                  type="number"
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value))}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2.5 text-xs text-cyan-200 font-mono focus:outline-none focus:border-cyan-500"
                  min="5"
                  max="120"
                />
              </div>
            </div>
            <div className="p-3 bg-cyan-950/30 border border-cyan-800/40 rounded-lg text-[11px] text-cyan-300/90 font-mono leading-relaxed">
              Token will be digitally signed by Central Manager Consent Root Key. Runtimes strictly reject execution if expired or target host is out of scope.
            </div>
            <div className="flex justify-between pt-2">
              <button
                onClick={() => setStep(3)}
                className="px-4 py-2 bg-gray-800 text-gray-300 text-xs rounded-lg"
              >
                Back
              </button>
              <button
                onClick={() => setStep(5)}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs rounded-lg flex items-center space-x-1"
              >
                <span>Next: Review & Sign</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Step 5: Review & Dispatch */}
        {step === 5 && (
          <div className="space-y-4">
            <h4 className="text-xs font-semibold text-gray-300 uppercase">Step 5: Review & Issue Consent-Bound Job</h4>
            <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-xl space-y-2 text-xs font-mono">
              <div><span className="text-gray-500">Selected Module:</span> <span className="text-cyan-300">{selectedScript?.filename}</span></div>
              <div><span className="text-gray-500">Target Fleet Scope:</span> <span className="text-gray-200">{selectedAgentIds.join(', ')}</span></div>
              <div><span className="text-gray-500">Incident Ticket ID:</span> <span className="text-indigo-300">{ticketId}</span></div>
              <div><span className="text-gray-500">Consent Token TTL:</span> <span className="text-amber-400">{ttlMinutes} Minutes</span></div>
              <div><span className="text-gray-500">CPU Budget Ceiling:</span> <span className="text-emerald-400">≤ {cpuLimit}%</span></div>
            </div>
            <div className="flex justify-between pt-2">
              <button
                onClick={() => setStep(4)}
                className="px-4 py-2 bg-gray-800 text-gray-300 text-xs rounded-lg"
              >
                Back
              </button>
              <button
                onClick={handleDispatch}
                disabled={dispatching}
                className="px-5 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-950/60 flex items-center space-x-2 transition"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>{dispatching ? 'Attesting & Dispatching...' : 'Sign Consent Token & Dispatch'}</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Dispatched Jobs Execution Stream */}
      <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Active & Historical Forensic Jobs</span>
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-2 lg:col-span-1">
            {jobs.map((job) => (
              <div
                key={job.id}
                onClick={() => setActiveJobView(job)}
                className={`p-3 rounded-lg border cursor-pointer transition ${
                  activeJobView?.id === job.id
                    ? 'bg-cyan-950/40 border-cyan-500'
                    : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-300">{job.id}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    {job.state}
                  </span>
                </div>
                <p className="text-xs text-gray-200 mt-1">{job.script_name}</p>
                <p className="text-[10px] text-gray-500 font-mono mt-1">Ticket: {job.ticket_id}</p>
              </div>
            ))}
          </div>

          {/* Active Job Execution Console */}
          {activeJobView && (
            <div className="lg:col-span-2 bg-[#080d18] border border-gray-800 rounded-lg p-4 font-mono text-xs space-y-3">
              <div className="flex justify-between border-b border-gray-800 pb-2">
                <span className="text-cyan-400 font-bold">Execution Log: {activeJobView.id}</span>
                <span className="text-gray-400">{activeJobView.ticket_id}</span>
              </div>
              <div className="space-y-1.5 text-gray-300 max-h-64 overflow-y-auto leading-relaxed">
                {activeJobView.logs.map((line, idx) => (
                  <div key={idx} className="text-emerald-300/90">{line}</div>
                ))}
              </div>
              <div className="pt-2 border-t border-gray-800/80 text-[11px] text-gray-500 space-y-1">
                <div>Consent Token ID: {activeJobView.consent_token.token_id}</div>
                <div>Digest: {activeJobView.consent_token.digest.substring(0, 32)}...</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
