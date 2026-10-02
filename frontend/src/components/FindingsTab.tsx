import React, { useState } from 'react';
import { 
  AlertTriangle, 
  Search, 
  Filter, 
  ShieldAlert, 
  FileJson, 
  ExternalLink, 
  CheckCircle, 
  XCircle,
  Copy,
  Check
} from 'lucide-react';
import { Finding, ThreatSeverity, TrustLevel } from '../types';

interface FindingsTabProps {
  findings: Finding[];
}

export const FindingsTab: React.FC<FindingsTabProps> = ({ findings }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(findings[0] || null);
  const [copied, setCopied] = useState(false);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.detail.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.mitre_technique.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const copyArtifactJSON = () => {
    if (!selectedFinding) return;
    navigator.clipboard.writeText(selectedFinding.artifact_json);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Search & Severity Filters */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-[#0c1322] border border-gray-800 rounded-xl">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search threats, MITRE tags, hosts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-gray-900/80 border border-gray-700/80 rounded-lg pl-9 pr-4 py-2 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <span className="text-xs text-gray-400">Severity:</span>
          {['all', 'critical', 'high', 'medium'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                severityFilter === sev
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                  : 'bg-gray-900/60 text-gray-400 hover:bg-gray-800 border border-transparent'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Grid: Finding Cards + Evidence Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Finding Cards List */}
        <div className="xl:col-span-2 space-y-3">
          {filteredFindings.map((finding) => {
            const isSelected = selectedFinding?.id === finding.id;
            return (
              <div
                key={finding.id}
                onClick={() => setSelectedFinding(finding)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-rose-950/20 border-rose-600/80 shadow-lg shadow-rose-950/30'
                    : 'bg-[#0c1322] border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-950/80 text-rose-400 border border-rose-800/60">
                      {finding.severity}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                        finding.trust === 'full'
                          ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40'
                          : 'bg-amber-950/60 text-amber-400 border border-amber-800/40'
                      }`}
                      title={finding.trust === 'degraded' ? 'Host telemetry was degraded when captured' : 'Full cryptographic attestation'}
                    >
                      Trust: {finding.trust}
                    </span>
                  </div>
                  <span className="text-[10px] text-gray-500 font-mono">{finding.id}</span>
                </div>

                <h4 className="text-sm font-bold text-gray-100">{finding.title}</h4>
                <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">{finding.detail}</p>

                <div className="flex flex-wrap items-center justify-between gap-2 mt-3 pt-3 border-t border-gray-800/60 text-[11px] font-mono">
                  <span className="text-cyan-400">Host: {finding.hostname}</span>
                  <span className="px-2 py-0.5 bg-gray-800/80 text-indigo-300 rounded">
                    {finding.mitre_technique}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Evidence Inspector Side Panel */}
        {selectedFinding && (
          <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="border-b border-gray-800 pb-3 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-gray-100 flex items-center space-x-2">
                  <FileJson className="w-4 h-4 text-cyan-400" />
                  <span>Evidence Inspector</span>
                </h3>
                <p className="text-[11px] text-gray-400 font-mono mt-0.5">ID: {selectedFinding.id}</p>
              </div>
              <button
                onClick={copyArtifactJSON}
                className="px-2.5 py-1 text-gray-300 hover:text-white bg-gray-800/80 rounded text-xs flex items-center space-x-1"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="text-[11px]">{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Honesty Affordance Stripe (§2.4 of 06-frontend-dashboard.md) */}
            {selectedFinding.trust !== 'full' && (
              <div className="p-3 bg-amber-950/40 border border-amber-800/50 rounded-lg text-xs text-amber-300 font-mono space-y-1">
                <div className="font-bold flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>DEGRADED EVIDENCE NOTICE</span>
                </div>
                <p className="text-[11px] text-amber-200/80 leading-normal">
                  This artifact was captured while host ETW providers were in a degraded or silenced state. Evidence trust level is capped.
                </p>
              </div>
            )}

            {/* Evidence Byte-Range URI */}
            <div className="space-y-1 text-xs font-mono">
              <span className="text-gray-400">Bundle Evidence Reference:</span>
              <div className="p-2.5 bg-gray-900 border border-gray-800 rounded-lg text-[10px] text-cyan-300 break-all">
                {selectedFinding.evidence_ref}
              </div>
            </div>

            {/* Raw Artifact JSON */}
            <div className="space-y-1 text-xs font-mono">
              <span className="text-gray-400">Raw Artifact JSON Payload:</span>
              <pre className="p-3 bg-[#080d18] border border-gray-800 rounded-lg text-[11px] text-emerald-300 overflow-x-auto max-h-72 scrollbar-none whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(JSON.parse(selectedFinding.artifact_json), null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
