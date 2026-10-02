import React from 'react';
import { 
  Shield, 
  Activity, 
  Terminal, 
  AlertTriangle, 
  FileText, 
  Code2, 
  KeyRound, 
  CheckCircle2,
  Cpu,
  Layers
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  counts: {
    agents: number;
    jobs: number;
    findings: number;
    audit: number;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, counts }) => {
  const navItems = [
    { id: 'overview', label: 'Fleet Overview', icon: Activity, count: null },
    { id: 'agents', label: 'Agents & Consent', icon: Cpu, count: counts.agents },
    { id: 'script-ide', label: 'JOCKY Script IDE', icon: Code2, count: null },
    { id: 'jobs', label: 'Forensic Jobs', icon: Terminal, count: counts.jobs },
    { id: 'findings', label: 'Threat Findings', icon: AlertTriangle, count: counts.findings, alert: counts.findings > 0 },
    { id: 'verifier', label: '.jkm Attestation', icon: KeyRound, count: null },
    { id: 'audit', label: 'Audit Log & Chain', icon: FileText, count: counts.audit },
  ];

  return (
    <aside className="w-64 border-r border-gray-800 bg-[#090d18] p-4 flex flex-col justify-between select-none">
      <div>
        {/* Brand */}
        <div className="flex items-center space-x-3 mb-8 px-2 py-1">
          <div className="p-2 bg-cyan-950/60 border border-cyan-800/80 rounded-xl shadow-lg shadow-cyan-950/30">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="font-extrabold text-base tracking-wider text-cyan-400 font-mono">JOCKY DFIR</h1>
            <p className="text-[11px] text-gray-400 font-mono">Consent-Bound Platform</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-700/60 shadow-md shadow-cyan-950/40'
                    : 'text-gray-400 hover:bg-gray-800/40 hover:text-gray-200 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-gray-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.count !== null && (
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold ${
                      item.alert
                        ? 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                        : isActive
                        ? 'bg-cyan-900/60 text-cyan-300'
                        : 'bg-gray-800/80 text-gray-400'
                    }`}
                  >
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Security Status Box */}
      <div className="p-3 bg-[#0c1424] border border-cyan-900/40 rounded-xl text-xs space-y-2">
        <div className="flex items-center space-x-2 text-cyan-400 font-semibold font-mono text-[11px]">
          <Layers className="w-3.5 h-3.5" />
          <span>Polymorphic Engine</span>
        </div>
        <p className="text-[11px] text-gray-400 leading-relaxed">
          4 diversification passes active: Basic-Block reordering, instruction substitution, ChaCha20 symbol mangling, BLAKE3 string XOR.
        </p>
        <div className="pt-2 border-t border-gray-800/80 flex items-center justify-between text-[10px] font-mono text-emerald-400">
          <span>● Attestation v0.1</span>
          <span>Ed25519 Enforced</span>
        </div>
      </div>
    </aside>
  );
};
