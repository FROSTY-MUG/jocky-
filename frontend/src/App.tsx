import React, { useState } from 'react';
import { Shield, Activity, Terminal, AlertTriangle, FileText, Lock } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('agents');

  return (
    <div className="min-h-screen flex bg-[#090d16] text-gray-100 font-sans">
      {/* Sidebar */}
      <div className="w-64 border-r border-gray-800 bg-[#0c1220] p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center space-x-3 mb-8 px-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="font-bold text-lg tracking-wider text-cyan-400">JOCKY DFIR</h1>
              <p className="text-xs text-gray-500">NTRO SIH26148</p>
            </div>
          </div>

          <nav className="space-y-2">
            {[
              { id: 'agents', label: 'Agents & Consent', icon: Activity },
              { id: 'jobs', label: 'Forensic Jobs', icon: Terminal },
              { id: 'findings', label: 'Threat Findings', icon: AlertTriangle },
              { id: 'audit', label: 'Audit Logs', icon: FileText },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                    activeTab === item.id
                      ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/50'
                      : 'text-gray-400 hover:bg-gray-800/40 hover:text-gray-200'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-3 bg-cyan-950/30 border border-cyan-900/40 rounded-lg text-xs">
          <div className="flex items-center space-x-2 text-cyan-400 font-semibold mb-1">
            <Lock className="w-3.5 h-3.5" />
            <span>WebRTC Guard Active</span>
          </div>
          <p className="text-gray-400">STUN/ICE leak protection enabled for admin VPN session.</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-8 overflow-y-auto">
        <div className="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-100 capitalize">{activeTab} Dashboard</h2>
            <p className="text-sm text-gray-400">Attested Endpoint Forensics & Telemetry Correlation</p>
          </div>
          <div className="flex items-center space-x-4">
            <span className="px-3 py-1 bg-emerald-950/60 border border-emerald-800 text-emerald-400 text-xs font-mono rounded-full">
              ● Manager gRPC Online
            </span>
          </div>
        </div>

        {/* Dynamic View Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-[#0e1626] border border-gray-800 p-5 rounded-xl shadow-lg">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Active Agents</p>
            <p className="text-3xl font-extrabold text-cyan-400 mt-2">14</p>
            <p className="text-xs text-emerald-400 mt-1">100% Consent Tokens Verified</p>
          </div>
          <div className="bg-[#0e1626] border border-gray-800 p-5 rounded-xl shadow-lg">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Executed JOCKY Scripts</p>
            <p className="text-3xl font-extrabold text-indigo-400 mt-2">128</p>
            <p className="text-xs text-gray-400 mt-1">Polymorphic Build Seeds: N=50</p>
          </div>
          <div className="bg-[#0e1626] border border-gray-800 p-5 rounded-xl shadow-lg">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Threat Detections</p>
            <p className="text-3xl font-extrabold text-rose-400 mt-2">3</p>
            <p className="text-xs text-rose-400 mt-1">Unbacked Memory / BYOVD Drivers</p>
          </div>
        </div>
      </div>
    </div>
  );
}
