import React from 'react';
import { Shield, Lock, Wifi, AlertCircle } from 'lucide-react';
import { ManagerHealth } from '../types';

interface HeaderProps {
  health: ManagerHealth | null;
  online: boolean;
  activeTab: string;
}

export const Header: React.FC<HeaderProps> = ({ health, online, activeTab }) => {
  return (
    <header className="border-b border-gray-800 bg-[#0a0f1d]/90 backdrop-blur-md px-8 py-4 flex items-center justify-between sticky top-0 z-20">
      <div>
        <div className="flex items-center space-x-3">
          <h2 className="text-xl font-bold tracking-tight text-gray-100 capitalize">
            {activeTab.replace('-', ' ')}
          </h2>
          <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
            JOCKY v0.1 • NTRO SIH26148
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-0.5">
          Consent-Bound DFIR Operations & Attested Polymorphic Telemetry
        </p>
      </div>

      <div className="flex items-center space-x-4">
        {/* WebRTC Guard Status */}
        <div className="flex items-center space-x-2 px-3 py-1.5 bg-cyan-950/40 border border-cyan-800/40 rounded-lg text-xs font-mono text-cyan-300">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>WebRTC Guard: STRICT (STUN Leak Protected)</span>
        </div>

        {/* Manager Connection */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-medium transition-colors"
          style={{
            backgroundColor: online ? 'rgba(6, 78, 59, 0.4)' : 'rgba(159, 18, 57, 0.4)',
            borderColor: online ? 'rgba(5, 150, 105, 0.5)' : 'rgba(225, 29, 72, 0.5)',
            color: online ? '#34d399' : '#fb7185',
          }}
        >
          {online ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Manager REST :8080 ONLINE</span>
            </>
          ) : (
            <>
              <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
              <span>Manager Standalone (Simulated)</span>
            </>
          )}
        </div>

        {/* Operator Badge */}
        <div className="flex items-center space-x-2 pl-3 border-l border-gray-800">
          <div className="w-8 h-8 rounded-full bg-indigo-950 border border-indigo-700/60 flex items-center justify-center text-xs font-bold text-indigo-300">
            IR
          </div>
          <div className="text-left hidden sm:block">
            <p className="text-xs font-semibold text-gray-200">Incident Responder</p>
            <p className="text-[10px] text-gray-400 font-mono">ROLE: LEAD_DFIR</p>
          </div>
        </div>
      </div>
    </header>
  );
};
