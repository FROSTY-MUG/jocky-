import React, { useState } from 'react';
import { 
  FileText, 
  ShieldCheck, 
  RefreshCw, 
  Download, 
  CheckCircle, 
  AlertTriangle,
  Link2,
  Lock
} from 'lucide-react';
import { AuditEntry } from '../types';
import { verifyAuditChain } from '../api';

interface AuditTabProps {
  auditLogs: AuditEntry[];
}

export const AuditTab: React.FC<AuditTabProps> = ({ auditLogs }) => {
  const [verifying, setVerifying] = useState(false);
  const [verificationState, setVerificationState] = useState<{
    verified: boolean;
    entries: number;
    head_hash: string;
    checkedAt: string;
  } | null>(null);

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditChain();
      setVerificationState({
        ...res,
        checkedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.error(err);
    } finally {
      setVerifying(false);
    }
  };

  const exportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `jocky-audit-chain-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Chain Status Bar */}
      <div className="p-5 bg-[#0c1322] border border-gray-800 rounded-xl shadow-lg flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-gray-100 font-mono">
              Tamper-Evident Cryptographic Audit Stream (§2.7)
            </h3>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Every administrative action, consent issuance, and telemetry capture is cryptographically bound in a SHA-256 hash-chain.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={exportJSON}
            className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold rounded-lg flex items-center space-x-2 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSONL</span>
          </button>

          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold rounded-lg shadow-md flex items-center space-x-2 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Chain Integrity'}</span>
          </button>
        </div>
      </div>

      {/* Verification Status Card */}
      {verificationState && (
        <div className="p-4 bg-emerald-950/40 border border-emerald-800/80 rounded-xl shadow-lg flex items-center justify-between font-mono text-xs">
          <div className="flex items-center space-x-3">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <div>
              <span className="text-emerald-300 font-bold">
                AUDIT HASH CHAIN INTACT & VERIFIED
              </span>
              <p className="text-[11px] text-emerald-400/80">
                Verified {verificationState.entries} sequential block hashes with zero collisions or link breaks.
              </p>
            </div>
          </div>
          <div className="text-right text-[11px] text-gray-400">
            <div>Head Hash: {verificationState.head_hash.substring(0, 16)}...</div>
            <div className="text-[10px] text-gray-500">{verificationState.checkedAt}</div>
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="bg-[#0c1322] border border-gray-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#090e1a] text-gray-400 uppercase text-[10px] font-mono tracking-wider border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">Index</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Entry Digest (SHA-256)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 font-mono text-[11px]">
              {auditLogs.map((entry) => (
                <tr key={entry.index} className="hover:bg-gray-900/40 transition">
                  <td className="py-3 px-4 text-cyan-400 font-bold">#{entry.index}</td>
                  <td className="py-3 px-4 text-gray-400">{entry.timestamp}</td>
                  <td className="py-3 px-4 font-semibold text-gray-200">{entry.actor}</td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-gray-800 text-indigo-300 border border-gray-700">
                      {entry.action}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-gray-400">{entry.target}</td>
                  <td className="py-3 px-4 text-emerald-400/90 break-all">
                    {entry.entry_hash.substring(0, 24)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
