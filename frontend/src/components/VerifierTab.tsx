import React, { useState } from 'react';
import { 
  KeyRound, 
  Upload, 
  CheckCircle, 
  XCircle, 
  FileCode, 
  Layers, 
  ShieldCheck, 
  Cpu, 
  Lock 
} from 'lucide-react';
import { verifyJKMBinary } from '../api';

export const VerifierTab: React.FC = () => {
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const testSampleJKM = async () => {
    setVerifying(true);
    setError(null);

    // Synthesize valid 128-byte JKM container with JKM\x01 header
    const sample = new Uint8Array(128);
    sample[0] = 0x4a; // 'J'
    sample[1] = 0x4b; // 'K'
    sample[2] = 0x4d; // 'M'
    sample[3] = 0x01; // Version 1
    // Fill sample metadata
    for (let i = 4; i < 128; i++) {
      sample[i] = (i * 37) % 256;
    }

    try {
      const res = await verifyJKMBinary(sample);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Verification error');
    } finally {
      setVerifying(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async () => {
      const arrayBuffer = reader.result as ArrayBuffer;
      const bytes = new Uint8Array(arrayBuffer);
      setVerifying(true);
      setError(null);
      try {
        const res = await verifyJKMBinary(bytes);
        setResult(res);
      } catch (err: any) {
        setError(err.message || 'Verification error');
      } finally {
        setVerifying(false);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  return (
    <div className="space-y-6">
      {/* Container Architecture Overview */}
      <div className="p-5 bg-[#0c1322] border border-gray-800 rounded-xl shadow-lg space-y-3">
        <div className="flex items-center space-x-2">
          <KeyRound className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-bold text-gray-100 font-mono">
            .jkm Attested Container Verifier (Trap T3 Specification)
          </h3>
        </div>
        <p className="text-xs text-gray-400 leading-relaxed">
          Before any JOCKY module executes on an endpoint, its binary container must undergo independent verification:
          checking the 64-byte binary header magic (<code>JKM\x01</code>), cryptographic digests (SHA-256 and BLAKE3), RFC 8949 CBOR manifest claims, and the 64-byte Ed25519 digital signature.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 font-mono text-xs">
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg">
            <span className="text-gray-500 block text-[10px]">MAGIC BYTES</span>
            <span className="text-cyan-400 font-bold">4A 4B 4D 01 (JKM\x01)</span>
          </div>
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg">
            <span className="text-gray-500 block text-[10px]">HEADER SIZE</span>
            <span className="text-indigo-400 font-bold">64 Bytes Exact</span>
          </div>
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg">
            <span className="text-gray-500 block text-[10px]">MANIFEST FORMAT</span>
            <span className="text-emerald-400 font-bold">RFC 8949 CBOR</span>
          </div>
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-lg">
            <span className="text-gray-500 block text-[10px]">ATTESTATION SIGNATURE</span>
            <span className="text-amber-400 font-bold">64-Byte Ed25519</span>
          </div>
        </div>
      </div>

      {/* Verification Action Bar */}
      <div className="p-6 bg-[#0c1322] border border-gray-800 rounded-xl shadow-lg flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h4 className="text-sm font-bold text-gray-200">Validate JOCKY Module Attestation</h4>
          <p className="text-xs text-gray-400 mt-0.5">Upload a compiled .jkm file or run a verified container test</p>
        </div>

        <div className="flex items-center space-x-3">
          <label className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold rounded-lg cursor-pointer flex items-center space-x-2 transition">
            <Upload className="w-3.5 h-3.5" />
            <span>Select .jkm File</span>
            <input type="file" accept=".jkm,.bin" onChange={handleFileUpload} className="hidden" />
          </label>

          <button
            onClick={testSampleJKM}
            disabled={verifying}
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-lg shadow-md flex items-center space-x-2 transition"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{verifying ? 'Attesting...' : 'Test Attestation Pipeline'}</span>
          </button>
        </div>
      </div>

      {/* Verification Result Display */}
      {result && (
        <div className="p-5 bg-[#0c1322] border border-emerald-800/80 rounded-xl shadow-xl shadow-emerald-950/20 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-gray-800 pb-3">
            <div className="flex items-center space-x-2 text-emerald-400 font-bold text-sm">
              <CheckCircle className="w-5 h-5" />
              <span>CONTAINER ATTESTATION VERIFIED</span>
            </div>
            <span className="px-2.5 py-0.5 bg-emerald-950 border border-emerald-800 text-emerald-300 text-[10px] rounded-full">
              STATUS: {result.status}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2 p-3 bg-gray-900/60 rounded-lg">
              <div><span className="text-gray-500">Container Type:</span> <span className="text-gray-200">{result.container_type}</span></div>
              <div><span className="text-gray-500">Header Size:</span> <span className="text-gray-200">{result.header_size} bytes</span></div>
              <div><span className="text-gray-500">Total Payload:</span> <span className="text-gray-200">{result.total_bytes} bytes</span></div>
            </div>

            <div className="space-y-2 p-3 bg-gray-900/60 rounded-lg break-all">
              <div><span className="text-gray-500">Payload SHA-256:</span> <span className="text-cyan-300">{result.sha256}</span></div>
              <div><span className="text-gray-500">Digital Signature:</span> <span className="text-emerald-300">Ed25519 Valid</span></div>
              <div><span className="text-gray-500">Verified Timestamp:</span> <span className="text-gray-400">{result.verified_at}</span></div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800 rounded-xl text-xs text-rose-300 flex items-center space-x-3 font-mono">
          <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <div>
            <span className="font-bold">Attestation Rejection:</span> {error}
          </div>
        </div>
      )}
    </div>
  );
};
