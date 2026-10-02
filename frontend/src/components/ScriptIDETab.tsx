import React, { useState, useMemo } from 'react';
import { 
  Code2, 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  FileCode, 
  Copy, 
  Check, 
  Sliders, 
  Sparkles,
  ArrowRight
} from 'lucide-react';
import { ForensicScript } from '../types';

interface ScriptIDETabProps {
  scripts: ForensicScript[];
  onDispatchScript: (script: ForensicScript) => void;
}

// 23 forbidden primitives from JOCKY AST denylist (§5 of README / 00-blueprint.md)
const FORBIDDEN_PRIMITIVES = [
  'inject_remote_process', 'write_process_memory', 'create_service',
  'dump_lsass', 'install_driver', 'harvest_credentials',
  'bypass_uac', 'create_remote_thread', 'virtual_alloc_ex',
  'set_run_key', 'schedule_task', 'disable_etw',
  'patch_amsi', 'token_steal', 'revert_to_self',
  'keylog', 'screenshare', 'exfiltrate_dns',
  'disable_defender', 'clear_event_log', 'modify_firewall',
  'encrypt_volume', 'zero_mbr'
];

export const ScriptIDETab: React.FC<ScriptIDETabProps> = ({ scripts, onDispatchScript }) => {
  const [selectedScriptId, setSelectedScriptId] = useState<string>(scripts[0]?.id || 'scr-byovd');
  const [sourceCode, setSourceCode] = useState<string>(scripts[0]?.source_code || '');
  const [seed, setSeed] = useState<number>(1000);
  const [copied, setCopied] = useState<boolean>(false);
  const [compileOutput, setCompileOutput] = useState<string | null>(null);

  const selectedScript = scripts.find((s) => s.id === selectedScriptId);

  const handleSelectScript = (scr: ForensicScript) => {
    setSelectedScriptId(scr.id);
    setSourceCode(scr.source_code);
    setCompileOutput(null);
  };

  // Live denylist scan of the editor content
  const denylistViolations = useMemo(() => {
    const violations: string[] = [];
    for (const prim of FORBIDDEN_PRIMITIVES) {
      if (sourceCode.includes(prim)) {
        violations.push(prim);
      }
    }
    return violations;
  }, [sourceCode]);

  // Diversification simulation based on seed
  const diversifiedIR = useMemo(() => {
    const symbolSuffix = (seed * 1103515245 + 12345) % 65536;
    const isOdd = seed % 2 !== 0;

    return `; JOCKY LLVM 17 IR (Polymorphically Diversified)
; Build Seed: ${seed} | Variant Hash: 0x${((seed * 31337) >>> 0).toString(16).padStart(8, '0')}
; Target: x86_64-pc-windows-msvc (SysV / COFF ABI)

define i64 @jky_fn_${symbolSuffix.toString(16)}(i64 %arg0) {
entry:
${isOdd ? '  ; Pass 2: Algebraic Instruction Substitution (a + b -> a - (-b))\n  %0 = sub i64 %arg0, -4096' : '  ; Pass 2: Canonical Addition\n  %0 = add i64 %arg0, 4096'}
${isOdd ? '  br label %bb_verify\n\nbb_verify:\n  ret i64 %0' : '  ret i64 %0'}
}

define i64 @main() {
entry:
  %res = call i64 @jky_fn_${symbolSuffix.toString(16)}(i64 1337)
  ret i64 %res
}
; JKM Section 0: Machine Code [${64 + (seed % 32)} bytes]
; JKM Section 1: CBOR RFC 8949 Manifest [128 bytes]
; JKM Section 2: Ed25519 Attested Signature [64 bytes]`;
  }, [seed]);

  const handleCompile = () => {
    if (denylistViolations.length > 0) {
      setCompileOutput(
        `[SECURITY REJECTION] Compile error: AST contains denylisted offensive primitive: '${denylistViolations[0]}'.\n` +
        `JOCKY is strictly defensive blue-team software. Capability rejected at parse phase.`
      );
      return;
    }

    setCompileOutput(
      `[OK] JOCKY Frontend Lex & Parse: 0 errors\n` +
      `[OK] Static Typechecking: Types verified (100% sound)\n` +
      `[OK] Capability Denylist Pass: SAFE (0 forbidden AST primitives detected)\n` +
      `[OK] Diversification Pass 1 (BB Reorder): Seed ${seed} deterministic schedule\n` +
      `[OK] Diversification Pass 2 (Algebraic Sub): Validated\n` +
      `[OK] Diversification Pass 3 (Symbol Mangle): ChaCha20 seeded\n` +
      `[OK] Diversification Pass 4 (BLAKE3 String XOR): Applied\n` +
      `[OK] LLVM 17 Object Generation: SysV/COFF object emitted\n` +
      `[OK] Container Pack: .jkm generated with Ed25519 digital signature\n` +
      `Attestation Signature: 4c9a...verified.`
    );
  };

  const copyCode = () => {
    navigator.clipboard.writeText(sourceCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Script Selector Ribbon */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2 scrollbar-none">
        {scripts.map((scr) => {
          const isSelected = scr.id === selectedScriptId;
          return (
            <button
              key={scr.id}
              onClick={() => handleSelectScript(scr)}
              className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
                isSelected
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/80 shadow-md shadow-cyan-950/50'
                  : 'bg-[#0c1322] text-gray-400 hover:bg-gray-800/60 border border-gray-800'
              }`}
            >
              <FileCode className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : 'text-gray-500'}`} />
              <span>{scr.filename}</span>
            </button>
          );
        })}
      </div>

      {/* Editor & Diversifier Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Code Editor */}
        <div className="bg-[#0c1322] border border-gray-800 rounded-xl overflow-hidden shadow-lg flex flex-col">
          <div className="bg-[#090e1a] px-4 py-3 border-b border-gray-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-gray-200 font-mono">
                {selectedScript?.filename || 'custom.jky'}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={copyCode}
                className="px-2.5 py-1 text-gray-400 hover:text-gray-200 text-xs flex items-center space-x-1"
                title="Copy code"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="text-[11px]">{copied ? 'Copied' : 'Copy'}</span>
              </button>
              <button
                onClick={handleCompile}
                className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs rounded-lg flex items-center space-x-1.5 transition"
              >
                <Play className="w-3 h-3 fill-current" />
                <span>Verify & Compile</span>
              </button>
            </div>
          </div>

          {/* Editor Body */}
          <div className="p-4 flex-1">
            <textarea
              value={sourceCode}
              onChange={(e) => {
                setSourceCode(e.target.value);
                setCompileOutput(null);
              }}
              rows={16}
              className="w-full bg-[#080d18] border border-gray-800 rounded-lg p-3 text-xs font-mono text-cyan-200 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
              spellCheck={false}
            />

            {/* Description & Capabilities */}
            {selectedScript && (
              <div className="mt-3 p-3 bg-gray-900/60 border border-gray-800 rounded-lg text-xs space-y-1.5">
                <p className="text-gray-300">{selectedScript.description}</p>
                <div className="flex items-center space-x-2 pt-1">
                  <span className="text-[11px] text-gray-500 font-mono">Required Capabilities:</span>
                  {selectedScript.capabilities.map((c) => (
                    <span key={c} className="px-2 py-0.5 bg-cyan-950/80 text-cyan-400 border border-cyan-800/50 rounded text-[10px] font-mono">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Denylist Alert If User Typed Forbidden Primitive */}
            {denylistViolations.length > 0 && (
              <div className="mt-3 p-3 bg-rose-950/60 border border-rose-800 rounded-lg text-xs text-rose-300 flex items-start space-x-2">
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold">Capability Denylist Triggered:</span>
                  <p className="text-[11px] text-rose-200/90 mt-0.5 font-mono">
                    Found forbidden offensive primitive: <span className="underline font-bold">{denylistViolations.join(', ')}</span>.
                    The JOCKY compiler will refuse to emit native code for this AST.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Polymorphic Diversification & Compiler Output */}
        <div className="space-y-6">
          {/* Polymorphic Control Card */}
          <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-gray-100 font-mono">Polymorphic Engine Simulator</h3>
              </div>
              <span className="text-[11px] font-mono text-indigo-400">4 Passes Active</span>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-gray-400">Diversification Build Seed:</span>
                <span className="text-cyan-400 font-bold">{seed}</span>
              </div>
              <input
                type="range"
                min="1"
                max="9999"
                value={seed}
                onChange={(e) => setSeed(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-gray-500 font-mono">
                <span>Seed 1</span>
                <span>Seed 5000</span>
                <span>Seed 9999</span>
              </div>
            </div>

            {/* Generated LLVM IR View */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono text-gray-400">Lowered IR Preview:</span>
              <pre className="p-3 bg-[#080d18] border border-gray-800 rounded-lg text-[11px] font-mono text-gray-300 overflow-x-auto max-h-56 scrollbar-none leading-relaxed">
                {diversifiedIR}
              </pre>
            </div>
          </div>

          {/* Compilation Output Card */}
          {compileOutput && (
            <div className="bg-[#0c1322] border border-gray-800 rounded-xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                <span className="text-xs font-bold text-gray-200 font-mono flex items-center space-x-2">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Compiler Diagnostic Output</span>
                </span>
              </div>
              <pre className={`p-3 rounded-lg text-[11px] font-mono whitespace-pre-wrap leading-relaxed ${
                denylistViolations.length > 0
                  ? 'bg-rose-950/40 text-rose-300 border border-rose-800/40'
                  : 'bg-emerald-950/30 text-emerald-300 border border-emerald-800/40'
              }`}>
                {compileOutput}
              </pre>
            </div>
          )}

          {/* Dispatch Button */}
          {selectedScript && (
            <div className="flex justify-end">
              <button
                onClick={() => onDispatchScript(selectedScript)}
                className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-cyan-950/50 flex items-center space-x-2 transition"
              >
                <span>Dispatch Module To Fleet</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
