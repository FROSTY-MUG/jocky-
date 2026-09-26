# JOCKY Architecture Overview

The canonical, detailed architectural specification for the JOCKY platform is located in **[docs/00-blueprint.md](00-blueprint.md)**.

---

## Architectural Summary

JOCKY is structured into four primary defensive subsystems:

```
                      +---------------------------------------+
                      |         JOCKY DSL Source (.jky)       |
                      +---------------------------------------+
                                          |
                                          v
+---------------------------------------------------------------------------------+
| Compiler Pipeline (jockyc)                                                      |
|   1. Lexer & Parser (logos + Pratt parser)                                      |
|   2. AST Safety Gate (23-primitive capability denylist check)                   |
|   3. Semantic Typechecker (type inference & validation)                         |
|   4. Polymorphic Diversification (BB reorder, substitution, mangling, enc)      |
|   5. LLVM 17 Codegen (Linux ELF64 & Windows COFF x86_64)                        |
|   6. Packaging (.jkm container, CBOR manifest, Ed25519 signing)                 |
+---------------------------------------------------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |        Signed .jkm Binary Container   |
                      +---------------------------------------+
                                          |
                                          v
+---------------------------------------------------------------------------------+
| Host Runtime & Verification (jocky-verify & Agents)                             |
|   1. Ed25519 Attestation & Tamper Check (validates Header + Code + Manifest)   |
|   2. Consent Token Validation (cryptographically bound operator authority)     |
|   3. Sandboxed Execution (read-only memory, strict CPU/memory quotas)          |
|   4. Forensic Collection (telemetry collection, hashing, audit logging)        |
+---------------------------------------------------------------------------------+
                                          |
                                          v
+---------------------------------------------------------------------------------+
| Management & Analytics Plane                                                    |
|   1. Go Manager Service (policy orchestration & registry)                       |
|   2. Immutable Transparency Audit Log (tamper-evident evidence chain)           |
|   3. DFIR Investigation Dashboard (real-time timeline analysis)                 |
+---------------------------------------------------------------------------------+
```

For subsystem deep-dives, see:
- Compiler: [02-language-and-compiler.md](02-language-and-compiler.md), [03-typechecker-and-codegen.md](03-typechecker-and-codegen.md)
- Packaging & Polymorphism: [04-cicd-polymorphism.md](04-cicd-polymorphism.md)
- Agent Runtimes: [03-agent-runtime.md](03-agent-runtime.md)
- Management Plane: [05-manager-and-cloud.md](05-manager-and-cloud.md)
- Threat Model: [01-threat-model.md](01-threat-model.md)
- Operations: [07-security-and-ops.md](07-security-and-ops.md), [runbook.md](runbook.md)
