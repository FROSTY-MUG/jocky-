# JOCKY Documentation Index

This directory contains the canonical technical specifications, architectural designs, threat models, and operational runbooks for the JOCKY DFIR language and platform.

---

## Technical Documentation Index

| File | Contents |
| --- | --- |
| [00-blueprint.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/00-blueprint.md) | High-level system architecture, constraints, capability denylist, and defensive framing. |
| [01-threat-model.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/01-threat-model.md) | STRIDE threat model, adversary assumptions, trust boundaries, and consent verification. |
| [02-language-and-compiler.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/02-language-and-compiler.md) | JOCKY v0.1 grammar specification, lexer, AST, parser design, and diagnostic errors. |
| [03-agent-runtime.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/03-agent-runtime.md) | Agent execution sandbox, consent token verification, host memory bounds, and safety limits. |
| [03-typechecker-and-codegen.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/03-typechecker-and-codegen.md) | Static type system, High-Level IR (HIR), and LLVM 17 IR lowering via inkwell. |
| [04-cicd-polymorphism.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/04-cicd-polymorphism.md) | 4 diversification passes, `.jkm` binary container format, and Ed25519 signing. |
| [05-manager-and-cloud.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/05-manager-and-cloud.md) | Central management plane, multi-tenant isolation, policy distribution, and audit log chaining. |
| [05-multi-language-toolchain.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/05-multi-language-toolchain.md) | Polyglot CI toolchain (Rust, Go, Python, Bash, PowerShell, C++, eBPF, Swift). |
| [06-frontend-dashboard.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/06-frontend-dashboard.md) | DFIR incident response dashboard specifications, wireframes, and event visualizations. |
| [07-security-and-ops.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/07-security-and-ops.md) | Operational security, key lifecycle management, zero-trust deployments, and emergency revocation. |
| [08-testing-plan.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/08-testing-plan.md) | Comprehensive QA strategy, differential testing against VM interpreters, and fuzzing harness. |
| [runbook.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/runbook.md) | Incident responder operational runbook for live deployment, attestation verification, and evidence extraction. |
| [GLOSSARY.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/GLOSSARY.md) | Terminology definitions covering DFIR, compiler, cryptography, and container concepts. |
| [ARCHITECTURE.md](file:///c:/Users/Aryan/Desktop/sihmaim/docs/ARCHITECTURE.md) | Architectural roadmap and index referencing system components and specifications. |
