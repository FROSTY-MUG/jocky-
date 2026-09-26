# Security Policy

The JOCKY project maintains rigorous defensive security controls to ensure its forensic analysis tooling cannot be subverted for offensive use, unauthorized execution, or data compromise.

---

## 1. Supported Versions

Only the latest release on the primary development branch receives security updates.

| Version | Supported | Notes |
| --- | --- | --- |
| `0.1.x` | :white_check_mark: | Active development (STEP 1.5, 2A, 2B complete) |
| `< 0.1.0` | :x: | Experimental development branches |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability in JOCKY, please do **not** open a public issue or discussion.

### Reporting Channel

Submit a private security report via GitHub Security Advisories:
👉 **[Open a Draft Security Advisory](https://github.com/FROSTY-MUG/jocky-/security/advisories/new)**

If GitHub Security Advisories is inaccessible, send encrypted details to the project maintainers via the contact listed in [AUTHORS.md](AUTHORS.md).

### Response Timeline

- **Initial Acknowledgement**: Within 72 hours of receiving your report.
- **Triage & Assessment**: Within 7 business days with an initial severity rating and reproduction status.
- **Coordinated Disclosure**: Fixes will be prepared, reviewed, and published within 90 days following mutual agreement.

---

## 3. Scope

### In Scope

- **Compiler Safety (`jockyc`)**: Bypasses of the compile-time capability denylist, type safety violations, or malicious object code generation.
- **Module Attestation (`.jkm` / `jocky-verify`)**: Signature forgery, parsing vulnerabilities, truncation attacks, or CBOR deserialization exploits.
- **Agent Runtimes**: Privilege boundary violations, unauthenticated execution, or consent token validation bypasses.
- **Manager & Policy Enforcement**: Unauthorized tenant access, unlogged administrative actions, or tampering with audit logs.

### Out of Scope

- Vulnerabilities in third-party runtime dependencies (e.g., LLVM, Rust standard library, OS kernel) unless JOCKY introduces an exploitable condition.
- The rejection of offensive primitives by the compiler (e.g., filing a bug that `dump_lsass` or `inject_remote_process` fails to compile is rejected by design).
- Attacks requiring physical device access or root compromise of the developer's build workstation.

---

## 4. What Constitutes a Security Issue

We actively investigate and prioritize reports regarding:

1. **Denylist Evasion**: Techniques that evade AST-level detection of prohibited primitives (e.g., aliasing or dynamic resolution of denylisted APIs).
2. **Attestation Bypass**: Any method enabling an agent to load or execute an unsigned, corrupted, or tampered `.jkm` module.
3. **Consent Forgery**: Circumvention of the consent token verification mechanism.
4. **Audit Evasion**: Forensic collection or network transmission occurring without recording an immutable audit entry.
5. **Scope Escape**: Agents executing forensic probes outside their designated host, memory region, or target namespace.

---

## 5. What Does NOT Constitute a Security Issue

- **Compiler Denial of Service via Intentional Denylist Violation**: The compiler purposefully terminates compilation with exit code 1 when a denylisted token or primitive is identified.
- **Standard Library Inspection Capabilities**: Legitimate collection of process lists, memory headers, or network statistics on machines where the user possesses root or administrative credentials.
- **Self-Generated Test Artifacts**: Synthesized test files in test harnesses executing on operator-owned environments.

---

## 6. Coordinated Disclosure Policy

1. Maintainers will work directly with the finder to validate and address the vulnerability.
2. A Common Vulnerabilities and Exposures (CVE) identifier will be requested through GitHub's CNA if appropriate.
3. Fixes will be committed to a private fork and tested across all supported platforms prior to release.
4. Credit will be visibly attributed to the reporter in the release notes and [CHANGELOG.md](CHANGELOG.md), unless anonymity is requested.

---

## 7. Safe Harbor for Good-Faith Security Research

The JOCKY project encourages security researchers to conduct vulnerability research under our safe harbor terms:

- Conduct research exclusively against local builds, private test environments, or infrastructure you legally own.
- Do not access, degrade, or exfiltrate data belonging to third parties.
- Do not perform denial-of-service attacks against shared or cloud infrastructure.
- Comply with all applicable laws and respect coordinated disclosure guidelines.

If research adheres to these guidelines, we consider it authorized, will not initiate legal action against you, and will work collaboratively to resolve identified issues.

---

## 8. Authorized Use Notice

JOCKY is intended exclusively for lawful digital forensics and incident response operations conducted with verified authorization. Maintainers do not provide support, assistance, or modifications for unauthorized usage, offensive testing, or black-hat deployment.
