# JOCKY Project Glossary

This glossary defines technical, cryptographic, and domain-specific terms used throughout the JOCKY architecture, compiler, and operational documentation.

---

## DFIR (Digital Forensics & Incident Response)

The cybersecurity discipline focused on identifying, investigating, containing, and remediating cyber threats while legally preserving digital evidence.

## Incident Response (IR)

The structured operational process an organization follows to detect, analyze, contain, and recover from a cyber attack or security breach.

## EDR (Endpoint Detection and Response)

Integrated endpoint security software that continuously monitors system activity, records behavioral events, and triggers automated defensive responses.

## AV (Antivirus)

Traditional host-based security software that detects, flags, and quarantines malicious programs primarily via signature matches and heuristic file scanning.

## BYOVD (Bring Your Own Vulnerable Driver)

An adversarial technique where an attacker drops a legitimate, legitimately signed, but known-vulnerable third-party kernel driver to achieve arbitrary kernel read/write access.

## LOLDrivers (Living Off The Land Drivers)

A curated community catalog of vulnerable or malicious Windows drivers that have been weaponized or abused in the wild to bypass driver signature enforcement (DSE).

## C2 (Command and Control)

Infrastructure, protocols, and software used by adversaries or penetration testers to maintain persistent communication with and control compromised systems. JOCKY explicitly rejects and excludes all C2 functionality.

## .jkm (JOCKY Module)

The proprietary binary container format produced by the JOCKY compiler, encapsulating raw relocatable object code, an RFC 8949 CBOR metadata manifest, and an Ed25519 signature.

## Capability Denylist

A strict compile-time enforcement mechanism within the JOCKY compiler frontend that inspects the Abstract Syntax Tree (AST) and unconditionally halts compilation if any of 23 prohibited offensive primitives are referenced.

## Consent Token

A cryptographically signed authorization credential issued by system administrators that an agent runtime must validate before executing any forensic collection operations on a host.

## Attestation

The cryptographic process of verifying the provenance, integrity, build seed, and compiler version of a binary module prior to loading or execution.

## Transparency Log

An append-only, tamper-evident cryptographic Merkle tree (similar to Certificate Transparency) that records every build manifest, signature, and release for independent verification.

## SBOM (Software Bill of Materials)

A structured, machine-readable inventory of software components, dependencies, licenses, and cryptographic file digests conforming to standard specifications such as SPDX 2.3.

## mTLS (Mutual Transport Layer Security)

A two-way authentication protocol where both the client agent and the management server verify each other's X.509 cryptographic identities before establishing an encrypted tunnel.

## CDN (Content Delivery Network)

A geographically distributed network of proxy servers and data centers providing high availability and resilient delivery of software artifacts and policy updates.

## Domain Fronting

A networking technique that leverages different domain names at the TLS layer (SNI) and the HTTP application layer (Host header) to route traffic through large shared CDNs. JOCKY documents this exclusively in the context of forensic resilience through network censorship.

## Polymorphism

The property of a software program having multiple distinct binary representations, instruction sequences, and structural layouts while preserving mathematically equivalent execution behavior.

## Diversification

The specific compiler transformations (basic-block reordering, algebraic instruction substitution, symbol name mangling, string literal encryption) applied during code generation to emit unique, collision-resistant binaries from a common source.
