# UDIF: Universal Digital Identity Framework

[![Build](https://github.com/QRCS-CORP/UDIF/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/UDIF/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/UDIF/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/UDIF/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/udif/badge)](https://www.codefactor.io/repository/github/qrcs-corp/udif)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/UDIF/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/UDIF/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/UDIF/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/UDIF)](https://github.com/QRCS-CORP/UDIF/releases/tag/2025-11-09)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/UDIF.svg)](https://github.com/QRCS-CORP/UDIF/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)
[![Sponsor UDIF](https://img.shields.io/badge/Sponsor-UDIF-blue?logo=github-sponsors)](https://github.com/sponsors/QRCS-CORP)

**A Post-Quantum, Hierarchical, Policy-Driven Digital Identity and Asset Management Framework**

> This project is currently under active development.

## Documentation

| Document | Description |
|----------|-------------|
| [Help Documentation](https://qrcs-corp.github.io/UDIF/) | API reference and integration guides |
| [Executive Summary](https://qrcs-corp.github.io/UDIF/pdf/udif_summary.pdf) | Overview for evaluators and decision-makers |
| [Protocol Specification](https://qrcs-corp.github.io/UDIF/pdf/udif_specification.pdf) | Full technical specification (Revision 2.0) |
| [Formal Analysis](https://qrcs-corp.github.io/UDIF/pdf/udif_formal.pdf) | Security proofs and formal verification |

---

## Overview

UDIF is a post-quantum identity and asset management framework that replaces the fragile trust models of legacy PKI and federated login systems with a hierarchical, cryptographically verifiable chain of authority. Every entity in a UDIF deployment holds a certificate signed by its parent, forming a verifiable chain back to a self-signed root. Objects representing identities, assets, or commodities are owned by end-user entities, tracked through their full lifecycle, and committed to tamper-evident audit logs via MCEL (Merkle Chain Event Ledger).

All cryptographic operations use NIST-standardized post-quantum primitives provided by the QSC library: ML-DSA (Dilithium) for signatures, ML-KEM (Kyber) for key encapsulation, and SHA-3/SHAKE for hashing and key derivation. Structures are encoded as fixed-size binary records with little-endian byte order, ensuring deterministic, byte-stable serialization across all platforms.

Core design goals:

- **Post-quantum security** via NIST-standardized algorithms (ML-DSA, ML-KEM, SHA-3)
- **Hierarchical trust** with strict separation of administrative authority and asset ownership
- **Tamper-evident audit trails** through MCEL-backed logs and signed Anchor Records
- **Minimal-disclosure queries** returning only YES/NO/DENY with optional Merkle proofs
- **Policy versioning** via the `policy_epoch` field carried in every certificate
- **Federated interoperability** through bilateral treaties, without central authority dependencies
- **Offline verification** — certificates are self-contained and require no network connectivity

---

## Architecture

UDIF defines four hierarchical roles with strict responsibilities at each level.

### Root Authority

The apex of the trust hierarchy. Issues a self-signed certificate (issuer serial equals its own serial) that defines the cryptographic suite and initial `policy_epoch` for the entire domain. The root certificate's trust is established through out-of-band verification. The Root typically operates offline or within a controlled enclave.

### Branch Controller (BC)

An intermediate authority operating in one of two mutually exclusive modes. In **branch-admin mode**, it manages subordinate Branch Controllers, scaling the hierarchy downward. In **user-admin mode**, it becomes a Group Controller and takes direct responsibility for User Agents. Branch Controllers never hold objects.

### Group Controller (GC)

A Branch Controller in user-admin mode. The operational core of a UDIF domain: it registers User Agents, issues certificates with capability bitmaps, and maintains three parallel MCEL ledgers (Membership, Transaction, Registry). All queries are validated and proxied through the Group Controller, which is the primary enforcement point for access control and audit integrity.

### User Agent (UA)

The leaf node of the hierarchy and the only entity that owns objects. Each User Agent holds a certificate issued by its Group Controller and maintains an Object Registry — a Merkle tree of the digests of all objects it owns. User Agents have no direct lateral communication; all traffic flows through their Group Controller.

---

## Core Components

### Certificates

Hierarchical credentials binding entities to their public keys and capabilities. Each certificate carries a signature, verification key, serial number, issuer serial, 64-bit capability bitmap, validity window, `policy_epoch`, role, and suite identifier. Signed by the issuer's Dilithium private key; root certificates are self-signed.

### Objects

Polymorphic containers representing any ownable entity — an identity, asset, account, device credential, or digital token. Each object carries a 16-byte serial number, creator and owner references, and a Merkle-committed attribute root binding it to its metadata. Objects are never deleted; they are cryptographically marked as destroyed, preserving the full audit trail.

### Object Registries

Per-UA Merkle trees of object digests. The registry root is committed periodically through MCEL and included in Anchor Records, enabling compact membership proofs without exposing the full registry.

### Capability Bitmaps

64-bit bitmasks that govern what each entity is permitted to do. The system is default-deny: no capability exists unless explicitly granted. Child entities can never hold a capability bit their parent does not possess, enforced at certificate issuance.

### Anchor Records

Signed digest packages transmitted from child to parent at configured intervals. Each record carries the current Merkle roots of the three MCEL ledgers, the child's serial, a 0-indexed sequence number (genesis = 0), a timestamp, and event counters. Anchor Records chain upward from User Agents through Group Controllers and Branch Controllers to the Root, creating a tamper-evident audit trail across the entire hierarchy.

### MCEL Integration

UDIF audit logging is built on the Merkle Chain Event Ledger (MCEL). MCEL stores cryptographic commitments (SHA3-256) rather than raw records, organizing them into Merkle-tree blocks sealed by signed checkpoints. Actual records are stored separately via the UDIF storage backend, which is pluggable (filesystem, database, object storage). The separation ensures that the cryptographic audit trail remains intact regardless of the underlying storage technology.

### Queries

Minimal-disclosure predicates (existence, ownership, membership) that return only YES/NO/DENY with optional Merkle proofs. Raw attributes are never exposed in query responses.

### Treaties

Bilateral agreements defining the query predicates one UDIF domain may pose to another. Treaties never grant administrative authority across domain boundaries, and both sides independently log every cross-domain query.

---

## Repository Structure

| File | Description |
|------|-------------|
| `udif.h` | Core constants, enumerations, macros, and cryptographic suite configuration |
| `udifcommon.h` | Shared type definitions, error codes, and utility structures |
| `certificate.c / .h` | Certificate generation, signing, verification, and serialization |
| `object.c / .h` | Object lifecycle management (create, transfer, update, destroy) |
| `anchor.c / .h` | Anchor record creation, serialization, and verification |
| `capability.c / .h` | Capability bitmap evaluation and inheritance checking |
| `query.c / .h` | Minimal-disclosure query processing and Merkle proof generation |
| `registry.c / .h` | Object registry management and Merkle root computation |
| `storage.c / .h` | Pluggable storage backend abstraction |
| `treaty.c / .h` | Cross-domain treaty management and query routing |
| `mcelmanager.c / .h` | MCEL integration — three-ledger management, checkpointing, and commitment coordination |

---

## Getting Started

Include the UDIF headers in your project and link against the QSC and MCEL libraries.
```c
#include "udif.h"
#include "certificate.h"
#include "object.h"
#include "anchor.h"
```

Select a cryptographic suite at compile time:
```c
#define UDIF_CONFIG_DILITHIUM_KYBER    // ML-DSA + ML-KEM (recommended)
// #define UDIF_CONFIG_SPHINCS_MCELIECE   // SPHINCS+ + McEliece (conservative)
```

Typical integration sequence:

1. Initialize root certificate (self-signed, `policy_epoch = 0`)
2. Issue Branch and Group Controller certificates down the hierarchy
3. Register User Agents and assign capability bitmaps
4. Create objects and assign ownership to User Agents
5. Configure MCEL manager with three ledgers (Membership, Transaction, Registry)
6. Generate Anchor Records at configured intervals and transmit to parent

Full API documentation is available at [qrcs-corp.github.io/UDIF](https://qrcs-corp.github.io/UDIF/).

---

## Cryptographic Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| [QSC](https://github.com/QRCS-CORP/QSC) | Post-quantum cryptographic primitives (ML-DSA, ML-KEM, SHA-3, KMAC, RCS) | QRCS-PL Private License |
| [MCEL](https://github.com/QRCS-CORP/MCEL) | Merkle Chain Event Ledger for tamper-evident audit logging | QRCS-PL Private License |
| [QSTP](https://github.com/QRCS-CORP/QSTP) | Quantum Secure Tunneling Protocol for encrypted transport | QRCS-PL Private License |

All QRCS libraries are copyrighted by QRCS Corporation with patents pending. See individual repositories for license terms.

---

## Sponsorship

UDIF is an open, cryptographically rigorous framework for post-quantum digital identity, asset representation, and auditable ownership. Sponsorship directly supports continued protocol research, formal specification work, reference implementation development, security analysis, and public documentation.

[**Become a Sponsor →**](https://github.com/sponsors/QRCS-CORP)

Sponsorship funds are used exclusively for protocol research, formal analysis, implementation work, and long-term maintenance of the UDIF specification and associated tooling.

---

## License

**Investment Inquiries:**
QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact us at contact@qrcscorp.ca or visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of our products and services.

**Patent Notice:**
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

**License and Use Notice (2025–2026):**
This repository is published under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026. This license permits non-commercial evaluation, academic research, cryptographic analysis, interoperability testing, and feasibility assessment only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license.

For licensing inquiries: licensing@qrcscorp.ca

*All rights reserved by QRCS Corporation, 2026.*