# UDIF: Universal Digital Identity Framework

## Introduction 

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


**UDIF: A Post-Quantum, Federated, Policy-Driven Digital Identity Framework**

## Overview

The Universal Digital Identity Framework (UDIF) is a **cryptographically secure, post-quantum identity infrastructure**.  
It replaces the fragile trust models of legacy PKI and federated login systems with a **deterministic, policy-bound, and extensible identity framework**. This project is currently under construction.


[UDIF Help Documentation](https://qrcs-corp.github.io/UDIF/)  
[UDIF Summary Document](https://qrcs-corp.github.io/UDIF/pdf/udif_summary.pdf)  
[UDIF Protocol Specification](https://qrcs-corp.github.io/UDIF/pdf/udif_specification.pdf)  
[UDIF Formal Analysis](https://qrcs-corp.github.io/UDIF/pdf/udif_formal.pdf)  


UDIF defines standardized object formats for:

- **Certificates:** Root, Issuer, and Entity certificates signed with PQ algorithms.  
- **Identity Records:** Binding subjects to namespaces, issuers, policies, and claim anchors.  
- **Claim Sets:** Deterministically encoded attributes (TLV) anchored to identities.  
- **Capability Masks:** Compact privilege and delegation control via fixed-size bitmasks.  
- **Permission Masks:** Subject- or resource-level access controls.  
- **Tokens:** Attestations and capability envelopes, optionally protected by PQ KEMs.  

Core design goals:
- Post-quantum cryptography (Dilithium, SPHINCS+, Kyber, McEliece, SHA3/SHAKE).  
- Deterministic canonicalization of every object.  
- Privacy through **minimal-disclosure queries** with Merkle proofs.  
- Explicit **policy hashes** to prevent silent drift.  
- Federated trust domains interoperating via proxies (UIP).
- 
## Support the Universal Digital Identity Framework (UDIF)

UDIF is an open, cryptographically rigorous framework for universal digital identity, asset representation, and auditable ownership. It is designed from first principles to address long-standing problems in identity interoperability, privacy, provenance, and post-quantum security.  

The project focuses on:  

- Post-quantum secure identity and object containers  
- Deterministic encoding, minimal-disclosure queries, and capability-based authorization  
- Tamper-evident audit logs with hierarchical anchoring  
- Cross-domain interoperability without surveillance or data leakage  

UDIF is being developed as a long-term, standards-grade system. Sponsorship directly supports continued research, formal specification work, reference implementations, security analysis, and public documentation.  
If you believe in open, verifiable digital infrastructure that is privacy-preserving and future-proof, consider sponsoring the project.  

**Support UDIF development**  
Help fund open research and implementation of a post-quantum, auditable digital identity framework.  
[Become a Sponsor →](https://github.com/sponsors/QRCS-CORP)  

### Transparency

Sponsorship funds are used for protocol research, formal analysis, implementation work, and long-term maintenance of the UDIF specification and associated tooling.

## Architecture

UDIF defines four principal roles:

### Universal Domain Controller (UDC)

**Role:**  
The root trust anchor of a namespace.  

**Functions:**
- Defines namespace codes and policy hashes.  
- Issues root certificates.  
- Signs Issuer certificates.  
- Maintains revocation and suspension records.  

### Inter-Domain Proxy (UIP)

**Role:**  
Federates multiple UDIF domains.  

**Functions:**
- Routes cross-domain identity queries.  
- Resolves namespaces and issuer domain codes.  
- Enforces capability-bounded treaties across domains.  

### Institutional Server (UIS)

**Role:**  
Issues entity certificates and validates claims within its domain.  

**Functions:**
- Issues entity and identity records to clients.  
- Validates claim sets against anchors.  
- Enforces domain policy.  
- Maintains registry of issued and revoked identities.  

### Client

**Role:**  
The subject entity (person, device, or application).  

**Functions:**
- Generates a subject identifier and key pair.  
- Obtains an entity certificate from a UIS.  
- Stores claims locally and presents Merkle proofs as needed.  
- Uses tokens for authentication and authorization.  

## UDIF Protocol Overview

- **Certificates:** Hierarchical root → issuer → entity, each cryptographically bound to namespace and policy.  
- **Identity Records:** Anchor claim sets, permissions, capabilities, and validity windows.  
- **Claims:** TLV-encoded, hashed, and anchored for deterministic verification.  
- **Tokens:** Portable attestation objects used for authorization.  
- **Revocation:** Logged and anchored events cascade through the hierarchy.  
- **Queries:** Minimal-disclosure checks (existence, ownership, membership) return only YES/NO/DENY with optional proofs.  

## File Description (planned)

The UDIF library will be modular and organized as follows:

- **udif.h:** Core library API (constants, enums, structs, functions).  
- **udifcommon.h:** Shared definitions, encodings, and type maps.  
- **certificates.c:** Certificate handling (encode, decode, verify).  
- **identity.c:** Identity record management.  
- **claims.c:** Claim set encode/decode and Merkle anchor computation.  
- **tokens.c:** Token issue, encode/decode, and verify.  
- **capability.c:** Capability and permission mask evaluation.  
- **network.c (future):** Inter-domain treaty and proxy resolution.  

## Getting Started

Once the codebase is published:

- Include the UDIF headers (`udif.h`, `udifcommon.h`) in your project.  
- Initialize namespaces and root certificates for your domain.  
- Issue and validate certificates and identity records.  
- Bind attributes to identities through claim sets and anchors.  
- Use capability and permission masks to enforce least-privilege policies.  

### Cryptographic Dependencies

UDIF will use the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC) for hashing, signatures, and KEM operations.  
*QRCS-PL private License. See license file for details. All rights reserved by QRCS Corporation, copyrighted and patents pending.*

## License

INVESTMENT INQUIRIES:
QRCS is currently seeking a corporate investor for this technology.
Parties interested in licensing or investment should connect to us at: contact@qrcscorp.ca  
Visit https://www.qrcscorp.ca for a full inventory of our products and services.    

PATENT NOTICE:  
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

License and Use Notice (2025-2026)  
This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.  
All source code and materials in this repository are provided under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026, unless explicitly stated otherwise.  
This license permits public access and non commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.  
The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.  
Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.  
For licensing inquiries, supported implementations, or commercial use, contact: licensing@qrcscorp.ca  
Quantum Resistant Cryptographic Solutions Corporation, 2026.  
_All rights reserved by QRCS Corp. 2026._
