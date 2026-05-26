# UDIF: Universal Digital Identity Framework

[![Build](https://github.com/QRCS-CORP/UDIF/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/UDIF/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/UDIF/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/UDIF/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/udif/badge)](https://www.codefactor.io/repository/github/qrcs-corp/udif)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#platforms)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/UDIF/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20PREL-blue.svg)](https://github.com/QRCS-CORP/UDIF/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/UDIF/)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/UDIF.svg)](https://github.com/QRCS-CORP/UDIF/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA%20Target&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Identity%20%7C%20Assets%20%7C%20Audit&color=brightgreen)](#)
[![Sponsor UDIF](https://img.shields.io/badge/Sponsor-UDIF-blue?logo=github-sponsors)](https://github.com/sponsors/QRCS-CORP)

**A post-quantum, hierarchical, policy-driven digital identity, object custody, and audit framework.**

> **Prototype status:** UDIF is an active research and engineering prototype. The repository contains a reference C implementation, serialization and verification logic, entity stores, control-plane handlers, tunnel framing, MCEL ledger integration, and a broad conformance/test harness. It is intended for evaluation, protocol review, interoperability testing, and continued development. It is not represented as a production-certified identity infrastructure or a finalized public standard.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Help Documentation](https://qrcs-corp.github.io/UDIF/) | API documentation and integration material |
| [Executive Summary](https://qrcs-corp.github.io/UDIF/pdf/udif_summary.pdf) | Strategic overview for evaluators and decision-makers |
| [Protocol Specification](https://qrcs-corp.github.io/UDIF/pdf/udif_specification.pdf) | Technical specification for the UDIF protocol and data model |
| [Formal Analysis](https://qrcs-corp.github.io/UDIF/pdf/udif_formal.pdf) | Formal security analysis, proof structure, and implementation alignment |

---

## Overview

The Universal Digital Identity Framework (UDIF) is a post-quantum framework for representing, certifying, querying, transferring, and auditing digital identities and owned objects. It defines a hierarchical chain of authority in which each entity holds a parent-signed certificate and all significant state transitions are logged through tamper-evident Merkle commitments.

UDIF is designed around four principles:

1. **Hierarchical authority:** trust flows downward from a Root Authority through Branch Controllers and Group Controllers to User Agents.
2. **End-user object ownership:** objects are owned by User Agents, not administrative controllers.
3. **Default-deny authorization:** certificates, capability bitmaps, and policy checks must explicitly authorize each operation.
4. **Audit without overexposure:** logs, registries, and treaty queries use digests, Merkle roots, and minimal-disclosure responses rather than raw personal or object data.

The current prototype implements the main protocol objects and enforcement mechanisms needed to evaluate this architecture: certificates and CSRs, certificate stores, capability tokens and capability stores, object lifecycle functions, transfer records, registry Merkle roots and proofs, query and response containers, treaty objects and treaty stores, anchor records, event logging, MCEL checkpoint integration, entity contexts, tunnel state, message dispatch, and role-aware control-plane handlers.

---

## Prototype Capabilities

The current UDIF prototype includes the following capabilities.

### Cryptographic and Encoding Layer

- Compile-time cryptographic suite selection.
- Default `UDIF_CONFIG_DILITHIUM_KYBER` profile using QSC ML-DSA/Dilithium signatures and ML-KEM/Kyber key encapsulation.
- Optional `UDIF_CONFIG_SPHINCS_MCELIECE` profile for SPHINCS+ signatures and Classic McEliece key encapsulation.
- RCS authenticated encryption support through QSC, with AES-GCM mapping retained as a compile-time alternative.
- SHA3/cSHAKE/KMAC-based digest, KDF, and authentication support through QSC.
- Fixed-size canonical binary encoding with little-endian integer serialization.
- Signature-first signed-structure layout for certificates, objects, registry commits, anchors, treaties, and responses.
- Domain-separated digest computation for protocol structures.
- Explicit zeroization and clear functions for sensitive structures.

### Certificate and Identity Layer

- Root, Branch Controller, Group Controller, User Agent, and object-role certificate support.
- Certificate signing request generation, serialization, deserialization, digest computation, and verification.
- Certificate generation for subordinate entities.
- Parent-signed certificate verification and chain validation.
- Certificate validity-window checking.
- Role-transition validation between parent and child roles.
- Capability inheritance checking to prevent child privilege expansion.
- Certificate comparison, serialization, deserialization, and secure clearing.
- Certificate store with add, find, status, revocation/suspension/resumption, and verification functions.

### Capability and Policy Layer

- 64-bit capability bitmap model.
- Verb and scope authorization checks.
- Capability serialization, deserialization, digest computation, KMAC verification, expiration checking, and secure clearing.
- Capability store with verified add, lookup, active/revoked/suspended status handling, status update, and removal functions.
- Policy authorization routines for certificate-bound and capability-bound operations.
- Query-specific policy mapping from query type to required capability verb.
- Default-deny authorization posture.

### Object and Registry Layer

- Object creation with owner, creator, type, timestamp, and attribute-root binding.
- Object digest and signature computation.
- Object verification against owner verification keys.
- Object attribute update with owner signature.
- Object destruction marking without log deletion.
- Transfer-record creation, serialization, deserialization, transaction-ID computation, and dual-party verification.
- Registry initialization per owner.
- Registry leaf encoding and digest computation.
- Object insertion, lookup, update, removal, transfer between registries, and active-state checks.
- Registry resizing, capacity tracking, and count tracking.
- Merkle root computation over registry leaves.
- Merkle proof generation and verification.
- Signed registry commit records.

### Audit, Event, and MCEL Integration

- Anchor record serialization, deserialization, digest computation, signing, comparison, freshness checking, and secure clearing.
- Anchor verification against expected sequence and child verification key.
- Anchor-chain verification between consecutive anchor records.
- Explicit 0-indexed anchor sequence handling.
- Entity-level expected-anchor-sequence tracking and commit updates.
- Event record creation, serialization, and MCEL-backed logging.
- MCEL manager integration for membership, transaction, and registry ledgers.
- Active-ledger selection.
- MCEL record add/read/size operations.
- Block flushing and checkpoint creation.
- Coordinated checkpoint-group creation across ledgers.
- Anchor creation from MCEL roots and counters.
- Default checkpoint configuration.
- Flush-all support and keypair access for MCEL signing contexts.

### Query Layer

- Canonical query containers for existence, owner-binding, attribute-bucket, and membership-proof predicates.
- Query digest computation.
- Query freshness checking.
- Query serialization and deserialization.
- Query authorization validation against capability and target serial.
- Canonical predicate validation.
- Registry-backed query evaluation.
- Response creation with YES, NO, or DENY verdicts.
- Optional proof attachment for authorized membership-proof flows.
- Query response digest computation, serialization, deserialization, signature verification, and full response verification.

### Treaty and Cross-Domain Layer

- Bilateral treaty object creation, proposal verification, acceptance, co-signing, and full verification.
- Treaty digest computation.
- Treaty serialization, deserialization, comparison, encoded-size calculation, and secure clearing.
- Treaty duration, active, expired, pending, participant, query-scope, and predicate-scope checks.
- Treaty store with add, find, status query, and status update operations.
- Treaty proposal, co-sign, revoke, treaty-query-forward, and treaty-query-response control-plane handlers.
- Pending treaty-query correlation through treaty-aware dispatch and store state.

### Transport, Message, and Dispatch Layer

- Canonical UDIF message creation, encoding, decoding, encoded-size calculation, disposal, and type-name mapping.
- Tunnel record header serialization and deserialization.
- Tunnel header validation using sequence, epoch, timestamp, and suite rules.
- Message-type to tunnel-record flag mapping.
- Tunnel send and receive processing.
- Keepalive handling and idle/session tick processing.
- Ratchet trigger path for long-lived tunnel state.
- Tunnel close and open-state checks.
- Entity tunnel table for peer/treaty tunnel lookup, QSTP-state lookup, addition, removal, and periodic ticking.
- Role-aware dispatch permission checks.
- Control-plane handlers for certificate enrollment, certificate status changes, capability grants/revocations, object operations, registry commits, anchors, treaty operations, query operations, and error reporting.

### Server, Storage, and Operational Support

- Role-specific server entry points for Root, Branch Controller, Group Controller, and User Agent operation.
- Server application-state initialization, storage, load, unload, backup save, and backup restore.
- Server configuration display, status display, command prompt setup, and banner output.
- User login/logout support for the prototype console environment.
- Hostname, domain name, IP address, port, console-timeout, and password-retry configuration helpers.
- Certificate generation, export, load, signing, and printing support for server state.
- Log writing, log printing, configuration clearing, log clearing, and erase-all support.
- Storage directory, certificate directory, key path, configuration path, data path, and backup-directory helpers.
- Pluggable storage context with write, read, append, size, flush, and callback mapping.
- File-backed storage path resolution, handle caching, handle eviction, and handle cleanup.

### Test Harness Coverage

The companion test project exercises the prototype across unit, conformance, control-plane, virtual-network, and endurance scenarios. Current test modules include:

- Anchor tests.
- Capability tests.
- Certificate tests.
- General conformance tests.
- Control-plane tests.
- Handler conformance tests.
- Inter-domain treaty tests.
- Load and endurance tests.
- MCEL hierarchy tests.
- MCEL manager tests.
- Object, registry, and transaction tests.
- Query mechanism tests.
- Query tests.
- Registry tests.
- Encoding tests.
- KDF tests.
- Logging tests.
- Transport tests.
- Treaty tests.
- Tunnel tests.
- Virtual-network tests.

---

## Architecture

UDIF defines a strict role hierarchy.

### Root Authority

The Root Authority is the trust anchor for a UDIF domain. It creates the self-signed root certificate, defines the cryptographic suite and initial policy epoch, issues subordinate Branch Controller certificates, verifies upstream anchor flow, and anchors the authoritative domain state. The root certificate is trusted through out-of-band inclusion in the trust store rather than by ordinary parent-chain validation.

### Branch Controller

A Branch Controller is an intermediate authority. It may operate in branch-administration mode, where it creates and governs subordinate branches, or in group-administration mode, where it governs user-facing groups. The branch role separates administrative control from object ownership. Branch Controllers do not own objects.

### Group Controller

A Group Controller manages User Agents. It issues UA certificates, grants and revokes capabilities, validates object and query operations, maintains registries, commits events to MCEL ledgers, and generates anchor records for its parent. The GC is the primary enforcement point for default-deny policy.

### User Agent

A User Agent is a leaf entity. It represents a user, service, device, or endpoint that owns objects and originates authorized actions through its Group Controller. User Agents do not communicate laterally in the core protocol model.

### Objects and Registries

Objects are signed containers representing identities, accounts, assets, credentials, commodities, records, or other ownable entities. Each User Agent maintains a registry that commits to its object set through Merkle roots and signed registry commits.

---

## Security Model

UDIF is designed to provide the following security properties.

| Property | Mechanism |
|----------|-----------|
| Post-quantum authenticity | ML-DSA/Dilithium or SPHINCS+ signatures through QSC |
| Post-quantum key establishment | ML-KEM/Kyber or Classic McEliece through QSC |
| Transport confidentiality and integrity | RCS authenticated encryption or AES-GCM compile-time mapping |
| Downgrade resistance | Compile-time suite lock and suite identifiers |
| Serialization determinism | Fixed-size little-endian canonical encodings |
| Least privilege | Certificate capability bitmaps and capability tokens |
| Privilege containment | Parent-to-child capability inheritance checks |
| Query privacy | YES/NO/DENY predicate responses with optional proofs |
| Audit integrity | MCEL commitments, Merkle roots, checkpoints, and signed anchors |
| Replay resistance | Sequence, timestamp, epoch, and freshness checks |
| Cross-domain containment | Bilateral treaties with explicit query and scope masks |
| State accountability | Event records, anchor sequence tracking, and parent verification |

---

## Core Protocol Objects

| Object | Purpose |
|--------|---------|
| `udif_certificate` | Parent-signed identity and role credential |
| `udif_certificate_csr` | Certificate signing request with proof material |
| `udif_capability` | Verbs, scope, validity, digest, and KMAC tag for delegated rights |
| `udif_object` | Signed ownable object record with attribute-root binding |
| `udif_transfer_record` | Dual-party transfer authorization and transaction digest material |
| `udif_registry_state` | Per-owner object registry and Merkle root state |
| `udif_registry_commit` | Signed registry-root commitment |
| `udif_anchor_record` | Signed commitment to membership, registry, and transaction roots |
| `udif_event_record` | Canonical event entry for MCEL-backed logging |
| `udif_query` | Minimal-disclosure predicate request |
| `udif_query_response` | Signed YES/NO/DENY response with optional proof |
| `udif_treaty` | Bilateral cross-domain predicate and scope agreement |
| `udif_message` | Encoded control-plane message wrapper |
| `udif_tunnel` | Authenticated tunnel state and record-processing context |
| `udif_entity_context` | Runtime entity state, stores, registries, anchor sequence state, and tunnels |

---

## Repository Structure

| File | Description |
|------|-------------|
| `udif.h` | Core configuration, cryptographic mapping macros, protocol constants, and suite selection |
| `udifcommon.h` | Common export macros, assertions, and shared platform definitions |
| `certificate.c / certificate.h` | Certificates, CSRs, role transitions, signing, verification, and capability inheritance |
| `certstore.c / certstore.h` | Certificate store and certificate status management |
| `capability.c / capability.h` | Capability encoding, digesting, validation, and permission checks |
| `capstore.c / capstore.h` | Capability store and capability status management |
| `object.c / object.h` | Object lifecycle, ownership transfer, updates, destruction, and transfer records |
| `registry.c / registry.h` | Object registry, leaves, Merkle roots, proofs, and registry commits |
| `anchor.c / anchor.h` | Anchor records, signing, verification, freshness, and chain continuity |
| `event.c / event.h` | Event creation, serialization, and MCEL-backed event logging |
| `mcelmanager.c / mcelmanager.h` | MCEL ledger manager, record insertion, checkpoints, checkpoint groups, and anchor creation |
| `query.c / query.h` | Predicate queries, query responses, proof verification, and registry-backed evaluation |
| `treaty.c / treaty.h` | Treaty creation, acceptance, validation, scope checks, and verification |
| `treatystore.c / treatystore.h` | Treaty store and treaty status management |
| `tunnel.c / tunnel.h` | Tunnel record headers, message protection, keepalive, close, receive, and ratchet logic |
| `message.c / message.h` | UDIF control-plane message encoding and decoding |
| `dispatch.c / dispatch.h` | Role-aware message dispatch and control-plane handlers |
| `entity.c / entity.h` | Entity runtime context, registry table, anchor sequence state, and tunnel table |
| `policy.c / policy.h` | Authorization decisions and query-to-capability mapping |
| `storage.c / storage.h` | Pluggable storage context and file-backed storage operations |
| `logger.c / logger.h` | Local application log helpers |
| `server.c / server.h` | Prototype server state, configuration, certificate, and console support |
| `root.c / root.h` | Root server entry points |
| `bc.c / bc.h` | Branch Controller server entry points |
| `gc.c / gc.h` | Group Controller server entry points |
| `ua.c / ua.h` | User Agent server entry points |
| `handler.c / handler.h` | Handler support layer |
| `commands.h` | Command identifiers and console command integration |
| `resources.h` | Resource identifiers and application-resource definitions |
| `qstpkeys.h` | QSTP key integration definitions |
| `UDIF.vcxproj` | Visual Studio project file |

---

## Build and Integration Notes

UDIF is written in C and is structured as a prototype library plus role-specific server entry points. The repository currently includes Visual Studio project files and is intended to be built with the QRCS dependency stack.

### Required Dependencies

| Library | Purpose |
|---------|---------|
| [QSC](https://github.com/QRCS-CORP/QSC) | Cryptographic primitives, post-quantum algorithms, SHA-3/SHAKE/KMAC, RCS, AES-GCM, memory utilities, sockets, and file utilities |
| [MCEL](https://github.com/QRCS-CORP/MCEL) | Merkle Chain Event Ledger for commitment logging, blocks, checkpoints, and audit roots |
| [QSTP](https://github.com/QRCS-CORP/QSTP) | Quantum Secure Tunneling Protocol integration and transport support |

### Compile-Time Suite Selection

The default build selects the Dilithium/Kyber profile:

```c
#define UDIF_CONFIG_DILITHIUM_KYBER
/* #define UDIF_CONFIG_SPHINCS_MCELIECE */
```

The symmetric transport mapping defaults to RCS:

```c
#define UDIF_USE_RCS_ENCRYPTION
```

When `UDIF_USE_RCS_ENCRYPTION` is not enabled, the implementation maps the symmetric layer to AES-GCM helper types and functions from QSC.

### Basic Integration Flow

A typical prototype integration follows this sequence:

1. Initialize a Root Authority and create the root certificate.
2. Generate and verify CSRs for Branch Controllers.
3. Issue subordinate certificates with constrained capability bitmaps.
4. Initialize Group Controllers under the selected Branch Controller.
5. Register User Agents under the Group Controller.
6. Initialize per-UA object registries.
7. Create, update, transfer, or destroy objects through signed object operations.
8. Log events into the appropriate MCEL ledger.
9. Generate registry, transaction, and membership commitments.
10. Create signed Anchor Records with 0-indexed sequence numbers.
11. Verify anchors at the parent entity and update expected sequence state.
12. Process local and treaty-scoped queries through policy-gated dispatch handlers.

---

## Testing

The UDIF test project is intended to validate both individual protocol structures and the emerging whole-system behavior. The test suite includes unit tests for serialization, signing, registry handling, query logic, transport framing, treaty state, and MCEL integration, as well as broader conformance and virtual-network tests.

Representative test areas include:

- Deterministic encoding and decoding.
- Certificate and CSR signing/verification.
- Capability inheritance and authorization.
- Certificate/capability/treaty store state transitions.
- Object creation, update, transfer, and destruction.
- Registry root and proof generation.
- Query authorization, evaluation, response verification, and proof handling.
- Anchor sequence verification and chain continuity.
- MCEL checkpoint and hierarchy behavior.
- Control-plane handler dispatch and role gating.
- Inter-domain treaty negotiation and treaty query behavior.
- Tunnel record validation, keepalive, close, and ratchet paths.
- Virtual-network role simulation and negative-path behavior.
- Load/endurance behavior under repeated operations.

---

## Current Prototype Boundaries

UDIF is under active development. The current repository should be interpreted as a reference prototype and engineering testbed. The following boundaries apply:

- The code is suitable for review, testing, research, and protocol-development work.
- The design and implementation are still evolving as the specification, formal analysis, and test harness converge.
- The project should not be deployed as production identity infrastructure without a separate security review, operational hardening pass, integration testing, and a commercial license.
- Some modules provide prototype server/console support rather than a complete production orchestration environment.
- Cross-domain treaties, virtual-network tests, and tunnel paths are implemented for protocol validation and are expected to continue maturing.
- The cryptographic dependencies and parameter mappings must be built and tested with the matching QRCS libraries.

---

## Use Cases

UDIF is designed as a general framework for post-quantum identity, asset custody, and verifiable audit. Candidate deployment profiles include:

- Government or institutional digital identity roots.
- Regulated financial identity and asset provenance systems.
- Cross-institutional verification treaties.
- Supply-chain custody and provenance records.
- Device identity and secure infrastructure access.
- Private registries requiring cryptographic auditability without public disclosure.
- Digital asset and credential systems where ownership must be transferred and proven.
- Compliance systems requiring minimal-disclosure predicate answers instead of raw data exchange.

---

## Sponsorship

UDIF is an open research and evaluation effort for post-quantum identity, asset representation, and auditable ownership. Sponsorship supports protocol research, formal specification work, reference implementation development, security analysis, test-harness expansion, and public documentation.

[**Become a Sponsor →**](https://github.com/sponsors/QRCS-CORP)

---

## License

**Investment Inquiries:**
QRCS is currently seeking corporate investment and commercial partnerships for this technology. Parties interested in licensing, diligence, or investment should contact QRCS or visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of products and services.

**Patent Notice:**
One or more patent applications, provisional or non-provisional, covering aspects of this software have been filed with the United States Patent and Trademark Office. Unauthorized use may result in patent infringement liability.

**License and Use Notice (2025-2026):**
This repository is published under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026. This license permits non-commercial evaluation, academic research, cryptographic analysis, interoperability testing, and feasibility assessment only. It does not permit production deployment, operational use, commercial redistribution, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license.

For licensing inquiries: licensing@qrcscorp.ca

*All rights reserved by QRCS Corporation, 2026.*
