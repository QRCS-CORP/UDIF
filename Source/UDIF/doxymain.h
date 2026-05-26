/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef UDIF_DOXYMAIN_H
#define UDIF_DOXYMAIN_H

/**
 * \mainpage Universal Digital Identification Framework (UDIF)
 *
 * \section intro_sec Introduction
 *
 * The Universal Digital Identification Framework is a post-quantum identity,
 * object, registry, query, and audit framework. It represents roots, branch
 * controllers, group controllers, user agents, and owned objects as canonical
 * binary records. Certificates, capabilities, object records, query records,
 * registry leaves, and anchor records are encoded deterministically and are
 * bound to post-quantum signatures, SHA3-family digests, and MCEL ledger
 * commitments.
 *
 * UDIF separates administrative authority from object ownership. Root
 * authorities issue Branch Controller certificates. Branch Controllers issue
 * Group Controller certificates. Group Controllers issue User Agent
 * certificates. User Agents are the only entities that own objects. All
 * administrative actions, object operations, registry commits, treaty events,
 * query responses, and anchor submissions are validated against certificate
 * role, certificate status, capability scope, canonical encoding, and ledger
 * continuity before they are accepted.
 *
 * \section role_sec Protocol Roles
 *
 * \subsection root_sec Root Authority
 *
 * The Root Authority is the trust anchor for a UDIF domain. It creates the
 * self-issued root certificate, defines the domain suite, accepts branch
 * enrollment requests, verifies child anchors, and maintains the top-level
 * membership ledger for the domain.
 *
 * \subsection bc_sec Branch Controller
 *
 * The Branch Controller administers a subordinate portion of the hierarchy. It
 * may issue child branch or group certificates according to its role and
 * capability mask, receive child anchors, enforce suspension and revocation,
 * and participate in bilateral treaty channels with peer domains.
 *
 * \subsection gc_sec Group Controller
 *
 * The Group Controller is the enforcement point for User Agents. It issues UA
 * certificates, validates object creation and transfer operations, maintains
 * membership, transaction, and registry ledgers, evaluates authorized query
 * predicates, and forwards only treaty-scoped queries.
 *
 * \subsection ua_sec User Agent
 *
 * The User Agent is the leaf entity that owns objects. A UA maintains its
 * object registry, signs object operations, originates authorized queries, and
 * communicates through its Group Controller. UAs do not exercise
 * administrative authority over other entities.
 *
 * \section data_sec Canonical Data Model
 *
 * UDIF structures are serialized using fixed-size fields, fixed field order,
 * little-endian integer encoding, raw byte arrays for serials, hashes, public
 * keys, and signatures, and exact-length decoders. Signed structures are
 * hashed over their canonical representation excluding the signature field.
 * This deterministic form prevents serialization ambiguity and ensures that
 * digests, signatures, Merkle roots, and MCEL commitments are byte-stable.
 *
 * \section cap_sec Certificates and Capabilities
 *
 * Certificates bind a role, suite identifier, issuer serial, subject serial,
 * validity window, policy epoch, public key, and capability bitmap to a parent
 * signature. Capability inheritance is restrictive: a child capability mask may
 * not exceed the parent authority. Runtime capability tokens are authenticated
 * with KMAC and resolved through the capability store before query evaluation
 * or protected operations are admitted.
 *
 * \section registry_sec Objects, Registries, and Transactions
 *
 * Objects are 32-byte-serial records owned by User Agents. Object creation is
 * signed by the owner and logged by the Group Controller. Transfers require
 * valid sender and receiver signatures over the same transfer digest before the
 * GC logs the transfer and updates the sender and receiver registry states.
 * Registries are Merkle trees over canonical object leaves and support
 * membership proof generation and verification against anchored registry
 * roots.
 *
 * \section mcel_sec MCEL Logs and Anchor Records
 *
 * UDIF uses MCEL for membership, transaction, and registry commitment ledgers.
 * Checkpoint groups are summarized into signed Anchor Records containing the
 * membership root, registry root, transaction root, child serial, timestamp,
 * event counters, and exact 0-indexed sequence number. Parents accept only the
 * expected genesis sequence 0 or the exact next sequence value. Duplicate,
 * skipped, forked, stale, future, wrong-child, and bad-signature anchors are
 * rejected.
 *
 * \section transport_sec UDIF-over-QSTP Transport Profile
 *
 * UDIF uses QSTP as the outer cryptographic transport substrate. QSTP performs
 * authenticated channel establishment, packet protection, and transport-level
 * rekeying. The UDIF payload sealed by QSTP is:
 *
 *     UDIF-Header || UDIF-Message
 *
 * The UDIF inner header contains the record class flags, sequence number, UTC
 * timestamp, epoch, and suite identifier. After QSTP authenticates and opens
 * the protected record, UDIF validates the inner header and then dispatches the
 * decoded message. Record-class flags must match the message class exactly;
 * ambiguous combined classes are rejected. This implementation therefore uses
 * a QSTP-wrapped inner-record model rather than a separate UDIF AEAD layer with
 * externally supplied associated data.
 *
 * \section query_sec Query and Treaty Processing
 *
 * UDIF supports existence, owner-binding, attribute-bucket, and membership-proof
 * query predicate families. Query predicates are canonicalized by type,
 * authorized by capability digest and KMAC tag, evaluated without leaking target
 * state on authorization failure, and answered with signed yes, no, or deny
 * responses. Cross-domain queries require an active bilateral treaty whose
 * parties, peer serials, signatures, expiry, and predicate scope are verified
 * before forwarding or execution. Treaties are non-transitive.
 *
 * \section security_sec Security Posture
 *
 * The implementation follows the UDIF fail-closed model: exact-length decoding,
 * recursive certificate-chain validation, role/message dispatch gates, active
 * certificate-status checks, strict sequence and timestamp checks, constant-time
 * digest comparisons where security-sensitive, QSC allocation and zeroization
 * utilities, and digest-only ledger commitments. Security hardening also avoids
 * large transient protocol objects on the stack in the tunnel, MCEL, and
 * role-server dispatch paths.
 *
 * \section modules_sec Primary Modules
 *
 * - certificate.h: certificate and CSR encoding, signing, and verification.
 * - certstore.h: certificate status and recursive chain validation.
 * - capability.h / capstore.h: capability encoding, tagging, storage, and checks.
 * - object.h: object creation, transfer, signing, and validation.
 * - registry.h: registry state, roots, leaves, and Merkle proofs.
 * - query.h: query and response encoding, signing, and registry evaluation.
 * - treaty.h: bilateral treaty construction, signature verification, and scope.
 * - tunnel.h: UDIF inner record header and tunnel sequencing state.
 * - dispatch.h: role-gated message dispatch and application handlers.
 * - mcelmanager.h: UDIF coordination of MCEL commitment ledgers.
 * - anchor.h: anchor creation, serialization, signature verification, and sequence checks.
 *
 * \author QRCS Corporation
 * \date 2026-05-23
 * ]version 1.1.0.0a
 */

#endif
