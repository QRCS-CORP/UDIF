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

#ifndef UDIF_EVENT_H
#define UDIF_EVENT_H

#include "udif.h"
#include "mcelmanager.h"

/**
 * \file event.h
 * \brief Canonical UDIF audit-event records.
 *
 * This header defines the canonical audit-event record format used by UDIF
 * membership, transaction, registry, and error ledgers. Audit events bind an
 * event class, event code, actor serial, subject serial, context identifier,
 * timestamp, payload digest, and payload length into a fixed-size record that
 * can be committed to the MCEL-backed audit subsystem.
 *
 * Event records store a digest of the event payload rather than the raw payload.
 * This preserves auditability while limiting ledger exposure of sensitive or
 * application-specific data.
 */

#define UDIF_EVENT_CONTEXT_SIZE 32U

/**
 * \def UDIF_EVENT_RECORD_SIZE
 * \brief Encoded size, in bytes, of a canonical UDIF audit-event record.
 *
 * The encoded event record contains the event class, event code, actor serial,
 * subject serial, context identifier, timestamp, payload digest, and payload
 * length. Integer fields are encoded in canonical little-endian form.
 */
#define UDIF_EVENT_RECORD_SIZE (1U + 2U + UDIF_SERIAL_NUMBER_SIZE + UDIF_SERIAL_NUMBER_SIZE + \
    UDIF_EVENT_CONTEXT_SIZE + 8U + UDIF_CRYPTO_HASH_SIZE + 8U)

/**
 * \enum udif_event_classes
 * \brief UDIF audit-event ledger class identifiers.
 *
 * Event classes select the logical ledger category to which an audit event
 * belongs. They are used to route canonical event records into the appropriate
 * MCEL-backed audit stream.
 */
typedef enum udif_event_classes
{
    udif_event_class_membership = 1U,   /*!< Membership lifecycle and administrative events. */
    udif_event_class_transaction = 2U,  /*!< Object transaction and transfer events. */
    udif_event_class_registry = 3U,     /*!< Registry-root and registry-state commitment events. */
    udif_event_class_error = 4U         /*!< Error-report and fault-report events. */
} udif_event_classes;

/**
 * \enum udif_event_codes
 * \brief UDIF audit-event operation identifiers.
 *
 * Event codes identify the specific protocol operation represented by an audit
 * event. Codes are grouped by functional range: certificate and capability
 * governance, query processing, object and registry operations, anchoring,
 * treaty operation, and error reporting.
 */
typedef enum udif_event_codes
{
    udif_audit_event_none = 0x0000U,                    /*!< No event or uninitialized event code. */
    udif_audit_event_cert_enroll_request = 0x1000U,     /*!< Certificate enrollment request event. */
    udif_audit_event_cert_enroll_response = 0x1001U,    /*!< Certificate enrollment response event. */
    udif_audit_event_cert_revoke = 0x1002U,             /*!< Certificate revocation event. */
    udif_audit_event_cert_suspend = 0x1003U,            /*!< Certificate suspension event. */
    udif_audit_event_cert_resume = 0x1004U,             /*!< Certificate resumption event. */
    udif_audit_event_cap_grant = 0x1005U,               /*!< Capability grant event. */
    udif_audit_event_cap_revoke = 0x1006U,              /*!< Capability revocation event. */
    udif_audit_event_query_request = 0x2000U,           /*!< Query request event. */
    udif_audit_event_query_response = 0x2001U,          /*!< Query response event. */
    udif_audit_event_object_create = 0x3000U,           /*!< Object creation event. */
    udif_audit_event_object_transfer_request = 0x3001U, /*!< Object transfer request event. */
    udif_audit_event_object_transfer_confirm = 0x3002U, /*!< Object transfer confirmation event. */
    udif_audit_event_registry_commit = 0x3003U,         /*!< Registry-root commitment event. */
    udif_audit_event_anchor_push = 0x4000U,             /*!< Anchor push event from a child controller to its parent. */
    udif_audit_event_anchor_ack = 0x4001U,              /*!< Anchor acknowledgement event. */
    udif_audit_event_treaty_propose = 0x5000U,          /*!< Treaty proposal event. */
    udif_audit_event_treaty_cosign = 0x5001U,           /*!< Treaty co-signature event. */
    udif_audit_event_treaty_revoke = 0x5002U,           /*!< Treaty revocation event. */
    udif_audit_event_treaty_query_forward = 0x5003U,    /*!< Treaty query forwarding event. */
    udif_audit_event_treaty_query_response = 0x5004U,   /*!< Treaty query response event. */
    udif_audit_event_error_report = 0x6000U             /*!< Signed or locally logged error-report event. */
} udif_event_codes;

/**
 * \struct udif_event_record
 * \brief Canonical UDIF audit-event record.
 *
 * This structure represents a fixed-size audit record committed into the UDIF
 * logging subsystem. The record identifies the class and code of the event,
 * binds the event to actor and subject certificate serial numbers, includes a
 * context identifier for correlation, records the event timestamp, and commits
 * to the event payload through a cryptographic digest and payload length.
 *
 * The payload itself is not stored in this structure. The digest is computed
 * over the canonical payload supplied to the event creation or logging path.
 */
typedef struct udif_event_record
{
    uint8_t eventclass;                             /*!< The audit-event class; one of \ref udif_event_classes. */
    uint16_t eventcode;                             /*!< The operation-specific audit-event code; one of \ref udif_event_codes. */
    uint8_t actorser[UDIF_SERIAL_NUMBER_SIZE];      /*!< Serial number of the entity that originated or authorized the event. */
    uint8_t subjectser[UDIF_SERIAL_NUMBER_SIZE];    /*!< Serial number of the entity, object owner, or protocol subject affected by the event. */
    uint8_t contextid[UDIF_EVENT_CONTEXT_SIZE];     /*!< Fixed-size event correlation identifier, such as a query id, transaction id, treaty id, or zero-padded context digest. */
    uint64_t timestamp;                             /*!< UTC event timestamp in seconds. */
    uint8_t payloaddigest[UDIF_CRYPTO_HASH_SIZE];   /*!< Cryptographic digest of the canonical event payload. */
    uint64_t payloadlen;                            /*!< Length, in bytes, of the canonical payload committed by \c payloaddigest. */
} udif_event_record;

/**
 * \brief Clear a UDIF audit-event record.
 *
 * This function clears all fields in an audit-event record and returns the
 * structure to a zeroized state. It is used to dispose of temporary event
 * records and to prevent stale event metadata from being reused.
 *
 * \param eventrec: [udif_event_record*] Pointer to the event record to clear.
 */
UDIF_EXPORT_API void udif_event_clear(udif_event_record* eventrec);

/**
 * \brief Create a canonical UDIF audit-event record.
 *
 * This function initializes an audit-event record from the supplied event
 * metadata and canonical payload. The function stores the event class, event
 * code, actor serial, subject serial, context identifier, timestamp, payload
 * length, and a cryptographic digest of the supplied payload.
 *
 * The raw payload is not copied into the event record. Only its digest and
 * length are retained, preserving audit integrity without storing the payload
 * itself in the event structure.
 *
 * \param eventrec: [udif_event_record*] Pointer to the destination event record.
 * \param eventclass: [udif_event_classes] The logical audit ledger class for the event.
 * \param eventcode: [udif_event_codes] The protocol operation code represented by the event.
 * \param actorser: [const uint8_t*] Serial number of the actor or issuing entity.
 * \param subjectser: [const uint8_t*] Serial number of the subject affected by the event.
 * \param contextid: [const uint8_t*] Fixed-size context identifier associated with the event.
 * \param timestamp: [uint64_t] UTC event timestamp in seconds.
 * \param payload: [const uint8_t*] Pointer to the canonical payload to commit by digest.
 * \param payloadlen: [size_t] Length, in bytes, of the canonical payload.
 *
 * \return Returns a \ref udif_errors value indicating success or failure.
 */
UDIF_EXPORT_API udif_errors udif_event_create(udif_event_record* eventrec, udif_event_classes eventclass, udif_event_codes eventcode,
    const uint8_t* actorser, const uint8_t* subjectser, const uint8_t* contextid, uint64_t timestamp, const uint8_t* payload, size_t payloadlen);

/**
 * \brief Serialize a UDIF audit-event record.
 *
 * This function serializes an audit-event record into its canonical binary
 * representation. The serialized form uses fixed-size fields and little-endian
 * encoding for integer values. The caller must provide an output buffer of at
 * least \ref UDIF_EVENT_RECORD_SIZE bytes.
 *
 * \param output: [uint8_t*] Pointer to the output buffer that receives the serialized event record.
 * \param outlen: [size_t] Length, in bytes, of the output buffer.
 * \param eventrec: [const udif_event_record*] Pointer to the event record to serialize.
 *
 * \return Returns a \ref udif_errors value indicating success or failure.
 */
UDIF_EXPORT_API udif_errors udif_event_serialize(uint8_t* output, size_t outlen, const udif_event_record* eventrec);

/**
 * \brief Create and append a UDIF audit event to an MCEL ledger.
 *
 * This function creates a canonical audit-event record from the supplied
 * metadata and payload, serializes the event record, and appends it to the
 * specified MCEL-backed UDIF ledger. The function is used by state-mutating
 * handlers to ensure that protocol state changes are durably committed to the
 * audit subsystem.
 *
 * The function fails closed if a usable MCEL manager is not supplied. Callers
 * that mutate protocol state after logging must treat a logging failure as a
 * hard failure and must not allow unaudited state transitions to survive.
 *
 * \param mgr: [udif_mcel_manager*] Pointer to the MCEL manager used for audit logging.
 * \param ledger: [udif_ledger_type] Target UDIF ledger type.
 * \param eventcode: [udif_event_codes] Protocol operation code represented by the event.
 * \param actorser: [const uint8_t*] Serial number of the actor or issuing entity.
 * \param subjectser: [const uint8_t*] Serial number of the subject affected by the event.
 * \param contextid: [const uint8_t*] Fixed-size context identifier associated with the event.
 * \param timestamp: [uint64_t] UTC event timestamp in seconds.
 * \param payload: [const uint8_t*] Pointer to the canonical payload to commit by digest.
 * \param payloadlen: [size_t] Length, in bytes, of the canonical payload.
 *
 * \return Returns a \ref udif_errors value indicating success or failure.
 */
UDIF_EXPORT_API udif_errors udif_event_log(udif_mcel_manager* mgr, udif_ledger_type ledger, udif_event_codes eventcode, const uint8_t* actorser,
    const uint8_t* subjectser, const uint8_t* contextid, uint64_t timestamp, const uint8_t* payload, size_t payloadlen);

#endif
