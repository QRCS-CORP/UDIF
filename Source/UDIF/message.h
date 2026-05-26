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

#ifndef UDIF_MESSAGE_H
#define UDIF_MESSAGE_H

#include "udif.h"
#include "qstp.h"

/**
 * \file message.h
 * \brief UDIF application-layer message framing.
 *
 * Defines the canonical message type taxonomy and the application wire
 * frame carried inside a UDIF tunnel record. QSTP provides cryptographic
 * confidentiality and integrity for the complete UDIF inner record:
 *
 *     UDIF tunnel header || UDIF message frame
 *
 * The UDIF tunnel layer prepends the header before QSTP sealing. UDIF
 * messages carry only protocol semantics after that tunnel record header.
 * Correlation, where needed, is carried inside the canonical payload of
 * specific message types (e.g. queryid inside a query, treatyid inside a
 * treaty exchange).
 *
 * Keepalives, which were removed from QSTP to reduce attack surface, live
 * here as udif_msg_keepalive. Both sides of a tunnel maintain independent
 * keepalive timers; any tunnel with no TX activity within the keepalive
 * interval emits an empty keepalive frame.
 */

/*!
 * \def UDIF_MESSAGE_HEADER_SIZE
 * \brief Fixed overhead of the wire frame: msgtype (1) + reserved (1) + payloadlen (4).
 */
#define UDIF_MESSAGE_HEADER_SIZE 6U

/*!
 * \def UDIF_MESSAGE_PAYLOAD_MAX
 * \brief Maximum UDIF message payload length in bytes.
 *
 * Derived from QSTP's per-packet message cap minus the QSTP tag overhead,
 * the 26-byte UDIF tunnel record header, and the UDIF frame header. Every
 * UDIF message fits inside a single QSTP packet; no fragmentation is
 * performed at the UDIF layer.
 *
 * At every currently-defined UDIF cryptographic suite (including the
 * SPHINCS+/McEliece configurations with SPHINCS+-S5 signatures), the
 * largest message type (a two-signature treaty cosign or object transfer
 * confirmation) fits within this cap with margin to spare. A future suite
 * that introduces larger signatures would surface as a clean
 * udif_error_encode_failure at integration time.
 */
#define UDIF_MESSAGE_PAYLOAD_MAX (QSTP_PACKET_MESSAGE_MAX - QSTP_MACTAG_SIZE - 26U - UDIF_MESSAGE_HEADER_SIZE)

/*!
 * \def UDIF_MESSAGE_VERSION
 * \brief Current UDIF frame version; embedded in the reserved byte.
 */
#define UDIF_MESSAGE_VERSION 1U

/*!
 * \enum udif_message_type
 * \brief Canonical UDIF message type codes.
 *
 * Each code maps to exactly one handler on the receiving side. The high
 * nibble groups related operations for readability; values are one byte
 * on the wire.
 */
typedef enum udif_message_type
{
	udif_msg_none = 0x00U,						/*!< Reserved; must not appear on the wire */
	udif_msg_keepalive = 0x01U,					/*!< Application-level keepalive; empty payload */
	/* Certificate enrollment and lifecycle */
	udif_msg_cert_enroll_req = 0x10U,			/*!< Child CSR to parent */
	udif_msg_cert_enroll_resp = 0x11U,			/*!< Parent-signed certificate to child */
	udif_msg_cert_revoke = 0x12U,				/*!< Parent notifies revocation */
	udif_msg_cert_suspend = 0x13U,				/*!< Parent notifies suspension */
	udif_msg_cert_resume = 0x14U,				/*!< Parent notifies resumption */
	udif_msg_cap_grant = 0x15U,					/*!< Parent grants a capability token */
	udif_msg_cap_revoke = 0x16U,				/*!< Parent revokes a capability token */
	/* Predicate queries */
	udif_msg_query_req = 0x20U,					/*!< Predicate query; inner type code selects family */
	udif_msg_query_resp = 0x21U,				/*!< Verdict and optional proof */
	/* Object and registry operations */
	udif_msg_object_create = 0x30U,				/*!< UA creates an object in its registry */
	udif_msg_object_transfer_req = 0x31U,		/*!< Sender UA requests transfer to receiver */
	udif_msg_object_transfer_confirm = 0x32U,	/*!< Receiver UA co-signs transfer */
	udif_msg_registry_commit = 0x33U,			/*!< Registry root update notification */
	/* Anchor propagation */
	udif_msg_anchor_push = 0x40U,				/*!< Child anchor record to parent */
	udif_msg_anchor_ack = 0x41U,				/*!< Parent acknowledgement */
	/* Peering treaties and cross-domain queries */
	udif_msg_treaty_propose = 0x50U,			/*!< Proposer sends treaty terms */
	udif_msg_treaty_cosign = 0x51U,				/*!< Peer co-signs treaty */
	udif_msg_treaty_revoke = 0x52U,				/*!< Either party revokes an active treaty */
	udif_msg_treaty_query_fwd = 0x53U,			/*!< Cross-domain query forwarded under treaty */
	udif_msg_treaty_query_resp = 0x54U,			/*!< Cross-domain query response */
	/* Non-fatal application errors */
	udif_msg_error_report = 0x60U				/*!< DENY, NOT_OWNER, etc. */
} udif_message_type;

/*!
 * \struct udif_message
 * \brief A single UDIF application message.
 *
 * Instances own their payload buffer. Use udif_message_init and
 * udif_message_dispose to manage lifetime. An empty message (payloadlen == 0, payload == NULL) 
 * is the normal shape for udif_msg_keepalive.
 */
UDIF_EXPORT_API typedef struct udif_message
{
	udif_message_type msgtype;					/*!< Dispatch code */
	uint32_t payloadlen;						/*!< Length of payload in bytes */
	uint8_t* payload;							/*!< Canonical-encoded body; NULL if payloadlen == 0 */
} udif_message;

/*!
 * \brief Initialize a message with a given type and payload.
 *
 * Copies payloadlen bytes from payload into a newly allocated buffer owned
 * by the message. Passing payload == NULL with payloadlen == 0 produces an
 * empty message.
 *
 * \param msg: The output message
 * \param msgtype: The message type code
 * \param payload: [const] The source payload bytes (may be NULL if payloadlen == 0)
 * \param payloadlen: The length of the source payload in bytes
 *
 * \return Returns udif_error_none on success, udif_error_invalid_input on bad arguments,
 *         udif_error_encode_failure if payloadlen exceeds UDIF_MESSAGE_PAYLOAD_MAX,
 *         udif_error_internal on allocation failure.
 */
UDIF_EXPORT_API udif_errors udif_message_init(udif_message* msg, udif_message_type msgtype, const uint8_t* payload, uint32_t payloadlen);

/*!
 * \brief Release allocated storage and zero the message.
 *
 * Safe to call on a zero-initialized or already-disposed message.
 *
 * \param msg: The message to dispose (may be NULL)
 */
UDIF_EXPORT_API void udif_message_dispose(udif_message* msg);

/*!
 * \brief Encode a message into its canonical wire form.
 *
 * Output layout (little-endian multi-byte fields):
 *   offset 0: msgtype     (uint8)
 *   offset 1: version     (uint8, UDIF_MESSAGE_VERSION)
 *   offset 2: payloadlen  (uint32)
 *   offset 6: payload     (payloadlen bytes)
 *
 * \param output: The destination buffer
 * \param outlen: The size of the destination buffer in bytes
 * \param msg: [const] The message to encode
 * \param written: The number of bytes written on success (may be NULL)
 *
 * \return Returns udif_error_none on success, udif_error_encode_failure if the
 *         destination buffer is too small, udif_error_invalid_input on bad arguments.
 */
UDIF_EXPORT_API udif_errors udif_message_encode(uint8_t* output, size_t outlen, const udif_message* msg, size_t* written);

/*!
 * \brief Decode a canonical wire message.
 *
 * Allocates a payload buffer owned by msg on success; caller must dispose
 * via udif_message_dispose.
 *
 * \param msg: The output message
 * \param input: [const] The source buffer containing a complete encoded message
 * \param inplen: The size of the source buffer in bytes
 * \param consumed: The number of bytes consumed from input on success (may be NULL)
 *
 * \return Returns udif_error_none on success, udif_error_decode_failure on malformed
 *         input or unsupported version, udif_error_internal on allocation failure.
 */
UDIF_EXPORT_API udif_errors udif_message_decode(udif_message* msg, const uint8_t* input, size_t inplen, size_t* consumed);

/*!
 * \brief Compute the total encoded wire size of a message.
 *
 * \param msg: [const] The message
 *
 * \return Returns UDIF_MESSAGE_HEADER_SIZE + msg->payloadlen, or 0 if msg is NULL.
 */
UDIF_EXPORT_API size_t udif_message_encoded_size(const udif_message* msg);

/*!
 * \brief Return a human-readable name for a message type.
 *
 * \param msgtype: The type code
 *
 * \return Returns a static string; never NULL (unknown codes return "unknown").
 */
UDIF_EXPORT_API const char* udif_message_type_name(udif_message_type msgtype);

#endif
