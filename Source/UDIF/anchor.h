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

#ifndef UDIFANCHOR_H
#define UDIFANCHOR_H

#include "udif.h"

/**
* \file anchor.h
* \brief UDIF anchor record operations
*
* This module implements anchor records for creating tamper-evident
* audit chains. Anchor records commit registry and log states at
* periodic intervals, signed by the child entity.
*
* Anchor Records contain:
* - Child entity serial
* - Sequence number
* - Timestamp
* - Registry Merkle root
* - Transaction log root
* - Membership log root
* - Object/event counts
* - Child signature
*
* Anchors flow from User Agents -> Group Controllers -> Branch Controllers -> Root,
* creating a hierarchical chain of trust and accountability.
*/


/*!
 * \def UDIF_ANCHOR_INTERVAL_SEC
 * \brief Default anchor interval (1 hour).
 */
#define UDIF_ANCHOR_INTERVAL_SEC 3600U

/*!
 * \def UDIF_ANCHOR_MAX_AGE_MAX
 * \brief Maximum anchor age for acceptance (2 hours).
 */
#define UDIF_ANCHOR_MAX_AGE_MAX 7200U

/*!
 * \def UDIF_ANCHOR_MAX_SIZE
 * \brief Maximum anchor encoded size estimate.
 */
#define UDIF_ANCHOR_MAX_SIZE (512U + UDIF_SIGNED_HASH_SIZE)

/*!
 * \def UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER
 * \brief The anchor membership event counter size.
 */
#define UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER 4U

/*!
 * \def UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER
 * \brief The anchor registry object counter size.
 */
#define UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER 4U

/*!
 * \def UDIF_ANCHOR_REGISTRY_TRANSACTION_COUNTER
 * \brief The anchor registry transaction counter size.
 */
#define UDIF_ANCHOR_REGISTRY_TRANSACTION_COUNTER 4U

/*!
 * \def UDIF_ANCHOR_SEQUENCE_SIZE
 * \brief The anchor sequence number size.
 */
#define UDIF_ANCHOR_SEQUENCE_SIZE 8U

/*!
 * \def UDIF_ANCHOR_RECORD_SIZE
 * \brief The byte size of an anchor record.
 */
#define UDIF_ANCHOR_RECORD_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_CRYPTO_HASH_SIZE +\
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_ANCHOR_SEQUENCE_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER + \
	UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER + \
	UDIF_ANCHOR_REGISTRY_TRANSACTION_COUNTER)

/*!
 * \def UDIF_ANCHOR_SIGNING_SIZE
 * \brief The anchor recordsigning size.
 */
#define UDIF_ANCHOR_SIGNING_SIZE (UDIF_CRYPTO_HASH_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER + \
	UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER + \
	UDIF_ANCHOR_SEQUENCE_SIZE + \
	UDIF_ANCHOR_REGISTRY_TRANSACTION_COUNTER)

/*!
 * \struct udif_anchor_record
 * \brief Anchor record
 *
 * Anchor records commit the state of logs and registries at periodic
 * intervals, creating a tamper-evident chain from UAs to the Root.
 */
UDIF_EXPORT_API typedef struct udif_anchor_record
{
	uint8_t signature[UDIF_SIGNED_HASH_SIZE];		/*!< Child signature */
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE];					/*!< Membership log root */
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE];				/*!< Registry Merkle root */
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE];					/*!< Transaction log root */
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE];		/*!< Child entity serial */
	uint64_t sequence;								/*!< Sequence number */
	uint64_t timestamp;								/*!< Anchor timestamp */
	uint32_t memcount;								/*!< Membership event count */
	uint32_t regcount;								/*!< Registry object count */
	uint32_t txcount;								/*!< Transaction count */
} udif_anchor_record;

/*!
* \brief Create an anchor record
*
* Generates an anchor record for a child entity's current state.
*
* \param anchor: The output anchor record
* \param childser: [const] The child entity serial (16 bytes)
* \param sequence: The sequence number (monotonically increasing)
* \param timestamp: The current time (UTC seconds)
* \param regroot: [const] The registry Merkle root (32 bytes)
* \param txroot: [const] The transaction log root (32 bytes)
* \param mroot: [const] The membership log root (32 bytes)
* \param regcount: The number of objects in registry
* \param txcount: The number of transactions
* \param memcount: The number of membership events
* \param childsigkey: [const] The child's private key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_anchor_create(udif_anchor_record* anchor, const uint8_t* childser, uint64_t sequence, uint64_t timestamp,
	const uint8_t* regroot, const uint8_t* txroot, const uint8_t* mroot, uint32_t regcount, uint32_t txcount,
	uint32_t memcount, const uint8_t* childsigkey, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Deserialize an anchor record
*
* Decodes an anchor record from canonical TLV format.
*
* \param anchor: The output anchor record
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_anchor_deserialize(udif_anchor_record* anchor, const uint8_t* input, size_t inplen);

/*!
* \brief Compute anchor digest
*
* Calculates the canonical digest of an anchor record.
*
* \param digest: The output digest (32 bytes)
* \param anchor: [const] The anchor record
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_anchor_compute_digest(uint8_t* digest, const udif_anchor_record* anchor);

/*!
* \brief Compute object digest and signature
*
* Computes the canonical digest for an object, and signs the object.
*
* \param anchor: The anchor
* \param sigkey: [const] The owner's private key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_anchor_compute_signature(udif_anchor_record* anchor, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Clear an anchor record
*
* Zeros out an anchor record structure.
*
* \param anchor: The anchor record to clear
*/
UDIF_EXPORT_API void udif_anchor_clear(udif_anchor_record* anchor);

/*!
* \brief Compare two anchor records
*
* Checks if two anchor records are identical.
*
* \param a: [const] The first anchor record
* \param b: [const] The second anchor record
*
* \return Returns true if identical
*/
UDIF_EXPORT_API bool udif_anchor_compare(const udif_anchor_record* a, const udif_anchor_record* b);

/*!
* \brief Get anchor encoded size
*
* Calculates the serialized size of an anchor record.
*
* \param anchor: [const] The anchor record
*
* \return The encoded size in bytes
*/
UDIF_EXPORT_API size_t udif_anchor_encoded_size(const udif_anchor_record* anchor);

/*!
* \brief Check anchor freshness
*
* Verifies that an anchor is recent (within time window).
*
* \param anchor: [const] The anchor record
* \param ctime: The current time (UTC seconds)
* \param maxage: Maximum age in seconds
*
* \return Returns true if fresh
*/
UDIF_EXPORT_API bool udif_anchor_is_fresh(const udif_anchor_record* anchor, uint64_t ctime, uint64_t maxage);

/*!
* \brief Serialize an anchor record
*
* Encodes an anchor record to canonical TLV format.
*
* \param output: The output buffer
* \param outlen: The output buffer length
* \param anchor: [const] The anchor record to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_anchor_serialize(uint8_t* output, size_t outlen, const udif_anchor_record* anchor);

/*!
* \brief Validate anchor sequence
*
* Checks that sequence number is valid (non-zero, monotonic).
*
* \param anchor: [const] The anchor record
* \param prevseq: The previous sequence number (0 = first anchor)
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_anchor_validate_sequence(const udif_anchor_record* anchor, uint64_t prevseq);

/*!
* \brief Verify an anchor record
*
* Verifies the signature and sequence on an anchor record.
*
* \param anchor: [const] The anchor record
* \param pubkey: [const] The child's public key
* \param expseq: The expected sequence number (0 = don't check)
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_anchor_verify(const udif_anchor_record* anchor, const uint8_t* childverkey, uint64_t expseq);

/*!
* \brief Verify anchor chain continuity
*
* Verifies that two sequential anchors form a valid chain.
*
* \param prevanchor: [const] The previous anchor
* \param nextanchor: [const] The next anchor
* \param childverkey: [const] The child's public key
*
* \return Returns true if chain is valid
*/
UDIF_EXPORT_API bool udif_anchor_verify_chain(const udif_anchor_record* prevanchor, const udif_anchor_record* nextanchor, const uint8_t* childverkey);

#endif
