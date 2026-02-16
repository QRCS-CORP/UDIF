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

#ifndef UDIF_TREATY_H
#define UDIF_TREATY_H

#include "udif.h"

/**
* \file treaty.h
* \brief UDIF treaty operations
*
* This module implements bilateral treaties between UDIF domains.
* Treaties establish formal agreements for cross-domain operations,
* defining what information can be shared and under what conditions.
*
* Treaty Features:
* - Bilateral agreements between two domains
* - Scope negotiation (what operations are allowed)
* - Duration limits (start and end times)
* - Policy epoch tracking for updates
* - Dual signatures (both parties must agree)
*
* Treaty Lifecycle:
* 1. Propose: Domain A creates treaty proposal
* 2. Accept: Domain B signs to accept
* 3. Active: Treaty is in effect
* 4. Expire: Treaty reaches end time
* 5. Revoke: Either party can revoke early
*
* Treaties enable:
* - Cross-domain queries
* - Object transfers between domains
* - Federated identity verification
* - Collaborative analytics
*/

/*!
 * \def UDIF_TREATY_SCOPE_ANALYTICS
 * \brief The treaty scope analytic.
 */
#define UDIF_TREATY_SCOPE_ANALYTICS 1U

/*!
 * \def UDIF_TREATY_SCOPE_INTRA_DOMAIN
 * \brief Intra-domain treaty scope.
 */
#define UDIF_TREATY_SCOPE_INTRA_DOMAIN 2U

/*!
 * \def UDIF_TREATY_SCOPE_LOCAL
 * \brief Local only treaty scope.
 */
#define UDIF_TREATY_SCOPE_LOCAL 4U

/*!
 * \def UDIF_TREATY_SCOPE_QUERY
 * \brief The intra-domain query scope.
 */
#define UDIF_TREATY_SCOPE_QUERY 8U

/*!
 * \def UDIF_TREATY_SCOPE_TRANSFER
 * \brief The cross domain scope transfer.
 */
#define UDIF_TREATY_SCOPE_TRANSFER 16U

/*!
 * \def UDIF_TREATY_SCOPE_TREATY
 * \brief Cross-domain treaty scope.
 */
#define UDIF_TREATY_SCOPE_TREATY 32U

/*!
 * \def UDIF_TREATY_SCOPE_RESERVED1
 * \brief The reserved-1 scope setting.
 */
#define UDIF_TREATY_SCOPE_RESERVED1 64U

/*!
 * \def UDIF_TREATY_SCOPE_RESERVED2
 * \brief The reserved-2 scope setting.
 */
#define UDIF_TREATY_SCOPE_RESERVED2 128U

/*!
 * \def UDIF_TREATY_SCOPE_RESERVED3
 * \brief The reserved-3 scope setting.
 */
#define UDIF_TREATY_SCOPE_RESERVED3 256U

/*!
 * \def UDIF_TREATY_SCOPE_MAX
 * \brief The maximum scope setting.
 */
#define UDIF_TREATY_SCOPE_MAX 256U

/*!
 * \def UDIF_TREATY_POLICY_VERSION_SIZE
 * \brief The policy version size.
 */
#define UDIF_TREATY_POLICY_VERSION_SIZE 4U

/*!
 * \def UDIF_TREATY_SCOPE_QUERY_SIZE
 * \brief The query scope integer size.
 */
#define UDIF_TREATY_SCOPE_QUERY_SIZE 4U

/*!
 * \def UDIF_TREATY_DEFAULT_DURATION
 * \brief Default treaty duration (1 year).
 */
#define UDIF_TREATY_DEFAULT_DURATION (365U * 24U * 3600U)

/*!
 * \def UDIF_TREATY_MAX_DURATION
 * \brief Maximum treaty duration (5 years).
 */
#define UDIF_TREATY_MAX_DURATION (5U * 365U * 24U * 3600U)

/*!
 * \def UDIF_TREATY_STRUCTURE_SIZE
 * \brief The treaty structure byte size.
 */
#define UDIF_TREATY_STRUCTURE_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_SIGNED_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_TREATY_POLICY_VERSION_SIZE + \
	UDIF_TREATY_SCOPE_QUERY_SIZE)

 /*!
 * \struct udif_treaty
 * \brief Cross-domain treaty
 *
 * A bilateral agreement between two domain controllers allowing
 * controlled cross-domain query operations.
 */
UDIF_EXPORT_API typedef struct udif_treaty
{
	uint8_t domsiga[UDIF_SIGNED_HASH_SIZE];		/*!< Domain A signature */
	uint8_t domsigb[UDIF_SIGNED_HASH_SIZE];		/*!< Domain B signature */
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE];   /*!< Domain A serial */
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE];	/*!< Domain B serial */
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];	/*!< Treaty identifier */
	uint64_t validfrom;							/*!< Establishment time */
	uint64_t validto;							/*!< Treaty duration */
	uint32_t policy;							/*!< Policy version */
	uint32_t scopebitmap;						/*!< Allowed query scopes */
} udif_treaty;

/*!
* \brief Accept a treaty proposal
*
* Signs a treaty proposal to accept and activate it.
*
* \param treaty: The treaty structure (will be updated)
* \param domsigkeyb: [const] Domain B's private key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_treaty_accept(udif_treaty* treaty, const uint8_t* domsigkeyb, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Check if treaty allows scope
*
* Tests if a specific operation scope is permitted.
*
* \param treaty: [const] The treaty
* \param scope: The scope to check
*
* \return Returns true if allowed
*/
UDIF_EXPORT_API bool udif_treaty_allows_scope(const udif_treaty* treaty, uint32_t scope);

/*!
* \brief Clear a treaty
*
* Zeros out a treaty structure.
*
* \param treaty: The treaty to clear
*/
UDIF_EXPORT_API void udif_treaty_clear(udif_treaty* treaty);

/*!
* \brief Compare two treaties
*
* Checks if two treaties are identical.
*
* \param a: [const] The first treaty
* \param b: [const] The second treaty
*
* \return Returns true if identical
*/
UDIF_EXPORT_API bool udif_treaty_compare(const udif_treaty* a, const udif_treaty* b);

/*!
* \brief Compute treaty digest
*
* Calculates the canonical digest of a treaty for signing.
*
* \param digest: The output digest (32 bytes)
* \param treaty: [const] The treaty
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_treaty_compute_digest(uint8_t* digest, const udif_treaty* treaty);

/*!
* \brief Create a treaty proposal
*
* Creates a treaty proposal for bilateral agreement.
*
* \param treaty: The output treaty structure
* \param treatyid: [const] The treaty identifier (32 bytes)
* \param domsera: [const] The first domain serial (16 bytes)
* \param domserb: [const] The second domain serial (16 bytes)
* \param scopebitmap: The allowed operation scopes
* \param validfrom: The treaty start time (UTC seconds)
* \param validto: The treaty end time (UTC seconds)
* \param policy: The policy version number
* \param domsigkeya: [const] Domain A's private key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_treaty_create_proposal(udif_treaty* treaty, const uint8_t* treatyid, const uint8_t* domsera, const uint8_t* domserb, 
	uint32_t scopebitmap, uint64_t validfrom, uint64_t validto, uint32_t policy, const uint8_t* domsigkeya, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Deserialize a treaty
*
* Decodes a treaty from canonical format.
*
* \param treaty: The output treaty structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_treaty_deserialize(udif_treaty* treaty, const uint8_t* input, size_t inplen);

/*!
* \brief Get treaty encoded size
*
* Calculates the serialized size of a treaty.
*
* \param treaty: [const] The treaty
*
* \return The encoded size in bytes
*/
UDIF_EXPORT_API size_t udif_treaty_encoded_size(const udif_treaty* treaty);

/*!
* \brief Get treaty duration
*
* Calculates the treaty duration in seconds.
*
* \param treaty: [const] The treaty
*
* \return The duration in seconds
*/
UDIF_EXPORT_API uint64_t udif_treaty_get_duration(const udif_treaty* treaty);

/*!
* \brief Check if treaty is active
*
* Verifies that a treaty is currently in effect.
*
* \param treaty: [const] The treaty
* \param ctime: The current time (UTC seconds)
*
* \return Returns true if active
*/
UDIF_EXPORT_API bool udif_treaty_is_active(const udif_treaty* treaty, uint64_t ctime);

/*!
* \brief Check if treaty is expired
*
* Tests if a treaty has reached its end time.
*
* \param treaty: [const] The treaty
* \param ctime: The current time (UTC seconds)
*
* \return Returns true if expired
*/
UDIF_EXPORT_API bool udif_treaty_is_expired(const udif_treaty* treaty, uint64_t ctime);

/*!
* \brief Check if entity is treaty participant
*
* Tests if an entity is one of the treaty parties.
*
* \param treaty: [const] The treaty
* \param entityser: [const] The entity serial (16 bytes)
*
* \return Returns true if participant
*/
UDIF_EXPORT_API bool udif_treaty_is_participant(const udif_treaty* treaty, const uint8_t* entityser);

/*!
* \brief Check if treaty is pending
*
* Tests if a treaty is proposed but not yet accepted.
*
* \param treaty: [const] The treaty
*
* \return Returns true if pending (only has one signature)
*/
UDIF_EXPORT_API bool udif_treaty_is_pending(const udif_treaty* treaty);

/*!
* \brief Serialize a treaty
*
* Encodes a treaty to canonical format.
*
* \param output: The output buffer
* \param outlen: The output buffer length
* \param treaty: [const] The treaty to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_treaty_serialize(uint8_t* output, size_t outlen, const udif_treaty* treaty);

/*!
* \brief Validate treaty parameters
*
* Checks that treaty parameters are valid.
*
* \param treaty: [const] The treaty
*
* \return Returns udif_error_none if valid
*/
UDIF_EXPORT_API udif_errors udif_treaty_validate(const udif_treaty* treaty);

/*!
* \brief Verify a treaty
*
* Verifies both signatures on a treaty.
*
* \param treaty: [const] The treaty to verify
* \param domverkeya: [const] Domain A's public key
* \param domverkeyb: [const] Domain B's public key
*
* \return Returns true if both signatures are valid
*/
UDIF_EXPORT_API bool udif_treaty_verify(const udif_treaty* treaty, const uint8_t* domverkeya, const uint8_t* domverkeyb);

#endif
