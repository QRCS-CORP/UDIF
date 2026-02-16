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

#ifndef UDIF_QUERY_H
#define UDIF_QUERY_H

#include "udif.h"
#include "capability.h"

/**
* \file query.h
* \brief UDIF query operations
*
* This module implements predicate-based queries with minimal disclosure.
* Queries allow entities to request information about objects and their
* ownership without revealing unnecessary details.
*
* Query Types:
* - Existence: Does object X exist?
* - Owner Binding: Is object X owned by entity Y?
* - Attribute Bucket: Does object X have attribute in range [A, B]?
* - Membership Proof: Prove object X is in registry
*
* Query Response Verdicts:
* - No: The predicate is false
* - Yes: The predicate is true (with optional proof)
* - Deny: The query is not authorized
*
* All queries require capability tokens for authorization.
*/

/*!
 * \def UDIF_QUERY_ID_SIZE
 * \brief The query id size.
 */
#define UDIF_QUERY_ID_SIZE 16U

/*!
 * \def UDIF_QUERY_MAX_PREDICATE_SIZE
 * \brief Maximum query predicate data size.
 */
#define UDIF_QUERY_MAX_PREDICATE_SIZE 1024U

/*!
 * \def UDIF_QUERY_MAX_PREDICATE_SIZE
 * \brief Maximum query proof size.
 */
#define UDIF_QUERY_MAX_PROOF_SIZE 8192U

/*!
 * \def UDIF_QUERY_PREDICATE_SIZE
 * \brief The query predicate size.
 */
#define UDIF_QUERY_PREDICATE_SIZE sizeof(size_t)

/*!
 * \def UDIF_QUERY_PROOF_SIZE
 * \brief The query proof size.
 */
#define UDIF_QUERY_PROOF_SIZE sizeof(size_t)

/*!
 * \def UDIF_QUERY_TYPE_SIZE
 * \brief The query type size.
 */
#define UDIF_QUERY_TYPE_SIZE 1U

/*!
 * \def UDIF_QUERY_VERDICT_SIZE
 * \brief The query verdict size.
 */
#define UDIF_QUERY_VERDICT_SIZE 1U

/*!
 * \def UDIF_QUERY_STRUCTURE_SIZE
 * \brief The query structure size.
 */
#define UDIF_QUERY_STRUCTURE_SIZE (UDIF_CRYPTO_HASH_SIZE + \
	UDIF_QUERY_ID_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_QUERY_PREDICATE_SIZE + \
	UDIF_QUERY_TYPE_SIZE)

/*!
 * \def UDIF_QUERY_RESPONSE_STRUCTURE_SIZE
 * \brief The query structure size.
 */
#define UDIF_QUERY_RESPONSE_STRUCTURE_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_QUERY_ID_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_QUERY_VERDICT_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_QUERY_PROOF_SIZE)

 /*!
 * \enum udif_query_types
 * \brief Query predicate types
 */
typedef enum udif_query_types
{
	udif_query_exist = 1U,						/*!< Existence query */
	udif_query_owner_binding = 2U,				/*!< Owner binding query */
	udif_query_attr_bucket = 3U,				/*!< Attribute bucket query */
	udif_query_membership_proof = 4U			/*!< Membership proof query */
} udif_query_types;

/*!
* \enum udif_query_verdicts
* \brief Query response verdicts
*/
typedef enum udif_query_verdicts
{
	udif_verdict_no = 0U,						/*!< Negative response */
	udif_verdict_yes = 1U,						/*!< Positive response */
	udif_verdict_deny = 2U						/*!< Access denied */
} udif_query_verdicts;

 /*!
 * \struct udif_query
 * \brief Query request
 *
 * A query asks a predicate question with minimal disclosure.
 * Responses are signed yes/no/deny verdicts.
 */
UDIF_EXPORT_API typedef struct udif_query
{
	uint8_t capabilityref[UDIF_CRYPTO_HASH_SIZE];	/*!< Capability reference */
	uint8_t queryid[UDIF_QUERY_ID_SIZE];			/*!< Query identifier */
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE];		/*!< Target entity serial */
	uint64_t timeanchor;							/*!< Time anchor */
	size_t predlen;									/*!< Predicate length */
	uint8_t querytype;								/*!< Query type */
	uint8_t* predicate;								/*!< Predicate data */
} udif_query;

/*!
* \struct udif_query_response
* \brief Query response
*
* Response to a query request with a verdict and optional proof.
*/
UDIF_EXPORT_API typedef struct udif_query_response
{
	uint8_t signature[UDIF_SIGNED_HASH_SIZE];		/*!< Response signature */
	uint8_t queryid[UDIF_QUERY_ID_SIZE];			/*!< Query identifier */
	uint8_t respser[UDIF_SERIAL_NUMBER_SIZE];		/*!< Responder serial */
	uint8_t verdict;								/*!< Verdict (yes/no/deny) */
	uint64_t timestamp;								/*!< Reply timestamp */
	size_t prooflen;								/*!< Proof length */
	uint8_t* proof;									/*!< Optional Merkle proof */
} udif_query_response;

/*!
* \brief Clear a query
*
* Zeros out a query structure.
*
* \param query: The query to clear
*/
UDIF_EXPORT_API void udif_query_clear(udif_query* query);

/*!
* \brief Compute query digest
*
* Calculates the canonical digest of a query for signing.
*
* \param digest: The output digest (32 bytes)
* \param query: [const] The query
*/
UDIF_EXPORT_API void udif_query_compute_digest(uint8_t* digest, const udif_query* query);

/*!
* \brief Create an attribute bucket query
*
* Asks whether an object's attribute falls within a range.
*
* \param query: The output query structure
* \param queryid: [const] The query identifier (32 bytes)
* \param targetser: [const] The target entity serial (16 bytes)
* \param serial: [const] The object serial (32 bytes)
* \param attrmin: The minimum attribute value
* \param attrmax: The maximum attribute value
* \param timeanchor: The time anchor (0 = current)
* \param capability: [const] The capability reference (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_create_attr_bucket(udif_query* query, const uint8_t* queryid, const uint8_t* targetser,
	const uint8_t* serial, uint64_t attrmin, uint64_t attrmax, uint64_t timeanchor, const uint8_t* capability);

/*!
* \brief Create an existence query
*
* Asks whether an object exists in the system.
*
* \param query: The output query structure
* \param queryid: [const] The query identifier (32 bytes)
* \param targetser: [const] The target entity serial (16 bytes)
* \param serial: [const] The object serial to query (32 bytes)
* \param timeanchor: The time anchor for temporal queries (0 = current)
* \param capability: [const] The capability reference (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_create_existence(udif_query* query, const uint8_t* queryid, const uint8_t* targetser,
	const uint8_t* serial, uint64_t timeanchor, const uint8_t* capability);

/*!
* \brief Create a membership proof query
*
* Requests a Merkle proof that an object is in the registry.
*
* \param query: The output query structure
* \param queryid: [const] The query identifier (32 bytes)
* \param targetser: [const] The target entity serial (16 bytes)
* \param serial: [const] The object serial (32 bytes)
* \param timeanchor: The time anchor (0 = current)
* \param capability: [const] The capability reference (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_create_membership_proof(udif_query* query, const uint8_t* queryid, const uint8_t* targetser,
	const uint8_t* serial, uint64_t timeanchor, const uint8_t* capability);

/*!
* \brief Create an owner binding query
*
* Asks whether an object is owned by a specific entity.
*
* \param query: The output query structure
* \param queryid: [const] The query identifier (32 bytes)
* \param targetser: [const] The target entity serial (16 bytes)
* \param serial: [const] The object serial (32 bytes)
* \param ownerser: [const] The claimed owner serial (16 bytes)
* \param timeanchor: The time anchor (0 = current)
* \param capability: [const] The capability reference (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_create_owner_binding(udif_query* query, const uint8_t* queryid, const uint8_t* targetser,
	const uint8_t* serial, const uint8_t* ownerser, uint64_t time_anchor, const uint8_t* capability);

/*!
* \brief Create a query response
*
* Generates a response to a query.
*
* \param response: The output response structure
* \param query: [const] The original query
* \param verdict: The verdict (no, yes, deny)
* \param proofdata: [const] The proof data (can be NULL)
* \param prooflen: The proof data length
* \param respser: [const] The responder's serial (16 bytes)
* \param respsigkey: [const] The responder's private key
* \param ctime: The current time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_create_response(udif_query_response* response, const udif_query* query, uint8_t verdict, const uint8_t* proofdata,
	size_t prooflen, const uint8_t* respser, const uint8_t* respsigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Deserialize a query
*
* Decodes a query from canonical format.
*
* \param query: The output query structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_deserialize(udif_query* query, const uint8_t* input, size_t inplen);

/*!
* \brief Serialize a query
*
* Encodes a query to canonical format.
*
* \param output: The output buffer
* \param outlen: Pointer to output length (in: buffer size, out: bytes written)
* \param query: [const] The query to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_serialize(uint8_t* output, size_t* outlen, const udif_query* query);

/*!
* \brief Check if query is fresh
*
* Verifies that a query is within the time window.
*
* \param query: [const] The query
* \param ctime: The current time (UTC seconds)
*
* \return Returns true if fresh
*/
UDIF_EXPORT_API bool udif_query_is_fresh(const udif_query* query, uint64_t ctime);

/*!
* \brief Clear a query response
*
* Zeros out and frees a query response structure.
*
* \param response: The response to clear
*/
UDIF_EXPORT_API void udif_query_response_clear(udif_query_response* response);

/*!
* \brief Compute response digest
*
* Calculates the canonical digest of a response for signing.
*
* \param digest: The output digest (32 bytes)
* \param response: [const] The response
* \param queryid: [const] The query identifier (32 bytes)
*/
UDIF_EXPORT_API void udif_query_response_compute_digest(uint8_t* digest, const udif_query_response* response, const uint8_t* queryid);

/*!
* \brief Deserialize a query response
*
* Decodes a response from canonical format.
*
* \param response: The output response structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_response_deserialize(udif_query_response* response, const uint8_t* input, size_t inplen);

/*!
* \brief Serialize a query response
*
* Encodes a response to canonical format.
*
* \param output: The output buffer
* \param outlen: Pointer to output length (in: buffer size, out: bytes written)
* \param response: [const] The response to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_query_response_serialize(uint8_t* output, size_t* outlen, const udif_query_response* response);

/*!
* \brief Validate query authorization
*
* Checks that the query has appropriate capability authorization.
*
* \param query: [const] The query
* \param capability: [const] The capability token
* \param target_serial: [const] The target entity serial (16 bytes)
*
* \return Returns true if authorized
*/
UDIF_EXPORT_API bool udif_query_validate_authorization(const udif_query* query, const udif_capability* capability, const uint8_t* targser);

/*!
* \brief Verify a query response
*
* Verifies the signature on a query response.
*
* \param response: [const] The response to verify
* \param query: [const] The original query
* \param respverkey: [const] The responder's public key
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_query_verify_response(const udif_query_response* response, const udif_query* query, const uint8_t* respverkey);

#endif
