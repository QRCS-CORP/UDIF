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

#ifndef UDIF_CAPABILITY_H
#define UDIF_CAPABILITY_H

#include "udif.h"

/**
* \file capability.h
* \brief UDIF capability token management
*
* This module implements capability-based access control for UDIF.
* Capabilities are unforgeable tokens that grant specific permissions
* to entities. They use KMAC-256 for authentication.
*
* Capabilities define:
* - Verbs: What operations are allowed
* - Scopes: Where operations can be performed
* - Subject: Who holds the capability
* - Issuer: Who granted the capability
* - Validity: When the capability expires
*/

/*! \def UDIF_CAPABILITY_BITMAP_SIZE
 * \brief Capability bitmap size in bytes (64-bit)
 */
#define UDIF_CAPABILITY_POLICY_SIZE 4U

/*! \def UDIF_CAPABILITY_ENCODED_SIZE
 * \brief The capability structure encoded size
 */
#define UDIF_CAPABILITY_ENCODED_SIZE (UDIF_CRYPTO_HASH_SIZE + \
	UDIF_CRYPTO_MAC_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_CAPABILITY_POLICY_SIZE)

/*! \def UDIF_CAPABILITY_SIGNED_SIZE
 * \brief The capability structure signed size
 */
#define UDIF_CAPABILITY_SIGNED_SIZE (UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_CAPABILITY_POLICY_SIZE)

/*!
* \struct udif_capability
* \brief Capability token
*
* A capability token grants specific permissions to an entity.
* It is authenticated with KMAC-256 and can be verified by the issuer.
*/
UDIF_EXPORT_API typedef struct udif_capability
{
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE];		/*!< Capability digest */
	uint8_t tag[UDIF_CRYPTO_MAC_SIZE];			/*!< KMAC authentication tag */
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE];	/*!< Issuer serial */
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE];	/*!< Recipient serial */
	uint64_t scopebitmap;						/*!< Allowed operation scopes */
	uint64_t validto;							/*!< Expiration time */
	uint64_t verbsbitmap;						/*!< Allowed operation verbs */
	uint32_t policy;							/*!< Policy version */
} udif_capability;


/** \cond NO_DOCUMENT */

static const char UDIF_CAPABILITY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Capability denied by policy",
	"Empty capability mask",
	"Conflicting capability bits"
};

/** \endcond NO_DOCUMENT */

/*!
 * \enum udif_capability_id
 * \brief Canonical capability identifiers (bit positions map to the mask).
 */
UDIF_EXPORT_API typedef enum udif_capability_id
{
	udif_capability_issue_certificate = 0x00U,		/*!< Issue subordinate certificates */
	udif_capability_revoke_certificate = 0x01U,	/*!< Revoke certificates */
	udif_capability_issue_token = 0x02U,		/*!< Issue capability/attestation tokens */
	udif_capability_validate_token = 0x03U,		/*!< Validate tokens and claims */
	udif_capability_register_issuer = 0x04U,	/*!< Register issuer domain codes */
	udif_capability_rotate_keys = 0x05U,		/*!< Rotate root/issuer keys */
	udif_capability_directory_query = 0x06U,	/*!< Query directory / discovery */
	udif_capability_audit_logging_access = 0x07U,	/*!< Access audit logs */
	udif_capability_admin = 0x08U				/*!< Administrative override */
} udif_capability_id;

/*!
* \enum udif_capability_verbs
* \brief Capability permission verbs (bit positions)
*/
UDIF_EXPORT_API typedef enum udif_capability_verbs
{
	udif_capability_query_exist = 0U,			/*!< Query existence */
	udif_capability_query_owner_binding = 1U,	/*!< Query owner binding */
	udif_capability_query_attr_bucket = 2U,		/*!< Query attribute bucket */
	udif_capability_prove_membership = 3U,		/*!< Prove membership */
	udif_capability_forward_query = 4U,			/*!< Forward query */
	udif_capability_admin_enroll = 5U,			/*!< Enroll entity */
	udif_capability_admin_suspend = 6U,			/*!< Suspend entity */
	udif_capability_admin_resume = 7U,			/*!< Resume entity */
	udif_capability_admin_revoke = 8U,			/*!< Revoke entity */
	udif_capability_admin_branch_create = 9U,	/*!< Create branch */
	udif_capability_admin_branch_retire = 10U,	/*!< Retire branch */
	udif_capability_registry_commit = 11U,		/*!< Commit registry */
	udif_capability_tx_create = 12U,            /*!< Create transaction */
	udif_capability_tx_accept = 13U,            /*!< Accept transaction */
	udif_capability_logging_anchor_send = 14U,  /*!< Send anchor */
	udif_capability_logging_anchor_verify = 15U,/*!< Verify anchor */
	udif_capability_treaty_negotiate = 16U,     /*!< Negotiate treaty */
	udif_capability_treaty_query_exec = 17U,    /*!< Execute treaty query */
	udif_capability_treaty_query_origin = 18U,  /*!< Originate treaty query */
	udif_capability_telemetry_export = 19U,     /*!< Export telemetry */
	udif_capability_error_report = 20U          /*!< Report error */
} udif_capability_verbs;

/*!
* \enum udif_capability_scopes
* \brief Capability scope flags
*/
UDIF_EXPORT_API typedef enum udif_capability_scopes
{
	udif_scope_local = 0U,						/*!< Local only */
	udif_scope_intra_domain = 1U,				/*!< Intra-domain */
	udif_scope_treaty = 2U						/*!< Cross-domain treaty */
} udif_capability_scopes;

/*!
* \brief Check if capability allows a scope
*
* Tests if a specific operation scope is granted.
*
* \param capability: [const] The capability
* \param scope: The scope to check
*
* \return Returns true if allowed
*/
UDIF_EXPORT_API bool udif_capability_allows_scope(const udif_capability* capability, uint32_t scope);

/*!
* \brief Check if capability allows a verb
*
* Tests if a specific operation verb is granted.
*
* \param capability: [const] The capability
* \param verb: The verb to check (bit position)
*
* \return Returns true if allowed
*/
UDIF_EXPORT_API bool udif_capability_allows_verb(const udif_capability* capability, uint32_t verb);

/*!
* \brief Clear a capability
*
* Zeros out a capability structure.
*
* \param capability: The capability to clear
*/
UDIF_EXPORT_API void udif_capability_clear(udif_capability* capability);

/*!
* \brief Create a capability token
*
* Creates a new capability token authenticated with KMAC-256.
*
* \param capability: The output capability structure
* \param verbsbitmap: The allowed operation verbs
* \param scopebitmap: The allowed operation scopes
* \param issuedto: [const] The recipient serial (16 bytes)
* \param issuedby: [const] The issuer serial (16 bytes)
* \param validto: The expiration time (UTC seconds)
* \param policy: The policy version number
* \param issuerkey: [const] The issuer's MAC key
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_create(udif_capability* capability, uint32_t verbsbitmap, uint32_t scopebitmap, const uint8_t* issuedto,
	const uint8_t* issuedby, uint64_t validto, uint32_t policy, const uint8_t* issuerkey);

/*!
* \brief Compute object digest
*
* Computes the canonical digest for an object, does not include the signature and hash.
*
* \param digest: The output digest (32 bytes)
* \param capability: The output capability structure
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_compute_digest(uint8_t* digest, const udif_capability* capability);

/*!
* \brief Deserialize a capability
*
* Decodes a capability from canonical TLV format.
*
* \param capability: The output capability structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_deserialize(udif_capability* capability, const uint8_t* input, size_t inplen);

/*!
* \brief Check if capability grants permission
*
* Comprehensive check: verb, scope, and expiration.
*
* \param capability: [const] The capability
* \param verb: The required verb
* \param scope: The required scope
* \param ctime: The current time
*
* \return Returns true if permission granted
*/
UDIF_EXPORT_API bool udif_capability_grants_permission(const udif_capability* capability, uint32_t verb, uint32_t scope, uint64_t ctime);

/*!
* \brief Check if capability is expired
*
* Tests if a capability has expired.
*
* \param capability: [const] The capability
* \param ctime: The current time (UTC seconds)
*
* \return Returns true if expired
*/
UDIF_EXPORT_API bool udif_capability_is_expired(const udif_capability* capability, uint64_t ctime);

/*!
* \brief Serialize a capability
*
* Encodes a capability to canonical TLV format.
*
* \param output: The output buffer
* \param outlen: The output buffer LENGTH
* \param capability: [const] The capability to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_serialize(uint8_t* output, size_t outlen, const udif_capability* capability);

/*!
* \brief Verify a capability token
*
* Verifies the KMAC authentication tag on a capability.
*
* \param capability: [const] The capability to verify
* \param issuerkey: [const] The issuer's MAC key
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_capability_verify(const udif_capability* capability, const uint8_t* issuerkey);

#endif
