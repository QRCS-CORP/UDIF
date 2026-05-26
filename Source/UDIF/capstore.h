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

#ifndef UDIF_CAPSTORE_H
#define UDIF_CAPSTORE_H

#include "udif.h"
#include "capability.h"

/**
 * \file capstore.h
 * \brief Runtime capability-token store.
 *
 * The capability store is a fixed-capacity, deterministic lookup table keyed
 * by the canonical capability digest. It is used by the policy engine to
 * resolve the capability reference carried by a query or administrative
 * request before an authorization decision is made.
 */

/*! \def UDIF_CAPSTORE_CAPACITY
 * \brief Maximum number of capability tokens retained in one entity context.
 */
#define UDIF_CAPSTORE_CAPACITY 128U

/*! \enum udif_capstore_status
 * \brief Runtime status for a stored capability token.
 */
UDIF_EXPORT_API typedef enum udif_capstore_status
{
	udif_capstore_status_unknown = 0x00U,          /*!< No matching token or invalid status */
	udif_capstore_status_active = 0x01U,           /*!< Token is active and usable */
	udif_capstore_status_revoked = 0x02U,          /*!< Token has been revoked */
	udif_capstore_status_expired = 0x03U           /*!< Token is expired */
} udif_capstore_status;

/*! \struct udif_capstore_entry
 * \brief Single stored capability-token entry.
 */
UDIF_EXPORT_API typedef struct udif_capstore_entry
{
	udif_capability capability;                   /*!< Stored capability token */
	udif_capstore_status status;                  /*!< Runtime token status */
	bool used;                                    /*!< Entry is occupied */
} udif_capstore_entry;

/*! \struct udif_capstore
 * \brief Fixed-capacity capability-token table.
 */
UDIF_EXPORT_API typedef struct udif_capstore
{
	udif_capstore_entry entries[UDIF_CAPSTORE_CAPACITY];	/*!< Capability entries */
	size_t count;											/*!< Number of used entries */
} udif_capstore;

/**
 * \brief Initialize a capability-token store.
 *
 * This function clears the capability store and places it in an empty,
 * deterministic state. All entries are marked unused, all runtime status
 * fields are reset, and the active entry count is set to zero.
 *
 * \param store: [udif_capstore*] Pointer to the capability store to initialize.
 */
UDIF_EXPORT_API void udif_capstore_initialize(udif_capstore* store);

/**
 * \brief Clear a capability-token store.
 *
 * This function securely clears the stored capability entries and resets the
 * store to an empty state. It is used when an entity context is disposed, reset,
 * or reinitialized so that stale capability tokens are not retained.
 *
 * \param store: [udif_capstore*] Pointer to the capability store to clear.
 */
UDIF_EXPORT_API void udif_capstore_clear(udif_capstore* store);

/**
 * \brief Add a capability token to the store without external verification.
 *
 * This function inserts the supplied capability token into the store using its
 * canonical capability digest as the lookup key. The inserted entry is marked
 * active. If a token with the same digest is already present, the existing entry
 * may be replaced or rejected according to the implementation policy.
 *
 * This function does not validate the capability tag, issuer key, expiry time,
 * or policy constraints. Callers that accept externally supplied tokens should
 * use \ref udif_capstore_add_verified instead.
 *
 * \param store: [udif_capstore*] Pointer to the capability store.
 * \param capability: [const udif_capability*] Pointer to the capability token to add.
 *
 * \return Returns a \ref udif_errors value indicating success or failure.
 */
UDIF_EXPORT_API udif_errors udif_capstore_add(udif_capstore* store, const udif_capability* capability);

/**
 * \brief Verify and add a capability token to the store.
 *
 * This function verifies the supplied capability token before inserting it into
 * the store. Verification includes recomputing the capability digest, validating
 * the issuer-authenticated KMAC tag with the supplied issuer key, checking
 * expiry against the supplied time value, and rejecting malformed or unauthorized
 * capability encodings according to the capability-token rules.
 *
 * On successful verification, the capability is inserted into the store and
 * marked active. If verification fails, the store is not updated.
 *
 * \param store: [udif_capstore*] Pointer to the capability store.
 * \param capability: [const udif_capability*] Pointer to the capability token to verify and add.
 * \param issuerkey: [const uint8_t*] Pointer to the issuer capability-authentication key.
 * \param nowsecs: [uint64_t] Current UTC time in seconds, used for expiry validation.
 *
 * \return Returns a \ref udif_errors value indicating success or failure.
 */
UDIF_EXPORT_API udif_errors udif_capstore_add_verified(udif_capstore* store, const udif_capability* capability, const uint8_t* issuerkey, uint64_t nowsecs);

/**
 * \brief Find an active capability token by digest.
 *
 * This function searches the store for a capability token whose canonical
 * digest matches the supplied digest. Only active, usable entries are returned;
 * revoked, expired, unknown, or unused entries are not returned.
 *
 * \param store: [const udif_capstore*] Pointer to the capability store.
 * \param digest: [const uint8_t*] Pointer to the capability digest to search for.
 *
 * \return Returns a pointer to the matching active capability token, or NULL if no active match is found.
 */
UDIF_EXPORT_API const udif_capability* udif_capstore_find(const udif_capstore* store, const uint8_t* digest);

/**
 * \brief Find a capability token by digest regardless of runtime status.
 *
 * This function searches the store for a capability token whose canonical
 * digest matches the supplied digest and returns the matching token even if the
 * stored entry is revoked or expired. It is intended for administrative,
 * revocation, diagnostic, or audit paths that must locate a token independently
 * of its current usability.
 *
 * \param store: [const udif_capstore*] Pointer to the capability store.
 * \param digest: [const uint8_t*] Pointer to the capability digest to search for.
 *
 * \return Returns a pointer to the matching capability token, or NULL if no matching token is found.
 */
UDIF_EXPORT_API const udif_capability* udif_capstore_find_any(const udif_capstore* store, const uint8_t* digest);

/**
 * \brief Get the runtime status of a stored capability token.
 *
 * This function locates a capability token by digest and returns its effective
 * runtime status. If the token is active but its validity interval has expired
 * relative to \c nowsecs, the function reports the token as expired. If the
 * token is not present, the function returns \ref udif_capstore_status_unknown.
 *
 * \param store: [const udif_capstore*] Pointer to the capability store.
 * \param digest: [const uint8_t*] Pointer to the capability digest to query.
 * \param nowsecs: [uint64_t] Current UTC time in seconds, used for expiry evaluation.
 *
 * \return Returns the effective \ref udif_capstore_status for the matching token.
 */
UDIF_EXPORT_API udif_capstore_status udif_capstore_get_status(const udif_capstore* store, const uint8_t* digest, uint64_t nowsecs);

/**
 * \brief Set the runtime status of a stored capability token.
 *
 * This function locates a capability token by digest and updates its runtime
 * status. It is used to revoke, expire, reactivate, or otherwise administratively
 * change the local status of a stored capability token, subject to the
 * implementation's status-transition rules.
 *
 * \param store: [udif_capstore*] Pointer to the capability store.
 * \param digest: [const uint8_t*] Pointer to the capability digest identifying the token.
 * \param status: [udif_capstore_status] New runtime status to assign.
 *
 * \return Returns true if the matching entry was found and updated; otherwise returns false.
 */
UDIF_EXPORT_API bool udif_capstore_set_status(udif_capstore* store, const uint8_t* digest, udif_capstore_status status);

/**
 * \brief Remove a capability token from the store.
 *
 * This function locates a capability token by digest and removes the entry from
 * the store. The removed entry is cleared and marked unused so that it can no
 * longer authorize policy checks or administrative operations.
 *
 * \param store: [udif_capstore*] Pointer to the capability store.
 * \param digest: [const uint8_t*] Pointer to the capability digest identifying the token to remove.
 *
 * \return Returns true if a matching entry was found and removed; otherwise returns false.
 */
UDIF_EXPORT_API bool udif_capstore_remove(udif_capstore* store, const uint8_t* digest);

#endif
