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

#ifndef UDIF_TREATYSTORE_H
#define UDIF_TREATYSTORE_H

#include "treaty.h"
#include "query.h"

/**
 * \file treatystore.h
 * \brief Runtime treaty store.
 *
 * The treaty store is a fixed-capacity table keyed by treaty identifier. It
 * records active and revoked bilateral treaties and provides peer/query lookup
 * helpers for cross-domain forwarding enforcement.
 */

/*! \def UDIF_TREATYSTORE_CAPACITY
 * \brief Maximum number of treaty records retained in one entity context.
 */
#define UDIF_TREATYSTORE_CAPACITY 64U

/*! \def UDIF_TREATYSTORE_PENDING_CAPACITY
 * \brief Maximum number of pending treaty-query responses tracked.
 */
#define UDIF_TREATYSTORE_PENDING_CAPACITY 64U

/*! \enum udif_treatystore_status
 * \brief Runtime treaty status.
 */
UDIF_EXPORT_API typedef enum udif_treatystore_status
{
	udif_treatystore_status_unknown = 0x00U,    /*!< No treaty status is known. */
	udif_treatystore_status_active = 0x01U,     /*!< Treaty is active and may authorize forwarding. */
	udif_treatystore_status_revoked = 0x02U,    /*!< Treaty has been revoked. */
	udif_treatystore_status_expired = 0x03U     /*!< Treaty has expired. */
} udif_treatystore_status;

/*! \struct udif_treatystore_entry
 * \brief Stored treaty record.
 */
UDIF_EXPORT_API typedef struct udif_treatystore_entry
{
	udif_treaty treaty;                         /*!< Stored treaty. */
	udif_treatystore_status status;             /*!< Runtime treaty status. */
	uint64_t statustime;                        /*!< UTC status time. */
	bool occupied;                              /*!< Entry is allocated. */
} udif_treatystore_entry;


/*! \struct udif_treatystore_pending_query
 * \brief Pending treaty query awaiting a signed response.
 */
UDIF_EXPORT_API typedef struct udif_treatystore_pending_query
{
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];      /*!< Treaty identifier authorizing the query. */
	uint8_t peerser[UDIF_SERIAL_NUMBER_SIZE];       /*!< Expected responding treaty peer. */
	uint8_t queryid[UDIF_QUERY_ID_SIZE];            /*!< Query identifier. */
	uint8_t querydigest[UDIF_CRYPTO_HASH_SIZE];     /*!< Canonical query digest. */
	uint64_t expires;                               /*!< Expiration time for the pending response. */
	uint8_t querytype;                              /*!< Query type expected in the response. */
	bool occupied;                                  /*!< Entry is allocated. */
} udif_treatystore_pending_query;

/*! \struct udif_treatystore
 * \brief Fixed-capacity treaty table.
 */
UDIF_EXPORT_API typedef struct udif_treatystore
{
	udif_treatystore_entry entries[UDIF_TREATYSTORE_CAPACITY]; /*!< Treaty records. */
	udif_treatystore_pending_query pending[UDIF_TREATYSTORE_PENDING_CAPACITY]; /*!< Pending treaty responses. */
	size_t count;                                               /*!< Number of occupied entries. */
	size_t pendingcount;                                        /*!< Number of pending response entries. */
} udif_treatystore;

/*! \brief Initialize a treaty store.
 *
 * \param store: The treaty store.
 */
UDIF_EXPORT_API void udif_treatystore_initialize(udif_treatystore* store);

/*! \brief Clear a treaty store.
 *
 * \param store: The treaty store.
 */
UDIF_EXPORT_API void udif_treatystore_clear(udif_treatystore* store);

/*! \brief Add or update a treaty.
 *
 * \param store: The treaty store.
 * \param treaty: [const] The treaty to store.
 * \param status: The treaty status.
 * \param nowsecs: The UTC status time.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_treatystore_add(udif_treatystore* store, const udif_treaty* treaty, udif_treatystore_status status, uint64_t nowsecs);

/*! \brief Find a treaty by identifier.
 *
 * \param store: [const] The treaty store.
 * \param treatyid: [const] The treaty identifier.
 *
 * \return Returns the stored treaty, or NULL.
 */
UDIF_EXPORT_API const udif_treaty* udif_treatystore_find(const udif_treatystore* store, const uint8_t* treatyid);

/*! \brief Return a treaty status by identifier.
 *
 * \param store: [const] The treaty store.
 * \param treatyid: [const] The treaty identifier.
 *
 * \return Returns the stored status, or unknown.
 */
UDIF_EXPORT_API udif_treatystore_status udif_treatystore_get_status(const udif_treatystore* store, const uint8_t* treatyid);

/*! \brief Set the status of an existing treaty.
 *
 * \param store: The treaty store.
 * \param treatyid: [const] The treaty identifier.
 * \param status: The new status.
 * \param nowsecs: The UTC status time.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_treatystore_set_status(udif_treatystore* store, const uint8_t* treatyid, udif_treatystore_status status, uint64_t nowsecs);

/*! \brief Find an active treaty linking the local and peer serials.
 *
 * \param store: The treaty store.
 * \param localser: [const] The local domain-controller serial.
 * \param peerser: [const] The peer domain-controller serial.
 * \param querytype: The requested query predicate family.
 * \param nowsecs: The UTC validation time.
 *
 * \return Returns the active treaty, or NULL.
 */
UDIF_EXPORT_API const udif_treaty* udif_treatystore_find_active_for_query(udif_treatystore* store, const uint8_t* localser, 
	const uint8_t* peerser, uint8_t querytype, uint64_t nowsecs);

/*! \brief Add a pending treaty query response expectation.
 *
 * \param store: The treaty store.
 * \param treatyid: [const] The treaty identifier.
 * \param peerser: [const] The expected responding peer serial.
 * \param query: [const] The outbound treaty query.
 * \param expires: The expiration time for the pending response.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_treatystore_add_pending_query(udif_treatystore* store, const uint8_t* treatyid, const uint8_t* peerser, 
	const udif_query* query, uint64_t expires);

/*! \brief Consume a pending treaty response expectation.
 *
 * A matching pending query is removed only when the response query id,
 * embedded query digest, expected peer, and expected query type match.
 *
 * \param store: The treaty store.
 * \param localser: [const] The local controller serial.
 * \param peerser: [const] The responding peer serial.
 * \param response: [const] The treaty query response.
 * \param nowsecs: The current UTC time.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_treatystore_consume_pending_response(udif_treatystore* store, const uint8_t* localser, const uint8_t* peerser,
	const udif_query_response* response, uint64_t nowsecs);

#endif
