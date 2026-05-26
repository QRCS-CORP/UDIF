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

#ifndef UDIF_CERTSTORE_H
#define UDIF_CERTSTORE_H

#include "certificate.h"

/**
 * \file certstore.h
 * \brief UDIF certificate status store.
 *
 * \details
 * This module implements the fixed-capacity certificate status table used by
 * UDIF authorities and user agents. The store is keyed by certificate serial
 * number and records the active, suspended, revoked, or expired state used by
 * handler-level authorization and chain validation.
 */

/*!
 * \def UDIF_CERTSTORE_CAPACITY
 * \brief Maximum number of certificate status records held by one context.
 */
#define UDIF_CERTSTORE_CAPACITY 256U

/*!
 * \enum udif_certstore_status
 * \brief Runtime status assigned to a certificate serial.
 */
UDIF_EXPORT_API typedef enum udif_certstore_status
{
	udif_certstore_status_unknown = 0x00U,    /*!< No status record exists for the serial. */
	udif_certstore_status_active = 0x01U,     /*!< Certificate is active and may be used. */
	udif_certstore_status_suspended = 0x02U,  /*!< Certificate is temporarily disabled. */
	udif_certstore_status_revoked = 0x03U,    /*!< Certificate is permanently revoked. */
	udif_certstore_status_expired = 0x04U     /*!< Certificate has passed its validity window. */
} udif_certstore_status;

/*!
 * \struct udif_certstore_entry
 * \brief Certificate status record.
 */
UDIF_EXPORT_API typedef struct udif_certstore_entry
{
	udif_certificate cert;              /*!< Stored certificate. */
	udif_certstore_status status;       /*!< Certificate status. */
	uint64_t statustime;                /*!< UTC time when the status was recorded. */
	bool occupied;                      /*!< True when this table slot is in use. */
} udif_certstore_entry;

/*!
 * \struct udif_certstore
 * \brief Fixed-capacity certificate status table.
 */
UDIF_EXPORT_API typedef struct udif_certstore
{
	udif_certstore_entry entries[UDIF_CERTSTORE_CAPACITY];	/*!< Certificate status entries. */
	size_t count;                                           /*!< Number of occupied entries. */
} udif_certstore;

/*!
 * \brief Initialize a certificate store.
 *
 * \param store: The certificate store to initialize.
 */
UDIF_EXPORT_API void udif_certstore_initialize(udif_certstore* store);

/*!
 * \brief Clear a certificate store.
 *
 * \param store: The certificate store to clear.
 */
UDIF_EXPORT_API void udif_certstore_clear(udif_certstore* store);

/*!
 * \brief Return the number of occupied entries.
 *
 * \param store: [const] The certificate store.
 *
 * \return Returns the number of stored certificates.
 */
UDIF_EXPORT_API size_t udif_certstore_count(const udif_certstore* store);

/*!
 * \brief Add or update a certificate status entry.
 *
 * \param store: The certificate store.
 * \param cert: [const] The certificate to store.
 * \param status: The certificate status.
 * \param nowsecs: The UTC status time.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_certstore_add(udif_certstore* store, const udif_certificate* cert, udif_certstore_status status, uint64_t nowsecs);

/*!
 * \brief Find a certificate by serial number.
 *
 * \param store: [const] The certificate store.
 * \param serial: [const] The certificate serial number.
 *
 * \return Returns a pointer to the certificate, or NULL if not found.
 */
UDIF_EXPORT_API const udif_certificate* udif_certstore_find(const udif_certstore* store, const uint8_t* serial);

/*!
 * \brief Return the stored status for a certificate serial.
 *
 * \param store: [const] The certificate store.
 * \param serial: [const] The certificate serial number.
 *
 * \return Returns the stored status, or unknown if not found.
 */
UDIF_EXPORT_API udif_certstore_status udif_certstore_get_status(const udif_certstore* store, const uint8_t* serial);

/*!
 * \brief Set the status of an existing certificate serial.
 *
 * \param store: The certificate store.
 * \param serial: [const] The certificate serial number.
 * \param status: The new certificate status.
 * \param nowsecs: The UTC status time.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_certstore_set_status(udif_certstore* store, const uint8_t* serial, udif_certstore_status status, uint64_t nowsecs);

/*!
 * \brief Validate that a certificate serial is active at a specified time.
 *
 * \param store: The certificate store.
 * \param serial: [const] The certificate serial number.
 * \param nowsecs: The UTC validation time.
 *
 * \return Returns udif_error_none if the certificate is active and valid.
 */
UDIF_EXPORT_API udif_errors udif_certstore_validate_status(udif_certstore* store, const uint8_t* serial, uint64_t nowsecs);

/*!
 * \brief Verify a certificate recursively against the stored root chain and status.
 *
 * This function validates the target certificate status and validity window, then
 * walks the issuer chain recursively to the stored Root certificate. Each issuer
 * must be active, within its validity window, have a valid parent signature, and
 * satisfy the UDIF role-transition rules. A revoked, suspended, expired, missing,
 * or malformed issuer causes the target certificate validation to fail.
 *
 * \param store: The certificate store containing the certificate chain.
 * \param serial: [const] The certificate serial number.
 * \param nowsecs: The UTC validation time.
 *
 * \return Returns udif_error_none if the complete chain is active, valid, and rooted.
 */
UDIF_EXPORT_API udif_errors udif_certstore_verify_certificate(udif_certstore* store, const uint8_t* serial, uint64_t nowsecs);

#endif
