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

#ifndef UDIF_POLICY_H
#define UDIF_POLICY_H

#include "udif.h"
#include "capability.h"
#include "certificate.h"
#include "query.h"

/**
 * \file policy.h
 * \brief Central UDIF capability and certificate authorization checks.
 */

/*!
 * \brief Map a query type to the required capability verb.
 *
 * \param querytype: The query type
 * \param verb: The output capability verb
 *
 * \return Returns true when the query type is recognized
 */
UDIF_EXPORT_API bool udif_policy_query_verb(uint8_t querytype, uint32_t* verb);

/*!
 * \brief Check whether a certificate embeds a required capability verb.
 *
 * \param certificate: [const] The caller certificate
 * \param verb: The required capability verb
 *
 * \return Returns true when the embedded certificate mask permits the verb
 */
UDIF_EXPORT_API bool udif_policy_certificate_allows(const udif_certificate* certificate, uint32_t verb);

/*!
 * \brief Authorize an operation against certificate and token permissions.
 *
 * The decision is fail-closed. The caller certificate must be valid at the
 * supplied time, its embedded capability mask must contain the required verb,
 * and a capability token must be present, issued to the caller, unexpired, and
 * grant both the required verb and scope.
 *
 * \param caller: [const] The caller certificate
 * \param capability: [const] The resolved capability token
 * \param verb: The required capability verb
 * \param scope: The required capability scope
 * \param ctime: The current UTC time
 *
 * \return Returns udif_policy_permit only when all checks pass
 */
UDIF_EXPORT_API udif_policy_decision udif_policy_authorize(const udif_certificate* caller, const udif_capability* capability,
	uint32_t verb, uint32_t scope, uint64_t ctime);

/*!
 * \brief Authorize a query using its capability reference.
 *
 * \param query: [const] The query
 * \param caller: [const] The caller certificate
 * \param capability: [const] The resolved capability token
 * \param scope: The required scope
 * \param ctime: The current UTC time
 *
 * \return Returns udif_policy_permit only when authorized
 */
UDIF_EXPORT_API udif_policy_decision udif_policy_authorize_query(const udif_query* query, const udif_certificate* caller,
	const udif_capability* capability, uint32_t scope, uint64_t ctime);

#endif
