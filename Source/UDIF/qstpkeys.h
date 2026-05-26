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

#ifndef UDIF_QSTPKEYS_H
#define UDIF_QSTPKEYS_H

/**
 * \file qstpkeys.h
 * \brief Forward declarations for QSTP functions used by UDIF role modules.
 *
 * qstp_root_key_generate, qstp_server_key_generate, qstp_server_start_ipv4,
 * and qstp_client_connect_ipv4 are defined in the QSTP project
 * (root.h / server.h / client.h).  When those headers are on the compiler's
 * include path the guard macros QSTP_ROOT_H / QSTP_SERVER_H / QSTP_CLIENT_H
 * suppress these declarations.  When they are not available these externs
 * satisfy the compiler; the linker resolves the symbols from the QSTP lib.
 */

#include "qstp.h"

#if !defined(QSTP_ROOT_H)
/** generate a new QSTP root signing keypair. */
QSTP_EXPORT_API void qstp_root_key_generate(qstp_root_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp);
#endif

#if !defined(QSTP_SERVER_H)
/** Generate a new QSTP server signing keypair. */
QSTP_EXPORT_API void qstp_server_key_generate(qstp_server_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp);

/**
 * \brief Start the IPv4 QSTP multi-threaded server.
 *
 * The function initializes, binds, and listens on the socket internally.
 * Blocks until the server is stopped.
 *
 * \param source: Pre-zeroed qsc_socket (filled by this function)
 * \param kset: Server signature key
 * \param receive_callback: Called when a message arrives
 * \param disconnect_callback: Called when a client disconnects
 * 
 * \return qstp_errors result code
 */
QSTP_EXPORT_API qstp_errors qstp_server_start_ipv4(qsc_socket* source, const qstp_server_signature_key* kset,
    void (*receive_callback)(qstp_connection_state*, const char*, size_t), void (*disconnect_callback)(qstp_connection_state*));
#endif

#if !defined(QSTP_CLIENT_H)
/**
 * \brief Connect to a QSTP server over IPv4.
 *
 * \param root: Root certificate (trust anchor)
 * \param cert: Client's server certificate
 * \param address: Server IPv4 address
 * \param port: Server port
 * \param send_func: Send-loop callback (drives keepalive / ratchet)
 * \param receive_callback: Called when a message arrives
 * 
 * \return qstp_errors result code
 */
QSTP_EXPORT_API qstp_errors qstp_client_connect_ipv4(const qstp_root_certificate* root, const qstp_server_certificate* cert, const qsc_ipinfo_ipv4_address* address,
    uint16_t port, void (*send_func)(qstp_connection_state*), void (*receive_callback)(qstp_connection_state*, const char*, size_t));
#endif

#endif
