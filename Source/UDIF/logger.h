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

#ifndef UDIF_LOGGER_H
#define UDIF_LOGGER_H

#include "udif.h"
#include "commands.h"

/*!
 * \file logger.h
 * \brief UDIF activity log functions.
 *
 * Plain-text append-only log file. All writes acquire a mutex so the
 * log is safe to call from background receive threads concurrently with
 * the console thread. The log path is supplied by the caller on every
 * call; there is no global state in this module.
 *
 * Decorated writes prepend the predefined message string from
 * UDIF_APPLICATION_MESSAGE_STRINGS, followed by the optional caller
 * message, and then the newline. Time-stamped variants additionally
 * prepend the current date-time.
 */

/*!
 * \brief Create or verify the log file.
 *
 * If the file does not exist it is created (empty). If it already
 * exists the call is a no-op.
 *
 * \param path: [const] Full path to the log file.
 */
UDIF_EXPORT_API void udif_logger_initialize(const char* path);

/*!
 * \brief Erase and recreate the log file, discarding all content.
 *
 * \param path: [const] Full path to the log file.
 */
UDIF_EXPORT_API void udif_logger_reset(const char* path);

/*!
 * \brief Delete the log file from disk.
 *
 * \param path: [const] Full path to the log file.
 *
 * \return Returns true if the file existed and was deleted.
 */
UDIF_EXPORT_API bool udif_logger_dispose(const char* path);

/*!
 * \brief Test whether the log file exists.
 *
 * \param path: [const] Full path to the log file.
 *
 * \return Returns true if the file exists.
 */
UDIF_EXPORT_API bool udif_logger_exists(const char* path);

/*!
 * \brief Append a raw message string to the log.
 *
 * Acquires the write mutex, appends message followed by a newline, and
 * releases the mutex.
 *
 * \param path:    [const] Full path to the log file.
 * \param message: [const] The message string to append.
 * \param msglen:  Length of message in bytes.
 *
 * \return Returns the number of bytes written (including the newline), or 0 on failure.
 */
UDIF_EXPORT_API size_t udif_logger_write_message(const char* path, const char* message, size_t msglen);

/*!
 * \brief Append a predefined message header followed by an optional caller message.
 *
 * Looks up msgtype in UDIF_APPLICATION_MESSAGE_STRINGS, concatenates
 * the optional message, and appends to the log.
 *
 * \param path:    [const] Full path to the log file.
 * \param msgtype: Predefined message enumerator.
 * \param message: [const] Optional supplementary text (may be NULL).
 * \param msglen:  Length of the supplementary text; ignored if NULL.
 *
 * \return Returns the number of bytes written, or 0 on failure.
 */
UDIF_EXPORT_API size_t udif_logger_write_decorated_message(const char* path, udif_application_messages msgtype, const char* message, size_t msglen);

/*!
 * \brief Append a timestamp, predefined message, and optional caller
 *        message to the log.
 *
 * Format: "[YYYY-MM-DD HH:MM:SS] <predefined message><message>\n"
 *
 * \param path:    [const] Full path to the log file.
 * \param msgtype: Predefined message enumerator.
 * \param message: [const] Optional supplementary text (may be NULL).
 * \param msglen:  Length of the supplementary text; ignored if NULL.
 *
 * \return Returns the number of bytes written, or 0 on failure.
 */
UDIF_EXPORT_API size_t udif_logger_write_decorated_time_stamped_message(const char* path, udif_application_messages msgtype, const char* message, size_t msglen);

/*!
 * \brief Append a timestamp and raw message to the log.
 *
 * \param path:    [const] Full path to the log file.
 * \param message: [const] The message string to append.
 * \param msglen:  Length of message in bytes.
 *
 * \return Returns the number of bytes written, or 0 on failure.
 */
UDIF_EXPORT_API size_t udif_logger_write_time_stamped_message(const char* path, const char* message, size_t msglen);

/*!
 * \brief Read the entire log file into a caller-supplied buffer.
 *
 * Acquires the read mutex before reading. The output is not
 * null-terminated by this function.
 *
 * \param path:   [const] Full path to the log file.
 * \param output: Destination buffer.
 * \param outlen: Size of the destination buffer in bytes.
 *
 * \return Returns the number of bytes copied, or 0 on failure.
 */
UDIF_EXPORT_API size_t udif_logger_read_all(const char* path, char* output, size_t outlen);

/*!
 * \brief Write the current date-time string into a caller buffer.
 *
 * Format: "YYYY-MM-DD HH:MM:SS " (trailing space, no null beyond that
 * unless the buffer is large enough).
 *
 * \param output: Destination buffer.
 * \param outlen: Size of the buffer in bytes.
 *
 * \return Returns the number of bytes written.
 */
UDIF_EXPORT_API size_t udif_logger_time_stamp(char* output, size_t outlen);

#endif
