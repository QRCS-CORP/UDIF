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

#ifndef UDIF_MENU_H
#define UDIF_MENU_H

#include "udif.h"
#include "commands.h"

/*!
 * \file menu.h
 * \brief UDIF console menu and prompt functions.
 *
 * All output functions print the mode prompt prefix (hostname + mode
 * suffix from UDIF_APPLICATION_MODE_STRINGS) before any message text.
 * This keeps the console output consistent with the IOS-style CLI
 * pattern used by MPDC.
 *
 * Confirm variants wait for a single-line Y|N response and return true
 * only for 'Y' or 'y'.
 */

/*!
 * \brief Return the mode prompt suffix for the given console mode.
 *
 * Returns a pointer into UDIF_APPLICATION_MODE_STRINGS; the caller
 * must not free or modify the returned pointer.
 *
 * \param mode: The current console mode.
 *
 * \return Returns a pointer to the null-terminated mode prompt suffix.
 */
UDIF_EXPORT_API const char* udif_menu_get_prompt(udif_console_modes mode);

/*!
 * \brief Print the mode prompt (hostname + mode suffix) with no newline.
 *
 * Format: "<hostname><mode-suffix>"  e.g. "myhost(config)# "
 *
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 */
UDIF_EXPORT_API void udif_menu_print_prompt(udif_console_modes mode, const char* host);

/*!
 * \brief Print a predefined message string on a new prompt line.
 *
 * Prints the mode prompt then the string from
 * UDIF_APPLICATION_MESSAGE_STRINGS indexed by msgnum, followed by a
 * newline.
 *
 * \param msgnum: The predefined message enumerator.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 */
UDIF_EXPORT_API void udif_menu_print_predefined_message(udif_application_messages msgnum, udif_console_modes mode, const char* host);

/*!
 * \brief Print a predefined message and wait for Y|N confirmation.
 *
 * Prints the predefined message on a prompt line, then prints another
 * prompt and reads one line. Returns true only if the first character
 * of the response is 'Y' or 'y'.
 *
 * \param msgnum: The predefined message enumerator.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 *
 * \return Returns true if the user confirmed with Y.
 */
UDIF_EXPORT_API bool udif_menu_print_predefined_message_confirm(udif_application_messages msgnum, udif_console_modes mode, const char* host);

/*!
 * \brief Print a predefined message string without a trailing newline.
 *
 * Used when the caller intends to append further output on the same
 * console line.
 *
 * \param msgnum: The predefined message enumerator.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 */
UDIF_EXPORT_API void udif_menu_print_predefined_text(udif_application_messages msgnum, udif_console_modes mode, const char* host);

/*!
 * \brief Print an arbitrary message string on a new prompt line.
 *
 * \param message: [const] The message to print.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 */
UDIF_EXPORT_API void udif_menu_print_message(const char* message, udif_console_modes mode, const char* host);

/*!
 * \brief Print an arbitrary message and wait for Y|N confirmation.
 *
 * \param message: [const] The message to print.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 *
 * \return Returns true if the user confirmed with Y.
 */
UDIF_EXPORT_API bool udif_menu_print_message_confirm(const char* message, udif_console_modes mode, const char* host);

/*!
 * \brief Print an arbitrary message string without a trailing newline.
 *
 * \param message: [const] The message to print.
 * \param mode: The current console mode.
 * \param host: [const] The server hostname.
 */
UDIF_EXPORT_API void udif_menu_print_prompt_text(const char* message, udif_console_modes mode, const char* host);

/*!
 * \brief Print a raw string with no prompt prefix and no newline.
 *
 * \param message: [const] The string to print.
 */
UDIF_EXPORT_API void udif_menu_print_text(const char* message);

/*!
 * \brief Print a raw string with no prompt prefix, followed by a newline.
 *
 * \param message: [const] The string to print.
 */
UDIF_EXPORT_API void udif_menu_print_text_line(const char* message);

/*!
 * \brief Print a bare fallback prompt with no hostname.
 *
 * Used during initialization before the hostname is configured.
 */
UDIF_EXPORT_API void udif_menu_print_prompt_empty(void);

#endif
