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

#ifndef UDIF_COMMANDS_H
#define UDIF_COMMANDS_H

#include "udif.h"

/*!
 * \file commands.h
 * \brief UDIF console command enumerations.
 *
 * Defines the console mode hierarchy, the per-mode command action set,
 * and all user-visible application message codes. These enumerations are
 * shared across all four UDIF entity types (Root, BC, GC, UA). Each server
 * type registers only the subset of actions relevant to its role; the shared
 * infrastructure (menu, help, logger) uses only the enum values.
 */

/*!
 * \enum udif_console_modes
 * \brief UDIF console mode hierarchy.
 *
 * Modes form a tree:
 *   user → enable → config → certificate
 *                           → server
 * Login gates the user → enable transition. Mode strings are indexed
 * from the UDIF_APPLICATION_MODE_STRINGS table in resources.h.
 */
typedef enum udif_console_modes
{
    udif_console_mode_user = 0x00U,                     /*!< User mode: enable, help, quit */
    udif_console_mode_enable = 0x01U,                   /*!< Enable mode: config, show, clear screen, quit */
    udif_console_mode_config = 0x02U,                   /*!< Config mode: network settings, sub-modes */
    udif_console_mode_certificate = 0x03U,              /*!< Certificate sub-mode */
    udif_console_mode_server = 0x04U,                   /*!< Server sub-mode */
} udif_console_modes;

/*!
 * \enum udif_command_actions
 * \brief All recognized command actions across all UDIF entity types.
 *
 * Each server type's set_command_action() function maps a parsed command
 * string to one of these values, which is then dispatched by
 * command_execute(). Unrecognized commands map to
 * udif_command_action_unrecognized, causing the help for the current
 * mode to be printed.
 *
 * The enum value is also used as an index into
 * UDIF_APPLICATION_HELP_STRINGS in resources.h.
 */
typedef enum udif_command_actions
{
    udif_command_action_none = 0x00U,                   /*!< No action (empty input) */
    udif_command_action_unrecognized = 0x01U,           /*!< Unrecognized command */

    /* certificate mode */
    udif_command_action_certificate_exit = 0x02U,       /*!< exit  (certificate → config) */
    udif_command_action_certificate_export = 0x03U,     /*!< export <directory> */
    udif_command_action_certificate_generate = 0x04U,   /*!< generate <days> */
    udif_command_action_certificate_help = 0x05U,       /*!< help */
    udif_command_action_certificate_print = 0x06U,      /*!< print */
    udif_command_action_certificate_sign = 0x07U,       /*!< sign <filepath>  (Root only) */

    /* config mode */
    udif_command_action_config_address = 0x08U,         /*!< address <ip> */
    udif_command_action_config_certificate = 0x09U,     /*!< certificate  (enter sub-mode) */
    udif_command_action_config_clear_all = 0x0AU,       /*!< clear all */
    udif_command_action_config_clear_config = 0x0BU,    /*!< clear config */
    udif_command_action_config_clear_log = 0x0CU,       /*!< clear log */
    udif_command_action_config_exit = 0x0DU,            /*!< exit  (config → enable) */
    udif_command_action_config_help = 0x0EU,            /*!< help */
    udif_command_action_config_log = 0x0FU,             /*!< log enable|disable */
    udif_command_action_config_name_domain = 0x10U,     /*!< name domain <name> */
    udif_command_action_config_name_host = 0x11U,       /*!< name host <name> */
    udif_command_action_config_port = 0x12U,            /*!< port <number> */
    udif_command_action_config_retries = 0x13U,         /*!< retries <count> */
    udif_command_action_config_server = 0x14U,          /*!< server  (enter sub-mode) */
    udif_command_action_config_timeout = 0x15U,         /*!< timeout <minutes> */

    /* server mode */
    udif_command_action_server_anchor = 0x16U,          /*!< anchor  (force anchor push now) */
    udif_command_action_server_backup = 0x17U,          /*!< backup */
    udif_command_action_server_exit = 0x18U,            /*!< exit  (server → config) */
    udif_command_action_server_help = 0x19U,            /*!< help */
    udif_command_action_server_restore = 0x1AU,         /*!< restore */
    udif_command_action_server_service = 0x1BU,         /*!< service start|stop|pause|resume */
    udif_command_action_server_status = 0x1CU,          /*!< status */

    /* enable mode */
    udif_command_action_enable_clear_screen = 0x1DU,    /*!< clear screen */
    udif_command_action_enable_config = 0x1EU,          /*!< config  (enter sub-mode) */
    udif_command_action_enable_exit = 0x1FU,            /*!< exit  (enable → user) */
    udif_command_action_enable_help = 0x20U,            /*!< help */
    udif_command_action_enable_quit = 0x21U,            /*!< quit */
    udif_command_action_enable_show_config = 0x22U,     /*!< show config */
    udif_command_action_enable_show_log = 0x23U,        /*!< show log */

    /* user mode */
    udif_command_action_user_enable = 0x24U,            /*!< enable  (triggers auth) */
    udif_command_action_user_help = 0x25U,              /*!< help */
    udif_command_action_user_quit = 0x26U,              /*!< quit */
} udif_command_actions;

/*!
 * \enum udif_application_messages
 * \brief Predefined application message codes.
 *
 * Each code indexes a human-readable string in
 * UDIF_APPLICATION_MESSAGE_STRINGS (resources.h). Used by
 * udif_menu_print_predefined_message() and udif_server_log_write().
 */
typedef enum udif_application_messages
{
    /* generic */
    udif_application_not_recognized = 0x00U,            /*!< Command not recognized */
    udif_application_erase_all = 0x01U,                 /*!< Erase all — confirm Y|N */
    udif_application_erase_config = 0x02U,              /*!< Erase config — confirm Y|N */
    udif_application_erase_log = 0x03U,                 /*!< Erase log — confirm Y|N */
    udif_application_authorization_failure = 0x04U,     /*!< Not authorized; press key */
    udif_application_retries_exceeded = 0x05U,          /*!< Max retries exceeded; press key */
    udif_application_quit = 0x06U,                      /*!< Quit entered; press key */
    udif_application_logging_disabled = 0x07U,          /*!< Logging disabled */
    udif_application_logging_enabled = 0x08U,           /*!< Logging enabled */
    udif_application_operation_aborted = 0x09U,         /*!< Operation aborted by user */
    udif_application_system_erased = 0x0AU,             /*!< System erased */
    udif_application_configuration_erased = 0x0BU,      /*!< Configuration erased */
    udif_application_log_erased = 0x0CU,                /*!< Log erased */
    udif_application_retry_invalid = 0x0DU,             /*!< Retry count invalid (1-5) */
    udif_application_timeout_invalid = 0x0EU,           /*!< Timeout invalid (1-60) */
    udif_application_domain_invalid = 0x0FU,            /*!< Domain name invalid */
    udif_application_hostname_invalid = 0x10U,          /*!< Host name invalid */
    udif_application_port_invalid = 0x11U,              /*!< Port number invalid */
    udif_application_address_change_success = 0x12U,    /*!< IP address changed */
    udif_application_address_change_failure = 0x13U,    /*!< IP address change failed */
    udif_application_log_empty = 0x14U,                 /*!< Log file is empty */

    /* first-run login */
    udif_application_first_login = 0x15U,               /*!< First run: set name/password */
    udif_application_choose_name = 0x16U,               /*!< Choose a user name */
    udif_application_choose_password = 0x17U,           /*!< Choose a password */
    udif_application_password_set = 0x18U,              /*!< User name and password set */
    udif_application_challenge_user = 0x19U,            /*!< Enter user name: */
    udif_application_challenge_user_failure = 0x1AU,    /*!< User name not recognized */
    udif_application_challenge_password = 0x1BU,        /*!< Enter password: */
    udif_application_challenge_password_failure = 0x1CU, /*!< Password invalid */
    udif_application_challenge_hostname = 0x1DU,        /*!< Enter host name: */
    udif_application_challenge_hostname_success = 0x1EU, /*!< Host name set */
    udif_application_challenge_hostname_failure = 0x1FU, /*!< Host name invalid */
    udif_application_challenge_address = 0x20U,         /*!< Enter IP address: */
    udif_application_console_timeout_expired = 0x21U,   /*!< Console timeout; logged out */

    /* certificate operations */
    udif_application_cert_generate_key_overwrite = 0x22U, /*!< Key exists; overwrite? Y|N */
    udif_application_cert_generate_success = 0x23U,     /*!< Certificate generated */
    udif_application_cert_generate_failure = 0x24U,     /*!< Certificate generation failed */
    udif_application_cert_export_success = 0x25U,       /*!< Certificate exported */
    udif_application_cert_export_failure = 0x26U,       /*!< Certificate export failed */
    udif_application_cert_sign_success = 0x27U,         /*!< Certificate signed */
    udif_application_cert_sign_failure = 0x28U,         /*!< Certificate signing failed */
    udif_application_cert_not_found = 0x29U,            /*!< Certificate file not found */
    udif_application_cert_invalid = 0x2AU,              /*!< Certificate is invalid */
    udif_application_cert_path_invalid = 0x2BU,         /*!< Certificate path invalid */

    /* server service */
    udif_application_service_start_success = 0x2CU,     /*!< Service started */
    udif_application_service_start_failure = 0x2DU,     /*!< Service start failed */
    udif_application_service_stopped = 0x2EU,           /*!< Service stopped */
    udif_application_service_paused = 0x2FU,            /*!< Service paused */
    udif_application_service_resume_success = 0x30U,    /*!< Service resumed */
    udif_application_service_resume_failure = 0x31U,    /*!< Service resume failed (not paused) */
    udif_application_backup_save_success = 0x32U,       /*!< State backup saved */
    udif_application_backup_restore_challenge = 0x33U,  /*!< Restore from backup? Y|N */

    /* anchor */
    udif_application_anchor_push_success = 0x34U,       /*!< Anchor pushed to parent */
    udif_application_anchor_push_failure = 0x35U,       /*!< Anchor push failed */
    udif_application_anchor_not_ready = 0x36U,          /*!< Service must be running first */

    /* log messages (written to file, not console) */
    udif_application_log_service_started = 0x37U,
    udif_application_log_service_stopped = 0x38U,
    udif_application_log_service_paused = 0x39U,
    udif_application_log_service_resumed = 0x3AU,
    udif_application_log_generate_success = 0x3BU,
    udif_application_log_generate_failure = 0x3CU,
    udif_application_log_sign_success = 0x3DU,
    udif_application_log_sign_failure = 0x3EU,
    udif_application_log_config_erased = 0x3FU,
    udif_application_log_backup_save = 0x40U,
    udif_application_log_backup_restore = 0x41U,
    udif_application_log_connection_accept = 0x42U,
    udif_application_log_connection_close = 0x43U,
    udif_application_log_enroll_success = 0x44U,
    udif_application_log_enroll_failure = 0x45U,
    udif_application_log_revoke_issued = 0x46U,
    udif_application_log_anchor_push_success = 0x47U,
    udif_application_log_anchor_push_failure = 0x48U,
    udif_application_log_anchor_recv_success = 0x49U,
    udif_application_log_allocation_failure = 0x4AU,
    udif_application_log_receive_failure = 0x4BU,
    udif_application_log_invalid_request = 0x4CU,
    udif_application_log_dispatch_failure = 0x4DU,
} udif_application_messages;

#endif
