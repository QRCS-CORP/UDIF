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

#ifndef UDIF_RESOURCES_H
#define UDIF_RESOURCES_H

/*!
 * \file resources.h
 * \brief UDIF static string resource tables.
 *
 * Three static tables, each indexed by an enum value from commands.h:
 *
 *   UDIF_APPLICATION_MESSAGE_STRINGS  — indexed by udif_application_messages
 *   UDIF_APPLICATION_MODE_STRINGS     — indexed by udif_console_modes
 *   UDIF_APPLICATION_HELP_STRINGS     — indexed by udif_command_actions
 *
 * All tables are declared static so each translation unit gets its own
 * copy. Include this header only in .c files that actually need the
 * tables (menu.c, help.c, logger.c, server.c).
 */

#define UDIF_APPLICATION_MESSAGE_STRING_DEPTH 78U
#define UDIF_APPLICATION_MESSAGE_STRING_SIZE 128U

#define UDIF_APPLICATION_MODE_STRING_DEPTH 5U
#define UDIF_APPLICATION_MODE_STRING_SIZE 28U

#define UDIF_APPLICATION_HELP_STRING_DEPTH 39U
#define UDIF_APPLICATION_HELP_STRING_SIZE 128U

/* path and log constants */
#define UDIF_LOGGER_PATH "UDIF"
#define UDIF_LOGGER_FILE "udif-activity.log"

static const char UDIF_APPLICATION_MESSAGE_STRINGS [UDIF_APPLICATION_MESSAGE_STRING_DEPTH][UDIF_APPLICATION_MESSAGE_STRING_SIZE] =
{
    /* 0x00 */ "The command was not recognized.",
    /* 0x01 */ "The system will be erased including all keys, certificates, ledgers and logs. Proceed? Y|N",
    /* 0x02 */ "The configuration will be erased. Proceed? Y|N",
    /* 0x03 */ "The log file will be erased. Proceed? Y|N",
    /* 0x04 */ "Authorization failure. Press any key to terminate.",
    /* 0x05 */ "Login has exceeded the maximum number of retries. Press any key to terminate.",
    /* 0x06 */ "The quit command has been entered. Press any key to close.",
    /* 0x07 */ "Activity logging has been disabled.",
    /* 0x08 */ "Activity logging has been enabled.",
    /* 0x09 */ "The operation was aborted by the user.",
    /* 0x0A */ "System reset: all keys, certificates, ledgers and logs have been erased.",
    /* 0x0B */ "Configuration erased.",
    /* 0x0C */ "Log file erased.",
    /* 0x0D */ "The retry count is invalid; valid range is 1 to 5.",
    /* 0x0E */ "The timeout value is invalid; valid range is 1 to 60 minutes.",
    /* 0x0F */ "The domain name is invalid; valid length is 2 to 260 characters.",
    /* 0x10 */ "The host name is invalid; valid length is 2 to 128 characters.",
    /* 0x11 */ "The port number is invalid; valid range is 1024 to 65535.",
    /* 0x12 */ "IP address updated. Restart the service for the change to take effect.",
    /* 0x13 */ "IP address change failed; the address is invalid.",
    /* 0x14 */ "The log file is empty.",
    /* 0x15 */ "First run: please set the host name, user name, and password.",
    /* 0x16 */ "Please choose a user name (6 to 128 characters).",
    /* 0x17 */ "Please choose a password (8 to 256 characters; letters, digits, symbols).",
    /* 0x18 */ "User name and password have been set.",
    /* 0x19 */ "Please enter the user name:",
    /* 0x1A */ "The user name entered was not recognized.",
    /* 0x1B */ "Please enter the password:",
    /* 0x1C */ "The password entered is incorrect.",
    /* 0x1D */ "Please enter the host name (2 to 128 characters):",
    /* 0x1E */ "Host name set.",
    /* 0x1F */ "The host name entered is invalid.",
    /* 0x20 */ "Please enter the local IPv4 address:",
    /* 0x21 */ "Console idle timeout expired. Logged out.",
    /* 0x22 */ "A certificate already exists. Overwrite? Y|N",
    /* 0x23 */ "Certificate generated successfully.",
    /* 0x24 */ "Certificate generation failed.",
    /* 0x25 */ "Certificate exported successfully.",
    /* 0x26 */ "Certificate export failed.",
    /* 0x27 */ "Certificate signed successfully.",
    /* 0x28 */ "Certificate signing failed; check that the file path is valid and the certificate is unsigned.",
    /* 0x29 */ "Certificate file not found.",
    /* 0x2A */ "The certificate is invalid or has expired.",
    /* 0x2B */ "The certificate path is invalid.",
    /* 0x2C */ "Service started.",
    /* 0x2D */ "Service start failed; check the IP address and port configuration.",
    /* 0x2E */ "Service stopped.",
    /* 0x2F */ "Service paused.",
    /* 0x30 */ "Service resumed.",
    /* 0x31 */ "Service resume failed; the service is not paused.",
    /* 0x32 */ "State backup saved.",
    /* 0x33 */ "Restore state from backup? This will overwrite current state. Y|N",
    /* 0x34 */ "Anchor record pushed to parent.",
    /* 0x35 */ "Anchor push failed; check that the upstream tunnel is active.",
    /* 0x36 */ "The network service must be running before an anchor can be pushed.",
    /* 0x37 */ "Service started.",
    /* 0x38 */ "Service stopped.",
    /* 0x39 */ "Service paused.",
    /* 0x3A */ "Service resumed.",
    /* 0x3B */ "Certificate generated.",
    /* 0x3C */ "Certificate generation failed.",
    /* 0x3D */ "Certificate signed.",
    /* 0x3E */ "Certificate signing failed.",
    /* 0x3F */ "Configuration erased.",
    /* 0x40 */ "State backup saved.",
    /* 0x41 */ "State restored from backup.",
    /* 0x42 */ "Connection accepted from: ",
    /* 0x43 */ "Connection closed for: ",
    /* 0x44 */ "Enrollment succeeded for: ",
    /* 0x45 */ "Enrollment failed for: ",
    /* 0x46 */ "Certificate revocation issued for: ",
    /* 0x47 */ "Anchor push succeeded.",
    /* 0x48 */ "Anchor push failed.",
    /* 0x49 */ "Anchor record received.",
    /* 0x4A */ "Memory allocation failure for: ",
    /* 0x4B */ "Receive failure from: ",
    /* 0x4C */ "Invalid request received from: ",
    /* 0x4D */ "Dispatch failure for message from: ",
};

static const char UDIF_APPLICATION_MODE_STRINGS [UDIF_APPLICATION_MODE_STRING_DEPTH][UDIF_APPLICATION_MODE_STRING_SIZE] =
{
    /* udif_console_mode_user        */ "> ",
    /* udif_console_mode_enable      */ "# ",
    /* udif_console_mode_config      */ "(config)# ",
    /* udif_console_mode_certificate */ "(config-certificate)# ",
    /* udif_console_mode_server      */ "(config-server)# ",
};

static const char UDIF_APPLICATION_HELP_STRINGS [UDIF_APPLICATION_HELP_STRING_DEPTH][UDIF_APPLICATION_HELP_STRING_SIZE] =
{
    /* 0x00 udif_command_action_none         */ "unknown command",
    /* 0x01 udif_command_action_unrecognized */ "unknown command",

    /* certificate mode (0x02-0x07) */
    /* 0x02 certificate_exit     */ "exit - exit to config mode",
    /* 0x03 certificate_export   */ "export <directory> - export certificate to directory",
    /* 0x04 certificate_generate */ "generate [days] - generate UDIF and QSTP keypairs",
    /* 0x05 certificate_help     */ "help - certificate mode help",
    /* 0x06 certificate_print    */ "print - display the current certificate",
    /* 0x07 certificate_sign     */ "sign [filepath] - sign a subordinate CSR (Root only)",

    /* config mode (0x08-0x15) */
    /* 0x08 config_address       */ "address [ip] - set the server IPv4 address",
    /* 0x09 config_certificate   */ "certificate - enter certificate mode",
    /* 0x0A config_clear_all     */ "clear all - erase all keys, certs, ledgers and logs",
    /* 0x0B config_clear_config  */ "clear config - erase the configuration file",
    /* 0x0C config_clear_log     */ "clear log - erase the activity log",
    /* 0x0D config_exit          */ "exit - exit to enable mode",
    /* 0x0E config_help          */ "help - config mode help",
    /* 0x0F config_log           */ "log enable|disable - control activity logging",
    /* 0x10 config_name_domain   */ "name domain [name] - set the domain name",
    /* 0x11 config_name_host     */ "name host [name] - set the host name",
    /* 0x12 config_port          */ "port [number] - set the listen port",
    /* 0x13 config_retries       */ "retries [count] - set login retry limit (1-5)",
    /* 0x14 config_server        */ "server - enter server mode",
    /* 0x15 config_timeout       */ "timeout [minutes] - set idle timeout (1-60)",

    /* server mode (0x16-0x1C) */
    /* 0x16 server_anchor        */ "anchor - force an anchor push to parent now",
    /* 0x17 server_backup        */ "backup - save a state backup",
    /* 0x18 server_exit          */ "exit - exit to config mode",
    /* 0x19 server_help          */ "help - server mode help",
    /* 0x1A server_restore       */ "restore - restore state from backup",
    /* 0x1B server_service       */ "service start|stop|pause|resume - control the network service",
    /* 0x1C server_status        */ "status - show tunnel and ledger status",

    /* enable mode (0x1D-0x23) */
    /* 0x1D enable_clear_screen  */ "clear screen - clear the console window",
    /* 0x1E enable_config        */ "config - enter config mode",
    /* 0x1F enable_exit          */ "exit - return to user mode",
    /* 0x20 enable_help          */ "help - enable mode help",
    /* 0x21 enable_quit          */ "quit - close the application",
    /* 0x22 enable_show_config   */ "show config - display current configuration",
    /* 0x23 enable_show_log      */ "show log - display the activity log",

    /* user mode (0x24-0x26) */
    /* 0x24 user_enable          */ "enable - authenticate and enter enable mode",
    /* 0x25 user_help            */ "help - user mode help",
    /* 0x26 user_quit            */ "quit - close the application",
};

#endif
