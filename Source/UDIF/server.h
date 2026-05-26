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

#ifndef UDIF_SERVER_H
#define UDIF_SERVER_H

#include "udif.h"
#include "udifcommon.h"
#include "commands.h"
#include "logger.h"
#include "entity.h"
#include "certificate.h"
#include "mcelmanager.h"
#include "qstp.h"
#include "root.h"

/*!
 * \file server.h
 * \brief UDIF server application state and shared support API.
 *
 * Defines udif_server_application_state — the single struct shared by
 * all four UDIF entity types (Root, BC, GC, UA) — and the full set of
 * support functions that operate on it. The design mirrors the MPDC
 * server.h pattern: one central state, one set of support functions,
 * per-entity files (root.c, bc.c, gc.c, ua.c) that call into this API.
 *
 * Key differences from MPDC server.h:
 *   - UDIF has two certificate layers: QSTP transport cert + UDIF
 *     identity cert. Both are stored in state.
 *   - The signing key is stored as a udif_signature_keypair (not a
 *     raw pointer into a keychain), keeping key material self-contained.
 *   - There is no encrypted topology file; the MCEL ledger manager
 *     handles all persistent identity and transaction state.
 *   - The log file is plain-text (not encrypted); background threads
 *     use mutex protection via udif_logger_write_*.
 *   - UA (udif_role_client) sets mcelmgr to NULL and haslistener to false.
 */

/* Constants */

/*!
 * \def UDIF_STORAGE_PROMPT_MAX
 * \brief Maximum length of the command prompt string.
 */
#define UDIF_STORAGE_PROMPT_MAX 64U

/*!
 * \def UDIF_STORAGE_HOSTNAME_MAX
 * \brief Maximum length of the hostname.
 */
#define UDIF_STORAGE_HOSTNAME_MAX 128U

/*!
 * \def UDIF_STORAGE_HOSTNAME_MIN
 * \brief Minimum length of the hostname.
 */
#define UDIF_STORAGE_HOSTNAME_MIN 2U

/*!
 * \def UDIF_STORAGE_DOMAINNAME_MAX
 * \brief Maximum length of the domain name.
 */
#define UDIF_STORAGE_DOMAINNAME_MAX 260U

/*!
 * \def UDIF_STORAGE_DOMAINNAME_MIN
 * \brief Minimum length of the domain name.
 */
#define UDIF_STORAGE_DOMAINNAME_MIN 2U

/*!
 * \def UDIF_STORAGE_ADDRESS_MAX
 * \brief Maximum length of an IPv4 address string.
 */
#define UDIF_STORAGE_ADDRESS_MAX 65U

/*!
 * \def UDIF_STORAGE_ADDRESS_MIN
 * \brief Minimum length of an IPv4 address string.
 */
#define UDIF_STORAGE_ADDRESS_MIN 7U

/*!
 * \def UDIF_STORAGE_PATH_MAX
 * \brief Maximum file system path length.
 */
#define UDIF_STORAGE_PATH_MAX 260U

/*!
 * \def UDIF_STORAGE_USERNAME_MAX
 * \brief Maximum length of the user name.
 */
#define UDIF_STORAGE_USERNAME_MAX 128U

/*!
 * \def UDIF_STORAGE_USERNAME_MIN
 * \brief Minimum length of the user name.
 */
#define UDIF_STORAGE_USERNAME_MIN 6U

/*!
 * \def UDIF_STORAGE_PASSWORD_MAX
 * \brief Maximum length of the password.
 */
#define UDIF_STORAGE_PASSWORD_MAX 256U

/*!
 * \def UDIF_STORAGE_PASSWORD_MIN
 * \brief Minimum length of the password.
 */
#define UDIF_STORAGE_PASSWORD_MIN 8U

/*!
 * \def UDIF_STORAGE_RETRIES_MIN
 * \brief Minimum value for login retry count.
 */
#define UDIF_STORAGE_RETRIES_MIN 1U

/*!
 * \def UDIF_STORAGE_RETRIES_MAX
 * \brief Maximum value for login retry count.
 */
#define UDIF_STORAGE_RETRIES_MAX 5U

/*!
 * \def UDIF_STORAGE_TIMEOUT_MIN
 * \brief Minimum value for console idle timeout (minutes).
 */
#define UDIF_STORAGE_TIMEOUT_MIN 1U

/*!
 * \def UDIF_STORAGE_TIMEOUT_MAX
 * \brief Maximum value for console idle timeout (minutes).
 */
#define UDIF_STORAGE_TIMEOUT_MAX 60U

/*!
 * \def UDIF_SERVER_PAUSE_INTERVAL
 * \brief Milliseconds to sleep per iteration when command loop is paused.
 */
#define UDIF_SERVER_PAUSE_INTERVAL 250U

/*!
 * \def UDIF_SERVER_MINIMUM_COMMAND_LENGTH
 * \brief Minimum meaningful command string length.
 */
#define UDIF_SERVER_MINIMUM_COMMAND_LENGTH 2U

/*!
 * \def UDIF_DEFAULT_SESSION_TIMEOUT
 * \brief Default console idle timeout in minutes.
 */
#define UDIF_DEFAULT_SESSION_TIMEOUT 10U

/*!
 * \def UDIF_DEFAULT_AUTH_RETRIES
 * \brief Default number of login retries allowed.
 */
#define UDIF_DEFAULT_AUTH_RETRIES 3U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_ROOT
 * \brief Default Root certificate validity in days (10 years).
 */
#define UDIF_CERTIFICATE_VALIDITY_ROOT 3650U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_BC
 * \brief Default Branch Controller certificate validity in days (5 years).
 */
#define UDIF_CERTIFICATE_VALIDITY_BC 1825U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_GC
 * \brief Default Group Controller certificate validity in days (5 years).
 */
#define UDIF_CERTIFICATE_VALIDITY_GC 1825U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_UA
 * \brief Default User Agent certificate validity in days (1 year).
 */
#define UDIF_CERTIFICATE_VALIDITY_UA 365U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_MIN
 * \brief Minimum certificate validity in days.
 */
#define UDIF_CERTIFICATE_VALIDITY_MIN 30U

/*!
 * \def UDIF_CERTIFICATE_VALIDITY_MAX
 * \brief Maximum certificate validity in days.
 */
#define UDIF_CERTIFICATE_VALIDITY_MAX 7300U

/* Enumerations */

/*!
 * \enum udif_server_loop_status
 * \brief Status of the server service loop or command loop.
 */
UDIF_EXPORT_API typedef enum udif_server_loop_status
{
    udif_server_loop_stopped = 0x00U, /*!< Loop is not running. */
    udif_server_loop_started = 0x01U, /*!< Loop is running. */
    udif_server_loop_paused  = 0x02U, /*!< Loop is paused; command loop sleeps. */
} udif_server_loop_status;

/* Application state */

/*!
 * \struct udif_server_application_state
 * \brief Central application state shared by all UDIF entity types.
 *
 * Allocated on the stack inside each server's start_server() function
 * and passed by pointer to all support functions. Never heap-allocated.
 *
 * Field groups:
 *   Console strings       — cmdprompt, hostname, domain, localip, logpath, username
 *   Resource pointers     — banner, srvname, wtitle, promptdef, aplpath, cfgname,
 *                           certname, keynamepub, keynamepri (all static, never freed)
 *   UDIF identity         — selfcert, parentcert, rootcert, selfkeypair
 *   QSTP transport        — qstprootcert, qstpserverkey (NULL for UA)
 *   MCEL ledger           — mcelmgr (NULL for UA)
 *   Tunnel table          — tunnels (shared with entity layer)
 *   Anchor cadence        — nextanchorsecs
 *   Console state         — action, mode, role
 *   Loop status           — cmdloopstatus, srvloopstatus
 *   Configuration scalars — port, timeout, retries, joined, loghost
 */
UDIF_EXPORT_API typedef struct udif_server_application_state
{
    /* console strings */
    char cmdprompt[UDIF_STORAGE_PROMPT_MAX];     /*!< Current command prompt string. */
    char domain[UDIF_STORAGE_DOMAINNAME_MAX];    /*!< Network domain name. */
    char hostname[UDIF_STORAGE_HOSTNAME_MAX];    /*!< Server host name. */
    char localip[UDIF_STORAGE_ADDRESS_MAX];      /*!< Bound IPv4 address string. */
    char logpath[UDIF_STORAGE_PATH_MAX];         /*!< Full path to the activity log file. */
    char username[UDIF_STORAGE_USERNAME_MAX];    /*!< Operator user name (set on first run). */

    /* static resource pointers (set in state_initialize) */
    const char* aplpath;                        /*!< Application subdirectory path (e.g. "\\Root"). */
    const char* banner;                         /*!< Multi-line startup banner text. */
    const char* cfgname;                        /*!< Config file name (e.g. "\\userconfig.rtcfg"). */
    const char* certname;                       /*!< UDIF certificate file name (e.g. "udif-root.cert"). */
    const char* keynamepri;                     /*!< UDIF private key file name (e.g. "udif-root.key"). */
    const char* keynamepub;                     /*!< QSTP server key file name (e.g. "qstp-server.key"). */
    const char* promptdef;                      /*!< Default prompt string (e.g. "Root> "). */
    const char* srvname;                        /*!< Short server name (e.g. "Root"). */
    const char* wtitle;                         /*!< Window title (e.g. "UDIF Root Authority v1.0"). */
    udif_certificate selfcert;                  /*!< This entity's UDIF certificate. */
    udif_certificate parentcert;                /*!< Parent entity's certificate (zeroed for Root). */
    udif_certificate rootcert;                  /*!< Root certificate. */
    udif_signature_keypair selfkeypair;         /*!< Long-term signing keypair. */
    qstp_root_certificate qstprootcert;         /*!< QSTP root certificate (loaded from file). */
    qstp_server_signature_key qstpserverkey;    /*!< QSTP server signing key (populated for listeners). */
    qstp_root_signature_key qstprootkey;        /*!< QSTP root signing key (populated for Root role only). */
    /* MCEL ledger */
    udif_mcel_manager* mcelmgr;                 /*!< Ledger manager; NULL for UA. */
    /* tunnel table */
    udif_tunnel_table tunnels;                  /*!< Active tunnel table. */
    /* anchor cadence */
    uint64_t nextanchorsecs;                    /*!< UTC epoch at which to push the next anchor. */
    /* console state */
    udif_command_actions action;                /*!< Current parsed command action. */
    udif_console_modes mode;                    /*!< Current console mode. */
    udif_roles role;                            /*!< Entity role (governs help and cert generation). */
    /* loop status */
    udif_server_loop_status cmdloopstatus;      /*!< Command loop status. */
    udif_server_loop_status srvloopstatus;      /*!< Network service loop status. */
    /* configuration scalars */
    uint16_t port;                              /*!< Network listen port. */
    uint16_t timeout;                           /*!< Console idle timeout in minutes. */
    uint8_t retries;                            /*!< Max login retries. */
    bool joined;                                /*!< True once enrolled with parent. */
    bool loghost;                               /*!< True when activity logging is enabled. */
} udif_server_application_state;

/* Lifecycle */

/*!
 * \brief Initialize the server application state for a given role.
 *
 * Clears the struct, sets all static resource pointers (banner, paths,
 * file names, default prompt), detects the local IP address and domain
 * name, sets default port, timeout, retries, and mode. Does not touch
 * the file system.
 *
 * \param state: The application state to initialize.
 * \param role: The entity role.
 */
UDIF_EXPORT_API void udif_server_state_initialize(udif_server_application_state* state, udif_roles role);

/*!
 * \brief Serialize and store the mutable state to disk.
 *
 * Writes domain, hostname, localip, username, port, timeout, retries,
 * joined, loghost to the config file. Certificate and key material is
 * NOT written here; that is handled by udif_server_cert_generate /
 * udif_server_cert_load.
 *
 * \param state: The application state to persist.
 *
 * \return Returns true if the file was written successfully.
 */
UDIF_EXPORT_API bool udif_server_state_store(udif_server_application_state* state);

/*!
 * \brief Load mutable state from disk and update the state struct.
 *
 * Reads the config file and deserializes into the state struct. Sets
 * the command prompt to the loaded hostname. Returns false if the
 * config file does not exist (first run).
 *
 * \param state: The application state to populate.
 *
 * \return Returns true if the config file existed and was loaded.
 */
UDIF_EXPORT_API bool udif_server_state_load(udif_server_application_state* state);

/*!
 * \brief Unload the state: zero sensitive key material and reset to defaults.
 *
 * Zeroes selfkeypair, clears the tunnel table, disposes the MCEL
 * manager if present, then re-initializes defaults via
 * udif_server_state_initialize.
 *
 * \param state: The application state to unload.
 */
UDIF_EXPORT_API void udif_server_state_unload(udif_server_application_state* state);

/*!
 * \brief Save a backup copy of all persistent files for this entity.
 *
 * Copies config, cert, key, and log files to a backup subdirectory.
 *
 * \param state: [const] The application state.
 */
UDIF_EXPORT_API void udif_server_state_backup_save(const udif_server_application_state* state);

/*!
 * \brief Restore persistent files from the backup subdirectory.
 *
 * \param state: [const] The application state.
 */
UDIF_EXPORT_API void udif_server_state_backup_restore(const udif_server_application_state* state);

/* Console */

/*!
 * \brief Print the startup banner.
 *
 * Prints state->banner followed by a blank line.
 *
 * \param state: [const] The application state.
 */
UDIF_EXPORT_API void udif_server_print_banner(const udif_server_application_state* state);

/*!
 * \brief Print the current configuration to the console.
 *
 * Prints domain, hostname, IP address, port, logging, timeout, retries,
 * joined status, and certificate summary.
 *
 * \param state: [const] The application state.
 */
UDIF_EXPORT_API void udif_server_print_configuration(const udif_server_application_state* state);

/*!
 * \brief Print the tunnel and ledger status to the console.
 *
 * Iterates the tunnel table and prints each active tunnel's role pair
 * and side. Prints ledger sequence numbers if mcelmgr is non-NULL.
 *
 * \param state: [const] The application state.
 */
UDIF_EXPORT_API void udif_server_print_status(const udif_server_application_state* state);

/*!
 * \brief Recompute and store the command prompt string.
 *
 * Builds cmdprompt from hostname + the mode suffix from
 * UDIF_APPLICATION_MODE_STRINGS. Called after every mode transition.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_set_command_prompt(udif_server_application_state* state);

/* Authentication */

/*!
 * \brief Run the operator login dialogue.
 *
 * On first run: prompts for a user name, password, host name, and IP
 * address, then stores the result. On subsequent runs: prompts for user
 * name and password and verifies against the stored credentials.
 *
 * \param state: The application state.
 *
 * \return Returns true if the operator authenticated successfully.
 */
UDIF_EXPORT_API bool udif_server_user_login(udif_server_application_state* state);

/*!
 * \brief Log out the current operator and return to user mode.
 *
 * Zeroes the password hash held in memory, clears username, resets
 * mode to udif_console_mode_user.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_user_logout(udif_server_application_state* state);

/* Configuration setters */

/*!
 * \brief Set the server's bound IPv4 address.
 *
 * \param state: The application state.
 * \param address: [const] Dotted-decimal IPv4 string.
 * \param addlen: Length of address.
 *
 * \return Returns true if the address is valid and was stored.
 */
UDIF_EXPORT_API bool udif_server_set_ip_address(udif_server_application_state* state, const char* address, size_t addlen);

/*!
 * \brief Set the host name.
 *
 * \param state: The application state.
 * \param name: [const] The new host name.
 * \param namelen: Length of name.
 *
 * \return Returns true if the name is valid and was stored.
 */
UDIF_EXPORT_API bool udif_server_set_host_name(udif_server_application_state* state, const char* name, size_t namelen);

/*!
 * \brief Set the domain name.
 *
 * \param state: The application state.
 * \param name: [const] The new domain name.
 * \param namelen: Length of name.
 *
 * \return Returns true if the name is valid and was stored.
 */
UDIF_EXPORT_API bool udif_server_set_domain_name(udif_server_application_state* state, const char* name, size_t namelen);

/*!
 * \brief Set the listen port.
 *
 * \param state: The application state.
 * \param snum: [const] Port number as a decimal string.
 * \param numlen: Length of snum.
 *
 * \return Returns true if the port is in range (1024-65535).
 */
UDIF_EXPORT_API bool udif_server_set_port(udif_server_application_state* state, const char* snum, size_t numlen);

/*!
 * \brief Set the console idle timeout.
 *
 * \param state: The application state.
 * \param snum: [const] Timeout in minutes as a decimal string.
 * \param numlen: Length of snum.
 *
 * \return Returns true if the value is in range (UDIF_STORAGE_TIMEOUT_MIN..MAX).
 */
UDIF_EXPORT_API bool udif_server_set_console_timeout(udif_server_application_state* state, const char* snum, size_t numlen);

/*!
 * \brief Set the login retry limit.
 *
 * \param state: The application state.
 * \param snum: [const] Retry count as a decimal string.
 * \param numlen: Length of snum.
 *
 * \return Returns true if the value is in range (UDIF_STORAGE_RETRIES_MIN..MAX).
 */
UDIF_EXPORT_API bool udif_server_set_password_retries(udif_server_application_state* state, const char* snum, size_t numlen);

/*!
 * \brief Toggle host activity logging and update the log file.
 *
 * If logging was disabled, enables it and writes an enable record.
 * If logging was enabled, writes a disable record and turns it off.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_log_host(udif_server_application_state* state);

/* Certificate management */

/*!
 * \brief Generate new UDIF and QSTP keypairs and certificates.
 *
 * For Root: generates a self-signed UDIF root cert and a QSTP root key.
 * For BC/GC/UA: generates a keypair and a CSR (unsigned cert); the
 * signed cert is installed later by udif_server_cert_load_signed.
 *
 * \param state: The application state.
 * \param validdays: Validity period in days.
 *
 * \return Returns true if generation and file write succeeded.
 */
UDIF_EXPORT_API bool udif_server_cert_generate(udif_server_application_state* state, uint32_t validdays);

/*!
 * \brief Export the local UDIF certificate to a directory.
 *
 * Copies the cert file to dpath. Used to distribute the cert to
 * subordinate entities or for manual import.
 *
 * \param state: [const] The application state.
 * \param dpath: [const] Destination directory path.
 *
 * \return Returns true if the file was copied successfully.
 */
UDIF_EXPORT_API bool udif_server_cert_export(const udif_server_application_state* state, const char* dpath);

/*!
 * \brief Load and validate the local UDIF certificate from disk.
 *
 * Reads selfcert and selfkeypair from the role-appropriate files.
 * If the cert file does not exist, sets selfcert to zeroed state
 * (first-run condition; caller should call cert_generate).
 *
 * \param state: The application state.
 *
 * \return Returns true if the cert and key were loaded and are valid.
 */
UDIF_EXPORT_API bool udif_server_cert_load(udif_server_application_state* state);

/*!
 * \brief Sign a subordinate certificate (Root only).
 *
 * Reads the CSR at fpath, signs it with state->selfkeypair.sigkey,
 * writes the signed certificate back to the same path. Validates that
 * the caller has udif_role_root before proceeding.
 *
 * \param state   The application state.
 * \param fpath: [const] Full path to the unsigned CSR file.
 *
 * \return Returns true if the certificate was signed and saved.
 */
UDIF_EXPORT_API bool udif_server_cert_sign(udif_server_application_state* state, const char* fpath);

/*!
 * \brief Print the local UDIF certificate fields to the console.
 *
 * Formats and prints: serial, role, issuer, valid-from, valid-to,
 * capability bitmap, and public key fingerprint.
 *
 * \param state: [const] The application state.
 *
 * \return Returns true if the certificate is loaded and was printed.
 */
UDIF_EXPORT_API bool udif_server_cert_print(const udif_server_application_state* state);

/* Logging */

/*!
 * \brief Write a timestamped, decorated log entry.
 *
 * Wrapper around udif_logger_write_decorated_time_stamped_message that
 * checks state->loghost before writing. No-op if logging is disabled.
 *
 * \param state: The application state.
 * \param msgtype: Predefined message enumerator (log-category entries).
 * \param message: [const] Optional supplementary text (may be NULL).
 * \param msglen: Length of supplementary text.
 *
 * \return Returns true if the entry was written.
 */
UDIF_EXPORT_API bool udif_server_log_write(udif_server_application_state* state, udif_application_messages msgtype, const char* message, size_t msglen);

/*!
 * \brief Print the activity log to the console, line by line.
 *
 * Reads the log file and prints each line with the enable-mode prompt.
 * Prints the "log is empty" message if the file is empty or missing.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_log_print(udif_server_application_state* state);

/* Erase */

/*!
 * \brief Erase the configuration file and reinitialize defaults.
 *
 * Deletes the config file from disk, reinitializes state to defaults.
 * Certificate and key files are NOT deleted; use udif_server_erase_all
 * for a full reset.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_clear_config(udif_server_application_state* state);

/*!
 * \brief Erase the activity log file and create a fresh one.
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_clear_log(udif_server_application_state* state);

/*!
 * \brief Erase all persistent state: config, certs, keys, log, ledger.
 *
 * Requires confirmation from the caller (the command handler must
 * present udif_application_erase_all before calling this function).
 *
 * \param state: The application state.
 */
UDIF_EXPORT_API void udif_server_erase_all(udif_server_application_state* state);

/* Path helpers */

/*!
 * \brief Build the full storage directory path for this entity.
 *
 * Format: <user-documents>\\UDIF<aplpath>\\
 * Creates the directory if it does not exist.
 *
 * \param state: [const] The application state.
 * \param dpath: Output buffer.
 * \param pathlen: Size of dpath.
 */
UDIF_EXPORT_API void udif_server_storage_directory(const udif_server_application_state* state, char* dpath, size_t pathlen);

/*!
 * \brief Build the full path to the certificate storage subdirectory.
 *
 * \param state: [const] The application state.
 * \param dpath: Output buffer.
 * \param pathlen: Size of dpath.
 */
UDIF_EXPORT_API void udif_server_cert_directory(const udif_server_application_state* state, char* dpath, size_t pathlen);

/*!
 * \brief Build the full path to the UDIF certificate file.
 *
 * \param state: [const] The application state.
 * \param fpath: Output buffer.
 * \param pathlen: Size of fpath.
 */
UDIF_EXPORT_API void udif_server_cert_path(const udif_server_application_state* state, char* fpath, size_t pathlen);

/*!
 * \brief Build the full path to the UDIF private key file.
 *
 * \param state: [const] The application state.
 * \param fpath: Output buffer.
 * \param pathlen: Size of fpath.
 */
UDIF_EXPORT_API void udif_server_key_path(const udif_server_application_state* state, char* fpath, size_t pathlen);

/*!
 * \brief Build the full path to the configuration file.
 *
 * \param state: [const] The application state.
 * \param fpath: Output buffer.
 * \param pathlen: Size of fpath.
 */
UDIF_EXPORT_API void udif_server_config_path(const udif_server_application_state* state, char* fpath, size_t pathlen);

/*!
 * \brief Build the full path to the MCEL data directory.
 *
 * \param state: [const] The application state.
 * \param dpath: Output buffer.
 * \param pathlen: Size of dpath.
 */
UDIF_EXPORT_API void udif_server_data_path(const udif_server_application_state* state, char* dpath, size_t pathlen);

/*!
 * \brief Build the full path to the backup subdirectory.
 *
 * \param state: [const] The application state.
 * \param dpath: Output buffer.
 * \param pathlen: Size of dpath.
 */
UDIF_EXPORT_API void udif_server_backup_directory(const udif_server_application_state* state, char* dpath, size_t pathlen);

#endif
