/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDAARS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef UDIF_SERVER_H
#define UDIF_SERVER_H

#include "udifcommon.h"
#include "certificate.h"
#include "commands.h"
#include "logger.h"
#include "udif.h"
#include "topology.h"
#include "collection.h"

/**
 * \file server.h
 * \brief The common UDIF server functions.
 *
 * Detailed File Description:
 * This header file defines the common functions, macros, enumerations, and data structures used by
 * the UDIF server. The functions in this file cover certificate management, logging, topology
 * management, configuration, state backup and restore, and user login functionalities. Every public
 * function, macro, struct, and enumeration is documented in detail below.
 */

/*---------------------------------------------------------------------------
  MACRO DEFINITIONS
---------------------------------------------------------------------------*/

/**
 * \def UDIF_SERVER_MINIMUM_COMMAND_LENGTH
 * \brief The minimum valid length for a server command.
 */
#define UDIF_SERVER_MINIMUM_COMMAND_LENGTH 4U

/**
 * \def UDIF_SERVER_APPLICATION_STATE_SIZE
 * \brief Calculates the size of the UDIF server application state.
 *
 * This macro sums the sizes of various maximum string lengths and fixed?size fields used in
 * the server state structure.
 */
#define UDIF_SERVER_APPLICATION_STATE_SIZE (UDIF_STORAGE_DOMAINNAME_MAX + UDIF_STORAGE_HOSTNAME_MAX + \
    UDIF_STORAGE_ADDRESS_MAX + UDIF_STORAGE_PATH_MAX + UDIF_STORAGE_USERNAME_MAX + UDIF_CERTIFICATE_ISSUER_SIZE + \
    sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(bool) + sizeof(bool) + \
    UDIF_ASYMMETRIC_SIGNING_KEY_SIZE)

/*---------------------------------------------------------------------------
  ENUMERATIONS
---------------------------------------------------------------------------*/

/*!
 * \enum udif_server_server_loop_status
 * \brief The UDIF server loop status.
 *
 * This enumeration represents the current state of the server's main loop.
 */
UDIF_EXPORT_API typedef enum udif_server_server_loop_status
{
    udif_server_loop_status_stopped = 0x00U,        /*!< The server is stopped. */
    udif_server_loop_status_started = 0x01U,        /*!< The server is running. */
    udif_server_loop_status_paused  = 0x02U,        /*!< The server is paused. */
} udif_server_server_loop_status;

/*---------------------------------------------------------------------------
  DATA STRUCTURES
---------------------------------------------------------------------------*/

/*!
 * \struct udif_server_application_state
 * \brief The UDIF server state.
 *
 * This structure holds all state information used by the UDIF server. It includes the command prompt,
 * network domain and host names, certificate issuer, IP address, log path, username, key chain, signing key,
 * file names and paths for various configuration files, certificate structures, topology list, current action,
 * console mode, network port, server type designation, timeout value, number of retries, and flags indicating
 * whether the server has joined a network or is logging host activity.
 */
UDIF_EXPORT_API typedef struct udif_server_application_state
{
    char cmdprompt[UDIF_STORAGE_PROMPT_MAX];          /*!< The current command prompt string. */
    char domain[UDIF_STORAGE_DOMAINNAME_MAX];         /*!< The network domain name. */
    char hostname[UDIF_STORAGE_HOSTNAME_MAX];         /*!< The server hostname. */
    char issuer[UDIF_CERTIFICATE_ISSUER_SIZE];         /*!< The certificate issuer string. */
    char localip[UDIF_STORAGE_ADDRESS_MAX];           /*!< The server's local IP address. */
    char logpath[UDIF_STORAGE_PATH_MAX];              /*!< The full path to the log file. */
    char username[UDIF_STORAGE_USERNAME_MAX];         /*!< The username used for login. */
    uint8_t* kchain;                                  /*!< Pointer to the key chain array. */
    uint8_t* sigkey;                                  /*!< Pointer to the secret signing key. */
    const char* aplpath;                              /*!< The application path. */
    const char* banner;                               /*!< The application banner text. */
    const char* cfgname;                              /*!< The configuration file name. */
    const char* prikeyname;                           /*!< The private key file name. */
    const char* promptdef;                            /*!< The default prompt string. */
    const char* pubkeyname;                           /*!< The public key file name. */
    const char* srvname;                              /*!< The server name. */
    const char* topname;                              /*!< The topology file name. */
    const char* wtitle;                               /*!< The window title. */
    udif_child_certificate ads;                       /*!< The ADC (Device-Level Authority) certificate. */
    udif_root_certificate root;                       /*!< The root certificate. */
    udif_topology_list_state tlist;                   /*!< The topology list state. */
    udif_command_actions action;                      /*!< The current command action. */
    udif_console_modes mode;                          /*!< The current console mode. */
    uint16_t port;                                    /*!< The network port number. */
    udif_network_designations srvtype;               /*!< The server type designation. */
    uint16_t timeout;                                 /*!< The console timeout in minutes. */
    uint8_t retries;                                  /*!< The allowed number of password retries. */
    bool joined;                                      /*!< True if the server has joined the network. */
    bool loghost;                                     /*!< True if host logging is enabled. */
} udif_server_application_state;

/*---------------------------------------------------------------------------
  FUNCTION PROTOTYPES
---------------------------------------------------------------------------*/

/**
 * \brief Get the full delimited path to the certificate storage directory.
 *
 * This function builds the full directory path where certificates are stored, based on the server's
 * configuration in the application state.
 *
 * \param state [const] The server application state.
 * \param dpath The output buffer that receives the certificate storage directory path.
 * \param pathlen The length of the dpath buffer.
 */
UDIF_EXPORT_API void udif_server_certificate_directory(const udif_server_application_state* state, char* dpath, size_t pathlen);

/**
 * \brief Get the full path to a certificate.
 *
 * This function constructs the full file path to a certificate based on the certificate issuer.
 *
 * \param state [const] The server application state.
 * \param fpath The output buffer that receives the certificate file path.
 * \param pathlen The length of the fpath buffer.
 * \param issuer [const] The issuer name of the certificate.
 */
UDIF_EXPORT_API void udif_server_certificate_path(const udif_server_application_state* state, char* fpath, size_t pathlen, const char* issuer);

/**
 * \brief Export the local certificate to a file.
 *
 * This function exports the local child certificate to the specified destination directory.
 *
 * \param state [const] The server application state.
 * \param dpath The destination directory path.
 *
 * \return Returns true if the certificate is successfully exported.
 */
UDIF_EXPORT_API bool udif_server_child_certificate_export(const udif_server_application_state* state, const char* dpath);

/**
 * \brief Get the certificate instance from file using the issuer string.
 *
 * This function loads a child certificate from file using the issuer string.
 *
 * \param ccert The output child certificate.
 * \param state [const] The server application state.
 * \param issuer [const] The certificate issuer string.
 *
 * \return Returns true if the certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_child_certificate_from_issuer(udif_child_certificate* ccert, const udif_server_application_state* state, const char* issuer);

/**
 * \brief Get the certificate instance from file using the serial number.
 *
 * This function loads a child certificate from file using its serial number.
 *
 * \param ccert The output child certificate.
 * \param state [const] The server application state.
 * \param serial [const] The certificate serial number.
 *
 * \return Returns true if the certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_child_certificate_from_serial(udif_child_certificate* ccert, const udif_server_application_state* state, const uint8_t* serial);

/**
 * \brief Generate a new child certificate.
 *
 * This function generates a new child certificate, writes the signature private key to the server state,
 * and populates the child certificate structure.
 *
 * \param state The server application state. The private key is written to state->sigkey.
 * \param ccert The output child certificate.
 * \param period The number of seconds the certificate is valid.
 * \param capability The capability bit mask.
 */
UDIF_EXPORT_API void udif_server_child_certificate_generate(udif_server_application_state* state, udif_child_certificate* ccert, uint64_t period, uint8_t* capability);

/**
 * \brief Import the local certificate signed by the root.
 *
 * This function imports the local certificate that has been signed by the root certificate.
 *
 * \param lcert The local certificate structure to populate.
 * \param state The server application state.
 * \param fpath The full file path to the certificate file.
 *
 * \return Returns true if the certificate is successfully imported.
 */
UDIF_EXPORT_API bool udif_server_child_certificate_import(udif_child_certificate* lcert, udif_server_application_state* state, const char* fpath);

/**
 * \brief Get the full path to the child certificate.
 *
 * This function retrieves the full file path of the child certificate based on the server state.
 *
 * \param state [const] The server application state.
 * \param fpath The output buffer that receives the certificate file path.
 * \param pathlen The length of the fpath buffer.
 */
UDIF_EXPORT_API void udif_server_child_certificate_path(const udif_server_application_state* state, char* fpath, size_t pathlen);

/**
 * \brief Get the certificate file path from the certificate issuer name.
 *
 * This function constructs the file path to a certificate using the issuer name.
 *
 * \param state [const] The server application state.
 * \param fpath The output buffer that receives the file path.
 * \param pathlen The length of the file path buffer.
 * \param issuer The certificate's issuer name.
 */
UDIF_EXPORT_API void udif_server_child_certificate_path_from_issuer(const udif_server_application_state* state, char* fpath, size_t pathlen, const char* issuer);

/**
 * \brief Print the local child certificate to console.
 *
 * This function prints the local child certificate (read from file) to the console.
 *
 * \param fpath The file path to the certificate.
 * \param pathlen The length of the file path buffer.
 *
 * \return Returns true if the certificate is successfully printed.
 */
UDIF_EXPORT_API bool udif_server_child_certificate_print(const char* fpath, size_t pathlen);

/**
 * \brief Store a child certificate.
 *
 * This function stores the local child certificate to file using the server state information.
 *
 * \param state The server application state.
 * \param ccert The child certificate to store.
 * \param address The network address associated with the certificate.
 */
UDIF_EXPORT_API void udif_server_local_certificate_store(udif_server_application_state* state, const udif_child_certificate* ccert, const char* address);

/**
 * \brief Erase and reset the configuration file.
 *
 * This function erases the current configuration file and resets it.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_clear_config(udif_server_application_state* state);

/**
 * \brief Erase the log file.
 *
 * This function erases the server log file.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_clear_log(udif_server_application_state* state);

/**
 * \brief Erase all state, including log files, and reset configuration.
 *
 * This function erases all persistent state and log files, effectively resetting the server.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_erase_all(udif_server_application_state* state);

/**
 * \brief Enable logging on the server.
 *
 * This function enables host logging for the server.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_log_host(udif_server_application_state* state);

/**
 * \brief Print the log file to the console.
 *
 * This function outputs the contents of the server log file to the console.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_log_print(udif_server_application_state* state);

/**
 * \brief Write a message to the log.
 *
 * This function writes a log message with an optional predefined message header.
 *
 * \param state The server application state.
 * \param msgtype The predefined message enumerator.
 * \param message [const] The optional text message.
 * \param msglen The length of the text message.
 * 
 * \return Returns true if the log message was successfully written.
 */
UDIF_EXPORT_API bool udif_server_log_write_message(udif_server_application_state* state, udif_application_messages msgtype, const char* message, size_t msglen);

/**
 * \brief Get the path to the mfk collection file.
 *
 * This function constructs the full file path for the master fragmentation key (mfk) collection.
 *
 * \param state [const] The server application state.
 * \param fpath The output buffer that receives the file path.
 * \param pathlen The length of the fpath buffer.
 */
UDIF_EXPORT_API void udif_server_mfkcol_path(const udif_server_application_state* state, char* fpath, size_t pathlen);

/**
 * \brief Convert an encrypted mfk collection file to a collection state.
 *
 * This function reads the encrypted mfk collection from file and converts it into the internal collection state.
 *
 * \param mfkcol The empty collection state that will be populated.
 * \param state [const] The server application state.
 *
 * \return Returns true if the mfk collection is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_mfkcol_from_file(qsc_collection_state* mfkcol, const udif_server_application_state* state);

/**
 * \brief Convert an mfk collection to an encrypted file.
 *
 * This function writes the current mfk collection state to an encrypted file.
 *
 * \param mfkcol [const] The mfk collection state.
 * \param state [const] The server application state.
 */
UDIF_EXPORT_API void udif_server_mfkcol_to_file(const qsc_collection_state* mfkcol, const udif_server_application_state* state);

/**
 * \brief Print the server banner.
 *
 * This function prints the server banner to the console.
 *
 * \param state [const] The server application state.
 */
UDIF_EXPORT_API void udif_server_print_banner(const udif_server_application_state* state);

/**
 * \brief Print a network error to the console.
 *
 * This function prints a formatted error message for network errors.
 *
 * \param state [const] The server application state.
 * \param appmsg The predefined application message enumerator.
 * \param message The error message text.
 * \param error The protocol error code.
 */
UDIF_EXPORT_API void udif_server_print_error(const udif_server_application_state* state, udif_application_messages appmsg, const char* message, udif_protocol_errors error);

/**
 * \brief Print the server configuration.
 *
 * This function prints the current server configuration to the console.
 *
 * \param state [const] The server application state.
 */
UDIF_EXPORT_API void udif_server_print_configuration(const udif_server_application_state* state);

/**
 * \brief Export the root certificate to a directory.
 *
 * This function exports the server's root certificate to the specified destination directory.
 *
 * \param state [const] The server application state.
 * \param dpath The destination directory path.
 *
 * \return Returns true if the export is successful.
 */
UDIF_EXPORT_API bool udif_server_root_certificate_export(const udif_server_application_state* state, const char* dpath);

/**
 * \brief Import the root certificate.
 *
 * This function prompts the user to import the root certificate through a dialogue.
 *
 * \param state The server application state.
 *
 * \return Returns true if the root certificate is successfully imported.
 */
UDIF_EXPORT_API bool udif_server_root_import_dialogue(udif_server_application_state* state);

/**
 * \brief Generate a new root certificate.
 *
 * This function generates a new root certificate, writes the signature private key to the server state,
 * and populates the root certificate structure.
 *
 * \param state The server application state; the private key is written to state->sigkey.
 * \param rcert The output root certificate.
 * \param period The validity period (in seconds) for the certificate.
 */
UDIF_EXPORT_API void udif_server_root_certificate_generate(udif_server_application_state* state, udif_root_certificate* rcert, uint64_t period);

/**
 * \brief Load a root certificate using the issuer name.
 *
 * This function loads the root certificate from file using the issuer name.
 *
 * \param state [const] The server application state.
 * \param root The output root certificate.
 * \param tlist [const] A pointer to the topology list.
 *
 * \return Returns true if the root certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_root_certificate_load(const udif_server_application_state* state, udif_root_certificate* root, const udif_topology_list_state* tlist);

/**
 * \brief Print a formatted root certificate to console.
 *
 * This function prints a formatted version of the root certificate to the console.
 *
 * \param fpath The file path to the root certificate.
 * \param pathlen The length of the file path buffer.
 *
 * \return Returns true if the certificate is successfully printed.
 */
UDIF_EXPORT_API bool udif_server_root_certificate_print(const char* fpath, size_t pathlen);

/**
 * \brief Store a root certificate to a file.
 *
 * This function stores the root certificate to file.
 *
 * \param state The server application state.
 * \param rcert The root certificate to store.
 * \param address The root certificate's address.
 */
UDIF_EXPORT_API void udif_server_root_certificate_store(udif_server_application_state* state, const udif_root_certificate* rcert);

/**
 * \brief Set the command prompt to the current state mode.
 *
 * This function sets the command prompt based on the current console mode in the server state.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_set_command_prompt(udif_server_application_state* state);

/**
 * \brief Set the number of idle minutes before the user is logged out.
 *
 * This function configures the console timeout period (in minutes) for automatic user logout.
 *
 * \param state The server application state.
 * \param snum The number string representing the timeout period in minutes.
 * \param numlen The length of the number string.
 *
 * \return Returns true if the timeout is successfully set.
 */
UDIF_EXPORT_API bool udif_server_set_console_timeout(udif_server_application_state* state, const char* snum, size_t numlen);

/**
 * \brief Rename the network domain.
 *
 * This function renames the network domain in the server configuration.
 *
 * \param state The server application state.
 * \param name The new domain name.
 * \param namelen The length of the domain name string.
 *
 * \return Returns true if the domain name is successfully changed.
 */
UDIF_EXPORT_API bool udif_server_set_domain_name(udif_server_application_state* state, const char* name, size_t namelen);

/**
 * \brief Rename the server host.
 *
 * This function renames the server host in the configuration.
 *
 * \param state The server application state.
 * \param name The new host name.
 * \param namelen The length of the host name string.
 *
 * \return Returns true if the host name is successfully changed.
 */
UDIF_EXPORT_API bool udif_server_set_host_name(udif_server_application_state* state, const char* name, size_t namelen);

/**
 * \brief Set the IP address of the server.
 *
 * This function sets the server's IP address.
 *
 * \param state The server application state.
 * \param address The IP address string.
 * \param addlen The length of the address string.
 *
 * \return Returns true if the IP address is successfully set.
 */
UDIF_EXPORT_API bool udif_server_set_ip_address(udif_server_application_state* state, const char* address, size_t addlen);

/**
 * \brief Set the number of failed password retries.
 *
 * This function sets the maximum number of failed password attempts allowed.
 *
 * \param state The server application state.
 * \param snum The number string representing the number of retries.
 * \param numlen The length of the number string.
 *
 * \return Returns true if the number of retries is successfully set.
 */
UDIF_EXPORT_API bool udif_server_set_password_retries(udif_server_application_state* state, const char* snum, size_t numlen);

/**
 * \brief Erase the signature-scheme signing key.
 *
 * This function erases the signing key stored in the server state.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_erase_signature_key(udif_server_application_state* state);

/**
 * \brief Restore the state from backup.
 *
 * This function restores the server state from a previously saved backup.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_state_backup_restore(const udif_server_application_state* state);

/**
 * \brief Backup the state.
 *
 * This function saves the current server state to a backup file.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_state_backup_save(const udif_server_application_state* state);

/**
 * \brief Initialize the internal state.
 *
 * This function initializes the UDIF server state for a given server type.
 *
 * \param state The server application state.
 * \param srvtype The server type designation.
 */
UDIF_EXPORT_API void udif_server_state_initialize(udif_server_application_state* state, udif_network_designations srvtype);

/**
 * \brief Write the server state to file.
 *
 * This function writes the current server state to an encrypted file.
 *
 * \param state The server application state.
 *
 * \return Returns true if the state is successfully stored.
 */
UDIF_EXPORT_API bool udif_server_state_store(udif_server_application_state* state);

/**
 * \brief Unload the server state from memory.
 *
 * This function unloads and clears the current server state from memory.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_state_unload(udif_server_application_state* state);

/**
 * \brief Load the ADC certificate from state.
 *
 * This function loads the ADC certificate from the server state.
 *
 * \param state [const] The server application state.
 * \param dcert The output ADC certificate.
 *
 * \return Returns true if the ADC certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_topology_adc_fetch(const udif_server_application_state* state, udif_child_certificate* dcert);

/**
 * \brief Load the topology from an encrypted file to state.
 *
 * This function loads the network topology from an encrypted file into the server state.
 *
 * \param state The server application state.
 *
 * \return Returns true if the topology is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_topology_load(udif_server_application_state* state);

/**
 * \brief Print the topological list to the console.
 *
 * This function prints the network topology list to the console.
 *
 * \param state [const] The server application state.
 */
UDIF_EXPORT_API void udif_server_topology_print_list(udif_server_application_state* state);

/**
 * \brief Clear the topology list except for the root and local nodes.
 *
 * This function purges the topology list by deleting all nodes except for the root and local nodes.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_topology_purge_externals(udif_server_application_state* state);

/**
 * \brief Delete the certificate.
 *
 * This function deletes a certificate from the topology based on its issuer.
 *
 * \param state The server application state.
 * \param issuer The target node's issuer string.
 */
UDIF_EXPORT_API void udif_server_topology_remove_certificate(udif_server_application_state* state, const char* issuer);

/**
 * \brief Remove a node from the topology.
 *
 * This function removes a node from the topology list based on its issuer.
 *
 * \param state The server application state.
 * \param issuer The target node's issuer string.
 */
UDIF_EXPORT_API void udif_server_topology_remove_node(udif_server_application_state* state, const char* issuer);

/**
 * \brief Delete all nodes and certificates except for the root.
 *
 * This function resets the topology list by deleting all nodes and certificates except the root.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_topology_reset(udif_server_application_state* state);

/**
 * \brief Load the local certificate from state.
 *
 * This function loads the local child certificate from the server state.
 *
 * \param state [const] The server application state.
 * \param ccert The output local certificate.
 *
 * \return Returns true if the certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_topology_local_fetch(const udif_server_application_state* state, udif_child_certificate* ccert);

/**
 * \brief Check if the root certificate exists on file.
 *
 * This function checks whether the root certificate file exists.
 *
 * \param state [const] The server application state.
 *
 * \return Returns true if the root certificate exists.
 */
UDIF_EXPORT_API bool udif_server_topology_root_exists(const udif_server_application_state* state);

/**
 * \brief Load the root certificate from state.
 *
 * This function loads the root certificate from the server state.
 *
 * \param state [const] The server application state.
 * \param rcert The output root certificate.
 *
 * \return Returns true if the root certificate is successfully loaded.
 */
UDIF_EXPORT_API bool udif_server_topology_root_fetch(const udif_server_application_state* state, udif_root_certificate* rcert);

/**
 * \brief Copy the topology to an encrypted file.
 *
 * This function writes the current network topology from the server state to an encrypted file.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_topology_to_file(udif_server_application_state* state);

/**
 * \brief Start the user login dialogue.
 *
 * This function initiates the user login process and prompts for credentials.
 *
 * \param state The server application state.
 *
 * \return Returns true if the user logged in successfully.
 */
UDIF_EXPORT_API bool udif_server_user_login(udif_server_application_state* state);

/**
 * \brief Log out of the server.
 *
 * This function logs out the current user and resets the session.
 *
 * \param state The server application state.
 */
UDIF_EXPORT_API void udif_server_user_logout(udif_server_application_state* state);

#endif
