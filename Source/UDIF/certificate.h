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

#ifndef UDIF_CERTIFICATE_H
#define UDIF_CERTIFICATE_H

#include "udif.h"

/**
* \file certificate.h
* \brief UDIF certificate operations
*
* This module implements certificate generation, signing, verification,
* and serialization for the UDIF trust hierarchy. Certificates bind
* entities to their public keys and define their capabilities.
*
* Certificate Hierarchy:
* - Root: Self-signed, starts the trust chain
* - Branch Controllers: Signed by Root or parent Branch
* - Group Controllers: Signed by Branch
* - User Agents: Signed by Group Controller
*/


///*!
// * \def UDIF_CERTIFICATE_PKI_ENABLED
// * \brief The root certificate is signed by an X.509 implementation
// */
//#define UDIF_CERTIFICATE_PKI_ENABLED

/*!
 * \def UDIF_CERTIFICATE_ADDRESS_SIZE
 * \brief The maximum IP address length.
 */
#define UDIF_CERTIFICATE_ADDRESS_SIZE 22U

/*!
 * \def UDIF_CERTIFICATE_ALGORITHM_SIZE
 * \brief The algorithm type.
 */
#define UDIF_CERTIFICATE_ALGORITHM_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_ALGORITHM_PREFIX_SIZE
 * \brief The algorithm field prefix length.
 */
#define UDIF_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U

/*!
 * \def UDIF_CERTIFICATE_DEFAULT_PERIOD
 * \brief The default certificate validity period in seconds.
 */
#define UDIF_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_DESIGNATION_SIZE
 * \brief The size of the child certificate designation field.
 */
#define UDIF_CERTIFICATE_DESIGNATION_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE
 * \brief The "valid to" field prefix length.
 */
#define UDIF_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U

/*!
 * \def UDIF_CERTIFICATE_FOOTER_SIZE
 * \brief The UDIF certificate footer string length.
 */
#define UDIF_CERTIFICATE_FOOTER_SIZE 64U

/*!
 * \def UDIF_CERTIFICATE_HEADER_SIZE
 * \brief The UDIF certificate header string length.
 */
#define UDIF_CERTIFICATE_HEADER_SIZE 64U

/*!
 * \def UDIF_CERTIFICATE_ISSUER_PREFIX_SIZE
 * \brief The certificate issuer prefix length.
 */
#define UDIF_CERTIFICATE_ISSUER_PREFIX_SIZE 9U

/*!
* \def UDIF_CERTIFICATE_ISSUER_SIZE
 * \brief The maximum certificate issuer string length.
 * The last character must be a string terminator.
 */
#define UDIF_CERTIFICATE_ISSUER_SIZE 16U

/*!
 * \def UDIF_CERTIFICATE_LINE_LENGTH
 * \brief The line length of the printed UDIF certificate.
 */
#define UDIF_CERTIFICATE_LINE_LENGTH 64U

/*!
 * \def UDIF_CERTIFICATE_MAXIMUM_PERIOD
 * \brief The maximum certificate validity period in seconds.
 */
#define UDIF_CERTIFICATE_MAXIMUM_PERIOD (UDIF_CERTIFICATE_DEFAULT_PERIOD * 2U)

/*!
 * \def UDIF_CERTIFICATE_MINIMUM_PERIOD
 * \brief The minimum certificate validity period in seconds.
 */
#define UDIF_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_POLICY_SIZE
 * \brief The certificate policy field length.
 */
#define UDIF_CERTIFICATE_POLICY_SIZE 4U

/*!
 * \def UDIF_CERTIFICATE_ROLE_SIZE
 * \brief The certificate role field size.
 */
#define UDIF_CERTIFICATE_ROLE_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_SERIAL_PREFIX_SIZE
 * \brief The certificate serial prefix length.
 */
#define UDIF_CERTIFICATE_SERIAL_PREFIX_SIZE 9U

/*!
 * \def UDIF_CERTIFICATE_VALID_FROM_PREFIX_SIZE
 * \brief The "valid from" field prefix length.
 */
#define UDIF_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U

/*!
 * \def UDIF_CERTIFICATE_VERSION_SIZE
 * \brief The certificate version field size.
 */
#define UDIF_CERTIFICATE_VERSION_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_VERSION_PREFIX_SIZE
 * \brief The version field prefix length.
 */
#define UDIF_CERTIFICATE_VERSION_PREFIX_SIZE 10U

/*!
 * \def UDIF_CERTIFICATE_SIZE
 * \brief The length of a child certificate.
 */
#define UDIF_CERTIFICATE_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CERTIFICATE_ISSUER_SIZE + \
	UDIF_VALID_TIME_STRUCTURE_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_CERTIFICATE_POLICY_SIZE + \
	UDIF_ROLE_SIZE + \
	UDIF_SUITEID_SIZE)

/*!
 * \def UDIF_CERTIFICATE_SIGNING_SIZE
 * \brief The length of the base child certificate.
 */
#define UDIF_CERTIFICATE_SIGNING_SIZE (UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CERTIFICATE_ISSUER_SIZE + \
	UDIF_VALID_TIME_STRUCTURE_SIZE + \
	UDIF_CAPABILITY_MASK_SIZE + \
	UDIF_CERTIFICATE_POLICY_SIZE + \
	UDIF_ROLE_SIZE + UDIF_SUITEID_SIZE)

 /** \cond */

#define UDIF_CERTIFICATE_SEPERATOR_SIZE 1U
#define UDIF_CHILD_CERTIFICATE_HEADER_SIZE 64U
#define UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE 30U
#define UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE 23U
#define UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE 9U
#define UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE 14U
#define UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define UDIF_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE 14U
#define UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE 18U
#define UDIF_CHILD_CERTIFICATE_FOOTER_SIZE 64U
#define UDIF_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE 19U

static const char UDIF_CHILD_CERTIFICATE_HEADER[UDIF_CHILD_CERTIFICATE_HEADER_SIZE] = "-----------BEGIN UDIF CHILD PUBLIC CERTIFICATE BLOCK-----------";
static const char UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX[UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE] = "Root Signed Public Key Hash: ";
static const char UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX[UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE] = "Public Signature Key: ";
static const char UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX[UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX[UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX[UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE] = "Root Serial: ";
static const char UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX[UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX[UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX[UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char UDIF_CHILD_CERTIFICATE_VERSION_PREFIX[UDIF_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX[UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE] = "Designation: ";
static const char UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX[UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE] = "Capability Mask: ";
static const char UDIF_CHILD_CERTIFICATE_FOOTER[UDIF_CHILD_CERTIFICATE_FOOTER_SIZE] = "------------END UDIF CHILD PUBLIC CERTIFICATE BLOCK------------";
static const char UDIF_CHILD_CERTIFICATE_DEFAULT_NAME[UDIF_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE] = " Child Certificate";

/** \endcond */

 /** \cond */

#define UDIF_ROOT_CERTIFICATE_HEADER_SIZE 64U
#define UDIF_ROOT_CERTIFICATE_HASH_PREFIX_SIZE 19U
#define UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13U
#define UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define UDIF_ROOT_CERTIFICATE_FOOTER_SIZE 64U
#define UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define UDIF_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define UDIF_ROOT_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE 18U
#define UDIF_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE 18U
#define UDIF_ACTIVE_VERSION_STRING_SIZE 5U

static const char UDIF_ROOT_CERTIFICATE_HEADER[UDIF_ROOT_CERTIFICATE_HEADER_SIZE] = "------------BEGIN UDIF ROOT PUBLIC CERTIFICATE BLOCK-----------";
static const char UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX[UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX[UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX[UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX[UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char UDIF_ROOT_CERTIFICATE_VERSION_PREFIX[UDIF_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char UDIF_ROOT_CERTIFICATE_CAPABILITY_MASK_PREFIX[UDIF_ROOT_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE] = "Capability Mask: ";
static const char UDIF_ROOT_CERTIFICATE_HASH_PREFIX[UDIF_ROOT_CERTIFICATE_HASH_PREFIX_SIZE] = "Certificate Hash: ";
static const char UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX[UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE] = "Public Key: ";
static const char UDIF_ROOT_CERTIFICATE_FOOTER[UDIF_ROOT_CERTIFICATE_FOOTER_SIZE] = "------------END UDIF ROOT PUBLIC CERTIFICATE BLOCK-------------";
static const char UDIF_ROOT_CERTIFICATE_DEFAULT_NAME[UDIF_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE] = " Root Certificate";

static const char UDIF_ACTIVE_VERSION_STRING[UDIF_ACTIVE_VERSION_STRING_SIZE] = "0x01";
static const char UDIF_CERTIFICATE_CHILD_EXTENSION[] = ".ccert";
static const char UDIF_CERTIFICATE_MFCOL_EXTENSION[] = ".mfcol";
static const char UDIF_CERTIFICATE_ROOT_EXTENSION[] = ".rcert";
static const char UDIF_CERTIFICATE_TOPOLOGY_EXTENSION[] = ".dtop";
static const char UDIF_APPLICATION_ROOT_PATH[] = "\\UDIF";
static const char UDIF_CERTIFICATE_BACKUP_PATH[] = "\\Backup";
static const char UDIF_CERTIFICATE_STORE_PATH[] = "\\Certificates";
static const char UDIF_ROOT_CERTIFICATE_PATH[] = "\\Root";
static const char UDIF_CERTIFICATE_TOPOLOGY_PATH[] = "\\Topology";

/** \endcond */

 /*!
 * \struct udif_certificate
 * \brief UDIF entity certificate
 *
 * A certificate binds an entity to its public key and defines its
 * capabilities within the UDIF hierarchy. Certificates are signed by
 * their issuer and form a trust chain from the root authority.
 */
UDIF_EXPORT_API typedef struct udif_certificate
{
	uint8_t signature[UDIF_SIGNED_HASH_SIZE];				/*!< Issuer signature */
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< Public signature key */
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE];				/*!< Certificate serial number */
	uint8_t issuer[UDIF_CERTIFICATE_ISSUER_SIZE];			/*!< Issuer certificate string */
	uint8_t capability[UDIF_CAPABILITY_BITMAP_SIZE];		/*!< Capability bitmap */
	udif_valid_time valid;									/*!< Certificate valid time period */
	uint32_t policy;										/*!< Policy version number */
	udif_roles role;										/*!< Entity role */
	uint8_t suiteid;										/*!< Cryptographic suite identifier */
} udif_certificate;

/*!
* \brief Check capability inheritance
*
* Verifies that child capabilities are a subset of parent capabilities.
*
* \param childbitmap: [const] The child capability bitmap
* \param parentbitmap: [const] The parent capability bitmap
*
* \return Returns true if inheritance is valid
*/
UDIF_EXPORT_API bool udif_certificate_check_capability_inheritance(const uint8_t* childbitmap, const uint8_t* parentbitmap);

/*!
* \brief Serialize a child certificate and compute the digest
*
* Encodes a certificate to canonical format excepting the signature field, and then hashes it.
*
* \param digest: The output digest buffer (32 bytes)
* \param cert: [const] The certificate to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_compute_digest(uint8_t* digest, const udif_certificate* cert);

/*!
* \brief Deserialize a child certificate
*
* Decodes a certificate from canonical format.
*
* \param cert: The output certificate structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_deserialize(udif_certificate* cert, const uint8_t* input, size_t inplen);

/*!
* \brief Sign a child certificate.
*
* \param cert: The input certificate structure
* \param sigkey: [const] The input signature key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_sign(udif_certificate* cert, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Clear a certificate
*
* Zeros out a certificate structure.
*
* \param cert: The certificate to clear
*/
UDIF_EXPORT_API void udif_certificate_clear(udif_certificate* cert);

/*!
* \brief Compare two certificates
*
* Checks if two certificates are identical.
*
* \param a: [const] The first certificate
* \param b: [const] The second certificate
*
* \return Returns true if identical
*/
UDIF_EXPORT_API bool udif_certificate_compare(const udif_certificate* a, const udif_certificate* b);

/*!
* \brief Generate a subordinate certificate
*
* Creates a child certificate signed by a parent certificate. Used for
* Branch Controllers, Group Controllers, and User Agents.
*
* \param cert: The output certificate structure
* \param keypair: The output signature keypair
* \param parentcert: [const] The parent certificate
* \param parentsigkey: [const] The parent's private key
* \param role: The child's role
* \param serial: [const] The certificate serial (16 bytes)
* \param valid: The validity start and end times time (UTC seconds)
* \param capability: [const] The capability bitmap (8 bytes)
* \param policy: The policy version number
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_generate(udif_certificate* cert, udif_signature_keypair* keypair, const udif_certificate* parentcert, 
	const uint8_t* parentsigkey, udif_roles role, const uint8_t* serial, udif_valid_time* valid, const uint8_t* capability, uint32_t policy, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Generate a root certificate
*
* Creates a self-signed root authority certificate. The root is the
* trust anchor for the entire UDIF hierarchy.
* Issuer field is left blank, but can be integrated into the PKI by
* enabling the 
*
* \param cert: The output certificate structure
* \param keypair: The output signature keypair
* \param serial: [const] The certificate serial (16 bytes)
* \param valid: The validity start and end times time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_root_generate(udif_certificate* cert, udif_signature_keypair* keypair, const uint8_t* serial, 
	udif_valid_time* valid, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Check if a certificate is expired
*
* Checks the certificate validity period against current time.
*
* \param cert: [const] The certificate to check
* \param curtime: The current time (UTC seconds)
*
* \return Returns true if expired
*/
UDIF_EXPORT_API bool udif_certificate_is_expired(const udif_certificate* cert, uint64_t curtime);

/*!
* \brief Check if a certificate is valid
*
* Checks both time validity and signature.
*
* \param cert: [const] The certificate to check
* \param issuer: [const] The issuer's root certificate
* \param curtime: The current time (UTC seconds)
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_certificate_is_valid(const udif_certificate* cert, const udif_certificate* issuer, uint64_t curtime);

/*!
* \brief Clear a keypair
*
* Securely erases a keypair structure.
*
* \param keypair: The keypair to clear
*/
UDIF_EXPORT_API void udif_certificate_keypair_clear(udif_signature_keypair* keypair);

/*!
* \brief Serialize a child certificate
*
* Encodes a certificate to canonical format.
*
* \param output: The output buffer
* \param outlen: Pointer to output length (in: buffer size, out: bytes written)
* \param cert: [const] The certificate to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_certificate_serialize(uint8_t* output, size_t outlen, const udif_certificate* cert);

/*!
* \brief Verify a certificate signature
*
* Verifies that a certificate was properly signed by its issuer.
*
* \param cert: [const] The certificate to verify
* \param issuer: [const] The issuer's root certificate
*
* \return Returns true if signature is valid
*/
UDIF_EXPORT_API bool udif_certificate_verify(const udif_certificate* cert, const udif_certificate* issuer);

/*!
* \brief Verify a certificate chain
*
* Verifies a complete chain from subordinate to root.
*
* \param cert: [const] The certificate to verify
* \param issuer: [const] The issuer's root certificate
*
* \return Returns true if chain is valid
*/
UDIF_EXPORT_API bool udif_certificate_verify_chain(const udif_certificate* cert, const udif_certificate* issuer);

#endif
