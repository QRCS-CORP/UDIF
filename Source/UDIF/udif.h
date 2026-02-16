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

#ifndef UDIF_H
#define UDIF_H

#include "udifcommon.h"
#include "sha3.h"
#include "socketbase.h"

#define UDIF_CONFIG_DILITHIUM_KYBER
//#define UDIF_CONFIG_SPHINCS_MCELIECE

#if defined(UDIF_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(UDIF_CONFIG_SPHINCS_MCELIECE)
#	include "mceliece.h"
#	include "sphincsplus.h"
#else
#	error Invalid parameter set!
#endif

/**
 * \file udif.h
 * \brief UDIF Common Definitions and Protocol Configuration.
 *
 * \details
 * This header defines the common constants, macros, enumerations, structures, and function prototypes
 * for the Anonymous Encrypted Relay Network (UDIF). It provides configuration for the cryptographic parameter sets,
 * certificate handling, network protocol operations, and socket communication required to implement the UDIF protocol.
 *
 * The UDIF protocol leverages a combination of asymmetric cipher and signature schemes from the QSC library.
 * The parameter sets can be configured in the QSC library's common.h file. For maximum security, the McEliece/SPHINCS+
 * parameter set is recommended; for a balance of performance and security, the Dilithium/Kyber parameter set is advised.
 *
 * Key components defined in this header include:
 * - **Function Mapping Macros:** Aliases that map UDIF high-level cryptographic operations (key generation,
 *   encapsulation/decapsulation, signing, and verification) to the corresponding functions in the QSC library,
 *   based on the selected configuration.
 * - **Modifiable Constants:** Preprocessor definitions that enable or disable protocol features (e.g., client-to-client
 *   encrypted tunneling, master fragment key cycling, IPv6 networking, and extended session security).
 * - **Parameter Macros:** Definitions for key sizes, certificate field sizes, network settings, and timing values that ensure
 *   consistency across the UDIF protocol implementation.
 * - **Enumerations:** Enumerated types for UDIF configuration sets, network designations, network and protocol error codes,
 *   and version sets.
 * - **Structures:** Data structures representing various certificates (ADC, APS, ROOT), connection and keep alive states,
 *   network packets, and cryptographic key pairs. These structures are central to protocol operations such as certificate
 *   management and secure message exchange.
 * - **Static Constants:** Predefined strings for certificate header/footer information and network designation labels.
 * - **Public API Functions:** Prototypes for functions handling connection management, packet encryption/decryption,
 *   packet serialization/deserialization, and error string conversion.
 *
 * \note
 * When using the McEliece/SPHINCS+ configuration in Visual Studio, it is recommended to increase the maximum stack size
 * (for example, to 200KB) to accommodate the larger key sizes.
 *
 * \test
 * Although this header does not directly implement test routines, it underpins multiple test modules that validate:
 * - The correct mapping of UDIF high-level function calls to the underlying QSC library routines.
 * - The consistency and accuracy of defined constants (e.g., key sizes, certificate sizes, network parameters).
 * - The proper serialization/deserialization of packet headers and full packets (via udif_packet_header_serialize and
 *   udif_stream_to_packet).
 * - The correct conversion of error codes to descriptive strings (using udif_network_error_to_string and
 *   udif_protocol_error_to_string).
 *
 * These tests collectively ensure the robustness, consistency, and security of the UDIF protocol configuration.
 */

 /* Function Mapping Macros */

 /*!
 * \def UDIF_USE_RCS_ENCRYPTION
 * \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
 * The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
 */
#define UDIF_USE_RCS_ENCRYPTION

#if defined(UDIF_USE_RCS_ENCRYPTION)
#	include "rcs.h"
#	define udif_cipher_state qsc_rcs_state
#	define udif_cipher_dispose qsc_rcs_dispose
#	define udif_cipher_initialize qsc_rcs_initialize
#	define udif_cipher_keyparams qsc_rcs_keyparams
#	define udif_cipher_set_associated qsc_rcs_set_associated
#	define udif_cipher_transform qsc_rcs_transform
#else
#	include "aes.h"
#	define udif_cipher_state qsc_aes_gcm256_state
#	define udif_cipher_dispose qsc_aes_gcm256_dispose
#	define udif_cipher_initialize qsc_aes_gcm256_initialize
#	define udif_cipher_keyparams qsc_aes_keyparams
#	define udif_cipher_set_associated qsc_aes_gcm256_set_associated
#	define udif_cipher_transform qsc_aes_gcm256_transform
#endif

/**
 * \brief UDIF function mapping macros.
 *
 * These macros alias the high-level UDIF cryptographic operations to the corresponding QSC library functions.
 * The mapping depends on the selected parameter set. For instance, if UDIF_CONFIG_SPHINCS_MCELIECE is defined,
 * then the UDIF cipher and signature functions map to the McEliece/SPHINCS+ routines. Alternatively, if
 * UDIF_CONFIG_DILITHIUM_KYBER is defined, the corresponding Dilithium/Kyber routines are used.
 */
#if defined(UDIF_CONFIG_SPHINCS_MCELIECE)
	/*!
	 * \def udif_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define udif_cipher_generate_keypair qsc_mceliece_generate_keypair
   /*!
	* \def udif_cipher_decapsulate
	* \brief Decapsulate a shared-secret with the asymmetric cipher
	*/
#	define udif_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def udif_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define udif_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def udif_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define udif_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def udif_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define udif_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def udif_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define udif_signature_verify qsc_sphincsplus_verify
#elif defined(UDIF_CONFIG_DILITHIUM_KYBER)
    /*!
     * \def udif_cipher_generate_keypair
     * \brief Generate an asymmetric cipher key-pair
     */
#	define udif_cipher_generate_keypair qsc_kyber_generate_keypair
    /*!
	 * \def udif_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define udif_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def udif_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define udif_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def udif_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define udif_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def udif_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define udif_signature_sign qsc_dilithium_sign
	/*!
	 * \def udif_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define udif_signature_verify qsc_dilithium_verify
#else
#	error Invalid parameter set!
#endif

/* ### Modifiable Constants: These constants can be enabled to turn on protocol features ### */

/*!
* \def UDIF_NETWORK_PROTOCOL_IPV6
* \brief UDIF is using the IPv6 networking stack.
*/
//#define UDIF_NETWORK_PROTOCOL_IPV6

/* ### End of Modifiable Constants ### */

#if defined(UDIF_CONFIG_DILITHIUM_KYBER)
    /*!
     * \def UDIF_ASYMMETRIC_CIPHERTEXT_SIZE
     * \brief The byte size of the asymmetric cipher-text array.
     */
#	define UDIF_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

   /*!
    * \def UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE
    * \brief The byte size of the asymmetric cipher private-key array.
    */
#	define UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

    /*!
     * \def UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE
     * \brief The byte size of the asymmetric cipher public-key array.
     */
#	define UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

    /*!
	 * \def UDIF_ASYMMETRIC_SIGNATURE_SIZE
	 * \brief The byte size of the asymmetric signature array.
	 */
#	define UDIF_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

	/*!
	 * \def UDIF_ASYMMETRIC_SIGNING_KEY_SIZE
	 * \brief The byte size of the asymmetric signature signing-key array.
	 */
#	define UDIF_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

	/*!
	 * \def UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE
	 * \brief The byte size of the asymmetric signature verification-key array.
	 */
#	define UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_KYBER_S1K2P512)
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D1K1
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D1K1
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 1U
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_KYBER_S3K3P768)
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D3K3
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D3K3
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 2U
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S5K4P1024)
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D5K5
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D5K5
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 3U
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S6K5P1280)
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D5K6
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D5K6
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 4U
#	else
		/* The library signature scheme and asymmetric cipher parameter sets
		must be synchronized to a common security level; s1, s3, s5, s5+ */
#		error the library parameter sets are mismatched!
#	endif

#elif defined(UDIF_CONFIG_SPHINCS_MCELIECE)
	/*!
	* \def UDIF_ASYMMETRIC_CIPHERTEXT_SIZE
	* \brief The byte size of the cipher-text array.
	*/
#	define UDIF_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)
	/*!
	* \def UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE
	* \brief The byte size of the asymmetric cipher private-key array.
	*/
#	define UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)
	/*!
	* \def UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE
	* \brief The byte size of the asymmetric cipher public-key array.
	*/
#	define UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)
	/*!
	* \def UDIF_ASYMMETRIC_SIGNATURE_SIZE
	* \brief The byte size of the asymmetric signature array.
	*/
#	define UDIF_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)
	/*!
	* \def UDIF_ASYMMETRIC_SIGNING_KEY_SIZE
	* \brief The byte size of the asymmetric signature signing-key array.
	*/
#	define UDIF_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)
	/*!
	* \def UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE
	* \brief The byte size of the asymmetric signature verification-key array.
	*/
#	define UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

#	if defined(QSC_MCELIECE_S1N3488T64)&& defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
		/*!
		* \def UDIF_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS
		* \brief The McEliece SF1M1 parameter set
		*/
#		define UDIF_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 5U
#	elif defined(QSC_MCELIECE_S3N4608T96) && defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
		/*!
		* \def UDIF_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS
		* \brief The McEliece SS3M3 parameter set
		*/
#		define UDIF_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 6U
#	elif defined(QSC_MCELIECE_S5N6688T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		/*!
		* \def UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS
		* \brief The McEliece SS5M5 parameter set
		*/
#		define UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 7U
#	elif defined(QSC_MCELIECE_S6N6960T119) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		/*!
		* \def UDIF_PARAMATERS_SPHINCSPLUS_S6S256SHAKERS
		* \brief The McEliece SF5M6 parameter set
		*/
#		define UDIF_PARAMATERS_SPHINCSPLUS_S6S256SHAKERS
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 8U
#	elif defined(QSC_MCELIECE_S7N8192T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		/*!
		* \def UDIF_PARAMATERS_SPHINCSPLUS_S7S256SHAKERS
		* \brief The McEliece SF5M7 parameter set
		*/
#		define UDIF_PARAMATERS_SPHINCSPLUS_S7S256SHAKERS
		/*!
		* \def UDIF_SUITE_ID
		* \brief The suite id.
		*/
#		define UDIF_SUITE_ID 9U
#	else
		/* The library signature scheme and asymmetric cipher parameter sets
		must be synchronized to a common security level; s1, s3, s5 or s6.
		Check the QSC library common.h file for cipher and signature security level alignment. */
#		error Invalid parameter sets, check the QSC library settings
#	endif
#endif


/*! \def UDIF_CAPABILITY_BITMAP_SIZE
 * \brief Capability bitmap size in bytes (64-bit)
 */
#define UDIF_CAPABILITY_BITMAP_SIZE 8U

/*!
 * \def UDIF_CAPABILITY_MASK_SIZE
 * \brief The size of a capability mask in hex characters.
 */
#define UDIF_CAPABILITY_MASK_SIZE 8U

/*!
 * \def UDIF_CAPABILITY_TOKEN_MAX_SIZE
 * \brief The maximum size of a serialized capability token.
 */
#define UDIF_CAPABILITY_TOKEN_MAX_SIZE 2048U

/*!
 * \def UDIF_CLAIM_ANCHOR_SIZE
 * \brief The size of a claim anchor or merkle root in bytes.
 */
#define UDIF_CLAIM_ANCHOR_SIZE 32U

/*!
 * \def UDIF_CRYPTO_HASH_SIZE
 * \brief The size of the certificate hash in bytes.
 */
#define UDIF_CRYPTO_HASH_SIZE 32U

/*!
 * \def UDIF_CRYPTO_KEY_SIZE
 * \brief The byte length of the symmetric cipher key.
 */
#define UDIF_CRYPTO_KEY_SIZE 32U

 /*!
 * \def UDIF_CRYPTO_MAC_SIZE
 * \brief The MAC function output byte size.
 */
#if defined(UDIF_USE_RCS_ENCRYPTION)
#	define UDIF_CRYPTO_MAC_SIZE 32U
#else
#	define UDIF_CRYPTO_MAC_SIZE 16U
#endif

 /*!
  * \def UDIF_CRYPTO_NONCE_SIZE
  * \brief The byte length of the symmetric cipher nonce.
  */
#if defined(UDIF_USE_RCS_ENCRYPTION)
#	define UDIF_CRYPTO_NONCE_SIZE 32U
#else
#	define UDIF_CRYPTO_NONCE_SIZE 16U
#endif

/*!
 * \def UDIF_IDENTITY_ID_SIZE
 * \brief The size of a subject identity identifier in bytes.
 */
#define UDIF_IDENTITY_ID_SIZE 32U

/*!
 * \def UDIF_ISSUER_DOMAIN_CODE_SIZE
 * \brief The size of an issuer domain code (unique identifier).
 */
#define UDIF_ISSUER_DOMAIN_CODE_SIZE 8U

/*!
 * \def UDIF_NAMESPACE_CODE_SIZE
 * \brief The size of a namespace code (short string or numeric).
 */
#define UDIF_NAMESPACE_CODE_SIZE 8U

/*!
 * \def UDIF_PERMISSION_MASK_SIZE
 * \brief The size of a permission mask in bytes.
 */
#define UDIF_PERMISSION_MASK_SIZE 8U

/*!
 * \def UDIF_POLICY_HASH_SIZE
 * \brief The size of a policy identifier hash in bytes.
 */
#define UDIF_POLICY_HASH_SIZE 32U

/*!
 * \def UDIF_POLICY_VERB_SIZE
 * \brief The size of a policy verb in bytes.
 */
#define UDIF_POLICY_VERB_SIZE 4U

/*!
 * \def UDIF_PROTOCOL_SET_SIZE
 * \brief The size of the protocol configuration string.
 */
#define UDIF_PROTOCOL_SET_SIZE 41U

/*!
 * \def UDIF_ROLE_SIZE
 * \brief The UDIF role parameter size.
 */
#define UDIF_ROLE_SIZE 1U

/*!
 * \def UDIF_SERIAL_NUMBER_SIZE
 * \brief The serial number field length.
 */
#define UDIF_SERIAL_NUMBER_SIZE 16U

/*!
 * \def UDIF_SIGNED_HASH_SIZE
 * \brief The combined size of a signature and hash.
 */
#define UDIF_SIGNED_HASH_SIZE (UDIF_ASYMMETRIC_SIGNATURE_SIZE + UDIF_CRYPTO_HASH_SIZE)

/*!
 * \def UDIF_SUITEID_SIZE
 * \brief The UDIF suite id parameter size.
 */
#define UDIF_SUITEID_SIZE 1U

/*!
 * \def UDIF_TIME_WINDOW_SECONDS
 * \brief The query time window seconds.
 */
#define UDIF_TIME_WINDOW_SECONDS 60U

/*!
 * \def UDIF_CERIFICATE_VALID_TIME_SIZE
 * \brief The byte size of the serialized certificate time parameter.
 */
#define UDIF_VALID_TIME_SIZE 8U

/*!
 * \def UDIF_VALID_TIME_STRUCTURE_SIZE
 * \brief The certificate expiration date length.
 */
#define UDIF_VALID_TIME_STRUCTURE_SIZE 16U

/* UDIF Enumerations */

/*!
 * \enum udif_claim_type
 * \brief Claim type identifiers (deterministic canonicalization required).
 */
typedef enum udif_claim_type
{
	udif_claim_unknown = 0U,					/*!< Unspecified claim type */
	udif_claim_commodity_id = 1U,				/*!< Commodity/asset identifier */
	udif_claim_biometric_hash = 2U,				/*!< Biometric template hash */
	udif_claim_institution_id = 3U,				/*!< Institutional ID / account */
	udif_claim_public_key = 4U,					/*!< Subjects public key / fingerprint */
	udif_claim_age_over = 5U,					/*!< Age threshold proof (boolean) */
	udif_claim_citizenship = 6U,				/*!< Country citizenship assertion */
	udif_claim_residency = 7U,					/*!< Residency assertion */
	udif_claim_membership_id = 8U,				/*!< Membership/affiliation identifier */
	udif_claim_contact_email = 9U,				/*!< Email address (validated form) */
	udif_claim_contact_phone = 10U,				/*!< Phone (E.164 normalized) */
	udif_claim_address = 11U,					/*!< Postal/civic address (normalized) */
	udif_claim_custom = 12U						/*!< Implementation-specific/custom */
} udif_claim_type;

/*!
 * \enum udif_configuration_sets
 * \brief The UDIF algorithm configuration sets.
 */
typedef enum udif_configuration_sets
{
	udif_configuration_set_none = 0x00U,										/*!< No algorithm identifier is set */
	udif_configuration_set_dilithium1_kyber1_rcs256_shake256 = 0x01U,			/*!< The Dilithium-S1/Kyber-S1/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium3_kyber3_rcs256_shake256 = 0x02U,			/*!< The Dilithium-S3/Kyber-S3/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium5_kyber5_rcs256_shake256 = 0x03U,			/*!< The Dilithium-S5/Kyber-S5/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium5_kyber6_rcs512_shake256 = 0x04U,			/*!< The Dilithium-S5/Kyber-S6/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus1_mceliece1_rcs256_shake256 = 0x05U,		/*!< The SPHINCS+-S1/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus3_mceliece3_rcs256_shake256 = 0x06U,		/*!< The SPHINCS+-S3/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5_mceliece5_rcs256_shake256 = 0x07U,		/*!< The SPHINCS+-S5/McEliece-S5/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5_mceliece6_rcs256_shake256 = 0x08U,		/*!< The SPHINCS+-S6/McEliece-S6/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5_mceliece7_rcs256_shake256 = 0x09U,		/*!< The SPHINCS+-S7/McEliece-S7/RCS-256/SHAKE-256 algorithm set */
} udif_configuration_sets;

#if defined(UDIF_PARAMATERS_DILITHIUM_KYBER_D1K1)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "dilithium-s1_kyber-s1_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_dilithium1_kyber1_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_DILITHIUM_KYBER_D3K3)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "dilithium-s3_kyber-s3_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_dilithium3_kyber3_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_DILITHIUM_KYBER_D5K5)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s5_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_dilithium5_kyber5_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_DILITHIUM_KYBER_D5K6)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s6_rcs-512_sha3-512";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_dilithium5_kyber6_rcs512_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-s1_mceliece-s1_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus1_mceliece1_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-s3_mceliece-s3_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus3_mceliece3_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-s5_mceliece-s5_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5_mceliece5_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S6S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-s5_mceliece-s6_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5_mceliece6_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S7S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-s5_mceliece-s7_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5_mceliece7_rcs256_shake256;
#else
#	error Invalid parameter set!
#endif

/*!
* \enum udif_errors
* \brief UDIF error codes
*/
typedef enum udif_errors
{
	udif_error_none = 0U,						/*!< No error */
	udif_error_invalid_input = 1U,				/*!< Invalid input parameter */
	udif_error_invalid_state = 2U,				/*!< Invalid state */
	udif_error_auth_failure = 3U,				/*!< Authentication failed */
	udif_error_certificate_expired = 4U,		/*!< Certificate expired */
	udif_error_certificate_revoked = 5U,		/*!< Certificate revoked */
	udif_error_capability_revoked = 6U,			/*!< Capability revoked */
	udif_error_invalid_sequence = 7U,			/*!< Invalid sequence number */
	udif_error_time_window = 8U,				/*!< Time window exceeded */
	udif_error_epoch_mismatch = 9U,				/*!< Epoch mismatch */
	udif_error_suite_mismatch = 10U,			/*!< Suite mismatch */
	udif_error_decode_failure = 11U,			/*!< Decode failure */
	udif_error_encode_failure = 12U,			/*!< Encode failure */
	udif_error_signature_invalid = 13U,			/*!< Invalid signature */
	udif_error_mac_invalid = 14U,				/*!< Invalid MAC */
	udif_error_not_authorized = 15U,			/*!< Not authorized */
	udif_error_object_not_found = 16U,			/*!< Object not found */
	udif_error_registry_full = 17U,				/*!< Registry full */
	udif_error_logging_failure = 18U,			/*!< Log operation failed */
	udif_error_anchor_invalid = 19U,			/*!< Invalid anchor record */
	udif_error_treaty_invalid = 20U,			/*!< Invalid treaty */
	udif_error_invalid_request = 21U,			/*!< Invalid request */
	udif_error_internal = 22U,					/*!< Internal error */
	udif_error_file_create_failed = 23U,		/*!< File creation failed */
	udif_error_file_not_found = 24U,			/*!< File not found */
	udif_error_invalid_parameter = 25U			/*!< Invalid parameter */
} udif_errors;

/*!
 * \enum udif_error_capability
 * \brief Capability/permission evaluation errors.
 */
typedef enum udif_error_capability
{
	udif_ecap_none = 0U,						/*!< No error */
	udif_ecap_denied = 1U,						/*!< Capability denied by policy */
	udif_ecap_mask_empty = 2U,					/*!< Empty/zero capability mask */
	udif_ecap_mask_conflict = 3U				/*!< Conflicting capability bits */
} udif_error_capability;

/*!
 * \enum udif_error_claims
 * \brief Claim/claim-set error codes.
 */
typedef enum udif_error_claims
{
	udif_ecl_none = 0U,							/*!< No error */
	udif_ecl_type_unknown = 1U,					/*!< Unknown claim type */
	udif_ecl_encoding_bad = 2U,					/*!< Bad/unsupported encoding */
	udif_ecl_canonical_fail = 3U,				/*!< Canonicalization failed */
	udif_ecl_anchor_bad = 4U,					/*!< Anchor/merkle root mismatch */
	udif_ecl_value_invalid = 5U					/*!< Claim value invalid/out of range */
} udif_error_claims;

/*!
 * \enum udif_error_encoding
 * \brief Encoding/decoding errors for UDIF objects.
 */
typedef enum udif_error_encoding
{
	udif_eenc_none = 0U,						/*!< No error */
	udif_eenc_overflow = 1U,					/*!< Buffer overflow/size mismatch */
	udif_eenc_underflow = 2U,					/*!< Buffer underflow/truncation */
	udif_eenc_format = 3U,						/*!< Bad format/version */
	udif_eenc_unsupported = 4U					/*!< Unsupported encoding */
} udif_error_encoding;

/*!
 * \enum udif_error_identity
 * \brief Identity-specific error codes.
 */
typedef enum udif_error_identity
{
	udif_eid_none = 0U,							/*!< No error */
	udif_eid_namespace_bad = 1U,				/*!< Invalid namespace code */
	udif_eid_issuer_bad = 2U,					/*!< Invalid issuer domain code */
	udif_eid_subject_bad = 3U,					/*!< Invalid subject identifier */
	udif_eid_mask_invalid = 4U,					/*!< Capability/permission mask invalid */
	udif_eid_anchor_mismatch = 5U,				/*!< Claim anchor does not match claims */
	udif_eid_sig_invalid = 6U,					/*!< Signature verification failed */
	udif_eid_expired = 7U,						/*!< Identity validity expired */
	udif_eid_future = 8U						/*!< Identity not yet valid */
} udif_error_identity;

/*!
 * \enum udif_error_policy
 * \brief Policy evaluation/lookup errors.
 */
typedef enum udif_error_policy
{
	udif_epol_none = 0U,						/*!< No error */
	udif_epol_not_found = 1U,					/*!< Policy not found */
	udif_epol_hash_mismatch = 2U,				/*!< Policy hash mismatch */
	udif_epol_indeterminate = 3U				/*!< Evaluation indeterminate */
} udif_error_policy;

/*!
* \enum udif_logging_event_codes
* \brief Membership and transaction log event codes
*/
typedef enum udif_logging_event_codes
{
	udif_event_enroll = 1U,						/*!< Entity enrollment */
	udif_event_suspend = 2U,					/*!< Entity suspension */
	udif_event_resume = 3U,						/*!< Entity resumption */
	udif_event_revoke = 4U,						/*!< Entity revocation */
	udif_event_capability_grant = 5U,           /*!< Capability grant */
	udif_event_capability_revoke = 6U,          /*!< Capability revocation */
	udif_event_registry_commit = 7U,			/*!< Registry commit */
	udif_event_branch_create = 8U,				/*!< Branch creation */
	udif_event_branch_suspend = 9U,				/*!< Branch suspension */
	udif_event_branch_revoke = 10U,				/*!< Branch revocation */
	udif_event_object_create = 11U,				/*!< Object creation */
	udif_event_object_transfer = 12U,			/*!< Object transfer */
	udif_event_object_update = 13U,				/*!< Object update */
	udif_event_object_destroy = 14U				/*!< Object destruction */
} udif_logging_event_codes;

/*!
 * \enum udif_permission_class
 * \brief Permission classes whose bits populate the permission mask.
 */
typedef enum udif_permission_class
{
	udif_perm_read_claims = 0U,					/*!< Read subject claims */
	udif_perm_write_claims = 1U,				/*!< Write/update subject claims */
	udif_perm_read_certs = 2U,					/*!< Read certificates/CRLs */
	udif_perm_write_certs = 3U,					/*!< Create/update certificates/CRLs */
	udif_perm_manage_policy = 4U,				/*!< Manage policy/validation parameters */
	udif_perm_manage_caps = 5U,					/*!< Grant/revoke capabilities */
	udif_perm_delegate = 6U,					/*!< Delegate permission subsets */
	udif_perm_export_identity = 7U,				/*!< Export identities/tokens */
	udif_perm_import_identity = 8U				/*!< Import identities/tokens */
} udif_permission_class;

/*!
 * \enum udif_policy_decision
 * \brief Policy evaluation outcome.
 */
typedef enum udif_policy_decision
{
	udif_policy_permit = 0U,					/*!< Permit */
	udif_policy_deny = 1U,						/*!< Deny */
	udif_policy_indeterminate = 2U,				/*!< Evaluation failed (error) */
	udif_policy_not_applicable = 3U				/*!< No matching rule */
} udif_policy_decision;

/*!
* \enum udif_roles
* \brief UDIF entity roles
*/
typedef enum udif_roles
{
	udif_role_none = 0U,						/*!< No role specified */
	udif_role_root = 1U,						/*!< Root authority */
	udif_role_udc = 2U,							/*!< Domain controller */
	udif_role_uip = 3U,							/*!< Identity provider role */
	udif_role_uis = 4U,							/*!< Identity server role */
	udif_role_client = 5U,						/*!< Client role */
	udif_role_audit = 6U,						/*!< Auditor role */
	udif_role_revoked = 7U,						/*!< Authority revoked for this entity */
	udif_role_any = 8U,							/*!< Entity has any priveledge */
} udif_roles;

/*!
 * \enum udif_time_validation
 * \brief Results of time/validity-window checks.
 */
typedef enum udif_time_validation
{
	udif_time_valid = 0U,						/*!< Within window */
	udif_time_future = 1U,						/*!< Not yet valid */
	udif_time_expired = 2U,						/*!< Expired */
	udif_time_skew_exceeds = 3U					/*!< Exceeds allowed clock skew */
} udif_time_validation;

/*!
 * \enum udif_token_type
 * \brief Token families issued/validated within UDIF.
 */
typedef enum udif_token_type
{
	udif_token_none = 0U,						/*!< Not a token */
	udif_token_capability = 1U,					/*!< Capability token (authZ) */
	udif_token_attestation = 2U,				/*!< Attestation token (statement + signature) */
	udif_token_session = 3U						/*!< Session/resumption ticket (envelope optional) */
} udif_token_type;

/*!
 * \enum udif_status
 * \brief Generic status codes for UDIF operations.
 */
typedef enum udif_status
{
	udif_status_success = 0U,					/*!< Operation succeeded */
	udif_status_invalid_argument = 1U,			/*!< Bad input parameter(s) */
	udif_status_not_found = 2U,					/*!< Object not found */
	udif_status_already_exists = 3U,			/*!< Duplicate object */
	udif_status_out_of_memory = 4U,				/*!< Allocation failed */
	udif_status_buffer_too_small = 5U,			/*!< Output buffer too small */
	udif_status_not_supported = 6U,				/*!< Feature not supported */
	udif_status_internal_error = 7U				/*!< Internal/unknown error */
} udif_status;

/*!
 * \enum udif_verify_policy
 * \brief Verification strictness for identity/cert/claim checks.
 */
typedef enum udif_verify_policy
{
	udif_verify_strict = 0U,					/*!< All checks required (fail-closed) */
	udif_verify_lenient = 1U					/*!< Allow missing non-critical fields (fail-open subset) */
} udif_verify_policy;

/*!
 * \enum udif_version_sets
 * \brief The UDIF version sets.
 */
typedef enum udif_version_sets
{
	udif_version_set_none = 0x00U,				/*!< No version identifier is set */
	udif_version_set_one_zero = 0x01U,			/*!< The 1.0 version identifier */
} udif_version_sets;

/** \cond NO_DOCUMENT */

/*! \def UDIF_VERSION_STRING
 * \brief UDIF implementation version string
 */
#define UDIF_VERSION_STRING "UDIF:1.0a"

/*! \def UDIF_SUITE_STRING
 * \brief Cryptographic suite identifier
 */
#define UDIF_SUITE_STRING "UDIF:RCS256-KMAC256-MLKEM5-MLDSA5"

/* Domain Separation Labels */

/*! \def UDIF_LABEL_MAX_SIZE
* \brief Maximum domain separation label size
*/
#define UDIF_LABEL_MAX_SIZE 64U

/* Domain separation label constants */
#define UDIF_LABEL_OBJ_DIGEST    "UDIF:OBJ-DIGEST:V1"
#define UDIF_LABEL_REGROOT       "UDIF:REGROOT:V1"
#define UDIF_LABEL_TXID          "UDIF:TXID:V1"
#define UDIF_LABEL_ANCHOR        "UDIF:ANCHOR:V1"
#define UDIF_LABEL_CAP_DIGEST    "UDIF:CAP-DIGEST:V1"
#define UDIF_LABEL_SESS_KDF      "UDIF:SESS-KDF:V1"
#define UDIF_LABEL_RATCHET       "UDIF:RATCHET:V1"
#define UDIF_LABEL_CERT_DIGEST   "UDIF:CERT-DIGEST:V1"
#define UDIF_LABEL_ROOT_DIGEST   "UDIF:ROOT-DIGEST:V1"

 /** \endcond NO_DOCUMENT */

/* Role/Designation Strings */

/** \cond NO_DOCUMENT */

/*!
 * \def UDIF_ERROR_STRING_DEPTH
 * \brief Number of entries per error string table.
 */
#define UDIF_ERROR_STRING_DEPTH 27U

/*!
 * \def UDIF_ERROR_STRING_SIZE
 * \brief Maximum size of an error string.
 */
#define UDIF_ERROR_STRING_SIZE 128U

/* Protocol errors*/

static const char UDIF_ERROR_STRINGS[UDIF_ERROR_STRING_DEPTH][UDIF_ERROR_STRING_SIZE] =
{
	"No error condition",
	"Invalid input parameter",
	"Invalid function state",
	"Authentication failed",
	"The certificate expired",
	"The certificate has been revoked",
	"The capability has been revoked",
	"Invalid sequence number",
	"The time window has been exceeded",
	"Epoch time mismatch",
	"Protocol suite mismatch",
	"Decoding failure",
	"Encoding failure",
	"Invalid signature",
	"Invalid MAC",
	"Not authorized",
	"Object not found",
	"Registry full",
	"Log operation failed",
	"Invalid anchor record",
	"Invalid treaty",
	"Invalid request",
	"Internal error",
	"File creation failed",
	"File not found",
	"Invalid parameter",
	"Unknown error type"
};

/* Certificate errors */
static const char UDIF_CERTIFICATE_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Unknown certificate type",
	"Bad or unknown serial number",
	"Invalid certificate chain",
	"Signature invalid",
	"Certificate expired",
	"Certificate not yet valid",
	"Policy hash mismatch",
	"Certificate revoked"
};

/* Claims errors */
static const char UDIF_CLAIMS_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Unknown claim type",
	"Invalid encoding",
	"Canonicalization failed",
	"Anchor mismatch",
	"Invalid claim value"
};

/* Encoding errors */
static const char UDIF_ENCODING_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Buffer overflow",
	"Buffer underflow",
	"Bad format/version",
	"Unsupported encoding"
};

/* Identity errors */
static const char UDIF_IDENTITY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Invalid namespace code",
	"Invalid issuer domain code",
	"Invalid subject identifier",
	"Capability/permission mask invalid",
	"Claim anchor mismatch",
	"Signature verification failed",
	"Identity expired",
	"Identity not yet valid"
};

/* Policy errors */
static const char UDIF_POLICY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Policy not found",
	"Policy hash mismatch",
	"Policy evaluation indeterminate"
};

#define UDIF_ROLE_STRING_SIZE 32U

static const char UDIF_ROLE_STRINGS[][UDIF_ROLE_STRING_SIZE] =
{
	"udif_role_none",
	"udif_role_udc",
	"udif_role_uip",
	"udif_role_uis",
	"udif_role_client",
	"udif_role_audit",
	"udif_role_revoked",
	"udif_role_any"
};

/** \endcond NO_DOCUMENT */

/* UDIF Structures */

/*!
 * \struct udif_capability_mask
 * \brief Fixed-size capability bitset (issuer-/role-scoped).
 * Capability bits; bit positions map to udif_capability_id
 */
UDIF_EXPORT_API typedef struct udif_capability_mask
{
	uint8_t bits[UDIF_CAPABILITY_MASK_SIZE];				/*!< The capability mask bits */
} udif_capability_mask;

/*!
 * \struct udif_claim
 * \brief A typed claim with deterministic canonical encoding.
 */
UDIF_EXPORT_API typedef struct udif_claim
{
	udif_claim_type type;									/*!< Claim type identifier */
	const uint8_t* value;									/*!< Pointer to claim value (external storage) */
	uint32_t length;										/*!< Length of claim value in bytes */
} udif_claim;

/*!
 * \struct udif_claim_anchor
 * \brief Anchor (e.g., Merkle root) binding a claim set to an identity.
 * Anchor/merkle root over canonical claim set
 */
UDIF_EXPORT_API typedef struct udif_claim_anchor
{
	uint8_t bytes[UDIF_CLAIM_ANCHOR_SIZE];
} udif_claim_anchor;

/*!
 * \struct udif_claim_set
 * \brief A collection of claims bound to an identity by an anchor.
 */
UDIF_EXPORT_API typedef struct udif_claim_set
{
	const udif_claim* items;                                /*!< Pointer to claim array (external storage) */
	uint32_t count;											/*!< Number of claims in the set */
	udif_claim_anchor anchor;                               /*!< Anchor/merkle root over canonicalized claims */
} udif_claim_set;

/*!
 * \struct udif_encoded_blob
 * \brief Generic encoded object buffer (for decode/encode APIs).
 */
UDIF_EXPORT_API typedef struct udif_encoded_blob
{
	uint8_t* bytes;                                         /*!< Pointer to external buffer */
	uint32_t size;                                          /*!< Allocated buffer size */
	uint32_t length;                                        /*!< Actual data length after (en|de)code */
} udif_encoded_blob;

/*!
 * \struct udif_identity_id
 * \brief Subject identity identifier (opaque, canonicalized).
 * Subject identifier bytes
 */
UDIF_EXPORT_API typedef struct udif_identity_id
{
	uint8_t bytes[UDIF_IDENTITY_ID_SIZE];					/*!< The identity byte array */
} udif_identity_id;

/*!
 * \struct udif_issuer_domain_code
 * \brief Issuer domain/controller identifier.
 * Issuer domain code (ASCII or compact code)
 */
UDIF_EXPORT_API typedef struct udif_issuer_domain_code
{
	uint8_t bytes[UDIF_ISSUER_DOMAIN_CODE_SIZE];			/*!< The issuer domain code byte array */
} udif_issuer_domain_code;

/*!
* \struct udif_kem_keypair
* \brief KEM key pair
*
* Contains a public/private key pair for Kyber KEM.
*/
UDIF_EXPORT_API typedef struct udif_kem_keypair
{
	uint8_t pubkey[UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE];		/*!< public encapsulation key */
	uint8_t prikey[UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE];		/*!< private decapsulation key */
} udif_kem_keypair;

/*!
 * \struct udif_namespace_code
 * \brief Namespace partition identifier.
 * Namespace code (ASCII or compact code)
 */
UDIF_EXPORT_API typedef struct udif_namespace_code
{
	uint8_t bytes[UDIF_NAMESPACE_CODE_SIZE];				/*!< The namespace code array */
} udif_namespace_code;

/*!
 * \struct udif_permission_mask
 * \brief Fixed-size permission bitset (subject-/resource-scoped).
 * Permission bits; bit positions map to udif_permission_class
 */
UDIF_EXPORT_API typedef struct udif_permission_mask
{
	uint8_t bits[UDIF_PERMISSION_MASK_SIZE];				/*!< The permission mask bits array */
} udif_permission_mask;

/*!
 * \struct udif_policy_hash
 * \brief Policy identifier (hash of canonical policy).
 * SHA3/SHAKE hash of policy document
 */
UDIF_EXPORT_API typedef struct udif_policy_hash
{
	uint8_t bytes[UDIF_POLICY_HASH_SIZE];					/*!< The policy hash bytes */
} udif_policy_hash;

/*!
 * \struct udif_signature_keypair
 * \brief The UDIF asymmetric signature scheme key container.
 */
UDIF_EXPORT_API typedef struct udif_signature_keypair
{
	uint8_t sigkey[UDIF_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The secret signing key */
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< The public signature verification key */
} udif_signature_keypair;

/*!
 * \struct udif_time_window
 * \brief A validity interval expressed in UTC seconds.
 */
UDIF_EXPORT_API typedef struct udif_time_window
{
	uint64_t before;										/*!< Start of validity window (epoch seconds) */
	uint64_t after;											/*!< End of validity window (epoch seconds) */
} udif_time_window;

/*!
 * \struct udif_token_header
 * \brief Common header for UDIF tokens (capability/attestation/session).
 */
UDIF_EXPORT_API typedef struct udif_token_header
{
	udif_token_type ttype;									/*!< Token type */
	udif_namespace_code nspace;								/*!< Namespace code */
	udif_issuer_domain_code issuer;                         /*!< Issuer domain code */
	udif_time_window validity;                              /*!< Token validity window */
} udif_token_header;

/*!
 * \struct udif_token
 * \brief Serialized token container with optional envelope protection.
 *
 * \details
 * If kem != udif_kem_none, the payload is a KEM-enveloped blob; otherwise
 * it is plaintext with a signature/MAC, depending on policy.
 */
UDIF_EXPORT_API typedef struct udif_token
{
	uint8_t signature[UDIF_ASYMMETRIC_SIGNATURE_SIZE];		/*!< Issuer signature over token */
	uint8_t payload[UDIF_CAPABILITY_TOKEN_MAX_SIZE];		/*!< Serialized payload (claims subset, attestations, etc.) */
	uint8_t chash[UDIF_CRYPTO_HASH_SIZE];					/*!< Canonical token hash */
	udif_token_header head;                                 /*!< Common token header */
	udif_identity_id subject;                               /*!< Subject to whom the token applies */
	udif_capability_mask caps;                              /*!< Capabilities conveyed (if applicable) */
	udif_permission_mask perms;                             /*!< Permissions conveyed (if applicable) */
	uint32_t paylen;										/*!< Payload length in bytes */
} udif_token;

/*!
 * \struct udif_valid_time
 * \brief The certificate expiration time structure.
 */
UDIF_EXPORT_API typedef struct udif_valid_time
{
	uint64_t from;											/*!< The starting time in seconds */
	uint64_t to;											/*!< The expiration time in seconds */
} udif_valid_time;

/*!
 * \struct udif_identity_record
 * \brief Core identity record bound to a namespace and issuer.
 *
 * \details
 * Serves as the canonical subject descriptor used for verification, policy
 * evaluation, and token issuance.
 */
UDIF_EXPORT_API typedef struct udif_identity_record
{
	udif_namespace_code nspace;								/*!< Namespace code */
	udif_issuer_domain_code issuer;                         /*!< Issuer domain code */
	udif_identity_id subject;								/*!< Subject identifier */
	udif_time_window validity;								/*!< Validity window */
	udif_permission_mask perms;                             /*!< Subject permission mask */
	udif_capability_mask caps;                              /*!< Capabilities granted to the subject */
	udif_policy_hash policy;								/*!< Policy hash applied to this identity */
	udif_claim_anchor anchor;								/*!< Anchor binding claims to identity */
	uint8_t signature[UDIF_ASYMMETRIC_SIGNATURE_SIZE];		/*!< Issuer signature over identity record */
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< Subject verification key (if key-bearing id) */
	uint8_t chash[UDIF_CRYPTO_HASH_SIZE];					/*!< Canonical record hash */
} udif_identity_record;

/**
* \brief Check if the suite id valid.
*
* \param suiteid The suite id.
*
* \return Returns true if the suite id is valid.
*/
UDIF_EXPORT_API bool udif_suite_is_valid(uint8_t suiteid);

/**
* \brief Convert an error to a string.
*
* \param error The error enumerator.
*
* \return Returns the errors string representation.
*/
UDIF_EXPORT_API const char* udif_error_to_string(udif_errors error);

#endif
