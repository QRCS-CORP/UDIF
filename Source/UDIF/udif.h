/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
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

/**
* \file udif.h
* \brief UDIF Common Definitions and Core Library Configuration.
* 
* \details
* This header defines the common constants, macros, enumerations, structures, and public API prototypes
* for the Universal Digital Identity Framework (UDIF). It provides the core library configuration used by
* UDIF components (controllers, proxies, institutional servers, and clients), including certificate and claim
* handling, capability tokens, identity encoding, permission masks, and secure transport primitives sourced
* from the QSC library.
* 
* UDIF composes standardized post-quantum asymmetric schemes with SHAKE-based hashing/KDF and an AEAD stream
* cipher for confidentiality and integrity. Algorithm families are selected through build-time configuration,
* mapping UDIF high-level operations (key generation, encapsulation/decapsulation, signing, verification,
* hashing, KDF, AEAD) to corresponding QSC library implementations. This style follows the MPDC design pattern
* (function-mapping macros, configurable parameter sets, and protocol-wide constants) to ensure portability
* across deployments and security levels.
* 
* Key elements defined in this header include:
* Function-Mapping Macros: Aliases that bind UDIF cryptographic operations (KEM, signature, hash/KDF, AEAD)
* to QSC implementations selected via compile-time parameter sets.
* Modifiable Constants: Preprocessor options to enable/disable library features (e.g., certificate
* extensions, epoch/valid-time enforcement, extended MAC length, strict claim validation, IPv6).
* Parameter Macros: Canonical byte lengths and field sizes for identities, serials, certificate fields,
* capability tokens, claim encodings, network packet framing, timing windows, and maximum message sizes.
* Enumerations: Configuration sets, entity designations (UDC, UIP, UIS, Client), error/status codes for
* library and protocol operations, certificate and claim types, capability and permission classes, and versioning.
* Structures: Root, domain, and entity certificates; identity descriptors; capability/permission masks;
* claim sets; encoded identity blobs; network packet headers; and cipher/key parameter aggregates.
* Static Constants: Canonical strings (PEM-like headers/footers), OID/label tags, human-readable error text,
* and curve/parameter labels aligned to the active configuration set.
* 
* Public API Prototypes: Core routines for certificate/claim encode-decode, identity/capability validation,
* token issue/verify, packet header (de)serialization and time-window checks, AEAD context management, and
* error-to-string conversion.
* 
* \note
* UDIF builds on a shared common header for export macros, debug asserts, and compiler/visibility control.
* Include udifcommon.h prior to using this header in all translation units.
* 
* \section udif_rationale Design Rationale and Parity with MPDC
* UDIF adopts the MPDC header organization to maximize reuse and consistency across projects:
* function-mapping macros for cryptographic agility; tightly scoped, centrally defined size
* constants; strict packet header format with time-validity windows; and compact error enums
* with string tables. Implementations SHOULD mirror MPDC's packet-associated-data practice
* (adding serialized headers as AEAD associated data) and sequence/time checks when applicable
* to UDIF transport wrappers.
* 
* \test
* Although this header does not implement tests, it underpins modules that validate:
* Correct mapping of UDIF high-level calls to QSC routines and parameter sets.
* Consistency of field/size constants for identities, certificates, claims, and tokens.
* Deterministic (de)serialization of headers, certificates, capabilities, and claims.
* Enforcement of sequence and UTC valid-time windows in packet prechecks.
* Accurate conversion of error/status codes to diagnostic strings.
* These tests collectively ensure correctness, robustness, and cryptographic soundness of the UDIF core library.
*/

#ifndef UDIF_H
#define UDIF_H

#include "udifcommon.h"

#include "udifcommon.h"
#include "sha3.h"
#include "socketbase.h"

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

  ///*!
  // * \def UDIF_NETWORK_CLIENT_CONNECT
  // * \brief Enable client to client encrypted tunnel.
  // */
  //#define UDIF_NETWORK_CLIENT_CONNECT

  ///*!
  // * \def UDIF_NETWORK_MFK_HASH_CYCLED
  // * \brief Enable mfk key cycling (default).
  // */
  //#define UDIF_NETWORK_MFK_HASH_CYCLED

  /*!
   * \def UDIF_NETWORK_PROTOCOL_IPV6
   * \brief UDIF is using the IPv6 networking stack.
   */
   //#define UDIF_NETWORK_PROTOCOL_IPV6

   ///*!
   // * \def UDIF_EXTENDED_SESSION_SECURITY
   // * \brief Enable 512-bit security on session tunnels.
   // */
   //#define UDIF_EXTENDED_SESSION_SECURITY

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
		* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
		* \brief The encoded certificate string length
		*/
#		define UDIF_CHILD_CERTIFICATE_STRING_SIZE 5630U
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D1K1
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D1K1
		/*!
		* \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
		* \brief The root certificate encoded string size
		*/
#		define UDIF_ROOT_CERTIFICATE_STRING_SIZE 2188U
		/*!
		* \def UDIF_SIGNATURE_ENCODING_SIZE
		* \brief The encoded signature size
		*/
#		define UDIF_SIGNATURE_ENCODING_SIZE 3312U
		/*!
		* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
		* \brief The verification key size
		*/
#		define UDIF_VERIFICATION_KEY_ENCODING_SIZE 1752U
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_KYBER_S3K3P768)
		/*!
		* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
		* \brief The encoded certificate string length
		*/
#		define UDIF_CHILD_CERTIFICATE_STRING_SIZE 7666U
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D3K3
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D3K3
		/*!
		* \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
		* \brief The root certificate encoded string size
		*/
#		define UDIF_ROOT_CERTIFICATE_STRING_SIZE 3053U
		/*!
		* \def UDIF_SIGNATURE_ENCODING_SIZE
		* \brief The encoded signature size
		*/
#		define UDIF_SIGNATURE_ENCODING_SIZE 4476U
		/*!
		* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
		* \brief The verification key size
		*/
#	define UDIF_VERIFICATION_KEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S5K4P1024)
		/*!
		* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
		* \brief The encoded certificate string length
		*/
#		define UDIF_CHILD_CERTIFICATE_STRING_SIZE 10327U
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D5K5
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D5K5
		/*!
		* \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
		* \brief The root certificate encoded string size
		*/
#		define UDIF_ROOT_CERTIFICATE_STRING_SIZE 3919U
		/*!
		* \def UDIF_SIGNATURE_ENCODING_SIZE
		* \brief The encoded signature size
		*/
#		define UDIF_SIGNATURE_ENCODING_SIZE 6212U
		/*!
		* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
		* \brief The verification key size
		*/
#		define UDIF_VERIFICATION_KEY_ENCODING_SIZE 3456U
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S6K5P1280)
		/*!
		* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
		* \brief The encoded certificate string length
		*/
#		define UDIF_CHILD_CERTIFICATE_STRING_SIZE 10327U
		/*!
		* \def UDIF_PARAMATERS_DILITHIUM_KYBER_D5K6
		* \brief The Dilithium D1K1 parameter set
		*/
#		define UDIF_PARAMATERS_DILITHIUM_KYBER_D5K6
		/*!
		* \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
		* \brief The root certificate encoded string size
		*/
#		define UDIF_ROOT_CERTIFICATE_STRING_SIZE 3919U
		/*!
		* \def UDIF_SIGNATURE_ENCODING_SIZE
		* \brief The encoded signature size
		*/
#		define UDIF_SIGNATURE_ENCODING_SIZE 6172U
		/*!
		* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
		* \brief The verification key size
		*/
#		define UDIF_VERIFICATION_KEY_ENCODING_SIZE 3456U
#	else
		/* The library signature scheme and asymmetric cipher parameter sets
		must be synchronized to a common security level; s1, s3, s5, s5+ */
#		error the library parameter sets are mismatched!
#	endif

#	elif defined(UDIF_CONFIG_SPHINCS_MCELIECE)
		/*!
		 * \def UDIF_ASYMMETRIC_CIPHERTEXT_SIZE
		 * \brief The byte size of the cipher-text array.
		 */
#		define UDIF_ASYMMETRIC_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)
		/*!
		 * \def UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE
		 * \brief The byte size of the asymmetric cipher private-key array.
		 */
#		define UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)
		/*!
		* \def UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE
		* \brief The byte size of the asymmetric cipher public-key array.
		*/
#		define UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)
		/*!
		* \def UDIF_ASYMMETRIC_SIGNATURE_SIZE
		* \brief The byte size of the asymmetric signature array.
		*/
#		define UDIF_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)
		/*!
		* \def UDIF_ASYMMETRIC_SIGNING_KEY_SIZE
		* \brief The byte size of the asymmetric signature signing-key array.
		*/
#		define UDIF_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)
		/*!
		* \def UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE
		* \brief The byte size of the asymmetric signature verification-key array.
		*/
#		define UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

#	if defined(QSC_MCELIECE_S1N3488T64)
#		if defined(QSC_SPHINCSPLUS_S1S128SHAKERF)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 23753U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SF1M1
			* \brief The McEliece SF1M1 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF1M1
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 470U
			/*!
			 * \def UDIF_SIGNATURE_ENCODING_SIZE
			 * \brief The encoded signature size
			 */
#			define UDIF_SIGNATURE_ENCODING_SIZE 22828U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 44U
#		elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 11253U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SS1M1
			* \brief The McEliece SS1M1 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSS_MCELIECE_SS1M1
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 470U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 10520U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 44U
#		endif
#	elif defined(QSC_MCELIECE_S3N4608T96)
#		if defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 48928U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SF3M3
			* \brief The McEliece SF3M3 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF3M3
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 491U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 47596U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 64U
#		elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
		  /*!
		   * \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
		   * \brief The encoded certificate string length
		   */
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 22606U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SS3M3
			* \brief The McEliece SS3M3 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSS_MCELIECE_SS3M3
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 491U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 21676U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 64U
#		endif
#	elif defined(QSC_MCELIECE_S5N6688T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 68176U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SF5M5
			* \brief The McEliece SF5M5 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M5
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 41003U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SS5M5
			* \brief The McEliece SS5M5 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSS_MCELIECE_SS5M5
			/*!
			* \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			* \brief The root certificate encoded string size
			*/
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		endif
#	elif defined(QSC_MCELIECE_S6N6960T119)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 68173U
			/*!
			* \def UDIF_PARAMATERS_MCELIECE_SF5M6
			* \brief The McEliece SF5M6 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M6
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 41003U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SS5M6
			* \brief The McEliece SS5M6 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSS_MCELIECE_SS5M6
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		endif
#	elif defined(QSC_MCELIECE_S7N8192T128)
#		if defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 68173U
		   /*!
			* \def UDIF_PARAMATERS_MCELIECE_SF5M7
			* \brief The McEliece SF5M7 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M7
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 66520U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
			/*!
			* \def UDIF_CHILD_CERTIFICATE_STRING_SIZE
			* \brief The encoded certificate string length
			*/
#			define UDIF_CHILD_CERTIFICATE_STRING_SIZE 41003U
			/*!
			* \def UDIF_PARAMATERS_MCELIECE_SS5M7
			* \brief The McEliece SS5M7 parameter set
			*/
#			define UDIF_PARAMATERS_SPHINCSS_MCELIECE_SS5M7
			/*!
			 * \def UDIF_ROOT_CERTIFICATE_STRING_SIZE
			 * \brief The root certificate encoded string size
			 */
#			define UDIF_ROOT_CERTIFICATE_STRING_SIZE 516U
			/*!
			* \def UDIF_SIGNATURE_ENCODING_SIZE
			* \brief The encoded signature size
			*/
#			define UDIF_SIGNATURE_ENCODING_SIZE 39768U
			/*!
			* \def UDIF_VERIFICATION_KEY_ENCODING_SIZE
			* \brief The verification key size
			*/
#			define UDIF_VERIFICATION_KEY_ENCODING_SIZE 88U
#		else
#			error Invalid parameter sets, check the QSC library settings 
#		endif
#	else
		/* The library signature scheme and asymmetric cipher parameter sets
		must be synchronized to a common security level; s1, s3, s5 or s6.
		Check the QSC library common.h file for cipher and signature security level alignment. */
#		error Invalid parameter sets, check the QSC library settings 
#	endif
#endif

		/* Claims and Capabilities */

/*!
 * \def UDIF_CLAIM_ANCHOR_SIZE
 * \brief The size of a claim anchor or merkle root in bytes.
 */
#define UDIF_CLAIM_ANCHOR_SIZE 32U

/*!
 * \def UDIF_POLICY_HASH_SIZE
 * \brief The size of a policy identifier hash in bytes.
 */
#define UDIF_POLICY_HASH_SIZE 32U

/*!
 * \def UDIF_PERMISSION_MASK_SIZE
 * \brief The size of a permission mask in bytes.
 */
#define UDIF_PERMISSION_MASK_SIZE 8U

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
 * \def UDIF_SUITEID_SIZE
 * \brief The UDIF suite id parameter size.
 */
#define UDIF_SUITEID_SIZE 1U

/*!
 * \def UDIF_ROLE_SIZE
 * \brief The UDIF role parameter size.
 */
#define UDIF_ROLE_SIZE 1U

/*!
 * \def UDIF_MINIMUM_TRUST
 * \brief The minimum trust designation number.
 */
#define UDIF_MINIMUM_TRUST 1U

/*!
 * \def UDIF_NAME_MAX_SIZE
 * \brief The maximum aps name string length in characters.
 * The last character must be a string terminator.
 */
#define UDIF_NAME_MAX_SIZE 256U

/*!
 * \def UDIF_TWOWAY_TRUST
 * \brief The two-way trust designation number.
 */
#define UDIF_TWOWAY_TRUST 1000002U

/*!
 * \def UDIF_APPLICATION_CLIENT_PORT
 * \brief The default UDIF Client port number.
 */
#define UDIF_APPLICATION_CLIENT_PORT 39761U

/*!
 * \def UDIF_APPLICATION_IDG_PORT
 * \brief The default UDIF IDG port number.
 */
#define UDIF_APPLICATION_IDG_PORT 39762U

/*!
 * \def UDIF_APPLICATION_UBC_PORT
 * \brief The default UBC port number.
 */
#define UDIF_APPLICATION_UBC_PORT 39763U

/*!
 * \def UDIF_APPLICATION_UGC_PORT
 * \brief The default UGC port number.
 */
#define UDIF_APPLICATION_UGC_PORT 39764U

/*!
 * \def UDIF_APPLICATION_URA_PORT
 * \brief The default UUA port number.
 */
#define UDIF_APPLICATION_URA_PORT 39765U

/*!
 * \def UDIF_APPLICATION_UUA_PORT
 * \brief The default UUA port number.
 */
#define UDIF_APPLICATION_UUA_PORT 39766U

/*!
 * \def UDIF_CANONICAL_NAME_MINIMUM_SIZE
 * \brief The minimum canonical name size.
 */
#define UDIF_CANONICAL_NAME_MINIMUM_SIZE 3U

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
 * \def UDIF_CERTIFICATE_DEFAULT_PERIOD
 * \brief The default certificate validity period in milliseconds.
 */
#define UDIF_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_DESIGNATION_SIZE
 * \brief The size of the child certificate designation field.
 */
#define UDIF_CERTIFICATE_DESIGNATION_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_EXPIRATION_SIZE
 * \brief The certificate expiration date length.
 */
#define UDIF_CERTIFICATE_EXPIRATION_SIZE 16U

/*!
 * \def UDIF_CERTIFICATE_HASH_SIZE
 * \brief The size of the certificate hash in bytes.
 */
#define UDIF_CERTIFICATE_HASH_SIZE 32U

/*!
* \def UDIF_CERTIFICATE_ISSUER_SIZE
 * \brief The maximum certificate issuer string length.
 * The last character must be a string terminator.
 */
#define UDIF_CERTIFICATE_ISSUER_SIZE 256U

/*!
 * \def UDIF_CERTIFICATE_LINE_LENGTH
 * \brief The line length of the printed UDIF certificate.
 */
#define UDIF_CERTIFICATE_LINE_LENGTH 64U

/*!
 * \def UDIF_CERTIFICATE_MAXIMUM_PERIOD
 * \brief The maximum certificate validity period in milliseconds.
 */
#define UDIF_CERTIFICATE_MAXIMUM_PERIOD (UDIF_CERTIFICATE_DEFAULT_PERIOD * 2U)

/*!
 * \def UDIF_CERTIFICATE_MINIMUM_PERIOD
 * \brief The minimum certificate validity period in milliseconds.
 */
#define UDIF_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_SERIAL_SIZE
 * \brief The certificate serial number field length.
 */
#define UDIF_CERTIFICATE_SERIAL_SIZE 16U

/*!
 * \def UDIF_CERTIFICATE_HINT_SIZE
 * \brief The topological hint.
 */
#define UDIF_CERTIFICATE_HINT_SIZE (UDIF_CERTIFICATE_HASH_SIZE + UDIF_CERTIFICATE_SERIAL_SIZE)

/*!
 * \def UDIF_CERTIFICATE_SIGNED_HASH_SIZE
 * \brief The size of the signature and hash field in a certificate.
 */
#define UDIF_CERTIFICATE_SIGNED_HASH_SIZE (UDIF_ASYMMETRIC_SIGNATURE_SIZE + UDIF_CERTIFICATE_HASH_SIZE)

/*!
 * \def UDIF_CERTIFICATE_VERSION_SIZE
 * \brief The version id.
 */
#define UDIF_CERTIFICATE_VERSION_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_CHILD_SIZE
 * \brief The length of a child certificate.
 */
#define UDIF_CERTIFICATE_CHILD_SIZE (UDIF_CERTIFICATE_SIGNED_HASH_SIZE + \
	UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	UDIF_CERTIFICATE_ISSUER_SIZE + \
	UDIF_CERTIFICATE_SERIAL_SIZE + \
	UDIF_CERTIFICATE_SERIAL_SIZE + \
	UDIF_CERTIFICATE_EXPIRATION_SIZE + \
	UDIF_CERTIFICATE_DESIGNATION_SIZE + \
	UDIF_CERTIFICATE_ALGORITHM_SIZE + \
	UDIF_CERTIFICATE_VERSION_SIZE + \
	UDIF_SUITEID_SIZE + \
	UDIF_ROLE_SIZE + \
	UDIF_CAPABILITY_MASK_SIZE)

/*!
 * \def UDIF_CERTIFICATE_IDG_SIZE
 * \brief The length of an IDG certificate.
 */
#define UDIF_CERTIFICATE_IDG_SIZE (UDIF_ASYMMETRIC_SIGNATURE_SIZE + \
	UDIF_CERTIFICATE_HASH_SIZE + \
	UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	UDIF_CERTIFICATE_ISSUER_SIZE + \
	UDIF_CERTIFICATE_ADDRESS_SIZE + \
	UDIF_CERTIFICATE_SERIAL_SIZE + \
	UDIF_CERTIFICATE_SERIAL_SIZE + \
	UDIF_CERTIFICATE_EXPIRATION_SIZE + \
	UDIF_CERTIFICATE_DESIGNATION_SIZE + \
	UDIF_CERTIFICATE_ALGORITHM_SIZE + \
	UDIF_CERTIFICATE_VERSION_SIZE + \
	UDIF_SUITEID_SIZE + \
	UDIF_ROLE_SIZE + \
	UDIF_CAPABILITY_MASK_SIZE)

/*!
 * \def UDIF_CERTIFICATE_ROOT_SIZE
 * \brief The length of the root certificate.
 */
#define UDIF_CERTIFICATE_ROOT_SIZE (UDIF_CERTIFICATE_HASH_SIZE + \
	UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	UDIF_CERTIFICATE_ISSUER_SIZE + \
	UDIF_CERTIFICATE_SERIAL_SIZE + \
	UDIF_CERTIFICATE_EXPIRATION_SIZE + \
	UDIF_CERTIFICATE_ALGORITHM_SIZE + \
	UDIF_CERTIFICATE_VERSION_SIZE + \
	UDIF_SUITEID_SIZE + \
	UDIF_ROLE_SIZE + \
	UDIF_CAPABILITY_MASK_SIZE)

/*!
 * \def UDIF_CRYPTO_SYMMETRIC_KEY_SIZE
 * \brief The byte length of the symmetric cipher key.
 */
#define UDIF_CRYPTO_SYMMETRIC_KEY_SIZE 32U

/*!
 * \def UDIF_MESSAGE_MAX_SIZE
 * \brief The maximum message size (max signature + max certificate sizes).
 */
#define UDIF_MESSAGE_MAX_SIZE 1400000UL

/*!
 * \def UDIF_MFK_EXPIRATION_PERIOD
 * \brief The MFK validity period in milliseconds.
 */
#define UDIF_MFK_EXPIRATION_PERIOD ((uint64_t)60U * 24U * 60U * 60U)

/*!
 * \def UDIF_MINIMUM_PATH_LENGTH
 * \brief The minimum file path length.
 */
#define UDIF_MINIMUM_PATH_LENGTH 9U

/*!
 * \def UDIF_NETWORK_CONNECTION_MTU
 * \brief The UDIF packet buffer size.
 */
#define UDIF_NETWORK_CONNECTION_MTU 1500U

/*!
 * \def UDIF_NETWORK_DOMAIN_NAME_MAX_SIZE
 * \brief The maximum domain name length in characters.
 * The last character must be a string terminator.
 */
#define UDIF_NETWORK_DOMAIN_NAME_MAX_SIZE 256U

/*!
 * \def UDIF_NETWORK_MAX_APSS
 * \brief The maximum number of aps connections in a network.
 */
#define UDIF_NETWORK_MAX_APSS 1000000UL

/*!
 * \def UDIF_NETWORK_NODE_ID_SIZE
 * \brief The node identification string length.
 */
#define UDIF_NETWORK_NODE_ID_SIZE 16

/*!
 * \def UDIF_PERIOD_DAY_TO_SECONDS
 * \brief A period of one day in seconds.
 */
#define UDIF_PERIOD_DAY_TO_SECONDS (24U * 60U * 60U)

/*!
 * \def UDIF_SOCKET_TERMINATOR_SIZE
 * \brief The packet delimiter byte size.
 */
#define UDIF_SOCKET_TERMINATOR_SIZE 1U

/*!
 * \def UDIF_PACKET_ERROR_SIZE
 * \brief The packet error message byte size.
 */
#define UDIF_PACKET_ERROR_SIZE 1U

/*!
 * \def UDIF_PACKET_HEADER_SIZE
 * \brief The UDIF packet header size.
 */
#define UDIF_PACKET_HEADER_SIZE 22U

/*!
 * \def UDIF_PACKET_SUBHEADER_SIZE
 * \brief The UDIF packet sub-header size.
 */
#define UDIF_PACKET_SUBHEADER_SIZE 16U

/*!
 * \def UDIF_PACKET_SEQUENCE_TERMINATOR
 * \brief The sequence number of a packet that closes a connection.
 */
#define UDIF_PACKET_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \def UDIF_PACKET_TIME_SIZE
 * \brief The byte size of the serialized packet time parameter.
 */
#define UDIF_PACKET_TIME_SIZE 8U

/*!
 * \def UDIF_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is valid.
 */
#define UDIF_PACKET_TIME_THRESHOLD 60U

/*!
 * \def UDIF_NETWORK_TERMINATION_MESSAGE_SIZE
 * \brief The network termination message size.
 */
#define UDIF_NETWORK_TERMINATION_MESSAGE_SIZE 1U

/*!
 * \def UDIF_NETWORK_TERMINATION_PACKET_SIZE
 * \brief The network termination packet size.
 */
#define UDIF_NETWORK_TERMINATION_PACKET_SIZE (UDIF_PACKET_HEADER_SIZE + UDIF_NETWORK_TERMINATION_MESSAGE_SIZE)

/* Versioning */

/*!
 * \def UDIF_ACTIVE_VERSION
 * \brief The UDIF active version identifier.
 */
#define UDIF_ACTIVE_VERSION 1U

/*!
 * \def UDIF_ACTIVE_VERSION_SIZE
 * \brief The UDIF version field size in bytes.
 */
#define UDIF_ACTIVE_VERSION_SIZE 2U

/* Identity and Namespace */

/*!
 * \def UDIF_NAMESPACE_CODE_SIZE
 * \brief The size of a namespace code (short string or numeric).
 */
#define UDIF_NAMESPACE_CODE_SIZE 8U

/*!
 * \def UDIF_ISSUER_DOMAIN_CODE_SIZE
 * \brief The size of an issuer domain code (unique identifier).
 */
#define UDIF_ISSUER_DOMAIN_CODE_SIZE 8U

/*!
 * \def UDIF_IDENTITY_ID_SIZE
 * \brief The size of a subject identity identifier in bytes.
 */
#define UDIF_IDENTITY_ID_SIZE 32U

/*!
 * \def UDIF_IDENTITY_MAX_SIZE
 * \brief Maximum encoded identity blob size.
 */
#define UDIF_IDENTITY_MAX_SIZE 512U

 /*!
  * \def UDIF_PERIOD_DAY_TO_SECONDS
  * \brief A period of one day in seconds.
  */
#define UDIF_PERIOD_DAY_TO_SECONDS (24U * 60U * 60U)

/* Certificate Fields */

 /*!
  * \def UDIF_CERTIFICATE_ROLE_SIZE
  * \brief The certificate role field size.
  */
#define UDIF_CERTIFICATE_ROLE_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_SERIAL_SIZE
 * \brief The certificate serial number field length.
 */
#define UDIF_CERTIFICATE_SERIAL_SIZE 16U

/*!
 * \def UDIF_CERTIFICATE_VERSION_SIZE
 * \brief The certificate version field size.
 */
#define UDIF_CERTIFICATE_VERSION_SIZE 1U

/*!
 * \def UDIF_CERTIFICATE_HASH_SIZE
 * \brief The size of the certificate hash in bytes (SHA3-256).
 */
#define UDIF_CERTIFICATE_HASH_SIZE 32U

/*!
 * \def UDIF_CERTIFICATE_SIGNED_HASH_SIZE
 * \brief The combined size of a signature and certificate hash.
 */
#define UDIF_CERTIFICATE_SIGNED_HASH_SIZE (UDIF_ASYMMETRIC_SIGNATURE_SIZE + UDIF_CERTIFICATE_HASH_SIZE)

/*!
 * \def UDIF_CERTIFICATE_DEFAULT_PERIOD
 * \brief Default certificate validity period in seconds (1 year).
 */
#define UDIF_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_MINIMUM_PERIOD
 * \brief Minimum certificate validity period in seconds (1 day).
 */
#define UDIF_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1U * 24U * 60U * 60U)

/*!
 * \def UDIF_CERTIFICATE_MAXIMUM_PERIOD
 * \brief Maximum certificate validity period in seconds (2 years).
 */
#define UDIF_CERTIFICATE_MAXIMUM_PERIOD (UDIF_CERTIFICATE_DEFAULT_PERIOD * 2U)

/* --- Cryptographic Parameters --- */

/*!
 * \def UDIF_CRYPTO_SYMMETRIC_KEY_SIZE
 * \brief Symmetric cipher key length in bytes.
 */
#define UDIF_CRYPTO_SYMMETRIC_KEY_SIZE 32U

/*!
 * \def UDIF_CRYPTO_SYMMETRIC_MAC_SIZE
 * \brief Symmetric cipher authentication tag size in bytes.
 */
#define UDIF_CRYPTO_SYMMETRIC_MAC_SIZE 32U

/*!
 * \def UDIF_CRYPTO_SYMMETRIC_HASH_SIZE
 * \brief Hash output size in bytes (SHA3-256).
 */
#define UDIF_CRYPTO_SYMMETRIC_HASH_SIZE 32U

  /*!
   * \def UDIF_CRYPTO_SYMMETRIC_NONCE_SIZE
   * \brief The byte length of the symmetric cipher nonce.
   */
#if defined(UDIF_USE_RCS_ENCRYPTION)
#	define UDIF_CRYPTO_SYMMETRIC_NONCE_SIZE 32U
#else
#	define UDIF_CRYPTO_SYMMETRIC_NONCE_SIZE 16U
#endif

/*!
* \def UDIF_CRYPTO_SEED_SIZE
* \brief The seed array byte size.
*/
#define UDIF_CRYPTO_SEED_SIZE 64U

/*!
* \def UDIF_CRYPTO_SYMMETRIC_TOKEN_SIZE
* \brief The byte length of the symmetric token.
*/
#define UDIF_CRYPTO_SYMMETRIC_TOKEN_SIZE 32U

/*!
* \def UDIF_CRYPTO_SYMMETRIC_HASH_SIZE
* \brief The hash function output byte size.
*/
#define UDIF_CRYPTO_SYMMETRIC_HASH_SIZE 32U

/*!
* \def UDIF_CRYPTO_SYMMETRIC_MAC_SIZE
* \brief The MAC function output byte size.
*/
#if defined(UDIF_USE_RCS_ENCRYPTION)
#	if defined(UDIF_EXTENDED_SESSION_SECURITY)
#		define UDIF_CRYPTO_SYMMETRIC_MAC_SIZE 64U
#	else
#		define UDIF_CRYPTO_SYMMETRIC_MAC_SIZE 32U
#	endif
#else
#	define UDIF_CRYPTO_SYMMETRIC_MAC_SIZE 16U
#endif

/*!
* \def UDIF_CRYPTO_SYMMETRIC_SECRET_SIZE
* \brief The shared secret byte size.
*/
#define UDIF_CRYPTO_SYMMETRIC_SECRET_SIZE 32U

/* UDIF Enumerations */

/*!
 * \enum udif_configuration_sets
 * \brief The UDIF algorithm configuration sets.
 */
UDIF_EXPORT_API typedef enum udif_configuration_sets
{
	udif_configuration_set_none = 0x00U,										/*!< No algorithm identifier is set */
	udif_configuration_set_dilithium1_kyber1_rcs256_shake256 = 0x01U,			/*!< The Dilithium-S1/Kyber-S1/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium3_kyber3_rcs256_shake256 = 0x02U,			/*!< The Dilithium-S3/Kyber-S3/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium5_kyber5_rcs256_shake256 = 0x03U,			/*!< The Dilithium-S5/Kyber-S5/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_dilithium5_kyber6_rcs512_shake256 = 0x04U,			/*!< The Dilithium-S5/Kyber-S6/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256 = 0x05U,		/*!< The SPHINCS+-S1F/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256 = 0x06U,		/*!< The SPHINCS+-S1S/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256 = 0x07U,		/*!< The SPHINCS+-S3F/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256 = 0x08U,		/*!< The SPHINCS+-S3S/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256 = 0x09U,		/*!< The SPHINCS+-S5F/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256 = 0x0AU,		/*!< The SPHINCS+-S5S/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256 = 0x0BU,		/*!< The SPHINCS+-S5F/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256 = 0x0CU,		/*!< The SPHINCS+-S5S/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256 = 0x0DU,		/*!< The SPHINCS+-S5F/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
	udif_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256 = 0x0EU,		/*!< The SPHINCS+-S5S/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
} udif_configuration_sets;

/*!
 * \enum udif_network_designations
 * \brief The UDIF device designation.
 */
UDIF_EXPORT_API typedef enum udif_network_designations
{
	udif_network_designation_none = 0x00U,							/*!< No designation was selected */
	udif_network_designation_ubc = 0x01U,							/*!< The device is an UBC */
	udif_network_designation_client = 0x02U,						/*!< The device is a client */
	udif_network_designation_ugc = 0x03U,							/*!< The device is the UGC */
	udif_network_designation_remote = 0x04U,						/*!< The device is a remote aps */
	udif_network_designation_ura = 0x05U,							/*!< The device is an URA security server */
	udif_network_designation_revoked = 0x06U,						/*!< The device has been revoked */
	udif_network_designation_idg = 0x07U,							/*!< The device is the IDG */
	udif_network_designation_uua = 0x08U,							/*!< The device is the UUA */
	udif_network_designation_all = 0xFFU,							/*!< Every server and client device on the network */
} udif_network_designations;

/*!
 * \enum udif_network_errors
 * \brief The UDIF network error values.
 */
UDIF_EXPORT_API typedef enum udif_network_errors
{
	udif_network_error_none = 0x00U,								/*!< No error was detected */
	udif_network_error_accept_fail = 0x01U,							/*!< The socket accept function returned an error */
	udif_network_error_auth_failure = 0x02U,						/*!< The cipher authentication has failed */
	udif_network_error_bad_keep_alive = 0x03U,						/*!< The keep alive check failed */
	udif_network_error_channel_down = 0x04U,						/*!< The communications channel has failed */
	udif_network_error_connection_failure = 0x05U,					/*!< The device could not make a connection to the remote host */
	udif_network_error_decryption_failure = 0x06U,					/*!< The decryption authentication has failed */
	udif_network_error_establish_failure = 0x07U,					/*!< The transmission failed at the kex establish phase */
	udif_network_error_general_failure = 0x08U,						/*!< The connection experienced an unexpected error */
	udif_network_error_hosts_exceeded = 0x09U,						/*!< The server has run out of socket connections */
	udif_network_error_identity_unknown = 0x10U,					/*!< The random generator experienced a failure */
	udif_network_error_invalid_input = 0x1AU,						/*!< The input is invalid */
	udif_network_error_invalid_request = 0x1BU,						/*!< The request is invalid */
	udif_network_error_keep_alive_expired = 0x1CU,					/*!< The keep alive has expired with no response */
	udif_network_error_keep_alive_timeout = 0x1DU,					/*!< The keepalive failure counter has exceeded maximum  */
	udif_network_error_kex_auth_failure = 0x1EU,					/*!< The kex authentication has failed */
	udif_network_error_key_not_recognized = 0x1FU,					/*!< The key-id is not recognized */
	udif_network_error_key_has_expired = 0x20U,						/*!< The certificate has expired */
	udif_network_error_listener_fail = 0x21U,						/*!< The listener function failed to initialize */
	udif_network_error_memory_allocation = 0x22U,					/*!< The server has run out of memory */
	udif_network_error_packet_unsequenced = 0x23U,					/*!< The random generator experienced a failure */
	udif_network_error_random_failure = 0x24U,						/*!< The random generator experienced a failure */
	udif_network_error_ratchet_fail = 0x25U,						/*!< The ratchet operation has failed */
	udif_network_error_receive_failure = 0x26U,						/*!< The receiver failed at the network layer */
	udif_network_error_transmit_failure = 0x27U,					/*!< The transmitter failed at the network layer */
	udif_network_error_unknown_protocol = 0x28U,					/*!< The protocol version is unknown */
	udif_network_error_unsequenced = 0x29U,							/*!< The packet was received out of sequence */
	udif_network_error_verify_failure = 0x2AU,						/*!< The expected data could not be verified */
} udif_network_errors;

/*!
 * \enum udif_network_flags
 * \brief The UDIF network flags.
 */
UDIF_EXPORT_API typedef enum udif_network_flags
{
	udif_network_flag_none = 0x00U,									/*!< No flag was selected */
	udif_network_flag_connection_terminate_request = 0x01U,			/*!< The packet contains a connection termination message  */
	udif_network_flag_error_condition = 0x02U,						/*!< The connection experienced an error message*/
	udif_network_flag_incremental_update_request = 0x09U,			/*!< The packet contains an incremental update request message */
	udif_network_flag_incremental_update_response = 0x0AU,			/*!< The packet contains an incremental update response message */
	udif_network_flag_register_request = 0x0BU,						/*!< The packet contains a join request message */
	udif_network_flag_register_response = 0x0CU,					/*!< The packet contains a join response message */
	udif_network_flag_register_update_request = 0x0DU,				/*!< The packet contains a join update request message */
	udif_network_flag_register_update_response = 0x0EU,				/*!< The packet contains a join update response message */
	udif_network_flag_keep_alive_request = 0x0FU,					/*!< The packet contains a keep alive request */
	udif_network_flag_keep_alive_response = 0x10U,					/*!< The packet contains a keep alive response */
	udif_network_flag_network_announce_broadcast = 0x15U,			/*!< The packet contains a topology announce broadcast */
	udif_network_flag_network_converge_request = 0x16U,				/*!< The packet contains a network converge request message */
	udif_network_flag_network_converge_response = 0x17U,			/*!< The packet contains a network converge response message */
	udif_network_flag_network_converge_update = 0x18U,				/*!< The packet contains a network converge update message */
	udif_network_flag_network_resign_request = 0x19U,				/*!< The packet contains a network resignation request message */
	udif_network_flag_network_resign_response = 0x1AU,				/*!< The packet contains a network resignation response message */
	udif_network_flag_network_revocation_broadcast = 0x1BU,			/*!< The packet contains a certificate revocation broadcast */
	udif_network_flag_network_signature_request = 0x1CU,			/*!< The packet contains a certificate signing request */
	udif_network_flag_system_error_condition = 0x1DU,				/*!< The packet contains an error condition message */
	udif_network_flag_tunnel_connection_terminate = 0x1EU,			/*!< The packet contains a socket close message */
	udif_network_flag_tunnel_encrypted_message = 0x1FU,				/*!< The packet contains an encrypted message */
	udif_network_flag_tunnel_session_established = 0x20U,			/*!< The exchange is in the established state */
	udif_network_flag_tunnel_transfer_request = 0x21U,				/*!< Reserved - The host has received a transfer request */
	udif_network_flag_topology_query_request = 0x22U,				/*!< The packet contains a topology query request message */
	udif_network_flag_topology_query_response = 0x23U,				/*!< The packet contains a topology query response message */
	udif_network_flag_topology_status_request = 0x24U,				/*!< The packet contains a topology status request message */
	udif_network_flag_topology_status_response = 0x25U,				/*!< The packet contains a topology status response message */
	udif_network_flag_topology_status_available = 0x26U,			/*!< The packet contains a topology status available message */
	udif_network_flag_topology_status_synchronized = 0x27U,			/*!< The packet contains a topology status synchronized message */
	udif_network_flag_topology_status_unavailable = 0x28U,			/*!< The packet contains a topology status unavailable message */
	udif_network_flag_network_remote_signing_request = 0x29U,		/*!< The packet contains a remote signing request message */
	udif_network_flag_network_remote_signing_response = 0x2AU,		/*!< The packet contains a remote signing response message */
} udif_network_flags;

/*!
 * \enum udif_protocol_errors
 * \brief The UDIF protocol error values.
 */
UDIF_EXPORT_API typedef enum udif_protocol_errors
{
	udif_protocol_error_none = 0x00U,								/*!< No error was detected */
	udif_protocol_error_authentication_failure = 0x01U,				/*!< The symmetric cipher had an authentication failure */
	udif_protocol_error_certificate_not_found = 0x02U,				/*!< The node certificate could not be found */
	udif_protocol_error_channel_down = 0x03U,						/*!< The communications channel has failed */
	udif_protocol_error_connection_failure = 0x04U,					/*!< The device could not make a connection to the remote host */
	udif_protocol_error_connect_failure = 0x05U,					/*!< The transmission failed at the KEX connection phase */
	udif_protocol_error_convergence_failure = 0x06U,				/*!< The convergence call has returned an error */
	udif_protocol_error_convergence_synchronized = 0x07U,			/*!< The database is already synchronized */
	udif_protocol_error_decapsulation_failure = 0x08U,				/*!< The asymmetric cipher failed to decapsulate the shared secret */
	udif_protocol_error_decoding_failure = 0x09U,					/*!< The node or certificate decoding failed */
	udif_protocol_error_decryption_failure = 0x0AU,					/*!< The decryption authentication has failed */
	udif_protocol_error_establish_failure = 0x0BU,					/*!< The transmission failed at the KEX establish phase */
	udif_protocol_error_exchange_failure = 0x0CU,					/*!< The transmission failed at the KEX exchange phase */
	udif_protocol_error_file_not_deleted = 0x0DU,					/*!< The application could not delete a local file */
	udif_protocol_error_file_not_found = 0x0EU,						/*!< The file could not be found */
	udif_protocol_error_file_not_written = 0x0FU,					/*!< The file could not be written to storage */
	udif_protocol_error_hash_invalid = 0x10U,						/*!< The public-key hash is invalid */
	udif_protocol_error_hosts_exceeded = 0x11U,						/*!< The server has run out of socket connections */
	udif_protocol_error_invalid_request = 0x12U,					/*!< The packet flag was unexpected */
	udif_protocol_error_certificate_expired = 0x13U,				/*!< The certificate has expired */
	udif_protocol_error_key_expired = 0x14U,						/*!< The UDIF public key has expired  */
	udif_protocol_error_key_unrecognized = 0x15U,					/*!< The key identity is unrecognized */
	udif_protocol_error_listener_fail = 0x16U,						/*!< The listener function failed to initialize */
	udif_protocol_error_memory_allocation = 0x17U,					/*!< The server has run out of memory */
	udif_protocol_error_message_time_invalid = 0x18U,				/*!< The network time is invalid or has substantial delay */
	udif_protocol_error_message_verification_failure = 0x19U,		/*!< The expected data could not be verified */
	udif_protocol_error_no_usable_address = 0x1AU,					/*!< The server has no usable IP address, assign in configuration */
	udif_protocol_error_node_not_available = 0x1BU,					/*!< The node is not available for a session */
	udif_protocol_error_node_not_found = 0x1CU,						/*!< The node could not be found in the database */
	udif_protocol_error_node_was_registered = 0x1DU,				/*!< The node was previously registered in the database */
	udif_protocol_error_operation_cancelled = 0x1EU,				/*!< The operation was cancelled by the user */
	udif_protocol_error_packet_header_invalid = 0x1FU,				/*!< The packet header received was invalid */
	udif_protocol_error_packet_unsequenced = 0x20U,					/*!< The packet was received out of sequence */
	udif_protocol_error_receive_failure = 0x21U,					/*!< The receiver failed at the network layer */
	udif_protocol_error_root_signature_invalid = 0x22U,				/*!< The root signature failed authentication */
	udif_protocol_error_serialization_failure = 0x23U,				/*!< The certificate could not be serialized */
	udif_protocol_error_signature_failure = 0x24U,					/*!< The signature scheme could not sign a message */
	udif_protocol_error_signing_failure = 0x25U,					/*!< The transmission failed to sign the data */
	udif_protocol_error_socket_binding = 0x26U,						/*!< The socket could not be bound to an IP address */
	udif_protocol_error_socket_creation = 0x27U,					/*!< The socket could not be created */
	udif_protocol_error_transmit_failure = 0x28U,					/*!< The transmitter failed at the network layer */
	udif_protocol_error_topology_no_aps = 0x29U,					/*!< The topological database has no aps entries */
	udif_protocol_error_unknown_protocol = 0x2AU,					/*!< The protocol string was not recognized */
	udif_protocol_error_verification_failure = 0x2BU,				/*!< The transmission failed at the KEX verify phase */
} udif_protocol_errors;

/*!
 * \enum udif_claim_type
 * \brief Claim type identifiers (deterministic canonicalization required).
 */
UDIF_EXPORT_API typedef enum udif_claim_type
{
	udif_claim_unknown = 0x00U,			/*!< Unspecified claim type */
	udif_claim_commodity_id = 0x10U,	/*!< Commodity/asset identifier */
	udif_claim_biometric_hash = 0x11U,	/*!< Biometric template hash */
	udif_claim_institution_id = 0x12U,	/*!< Institutional ID / account */
	udif_claim_public_key = 0x13U,		/*!< Subjects public key / fingerprint */
	udif_claim_age_over = 0x14U,		/*!< Age threshold proof (boolean) */
	udif_claim_citizenship = 0x15U,		/*!< Country citizenship assertion */
	udif_claim_residency = 0x16U,		/*!< Residency assertion */
	udif_claim_membership_id = 0x17U,	/*!< Membership/affiliation identifier */
	udif_claim_contact_email = 0x18U,	/*!< Email address (validated form) */
	udif_claim_contact_phone = 0x19U,	/*!< Phone (E.164 normalized) */
	udif_claim_address = 0x1AU,			/*!< Postal/civic address (normalized) */
	udif_claim_custom = 0x7FU			/*!< Implementation-specific/custom */
} udif_claim_type;

/*!
 * \enum udif_token_type
 * \brief Token families issued/validated within UDIF.
 */
UDIF_EXPORT_API typedef enum udif_token_type
{
	udif_token_none = 0x00U,			/*!< Not a token */
	udif_token_capability = 0x01U,		/*!< Capability token (authZ) */
	udif_token_attestation = 0x02U,		/*!< Attestation token (statement + signature) */
	udif_token_session = 0x03U			/*!< Session/resumption ticket (envelope optional) */
} udif_token_type;

/*!
 * \enum udif_capability_id
 * \brief Canonical capability identifiers (bit positions map to the mask).
 */
UDIF_EXPORT_API typedef enum udif_capability_id
{
	udif_cap_issue_certificate = 0x00U, /*!< Issue subordinate certificates */
	udif_cap_revoke_certificate = 0x01U,/*!< Revoke certificates */
	udif_cap_issue_token = 0x02U,		/*!< Issue capability/attestation tokens */
	udif_cap_validate_token = 0x03U,	/*!< Validate tokens and claims */
	udif_cap_register_issuer = 0x04U,	/*!< Register issuer domain codes */
	udif_cap_rotate_keys = 0x05U,		/*!< Rotate root/issuer keys */
	udif_cap_directory_query = 0x06U,	/*!< Query directory / discovery */
	udif_cap_audit_log_access = 0x07U,	/*!< Access audit logs */
	udif_cap_admin = 0x08U				/*!< Administrative override */
} udif_capability_id;

/*!
 * \enum udif_permission_class
 * \brief Permission classes whose bits populate the permission mask.
 */
UDIF_EXPORT_API typedef enum udif_permission_class
{
	udif_perm_read_claims = 0x00U,		/*!< Read subject claims */
	udif_perm_write_claims = 0x01U,		/*!< Write/update subject claims */
	udif_perm_read_certs = 0x02U,		/*!< Read certificates/CRLs */
	udif_perm_write_certs = 0x03U,		/*!< Create/update certificates/CRLs */
	udif_perm_manage_policy = 0x04U,	/*!< Manage policy/validation parameters */
	udif_perm_manage_caps = 0x05U,		/*!< Grant/revoke capabilities */
	udif_perm_delegate = 0x06U,			/*!< Delegate permission subsets */
	udif_perm_export_identity = 0x07U,	/*!< Export identities/tokens */
	udif_perm_import_identity = 0x08U	/*!< Import identities/tokens */
} udif_permission_class;

/*!
 * \enum udif_policy_decision
 * \brief Policy evaluation outcome.
 */
UDIF_EXPORT_API typedef enum udif_policy_decision
{
	udif_policy_permit = 0x00U,			/*!< Permit */
	udif_policy_deny = 0x01U,			/*!< Deny */
	udif_policy_indeterminate = 0x02U,	/*!< Evaluation failed (error) */
	udif_policy_not_applicable= 0x03U	/*!< No matching rule */
} udif_policy_decision;

/*!
 * \enum udif_verify_policy
 * \brief Verification strictness for identity/cert/claim checks.
 */
UDIF_EXPORT_API typedef enum udif_verify_policy
{
	udif_verify_strict = 0x00U,			/*!< All checks required (fail-closed) */
	udif_verify_lenient = 0x01U			/*!< Allow missing non-critical fields (fail-open subset) */
} udif_verify_policy;

/*!
 * \enum udif_time_validation
 * \brief Results of time/validity-window checks.
 */
UDIF_EXPORT_API typedef enum udif_time_validation
{
	udif_time_valid = 0x00U,			/*!< Within window */
	udif_time_future = 0x01U,			/*!< Not yet valid */
	udif_time_expired = 0x02U,			/*!< Expired */
	udif_time_skew_exceeds = 0x03U		/*!< Exceeds allowed clock skew */
} udif_time_validation;

/*!
 * \enum udif_status
 * \brief Generic status codes for UDIF operations.
 */
UDIF_EXPORT_API typedef enum udif_status
{
	udif_status_success = 0x00U,		/*!< Operation succeeded */
	udif_status_invalid_argument = 0x01U, /*!< Bad input parameter(s) */
	udif_status_not_found = 0x02U,		/*!< Object not found */
	udif_status_already_exists = 0x03U, /*!< Duplicate object */
	udif_status_out_of_memory = 0x04U,	/*!< Allocation failed */
	udif_status_buffer_too_small = 0x05U, /*!< Output buffer too small */
	udif_status_not_supported = 0x06U,	/*!< Feature not supported */
	udif_status_internal_error = 0x07U  /*!< Internal/unknown error */
} udif_status;

/*!
 * \enum udif_error_identity
 * \brief Identity-specific error codes.
 */
UDIF_EXPORT_API typedef enum udif_error_identity
{
	udif_eid_none = 0x00U,				/*!< No error */
	udif_eid_namespace_bad = 0x01U,		/*!< Invalid namespace code */
	udif_eid_issuer_bad = 0x02U,		/*!< Invalid issuer domain code */
	udif_eid_subject_bad = 0x03U,		/*!< Invalid subject identifier */
	udif_eid_mask_invalid = 0x04U,		/*!< Capability/permission mask invalid */
	udif_eid_anchor_mismatch = 0x05U,	/*!< Claim anchor does not match claims */
	udif_eid_sig_invalid = 0x06U,		/*!< Signature verification failed */
	udif_eid_expired = 0x07U,			/*!< Identity validity expired */
	udif_eid_future = 0x08U				/*!< Identity not yet valid */
} udif_error_identity;

/*!
 * \enum udif_error_certificate
 * \brief Certificate-specific error codes.
 */
UDIF_EXPORT_API typedef enum udif_error_certificate
{
	udif_ecert_none = 0x00U,			/*!< No error */
	udif_ecert_type_unknown = 0x01U,	/*!< Unknown certificate type */
	udif_ecert_serial_bad = 0x02U,		/*!< Serial malformed/unknown */
	udif_ecert_chain_invalid = 0x03U,	/*!< Chain does not validate to UDC */
	udif_ecert_sig_invalid = 0x04U,		/*!< Signature invalid */
	udif_ecert_expired = 0x05U,			/*!< Certificate expired */
	udif_ecert_future = 0x06U,			/*!< Not yet valid */
	udif_ecert_policy_mismatch = 0x07U, /*!< Policy hash mismatch */
	udif_ecert_revoked = 0x08U			/*!< Certificate revoked */
} udif_error_certificate;

/*!
 * \enum udif_error_claims
 * \brief Claim/claim-set error codes.
 */
UDIF_EXPORT_API typedef enum udif_error_claims
{
	udif_ecl_none = 0x00U,				/*!< No error */
	udif_ecl_type_unknown = 0x01U,		/*!< Unknown claim type */
	udif_ecl_encoding_bad = 0x02U,		/*!< Bad/unsupported encoding */
	udif_ecl_canonical_fail = 0x03U,	/*!< Canonicalization failed */
	udif_ecl_anchor_bad = 0x04U,		/*!< Anchor/merkle root mismatch */
	udif_ecl_value_invalid = 0x05U		/*!< Claim value invalid/out of range */
} udif_error_claims;

/*!
 * \enum udif_error_capability
 * \brief Capability/permission evaluation errors.
 */
UDIF_EXPORT_API typedef enum udif_error_capability
{
	udif_ecap_none = 0x00U,				/*!< No error */
	udif_ecap_denied = 0x01U,			/*!< Capability denied by policy */
	udif_ecap_mask_empty = 0x02U,		/*!< Empty/zero capability mask */
	udif_ecap_mask_conflict = 0x03U		/*!< Conflicting capability bits */
} udif_error_capability;

/*!
 * \enum udif_error_policy
 * \brief Policy evaluation/lookup errors.
 */
UDIF_EXPORT_API typedef enum udif_error_policy
{
	udif_epol_none = 0x00U,				/*!< No error */
	udif_epol_not_found = 0x01U,		/*!< Policy not found */
	udif_epol_hash_mismatch= 0x02U,		/*!< Policy hash mismatch */
	udif_epol_indeterminate= 0x03U		/*!< Evaluation indeterminate */
} udif_error_policy;

/*!
 * \enum udif_error_encoding
 * \brief Encoding/decoding errors for UDIF objects.
 */
UDIF_EXPORT_API typedef enum udif_error_encoding
{
	udif_eenc_none = 0x00U,				/*!< No error */
	udif_eenc_overflow = 0x01U,			/*!< Buffer overflow/size mismatch */
	udif_eenc_underflow = 0x02U,		/*!< Buffer underflow/truncation */
	udif_eenc_format = 0x03U,			/*!< Bad format/version */
	udif_eenc_unsupported = 0x04U		/*!< Unsupported encoding */
} udif_error_encoding;

/* Certificate block banners */

/*!
 * \def UDIF_CERTIFICATE_HEADER_SIZE
 * \brief The UDIF certificate header string length.
 */
#define UDIF_CERTIFICATE_HEADER_SIZE 64U

/*!
 * \def UDIF_CERTIFICATE_FOOTER_SIZE
 * \brief The UDIF certificate footer string length.
 */
#define UDIF_CERTIFICATE_FOOTER_SIZE 64U

/* Certificate field prefixes */

/*!
 * \def UDIF_CERTIFICATE_ISSUER_PREFIX_SIZE
 * \brief The certificate issuer prefix length.
 */
#define UDIF_CERTIFICATE_ISSUER_PREFIX_SIZE 9U

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
 * \def UDIF_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE
 * \brief The "valid to" field prefix length.
 */
#define UDIF_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U

/*!
 * \def UDIF_CERTIFICATE_ALGORITHM_PREFIX_SIZE
 * \brief The algorithm field prefix length.
 */
#define UDIF_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U

/*!
 * \def UDIF_CERTIFICATE_VERSION_PREFIX_SIZE
 * \brief The version field prefix length.
 */
#define UDIF_CERTIFICATE_VERSION_PREFIX_SIZE 10U

/*!
 * \def UDIF_CERTIFICATE_ROLE_PREFIX_SIZE
 * \brief The role field prefix length.
 */
#define UDIF_CERTIFICATE_ROLE_PREFIX_SIZE 6U
#define UDIF_ROOT_CERTIFICATE_HEADER_SIZE 64U
#define UDIF_ROOT_CERTIFICATE_HASH_PREFIX_SIZE 19U
#define UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13U
#define UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE 9U
#define UDIF_ROOT_CERTIFICATE_NAME_PREFIX_SIZE 7U
#define UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define UDIF_ROOT_CERTIFICATE_FOOTER_SIZE 64U
#define UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define UDIF_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define UDIF_ROOT_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE 18U
#define UDIF_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE 18U
#define UDIF_ACTIVE_VERSION_STRING_SIZE 5U

 /** \endcond */

 /** \cond */

static const char UDIF_ROOT_CERTIFICATE_HEADER[UDIF_ROOT_CERTIFICATE_HEADER_SIZE] = "------------BEGIN UDIF ROOT PUBLIC CERTIFICATE BLOCK-----------";
static const char UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX[UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char UDIF_ROOT_CERTIFICATE_NAME_PREFIX[UDIF_ROOT_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
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

/** \cond */

#define UDIF_CERTIFICATE_SEPERATOR_SIZE 1U
#define UDIF_CHILD_CERTIFICATE_HEADER_SIZE 64U
#define UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE 30U
#define UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE 23U
#define UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE 9U
#define UDIF_CHILD_CERTIFICATE_NAME_PREFIX_SIZE 7U
#define UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE 9U
#define UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE 14U
#define UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13U
#define UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 6U
#define UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12U
#define UDIF_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE 10U
#define UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE 14U
#define UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE 18U
#define UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE 10U
#define UDIF_CHILD_CERTIFICATE_FOOTER_SIZE 64U
#define UDIF_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE 19U

static const char UDIF_CHILD_CERTIFICATE_HEADER[UDIF_CHILD_CERTIFICATE_HEADER_SIZE] = "-----------BEGIN UDIF CHILD PUBLIC CERTIFICATE BLOCK-----------";
static const char UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX[UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX_SIZE] = "Root Signed Public Key Hash: ";
static const char UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX[UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE] = "Public Signature Key: ";
static const char UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX[UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char UDIF_CHILD_CERTIFICATE_NAME_PREFIX[UDIF_CHILD_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX[UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX[UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE] = "Root Serial: ";
static const char UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX[UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX[UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = " To: ";
static const char UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX[UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char UDIF_CHILD_CERTIFICATE_VERSION_PREFIX[UDIF_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX[UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE] = "Designation: ";
static const char UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX[UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX_SIZE] = "Capability Mask: ";
static const char UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX[UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE] = "Address: ";
static const char UDIF_CHILD_CERTIFICATE_FOOTER[UDIF_CHILD_CERTIFICATE_FOOTER_SIZE] = "------------END UDIF CHILD PUBLIC CERTIFICATE BLOCK------------";
static const char UDIF_CHILD_CERTIFICATE_DEFAULT_NAME[UDIF_CHILD_CERTIFICATE_DEFAULT_NAME_SIZE] = " Child Certificate";

#define UDIF_NETWORK_DESIGNATION_SIZE 33
static const char UDIF_NETWORK_DESIGNATION_NONE[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_none";
static const char UDIF_NETWORK_DESIGNATION_URA[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_ura";
static const char UDIF_NETWORK_DESIGNATION_CLIENT[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_client";
static const char UDIF_NETWORK_DESIGNATION_UBC[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_ubc";
static const char UDIF_NETWORK_DESIGNATION_IDG[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_idg";
static const char UDIF_NETWORK_DESIGNATION_UUA[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_uua";
static const char UDIF_NETWORK_DESIGNATION_UGC[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_ugc";
static const char UDIF_NETWORK_DESIGNATION_ALL[UDIF_NETWORK_DESIGNATION_SIZE] = "udif_network_designation_all";

/*!
 * \def UDIF_PROTOCOL_SET_SIZE
 * \brief The size of the protocol configuration string.
 */
#define UDIF_PROTOCOL_SET_SIZE 41U

 /* Valid parameter sets:
 Kyber-S1, Dilithium-S1
 Kyber-S3, Dilithium-S3
 Kyber-S5, Dilithium-S5
 Kyber-S6, Dilithium-S5
 McEliece-S1, Sphincs-S1(f,s)
 McEliece-S3, Sphincs-S3(f,s)
 McEliece-S5, Sphincs-S5(f,s)
 McEliece-S6, Sphincs-S5(f,s)
 McEliece-S7, Sphincs-S6(f,s) */

 /** \cond */

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
#elif defined(UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF1M1) 
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-1f_mceliece-s1_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S1S128SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-1s_mceliece-s1_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF3M3)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-3f_mceliece-s3_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S3S192SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-3s_mceliece-s3_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M5)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s5_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s5_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M6)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s6_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s6_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
#elif defined(UDIF_PARAMATERS_SPHINCSF_MCELIECE_SF5M7)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5f_mceliece-s7_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
#define UDIF_SUITE_ID 13U
#elif defined(UDIF_PARAMATERS_SPHINCSPLUS_S5S256SHAKERS)
static const char UDIF_CONFIG_STRING[UDIF_PROTOCOL_SET_SIZE] = "sphincs-5s_mceliece-s7_rcs-256_sha3-256";
static const udif_configuration_sets UDIF_CONFIGURATION_SET = udif_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
#else
#	error Invalid parameter set!
#endif

/** \endcond */

/* Role/Designation Strings */

#define UDIF_ROLE_STRING_SIZE 32U

/** \cond */
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
/** \endcond */


/* Error String Tables */

/*!
 * \def UDIF_ERROR_STRING_DEPTH
 * \brief Number of entries per error string table.
 */
#define UDIF_ERROR_STRING_DEPTH 16U

/*!
 * \def UDIF_ERROR_STRING_SIZE
 * \brief Maximum size of an error string.
 */
#define UDIF_ERROR_STRING_SIZE 128U

/** \cond */

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

/* Capability errors */
static const char UDIF_CAPABILITY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Capability denied by policy",
	"Empty capability mask",
	"Conflicting capability bits"
};

/* Policy errors */
static const char UDIF_POLICY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Policy not found",
	"Policy hash mismatch",
	"Policy evaluation indeterminate"
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

/** \endcond */

/* UDIF Structures */

/*!
 * \struct udif_time_window
 * \brief A validity interval expressed in UTC seconds.
 */
UDIF_EXPORT_API typedef struct udif_time_window
{
	uint64_t not_before;			/*!< Start of validity window (epoch seconds) */
	uint64_t not_after;				/*!< End of validity window (epoch seconds) */
} udif_time_window;

/*!
 * \struct udif_capability_mask
 * \brief Fixed-size capability bitset (issuer-/role-scoped).
 * Capability bits; bit positions map to udif_capability_id
 */
UDIF_EXPORT_API typedef struct udif_capability_mask
{
	uint8_t bits[UDIF_CAPABILITY_MASK_SIZE];
} udif_capability_mask;

/*!
 * \struct udif_permission_mask
 * \brief Fixed-size permission bitset (subject-/resource-scoped).
 * Permission bits; bit positions map to udif_permission_class
 */
UDIF_EXPORT_API typedef struct udif_permission_mask
{
	uint8_t bits[UDIF_PERMISSION_MASK_SIZE];
} udif_permission_mask;

/*!
 * \struct udif_identity_id
 * \brief Subject identity identifier (opaque, canonicalized).
 * Subject identifier bytes
 */
UDIF_EXPORT_API typedef struct udif_identity_id
{
	uint8_t bytes[UDIF_IDENTITY_ID_SIZE];
} udif_identity_id;

/*!
 * \struct udif_namespace_code
 * \brief Namespace partition identifier.
 * Namespace code (ASCII or compact code)
 */
UDIF_EXPORT_API typedef struct udif_namespace_code
{
	uint8_t bytes[UDIF_NAMESPACE_CODE_SIZE];
} udif_namespace_code;

/*!
 * \struct udif_issuer_domain_code
 * \brief Issuer domain/controller identifier.
 * Issuer domain code (ASCII or compact code)
 */
UDIF_EXPORT_API typedef struct udif_issuer_domain_code
{
	uint8_t bytes[UDIF_ISSUER_DOMAIN_CODE_SIZE];
} udif_issuer_domain_code;

/*!
 * \struct udif_policy_hash
 * \brief Policy identifier (hash of canonical policy).
 * SHA3/SHAKE hash of policy document
 */
UDIF_EXPORT_API typedef struct udif_policy_hash
{
	uint8_t bytes[UDIF_POLICY_HASH_SIZE];
} udif_policy_hash;

/*!
 * \struct udif_claim_anchor
 * \brief Anchor (e.g., Merkle root) binding a claim set to an identity.
 * Anchor/merkle root over canonical claim set
 */
UDIF_EXPORT_API typedef struct udif_claim_anchor
{
	uint8_t bytes[UDIF_CLAIM_ANCHOR_SIZE];
} udif_claim_anchor;


/* Certificates */

/*!
 * \enum udif_version_sets
 * \brief The UDIF version sets.
 */
UDIF_EXPORT_API typedef enum udif_version_sets
{
	udif_version_set_none = 0x00U,									/*!< No version identifier is set */
	udif_version_set_one_zero = 0x01U,								/*!< The 1.0 version identifier */
} udif_version_sets;

/* public structures */

/*!
 * \struct udif_certificate_expiration
 * \brief The certificate expiration time structure.
 */
UDIF_EXPORT_API typedef struct udif_certificate_expiration
{
	uint64_t from;													/*!< The starting time in seconds */
	uint64_t to;													/*!< The expiration time in seconds */
} udif_certificate_expiration;

/*!
 * \struct udif_child_certificate
 * \brief The child certificate structure.
 */
UDIF_EXPORT_API typedef struct udif_child_certificate
{
	uint8_t csig[UDIF_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	char issuer[UDIF_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	uint8_t serial[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	udif_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	udif_network_designations designation;							/*!< The certificate type designation */
	udif_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
	uint8_t capability[UDIF_CAPABILITY_MASK_SIZE];					/*!< The capability bitmap */
} udif_child_certificate;

/*!
 * \def UDIF_X509_CERTIFICATE_SIZE
 * \brief x509 implementation where algorithm/signature output size is stored.
 */
#define UDIF_X509_CERTIFICATE_SIZE 4096U

 /*!
  * \def UDIF_IDG_HINT_SIZE
  * \brief Hint query; certificate hash, root serial number hi=(H(cert) | rsn)
  * idg query asks if a peer knows of the root security server for a domain;
  * if the peer does know the root of the other domain, it sends back information
  * about that rds (address, certificate hash, root serial number, and trust metric).
  */
#define UDIF_IDG_HINT_SIZE (UDIF_CERTIFICATE_HASH_SIZE + UDIF_CERTIFICATE_SERIAL_SIZE)

  /*!
   * \struct udif_idg_hint
   * \brief The IDG hint structure.
   */
UDIF_EXPORT_API typedef struct udif_idg_hint
{
	uint8_t chash[UDIF_CERTIFICATE_HASH_SIZE];						/*!< The remote certificate's signed hash */
	uint8_t rootser[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The remote certificate's root serial number */
} udif_idg_hint;

/*!
 * \struct udif_idg_certificate
 * \brief The IDG certificate structure.
 *
 * The IDG certificate structure contains the necessary fields for identification and verification
 * of an inter-domain gateway. (Note: A field for a serialized x509 certificate may be added in future revisions.)
 */
UDIF_EXPORT_API typedef struct udif_idg_certificate
{
	uint8_t csig[UDIF_CERTIFICATE_SIGNED_HASH_SIZE];				/*!< The certificate's signed hash */
	uint8_t vkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public verification key */
	uint8_t xcert[UDIF_X509_CERTIFICATE_SIZE];						/*!< The serialized X509 certificate */
	uint8_t serial[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	uint8_t rootser[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The root certificate's serial number */
	uint8_t hint[UDIF_IDG_HINT_SIZE];								/*!< The certificate's topological hint  */
	char issuer[UDIF_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer */
	udif_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	udif_network_designations designation;							/*!< The certificate type designation */
	udif_configuration_sets algorithm;								/*!< The algorithm configuration identifier */
	uint8_t version;												/*!< The certificate version */
	uint8_t capability[UDIF_CAPABILITY_MASK_SIZE];					/*!< The capability bitmap */
} udif_idg_certificate;

/*!
 * \struct udif_connection_state
 * \brief The UDIF socket connection state structure.
 */
UDIF_EXPORT_API typedef struct udif_connection_state
{
	qsc_socket target;												/*!< The target socket structure */
	udif_cipher_state rxcpr;										/*!< The receive channel cipher state */
	udif_cipher_state txcpr;										/*!< The transmit channel cipher state */
	uint64_t rxseq;													/*!< The receive channel's packet sequence number */
	uint64_t txseq;													/*!< The transmit channel's packet sequence number */
	uint32_t instance;												/*!< The connection's instance count */
	udif_network_flags exflag;										/*!< The network stage flag */
} udif_connection_state;

/*!
 * \struct udif_keep_alive_state
 * \brief The UDIF keep alive state structure.
 */
UDIF_EXPORT_API typedef struct udif_keep_alive_state
{
	qsc_socket target;												/*!< The target socket structure */
	uint64_t etime;													/*!< The keep alive epoch time  */
	uint64_t seqctr;												/*!< The keep alive packet sequence counter  */
	bool recd;														/*!< The keep alive response received status  */
} udif_keep_alive_state;

/*!
 * \struct udif_network_packet
 * \brief The UDIF packet structure.
 */
UDIF_EXPORT_API typedef struct udif_network_packet
{
	uint8_t flag;													/*!< The packet flag */
	uint32_t msglen;												/*!< The packet's message length */
	uint64_t sequence;												/*!< The packet sequence number */
	uint64_t utctime;												/*!< The UTC time the packet was created (in seconds) */
	uint8_t* pmessage;												/*!< A pointer to the packet's message buffer */
} udif_network_packet;

/*!
 * \struct udif_root_certificate
 * \brief The root certificate structure.
 *
 * The root certificate structure contains the fields for the UDIF root (trust anchor)
 * including the public verification key, issuer information, certificate serial, validity times,
 * algorithm identifier, and version.
 */
UDIF_EXPORT_API typedef struct udif_root_certificate
{
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The serialized public key */
	char issuer[UDIF_CERTIFICATE_ISSUER_SIZE];						/*!< The certificate issuer text name */
	uint8_t serial[UDIF_CERTIFICATE_SERIAL_SIZE];					/*!< The certificate serial number */
	udif_certificate_expiration expiration;							/*!< The from and to certificate expiration times */
	udif_configuration_sets algorithm;								/*!< The signature algorithm identifier */
	udif_version_sets version;										/*!< The certificate version type */
	uint8_t capability[UDIF_CAPABILITY_MASK_SIZE];					/*!< The capability bitmap */
} udif_root_certificate;

/*!
 * \struct udif_serialized_symmetric_key
 * \brief The structure for a serialized symmetric key.
 */
UDIF_EXPORT_API typedef struct udif_serialized_symmetric_key
{
	uint64_t keyid;													/*!< The key identity */
	uint8_t key[UDIF_CRYPTO_SYMMETRIC_KEY_SIZE];					/*!< The symmetric key */
	uint8_t nonce[UDIF_CRYPTO_SYMMETRIC_NONCE_SIZE];				/*!< The symmetric nonce */
} udif_serialized_symmetric_key;

/*!
 * \struct udif_signature_keypair
 * \brief The UDIF asymmetric signature scheme key container.
 */
UDIF_EXPORT_API typedef struct udif_signature_keypair
{
	uint8_t prikey[UDIF_ASYMMETRIC_SIGNING_KEY_SIZE];				/*!< The secret signing key */
	uint8_t pubkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The public signature verification key */
} udif_signature_keypair;

/*!
 * \struct udif_cipher_keypair
 * \brief The UDIF asymmetric cipher key container.
 */
UDIF_EXPORT_API typedef struct udif_cipher_keypair
{
	uint8_t prikey[UDIF_ASYMMETRIC_PRIVATE_KEY_SIZE];				/*!< The asymmetric cipher private key */
	uint8_t pubkey[UDIF_ASYMMETRIC_PUBLIC_KEY_SIZE];				/*!< The asymmetric cipher public key */
} udif_cipher_keypair;


/* Identity & Claims */

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
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE];		/*!< Subject verification key (if key-bearing id) */
	uint8_t chash[UDIF_CERTIFICATE_HASH_SIZE];				/*!< Canonical record hash */
	uint8_t signature[UDIF_ASYMMETRIC_SIGNATURE_SIZE];			/*!< Issuer signature over identity record */
} udif_identity_record;


/* Tokens */

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
	udif_token_header head;                                 /*!< Common token header */
	udif_identity_id subject;                               /*!< Subject to whom the token applies */
	udif_capability_mask caps;                              /*!< Capabilities conveyed (if applicable) */
	udif_permission_mask perms;                             /*!< Permissions conveyed (if applicable) */
	uint8_t payload[UDIF_CAPABILITY_TOKEN_MAX_SIZE];		/*!< Serialized payload (claims subset, attestations, etc.) */
	uint32_t payload_len;									/*!< Payload length in bytes */
	uint8_t chash[UDIF_CERTIFICATE_HASH_SIZE];				/*!< Canonical token hash */
	uint8_t signature[UDIF_ASYMMETRIC_SIGNATURE_SIZE];			/*!< Issuer signature over token */
} udif_token;


/* Encoded Blobs & Helpers */

/*!
 * \struct udif_encoded_blob
 * \brief Generic encoded object buffer (for decode/encode APIs).
 */
UDIF_EXPORT_API typedef struct udif_encoded_blob
{
	uint8_t* bytes;                                            /*!< Pointer to external buffer */
	uint32_t size;                                             /*!< Allocated buffer size */
	uint32_t length;                                           /*!< Actual data length after (en|de)code */
} udif_encoded_blob;

#define UDIF_NETWORK_ERROR_STRING_DEPTH 28U
#define UDIF_NETWORK_ERROR_STRING_SIZE 128U

/** \cond */

static const char UDIF_NETWORK_ERROR_STRINGS[UDIF_NETWORK_ERROR_STRING_DEPTH][UDIF_NETWORK_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The cipher authentication has failed",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connnection to the remote host",
	"The decryption authentication has failed",
	"The transmission failed at the kex establish phase",
	"The connection experienced an unexpected error",
	"The server has run out of socket connections",
	"The random generator experienced a failure",
	"The input is invalid",
	"The request is invalid",
	"The keep alive has expired with no response",
	"The keepalive failure counter has exceeded maximum ",
	"The kex authentication has failed",
	"The key-id is not recognized",
	"The certificate has expired",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The random generator experienced a failure",
	"The random generator experienced a failure",
	"The ratchet operation has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol version is unknown",
	"The packet was received out of sequence",
	"The expected data could not be verified"
};

#define UDIF_PROTOCOL_ERROR_STRING_DEPTH 44U
#define UDIF_PROTOCOL_ERROR_STRING_SIZE 128U

static const char UDIF_PROTOCOL_ERROR_STRINGS[UDIF_PROTOCOL_ERROR_STRING_DEPTH][UDIF_PROTOCOL_ERROR_STRING_SIZE] =
{
	"No error was detected",
	"The symmetric cipher had an authentication failure",
	"The node certificate could not be found",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The convergence call has returned an error",
	"The database is already synchronized",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The node or certificate decoding failed",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The application could not delete a local file",
	"The file could not be found",
	"The file could not be written to storage",
	"The public-key hash is invalid",
	"The server has run out of socket connections",
	"The packet flag was unexpected",
	"The certificate has expired and is invalid",
	"The UDIF public key has expired ",
	"The key identity is unrecognized",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The network time is invalid or has substantial delay",
	"The expected data could not be verified",
	"The server has no usable IP address, assign in configuration",
	"The node is offline or not available for connection",
	"The node could not be found in the database",
	"The node was previously registered in the database",
	"The operation was cancelled by the user",
	"The packet header received was invalid",
	"The packet was received out of sequence",
	"The receiver failed at the network layer",
	"The root signature failed authentication",
	"The certificate could not be serialized",
	"The signature scheme could not sign a message",
	"The transmission failed to sign the data",
	"The socket could not be bound to an IP address",
	"The socket could not be created",
	"The transmitter failed at the network layer",
	"The topological database has no aps entries",
	"The protocol string was not recognized",
	"The transmission failed at the KEX verify phase"
};

/** \endcond */


/* API */

/**
 * \brief Close the network connection between hosts.
 *
 * \param rsock A pointer to the socket structure representing the connection.
 * \param err The network error code to report.
 * \param notify If true, notify the remote host that the connection is closing.
 */
UDIF_EXPORT_API void udif_connection_close(qsc_socket* rsock, udif_network_errors err, bool notify);

/**
 * \brief Decrypt a message and copy it to the output buffer.
 *
 * \param cns A pointer to the connection state structure.
 * \param message The output array for the decrypted message.
 * \param msglen A pointer to a variable that will receive the length of the decrypted message.
 * \param packetin [const] A pointer to the input packet structure.
 *
 * \return Returns the network error state.
 */
UDIF_EXPORT_API udif_protocol_errors udif_decrypt_packet(udif_connection_state* cns, uint8_t* message, size_t* msglen, const udif_network_packet* packetin);

/**
 * \brief Encrypt a message and build an output packet.
 *
 * \param cns A pointer to the connection state structure.
 * \param packetout A pointer to the output packet structure.
 * \param message [const] The input message array.
 * \param msglen The length of the input message.
 *
 * \return Returns the network error state.
 */
UDIF_EXPORT_API udif_protocol_errors udif_encrypt_packet(udif_connection_state* cns, udif_network_packet* packetout, const uint8_t* message, size_t msglen);

/**
 * \brief Dispose of the tunnel connection state.
 *
 * \param cns A pointer to the connection state structure to dispose.
 */
UDIF_EXPORT_API void udif_connection_state_dispose(udif_connection_state* cns);

/**
 * \brief Return a pointer to a string description of a network error code.
 *
 * \param error The network error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
UDIF_EXPORT_API const char* udif_network_error_to_string(udif_network_errors error);

/**
 * \brief Return a pointer to a string description of a protocol error code.
 *
 * \param error The protocol error code.
 *
 * \return Returns a pointer to an error string or NULL if the code is unrecognized.
 */
UDIF_EXPORT_API const char* udif_protocol_error_to_string(udif_protocol_errors error);

/**
 * \brief Clear the state of a network packet.
 *
 * \param packet A pointer to the packet structure to clear.
 */
UDIF_EXPORT_API void udif_packet_clear(udif_network_packet* packet);

/**
 * \brief Populate a packet structure with an error message.
 *
 * \param packet A pointer to the packet structure.
 * \param error The protocol error code to embed in the packet.
 */
UDIF_EXPORT_API void udif_packet_error_message(udif_network_packet* packet, udif_protocol_errors error);

/**
 * \brief Deserialize a byte array into a packet header.
 *
 * \param header [const] The header byte array to deserialize.
 * \param packet A pointer to the packet structure that will be populated.
 */
UDIF_EXPORT_API void udif_packet_header_deserialize(const uint8_t* header, udif_network_packet* packet);

/**
 * \brief Serialize a packet header into a byte array.
 *
 * \param packet [const] A pointer to the packet structure to serialize.
 * \param header The byte array that will receive the serialized header.
 */
UDIF_EXPORT_API void udif_packet_header_serialize(const udif_network_packet* packet, uint8_t* header);

/**
 * \brief Set the local UTC time in the packet header.
 *
 * \param packet A pointer to the network packet.
 */
UDIF_EXPORT_API void udif_packet_set_utc_time(udif_network_packet* packet);

/**
 * \brief Check if the packet's UTC time is within the valid time threshold.
 *
 * \param packet [const] A pointer to the network packet.
 *
 * \return Returns true if the packet was received within the valid time threshold.
 */
UDIF_EXPORT_API bool udif_packet_time_valid(const udif_network_packet* packet);

/**
 * \brief Serialize a network packet to a byte stream.
 *
 * \param packet [const] A pointer to the packet.
 * \param pstream A pointer to the output byte stream.
 *
 * \return Returns the size of the serialized byte stream.
 */
UDIF_EXPORT_API size_t udif_packet_to_stream(const udif_network_packet* packet, uint8_t* pstream);

/**
 * \brief Deserialize a byte stream into a network packet.
 *
 * \param pstream [const] The byte stream containing the packet data.
 * \param packet A pointer to the packet structure to populate.
 */
UDIF_EXPORT_API void udif_stream_to_packet(const uint8_t* pstream, udif_network_packet* packet);

#endif