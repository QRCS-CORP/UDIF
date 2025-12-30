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
 * \brief UDIF Certificate Handling Functions.
 *
 * \details
 * This header defines the functions for managing and processing certificates used by the
 * Anonymous Encrypted Relay Network (UDIF). The certificate module is responsible for creating,
 * encoding, decoding, serializing, deserializing, signing, and verifying both child (device)
 * and root (trust anchor) certificates. These certificates carry critical information such as:
 *
 * - The issuer identity.
 * - Certificate validity periods.
 * - Public verification keys.
 * - Algorithm configuration identifiers.
 * - Digital signatures produced by the root certificate.
 *
 * The functions provided in this module allow conversion between protocol-set strings and their
 * enumerated representations, as well as conversion of network-designation values between string and
 * enumerated forms. They also perform cryptographic operations such as hashing and digital signing,
 * using the underlying QSC cryptographic primitives.
 *
 * \note
 * The certificate functions depend on the QSC library for routines including SHA3 (Keccak),
 * base64 encoding/decoding, file I/O, and memory utilities. The active UDIF configuration (protocol-set)
 * is used to automatically populate certificate fields.
 *
 * \test
 * When the UDIF_DEBUG_TESTS_RUN macro is defined, the function
 * \ref udif_certificate_functions_test() executes a series of self-tests that verify:
 *
 * - **Algorithm Conversion:** That protocol-set strings are correctly decoded into enumerated values
 *   (and vice versa) via udif_certificate_algorithm_decode() and udif_certificate_algorithm_encode().
 *
 * - **Child Certificate Operations:** The creation (udif_certificate_child_create()), signing
 *   (udif_certificate_root_sign()), encoding (udif_certificate_child_encode()),
 *   serialization/deserialization (udif_certificate_child_serialize()/udif_certificate_child_deserialize()),
 *   and validity testing (udif_certificate_child_is_valid()) of child certificates.
 *
 * - **Root Certificate Operations:** The creation (udif_certificate_root_create()), encoding
 *   (udif_certificate_root_encode()), serialization/deserialization (udif_certificate_root_serialize()/udif_certificate_root_deserialize()),
 *   and verification (udif_certificate_root_signature_verify()) of root certificates.
 *
 * - **Equality and Copy:** That child certificates can be compared (udif_certificate_child_are_equal())
 *   and copied (udif_certificate_child_copy()) correctly.
 *
 * - **Expiration and Signature Functions:** That certificate expiration is properly set and verified,
 *   and that messages can be hashed and signed/verified (udif_certificate_message_hash_sign() and
 *   udif_certificate_signature_verify_message()).
 *
 * These tests help ensure that the certificate operations function as expected in real-world use.
 */


/* Function Prototypes */

/**
 * \brief Decode the string algorithm-set number to the enumerated representation.
 *
 * \param name [in, const] The protocol-set string (for example, "dilithium-s1_kyber-s1_rcs-256_sha3-256").
 *
 * \return Returns the corresponding protocol-set enumerator.
 */
UDIF_EXPORT_API udif_configuration_sets udif_certificate_algorithm_decode(const char* name);

/**
 * \brief Test if the specified protocol-set is enabled on this system.
 *
 * \param conf The protocol-set enumerator to test.
 *
 * \return Returns true if the given protocol-set is enabled; otherwise, false.
 */
UDIF_EXPORT_API bool udif_certificate_algorithm_enabled(udif_configuration_sets conf);

/**
 * \brief Encode the protocol-set enumerator into its string form.
 *
 * \param name [out] The output buffer that will receive the protocol-set string.
 * \param conf The protocol-set enumerator to encode.
 */
UDIF_EXPORT_API void udif_certificate_algorithm_encode(char* name, udif_configuration_sets conf);

/**
 * \brief Compare two child certificates for equivalence.
 *
 * This function compares all the significant fields of two child certificate structures
 * (including algorithm, version, designation, expiration, issuer, serial, signature, and public key).
 *
 * \param a [in, const] The first certificate.
 * \param b [in, const] The second certificate.
 *
 * \return Returns true if the two certificates are equal.
 */
UDIF_EXPORT_API bool udif_certificate_child_are_equal(const udif_child_certificate* a, const udif_child_certificate* b);

/**
 * \brief Copy a child certificate structure.
 *
 * This function performs a deep copy of the child certificate from the \p input structure to the
 * \p output structure.
 *
 * \param output [out] The destination child certificate.
 * \param input [in, const] The source child certificate.
 */
UDIF_EXPORT_API void udif_certificate_child_copy(udif_child_certificate* output, const udif_child_certificate* input);

/**
 * \brief Create a child certificate.
 *
 * This function initializes and populates a child certificate structure with the provided public key,
 * expiration information, issuer string, and designation.
 *
 * \param child [out] A pointer to the empty child certificate to populate.
 * \param pubkey [in] A pointer to the public signature key.
 * \param expiration [in, const] The certificate expiration time structure.
 * \param issuer [in, const] The certificate issuer string.
 * \param designation The certificate designation type (e.g. aps, client, etc.).
 */
UDIF_EXPORT_API void udif_certificate_child_create(udif_child_certificate* child, const uint8_t* pubkey, const udif_certificate_expiration* expiration, 
	const char* issuer, udif_network_designations designation, const uint8_t* capability);

/**
 * \brief Decode a child certificate string into a certificate structure.
 *
 * This function decodes an encoded child certificate string (with a fixed maximum size) into its
 * corresponding certificate structure.
 *
 * \param child [out] The pointer to the child certificate structure to populate.
 * \param enck [in] The encoded certificate string.
 *
 * \return Returns true if the certificate was successfully decoded.
 */
UDIF_EXPORT_API bool udif_certificate_child_decode(udif_child_certificate* child, const char enck[UDIF_CHILD_CERTIFICATE_STRING_SIZE]);

/**
 * \brief Deserialize a child certificate from a byte array.
 *
 * This function converts a serialized child certificate (stored as a byte stream) into a certificate structure.
 *
 * \param child [out] The pointer to the child certificate structure to populate.
 * \param input [in, const] The input byte array containing the serialized certificate.
 */
UDIF_EXPORT_API void udif_certificate_child_deserialize(udif_child_certificate* child, const uint8_t* input);

/**
 * \brief Encode a public child certificate into a human-readable string.
 *
 * This function encodes the given child certificate into a formatted string representation.
 *
 * \param enck [out] The output buffer that will receive the encoded certificate string.
 * \param child [in, const] The child certificate to encode.
 *
 * \return Returns the size of the encoded certificate string.
 */
UDIF_EXPORT_API size_t udif_certificate_child_encode(char enck[UDIF_CHILD_CERTIFICATE_STRING_SIZE], const udif_child_certificate* child);

/**
 * \brief Delete (erase) a child certificate.
 *
 * This function securely erases all fields of a child certificate structure.
 *
 * \param child [in,out] A pointer to the child certificate to erase.
 */
UDIF_EXPORT_API void udif_certificate_child_erase(udif_child_certificate* child);

/**
 * \brief Copy a serialized certificate from a file into a child certificate structure.
 *
 * This function reads a file containing a serialized child certificate, deserializes it, and populates
 * the provided certificate structure.
 *
 * \param fpath [in, const] The file path from which to load the certificate.
 * \param child [out] A pointer to the child certificate structure.
 *
 * \return Returns true on success.
 */
UDIF_EXPORT_API bool udif_certificate_child_file_to_struct(const char* fpath, udif_child_certificate* child);

/**
 * \brief Compute the cryptographic hash of a child certificate.
 *
 * The hash is computed over key fields such as algorithm, designation, version, expiration, issuer,
 * serial, and public verification key.
 *
 * \param output [out] The output hash array (size: UDIF_CERTIFICATE_HASH_SIZE).
 * \param child [in, const] A pointer to the child certificate.
 */
UDIF_EXPORT_API void udif_certificate_child_hash(uint8_t* output, const udif_child_certificate* child);

/**
 * \brief Test a child certificate for a valid format and expiration.
 *
 * This function checks that the certificate fields (including algorithm, designation, version,
 * signature, serial, and public key) are nonzero and that the current time is within the expiration period.
 *
 * \param child [in, const] A pointer to the child certificate.
 *
 * \return Returns true if the certificate is valid.
 */
UDIF_EXPORT_API bool udif_certificate_child_is_valid(const udif_child_certificate* child);

/**
 * \brief Verify a message signature using a child certificate.
 *
 * This function uses the public verification key from the child certificate to verify that a given
 * signature correctly authenticates a message.
 *
 * \param message [out] The output buffer for the recovered message (if applicable).
 * \param msglen [in,out] A pointer to the length of the recovered message.
 * \param signature [in, const] A pointer to the signature.
 * \param siglen The length of the signature.
 * \param child [in, const] A pointer to the child certificate.
 *
 * \return Returns true if the message signature is verified.
 */
UDIF_EXPORT_API bool udif_certificate_child_message_verify(uint8_t* message, size_t* msglen, const uint8_t* signature, size_t siglen, const udif_child_certificate* child);

/**
 * \brief Serialize a child certificate into a contiguous byte array.
 *
 * \param output [out] A pointer to the array receiving the serialized certificate (size: UDIF_CERTIFICATE_CHILD_SIZE).
 * \param child [in, const] The child certificate to serialize.
 */
UDIF_EXPORT_API void udif_certificate_child_serialize(uint8_t* output, const udif_child_certificate* child);

/**
 * \brief Verify that a signature hash matches a computed message hash using a child certificate.
 *
 * This function first verifies the signature using the child certificate's public key and then
 * compares the resulting hash to an independently computed hash of the message.
 *
 * \param signature [in, const] A pointer to the signed hash.
 * \param siglen The length of the signed hash.
 * \param message [in, const] A pointer to the message.
 * \param msglen The length of the message.
 * \param lcert [in, const] A pointer to the child certificate used for verification.
 *
 * \return Returns true if the signature hash verifies correctly.
 */
UDIF_EXPORT_API bool udif_certificate_signature_hash_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const udif_child_certificate* lcert);

/**
 * \brief Write a child certificate structure to a file.
 *
 * \param fpath [in, const] The file path where the certificate will be stored.
 * \param child [in, const] A pointer to the child certificate structure.
 *
 * \return Returns true on success.
 */
UDIF_EXPORT_API bool udif_certificate_child_struct_to_file(const char* fpath, const udif_child_certificate* child);

/**
 * \brief Decode the network-designation string to its enumerated representation.
 *
 * \param sdsg [in, const] The network-designation string.
 *
 * \return Returns the corresponding network-designation enumerator.
 */
UDIF_EXPORT_API udif_network_designations udif_certificate_designation_decode(const char* sdsg);

/**
 * \brief Encode the network-designation enumerator into a string.
 *
 * \param sdsg [out] The output buffer that will receive the encoded network-designation string.
 * \param designation The certificate designation type.
 *
 * \return Returns the size of the encoded string.
 */
UDIF_EXPORT_API size_t udif_certificate_designation_encode(char* sdsg, udif_network_designations designation);

/**
 * \brief Set the expiration days on a certificate expiration structure.
 *
 * This function sets the \p from and \p to fields of the expiration structure using day intervals.
 *
 * \param expiration [in,out] A pointer to the expiration structure.
 * \param start The number of days until the certificate becomes valid.
 * \param duration The number of days the certificate remains valid.
 */
UDIF_EXPORT_API void udif_certificate_expiration_set_days(udif_certificate_expiration* expiration, uint16_t start, uint16_t duration);

/**
 * \brief Set the expiration seconds on a certificate expiration structure.
 *
 * \param expiration [in,out] A pointer to the expiration structure.
 * \param start The number of seconds to delay before the certificate becomes valid.
 * \param period The number of seconds the certificate remains valid.
 */
UDIF_EXPORT_API void udif_certificate_expiration_set_seconds(udif_certificate_expiration* expiration, uint64_t start, uint64_t period);

/**
 * \brief Verify the expiration time against the current UTC time.
 *
 * \param expiration [in, const] A pointer to the expiration time structure.
 *
 * \return Returns true if the current time is within the certificate's validity period.
 */
UDIF_EXPORT_API bool udif_certificate_expiration_time_verify(const udif_certificate_expiration* expiration);

/**
 * \brief Hash a message and sign the hash.
 *
 * This function computes the SHA3-256 hash of the provided message and then signs that hash using
 * the given private signature key.
 *
 * \param signature [out] The array receiving the signature (size: UDIF_ASYMMETRIC_SIGNATURE_SIZE).
 * \param sigkey [in, const] The private signature key.
 * \param message [in, const] The message to sign.
 * \param msglen The length of the message.
 *
 * \return Returns the size of the generated signature.
 */
UDIF_EXPORT_API size_t udif_certificate_message_hash_sign(uint8_t* signature, const uint8_t* sigkey, const uint8_t* message, size_t msglen);

/**
 * \brief Compare two root certificates for equivalence.
 *
 * This function compares the key fields of two root certificates to determine if they are equal.
 *
 * \param a [in, const] The first root certificate.
 * \param b [in, const] The second root certificate.
 *
 * \return Returns true if the certificates are equivalent.
 */
UDIF_EXPORT_API bool udif_certificate_root_compare(const udif_root_certificate* a, const udif_root_certificate* b);

/**
 * \brief Create a root certificate.
 *
 * This function creates a root certificate by populating its fields with the provided public key,
 * expiration structure, and issuer name. The generated certificate serves as the trust anchor.
 *
 * \param root [out] A pointer to the empty root certificate to populate.
 * \param pubkey [in] A pointer to the public signature key.
 * \param expiration [in, const] The certificate expiration time structure.
 * \param issuer [in, const] The issuer name string.
 */
UDIF_EXPORT_API void udif_certificate_root_create(udif_root_certificate* root, const uint8_t* pubkey, const udif_certificate_expiration* expiration, const char* issuer);

/**
 * \brief Decode a root certificate string into a certificate structure.
 *
 * This function decodes an encoded root certificate string into its corresponding root certificate structure.
 *
 * \param root [out] The pointer to the root certificate structure to populate.
 * \param enck [in, const] The encoded certificate string.
 *
 * \return Returns true if the certificate was successfully decoded.
 */
UDIF_EXPORT_API bool udif_certificate_root_decode(udif_root_certificate* root, const char* enck);

/**
 * \brief Deserialize a root certificate from a byte array.
 *
 * \param root [out] A pointer to the root certificate structure to populate.
 * \param input [in, const] A pointer to the input byte array (size: UDIF_CERTIFICATE_ROOT_SIZE).
 */
UDIF_EXPORT_API void udif_certificate_root_deserialize(udif_root_certificate* root, const uint8_t* input);

/**
 * \brief Encode a public root certificate into a human-readable string.
 *
 * This function encodes the given root certificate into a formatted string.
 *
 * \param enck [out] The output buffer that will receive the encoded certificate string.
 * \param root [in, const] The root certificate to encode.
 *
 * \return Returns the size of the encoded certificate string.
 */
UDIF_EXPORT_API size_t udif_certificate_root_encode(char* enck, const udif_root_certificate* root);

/**
 * \brief Delete (erase) a root certificate.
 *
 * This function securely erases all fields of a root certificate structure.
 *
 * \param root [in,out] A pointer to the root certificate to erase.
 */
UDIF_EXPORT_API void udif_certificate_root_erase(udif_root_certificate* root);

/**
 * \brief Copy a serialized root certificate from a file into a root certificate structure.
 *
 * \param fpath [in, const] The file path from which to read the certificate.
 * \param root [out] A pointer to the root certificate structure to populate.
 *
 * \return Returns true on success.
 */
UDIF_EXPORT_API bool udif_certificate_root_file_to_struct(const char* fpath, udif_root_certificate* root);

/**
 * \brief Compute the cryptographic hash of a root certificate.
 *
 * The hash is computed over key fields such as algorithm, version, expiration times,
 * issuer, serial, and public key.
 *
 * \param output [out] The output hash array.
 * \param root [in, const] A pointer to the root certificate.
 */
UDIF_EXPORT_API void udif_certificate_root_hash(uint8_t* output, const udif_root_certificate* root);

/**
 * \brief Serialize a root certificate into a contiguous byte array.
 *
 * \param output [out] A pointer to the array receiving the serialized certificate (size: UDIF_CERTIFICATE_ROOT_SIZE).
 * \param root [in, const] The root certificate to serialize.
 */
UDIF_EXPORT_API void udif_certificate_root_serialize(uint8_t* output, const udif_root_certificate* root);

/**
 * \brief Sign a child certificate with the root certificate.
 *
 * This function hashes the child certificate, copies the root certificate serial number into the child,
 * and then produces a digital signature over the child certificate hash using the provided root signing key.
 *
 * \param child [in,out] A pointer to the child certificate to sign.
 * \param root [in, const] A pointer to the root certificate.
 * \param rsigkey [in, const] A pointer to the root private signing key.
 *
 * \return Returns the size of the generated signature.
 */
UDIF_EXPORT_API size_t udif_certificate_root_sign(udif_child_certificate* child, const udif_root_certificate* root, const uint8_t* rsigkey);

/**
 * \brief Verify a child certificate against a root certificate.
 *
 * This function verifies that the digital signature on the child certificate (stored in its signed hash)
 * was produced by the given root certificate.
 *
 * \param child [in, const] A pointer to the child certificate.
 * \param root [in, const] A pointer to the root certificate.
 *
 * \return Returns true if the child certificate signature is valid.
 */
UDIF_EXPORT_API bool udif_certificate_root_signature_verify(const udif_child_certificate* child, const udif_root_certificate* root);

/**
 * \brief Write a root certificate structure to a file.
 *
 * \param fpath [in, const] The file path where the certificate will be written.
 * \param root [in, const] A pointer to the root certificate structure.
 *
 * \return Returns true on success.
 */
UDIF_EXPORT_API bool udif_certificate_root_struct_to_file(const char* fpath, const udif_root_certificate* root);

/**
 * \brief Validate a root certificate.
 *
 * This function checks that the root certificate fields are nonzero and that the current time
 * is within its expiration period.
 *
 * \param root [in, const] A pointer to the root certificate.
 *
 * \return Returns true if the root certificate is valid.
 */
UDIF_EXPORT_API bool udif_certificate_root_is_valid(const udif_root_certificate* root);

/**
 * \brief Generate and encode an asymmetric signature scheme keypair.
 *
 * This function generates a new keypair for the UDIF asymmetric signature scheme and populates the
 * provided keypair container.
 *
 * \param keypair [out] A pointer to the keypair container.
 */
UDIF_EXPORT_API void udif_certificate_signature_generate_keypair(udif_signature_keypair* keypair);

/**
 * \brief Sign a message using the asymmetric signature scheme.
 *
 * \param signature [out] The array that will receive the signature (size: UDIF_ASYMMETRIC_SIGNATURE_SIZE).
 * \param message [in, const] The message to sign.
 * \param msglen The length of the message.
 * \param prikey [in] The private signature key.
 *
 * \return Returns the length of the generated signature.
 */
UDIF_EXPORT_API size_t udif_certificate_signature_sign_message(uint8_t* signature, const uint8_t* message, size_t msglen, const uint8_t* prikey);

/**
 * \brief Verify a message signature using the asymmetric signature scheme.
 *
 * \param message [in, const] The original message.
 * \param msglen The length of the message.
 * \param signature [in, const] The signature to verify.
 * \param siglen The length of the signature.
 * \param pubkey [in] The public signature verification key.
 *
 * \return Returns true if the signature is verified.
 */
UDIF_EXPORT_API bool udif_certificate_signature_verify_message(const uint8_t* message, size_t msglen, const uint8_t* signature, size_t siglen, const uint8_t* pubkey);

#if defined(UDIF_DEBUG_TESTS_RUN)
/**
 * \brief Test the certificate functions.
 *
 * This function runs a suite of self-tests that verify:
 * - Correct conversion between protocol-set strings and enumerated configuration sets.
 * - Successful creation, signing, encoding, serialization, deserialization, and equality checking of both
 *   root and child certificates.
 * - Proper functioning of expiration, hashing, and signature verification routines.
 *
 * \return Returns true if all certificate function tests pass.
 */
UDIF_EXPORT_API bool udif_certificate_functions_test(void);
#endif

#endif
