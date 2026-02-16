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

#ifndef UDIF_OBJECT_H
#define UDIF_OBJECT_H

#include "udif.h"

/**
* \file object.h
* \brief UDIF object operations
*
* This module implements object lifecycle management for UDIF.
* Objects are polymorphic containers that can represent identities,
* assets, commodities, or any ownable entity.
*
* Object Lifecycle:
* - Create: New object signed by creator
* - Transfer: Bi-modal signed ownership transfer
* - Update: Attribute root update by owner
* - Destroy: Mark as destroyed (never deleted)
*
* All objects maintain:
* - Immutable serial number
* - Creator certificate reference
* - Current owner
* - Attribute Merkle root
* - Creation and update timestamps
* - Owner signature
*/

/*!
 * \def UDIF_OBJECT_FLAG_DESTROYED
 * \brief Object flag bits.
 */
#define UDIF_OBJECT_FLAG_DESTROYED 0x01U

/*! \def UDIF_OBJECT_FLAG_SIZE
 * \brief Object flag size in bytes
 */
#define UDIF_OBJECT_FLAG_SIZE 4U

/*! \def UDIF_OBJECT_TYPE_SIZE
 * \brief Object type size in bytes
 */
#define UDIF_OBJECT_TYPE_SIZE 4U

/*! \def UDIF_OBJECT_ENCODED_SIZE
 * \brief The encoded object record size
 */
#define UDIF_OBJECT_ENCODED_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_STRUCTURE_SIZE + \
	UDIF_OBJECT_FLAG_SIZE + \
	UDIF_OBJECT_TYPE_SIZE)

/*! \def UDIF_OBJECT_SIGNING_SIZE
 * \brief The encoded object record signing size
 */
#define UDIF_OBJECT_SIGNING_SIZE (UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_STRUCTURE_SIZE + \
	UDIF_OBJECT_FLAG_SIZE + \
	UDIF_OBJECT_TYPE_SIZE)

/*! \def UDIF_OBJECT_TRANSFER_SIZE
 * \brief The object transfer buffer size
 */
#define UDIF_OBJECT_TRANSFER_SIZE (UDIF_SERIAL_NUMBER_SIZE + \
    UDIF_SERIAL_NUMBER_SIZE + \
    UDIF_SERIAL_NUMBER_SIZE + \
    UDIF_VALID_TIME_SIZE)

/*! \def UDIF_TRANSFER_RECORD_ENCODED_SIZE
 * \brief The encoded transfer record size
 */
#define UDIF_TRANSFER_RECORD_ENCODED_SIZE (UDIF_SIGNED_HASH_SIZE + \
	UDIF_SIGNED_HASH_SIZE + \
	UDIF_CRYPTO_HASH_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_VALID_TIME_SIZE)


 /*!
 * \struct udif_object
 * \brief UDIF object container
 *
 * Objects are polymorphic containers that can represent identities,
 * assets, or any commodifiable entity. They have a lifecycle and
 * ownership chain tracked through signatures.
 */
UDIF_EXPORT_API typedef struct udif_object
{
	uint8_t signature[UDIF_SIGNED_HASH_SIZE];	/*!< Owner signature */
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];	/*!< Attribute Merkle root */
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE];	/*!< Object serial number */
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE];	/*!< Creator certificate serial */
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE];		/*!< Current owner serial */
	uint64_t created;							/*!< Creation timestamp */
	uint64_t updated;							/*!< Last update timestamp */
	uint32_t flags;								/*!< Object flags */
	uint32_t type;								/*!< Object type code */
} udif_object;

/*!
* \struct udif_transfer_record
* \brief Object transfer record
*
* Records a bi-modal signed transfer of object ownership.
*/
UDIF_EXPORT_API typedef struct udif_transfer_record
{
	uint8_t sender[UDIF_SIGNED_HASH_SIZE];		/*!< Sender signature */
	uint8_t receiver[UDIF_SIGNED_HASH_SIZE];	/*!< Receiver signature */
	uint8_t txid[UDIF_CRYPTO_HASH_SIZE];				/*!< Transaction ID */
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE];	/*!< Object serial */
	uint8_t originator[UDIF_SERIAL_NUMBER_SIZE];/*!< Previous owner */
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE];		/*!< New owner */
	uint64_t timestamp;							/*!< Transfer time */
} udif_transfer_record;

/*!
* \brief Clear an object
*
* Zeros out an object structure.
*
* \param obj: The object to clear
*/
UDIF_EXPORT_API void udif_object_clear(udif_object* obj);

/*!
* \brief Compare two objects
*
* Checks if two objects are identical.
*
* \param a: [const] The first object
* \param b: [const] The second object
*
* \return Returns true if identical
*/
UDIF_EXPORT_API bool udif_object_compare(const udif_object* a, const udif_object* b);

/*!
* \brief Compute object digest
*
* Computes the canonical digest for an object, does not include the signature and hash.
*
* \param digest: The output digest (32 bytes)
* \param obj: [const] The object
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_compute_digest(uint8_t* digest, const udif_object* obj);

/*!
* \brief Compute object digest and signature
*
* Computes the canonical digest for an object, and signs the object.
*
* \param obj: The object
* \param sigkey: [const] The owner's private key
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_compute_signature(udif_object* obj, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Compute transfer object digest
*
* Computes the canonical digest for an object transfer.
*
* \param digest: The output digest (32 bytes)
* \param objserial: [const] The object serial number
* \param txid: [const] The transfer id
* \param toowner: [const] The new object owner
* \param timestamp: The current timestamp
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_compute_transfer_digest(uint8_t* digest, const uint8_t* objserial, const uint8_t* txid, const uint8_t* toowner, uint64_t timestamp);

/*!
* \brief Create a new object
*
* Creates a new object and signs it with the creator's private key.
* The creator becomes the initial owner.
*
* \param obj: The output object structure
* \param serial: [const] The object serial number (32 bytes)
* \param type: The object type code
* \param creator: [const] The creator certificate serial (16 bytes)
* \param attrroot: [const] The initial attribute Merkle root (32 bytes)
* \param owner: [const] The initial owner serial (16 bytes)
* \param sigkey: [const] The owner's private signing key
* \param ctime: The current time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_create(udif_object* obj, const uint8_t* serial, uint32_t type, const uint8_t* creator, const uint8_t* attrroot, 
	const uint8_t* owner, const uint8_t* sigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Deserialize an object
*
* Decodes an object from canonical TLV format.
*
* \param obj: The output object structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_deserialize(udif_object* obj, const uint8_t* input, size_t inplen);

/*!
* \brief Mark object as destroyed
*
* Sets the destroyed flag. Object is never deleted, just flagged.
*
* \param obj: The object to destroy
* \param ownersigkey: [const] The owner's private key
* \param ctime: The current time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_destroy(udif_object* obj, const uint8_t* ownersigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Check if object is destroyed
*
* Tests the destroyed flag.
*
* \param obj: [const] The object
*
* \return Returns true if destroyed
*/
UDIF_EXPORT_API bool udif_object_is_destroyed(const udif_object* obj);

/*!
* \brief Serialize an object
*
* Encodes an object to canonical TLV format.
*
* \param output: The output buffer
* \param outlen: The output buffer length
* \param obj: [const] The object to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_serialize(uint8_t* output, size_t outlen, const udif_object* obj);

/*!
* \brief Transfer object ownership
*
* Transfers ownership using bi-modal signatures (sender and receiver).
* Creates a transfer record that must be logged.
*
* \param obj: The object to transfer (will be updated)
* \param transfer: The output transfer record
* \param newowner: [const] The new owner serial (16 bytes)
* \param sendsigkey: [const] The current owner's private key
* \param recvsigkey: [const] The new owner's private key
* \param ctime: The current time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_transfer(udif_object* obj, udif_transfer_record* transfer, const uint8_t* newowner, const uint8_t* sendsigkey, 
	const uint8_t* recvsigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Update object attributes
*
* Updates the attribute Merkle root and timestamp, signed by owner.
*
* \param obj: The object to update
* \param newattrroot: [const] The new attribute root (32 bytes)
* \param ownersigkey: [const] The owner's private key
* \param ctime: The current time (UTC seconds)
* \param rng_generate: Random number generator function
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_object_update_attributes(udif_object* obj, const uint8_t* newattrroot, const uint8_t* ownersigkey, uint64_t ctime, 
	bool (*rng_generate)(uint8_t*, size_t));

/*!
* \brief Verify object signature
*
* Verifies the object signature matches the current owner.
*
* \param obj: [const] The object to verify
* \param ownerverkey: [const] The owner's public key
*
* \return Returns true if signature is valid
*/
UDIF_EXPORT_API bool udif_object_verify(const udif_object* obj, const uint8_t* ownerverkey);

/*!
* \brief Clear a transfer record
*
* Zeros out a transfer record structure.
*
* \param transfer: The transfer record to clear
*/
UDIF_EXPORT_API void udif_transfer_clear(udif_transfer_record* transfer);

/*!
* \brief Deserialize a transfer record
*
* Decodes a transfer record from canonical format.
*
* \param transfer: The output transfer record structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_transfer_deserialize(udif_transfer_record* transfer, const uint8_t* input, size_t inplen);

/*!
* \brief Serialize a transfer record
*
* Encodes a transfer record to canonical format.
*
* \param output: The output buffer
* \param outlen: The output array length
* \param transfer: [const] The transfer record to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_transfer_serialize(uint8_t* output, size_t outlen, const udif_transfer_record* transfer);

/*!
* \brief Verify transfer record
*
* Verifies both sender and receiver signatures on a transfer.
*
* \param transfer: [const] The transfer record
* \param senderverkey: [const] The sender's public key
* \param recvverkey: [const] The receiver's public key
*
* \return Returns true if both signatures are valid
*/
UDIF_EXPORT_API bool udif_transfer_verify(const udif_transfer_record* transfer, const uint8_t* senderverkey, const uint8_t* recvverkey);

#endif
