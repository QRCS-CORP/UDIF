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

#ifndef UDIFREGISTRY_H
#define UDIFREGISTRY_H

#include "udif.h"
#include "object.h"

 /**
 * \file registry.h
 * \brief UDIF object registry management
 *
 * This module implements Merkle tree-based registries for User Agents.
 * Each User Agent maintains a registry of owned objects as a Merkle tree,
 * allowing efficient membership proofs and tamper-evident commits.
 *
 * Registry Operations:
 * - Initialize: Create empty registry
 * - Add: Add object to registry
 * - Remove: Remove object from registry
 * - Update: Update object in registry
 * - Commit: Compute Merkle root
 * - Prove: Generate membership proof
 * - Verify: Verify membership proof
 *
 * The registry uses SHA3-256 for Merkle tree hashing with domain
 * separation to prevent cross-context attacks.
 */

/*!
* \def UDIF_REGISTRY_DEFAULT_CAPACITY
* \brief Default registry capacity.
*/
#define UDIF_REGISTRY_DEFAULT_CAPACITY 1024U

/*!
* \def UDIF_REGISTRY_MAX_CAPACITY
* \brief Maximum registry capacity.
*/
#define UDIF_REGISTRY_MAX_CAPACITY 1048576U


/*!
 * \def UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE
 * \brief Serialized size of a signed registry commitment record.
 */
#define UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE (UDIF_SIGNED_HASH_SIZE + \
    UDIF_SERIAL_NUMBER_SIZE + \
    UDIF_CRYPTO_HASH_SIZE + \
    sizeof(uint64_t) + \
    sizeof(uint64_t))

/*!
 * \struct udif_registry_commit
 * \brief Signed canonical registry root commitment.
 *
 * A registry commitment binds an owner serial, registry Merkle root,
 * monotonic registry epoch, and UTC timestamp to the committing entity's
 * signature. The signature covers all fields except the signature itself.
 */
UDIF_EXPORT_API typedef struct udif_registry_commit
{
	uint8_t signature[UDIF_SIGNED_HASH_SIZE];		/*!< Committer signature */
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE];		/*!< Registry owner serial */
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE];			/*!< Registry Merkle root */
	uint64_t epoch;								/*!< Registry state epoch */
	uint64_t timestamp;							/*!< UTC commit time */
} udif_registry_commit;

/*!
* \struct udif_merkle_node
* \brief Merkle proof node structure.
*/
UDIF_EXPORT_API typedef struct udif_merkle_node
{
	uint8_t hash[UDIF_CRYPTO_HASH_SIZE];		/*!< The node hash */
	bool isleft;								/*!< The hash orientation */
} udif_merkle_node;

/*!
* \def UDIF_REGISTRY_FLAG_ACTIVE
* \brief Registry leaf active-state flag.
*/
#define UDIF_REGISTRY_FLAG_ACTIVE 0x00000001UL

/*!
* \def UDIF_REGISTRY_FLAG_DESTROYED
* \brief Registry leaf destroyed-state flag.
*/
#define UDIF_REGISTRY_FLAG_DESTROYED 0x00000002UL

/*!
* \def UDIF_REGISTRY_FLAG_TRANSFERRED
* \brief Registry leaf transferred-state flag.
*/
#define UDIF_REGISTRY_FLAG_TRANSFERRED 0x00000004UL

/*!
* \struct udif_registry_leaf
* \brief Canonical UDIF registry leaf.
*/
UDIF_EXPORT_API typedef struct udif_registry_leaf
{
	uint8_t objdigest[UDIF_CRYPTO_HASH_SIZE];	/*!< Object digest */
	uint8_t ownerdigest[UDIF_CRYPTO_HASH_SIZE];	/*!< Owner certificate digest */
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE];	/*!< Object serial lookup key */
	uint64_t timestamp;						/*!< Leaf update time */
	uint32_t flags;							/*!< Registry status flags */
} udif_registry_leaf;

/*!
* \struct udif_registry_state
* \brief User Agent object registry
*
* Each User Agent maintains a registry of owned objects as canonical
* registry leaves. Merkle roots are computed over the canonical
* leaf encodings sorted lexicographically by object digest.
*/
UDIF_EXPORT_API typedef struct udif_registry_state
{
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE];	/*!< Owner serial number */
	uint8_t ownerdigest[UDIF_CRYPTO_HASH_SIZE];	/*!< Owner certificate digest */
	qsc_keccak_state mstate;					/*!< Merkle tree state */
	udif_registry_leaf* leaves;				/*!< Canonical registry leaves */
	size_t objcount;							/*!< Number of leaves */
	size_t capacity;							/*!< Registry capacity */
	bool initialized;							/*!< Initialization flag */
} udif_registry_state;

/*!
* \brief Encode a registry leaf in canonical UDIF order.
*
* \param output: The output buffer.
* \param leaf: [const] The registry leaf.
*
* 
eturn Returns udif_error_none on success.
*/
UDIF_EXPORT_API udif_errors udif_registry_leaf_encode(uint8_t* output, const udif_registry_leaf* leaf);

/*!
* \brief Compute a registry leaf digest.
*
* \param digest: The output leaf digest.
* \param leaf: [const] The registry leaf.
*
* 
eturn Returns udif_error_none on success.
*/
UDIF_EXPORT_API udif_errors udif_registry_leaf_digest(uint8_t* digest, const udif_registry_leaf* leaf);

/*!
* \brief Add an object to the registry
*
* Adds an object's digest to the registry Merkle tree.
*
* \param reg: The registry state structure
* \param obj: [const] The object to add
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_add_object(udif_registry_state* reg, const udif_object* obj);

/*!
* \brief Add or update a canonical registry leaf.
*
* Adds a canonical leaf to the registry or updates the existing leaf with
* the same object serial. The registry remains sorted by object digest.
*
* \param reg: The registry state structure.
* \param leaf: [const] The canonical leaf to store.
*
* \return Returns udif_error_none on success.
*/
UDIF_EXPORT_API udif_errors udif_registry_add_leaf(udif_registry_state* reg, const udif_registry_leaf* leaf);

/*!
* \brief Copy a registry leaf by object serial.
*
* \param leaf: The output leaf.
* \param reg: [const] The registry state structure.
* \param serial: [const] The object serial (32 bytes).
*
* \return Returns udif_error_none on success.
*/
UDIF_EXPORT_API udif_errors udif_registry_get_leaf(udif_registry_leaf* leaf, const udif_registry_state* reg, const uint8_t* serial);

/*!
* \brief Test whether a registry leaf is active.
*
* \param reg: [const] The registry state structure.
* \param serial: [const] The object serial (32 bytes).
*
* \return Returns true if the object is present and active.
*/
UDIF_EXPORT_API bool udif_registry_object_is_active(const udif_registry_state* reg, const uint8_t* serial);

/*!
* \brief Move an object leaf from one owner registry to another.
*
* Marks the origin registry leaf as transferred and inactive, then creates
* or updates the destination registry leaf as active under the destination
* owner digest.
*
* \param origin: The origin owner registry.
* \param dest: The destination owner registry.
* \param transfer: [const] The verified transfer record.
*
* \return Returns udif_error_none on success.
*/
UDIF_EXPORT_API udif_errors udif_registry_transfer_object(udif_registry_state* origin, udif_registry_state* dest, const udif_transfer_record* transfer);

/*!
* \brief Get registry capacity
*
* Returns the current capacity of the registry.
*
* \param reg: [const] The registry state structure
*
* \return The registry capacity
*/
UDIF_EXPORT_API size_t udif_registry_get_capacity(const udif_registry_state* reg);

/*!
* \brief Clear registry
*
* Removes all objects from the registry without freeing resources.
*
* \param reg: The registry state structure
*/
UDIF_EXPORT_API void udif_registry_clear(udif_registry_state* reg);

/*!
* \brief Compute registry Merkle root
*
* Computes the Merkle root of all objects in the registry.
*
* \param root: The output Merkle root (32 bytes)
* \param reg: [const] The registry state structure
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_compute_root(uint8_t* root, const udif_registry_state* reg);

/*!
* \brief Dispose registry
*
* Frees all resources and clears the registry.
*
* \param reg: The registry state structure
*/
UDIF_EXPORT_API void udif_registry_dispose(udif_registry_state* reg);

/*!
* \brief Find object in registry
*
* Searches for an object by serial number.
*
* \param reg: [const] The registry state structure
* \param serial: [const] The object serial (32 bytes)
* \param index: Pointer to receive the object index
*
* \return Returns true if found
*/
UDIF_EXPORT_API bool udif_registry_find_object(const udif_registry_state* reg, const uint8_t* serial, size_t* index);

/*!
* \brief Generate membership proof
*
* Generates a Merkle inclusion proof for an object in the registry.
*
* \param proof: The output proof buffer
* \param prooflen: Pointer to proof length (in: buffer size, out: bytes written)
* \param reg: [const] The registry state structure
* \param serial: [const] The object serial (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_generate_proof(uint8_t* proof, size_t* prooflen, const udif_registry_state* reg, const uint8_t* serial);

/*!
* \brief Get object count
*
* Returns the number of objects in the registry.
*
* \param reg: [const] The registry state structure
*
* \return The object count
*/
UDIF_EXPORT_API size_t udif_registry_get_count(const udif_registry_state* reg);

/*!
* \brief Get registry leaf digest at index
*
* Retrieves the canonical registry leaf digest at a specific index.
*
* \param digest: The output leaf digest (32 bytes)
* \param reg: [const] The registry state structure
* \param index: The object index
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_get_digest_at(uint8_t* digest, const udif_registry_state* reg, size_t index);

/*!
* \brief Initialize a registry
*
* Creates an empty registry for a User Agent.
*
* \param reg: The registry state structure
* \param ownerser: [const] The owner's serial number (16 bytes)
* \param incapacity: The initial capacity (number of objects)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_initialize(udif_registry_state* reg, const uint8_t* ownerser, size_t capacity);

/*!
* \brief Check if registry is full
*
* Tests if the registry has reached capacity.
*
* \param reg: [const] The registry state structure
*
* \return Returns true if full
*/
UDIF_EXPORT_API bool udif_registry_is_full(const udif_registry_state* reg);

/*!
* \brief Remove an object from the registry
*
* Marks an object leaf as destroyed without removing the audit leaf.
*
* \param reg: The registry state structure
* \param serial: [const] The object serial (32 bytes)
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_remove_object(udif_registry_state* reg, const uint8_t* serial);

/*!
* \brief Resize registry
*
* Increases the registry capacity.
*
* \param reg: The registry state structure
* \param newcapacity: The new capacity
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_resize(udif_registry_state* reg, size_t newcapacity);

/*!
* \brief Update an object in the registry
*
* Updates an object's digest in the registry.
*
* \param reg: The registry state structure
* \param obj: [const] The updated object
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_registry_update_object(udif_registry_state* reg, const udif_object* obj);

/*!
* \brief Verify membership proof
*
* Verifies a Merkle inclusion proof against a registry root using the
* canonical left/right proof orientation emitted by udif_registry_get_proof.
*
* \param proof: [const] The proof data
* \param prooflen: The proof length
* \param root: [const] The registry Merkle root (32 bytes)
* \param objdigest: [const] The object digest (32 bytes)
*
* \return Returns true if proof is valid
*/
UDIF_EXPORT_API bool udif_registry_verify_proof(const uint8_t* proof, size_t prooflen, const uint8_t* root, const uint8_t* objdigest);

/*!
 * \brief Clear a registry commitment record.
 *
 * \param commit: The registry commitment record.
 */
UDIF_EXPORT_API void udif_registry_commit_clear(udif_registry_commit* commit);

/*!
 * \brief Compute the canonical digest of a registry commitment.
 *
 * \param digest: The output digest.
 * \param commit: [const] The registry commitment.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_registry_commit_digest(uint8_t* digest, const udif_registry_commit* commit);

/*!
 * \brief Deserialize a signed registry commitment.
 *
 * \param commit: The output commitment.
 * \param input: [const] The encoded commitment.
 * \param inlen: The encoded commitment length.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_registry_commit_deserialize(udif_registry_commit* commit, const uint8_t* input, size_t inlen);

/*!
 * \brief Serialize a signed registry commitment.
 *
 * \param output: The output buffer.
 * \param outlen: The output buffer size.
 * \param commit: [const] The commitment to serialize.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_registry_commit_serialize(uint8_t* output, size_t outlen, const udif_registry_commit* commit);

/*!
 * \brief Sign a registry commitment.
 *
 * \param commit: The registry commitment.
 * \param sigkey: [const] The signing key.
 * \param rng_generate: The random generator.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_registry_commit_sign(udif_registry_commit* commit, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t));

/*!
 * \brief Verify a registry commitment signature.
 *
 * \param commit: [const] The registry commitment.
 * \param verkey: [const] The signer verification key.
 *
 * \return Returns true if the signature is valid.
 */
UDIF_EXPORT_API bool udif_registry_commit_verify(const udif_registry_commit* commit, const uint8_t* verkey);

#endif
