/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * UDIF Implementation (Universal Digital Identification Framework)
 * Based on UDIF Specification Revision 1a, September 05, 2025
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef UDIFREGISTRY_H
#define UDIFREGISTRY_H

#include "udif.h"
#include "object.h"

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
* \struct udif_merkle_node
* \brief Merkle proof node structure.
*/
UDIF_EXPORT_API typedef struct udif_merkle_node
{
	uint8_t hash[UDIF_CRYPTO_HASH_SIZE];		/*!< The node hash */
	bool isleft;								/*!< The hash orientation */
} udif_merkle_node;

/*!
* \struct udif_registry_state
* \brief User Agent object registry
*
* Each User Agent maintains a registry of owned objects as a Merkle tree.
* The registry root is committed periodically to the Group Controller.
*/
UDIF_EXPORT_API typedef struct udif_registry_state
{
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE];	/*!< Owner serial number */
	qsc_keccak_state mstate;                    /*!< Merkle tree state */
	uint8_t* objdigests;						/*!< Object digest array */
	uint8_t* objserials;						/*!< Object serial array */
	size_t objcount;							/*!< Number of objects */
	size_t capacity;                            /*!< Registry capacity */
	bool initialized;                           /*!< Initialization flag */
} udif_registry_state;


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
* \param serial: [const] The object serial (16 bytes)
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
* \param serial: [const] The object serial (16 bytes)
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
* \brief Get object digest at index
*
* Retrieves the digest of an object at a specific index.
*
* \param digest: The output digest (32 bytes)
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
* Removes an object's digest from the registry.
*
* \param reg: The registry state structure
* \param serial: [const] The object serial
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
* Verifies a Merkle inclusion proof against a registry root.
*
* \param proof: [const] The proof data
* \param prooflen: The proof length
* \param root: [const] The registry Merkle root (32 bytes)
* \param object_digest: [const] The object digest (32 bytes)
*
* \return Returns true if proof is valid
*/
UDIF_EXPORT_API bool udif_registry_verify_proof(const uint8_t* proof, size_t prooflen, const uint8_t* root, const uint8_t* objdigest);

#endif
