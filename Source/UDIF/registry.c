#include "registry.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

static void merkle_parent_hash(uint8_t* output, const uint8_t* left, const uint8_t* right)
{
	/* compute parent hash in Merkle tree */
	uint8_t buf[UDIF_CRYPTO_HASH_SIZE * 2U] = { 0U };

	/* combine left || right */
	qsc_memutils_copy(buf, left, UDIF_CRYPTO_HASH_SIZE);
	qsc_memutils_copy(buf + UDIF_CRYPTO_HASH_SIZE, right, UDIF_CRYPTO_HASH_SIZE);

	/* compute digest */
	qsc_cshake256_compute(output, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_REGROOT, sizeof(UDIF_LABEL_REGROOT) - 1U, NULL, 0U);

	/* clear temporary buffer */
	qsc_memutils_clear(buf, sizeof(buf));
}

udif_errors udif_registry_add_object(udif_registry_state* reg, const udif_object* obj)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(obj != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && obj != NULL && reg->initialized == true)
	{
		/* check capacity */
		if (reg->objcount < reg->capacity)
		{
			/* check if object already exists */
			if (udif_registry_find_object(reg, obj->serial, NULL) == false)
			{
				/* compute object digest */
				udif_object_compute_digest(digest, obj);

				/* add digest to registry */
				qsc_memutils_copy(reg->objdigests + (reg->objcount * UDIF_CRYPTO_HASH_SIZE), digest, UDIF_CRYPTO_HASH_SIZE);

				/* add serial to registry */
				qsc_memutils_copy(reg->objserials + (reg->objcount * UDIF_SERIAL_NUMBER_SIZE), obj->serial, UDIF_SERIAL_NUMBER_SIZE);

				++reg->objcount;
				qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
				err = udif_error_none;
			}
			else
			{
				err = udif_error_invalid_state;
			}
		}
		else
		{
			err = udif_error_registry_full;
		}
	}

	return err;
}

void udif_registry_clear(udif_registry_state* reg)
{
	if (reg != NULL && reg->initialized == true)
	{
		qsc_memutils_clear(reg->objdigests, reg->capacity * UDIF_CRYPTO_HASH_SIZE);
		qsc_memutils_clear(reg->objserials, reg->capacity * UDIF_SERIAL_NUMBER_SIZE);
		reg->objcount = 0U;
	}
}

udif_errors udif_registry_compute_root(uint8_t* root, const udif_registry_state* reg)
{
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(reg != NULL);

	uint8_t* tree;
	size_t tree_size;
	size_t level_size;
	size_t i;
	udif_errors err;

	err = udif_error_invalid_input;

	if (root != NULL && reg != NULL && reg->initialized == true)
	{
		if (reg->objcount == 0U)
		{
			/* empty registry: hash of zero bytes */
			qsc_memutils_clear(root, UDIF_CRYPTO_HASH_SIZE);
			err = udif_error_none;
		}
		else if (reg->objcount == 1U)
		{
			/* single object: root is the object digest */
			qsc_memutils_copy(root, reg->objdigests, UDIF_CRYPTO_HASH_SIZE);
			err = udif_error_none;
		}
		else
		{
			/* compute Merkle tree */
			tree_size = qsc_intutils_next_power_of_2(reg->objcount) * 2U;
			tree = (uint8_t*)qsc_memutils_malloc(tree_size * UDIF_CRYPTO_HASH_SIZE);

			if (tree != NULL)
			{
				/* copy leaf nodes */
				qsc_memutils_copy(tree, reg->objdigests, reg->objcount * UDIF_CRYPTO_HASH_SIZE);

				/* pad with zeros if needed */
				level_size = qsc_intutils_next_power_of_2(reg->objcount);

				if (reg->objcount < level_size)
				{
					qsc_memutils_clear(tree + (reg->objcount * UDIF_CRYPTO_HASH_SIZE), (level_size - reg->objcount) * UDIF_CRYPTO_HASH_SIZE);
				}

				/* build tree bottom-up */
				while (level_size > 1U)
				{
					for (i = 0; i < level_size / 2U; i++)
					{
						merkle_parent_hash(tree + (level_size + i) * UDIF_CRYPTO_HASH_SIZE, tree + (i * 2U) * UDIF_CRYPTO_HASH_SIZE,
							tree + ((i * 2U) + 1U) * UDIF_CRYPTO_HASH_SIZE
						);
					}

					/* move to next level */
					qsc_memutils_copy(tree, tree + (level_size * UDIF_CRYPTO_HASH_SIZE), (level_size / 2U) * UDIF_CRYPTO_HASH_SIZE);
					level_size /= 2U;
				}

				/* root is at index 0 */
				qsc_memutils_copy(root, tree, UDIF_CRYPTO_HASH_SIZE);

				/* clear and free tree */
				qsc_memutils_clear(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
				qsc_memutils_alloc_free(tree);

				err = udif_error_none;
			}
			else
			{
				err = udif_error_internal;
			}
		}
	}

	return err;
}

void udif_registry_dispose(udif_registry_state* reg)
{
	if (reg != NULL && reg->initialized == true)
	{
		/* clear and free digest array */
		if (reg->objdigests != NULL)
		{
			qsc_memutils_clear(reg->objdigests, reg->capacity * UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_alloc_free(reg->objdigests);
			reg->objdigests = NULL;
		}

		/* clear and free serial array */
		if (reg->objserials != NULL)
		{
			qsc_memutils_clear(reg->objserials, reg->capacity * UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_alloc_free(reg->objserials);
			reg->objserials = NULL;
		}

		qsc_keccak_dispose(&reg->mstate);
		qsc_memutils_clear((uint8_t*)reg, sizeof(udif_registry_state));
	}
}

bool udif_registry_find_object(const udif_registry_state* reg, const uint8_t* serial, size_t* index)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (reg != NULL && serial != NULL && reg->initialized == true)
	{
		for (size_t i = 0U; i < reg->objcount; ++i)
		{
			if (qsc_memutils_are_equal(reg->objserials + (i * UDIF_SERIAL_NUMBER_SIZE), serial, UDIF_SERIAL_NUMBER_SIZE) == true)
			{
				if (index != NULL)
				{
					*index = i;
				}

				res = true;
				break;
			}
		}
	}

	return res;
}

udif_errors udif_registry_generate_proof(uint8_t* proof, size_t* prooflen, const udif_registry_state* reg, const uint8_t* serial)
{
	UDIF_ASSERT(proof != NULL);
	UDIF_ASSERT(prooflen != NULL);
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	uint8_t* tree;
	size_t index;
	size_t level_size;
	size_t proof_pos;
	size_t tree_size;
	udif_errors err;

	err = udif_error_invalid_input;

	if (proof != NULL && prooflen != NULL && reg != NULL && serial != NULL && reg->initialized == true)
	{
		/* find object */
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			if (reg->objcount == 1U)
			{
				/* single object: empty proof */
				*prooflen = 0;
				err = udif_error_none;
			}
			else
			{
				/* build Merkle tree */
				tree_size = qsc_intutils_next_power_of_2(reg->objcount) * 2U;

				tree = (uint8_t*)qsc_memutils_malloc(tree_size * UDIF_CRYPTO_HASH_SIZE);

				if (tree != NULL)
				{
					/* copy leaf nodes */
					qsc_memutils_copy(tree, reg->objdigests, reg->objcount * UDIF_CRYPTO_HASH_SIZE);

					/* pad with zeros */
					level_size = qsc_intutils_next_power_of_2(reg->objcount);

					if (reg->objcount < level_size)
					{
						qsc_memutils_clear(tree + (reg->objcount * UDIF_CRYPTO_HASH_SIZE), (level_size - reg->objcount) * UDIF_CRYPTO_HASH_SIZE);
					}

					proof_pos = 0U;

					/* collect sibling hashes up the tree */
					while (level_size > 1U)
					{
						/* get sibling index */
						size_t sibling;

						sibling = (index & 1) ? (index - 1U) : (index + 1U);

						/* copy sibling hash to proof */
						qsc_memutils_copy(proof + proof_pos, tree + (sibling * UDIF_CRYPTO_HASH_SIZE), UDIF_CRYPTO_HASH_SIZE);
						proof_pos += UDIF_CRYPTO_HASH_SIZE;

						/* store direction bit (0 = sibling is left, 1 = sibling is right) */
						proof[proof_pos] = (uint8_t)(index & 1);
						++proof_pos;

						/* build next level */
						for (size_t i = 0U; i < level_size / 2U; ++i)
						{
							merkle_parent_hash(tree + (level_size + i) * UDIF_CRYPTO_HASH_SIZE, tree + (i * 2U) * UDIF_CRYPTO_HASH_SIZE,
								tree + ((i * 2U) + 1U) * UDIF_CRYPTO_HASH_SIZE);
						}

						/* move to next level */
						qsc_memutils_copy(tree, tree + (level_size * UDIF_CRYPTO_HASH_SIZE), (level_size / 2U) * UDIF_CRYPTO_HASH_SIZE);
						index /= 2U;
						level_size /= 2U;
					}

					*prooflen = proof_pos;

					/* clear and free tree */
					qsc_memutils_clear(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_alloc_free(tree);

					err = udif_error_none;
				}
				else
				{
					err = udif_error_internal;
				}
			}
		}
		else
		{
			err = udif_error_object_not_found;
		}
	}

	return err;
}

size_t udif_registry_get_capacity(const udif_registry_state* reg)
{
	UDIF_ASSERT(reg != NULL);

	size_t capacity;

	capacity = 0U;

	if (reg != NULL && reg->initialized == true)
	{
		capacity = reg->capacity;
	}

	return capacity;
}

size_t udif_registry_get_count(const udif_registry_state* reg)
{
	UDIF_ASSERT(reg != NULL);

	size_t count;

	count = 0U;

	if (reg != NULL && reg->initialized == true)
	{
		count = reg->objcount;
	}

	return count;
}

udif_errors udif_registry_get_digest_at(uint8_t* digest, const udif_registry_state* reg, size_t index)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(reg != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (digest != NULL && reg != NULL && reg->initialized == true && index < reg->objcount)
	{
		qsc_memutils_copy(digest, reg->objdigests + (index * UDIF_CRYPTO_HASH_SIZE), UDIF_CRYPTO_HASH_SIZE);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_registry_initialize(udif_registry_state* reg, const uint8_t* ownerser, size_t capacity)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(ownerser != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && ownerser != NULL && capacity > 0 && capacity <= UDIF_REGISTRY_MAX_CAPACITY)
	{
		qsc_memutils_clear((uint8_t*)reg, sizeof(udif_registry_state));

		/* allocate digest array */
		reg->objdigests = (uint8_t*)qsc_memutils_malloc(capacity * UDIF_CRYPTO_HASH_SIZE);

		if (reg->objdigests != NULL)
		{
			/* allocate serial array */
			reg->objserials = (uint8_t*)qsc_memutils_malloc(capacity * UDIF_SERIAL_NUMBER_SIZE);

			if (reg->objserials != NULL)
			{
				qsc_memutils_copy(reg->ownerser, ownerser, UDIF_SERIAL_NUMBER_SIZE);
				reg->capacity = capacity;
				reg->objcount = 0U;
				reg->initialized = true;

				qsc_keccak_initialize_state(&reg->mstate);

				err = udif_error_none;
			}
			else
			{
				/* clean up digest array on serial allocation failure */
				qsc_memutils_alloc_free(reg->objdigests);
				reg->objdigests = NULL;
				err = udif_error_internal;
			}
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

bool udif_registry_is_full(const udif_registry_state* reg)
{
	UDIF_ASSERT(reg != NULL);

	bool res;

	res = true;

	if (reg != NULL && reg->initialized == true)
	{
		res = (reg->objcount >= reg->capacity);
	}

	return res;
}

udif_errors udif_registry_remove_object(udif_registry_state* reg, const uint8_t* serial)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	size_t index;
	size_t mlen;
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && serial != NULL && reg->initialized == true)
	{
		/* find object */
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			/* move remaining objects down */
			if (index < reg->objcount - 1U)
			{
				/* move digests */
				mlen = (reg->objcount - index - 1U) * UDIF_CRYPTO_HASH_SIZE;
				qsc_memutils_move(reg->objdigests + (index * UDIF_CRYPTO_HASH_SIZE), reg->objdigests + ((index + 1U) * UDIF_CRYPTO_HASH_SIZE), mlen);

				/* move serials */
				mlen = (reg->objcount - index - 1U) * UDIF_SERIAL_NUMBER_SIZE;
				qsc_memutils_move(reg->objserials + (index * UDIF_SERIAL_NUMBER_SIZE), reg->objserials + ((index + 1U) * UDIF_SERIAL_NUMBER_SIZE), mlen);
			}

			/* clear last slots */
			qsc_memutils_clear(reg->objdigests + ((reg->objcount - 1U) * UDIF_CRYPTO_HASH_SIZE), UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_clear(reg->objserials + ((reg->objcount - 1U) * UDIF_SERIAL_NUMBER_SIZE), UDIF_SERIAL_NUMBER_SIZE);
			--reg->objcount;

			err = udif_error_none;
		}
		else
		{
			err = udif_error_object_not_found;
		}
	}

	return err;
}

udif_errors udif_registry_resize(udif_registry_state* reg, size_t newcapacity)
{
	UDIF_ASSERT(reg != NULL);

	uint8_t* new_digests;
	uint8_t* new_serials;
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && reg->initialized == true && newcapacity > reg->capacity && newcapacity <= UDIF_REGISTRY_MAX_CAPACITY)
	{
		/* allocate new digest array */
		new_digests = (uint8_t*)qsc_memutils_malloc(newcapacity * UDIF_CRYPTO_HASH_SIZE);

		if (new_digests != NULL)
		{
			/* allocate new serial array */
			new_serials = (uint8_t*)qsc_memutils_malloc(newcapacity * UDIF_SERIAL_NUMBER_SIZE);

			if (new_serials != NULL)
			{
				/* copy existing digests */
				qsc_memutils_copy(new_digests, reg->objdigests, reg->objcount * UDIF_CRYPTO_HASH_SIZE);

				/* copy existing serials */
				qsc_memutils_copy(new_serials, reg->objserials, reg->objcount * UDIF_SERIAL_NUMBER_SIZE);

				/* clear and free old arrays */
				qsc_memutils_clear(reg->objdigests, reg->capacity * UDIF_CRYPTO_HASH_SIZE);
				qsc_memutils_alloc_free(reg->objdigests);
				qsc_memutils_clear(reg->objserials, reg->capacity * UDIF_SERIAL_NUMBER_SIZE);
				qsc_memutils_alloc_free(reg->objserials);

				/* update registry */
				reg->objdigests = new_digests;
				reg->objserials = new_serials;
				reg->capacity = newcapacity;

				err = udif_error_none;
			}
			else
			{
				/* clean up digest array on serial allocation failure */
				qsc_memutils_alloc_free(new_digests);
				err = udif_error_internal;
			}
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

udif_errors udif_registry_update_object(udif_registry_state* reg, const udif_object* obj)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(obj != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t index;
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && obj != NULL && reg->initialized == true)
	{
		/* find object */
		if (udif_registry_find_object(reg, obj->serial, &index) == true)
		{
			/* compute new digest */
			udif_object_compute_digest(digest, obj);

			/* update digest */
			qsc_memutils_copy(reg->objdigests + (index * UDIF_CRYPTO_HASH_SIZE), digest, UDIF_CRYPTO_HASH_SIZE);

			err = udif_error_none;

			/* clear digest */
			qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
		}
		else
		{
			err = udif_error_object_not_found;
		}
	}

	return err;
}

bool udif_registry_verify_proof(const uint8_t* proof, size_t prooflen, const uint8_t* root, const uint8_t* objdigest)
{
	UDIF_ASSERT(proof != NULL || prooflen == 0U);
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(objdigest != NULL);

	uint8_t computed[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t sibling[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t pos;
	uint8_t isright;
	bool res;

	res = false;

	if (root != NULL && objdigest != NULL && (proof != NULL || prooflen == 0U))
	{
		/* empty proof means single object */
		if (prooflen != 0U)
		{
			/* start with object digest */
			qsc_memutils_copy(computed, objdigest, UDIF_CRYPTO_HASH_SIZE);
			pos = 0U;

			/* walk up the tree */
			while (pos < prooflen)
			{
				/* extract sibling hash */
				qsc_memutils_copy(sibling, proof + pos, UDIF_CRYPTO_HASH_SIZE);
				pos += UDIF_CRYPTO_HASH_SIZE;

				/* extract direction */
				isright = proof[pos];
				++pos;

				/* compute parent */
				if (isright == 0U)
				{
					/* current is right child, sibling is left */
					merkle_parent_hash(computed, sibling, computed);
				}
				else
				{
					/* current is left child, sibling is right */
					merkle_parent_hash(computed, computed, sibling);
				}
			}

			/* check if computed root matches */
			res = qsc_memutils_are_equal(computed, root, UDIF_CRYPTO_HASH_SIZE);

			/* clear temporary data */
			qsc_memutils_clear(computed, UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_clear(sibling, UDIF_CRYPTO_HASH_SIZE);
		}
		else
		{
			res = qsc_memutils_are_equal(root, objdigest, UDIF_CRYPTO_HASH_SIZE);
		}
	}

	return res;
}
