#include "registry.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "timestamp.h"

static int32_t registry_compare_digest(const uint8_t* a, const uint8_t* b)
{
	int32_t res;
	size_t i;

	res = 0;

	for (i = 0U; i < UDIF_CRYPTO_HASH_SIZE; ++i)
	{
		if (a[i] < b[i])
		{
			res = -1;
			break;
		}
		else if (a[i] > b[i])
		{
			res = 1;
			break;
		}
		else
		{
			/* no comparison result */
		}
	}

	return res;
}

static void registry_compute_owner_digest(uint8_t* digest, const uint8_t* ownerser)
{
	qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, ownerser, UDIF_SERIAL_NUMBER_SIZE, (const uint8_t*)UDIF_LABEL_REGROOT, sizeof(UDIF_LABEL_REGROOT) - 1U, NULL, 0U);
}

static void registry_empty_root(uint8_t* root)
{
	qsc_cshake256_compute(root, UDIF_CRYPTO_HASH_SIZE, (const uint8_t*)"", 0U, (const uint8_t*)UDIF_LABEL_REGROOT, sizeof(UDIF_LABEL_REGROOT) - 1U, NULL, 0U);
}

static void registry_parent_hash(uint8_t* output, const uint8_t* left, const uint8_t* right)
{
	uint8_t buf[UDIF_CRYPTO_HASH_SIZE * 2U] = { 0U };

	qsc_memutils_copy(buf, left, UDIF_CRYPTO_HASH_SIZE);
	qsc_memutils_copy(buf + UDIF_CRYPTO_HASH_SIZE, right, UDIF_CRYPTO_HASH_SIZE);
	qsc_cshake256_compute(output, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_REGROOT, sizeof(UDIF_LABEL_REGROOT) - 1U, NULL, 0U);
	qsc_memutils_secure_erase(buf, sizeof(buf));
}

static void registry_leaf_swap(udif_registry_leaf* a, udif_registry_leaf* b)
{
	udif_registry_leaf tmp = { 0U };

	qsc_memutils_copy(&tmp, a, sizeof(udif_registry_leaf));
	qsc_memutils_copy(a, b, sizeof(udif_registry_leaf));
	qsc_memutils_copy(b, &tmp, sizeof(udif_registry_leaf));
	qsc_memutils_secure_erase(&tmp, sizeof(udif_registry_leaf));
}

static void registry_sort_leaves(udif_registry_state* reg)
{
	size_t i;
	size_t j;

	for (i = 1U; i < reg->objcount; ++i)
	{
		j = i;

		while (j > 0U && registry_compare_digest(reg->leaves[j - 1U].objdigest, reg->leaves[j].objdigest) > 0)
		{
			registry_leaf_swap(&reg->leaves[j - 1U], &reg->leaves[j]);
			--j;
		}
	}
}

static udif_errors registry_build_leaf_hashes(uint8_t* hashes, const udif_registry_state* reg)
{
	size_t i;
	udif_errors err;

	err = udif_error_none;

	for (i = 0U; i < reg->objcount; ++i)
	{
		err = udif_registry_leaf_digest(hashes + (i * UDIF_CRYPTO_HASH_SIZE), &reg->leaves[i]);

		if (err != udif_error_none)
		{
			break;
		}
	}

	return err;
}

udif_errors udif_registry_leaf_encode(uint8_t* output, const udif_registry_leaf* leaf)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(leaf != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && leaf != NULL)
	{
		pos = 0U;
		qsc_memutils_copy(output + pos, leaf->objdigest, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, leaf->ownerdigest, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, leaf->objserial, UDIF_OBJECT_SERIAL_SIZE);
		pos += UDIF_OBJECT_SERIAL_SIZE;
		qsc_intutils_le32to8(output + pos, leaf->flags);
		pos += UDIF_REGISTRY_LEAF_FLAGS_SIZE;
		qsc_intutils_le64to8(output + pos, leaf->timestamp);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_registry_leaf_digest(uint8_t* digest, const udif_registry_leaf* leaf)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(leaf != NULL);

	uint8_t enc[UDIF_REGISTRY_LEAF_ENCODED_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (digest != NULL && leaf != NULL)
	{
		err = udif_registry_leaf_encode(enc, leaf);

		if (err == udif_error_none)
		{
			qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, enc, sizeof(enc),
				(const uint8_t*)UDIF_LABEL_REGROOT, sizeof(UDIF_LABEL_REGROOT) - 1U, NULL, 0U);
		}
	}

	qsc_memutils_secure_erase(enc, sizeof(enc));

	return err;
}


udif_errors udif_registry_add_leaf(udif_registry_state* reg, const udif_registry_leaf* leaf)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(leaf != NULL);

	size_t index;
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && leaf != NULL && reg->initialized == true)
	{
		if (udif_registry_find_object(reg, leaf->objserial, &index) == true)
		{
			qsc_memutils_copy(&reg->leaves[index], leaf, sizeof(udif_registry_leaf));
			registry_sort_leaves(reg);
			err = udif_error_none;
		}
		else if (reg->objcount < reg->capacity)
		{
			qsc_memutils_copy(&reg->leaves[reg->objcount], leaf, sizeof(udif_registry_leaf));
			++reg->objcount;
			registry_sort_leaves(reg);
			err = udif_error_none;
		}
		else
		{
			err = udif_error_registry_full;
		}
	}

	return err;
}

udif_errors udif_registry_get_leaf(udif_registry_leaf* leaf, const udif_registry_state* reg, const uint8_t* serial)
{
	UDIF_ASSERT(leaf != NULL);
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	size_t index;
	udif_errors err;

	err = udif_error_invalid_input;

	if (leaf != NULL && reg != NULL && serial != NULL && reg->initialized == true)
	{
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			qsc_memutils_copy(leaf, &reg->leaves[index], sizeof(udif_registry_leaf));
			err = udif_error_none;
		}
		else
		{
			err = udif_error_object_not_found;
		}
	}

	return err;
}

bool udif_registry_object_is_active(const udif_registry_state* reg, const uint8_t* serial)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	size_t index;
	bool res;

	res = false;

	if (reg != NULL && serial != NULL && reg->initialized == true)
	{
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			res = ((reg->leaves[index].flags & UDIF_REGISTRY_FLAG_ACTIVE) != 0U && (reg->leaves[index].flags & UDIF_REGISTRY_FLAG_DESTROYED) == 0U);
		}
	}

	return res;
}

udif_errors udif_registry_transfer_object(udif_registry_state* origin, udif_registry_state* dest, const udif_transfer_record* transfer)
{
	UDIF_ASSERT(origin != NULL);
	UDIF_ASSERT(dest != NULL);
	UDIF_ASSERT(transfer != NULL);

	udif_registry_leaf leaf;
	size_t index;
	udif_errors err;

	qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
	err = udif_error_invalid_input;

	if (origin != NULL && dest != NULL && transfer != NULL &&
		origin->initialized == true && dest->initialized == true)
	{
		if (qsc_memutils_are_equal(origin->ownerser, transfer->originator, UDIF_SERIAL_NUMBER_SIZE) == false ||
			qsc_memutils_are_equal(dest->ownerser, transfer->owner, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			err = udif_error_not_authorized;
		}
		else if (udif_registry_find_object(origin, transfer->serial, &index) == false)
		{
			err = udif_error_object_not_found;
		}
		else if ((origin->leaves[index].flags & UDIF_REGISTRY_FLAG_ACTIVE) == 0U ||
			(origin->leaves[index].flags & UDIF_REGISTRY_FLAG_DESTROYED) != 0U)
		{
			err = udif_error_invalid_state;
		}
		else if (udif_registry_find_object(dest, transfer->serial, NULL) == false &&
			dest->objcount >= dest->capacity)
		{
			err = udif_error_registry_full;
		}
		else
		{
			qsc_memutils_copy(&leaf, &origin->leaves[index], sizeof(udif_registry_leaf));
			origin->leaves[index].flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_ACTIVE);
			origin->leaves[index].flags |= UDIF_REGISTRY_FLAG_TRANSFERRED;
			origin->leaves[index].timestamp = transfer->timestamp;

			qsc_memutils_copy(leaf.ownerdigest, dest->ownerdigest, UDIF_CRYPTO_HASH_SIZE);
			leaf.flags |= UDIF_REGISTRY_FLAG_ACTIVE;
			leaf.flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_DESTROYED);
			leaf.flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_TRANSFERRED);
			leaf.timestamp = transfer->timestamp;
			err = udif_registry_add_leaf(dest, &leaf);
		}
	}

	qsc_memutils_secure_erase((uint8_t*)&leaf, sizeof(udif_registry_leaf));

	return err;
}

udif_errors udif_registry_add_object(udif_registry_state* reg, const udif_object* obj)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(obj != NULL);

	udif_registry_leaf leaf = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && obj != NULL && reg->initialized == true)
	{
		if (qsc_memutils_are_equal(reg->ownerser, obj->owner, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			err = udif_error_not_authorized;
		}
		else if (reg->objcount < reg->capacity)
		{
			if (udif_registry_find_object(reg, obj->serial, NULL) == false)
			{
				err = udif_object_compute_digest(leaf.objdigest, obj);

				if (err == udif_error_none)
				{
					qsc_memutils_copy(leaf.ownerdigest, reg->ownerdigest, UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_copy(leaf.objserial, obj->serial, UDIF_OBJECT_SERIAL_SIZE);
					leaf.timestamp = obj->updated;
					leaf.flags = UDIF_REGISTRY_FLAG_ACTIVE;
					qsc_memutils_copy(&reg->leaves[reg->objcount], &leaf, sizeof(udif_registry_leaf));
					++reg->objcount;
					registry_sort_leaves(reg);
				}
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

	qsc_memutils_secure_erase(&leaf, sizeof(udif_registry_leaf));

	return err;
}

void udif_registry_clear(udif_registry_state* reg)
{
	if (reg != NULL && reg->initialized == true)
	{
		qsc_memutils_secure_erase(reg->leaves, reg->capacity * sizeof(udif_registry_leaf));
		reg->objcount = 0U;
	}
}

udif_errors udif_registry_compute_root(uint8_t* root, const udif_registry_state* reg)
{
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(reg != NULL);

	uint8_t* tree;
	size_t level_size;
	size_t tree_size;
	size_t i;
	udif_errors err;

	tree = NULL;
	err = udif_error_invalid_input;

	if (root != NULL && reg != NULL && reg->initialized == true)
	{
		if (reg->objcount == 0U)
		{
			registry_empty_root(root);
			err = udif_error_none;
		}
		else
		{
			level_size = qsc_intutils_next_power_of_2(reg->objcount);
			tree_size = level_size * 2U;
			tree = (uint8_t*)qsc_memutils_malloc(tree_size * UDIF_CRYPTO_HASH_SIZE);

			if (tree != NULL)
			{
				qsc_memutils_clear(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
				err = registry_build_leaf_hashes(tree, reg);

				if (err == udif_error_none)
				{
					while (level_size > 1U)
					{
						for (i = 0U; i < (level_size / 2U); ++i)
						{
							registry_parent_hash(tree + ((level_size + i) * UDIF_CRYPTO_HASH_SIZE), tree + ((i * 2U) * UDIF_CRYPTO_HASH_SIZE), tree + (((i * 2U) + 1U) * UDIF_CRYPTO_HASH_SIZE));
						}

						qsc_memutils_copy(tree, tree + (level_size * UDIF_CRYPTO_HASH_SIZE), (level_size / 2U) * UDIF_CRYPTO_HASH_SIZE);
						level_size /= 2U;
					}

					qsc_memutils_copy(root, tree, UDIF_CRYPTO_HASH_SIZE);
				}

				qsc_memutils_secure_erase(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
				qsc_memutils_alloc_free(tree);
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
		if (reg->leaves != NULL)
		{
			qsc_memutils_secure_erase(reg->leaves, reg->capacity * sizeof(udif_registry_leaf));
			qsc_memutils_alloc_free(reg->leaves);
			reg->leaves = NULL;
		}

		qsc_keccak_dispose(&reg->mstate);
		qsc_memutils_secure_erase(reg, sizeof(udif_registry_state));
	}
}

bool udif_registry_find_object(const udif_registry_state* reg, const uint8_t* serial, size_t* index)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(serial != NULL);

	size_t i;
	bool res;

	res = false;

	if (reg != NULL && serial != NULL && reg->initialized == true)
	{
		for (i = 0U; i < reg->objcount; ++i)
		{
			if (qsc_memutils_are_equal(reg->leaves[i].objserial, serial, UDIF_OBJECT_SERIAL_SIZE) == true)
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
	size_t proof_bound;
	size_t proof_pos;
	size_t sibling;
	size_t tree_size;
	size_t i;
	udif_errors err;

	tree = NULL;
	err = udif_error_invalid_input;

	if (proof != NULL && prooflen != NULL && reg != NULL && serial != NULL && reg->initialized == true)
	{
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			level_size = qsc_intutils_next_power_of_2(reg->objcount);
			proof_bound = 0U;

			while (level_size > 1U)
			{
				proof_bound += (UDIF_CRYPTO_HASH_SIZE + 1U);
				level_size /= 2U;
			}

			if (*prooflen < proof_bound)
			{
				err = udif_error_invalid_input;
			}
			else if (reg->objcount == 1U)
			{
				*prooflen = 0U;
				err = udif_error_none;
			}
			else
			{
				level_size = qsc_intutils_next_power_of_2(reg->objcount);
				tree_size = level_size * 2U;
				tree = (uint8_t*)qsc_memutils_malloc(tree_size * UDIF_CRYPTO_HASH_SIZE);

				if (tree != NULL)
				{
					qsc_memutils_clear(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
					err = registry_build_leaf_hashes(tree, reg);
					proof_pos = 0U;

					while (err == udif_error_none && level_size > 1U)
					{
						sibling = ((index & 1U) != 0U) ? (index - 1U) : (index + 1U);
						qsc_memutils_copy(proof + proof_pos, tree + (sibling * UDIF_CRYPTO_HASH_SIZE), UDIF_CRYPTO_HASH_SIZE);
						proof_pos += UDIF_CRYPTO_HASH_SIZE;
						proof[proof_pos] = (uint8_t)(index & 1U);
						++proof_pos;

						for (i = 0U; i < (level_size / 2U); ++i)
						{
							registry_parent_hash(tree + ((level_size + i) * UDIF_CRYPTO_HASH_SIZE), tree + ((i * 2U) * UDIF_CRYPTO_HASH_SIZE), tree + (((i * 2U) + 1U) * UDIF_CRYPTO_HASH_SIZE));
						}

						qsc_memutils_copy(tree, tree + (level_size * UDIF_CRYPTO_HASH_SIZE), (level_size / 2U) * UDIF_CRYPTO_HASH_SIZE);
						index /= 2U;
						level_size /= 2U;
					}

					if (err == udif_error_none)
					{
						*prooflen = proof_pos;
					}

					qsc_memutils_secure_erase(tree, tree_size * UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_alloc_free(tree);
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
		err = udif_registry_leaf_digest(digest, &reg->leaves[index]);
	}

	return err;
}

udif_errors udif_registry_initialize(udif_registry_state* reg, const uint8_t* ownerser, size_t capacity)
{
	UDIF_ASSERT(reg != NULL);
	UDIF_ASSERT(ownerser != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && ownerser != NULL && capacity > 0U && capacity <= UDIF_REGISTRY_MAX_CAPACITY)
	{
		qsc_memutils_clear(reg, sizeof(udif_registry_state));
		reg->leaves = (udif_registry_leaf*)qsc_memutils_malloc(capacity * sizeof(udif_registry_leaf));

		if (reg->leaves != NULL)
		{
			qsc_memutils_clear(reg->leaves, capacity * sizeof(udif_registry_leaf));
			qsc_memutils_copy(reg->ownerser, ownerser, UDIF_SERIAL_NUMBER_SIZE);
			registry_compute_owner_digest(reg->ownerdigest, ownerser);
			reg->capacity = capacity;
			reg->objcount = 0U;
			reg->initialized = true;
			qsc_keccak_initialize_state(&reg->mstate);
			err = udif_error_none;
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
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && serial != NULL && reg->initialized == true)
	{
		if (udif_registry_find_object(reg, serial, &index) == true)
		{
			reg->leaves[index].flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_ACTIVE);
			reg->leaves[index].flags |= UDIF_REGISTRY_FLAG_DESTROYED;
			reg->leaves[index].timestamp = qsc_timestamp_datetime_utc();
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

	udif_registry_leaf* new_leaves;
	udif_errors err;

	new_leaves = NULL;
	err = udif_error_invalid_input;

	if (reg != NULL && reg->initialized == true && newcapacity > reg->capacity && newcapacity <= UDIF_REGISTRY_MAX_CAPACITY)
	{
		new_leaves = (udif_registry_leaf*)qsc_memutils_malloc(newcapacity * sizeof(udif_registry_leaf));

		if (new_leaves != NULL)
		{
			qsc_memutils_secure_erase(new_leaves, newcapacity * sizeof(udif_registry_leaf));
			qsc_memutils_copy(new_leaves, reg->leaves, reg->objcount * sizeof(udif_registry_leaf));
			qsc_memutils_secure_erase(reg->leaves, reg->capacity * sizeof(udif_registry_leaf));
			qsc_memutils_alloc_free(reg->leaves);
			reg->leaves = new_leaves;
			reg->capacity = newcapacity;
			err = udif_error_none;
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

	size_t index;
	udif_errors err;

	err = udif_error_invalid_input;

	if (reg != NULL && obj != NULL && reg->initialized == true)
	{
		if (qsc_memutils_are_equal(reg->ownerser, obj->owner, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			err = udif_error_not_authorized;
		}
		else if (udif_registry_find_object(reg, obj->serial, &index) == true)
		{
			err = udif_object_compute_digest(reg->leaves[index].objdigest, obj);

			if (err == udif_error_none)
			{
				reg->leaves[index].flags |= UDIF_REGISTRY_FLAG_ACTIVE;
				reg->leaves[index].flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_DESTROYED);
				reg->leaves[index].timestamp = obj->updated;
				registry_sort_leaves(reg);
			}
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
		if ((prooflen % (UDIF_CRYPTO_HASH_SIZE + 1U)) == 0U)
		{
			qsc_memutils_copy(computed, objdigest, UDIF_CRYPTO_HASH_SIZE);
			pos = 0U;

			while (pos < prooflen)
			{
				qsc_memutils_copy(sibling, proof + pos, UDIF_CRYPTO_HASH_SIZE);
				pos += UDIF_CRYPTO_HASH_SIZE;
				isright = proof[pos];
				++pos;

				if (isright == 0U)
				{
					registry_parent_hash(computed, computed, sibling);
				}
				else if (isright == 1U)
				{
					registry_parent_hash(computed, sibling, computed);
				}
				else
				{
					break;
				}
			}

			if (pos == prooflen)
			{
				res = qsc_memutils_are_equal(computed, root, UDIF_CRYPTO_HASH_SIZE);
			}
		}
	}

	qsc_memutils_secure_erase(computed, sizeof(computed));
	qsc_memutils_secure_erase(sibling, sizeof(sibling));

	return res;
}

void udif_registry_commit_clear(udif_registry_commit* commit)
{
	if (commit != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)commit, sizeof(udif_registry_commit));
	}
}

udif_errors udif_registry_commit_digest(uint8_t* digest, const udif_registry_commit* commit)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(commit != NULL);

	qsc_keccak_state kstate = { 0U };
	uint8_t buf[sizeof(uint64_t)] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (digest != NULL && commit != NULL)
	{
		qsc_sha3_initialize(&kstate);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)"UDIF:REGISTRY-COMMIT:V1", sizeof("UDIF:REGISTRY-COMMIT:V1") - 1U, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, commit->ownerser, UDIF_SERIAL_NUMBER_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, commit->regroot, UDIF_CRYPTO_HASH_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_intutils_le64to8(buf, commit->epoch);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(buf), QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_intutils_le64to8(buf, commit->timestamp);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(buf), QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, digest);
		qsc_memutils_secure_erase(buf, sizeof(buf));
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_registry_commit_deserialize(udif_registry_commit* commit, const uint8_t* input, size_t inlen)
{
	UDIF_ASSERT(commit != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (commit != NULL && input != NULL)
	{
		qsc_memutils_clear((uint8_t*)commit, sizeof(udif_registry_commit));

		if (inlen == UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE)
		{
			pos = 0U;
			qsc_memutils_copy(commit->signature, input + pos, UDIF_SIGNED_HASH_SIZE);
			pos += UDIF_SIGNED_HASH_SIZE;
			qsc_memutils_copy(commit->ownerser, input + pos, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			qsc_memutils_copy(commit->regroot, input + pos, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			commit->epoch = qsc_intutils_le8to64(input + pos);
			pos += sizeof(uint64_t);
			commit->timestamp = qsc_intutils_le8to64(input + pos);
			err = udif_error_none;
		}
		else
		{
			err = udif_error_decode_failure;
		}
	}

	return err;
}

udif_errors udif_registry_commit_serialize(uint8_t* output, size_t outlen, const udif_registry_commit* commit)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(commit != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && commit != NULL)
	{
		if (outlen >= UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE)
		{
			pos = 0U;
			qsc_memutils_copy(output + pos, commit->signature, UDIF_SIGNED_HASH_SIZE);
			pos += UDIF_SIGNED_HASH_SIZE;
			qsc_memutils_copy(output + pos, commit->ownerser, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			qsc_memutils_copy(output + pos, commit->regroot, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			qsc_intutils_le64to8(output + pos, commit->epoch);
			pos += sizeof(uint64_t);
			qsc_intutils_le64to8(output + pos, commit->timestamp);
			err = udif_error_none;
		}
	}

	return err;
}

udif_errors udif_registry_commit_sign(udif_registry_commit* commit, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(commit != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t smlen;
	udif_errors err;

	err = udif_error_invalid_input;

	if (commit != NULL && sigkey != NULL && rng_generate != NULL)
	{
		err = udif_registry_commit_digest(digest, commit);

		if (err == udif_error_none)
		{
			smlen = 0U;

			if (udif_signature_sign(commit->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, sigkey, rng_generate) == true && smlen == UDIF_SIGNED_HASH_SIZE)
			{
				err = udif_error_none;
			}
			else
			{
				err = udif_error_signature_invalid;
			}
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	return err;
}

bool udif_registry_commit_verify(const udif_registry_commit* commit, const uint8_t* verkey)
{
	UDIF_ASSERT(commit != NULL);
	UDIF_ASSERT(verkey != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (commit != NULL && verkey != NULL)
	{
		if (udif_registry_commit_digest(digest1, commit) == udif_error_none)
		{
			mlen = 0U;

			if (udif_signature_verify(digest2, &mlen, commit->signature, UDIF_SIGNED_HASH_SIZE, verkey) == true && mlen == UDIF_CRYPTO_HASH_SIZE)
			{
				res = qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE);
			}
		}
	}

	qsc_memutils_secure_erase(digest1, sizeof(digest1));
	qsc_memutils_secure_erase(digest2, sizeof(digest2));

	return res;
}
