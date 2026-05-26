#include "capstore.h"
#include "intutils.h"
#include "memutils.h"

static bool capstore_digest_is_valid(const udif_capability* capability)
{
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (capability != NULL)
	{
		if (udif_capability_compute_digest(digest, capability) == udif_error_none)
		{
			res = qsc_memutils_are_equal(digest, capability->digest, UDIF_CRYPTO_HASH_SIZE);
		}

		qsc_memutils_clear(digest, sizeof(digest));
	}

	return res;
}

static size_t capstore_find_position(const udif_capstore* store, const uint8_t* digest)
{
	size_t i;
	size_t pos;

	pos = UDIF_CAPSTORE_CAPACITY;

	if (store != NULL && digest != NULL)
	{
		for (i = 0U; i < UDIF_CAPSTORE_CAPACITY; ++i)
		{
			if (store->entries[i].used == true)
			{
				if (qsc_memutils_are_equal(store->entries[i].capability.digest, digest, UDIF_CRYPTO_HASH_SIZE) == true)
				{
					pos = i;
					break;
				}
			}
		}
	}

	return pos;
}

void udif_capstore_initialize(udif_capstore* store)
{
	UDIF_ASSERT(store != NULL);

	if (store != NULL)
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_capstore));
	}
}

void udif_capstore_clear(udif_capstore* store)
{
	UDIF_ASSERT(store != NULL);

	if (store != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)store, sizeof(udif_capstore));
	}
}

udif_errors udif_capstore_add(udif_capstore* store, const udif_capability* capability)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(capability != NULL);

	size_t i;
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && capability != NULL)
	{
		if (capstore_digest_is_valid(capability) == false)
		{
			err = udif_error_mac_invalid;
		}
		else
		{
			pos = capstore_find_position(store, capability->digest);

			if (pos == UDIF_CAPSTORE_CAPACITY)
			{
				for (i = 0U; i < UDIF_CAPSTORE_CAPACITY; ++i)
				{
					if (store->entries[i].used == false)
					{
						pos = i;
						break;
					}
				}
			}

			if (pos < UDIF_CAPSTORE_CAPACITY)
			{
				if (store->entries[pos].used == false)
				{
					++store->count;
				}

				qsc_memutils_copy((uint8_t*)&store->entries[pos].capability, (const uint8_t*)capability, sizeof(udif_capability));
				store->entries[pos].status = udif_capstore_status_active;
				store->entries[pos].used = true;
				err = udif_error_none;
			}
			else
			{
				err = udif_error_registry_full;
			}
		}
	}

	return err;
}

udif_errors udif_capstore_add_verified(udif_capstore* store, const udif_capability* capability, const uint8_t* issuerkey, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(issuerkey != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && capability != NULL && issuerkey != NULL)
	{
		if (capability->validto <= nowsecs)
		{
			err = udif_error_certificate_expired;
		}
		else if (udif_capability_verify(capability, issuerkey) == false)
		{
			err = udif_error_mac_invalid;
		}
		else
		{
			err = udif_capstore_add(store, capability);
		}
	}

	return err;
}

const udif_capability* udif_capstore_find(const udif_capstore* store, const uint8_t* digest)
{
	const udif_capability* capability;
	size_t pos;

	capability = NULL;
	pos = capstore_find_position(store, digest);

	if (pos < UDIF_CAPSTORE_CAPACITY)
	{
		if (store->entries[pos].status == udif_capstore_status_active)
		{
			capability = &store->entries[pos].capability;
		}
	}

	return capability;
}

const udif_capability* udif_capstore_find_any(const udif_capstore* store, const uint8_t* digest)
{
	const udif_capability* capability;
	size_t pos;

	capability = NULL;
	pos = capstore_find_position(store, digest);

	if (pos < UDIF_CAPSTORE_CAPACITY)
	{
		capability = &store->entries[pos].capability;
	}

	return capability;
}

udif_capstore_status udif_capstore_get_status(const udif_capstore* store, const uint8_t* digest, uint64_t nowsecs)
{
	size_t pos;
	udif_capstore_status status;

	status = udif_capstore_status_unknown;
	pos = capstore_find_position(store, digest);

	if (pos < UDIF_CAPSTORE_CAPACITY)
	{
		status = store->entries[pos].status;

		if (status == udif_capstore_status_active && store->entries[pos].capability.validto <= nowsecs)
		{
			status = udif_capstore_status_expired;
		}
	}

	return status;
}

bool udif_capstore_set_status(udif_capstore* store, const uint8_t* digest, udif_capstore_status status)
{
	size_t pos;
	bool res;

	res = false;
	pos = capstore_find_position(store, digest);

	if (pos < UDIF_CAPSTORE_CAPACITY && status != udif_capstore_status_unknown)
	{
		store->entries[pos].status = status;
		res = true;
	}

	return res;
}

bool udif_capstore_remove(udif_capstore* store, const uint8_t* digest)
{
	size_t pos;
	bool res;

	res = false;
	pos = capstore_find_position(store, digest);

	if (pos < UDIF_CAPSTORE_CAPACITY)
	{
		qsc_memutils_secure_erase((uint8_t*)&store->entries[pos], sizeof(udif_capstore_entry));

		if (store->count > 0U)
		{
			--store->count;
		}

		res = true;
	}

	return res;
}
