#include "treatystore.h"
#include "memutils.h"

static size_t treatystore_find_index(const udif_treatystore* store, const uint8_t* treatyid)
{
	size_t i;
	size_t res;

	res = UDIF_TREATYSTORE_CAPACITY;

	if (store != NULL && treatyid != NULL)
	{
		for (i = 0U; i < UDIF_TREATYSTORE_CAPACITY; ++i)
		{
			if (store->entries[i].occupied == true)
			{
				if (qsc_memutils_are_equal(store->entries[i].treaty.treatyid, treatyid, UDIF_SERIAL_NUMBER_SIZE) == true)
				{
					res = i;
					break;
				}
			}
		}
	}

	return res;
}

static size_t treatystore_find_free_index(const udif_treatystore* store)
{
	size_t i;
	size_t res;

	res = UDIF_TREATYSTORE_CAPACITY;

	if (store != NULL)
	{
		for (i = 0U; i < UDIF_TREATYSTORE_CAPACITY; ++i)
		{
			if (store->entries[i].occupied == false)
			{
				res = i;
				break;
			}
		}
	}

	return res;
}

static bool treatystore_participant_pair(const udif_treaty* treaty, const uint8_t* localser, const uint8_t* peerser)
{
	bool res;

	res = false;

	if (treaty != NULL && localser != NULL && peerser != NULL)
	{
		if (qsc_memutils_are_equal(treaty->domsera, localser, UDIF_SERIAL_NUMBER_SIZE) == true &&
			qsc_memutils_are_equal(treaty->domserb, peerser, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			res = true;
		}
		else if (qsc_memutils_are_equal(treaty->domsera, peerser, UDIF_SERIAL_NUMBER_SIZE) == true &&
			qsc_memutils_are_equal(treaty->domserb, localser, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			res = true;
		}
	}

	return res;
}

void udif_treatystore_initialize(udif_treatystore* store)
{
	UDIF_ASSERT(store != NULL);

	if (store != NULL)
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_treatystore));
	}
}

void udif_treatystore_clear(udif_treatystore* store)
{
	if (store != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)store, sizeof(udif_treatystore));
	}
}

udif_errors udif_treatystore_add(udif_treatystore* store, const udif_treaty* treaty, udif_treatystore_status status, uint64_t nowsecs)
{
	size_t pos;
	udif_errors err;

	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(treaty != NULL);

	err = udif_error_invalid_input;

	if (store != NULL && treaty != NULL && status != udif_treatystore_status_unknown)
	{
		if (udif_treaty_validate(treaty) == udif_error_none)
		{
			pos = treatystore_find_index(store, treaty->treatyid);

			if (pos == UDIF_TREATYSTORE_CAPACITY)
			{
				pos = treatystore_find_free_index(store);

				if (pos != UDIF_TREATYSTORE_CAPACITY)
				{
					store->entries[pos].occupied = true;
					++store->count;
				}
			}

			if (pos != UDIF_TREATYSTORE_CAPACITY)
			{
				qsc_memutils_copy((uint8_t*)&store->entries[pos].treaty, (const uint8_t*)treaty, sizeof(udif_treaty));
				store->entries[pos].status = status;
				store->entries[pos].statustime = nowsecs;
				err = udif_error_none;
			}
			else
			{
				err = udif_error_registry_full;
			}
		}
		else
		{
			err = udif_error_treaty_invalid;
		}
	}

	return err;
}

const udif_treaty* udif_treatystore_find(const udif_treatystore* store, const uint8_t* treatyid)
{
	const udif_treaty* treaty;
	size_t pos;

	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(treatyid != NULL);

	treaty = NULL;

	if (store != NULL && treatyid != NULL)
	{
		pos = treatystore_find_index(store, treatyid);

		if (pos != UDIF_TREATYSTORE_CAPACITY)
		{
			treaty = &store->entries[pos].treaty;
		}
	}

	return treaty;
}

udif_treatystore_status udif_treatystore_get_status(const udif_treatystore* store, const uint8_t* treatyid)
{
	udif_treatystore_status status;
	size_t pos;

	status = udif_treatystore_status_unknown;

	if (store != NULL && treatyid != NULL)
	{
		pos = treatystore_find_index(store, treatyid);

		if (pos != UDIF_TREATYSTORE_CAPACITY)
		{
			status = store->entries[pos].status;
		}
	}

	return status;
}

udif_errors udif_treatystore_set_status(udif_treatystore* store, const uint8_t* treatyid, udif_treatystore_status status, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(treatyid != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && treatyid != NULL && status != udif_treatystore_status_unknown)
	{
		pos = treatystore_find_index(store, treatyid);

		if (pos != UDIF_TREATYSTORE_CAPACITY)
		{
			store->entries[pos].status = status;
			store->entries[pos].statustime = nowsecs;
			err = udif_error_none;
		}
		else
		{
			err = udif_error_file_not_found;
		}
	}

	return err;
}

const udif_treaty* udif_treatystore_find_active_for_query(udif_treatystore* store, const uint8_t* localser, const uint8_t* peerser, uint8_t querytype, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(localser != NULL);
	UDIF_ASSERT(peerser != NULL);

	const udif_treaty* treaty;
	size_t i;

	treaty = NULL;

	if (store != NULL && localser != NULL && peerser != NULL)
	{
		for (i = 0U; i < UDIF_TREATYSTORE_CAPACITY; ++i)
		{
			if (store->entries[i].occupied == true)
			{
				if (store->entries[i].status == udif_treatystore_status_active)
				{
					if (udif_treaty_is_active(&store->entries[i].treaty, nowsecs) == true)
					{
						if (treatystore_participant_pair(&store->entries[i].treaty, localser, peerser) == true)
						{
							if (udif_treaty_allows_query(&store->entries[i].treaty, querytype) == true)
							{
								treaty = &store->entries[i].treaty;
								break;
							}
						}
					}
					else if (nowsecs > store->entries[i].treaty.validto)
					{
						store->entries[i].status = udif_treatystore_status_expired;
						store->entries[i].statustime = nowsecs;
					}
				}
			}
		}
	}

	return treaty;
}

static size_t treatystore_find_free_pending_index(const udif_treatystore* store)
{
	size_t i;
	size_t res;

	res = UDIF_TREATYSTORE_PENDING_CAPACITY;

	if (store != NULL)
	{
		for (i = 0U; i < UDIF_TREATYSTORE_PENDING_CAPACITY; ++i)
		{
			if (store->pending[i].occupied == false)
			{
				res = i;
				break;
			}
		}
	}

	return res;
}

udif_errors udif_treatystore_add_pending_query(udif_treatystore* store, const uint8_t* treatyid, const uint8_t* peerser, const udif_query* query, uint64_t expires)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(treatyid != NULL);
	UDIF_ASSERT(peerser != NULL);
	UDIF_ASSERT(query != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && treatyid != NULL && peerser != NULL && query != NULL && expires != 0U)
	{
		pos = treatystore_find_free_pending_index(store);

		if (pos != UDIF_TREATYSTORE_PENDING_CAPACITY)
		{
			qsc_memutils_clear((uint8_t*)&store->pending[pos], sizeof(udif_treatystore_pending_query));
			qsc_memutils_copy(store->pending[pos].treatyid, treatyid, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(store->pending[pos].peerser, peerser, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(store->pending[pos].queryid, query->queryid, UDIF_QUERY_ID_SIZE);
			udif_query_compute_digest(store->pending[pos].querydigest, query);
			store->pending[pos].querytype = query->querytype;
			store->pending[pos].expires = expires;
			store->pending[pos].occupied = true;
			++store->pendingcount;
			err = udif_error_none;
		}
		else
		{
			err = udif_error_registry_full;
		}
	}

	return err;
}

udif_errors udif_treatystore_consume_pending_response(udif_treatystore* store, const uint8_t* localser, const uint8_t* peerser, const udif_query_response* response, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(localser != NULL);
	UDIF_ASSERT(peerser != NULL);
	UDIF_ASSERT(response != NULL);

	size_t i;
	udif_errors err;

	err = udif_error_not_authorized;

	if (store != NULL && localser != NULL && peerser != NULL && response != NULL)
	{
		for (i = 0U; i < UDIF_TREATYSTORE_PENDING_CAPACITY; ++i)
		{
			if (store->pending[i].occupied == true)
			{
				if (nowsecs <= store->pending[i].expires &&
					qsc_memutils_are_equal(store->pending[i].peerser, peerser, UDIF_SERIAL_NUMBER_SIZE) == true &&
					qsc_memutils_are_equal(store->pending[i].queryid, response->queryid, UDIF_QUERY_ID_SIZE) == true &&
					qsc_memutils_are_equal(store->pending[i].querydigest, response->querydigest, UDIF_CRYPTO_HASH_SIZE) == true &&
					udif_treatystore_find_active_for_query(store, localser, peerser, store->pending[i].querytype, nowsecs) != NULL)
				{
					qsc_memutils_secure_erase((uint8_t*)&store->pending[i], sizeof(udif_treatystore_pending_query));

					if (store->pendingcount > 0U)
					{
						--store->pendingcount;
					}

					err = udif_error_none;
					break;
				}
				else if (nowsecs > store->pending[i].expires)
				{
					qsc_memutils_secure_erase((uint8_t*)&store->pending[i], sizeof(udif_treatystore_pending_query));

					if (store->pendingcount > 0U)
					{
						--store->pendingcount;
					}
				}
			}
		}
	}

	return err;
}
