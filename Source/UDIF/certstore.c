#include "certstore.h"
#include "memutils.h"

static bool certstore_serial_is_zero(const uint8_t* serial)
{
	uint8_t zero[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	bool res;

	res = false;

	if (serial != NULL)
	{
		res = qsc_memutils_are_equal(serial, zero, UDIF_SERIAL_NUMBER_SIZE);
	}

	return res;
}

static size_t certstore_find_index(const udif_certstore* store, const uint8_t* serial)
{
	size_t pos;
	size_t res;

	res = UDIF_CERTSTORE_CAPACITY;

	if (store != NULL && serial != NULL)
	{
		for (pos = 0U; pos < UDIF_CERTSTORE_CAPACITY; ++pos)
		{
			if (store->entries[pos].occupied == true)
			{
				if (qsc_memutils_are_equal(store->entries[pos].cert.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == true)
				{
					res = pos;
					break;
				}
			}
		}
	}

	return res;
}

static size_t certstore_find_free_index(const udif_certstore* store)
{
	size_t pos;
	size_t res;

	res = UDIF_CERTSTORE_CAPACITY;

	if (store != NULL)
	{
		for (pos = 0U; pos < UDIF_CERTSTORE_CAPACITY; ++pos)
		{
			if (store->entries[pos].occupied == false)
			{
				res = pos;
				break;
			}
		}
	}

	return res;
}

static bool certstore_time_valid(const udif_certificate* cert, uint64_t nowsecs)
{
	bool res;

	res = false;

	if (cert != NULL)
	{
		if (nowsecs >= cert->valid.from && nowsecs <= cert->valid.to)
		{
			res = true;
		}
	}

	return res;
}


static void certstore_revoke_descendants(udif_certstore* store, const uint8_t* issuer, uint64_t nowsecs)
{
	size_t pos;

	if (store != NULL && issuer != NULL)
	{
		for (pos = 0U; pos < UDIF_CERTSTORE_CAPACITY; ++pos)
		{
			if (store->entries[pos].occupied == true)
			{
				if (store->entries[pos].status != udif_certstore_status_revoked)
				{
					if (qsc_memutils_are_equal(store->entries[pos].cert.issuer, issuer, UDIF_SERIAL_NUMBER_SIZE) == true)
					{
						if (qsc_memutils_are_equal(store->entries[pos].cert.serial, issuer, UDIF_SERIAL_NUMBER_SIZE) == false)
						{
							store->entries[pos].status = udif_certstore_status_revoked;
							store->entries[pos].statustime = nowsecs;
							certstore_revoke_descendants(store, store->entries[pos].cert.serial, nowsecs);
						}
					}
				}
			}
		}
	}
}


static udif_errors certstore_verify_certificate_internal(udif_certstore* store, const uint8_t* serial, uint64_t nowsecs, size_t depth)
{
	const udif_certificate* cert;
	const udif_certificate* issuer;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && serial != NULL)
	{
		if (depth < UDIF_CERTSTORE_CAPACITY)
		{
			err = udif_certstore_validate_status(store, serial, nowsecs);

			if (err == udif_error_none)
			{
				cert = udif_certstore_find(store, serial);

				if (cert != NULL)
				{
					if (cert->role == udif_role_root)
					{
						if (qsc_memutils_are_equal(cert->issuer, cert->serial, UDIF_SERIAL_NUMBER_SIZE) == true)
						{
							if (udif_certificate_verify(cert, cert) == true)
							{
								err = udif_error_none;
							}
							else
							{
								err = udif_error_signature_invalid;
							}
						}
						else
						{
							err = udif_error_invalid_state;
						}
					}
					else
					{
						issuer = udif_certstore_find(store, cert->issuer);

						if (issuer != NULL)
						{
							err = certstore_verify_certificate_internal(store, issuer->serial, nowsecs, depth + 1U);

							if (err == udif_error_none)
							{
								if (udif_certificate_role_transition_valid((udif_roles)issuer->role, (udif_roles)cert->role) == true)
								{
									if (udif_certificate_verify_chain(cert, issuer) == true)
									{
										err = udif_error_none;
									}
									else
									{
										err = udif_error_signature_invalid;
									}
								}
								else
								{
									err = udif_error_not_authorized;
								}
							}
						}
						else
						{
							err = udif_error_file_not_found;
						}
					}
				}
				else
				{
					err = udif_error_file_not_found;
				}
			}
		}
		else
		{
			err = udif_error_invalid_state;
		}
	}

	return err;
}

void udif_certstore_initialize(udif_certstore* store)
{
	UDIF_ASSERT(store != NULL);

	if (store != NULL)
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_certstore));
	}
}

void udif_certstore_clear(udif_certstore* store)
{
	UDIF_ASSERT(store != NULL);

	if (store != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)store, sizeof(udif_certstore));
	}
}

size_t udif_certstore_count(const udif_certstore* store)
{
	size_t res;

	res = 0U;

	if (store != NULL)
	{
		res = store->count;
	}

	return res;
}

udif_errors udif_certstore_add(udif_certstore* store, const udif_certificate* cert, udif_certstore_status status, uint64_t nowsecs)
{
	size_t pos;
	udif_errors err;

	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(cert != NULL);

	err = udif_error_invalid_input;

	if (store != NULL && cert != NULL && certstore_serial_is_zero(cert->serial) == false)
	{
		if (status != udif_certstore_status_unknown)
		{
			pos = certstore_find_index(store, cert->serial);

			if (pos == UDIF_CERTSTORE_CAPACITY)
			{
				pos = certstore_find_free_index(store);

				if (pos != UDIF_CERTSTORE_CAPACITY)
				{
					store->entries[pos].occupied = true;
					++store->count;
				}
			}

			if (pos != UDIF_CERTSTORE_CAPACITY)
			{
				qsc_memutils_copy((uint8_t*)&store->entries[pos].cert, (const uint8_t*)cert, sizeof(udif_certificate));
				store->entries[pos].status = status;
				store->entries[pos].statustime = nowsecs;

				if (status == udif_certstore_status_revoked)
				{
					certstore_revoke_descendants(store, cert->serial, nowsecs);
				}

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

const udif_certificate* udif_certstore_find(const udif_certstore* store, const uint8_t* serial)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(serial != NULL);

	const udif_certificate* res;
	size_t pos;

	res = NULL;

	if (store != NULL && serial != NULL)
	{
		pos = certstore_find_index(store, serial);

		if (pos != UDIF_CERTSTORE_CAPACITY)
		{
			res = &store->entries[pos].cert;
		}
	}

	return res;
}

udif_certstore_status udif_certstore_get_status(const udif_certstore* store, const uint8_t* serial)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(serial != NULL);

	udif_certstore_status res;
	size_t pos;

	res = udif_certstore_status_unknown;

	if (store != NULL && serial != NULL)
	{
		pos = certstore_find_index(store, serial);

		if (pos != UDIF_CERTSTORE_CAPACITY)
		{
			res = store->entries[pos].status;
		}
	}

	return res;
}

udif_errors udif_certstore_set_status(udif_certstore* store, const uint8_t* serial, udif_certstore_status status, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(serial != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && serial != NULL && status != udif_certstore_status_unknown)
	{
		pos = certstore_find_index(store, serial);

		if (pos != UDIF_CERTSTORE_CAPACITY)
		{
			if (store->entries[pos].status == udif_certstore_status_revoked &&
				status != udif_certstore_status_revoked)
			{
				err = udif_error_certificate_revoked;
			}
			else
			{
				store->entries[pos].status = status;
				store->entries[pos].statustime = nowsecs;

				if (status == udif_certstore_status_revoked)
				{
					certstore_revoke_descendants(store, serial, nowsecs);
				}

				err = udif_error_none;
			}
		}
		else
		{
			err = udif_error_file_not_found;
		}
	}

	return err;
}

udif_errors udif_certstore_validate_status(udif_certstore* store, const uint8_t* serial, uint64_t nowsecs)
{
	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(serial != NULL);

	udif_certstore_status status;
	const udif_certificate* cert;
	udif_errors err;

	err = udif_error_invalid_input;

	if (store != NULL && serial != NULL)
	{
		cert = udif_certstore_find(store, serial);

		if (cert != NULL)
		{
			status = udif_certstore_get_status(store, serial);

			if (status == udif_certstore_status_active)
			{
				if (certstore_time_valid(cert, nowsecs) == true)
				{
					err = udif_error_none;
				}
				else
				{
					(void)udif_certstore_set_status(store, serial, udif_certstore_status_expired, nowsecs);
					err = udif_error_certificate_expired;
				}
			}
			else if (status == udif_certstore_status_suspended)
			{
				err = udif_error_not_authorized;
			}
			else if (status == udif_certstore_status_revoked)
			{
				err = udif_error_certificate_revoked;
			}
			else if (status == udif_certstore_status_expired)
			{
				err = udif_error_certificate_expired;
			}
			else
			{
				err = udif_error_invalid_state;
			}
		}
		else
		{
			err = udif_error_file_not_found;
		}
	}

	return err;
}

udif_errors udif_certstore_verify_certificate(udif_certstore* store, const uint8_t* serial, uint64_t nowsecs)
{
	udif_errors err;

	UDIF_ASSERT(store != NULL);
	UDIF_ASSERT(serial != NULL);

	err = udif_error_invalid_input;

	if (store != NULL && serial != NULL)
	{
		err = certstore_verify_certificate_internal(store, serial, nowsecs, 0U);
	}

	return err;
}
