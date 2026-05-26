#include "capability_test.h"
#include "capability.h"
#include "capstore.h"
#include "certificate.h"
#include "policy.h"
#include "query.h"
#include "consoleutils.h"
#include "memutils.h"
#include "timestamp.h"

static void capability_test_key(uint8_t* issuerkey)
{
	size_t i;

	for (i = 0U; i < UDIF_CRYPTO_KEY_SIZE; ++i)
	{
		issuerkey[i] = (uint8_t)i;
	}
}

static bool capability_test_create(void)
{
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t expiration;
	bool res;

	res = false;
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	capability_test_key(issuerkey);
	expiration = qsc_timestamp_datetime_utc() + 3600U;
	udif_capability_clear(&cap);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist) | (1U << udif_capability_admin_enroll),
		(1U << udif_scope_local), issuedto, issuedby, expiration, 1U, issuerkey) == udif_error_none)
	{
		res = (qsc_memutils_are_equal(cap.issuedby, issuedby, UDIF_SERIAL_NUMBER_SIZE) == true &&
			qsc_memutils_are_equal(cap.issuedto, issuedto, UDIF_SERIAL_NUMBER_SIZE) == true);
	}

	udif_capability_clear(&cap);
	return res;
}

static bool capability_test_verify(void)
{
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t expiration;
	bool res;

	res = false;
	capability_test_key(issuerkey);
	expiration = qsc_timestamp_datetime_utc() + 3600U;
	udif_capability_clear(&cap);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_local),
		issuedto, issuedby, expiration, 1U, issuerkey) == udif_error_none)
	{
		if (udif_capability_verify(&cap, issuerkey) == true)
		{
			issuerkey[0U] ^= 0x5AU;
			res = (udif_capability_verify(&cap, issuerkey) == false);
		}
	}

	udif_capability_clear(&cap);
	return res;
}

static bool capability_test_permissions(void)
{
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t expiration;
	bool res;

	res = false;
	capability_test_key(issuerkey);
	expiration = qsc_timestamp_datetime_utc() + 3600U;
	udif_capability_clear(&cap);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist) | (1U << udif_capability_tx_create),
		(1U << udif_scope_local) | (1U << udif_scope_intra_domain), issuedto, issuedby, expiration, 1U, issuerkey) == udif_error_none)
	{
		res = (udif_capability_allows_verb(&cap, udif_capability_query_exist) == true &&
			udif_capability_allows_verb(&cap, udif_capability_tx_create) == true &&
			udif_capability_allows_verb(&cap, udif_capability_admin_enroll) == false &&
			udif_capability_allows_scope(&cap, udif_scope_local) == true &&
			udif_capability_allows_scope(&cap, udif_scope_intra_domain) == true &&
			udif_capability_allows_scope(&cap, udif_scope_treaty) == false);
	}

	udif_capability_clear(&cap);
	return res;
}

static bool capability_test_store(void)
{
	udif_capstore* store;
	udif_capability cap;
	const udif_capability* found;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t expiration;
	uint64_t nowsecs;
	bool res;

	res = false;
	store = NULL;
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	capability_test_key(issuerkey);
	nowsecs = qsc_timestamp_datetime_utc();
	expiration = nowsecs + 3600U;
	udif_capability_clear(&cap);

	store = (udif_capstore*)qsc_memutils_malloc(sizeof(udif_capstore));

	if (store != NULL)
	{
		udif_capstore_initialize(store);

		if (udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_intra_domain),
			issuedto, issuedby, expiration, 1U, issuerkey) == udif_error_none)
		{
			if (udif_capstore_add_verified(store, &cap, issuerkey, nowsecs) == udif_error_none)
			{
				found = udif_capstore_find(store, cap.digest);

				if (found != NULL && qsc_memutils_are_equal(found->digest, cap.digest, UDIF_CRYPTO_HASH_SIZE) == true)
				{
					if (udif_capstore_set_status(store, cap.digest, udif_capstore_status_revoked) == true)
					{
						res = (udif_capstore_find(store, cap.digest) == NULL &&
							udif_capstore_get_status(store, cap.digest, nowsecs) == udif_capstore_status_revoked);
					}
				}
			}
		}

		udif_capstore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	udif_capability_clear(&cap);
	return res;
}

static bool capability_test_store_verified_rejects_bad_tag(void)
{
	udif_capstore store;
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t nowsecs;
	bool res;

	res = false;
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	capability_test_key(issuerkey);
	nowsecs = qsc_timestamp_datetime_utc();
	udif_capability_clear(&cap);
	udif_capstore_initialize(&store);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_local),
		issuedto, issuedby, nowsecs + 3600U, 1U, issuerkey) == udif_error_none)
	{
		cap.tag[0U] ^= 0x01U;
		res = (udif_capstore_add_verified(&store, &cap, issuerkey, nowsecs) == udif_error_mac_invalid &&
			udif_capstore_find(&store, cap.digest) == NULL);
	}

	udif_capability_clear(&cap);
	udif_capstore_clear(&store);
	return res;
}

static bool capability_test_policy_query(void)
{
	udif_certificate caller;
	udif_capability cap;
	udif_query query;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint8_t objser[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint64_t nowsecs;
	bool res;

	res = false;
	nowsecs = qsc_timestamp_datetime_utc();
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	objser[0U] = 3U;
	queryid[0U] = 4U;
	capability_test_key(issuerkey);
	qsc_memutils_clear((uint8_t*)&caller, sizeof(udif_certificate));
	qsc_memutils_copy(caller.serial, issuedto, UDIF_SERIAL_NUMBER_SIZE);
	caller.valid.from = nowsecs - 1U;
	caller.valid.to = nowsecs + 3600U;
	caller.capability = (UINT64_C(1) << udif_capability_query_exist);
	caller.role = udif_role_client;
	qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
	udif_capability_clear(&cap);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_intra_domain),
		issuedto, issuedby, nowsecs + 3600U, 1U, issuerkey) == udif_error_none)
	{
		if (udif_query_create_existence(&query, queryid, issuedto, objser, nowsecs, cap.digest) == udif_error_none)
		{
			if (udif_policy_authorize_query(&query, &caller, &cap, (uint32_t)udif_scope_intra_domain, nowsecs) == udif_policy_permit)
			{
				caller.capability = 0U;

				if (udif_policy_authorize_query(&query, &caller, &cap, (uint32_t)udif_scope_intra_domain, nowsecs) == udif_policy_deny)
				{
					caller.capability = (UINT64_C(1) << udif_capability_query_exist);
					res = (udif_policy_authorize_query(&query, &caller, &cap, (uint32_t)udif_scope_treaty, nowsecs) == udif_policy_deny);
				}
			}
		}
	}

	udif_query_clear(&query);
	udif_capability_clear(&cap);
	return res;
}


static bool capability_test_rejects_forged_digest(void)
{
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t nowsecs;
	bool res;

	res = false;
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	capability_test_key(issuerkey);
	nowsecs = qsc_timestamp_datetime_utc();
	udif_capability_clear(&cap);

	if (udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_local),
		issuedto, issuedby, nowsecs + 3600U, 1U, issuerkey) == udif_error_none)
	{
		cap.digest[0U] ^= 0x01U;
		res = (udif_capability_verify(&cap, issuerkey) == false);
	}

	udif_capability_clear(&cap);
	return res;
}

static bool capability_test_rejects_reserved_core_bits(void)
{
	udif_capability cap;
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	uint64_t nowsecs;
	uint64_t verbs;
	bool res;

	res = false;
	issuedby[0U] = 1U;
	issuedto[0U] = 2U;
	capability_test_key(issuerkey);
	nowsecs = qsc_timestamp_datetime_utc();
	verbs = (UINT64_C(1) << udif_capability_query_exist) | UDIF_CAP_RESERVED_FUTURE_CORE_MASK;
	udif_capability_clear(&cap);

	res = (udif_capability_create(&cap, (uint32_t)verbs, (1U << udif_scope_local),
		issuedto, issuedby, nowsecs + 3600U, 1U, issuerkey) != udif_error_none);

	udif_capability_clear(&cap);
	return res;
}

bool capability_test_run(void)
{
	bool res;

	res = true;

	if (capability_test_create() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity object creation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity object creation test has failed.");
		res = false;
	}

	if (capability_test_verify() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity object verification test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity object verification test has failed.");
		res = false;
	}

	if (capability_test_permissions() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity permissions test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity permissions test has failed.");
		res = false;
	}

	if (capability_test_store() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity store test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity store test has failed.");
		res = false;
	}

	if (capability_test_store_verified_rejects_bad_tag() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity verified-store rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity verified-store rejection test has failed.");
		res = false;
	}

	if (capability_test_policy_query() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity policy query test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity policy query test has failed.");
		res = false;
	}

	if (capability_test_rejects_forged_digest() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity forged digest rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity forged digest rejection test has failed.");
		res = false;
	}

	if (capability_test_rejects_reserved_core_bits() == true)
	{
		qsc_consoleutils_print_line("Success! Capablity reserved core bit rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Capablity reserved core bit rejection test has failed.");
		res = false;
	}

	return res;
}
