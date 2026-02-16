#include "capability_test.h"
#include "capability.h"
#include "memutils.h"
#include "timestamp.h"

static bool capability_test_create(void)
{
	udif_capability cap = { 0U };
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	const char* pstr;
	uint64_t expiration;
	udif_errors err;
	bool res;

	res = false;

	/* generate test data */

	issuedby[0U] = 1U;
	issuedto[0U] = 2U;

	for (int i = 0U; i < UDIF_CRYPTO_KEY_SIZE; i++) 
	{
		issuerkey[i] = (uint8_t)i;
	}

	expiration = qsc_timestamp_datetime_utc() + 3600;

	/* create capability, corrected parameter order: (cap, verbs, scopes, issued_to, issued_by, ...) */

	err = udif_capability_create(&cap, (1U << udif_capability_query_exist) | (1U << udif_capability_admin_enroll),
		(1U << udif_scope_local), issuedto, issuedby, expiration, 1U, issuerkey);

	if (err == udif_error_none)
	{
		if (qsc_memutils_are_equal(cap.issuedby, issuedby, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			if (qsc_memutils_are_equal(cap.issuedto, issuedto, UDIF_SERIAL_NUMBER_SIZE) == true)
			{
				res = true;
			}
			else
			{
				qsc_consoleutils_print_line("Capablity create test failed: issued by mismatch");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Capablity create test failed: mismatch");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Capablity create test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

	udif_capability_clear(&cap);

	return res;
}

static bool capability_test_verify(void)
{
	udif_capability cap = { 0U };
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	const char* pstr;
	uint64_t expiration;
	udif_errors err;
	bool res;
	bool valid;

	res = false;

	/* generate test data */

	for (int i = 0; i < UDIF_CRYPTO_KEY_SIZE; i++) 
	{
		issuerkey[i] = (uint8_t)i;
	}

	expiration = qsc_timestamp_datetime_utc() + 3600;

	/* create capability */

	err = udif_capability_create(&cap, (1U << udif_capability_query_exist), (1U << udif_scope_local), 
		issuedto, issuedby, expiration, 1U, issuerkey);

	if (err == udif_error_none)
	{
		/* verify with correct key */
		valid = udif_capability_verify(&cap, issuerkey);

		if (valid == true)
		{
			/* clear the key and try again */
			qsc_memutils_clear(issuerkey, sizeof(issuerkey));
			/* should fail */
			valid = udif_capability_verify(&cap, issuerkey);

			if (valid == false)
			{
				res = true;
			}
			else
			{
				qsc_consoleutils_print_line("Capablity verify test failed: invalid key test");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Capablity verify test failed: authorized issuer test");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Capablity verify test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

	udif_capability_clear(&cap);

	return res;
}

static bool capability_test_permissions(void)
{
	udif_capability cap = { 0U };
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	const char* pstr;
	uint64_t expiration;
	udif_errors err;
	bool allowed;
	bool res;

	res = false;

	/* generate test data */

	for (int i = 0; i < UDIF_CRYPTO_KEY_SIZE; i++)
	{
		issuerkey[i] = (uint8_t)i;
	}

	expiration = qsc_timestamp_datetime_utc() + 3600;

	/* create capability with specific permissions */

	err = udif_capability_create(&cap, (1U << udif_capability_query_exist) | (1U << udif_capability_tx_create),
		(1U << udif_scope_local) | (1U << udif_scope_intra_domain), issuedto, issuedby, expiration, 1U, issuerkey);

	if (err == udif_error_none)
	{
		allowed = udif_capability_allows_verb(&cap, udif_capability_query_exist);

		if (allowed == true)
		{
			allowed = udif_capability_allows_verb(&cap, udif_capability_tx_create);

			if (allowed == true)
			{
				allowed = udif_capability_allows_verb(&cap, udif_capability_admin_enroll);

				if (allowed == false)
				{
					allowed = udif_capability_allows_scope(&cap, udif_scope_local);

					if (allowed == true)
					{
						allowed = udif_capability_allows_scope(&cap, udif_scope_intra_domain);

						if (allowed == true)
						{
							allowed = udif_capability_allows_scope(&cap, udif_scope_treaty);

							if (allowed == false)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}
	else
	{
		qsc_consoleutils_print_line("Capablity permissions test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

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

	return res;
}