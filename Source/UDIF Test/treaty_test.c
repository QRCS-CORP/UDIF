#include "treaty_test.h"
#include "treaty.h"
#include "udif.h"
#include "consoleutils.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

static bool treaty_test_create_proposal(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY | UDIF_TREATY_SCOPE_TRANSFER;
	policy = 1U;

	/* generate keypair for domain A */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create treaty proposal */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_create_proposal: treaty creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(treaty.treatyid, treatyid, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: treaty id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(treaty.domsera, domsera, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: domain A serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(treaty.domserb, domserb, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: domain B serial mismatch");
			res = false;
		}
		else if (treaty.validfrom != validfrom)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: valid from mismatch");
			res = false;
		}
		else if (treaty.validto != validto)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: valid to mismatch");
			res = false;
		}
		else if (treaty.scopebitmap != scopebitmap)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: scope bitmap mismatch");
			res = false;
		}
		else if (treaty.policy != policy)
		{
			qsc_consoleutils_print_line("treaty_test_create_proposal: policy mismatch");
			res = false;
		}
		else
		{
			/* verify domain A signature is not all zeros */
			ret = qsc_memutils_zeroed(treaty.domsiga, UDIF_SIGNED_HASH_SIZE);

			if (ret == true)
			{
				qsc_consoleutils_print_line("treaty_test_create_proposal: domain A signature is all zeros");
				res = false;
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_accept(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	udif_signature_keypair kpb = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY;
	policy = 1U;

	/* generate keypairs for both domains */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kpb.verkey, kpb.sigkey, qsc_csp_generate);

	/* create treaty proposal */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_accept: treaty creation failed");
		res = false;
	}
	else
	{
		/* verify treaty is pending before acceptance */
		if (udif_treaty_is_pending(&treaty) == false)
		{
			qsc_consoleutils_print_line("treaty_test_accept: treaty should be pending before acceptance");
			res = false;
		}
		else
		{
			/* accept treaty */
			err = udif_treaty_accept(&treaty, kpb.sigkey, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("treaty_test_accept: treaty acceptance failed");
				res = false;
			}
			else
			{
				/* verify domain B signature is not all zeros */
				ret = qsc_memutils_zeroed(treaty.domsigb, UDIF_SIGNED_HASH_SIZE);

				if (ret == true)
				{
					qsc_consoleutils_print_line("treaty_test_accept: domain B signature is all zeros");
					res = false;
				}
				else if (udif_treaty_is_pending(&treaty) == true)
				{
					qsc_consoleutils_print_line("treaty_test_accept: treaty should not be pending after acceptance");
					res = false;
				}
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_verify(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	udif_signature_keypair kpb = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY | UDIF_TREATY_SCOPE_TRANSFER;
	policy = 1U;

	/* generate keypairs */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kpb.verkey, kpb.sigkey, qsc_csp_generate);

	/* create and accept treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_verify: treaty creation failed");
		res = false;
	}
	else
	{
		err = udif_treaty_accept(&treaty, kpb.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("treaty_test_verify: treaty acceptance failed");
			res = false;
		}
		else
		{
			/* verify both signatures */
			if (udif_treaty_verify(&treaty, kpa.verkey, kpb.verkey) == false)
			{
				qsc_consoleutils_print_line("treaty_test_verify: treaty verification failed");
				res = false;
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_serialize(void)
{
	udif_treaty treaty1 = { 0U };
	udif_treaty treaty2 = { 0U };
	udif_signature_keypair kpa = { 0U };
	udif_signature_keypair kpb = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t buffer[UDIF_TREATY_STRUCTURE_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	size_t encsize;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY | UDIF_TREATY_SCOPE_ANALYTICS;
	policy = 2;

	/* generate keypairs */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kpb.verkey, kpb.sigkey, qsc_csp_generate);

	/* create and accept treaty */
	err = udif_treaty_create_proposal(&treaty1, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_serialize: treaty creation failed");
		res = false;
	}
	else
	{
		err = udif_treaty_accept(&treaty1, kpb.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("treaty_test_serialize: treaty acceptance failed");
			res = false;
		}
		else
		{
			/* get encoded size */
			encsize = udif_treaty_encoded_size(&treaty1);

			if (encsize != UDIF_TREATY_STRUCTURE_SIZE)
			{
				qsc_consoleutils_print_line("treaty_test_serialize: encoded size mismatch");
				res = false;
			}
			else
			{
				/* serialize */
				err = udif_treaty_serialize(buffer, sizeof(buffer), &treaty1);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("treaty_test_serialize: serialization failed");
					res = false;
				}
				else
				{
					/* deserialize */
					err = udif_treaty_deserialize(&treaty2, buffer, sizeof(buffer));

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("treaty_test_serialize: deserialization failed");
						res = false;
					}
					else if (udif_treaty_compare(&treaty1, &treaty2) == false)
					{
						qsc_consoleutils_print_line("treaty_test_serialize: deserialized treaty does not match original");
						res = false;
					}
				}
			}
		}
	}

	udif_treaty_clear(&treaty1);
	udif_treaty_clear(&treaty2);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_state_validation(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	udif_signature_keypair kpb = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint64_t ctime;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	ctime = qsc_timestamp_datetime_utc();
	validfrom = ctime;
	validto = validfrom + 86400U;  /* 1 day */
	scopebitmap = UDIF_TREATY_SCOPE_QUERY;
	policy = 1U;

	/* generate keypairs */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kpb.verkey, kpb.sigkey, qsc_csp_generate);

	/* create and accept treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_state_validation: treaty creation failed");
		res = false;
	}
	else
	{
		err = udif_treaty_accept(&treaty, kpb.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("treaty_test_state_validation: treaty acceptance failed");
			res = false;
		}
		else
		{
			/* test active at current time */
			if (udif_treaty_is_active(&treaty, ctime) == false)
			{
				qsc_consoleutils_print_line("treaty_test_state_validation: treaty should be active at current time");
				res = false;
			}
			else if (udif_treaty_is_expired(&treaty, ctime) == true)
			{
				qsc_consoleutils_print_line("treaty_test_state_validation: treaty should not be expired at current time");
				res = false;
			}
			else
			{
				/* test expired in future */
				if (udif_treaty_is_active(&treaty, validto + 3600U) == true)
				{
					qsc_consoleutils_print_line("treaty_test_state_validation: treaty should not be active after expiration");
					res = false;
				}
				else if (udif_treaty_is_expired(&treaty, validto + 3600U) == false)
				{
					qsc_consoleutils_print_line("treaty_test_state_validation: treaty should be expired after end time");
					res = false;
				}
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_scope_permissions(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY | UDIF_TREATY_SCOPE_TRANSFER;
	policy = 1U;

	/* generate keypair */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_scope_permissions: treaty creation failed");
		res = false;
	}
	else
	{
		/* test allowed scopes */
		if (udif_treaty_allows_scope(&treaty, UDIF_TREATY_SCOPE_QUERY) == false)
		{
			qsc_consoleutils_print_line("treaty_test_scope_permissions: query scope should be allowed");
			res = false;
		}
		else if (udif_treaty_allows_scope(&treaty, UDIF_TREATY_SCOPE_TRANSFER) == false)
		{
			qsc_consoleutils_print_line("treaty_test_scope_permissions: transfer scope should be allowed");
			res = false;
		}
		else
		{
			/* test disallowed scope */
			if (udif_treaty_allows_scope(&treaty, UDIF_TREATY_SCOPE_ANALYTICS) == true)
			{
				qsc_consoleutils_print_line("treaty_test_scope_permissions: analytics scope should not be allowed");
				res = false;
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_participant(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t nonparticipant[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(nonparticipant, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY;
	policy = 1U;

	/* generate keypair */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_participant: treaty creation failed");
		res = false;
	}
	else
	{
		/* test domain A is participant */
		if (udif_treaty_is_participant(&treaty, domsera) == false)
		{
			qsc_consoleutils_print_line("treaty_test_participant: domain A should be participant");
			res = false;
		}
		else if (udif_treaty_is_participant(&treaty, domserb) == false)
		{
			qsc_consoleutils_print_line("treaty_test_participant: domain B should be participant");
			res = false;
		}
		else
		{
			/* test non-participant */
			if (udif_treaty_is_participant(&treaty, nonparticipant) == true)
			{
				qsc_consoleutils_print_line("treaty_test_participant: non-participant should not be recognized");
				res = false;
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_compare_digest(void)
{
	udif_treaty treaty1 = { 0U };
	udif_treaty treaty2 = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY;
	policy = 1U;

	/* generate keypair */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create two identical treaties */
	err = udif_treaty_create_proposal(&treaty1, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_compare_digest: first treaty creation failed");
		res = false;
	}
	else
	{
		err = udif_treaty_create_proposal(&treaty2, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("treaty_test_compare_digest: second treaty creation failed");
			res = false;
		}
		else
		{
			/* compute digests */
			err = udif_treaty_compute_digest(digest1, &treaty1);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("treaty_test_compare_digest: first digest computation failed");
				res = false;
			}
			else
			{
				/* verify digest is not all zeros */
				ret = qsc_memutils_zeroed(digest1, sizeof(digest1));

				if (ret == true)
				{
					qsc_consoleutils_print_line("treaty_test_compare_digest: digest is all zeros");
					res = false;
				}
				else
				{
					err = udif_treaty_compute_digest(digest2, &treaty2);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("treaty_test_compare_digest: second digest computation failed");
						res = false;
					}
					else if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
					{
						qsc_consoleutils_print_line("treaty_test_compare_digest: digests should match for same treaty data");
						res = false;
					}
					else
					{
						/* copy treaty and verify compare */
						qsc_memutils_copy((uint8_t*)&treaty2, (uint8_t*)&treaty1, sizeof(udif_treaty));

						if (udif_treaty_compare(&treaty1, &treaty2) == false)
						{
							qsc_consoleutils_print_line("treaty_test_compare_digest: copied treaties should be equal");
							res = false;
						}
					}
				}
			}
		}
	}

	udif_treaty_clear(&treaty1);
	udif_treaty_clear(&treaty2);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_duration(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint64_t duration;
	uint64_t expected_duration;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	expected_duration = 86400U * 30U;  /* 30 days */
	validto = validfrom + expected_duration;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY;
	policy = 1U;

	/* generate keypair */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_duration: treaty creation failed");
		res = false;
	}
	else
	{
		/* get duration */
		duration = udif_treaty_get_duration(&treaty);

		if (duration != expected_duration)
		{
			qsc_consoleutils_print_line("treaty_test_duration: duration mismatch");
			res = false;
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

static bool treaty_test_validate(void)
{
	udif_treaty treaty = { 0U };
	udif_signature_keypair kpa = { 0U };
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t validfrom;
	uint64_t validto;
	uint32_t scopebitmap;
	uint32_t policy;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(treatyid, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domsera, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(domserb, UDIF_SERIAL_NUMBER_SIZE);
	validfrom = qsc_timestamp_datetime_utc();
	validto = validfrom + UDIF_TREATY_DEFAULT_DURATION;
	scopebitmap = UDIF_TREATY_SCOPE_QUERY | UDIF_TREATY_SCOPE_TRANSFER;
	policy = 1U;

	/* generate keypair */
	udif_signature_generate_keypair(kpa.verkey, kpa.sigkey, qsc_csp_generate);

	/* create valid treaty */
	err = udif_treaty_create_proposal(&treaty, treatyid, domsera, domserb, scopebitmap, validfrom, validto, policy, kpa.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("treaty_test_validate: treaty creation failed");
		res = false;
	}
	else
	{
		/* validate treaty */
		err = udif_treaty_validate(&treaty);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("treaty_test_validate: valid treaty failed validation");
			res = false;
		}
		else
		{
			/* test invalid duration (validto before validfrom) */
			treaty.validto = treaty.validfrom - 3600U;
			err = udif_treaty_validate(&treaty);

			if (err == udif_error_none)
			{
				qsc_consoleutils_print_line("treaty_test_validate: invalid duration should fail validation");
				res = false;
			}
		}
	}

	udif_treaty_clear(&treaty);
	qsc_memutils_clear((uint8_t*)&kpa, sizeof(udif_signature_keypair));

	return res;
}

bool treaty_test_run(void)
{
	bool res;

	res = true;

	if (treaty_test_create_proposal() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty create proposal test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty create proposal test has failed.");
		res = false;
	}

	if (treaty_test_accept() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty accept proposal test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty accept proposal test has failed.");
		res = false;
	}

	if (treaty_test_verify() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty verify test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty verify test has failed.");
		res = false;
	}

	if (treaty_test_serialize() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty serialize test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty serialize test has failed.");
		res = false;
	}

	if (treaty_test_state_validation() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty state validation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty state validation test has failed.");
		res = false;
	}

	if (treaty_test_scope_permissions() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty scope permissions test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty scope permissions test has failed.");
		res = false;
	}

	if (treaty_test_participant() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty participant test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty participant test has failed.");
		res = false;
	}

	if (treaty_test_compare_digest() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty compare digest test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty compare digest test has failed.");
		res = false;
	}

	if (treaty_test_duration() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty duration test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty duration test has failed.");
		res = false;
	}

	if (treaty_test_validate() == true)
	{
		qsc_consoleutils_print_line("Success! Treaty validate test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Treaty validate test has failed.");
		res = false;
	}

	return res;
}



