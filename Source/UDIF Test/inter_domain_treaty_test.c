#include "inter_domain_treaty_test.h"
#include "query.h"
#include "treaty.h"
#include "treatystore.h"
#include "consoleutils.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

static void inter_domain_treaty_test_fill(uint8_t* output, size_t outlen, uint8_t seed)
{
	size_t i;

	for (i = 0U; i < outlen; ++i)
	{
		output[i] = (uint8_t)(seed + (uint8_t)i);
	}
}

static bool inter_domain_treaty_test_create_active(udif_treaty* treaty, const uint8_t* treatyid,
	const uint8_t* domsera, const uint8_t* domserb, uint32_t scopebitmap, uint64_t validfrom,
	uint64_t validto, const udif_signature_keypair* kpa, const udif_signature_keypair* kpb)
{
	udif_errors err;
	bool res;

	res = false;
	err = udif_treaty_create_proposal(treaty, treatyid, domsera, domserb, scopebitmap, validfrom,
		validto, 1U, kpa->sigkey, qsc_csp_generate);

	if (err == udif_error_none)
	{
		if (udif_treaty_verify_proposal(treaty, kpa->verkey) == true)
		{
			err = udif_treaty_accept(treaty, kpb->sigkey, qsc_csp_generate);

			if (err == udif_error_none)
			{
				res = udif_treaty_verify(treaty, kpa->verkey, kpb->verkey);
			}
		}
	}

	return res;
}

static bool inter_domain_treaty_lifecycle_test(void)
{
	udif_treatystore* storea;
	udif_treatystore* storeb;
	udif_treaty* treaty;
	udif_signature_keypair* kpa;
	udif_signature_keypair* kpb;
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE];
	uint64_t nowsecs;
	bool res;

	res = false;
	storea = (udif_treatystore*)qsc_memutils_malloc(sizeof(udif_treatystore));
	storeb = (udif_treatystore*)qsc_memutils_malloc(sizeof(udif_treatystore));
	treaty = (udif_treaty*)qsc_memutils_malloc(sizeof(udif_treaty));
	kpa = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	kpb = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));

	if (storea != NULL && storeb != NULL && treaty != NULL && kpa != NULL && kpb != NULL)
	{
		res = true;
		qsc_memutils_clear((uint8_t*)storea, sizeof(udif_treatystore));
		qsc_memutils_clear((uint8_t*)storeb, sizeof(udif_treatystore));
		qsc_memutils_clear((uint8_t*)treaty, sizeof(udif_treaty));
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));

		inter_domain_treaty_test_fill(treatyid, sizeof(treatyid), 0x10U);
		inter_domain_treaty_test_fill(domsera, sizeof(domsera), 0x30U);
		inter_domain_treaty_test_fill(domserb, sizeof(domserb), 0x50U);
		udif_signature_generate_keypair(kpa->verkey, kpa->sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(kpb->verkey, kpb->sigkey, qsc_csp_generate);
		udif_treatystore_initialize(storea);
		udif_treatystore_initialize(storeb);
		nowsecs = qsc_timestamp_datetime_utc();

		if (inter_domain_treaty_test_create_active(treaty, treatyid, domsera, domserb,
			UDIF_TREATY_SCOPE_QUERY_EXIST | UDIF_TREATY_SCOPE_QUERY_OWNER, nowsecs,
			nowsecs + UDIF_TREATY_DEFAULT_DURATION, kpa, kpb) == false)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: treaty creation failed");
			res = false;
		}
		else if (udif_treatystore_add(storea, treaty, udif_treatystore_status_active, nowsecs) != udif_error_none ||
			udif_treatystore_add(storeb, treaty, udif_treatystore_status_active, nowsecs) != udif_error_none)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: treaty store install failed");
			res = false;
		}
		else if (udif_treatystore_find_active_for_query(storea, domsera, domserb, (uint8_t)udif_query_exist, nowsecs) == NULL)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: existence scope rejected");
			res = false;
		}
		else if (udif_treatystore_find_active_for_query(storea, domsera, domserb, (uint8_t)udif_query_owner_binding, nowsecs) == NULL)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: owner scope rejected");
			res = false;
		}
		else if (udif_treatystore_find_active_for_query(storea, domsera, domserb, (uint8_t)udif_query_membership_proof, nowsecs) != NULL)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: out-of-scope proof permitted");
			res = false;
		}
		else if (udif_treatystore_find_active_for_query(storea, domsera, domsera, (uint8_t)udif_query_exist, nowsecs) != NULL)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: wrong peer permitted");
			res = false;
		}
		else if (udif_treatystore_set_status(storea, treatyid, udif_treatystore_status_revoked, nowsecs) != udif_error_none)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: treaty revocation failed");
			res = false;
		}
		else if (udif_treatystore_find_active_for_query(storea, domsera, domserb, (uint8_t)udif_query_exist, nowsecs) != NULL)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_lifecycle_test: revoked treaty permitted");
			res = false;
		}
	}

	if (storea != NULL)
	{
		udif_treatystore_clear(storea);
		qsc_memutils_alloc_free(storea);
	}

	if (storeb != NULL)
	{
		udif_treatystore_clear(storeb);
		qsc_memutils_alloc_free(storeb);
	}

	if (treaty != NULL)
	{
		udif_treaty_clear(treaty);
		qsc_memutils_alloc_free(treaty);
	}

	if (kpa != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpa);
	}

	if (kpb != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpb);
	}

	return res;
}

static bool inter_domain_treaty_attack_test(void)
{
	udif_treatystore* store;
	udif_treaty* treaty;
	udif_signature_keypair* kpa;
	udif_signature_keypair* kpb;
	udif_signature_keypair* kpx;
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t nonparty[UDIF_SERIAL_NUMBER_SIZE];
	uint64_t nowsecs;
	bool res;

	res = false;
	store = (udif_treatystore*)qsc_memutils_malloc(sizeof(udif_treatystore));
	treaty = (udif_treaty*)qsc_memutils_malloc(sizeof(udif_treaty));
	kpa = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	kpb = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	kpx = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));

	if (store != NULL && treaty != NULL && kpa != NULL && kpb != NULL && kpx != NULL)
	{
		res = true;
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_treatystore));
		qsc_memutils_clear((uint8_t*)treaty, sizeof(udif_treaty));
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)kpx, sizeof(udif_signature_keypair));
		inter_domain_treaty_test_fill(treatyid, sizeof(treatyid), 0x71U);
		inter_domain_treaty_test_fill(domsera, sizeof(domsera), 0x81U);
		inter_domain_treaty_test_fill(domserb, sizeof(domserb), 0x91U);
		inter_domain_treaty_test_fill(nonparty, sizeof(nonparty), 0xA1U);
		udif_signature_generate_keypair(kpa->verkey, kpa->sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(kpb->verkey, kpb->sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(kpx->verkey, kpx->sigkey, qsc_csp_generate);
		udif_treatystore_initialize(store);
		nowsecs = qsc_timestamp_datetime_utc();

		if (inter_domain_treaty_test_create_active(treaty, treatyid, domsera, domserb,
			UDIF_TREATY_SCOPE_QUERY_EXIST, nowsecs, nowsecs + UDIF_TREATY_DEFAULT_DURATION,
			kpa, kpb) == false)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_attack_test: treaty creation failed");
			res = false;
		}
		else
		{
			if (udif_treaty_verify(treaty, kpx->verkey, kpb->verkey) == true)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: wrong domain A key accepted");
				res = false;
			}

			treaty->scopebitmap |= UDIF_TREATY_SCOPE_QUERY_PROOF;

			if (udif_treaty_verify(treaty, kpa->verkey, kpb->verkey) == true)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: altered scope bitmap accepted");
				res = false;
			}

			treaty->scopebitmap &= (uint32_t)(~UDIF_TREATY_SCOPE_QUERY_PROOF);
			(void)udif_treatystore_add(store, treaty, udif_treatystore_status_active, nowsecs);

			if (udif_treatystore_find_active_for_query(store, nonparty, domserb, (uint8_t)udif_query_exist, nowsecs) != NULL)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: non-party origin accepted");
				res = false;
			}

			if (udif_treatystore_find_active_for_query(store, domsera, nonparty, (uint8_t)udif_query_exist, nowsecs) != NULL)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: non-party peer accepted");
				res = false;
			}

			if (udif_treatystore_find_active_for_query(store, domsera, domserb, (uint8_t)udif_query_membership_proof, nowsecs) != NULL)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: out-of-scope query accepted");
				res = false;
			}

			if (udif_treatystore_find_active_for_query(store, domsera, domserb, (uint8_t)udif_query_exist,
				nowsecs + UDIF_TREATY_DEFAULT_DURATION + 2U) != NULL)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_attack_test: expired treaty accepted");
				res = false;
			}
		}
	}

	if (store != NULL)
	{
		udif_treatystore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	if (treaty != NULL)
	{
		udif_treaty_clear(treaty);
		qsc_memutils_alloc_free(treaty);
	}

	if (kpa != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpa);
	}

	if (kpb != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpb);
	}

	if (kpx != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpx, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpx);
	}

	return res;
}

static bool inter_domain_treaty_response_test(void)
{
	udif_query query;
	udif_query_response resp;
	udif_signature_keypair kpb;
	udif_signature_keypair kpx;
	uint8_t queryid[UDIF_QUERY_ID_SIZE];
	uint8_t targetser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t objectser[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE];
	uint8_t respser[UDIF_SERIAL_NUMBER_SIZE];
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&query, sizeof(query));
	qsc_memutils_clear((uint8_t*)&resp, sizeof(resp));
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(kpb));
	qsc_memutils_clear((uint8_t*)&kpx, sizeof(kpx));
	inter_domain_treaty_test_fill(queryid, sizeof(queryid), 0x11U);
	inter_domain_treaty_test_fill(targetser, sizeof(targetser), 0x22U);
	inter_domain_treaty_test_fill(objectser, sizeof(objectser), 0x33U);
	inter_domain_treaty_test_fill(capref, sizeof(capref), 0x44U);
	inter_domain_treaty_test_fill(respser, sizeof(respser), 0x55U);
	udif_signature_generate_keypair(kpb.verkey, kpb.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kpx.verkey, kpx.sigkey, qsc_csp_generate);
	nowsecs = qsc_timestamp_datetime_utc();

	err = udif_query_create_existence(&query, queryid, targetser, objectser, nowsecs, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("inter_domain_treaty_response_test: query creation failed");
		res = false;
	}
	else
	{
		err = udif_query_create_response(&resp, &query, (uint8_t)udif_verdict_yes, NULL, 0U,
			respser, kpb.sigkey, nowsecs, qsc_csp_generate);

		if (err != udif_error_none || udif_query_verify_response(&resp, &query, kpb.verkey) == false)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_response_test: response signature failed");
			res = false;
		}
		else if (udif_query_verify_response(&resp, &query, kpx.verkey) == true)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_response_test: non-party response key accepted");
			res = false;
		}
		else
		{
			resp.verdict = (uint8_t)udif_verdict_no;

			if (udif_query_verify_response(&resp, &query, kpb.verkey) == true)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_response_test: altered verdict accepted");
				res = false;
			}
		}
	}

	udif_query_clear(&query);
	udif_query_response_clear(&resp);
	qsc_memutils_clear((uint8_t*)&kpb, sizeof(kpb));
	qsc_memutils_clear((uint8_t*)&kpx, sizeof(kpx));

	return res;
}


static bool inter_domain_treaty_response_without_pending_query_test(void)
{
	udif_treatystore* store;
	udif_treaty* treaty;
	udif_query query;
	udif_query_response resp;
	udif_signature_keypair* kpa;
	udif_signature_keypair* kpb;
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domsera[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t domserb[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t queryid[UDIF_QUERY_ID_SIZE];
	uint8_t targetser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t objectser[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE];
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	store = (udif_treatystore*)qsc_memutils_malloc(sizeof(udif_treatystore));
	treaty = (udif_treaty*)qsc_memutils_malloc(sizeof(udif_treaty));
	kpa = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	kpb = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&query, sizeof(query));
	qsc_memutils_clear((uint8_t*)&resp, sizeof(resp));

	if (store != NULL && treaty != NULL && kpa != NULL && kpb != NULL)
	{
		res = true;
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_treatystore));
		qsc_memutils_clear((uint8_t*)treaty, sizeof(udif_treaty));
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));
		inter_domain_treaty_test_fill(treatyid, sizeof(treatyid), 0xB0U);
		inter_domain_treaty_test_fill(domsera, sizeof(domsera), 0xC0U);
		inter_domain_treaty_test_fill(domserb, sizeof(domserb), 0xD0U);
		inter_domain_treaty_test_fill(queryid, sizeof(queryid), 0xE0U);
		inter_domain_treaty_test_fill(targetser, sizeof(targetser), 0x21U);
		inter_domain_treaty_test_fill(objectser, sizeof(objectser), 0x31U);
		inter_domain_treaty_test_fill(capref, sizeof(capref), 0x41U);
		udif_signature_generate_keypair(kpa->verkey, kpa->sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(kpb->verkey, kpb->sigkey, qsc_csp_generate);
		udif_treatystore_initialize(store);
		nowsecs = qsc_timestamp_datetime_utc();

		if (inter_domain_treaty_test_create_active(treaty, treatyid, domsera, domserb,
			UDIF_TREATY_SCOPE_QUERY_EXIST, nowsecs, nowsecs + UDIF_TREATY_DEFAULT_DURATION,
			kpa, kpb) == false)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_response_without_pending_query_test: treaty creation failed");
			res = false;
		}
		else if (udif_treatystore_add(store, treaty, udif_treatystore_status_active, nowsecs) != udif_error_none)
		{
			qsc_consoleutils_print_line("inter_domain_treaty_response_without_pending_query_test: treaty store install failed");
			res = false;
		}
		else
		{
			err = udif_query_create_existence(&query, queryid, targetser, objectser, nowsecs, capref);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("inter_domain_treaty_response_without_pending_query_test: query creation failed");
				res = false;
			}
			else
			{
				err = udif_query_create_response(&resp, &query, (uint8_t)udif_verdict_yes, NULL, 0U,
					domserb, kpb->sigkey, nowsecs, qsc_csp_generate);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("inter_domain_treaty_response_without_pending_query_test: response creation failed");
					res = false;
				}
				else if (udif_treatystore_consume_pending_response(store, domsera, domserb, &resp, nowsecs) == udif_error_none)
				{
					qsc_consoleutils_print_line("inter_domain_treaty_response_without_pending_query_test: response accepted without pending query state");
					res = false;
				}
			}
		}
	}

	udif_query_clear(&query);
	udif_query_response_clear(&resp);

	if (store != NULL)
	{
		udif_treatystore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	if (treaty != NULL)
	{
		udif_treaty_clear(treaty);
		qsc_memutils_alloc_free(treaty);
	}

	if (kpa != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpa, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpa);
	}

	if (kpb != NULL)
	{
		qsc_memutils_clear((uint8_t*)kpb, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kpb);
	}

	return res;
}

bool inter_domain_treaty_test_run(void)
{
	bool res;

	res = true;

	if (inter_domain_treaty_lifecycle_test() == true)
	{
		qsc_consoleutils_print_line("Success! Inter-domain treaty lifecycle test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Inter-domain treaty lifecycle test has failed.");
		res = false;
	}

	if (inter_domain_treaty_attack_test() == true)
	{
		qsc_consoleutils_print_line("Success! Inter-domain treaty attack test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Inter-domain treaty attack test has failed.");
		res = false;
	}

	if (inter_domain_treaty_response_without_pending_query_test() == true)
	{
		qsc_consoleutils_print_line("Success! Inter-domain treaty response without pending query test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Inter-domain treaty response without pending query test has failed.");
		res = false;
	}

	if (inter_domain_treaty_response_test() == true)
	{
		qsc_consoleutils_print_line("Success! Inter-domain treaty response test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Inter-domain treaty response test has failed.");
		res = false;
	}

	return res;
}
