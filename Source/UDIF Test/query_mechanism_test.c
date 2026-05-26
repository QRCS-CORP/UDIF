#include "query_mechanism_test.h"
#include "capability.h"
#include "capstore.h"
#include "object.h"
#include "query.h"
#include "registry.h"
#include "csp.h"
#include "consoleutils.h"
#include "memutils.h"
#include "timestamp.h"

typedef struct query_mechanism_test_state
{
	udif_registry_state registry;
	udif_object active_object;
	udif_object destroyed_object;
	udif_object transferred_object;
	udif_capability capability;
	udif_capstore capstore;
	udif_signature_keypair ownerkp;
	udif_signature_keypair responderkp;
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE];
	uint8_t issuerser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t subjectser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t creatorser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t active_serial[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t destroyed_serial[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t transferred_serial[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t unknown_serial[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];
	uint8_t queryid[UDIF_QUERY_ID_SIZE];
	uint8_t proof[UDIF_QUERY_MAX_PROOF_SIZE];
} query_mechanism_test_state;

static void query_mechanism_test_fill(uint8_t* output, size_t outlen, uint8_t seed)
{
	size_t i;

	for (i = 0U; i < outlen; ++i)
	{
		output[i] = (uint8_t)(seed + (uint8_t)i);
	}
}

static bool query_mechanism_test_setup(query_mechanism_test_state* st)
{
	udif_registry_leaf leaf;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		qsc_memutils_clear((uint8_t*)st, sizeof(query_mechanism_test_state));
		qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
		query_mechanism_test_fill(st->issuerser, sizeof(st->issuerser), 0x10U);
		query_mechanism_test_fill(st->subjectser, sizeof(st->subjectser), 0x30U);
		query_mechanism_test_fill(st->ownerser, sizeof(st->ownerser), 0x50U);
		query_mechanism_test_fill(st->creatorser, sizeof(st->creatorser), 0x70U);
		query_mechanism_test_fill(st->active_serial, sizeof(st->active_serial), 0x90U);
		query_mechanism_test_fill(st->destroyed_serial, sizeof(st->destroyed_serial), 0xB0U);
		query_mechanism_test_fill(st->transferred_serial, sizeof(st->transferred_serial), 0xD0U);
		query_mechanism_test_fill(st->unknown_serial, sizeof(st->unknown_serial), 0xF0U);
		qsc_csp_generate(st->issuerkey, sizeof(st->issuerkey));
		qsc_csp_generate(st->attrroot, sizeof(st->attrroot));
		qsc_csp_generate(st->queryid, sizeof(st->queryid));
		udif_signature_generate_keypair(st->ownerkp.verkey, st->ownerkp.sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(st->responderkp.verkey, st->responderkp.sigkey, qsc_csp_generate);

		nowsecs = qsc_timestamp_datetime_utc();
		err = udif_registry_initialize(&st->registry, st->ownerser, 8U);

		if (err == udif_error_none)
		{
			err = udif_object_create(&st->active_object, st->active_serial, 1U, st->creatorser, st->attrroot,
				st->ownerser, st->ownerkp.sigkey, nowsecs, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_object_create(&st->destroyed_object, st->destroyed_serial, 1U, st->creatorser, st->attrroot,
				st->ownerser, st->ownerkp.sigkey, nowsecs, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_object_create(&st->transferred_object, st->transferred_serial, 1U, st->creatorser, st->attrroot,
				st->ownerser, st->ownerkp.sigkey, nowsecs, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_add_object(&st->registry, &st->active_object);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_add_object(&st->registry, &st->destroyed_object);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_add_object(&st->registry, &st->transferred_object);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_remove_object(&st->registry, st->destroyed_serial);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_get_leaf(&leaf, &st->registry, st->transferred_serial);
		}

		if (err == udif_error_none)
		{
			leaf.flags &= (uint32_t)(~UDIF_REGISTRY_FLAG_ACTIVE);
			leaf.flags |= UDIF_REGISTRY_FLAG_TRANSFERRED;
			err = udif_registry_add_leaf(&st->registry, &leaf);
		}

		if (err == udif_error_none)
		{
			err = udif_capability_create(&st->capability,
				(uint32_t)(UDIF_CAP_QUERY_EXIST | UDIF_CAP_QUERY_OWNER_BINDING | UDIF_CAP_QUERY_ATTR_BUCKET | UDIF_CAP_PROVE_MEMBERSHIP),
				(uint32_t)(1UL << (uint32_t)udif_scope_intra_domain), st->subjectser, st->issuerser, nowsecs + 600U, 0U, st->issuerkey);
		}

		if (err == udif_error_none)
		{
			udif_capstore_initialize(&st->capstore);
			err = udif_capstore_add_verified(&st->capstore, &st->capability, st->issuerkey, nowsecs);
		}

		res = (err == udif_error_none);
	}

	return res;
}

static void query_mechanism_test_teardown(query_mechanism_test_state* st)
{
	if (st != NULL)
	{
		udif_registry_dispose(&st->registry);
		qsc_memutils_clear((uint8_t*)st, sizeof(query_mechanism_test_state));
	}
}

static bool query_mechanism_test_eval(query_mechanism_test_state* st, udif_query* query, uint8_t expverdict)
{
	size_t prooflen;
	udif_errors err;
	uint8_t verdict;
	bool res;

	res = false;
	verdict = (uint8_t)udif_verdict_deny;
	prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
	err = udif_query_evaluate_registry(&verdict, st->proof, &prooflen, query, &st->registry, &st->capability,
		st->subjectser, qsc_timestamp_datetime_utc());

	if (err == udif_error_none && verdict == expverdict)
	{
		res = true;
	}

	return res;
}

static bool query_mechanism_test_predicates(void)
{
	query_mechanism_test_state* st;
	udif_query query;
	uint8_t other_owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;
	bool res;

	res = true;
	st = (query_mechanism_test_state*)qsc_memutils_malloc(sizeof(query_mechanism_test_state));

	if (st == NULL || query_mechanism_test_setup(st) == false)
	{
		qsc_consoleutils_print_line("query_mechanism_test_predicates: initialization failed");
		res = false;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->active_serial, qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_yes) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: known object existence failed");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->unknown_serial, qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_no) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: unknown object existence failed");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_owner_binding(&query, st->queryid, st->ownerser, st->active_serial, st->ownerser,
			qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_yes) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: owner binding true failed");
			res = false;
		}

		query_mechanism_test_fill(other_owner, sizeof(other_owner), 0x22U);
		udif_query_clear(&query);
		err = udif_query_create_owner_binding(&query, st->queryid, st->ownerser, st->active_serial, other_owner,
			qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_no) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: owner binding false failed");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_attr_bucket(&query, st->queryid, st->ownerser, st->active_serial,
			UDIF_REGISTRY_FLAG_ACTIVE, UDIF_REGISTRY_FLAG_ACTIVE, qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_yes) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: active attribute bucket failed");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_attr_bucket(&query, st->queryid, st->ownerser, st->destroyed_serial,
			UDIF_REGISTRY_FLAG_DESTROYED, UDIF_REGISTRY_FLAG_DESTROYED, qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_yes) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: destroyed attribute bucket failed");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_attr_bucket(&query, st->queryid, st->ownerser, st->transferred_serial,
			UDIF_REGISTRY_FLAG_TRANSFERRED, UDIF_REGISTRY_FLAG_TRANSFERRED, qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err != udif_error_none || query_mechanism_test_eval(st, &query, (uint8_t)udif_verdict_yes) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_predicates: transferred attribute bucket failed");
			res = false;
		}

		udif_query_clear(&query);
	}

	if (st != NULL)
	{
		query_mechanism_test_teardown(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

static bool query_mechanism_test_membership_proof(void)
{
	query_mechanism_test_state* st;
	udif_query query;
	size_t leafindex;
	uint8_t root[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t leafdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t prooflen;
	udif_errors err;
	uint8_t verdict;
	bool res;

	res = true;
	st = (query_mechanism_test_state*)qsc_memutils_malloc(sizeof(query_mechanism_test_state));

	if (st == NULL || query_mechanism_test_setup(st) == false)
	{
		qsc_consoleutils_print_line("query_mechanism_test_membership_proof: initialization failed");
		res = false;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
		leafindex = 0U;
		err = udif_query_create_membership_proof(&query, st->queryid, st->ownerser, st->active_serial,
			qsc_timestamp_datetime_utc(), st->capability.digest);
		prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
		verdict = (uint8_t)udif_verdict_deny;

		if (err == udif_error_none)
		{
			err = udif_query_evaluate_registry(&verdict, st->proof, &prooflen, &query, &st->registry, &st->capability,
				st->subjectser, qsc_timestamp_datetime_utc());
		}

		if (err != udif_error_none || verdict != (uint8_t)udif_verdict_yes ||
			udif_registry_compute_root(root, &st->registry) != udif_error_none ||
			udif_registry_find_object(&st->registry, st->active_serial, &leafindex) == false ||
			udif_registry_get_digest_at(leafdigest, &st->registry, leafindex) != udif_error_none ||
			udif_registry_verify_proof(st->proof, prooflen, root, leafdigest) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_membership_proof: proof verification failed");
			res = false;
		}

		if (prooflen > 0U)
		{
			st->proof[0U] ^= 0x01U;

			if (udif_registry_verify_proof(st->proof, prooflen, root, leafdigest) == true)
			{
				qsc_consoleutils_print_line("query_mechanism_test_membership_proof: altered proof accepted");
				res = false;
			}
		}

		udif_query_clear(&query);
	}

	if (st != NULL)
	{
		query_mechanism_test_teardown(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

static bool query_mechanism_test_authorization_attacks(void)
{
	query_mechanism_test_state* st;
	udif_query query;
	udif_capability badcap;
	uint8_t badkey[UDIF_CRYPTO_KEY_SIZE] = { 0U };
	size_t prooflen;
	udif_errors err;
	uint8_t verdict;
	bool res;

	res = true;
	st = (query_mechanism_test_state*)qsc_memutils_malloc(sizeof(query_mechanism_test_state));

	if (st == NULL || query_mechanism_test_setup(st) == false)
	{
		qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: initialization failed");
		res = false;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->active_serial,
			qsc_timestamp_datetime_utc(), st->capability.digest);
		prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
		verdict = (uint8_t)udif_verdict_yes;

		if (err != udif_error_none || udif_query_evaluate_registry(&verdict, st->proof, &prooflen, &query, &st->registry, NULL,
			st->subjectser, qsc_timestamp_datetime_utc()) != udif_error_none || verdict != (uint8_t)udif_verdict_deny)
		{
			qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: missing capability leaked state");
			res = false;
		}

		query.capabilityref[0U] ^= 0x80U;
		verdict = (uint8_t)udif_verdict_yes;
		prooflen = UDIF_QUERY_MAX_PROOF_SIZE;

		if (udif_query_evaluate_registry(&verdict, st->proof, &prooflen, &query, &st->registry, &st->capability,
			st->subjectser, qsc_timestamp_datetime_utc()) != udif_error_none || verdict != (uint8_t)udif_verdict_deny)
		{
			qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: forged capability digest accepted");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->active_serial,
			qsc_timestamp_datetime_utc() - (UDIF_TIME_WINDOW_SECONDS + 10U), st->capability.digest);
		prooflen = UDIF_QUERY_MAX_PROOF_SIZE;

		if (err != udif_error_none || udif_query_evaluate_registry(&verdict, st->proof, &prooflen, &query, &st->registry, &st->capability,
			st->subjectser, qsc_timestamp_datetime_utc()) != udif_error_time_window)
		{
			qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: replay window not enforced");
			res = false;
		}

		udif_query_clear(&query);
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->active_serial,
			qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err == udif_error_none)
		{
			query.querytype = 0xFFU;

			if (udif_query_predicate_is_canonical(&query) == true)
			{
				qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: wrong predicate type accepted");
				res = false;
			}
		}

		qsc_memutils_copy((uint8_t*)&badcap, (const uint8_t*)&st->capability, sizeof(udif_capability));
		badcap.tag[0U] ^= 0x01U;
		qsc_csp_generate(badkey, sizeof(badkey));

		if (udif_capability_verify(&badcap, st->issuerkey) == true ||
			udif_capstore_add_verified(&st->capstore, &badcap, st->issuerkey, qsc_timestamp_datetime_utc()) != udif_error_mac_invalid)
		{
			qsc_consoleutils_print_line("query_mechanism_test_authorization_attacks: forged KMAC tag accepted");
			res = false;
		}

		udif_query_clear(&query);
	}

	if (st != NULL)
	{
		query_mechanism_test_teardown(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

static bool query_mechanism_test_response_signature(void)
{
	query_mechanism_test_state* st;
	udif_query query;
	udif_query_response response;
	udif_errors err;
	bool res;

	res = true;
	st = (query_mechanism_test_state*)qsc_memutils_malloc(sizeof(query_mechanism_test_state));

	if (st == NULL || query_mechanism_test_setup(st) == false)
	{
		qsc_consoleutils_print_line("query_mechanism_test_response_signature: initialization failed");
		res = false;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
		qsc_memutils_clear((uint8_t*)&response, sizeof(udif_query_response));
		err = udif_query_create_existence(&query, st->queryid, st->ownerser, st->active_serial,
			qsc_timestamp_datetime_utc(), st->capability.digest);

		if (err == udif_error_none)
		{
			err = udif_query_create_response(&response, &query, (uint8_t)udif_verdict_yes, NULL, 0U, st->ownerser,
				st->responderkp.sigkey, qsc_timestamp_datetime_utc(), qsc_csp_generate);
		}

		if (err != udif_error_none || udif_query_verify_response(&response, &query, st->responderkp.verkey) == false)
		{
			qsc_consoleutils_print_line("query_mechanism_test_response_signature: signed response rejected");
			res = false;
		}

		response.verdict = (uint8_t)udif_verdict_no;

		if (udif_query_verify_response(&response, &query, st->responderkp.verkey) == true)
		{
			qsc_consoleutils_print_line("query_mechanism_test_response_signature: altered verdict accepted");
			res = false;
		}

		udif_query_clear(&query);
		udif_query_response_clear(&response);
	}

	if (st != NULL)
	{
		query_mechanism_test_teardown(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

bool query_mechanism_test_run(void)
{
	bool res;

	res = true;

	if (query_mechanism_test_predicates() == true)
	{
		qsc_consoleutils_print_line("Success! Query mechanism predicate tests have passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query mechanism predicate tests have failed.");
		res = false;
	}

	if (query_mechanism_test_membership_proof() == true)
	{
		qsc_consoleutils_print_line("Success! Query mechanism membership proof tests have passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query mechanism membership proof tests have failed.");
		res = false;
	}

	if (query_mechanism_test_authorization_attacks() == true)
	{
		qsc_consoleutils_print_line("Success! Query mechanism authorization attack tests have passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query mechanism authorization attack tests have failed.");
		res = false;
	}

	if (query_mechanism_test_response_signature() == true)
	{
		qsc_consoleutils_print_line("Success! Query mechanism response signature tests have passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query mechanism response signature tests have failed.");
		res = false;
	}

	return res;
}
