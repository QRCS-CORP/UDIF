#include "query_test.h"
#include "query.h"
#include "capability.h"
#include "udif.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

static bool query_test_create_existence(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timeanchor;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* create existence query */
	err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_create_existence: query creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(query.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_existence: query id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.targser, targser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_existence: target serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_existence: capability reference mismatch");
			res = false;
		}
		else if (query.querytype != udif_query_exist)
		{
			qsc_consoleutils_print_line("query_test_create_existence: query type mismatch");
			res = false;
		}
		else if (query.timeanchor != timeanchor)
		{
			qsc_consoleutils_print_line("query_test_create_existence: time anchor mismatch");
			res = false;
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_create_owner_binding(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timeanchor;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* create owner binding query */
	err = udif_query_create_owner_binding(&query, queryid, targser, objserial, ownerser, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_create_owner_binding: query creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(query.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_owner_binding: query id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.targser, targser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_owner_binding: target serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_owner_binding: capability reference mismatch");
			res = false;
		}
		else if (query.querytype != udif_query_owner_binding)
		{
			qsc_consoleutils_print_line("query_test_create_owner_binding: query type mismatch");
			res = false;
		}
		else if (query.timeanchor != timeanchor)
		{
			qsc_consoleutils_print_line("query_test_create_owner_binding: time anchor mismatch");
			res = false;
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_create_attr_bucket(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t attrmin;
	uint64_t attrmax;
	uint64_t timeanchor;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	attrmin = 1000U;
	attrmax = 5000U;
	timeanchor = qsc_timestamp_datetime_utc();

	/* create attribute bucket query */
	err = udif_query_create_attr_bucket(&query, queryid, targser, objserial, attrmin, attrmax, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_create_attr_bucket: query creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(query.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_attr_bucket: query id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.targser, targser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_attr_bucket: target serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_attr_bucket: capability reference mismatch");
			res = false;
		}
		else if (query.querytype != udif_query_attr_bucket)
		{
			qsc_consoleutils_print_line("query_test_create_attr_bucket: query type mismatch");
			res = false;
		}
		else if (query.timeanchor != timeanchor)
		{
			qsc_consoleutils_print_line("query_test_create_attr_bucket: time anchor mismatch");
			res = false;
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_create_membership_proof(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timeanchor;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* create membership proof query */
	err = udif_query_create_membership_proof(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_create_membership_proof: query creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(query.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_membership_proof: query id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.targser, targser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_membership_proof: target serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(query.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_create_membership_proof: capability reference mismatch");
			res = false;
		}
		else if (query.querytype != udif_query_membership_proof)
		{
			qsc_consoleutils_print_line("query_test_create_membership_proof: query type mismatch");
			res = false;
		}
		else if (query.timeanchor != timeanchor)
		{
			qsc_consoleutils_print_line("query_test_create_membership_proof: time anchor mismatch");
			res = false;
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_response(void)
{
	udif_query query = { 0U };
	udif_query_response response = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t respser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t proofdata[256] = { 0U };
	uint64_t timeanchor;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(respser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(proofdata, sizeof(proofdata));
	timeanchor = qsc_timestamp_datetime_utc();
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create query */
	err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_response: query creation failed");
		res = false;
	}
	else
	{
		/* create response */
		err = udif_query_create_response(&response, &query, udif_verdict_yes, proofdata, sizeof(proofdata), respser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("query_test_response: response creation failed");
			res = false;
		}
		else if (qsc_memutils_are_equal(response.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_response: query id mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(response.respser, respser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("query_test_response: responder serial mismatch");
			res = false;
		}
		else if (response.verdict != udif_verdict_yes)
		{
			qsc_consoleutils_print_line("query_test_response: verdict mismatch");
			res = false;
		}
		else if (response.timestamp != ctime)
		{
			qsc_consoleutils_print_line("query_test_response: timestamp mismatch");
			res = false;
		}
		else if (response.prooflen != sizeof(proofdata))
		{
			qsc_consoleutils_print_line("query_test_response: proof length mismatch");
			res = false;
		}
		else
		{
			/* verify response */
			if (udif_query_verify_response(&response, &query, kp.verkey) == false)
			{
				qsc_consoleutils_print_line("query_test_response: response signature verification failed");
				res = false;
			}
		}
	}

	udif_query_clear(&query);
	udif_query_response_clear(&response);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool query_test_serialize(void)
{
	udif_query query1 = { 0U };
	udif_query query2 = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t buffer[UDIF_QUERY_MAX_PREDICATE_SIZE] = { 0U };
	uint64_t timeanchor;
	size_t buflen;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* create query */
	err = udif_query_create_existence(&query1, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_serialize: query creation failed");
		res = false;
	}
	else
	{
		/* serialize */
		buflen = sizeof(buffer);
		err = udif_query_serialize(buffer, &buflen, &query1);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("query_test_serialize: serialization failed");
			res = false;
		}
		else
		{
			/* deserialize */
			err = udif_query_deserialize(&query2, buffer, buflen);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialization failed");
				res = false;
			}
			else if (qsc_memutils_are_equal(query2.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialized query id mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(query2.targser, targser, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialized target serial mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(query2.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialized capability reference mismatch");
				res = false;
			}
			else if (query2.querytype != query1.querytype)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialized query type mismatch");
				res = false;
			}
			else if (query2.timeanchor != query1.timeanchor)
			{
				qsc_consoleutils_print_line("query_test_serialize: deserialized time anchor mismatch");
				res = false;
			}
		}
	}

	udif_query_clear(&query1);
	udif_query_clear(&query2);

	return res;
}

static bool query_test_response_serialize(void)
{
	udif_query query = { 0U };
	udif_query_response response1 = { 0U };
	udif_query_response response2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t respser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t buffer[UDIF_QUERY_MAX_PROOF_SIZE] = { 0U };
	uint64_t timeanchor;
	uint64_t ctime;
	size_t buflen;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(respser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create query and response */
	err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_response_serialize: query creation failed");
		res = false;
	}
	else
	{
		err = udif_query_create_response(&response1, &query, udif_verdict_yes, NULL, 0, respser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("query_test_response_serialize: response creation failed");
			res = false;
		}
		else
		{
			/* serialize */
			buflen = sizeof(buffer);
			err = udif_query_response_serialize(buffer, &buflen, &response1);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("query_test_response_serialize: serialization failed");
				res = false;
			}
			else
			{
				/* deserialize */
				err = udif_query_response_deserialize(&response2, buffer, buflen);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("query_test_response_serialize: deserialization failed");
					res = false;
				}
				else if (qsc_memutils_are_equal(response2.queryid, queryid, UDIF_QUERY_ID_SIZE) == false)
				{
					qsc_consoleutils_print_line("query_test_response_serialize: deserialized query id mismatch");
					res = false;
				}
				else if (qsc_memutils_are_equal(response2.respser, respser, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					qsc_consoleutils_print_line("query_test_response_serialize: deserialized responder serial mismatch");
					res = false;
				}
				else if (response2.verdict != response1.verdict)
				{
					qsc_consoleutils_print_line("query_test_response_serialize: deserialized verdict mismatch");
					res = false;
				}
				else if (response2.timestamp != response1.timestamp)
				{
					qsc_consoleutils_print_line("query_test_response_serialize: deserialized timestamp mismatch");
					res = false;
				}
				else
				{
					/* verify deserialized response */
					if (udif_query_verify_response(&response2, &query, kp.verkey) == false)
					{
						qsc_consoleutils_print_line("query_test_response_serialize: deserialized response signature invalid");
						res = false;
					}
				}
			}
		}
	}

	udif_query_clear(&query);
	udif_query_response_clear(&response1);
	udif_query_response_clear(&response2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool query_test_freshness(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timeanchor;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();
	timeanchor = ctime;

	/* create query with current time */
	err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_freshness: query creation failed");
		res = false;
	}
	else
	{
		/* check freshness at current time */
		if (udif_query_is_fresh(&query, ctime) == false)
		{
			qsc_consoleutils_print_line("query_test_freshness: fresh query reported as stale");
			res = false;
		}
		else
		{
			/* check with time far in future */
			if (udif_query_is_fresh(&query, ctime + (86400U * 365U)) == true)
			{
				qsc_consoleutils_print_line("query_test_freshness: stale query reported as fresh");
				res = false;
			}
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_authorization(void)
{
	udif_query query = { 0U };
	udif_capability cap = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t badtargser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t timeanchor;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* setup capability first */
	qsc_memutils_clear((uint8_t*)&cap, sizeof(udif_capability));
	qsc_memutils_copy(cap.issuedto, targser, UDIF_SERIAL_NUMBER_SIZE);
	cap.verbsbitmap = 0xFFFFFFFFFFFFFFFFULL;
	cap.scopebitmap = 0xFFFFFFFFFFFFFFFFULL;
	cap.validto = timeanchor + 86400U;

	/* compute capability digest for query reference */
	err = udif_capability_compute_digest(capref, &cap);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_authorization: capability digest computation failed");
		res = false;
	}
	else
	{
		/* create query with correct capability reference */
		err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("query_test_authorization: query creation failed");
			res = false;
		}
		else
		{
			/* validate authorization */
			if (udif_query_validate_authorization(&query, &cap, targser) == false)
			{
				qsc_consoleutils_print_line("query_test_authorization: valid authorization rejected");
				res = false;
			}
			else
			{
				/* test with wrong target serial */
				qsc_csp_generate(badtargser, UDIF_SERIAL_NUMBER_SIZE);

				if (udif_query_validate_authorization(&query, &cap, badtargser) == true)
				{
					qsc_consoleutils_print_line("query_test_authorization: invalid authorization accepted");
					res = false;
				}
			}
		}
	}

	udif_query_clear(&query);

	return res;
}

static bool query_test_digest(void)
{
	udif_query query = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timeanchor;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(queryid, UDIF_QUERY_ID_SIZE);
	qsc_csp_generate(targser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(capref, UDIF_CRYPTO_HASH_SIZE);
	timeanchor = qsc_timestamp_datetime_utc();

	/* create query */
	err = udif_query_create_existence(&query, queryid, targser, objserial, timeanchor, capref);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("query_test_digest: query creation failed");
		res = false;
	}
	else
	{
		/* compute digest */
		udif_query_compute_digest(digest1, &query);

		/* check digest not all zeros */
		ret = qsc_memutils_zeroed(digest1, sizeof(digest1));

		if (ret == true)
		{
			qsc_consoleutils_print_line("query_test_digest: digest is all zeros");
			res = false;
		}
		else
		{
			/* compute digest again and verify determinism */
			udif_query_compute_digest(digest2, &query);

			if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("query_test_digest: digest not deterministic");
				res = false;
			}
		}
	}

	udif_query_clear(&query);

	return res;
}

bool query_test_run(void)
{
	bool res;

	res = true;

	if (query_test_create_existence() == true)
	{
		qsc_consoleutils_print_line("Success! Query create test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query create test has failed.");
		res = false;
	}

	if (query_test_create_owner_binding() == true)
	{
		qsc_consoleutils_print_line("Success! Query owner binding test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query owner binding test has failed.");
		res = false;
	}

	if (query_test_create_attr_bucket() == true)
	{
		qsc_consoleutils_print_line("Success! Query create attribute bucket test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query create attribute bucket test has failed.");
		res = false;
	}

	if (query_test_create_membership_proof() == true)
	{
		qsc_consoleutils_print_line("Success! Query create membership proof test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query create membership proof test has failed.");
		res = false;
	}

	if (query_test_response() == true)
	{
		qsc_consoleutils_print_line("Success! Query response test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query response test has failed.");
		res = false;
	}

	if (query_test_serialize() == true)
	{
		qsc_consoleutils_print_line("Success! Query serialize test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query serialize test has failed.");
		res = false;
	}

	if (query_test_response_serialize() == true)
	{
		qsc_consoleutils_print_line("Success! Query response serialize test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query response serialize test has failed.");
		res = false;
	}

	if (query_test_freshness() == true)
	{
		qsc_consoleutils_print_line("Success! Query freshness test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query freshness test has failed.");
		res = false;
	}

	if (query_test_authorization() == true)
	{
		qsc_consoleutils_print_line("Success! Query authorization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query authorization test has failed.");
		res = false;
	}

	if (query_test_digest() == true)
	{
		qsc_consoleutils_print_line("Success! Query digest test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Query digest test has failed.");
		res = false;
	}

	return res;
}

