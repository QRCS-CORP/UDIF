#include "udif.h"
#include "query.h"
#include "policy.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "timestamp.h"

static bool query_verdict_is_valid(uint8_t verdict)
{
	return (verdict == (uint8_t)udif_verdict_no || verdict == (uint8_t)udif_verdict_yes || verdict == (uint8_t)udif_verdict_deny);
}

static bool query_type_is_valid(uint8_t querytype)
{
	return (querytype == (uint8_t)udif_query_exist ||
		querytype == (uint8_t)udif_query_owner_binding ||
		querytype == (uint8_t)udif_query_attr_bucket ||
		querytype == (uint8_t)udif_query_membership_proof);
}


void udif_query_clear(udif_query* query)
{
	if (query != NULL)
	{
		if (query->predicate != NULL)
		{
			qsc_memutils_secure_erase(query->predicate, query->predlen);
			qsc_memutils_alloc_free(query->predicate);
		}

		qsc_memutils_secure_erase((uint8_t*)query, sizeof(udif_query));
	}
}

void udif_query_compute_digest(uint8_t* digest, const udif_query* query)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(query != NULL);

	qsc_keccak_state kstate = { 0U };
	uint8_t buf[sizeof(uint64_t)] = { 0U };

	if (digest != NULL && query != NULL)
	{
		qsc_sha3_initialize(&kstate);

		/* hash all fields except signature */
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, query->queryid, UDIF_QUERY_ID_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, &query->querytype, 1U, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, query->targser, UDIF_SERIAL_NUMBER_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_intutils_le64to8(buf, query->timeanchor);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint64_t), QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_keccak_update(&kstate, qsc_keccak_rate_256, query->capabilityref, UDIF_CRYPTO_HASH_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);

		if (query->predlen > 0 && query->predicate != NULL)
		{
			qsc_keccak_update(&kstate, qsc_keccak_rate_256, query->predicate, query->predlen, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		/* finalize */
		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, digest);
	}
}

udif_errors udif_query_create_attr_bucket(udif_query* query, const uint8_t* queryid, const uint8_t* targser, const uint8_t* serial, uint64_t attrmin, 
	uint64_t attrmax, uint64_t timeanchor, const uint8_t* capability)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(queryid != NULL);
	UDIF_ASSERT(targser != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(capability != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (query != NULL && queryid != NULL && targser != NULL && serial != NULL && capability != NULL && attrmin <= attrmax)
	{
		qsc_memutils_clear((uint8_t*)query, sizeof(udif_query));

		qsc_memutils_copy(query->queryid, queryid, UDIF_QUERY_ID_SIZE);
		query->querytype = (uint8_t)udif_query_attr_bucket;
		qsc_memutils_copy(query->targser, targser, UDIF_SERIAL_NUMBER_SIZE);
		query->timeanchor = timeanchor;
		qsc_memutils_copy(query->capabilityref, capability, UDIF_CRYPTO_HASH_SIZE);

		/* encode predicate: serial || attr_min || attr_max */
		query->predicate = (uint8_t*)qsc_memutils_malloc(UDIF_OBJECT_SERIAL_SIZE + 16U);

		if (query->predicate != NULL)
		{
			pos = 0U;
			qsc_memutils_copy(query->predicate + pos, serial, UDIF_OBJECT_SERIAL_SIZE);
			pos += UDIF_OBJECT_SERIAL_SIZE;
			qsc_intutils_le64to8(query->predicate + pos, attrmin);
			pos += sizeof(uint64_t);
			qsc_intutils_le64to8(query->predicate + pos, attrmax);
			pos += sizeof(uint64_t);
			query->predlen = pos;

			err = udif_error_none;
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

udif_errors udif_query_create_existence(udif_query* query, const uint8_t* queryid, const uint8_t* targser, const uint8_t* serial, uint64_t timeanchor, const uint8_t* capability)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(queryid != NULL);
	UDIF_ASSERT(targser != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(capability != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (query != NULL && queryid != NULL && targser != NULL && serial != NULL && capability != NULL)
	{
		qsc_memutils_clear((uint8_t*)query, sizeof(udif_query));

		qsc_memutils_copy(query->queryid, queryid, UDIF_QUERY_ID_SIZE);
		query->querytype = (uint8_t)udif_query_exist;
		qsc_memutils_copy(query->targser, targser, UDIF_SERIAL_NUMBER_SIZE);
		query->timeanchor = timeanchor;
		qsc_memutils_copy(query->capabilityref, capability, UDIF_CRYPTO_HASH_SIZE);

		/* encode predicate serial */
		query->predicate = (uint8_t*)qsc_memutils_malloc(UDIF_OBJECT_SERIAL_SIZE);

		if (query->predicate != NULL)
		{
			qsc_memutils_copy(query->predicate, serial, UDIF_OBJECT_SERIAL_SIZE);
			query->predlen = UDIF_OBJECT_SERIAL_SIZE;

			err = udif_error_none;
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

udif_errors udif_query_create_membership_proof(udif_query* query, const uint8_t* queryid, const uint8_t* targser, const uint8_t* serial, uint64_t timeanchor, const uint8_t* capability)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(queryid != NULL);
	UDIF_ASSERT(targser != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(capability != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (query != NULL && queryid != NULL && targser != NULL && serial != NULL && capability != NULL)
	{
		qsc_memutils_clear((uint8_t*)query, sizeof(udif_query));

		qsc_memutils_copy(query->queryid, queryid, UDIF_QUERY_ID_SIZE);
		query->querytype = (uint8_t)udif_query_membership_proof;
		qsc_memutils_copy(query->targser, targser, UDIF_SERIAL_NUMBER_SIZE);
		query->timeanchor = timeanchor;
		qsc_memutils_copy(query->capabilityref, capability, UDIF_CRYPTO_HASH_SIZE);

		/* encode predicate serial */
		query->predicate = (uint8_t*)qsc_memutils_malloc(UDIF_OBJECT_SERIAL_SIZE);

		if (query->predicate != NULL)
		{
			qsc_memutils_copy(query->predicate, serial, UDIF_OBJECT_SERIAL_SIZE);
			query->predlen = UDIF_OBJECT_SERIAL_SIZE;

			err = udif_error_none;
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

udif_errors udif_query_create_owner_binding(udif_query* query, const uint8_t* queryid, const uint8_t* targser, const uint8_t* serial, const uint8_t* ownerser, uint64_t timeanchor, const uint8_t* capability)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(queryid != NULL);
	UDIF_ASSERT(targser != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(ownerser != NULL);
	UDIF_ASSERT(capability != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (query != NULL && queryid != NULL && targser != NULL && serial != NULL && ownerser != NULL && capability != NULL)
	{
		qsc_memutils_clear((uint8_t*)query, sizeof(udif_query));

		qsc_memutils_copy(query->queryid, queryid, UDIF_QUERY_ID_SIZE);
		query->querytype = (uint8_t)udif_query_owner_binding;
		qsc_memutils_copy(query->targser, targser, UDIF_SERIAL_NUMBER_SIZE);
		query->timeanchor = timeanchor;
		qsc_memutils_copy(query->capabilityref, capability, UDIF_CRYPTO_HASH_SIZE);

		/* encode predicate: serial || owner_serial */
		query->predicate = (uint8_t*)qsc_memutils_malloc(UDIF_OBJECT_SERIAL_SIZE + UDIF_SERIAL_NUMBER_SIZE);

		if (query->predicate != NULL)
		{
			pos = 0U;
			qsc_memutils_copy(query->predicate + pos, serial, UDIF_OBJECT_SERIAL_SIZE);
			pos += UDIF_OBJECT_SERIAL_SIZE;
			qsc_memutils_copy(query->predicate + pos, ownerser, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;

			query->predlen = pos;
			err = udif_error_none;
		}
		else
		{
			err = udif_error_internal;
		}
	}

	return err;
}

udif_errors udif_query_create_response(udif_query_response* response, const udif_query* query, uint8_t verdict, const uint8_t* proofdata, size_t prooflen,
	const uint8_t* respser, const uint8_t* respsigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(response != NULL);
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(respser != NULL);
	UDIF_ASSERT(respsigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);
	UDIF_ASSERT(proofdata != NULL || prooflen == 0U);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (response != NULL && query != NULL && respser != NULL && respsigkey != NULL && rng_generate != NULL && (proofdata != NULL || prooflen == 0U))
	{
		size_t smlen;

		/* validate verdict */
		if (verdict == (uint8_t)udif_verdict_no || verdict == (uint8_t)udif_verdict_yes || verdict == (uint8_t)udif_verdict_deny)
		{
			/* validate proof size */
			if (prooflen <= UDIF_QUERY_MAX_PROOF_SIZE)
			{
				qsc_memutils_clear((uint8_t*)response, sizeof(udif_query_response));
				qsc_memutils_copy(response->queryid, query->queryid, UDIF_QUERY_ID_SIZE);
				response->verdict = verdict;
				response->timestamp = ctime;
				qsc_memutils_copy(response->respser, respser, UDIF_SERIAL_NUMBER_SIZE);

				/* copy proof if provided */
				if (prooflen > 0 && proofdata != NULL)
				{
					response->proof = (uint8_t*)qsc_memutils_malloc(prooflen);

					if (response->proof != NULL)
					{
						qsc_memutils_copy(response->proof, proofdata, prooflen);
						response->prooflen = prooflen;
					}
					else
					{
						err = udif_error_internal;
					}
				}
				else
				{
					response->proof = NULL;
					response->prooflen = 0;
				}

				if (err != udif_error_internal)
				{
					/* bind the serialized response to the complete query transcript */
					udif_query_compute_digest(response->querydigest, query);

					/* compute digest and sign */
					udif_query_response_compute_digest(digest, response, query);
					smlen = 0U;

					if (udif_signature_sign(response->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, respsigkey, rng_generate) == true)
					{
						if (smlen == UDIF_SIGNED_HASH_SIZE)
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
						/* clean up on failure */
						if (response->proof != NULL)
						{
							qsc_memutils_secure_erase(response->proof, response->prooflen);
							qsc_memutils_alloc_free(response->proof);
							response->proof = NULL;
						}

						err = udif_error_signature_invalid;
					}

					qsc_memutils_secure_erase(digest, UDIF_CRYPTO_HASH_SIZE);
				}
			}
			else
			{
				err = udif_error_invalid_input;
			}
		}
		else
		{
			err = udif_error_invalid_input;
		}
	}

	return err;
}

udif_errors udif_query_deserialize(udif_query* query, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(input != NULL);

	uint64_t predlen;
	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;

	if (query != NULL && input != NULL)
	{
		pos = 0U;
		qsc_memutils_clear((uint8_t*)query, sizeof(udif_query));

		if (inplen >= UDIF_QUERY_STRUCTURE_SIZE)
		{
			qsc_memutils_copy(query->capabilityref, input + pos, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			qsc_memutils_copy(query->queryid, input + pos, UDIF_QUERY_ID_SIZE);
			pos += UDIF_QUERY_ID_SIZE;
			qsc_memutils_copy(query->targser, input + pos, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			query->timeanchor = qsc_intutils_le8to64(input + pos);
			pos += UDIF_VALID_TIME_SIZE;
			predlen = qsc_intutils_le8to64(input + pos);
			pos += UDIF_QUERY_PREDICATE_SIZE;
			query->querytype = input[pos];
			pos += UDIF_QUERY_TYPE_SIZE;

			if (query_type_is_valid(query->querytype) == true && predlen <= UDIF_QUERY_MAX_PREDICATE_SIZE && pos + (size_t)predlen == inplen)
			{
				if (predlen > 0U)
				{
					query->predicate = (uint8_t*)qsc_memutils_malloc((size_t)predlen);

					if (query->predicate != NULL)
					{
						qsc_memutils_copy(query->predicate, input + pos, (size_t)predlen);
						query->predlen = (size_t)predlen;
						err = udif_error_none;
					}
					else
					{
						err = udif_error_internal;
					}
				}
				else
				{
					query->predicate = NULL;
					query->predlen = 0U;
					err = udif_error_none;
				}
			}
		}
	}
	else
	{
		err = udif_error_invalid_input;
	}

	if (err == udif_error_none && udif_query_predicate_is_canonical(query) == false)
	{
		udif_query_clear(query);
		err = udif_error_decode_failure;
	}

	return err;
}

udif_errors udif_query_serialize(uint8_t* output, size_t* outlen, const udif_query* query)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != NULL);
	UDIF_ASSERT(query != NULL);

	size_t pos;
	size_t enclen;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && outlen != NULL && query != NULL)
	{
		enclen = UDIF_QUERY_STRUCTURE_SIZE + query->predlen;

		if (query->predlen <= UDIF_QUERY_MAX_PREDICATE_SIZE &&
			(query->predicate != NULL || query->predlen == 0U) &&
			udif_query_predicate_is_canonical(query) == true &&
			*outlen >= enclen)
		{
			pos = 0U;

			qsc_memutils_copy(output + pos, query->capabilityref, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			qsc_memutils_copy(output + pos, query->queryid, UDIF_QUERY_ID_SIZE);
			pos += UDIF_QUERY_ID_SIZE;
			qsc_memutils_copy(output + pos, query->targser, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			qsc_intutils_le64to8(output + pos, query->timeanchor);
			pos += UDIF_VALID_TIME_SIZE;
			qsc_intutils_le64to8(output + pos, (uint64_t)query->predlen);
			pos += UDIF_QUERY_PREDICATE_SIZE;
			output[pos] = query->querytype;
			pos += UDIF_QUERY_TYPE_SIZE;

			if (query->predlen > 0U)
			{
				qsc_memutils_copy(output + pos, query->predicate, query->predlen);
				pos += query->predlen;
			}

			*outlen = pos;
			err = udif_error_none;
		}
	}

	return err;
}

bool udif_query_is_fresh(const udif_query* query, uint64_t ctime)
{
	UDIF_ASSERT(query != NULL);

	bool res;
	uint64_t age;

	res = false;

	if (query != NULL)
	{
		/* if time_anchor is 0, query is for current state */
		if (query->timeanchor == 0U)
		{
			res = true;
		}
		else
		{
			/* check if anchor is within range */
			if (ctime >= query->timeanchor)
			{
				age = ctime - query->timeanchor;
				res = (age <= UDIF_TIME_WINDOW_SECONDS);
			}
		}
	}

	return res;
}

void udif_query_response_compute_digest(uint8_t* digest, const udif_query_response* response, const udif_query* query)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(response != NULL);

	qsc_keccak_state kstate = { 0U };
	uint8_t buf[sizeof(uint64_t)] = { 0U };

	(void)query;

	if (digest != NULL && response != NULL)
	{
		qsc_sha3_initialize(&kstate);

		/* hash all fields except signature; bind the response to the embedded canonical query digest */
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, response->querydigest, UDIF_CRYPTO_HASH_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, response->queryid, UDIF_QUERY_ID_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, &response->verdict, 1U, QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_intutils_le64to8(buf, response->timestamp);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint64_t), QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_keccak_update(&kstate, qsc_keccak_rate_256, response->respser, UDIF_SERIAL_NUMBER_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);

		if (response->prooflen > 0U && response->proof != NULL)
		{
			qsc_keccak_update(&kstate, qsc_keccak_rate_256, response->proof, response->prooflen, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, digest);
	}
}

udif_errors udif_query_response_deserialize(udif_query_response* response, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(response != NULL);
	UDIF_ASSERT(input != NULL);

	uint64_t prooflen;
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (response != NULL && input != NULL)
	{
		pos = 0U;
		qsc_memutils_clear((uint8_t*)response, sizeof(udif_query_response));

		if (UDIF_QUERY_RESPONSE_STRUCTURE_SIZE <= inplen)
		{
			qsc_memutils_copy(response->signature, input + pos, UDIF_SIGNED_HASH_SIZE);
			pos += UDIF_SIGNED_HASH_SIZE;
			qsc_memutils_copy(response->queryid, input + pos, UDIF_QUERY_ID_SIZE);
			pos += UDIF_QUERY_ID_SIZE;
			qsc_memutils_copy(response->querydigest, input + pos, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			qsc_memutils_copy(response->respser, input + pos, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			response->verdict = input[pos];
			pos += UDIF_QUERY_VERDICT_SIZE;
			response->timestamp = qsc_intutils_le8to64(input + pos);
			pos += UDIF_VALID_TIME_SIZE;
			prooflen = qsc_intutils_le8to64(input + pos);
			pos += UDIF_QUERY_PROOF_SIZE;

			if (query_verdict_is_valid(response->verdict) == true && prooflen <= UDIF_QUERY_MAX_PROOF_SIZE && pos + (size_t)prooflen == inplen)
			{
				err = udif_error_none;

				if (prooflen > 0U)
				{
					response->proof = (uint8_t*)qsc_memutils_malloc((size_t)prooflen);

					if (response->proof != NULL)
					{
						qsc_memutils_copy(response->proof, input + pos, (size_t)prooflen);
						response->prooflen = (size_t)prooflen;
					}
					else
					{
						err = udif_error_internal;
					}
				}
			}
			else
			{
				err = udif_error_decode_failure;
			}
		}
		else
		{
			err = udif_error_decode_failure;
		}
	}

	return err;
}

udif_errors udif_query_response_serialize(uint8_t* output, size_t* outlen, const udif_query_response* response)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != NULL);
	UDIF_ASSERT(response != NULL);

	size_t pos;
	size_t enclen;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && outlen != NULL && response != NULL)
	{
		enclen = UDIF_QUERY_RESPONSE_STRUCTURE_SIZE + response->prooflen;

		if (query_verdict_is_valid(response->verdict) == true &&
			response->prooflen <= UDIF_QUERY_MAX_PROOF_SIZE &&
			(response->proof != NULL || response->prooflen == 0U) &&
			*outlen >= enclen)
		{
			pos = 0U;

			qsc_memutils_copy(output + pos, response->signature, UDIF_SIGNED_HASH_SIZE);
			pos += UDIF_SIGNED_HASH_SIZE;
			qsc_memutils_copy(output + pos, response->queryid, UDIF_QUERY_ID_SIZE);
			pos += UDIF_QUERY_ID_SIZE;
			qsc_memutils_copy(output + pos, response->querydigest, UDIF_CRYPTO_HASH_SIZE);
			pos += UDIF_CRYPTO_HASH_SIZE;
			qsc_memutils_copy(output + pos, response->respser, UDIF_SERIAL_NUMBER_SIZE);
			pos += UDIF_SERIAL_NUMBER_SIZE;
			output[pos] = response->verdict;
			pos += UDIF_QUERY_VERDICT_SIZE;
			qsc_intutils_le64to8(output + pos, response->timestamp);
			pos += UDIF_VALID_TIME_SIZE;
			qsc_intutils_le64to8(output + pos, (uint64_t)response->prooflen);
			pos += UDIF_QUERY_PROOF_SIZE;

			if (response->prooflen > 0U)
			{
				qsc_memutils_copy(output + pos, response->proof, response->prooflen);
				pos += response->prooflen;
			}

			*outlen = pos;
			err = udif_error_none;
		}
	}

	return err;
}

void udif_query_response_clear(udif_query_response* response)
{
	UDIF_ASSERT(response != NULL);

	if (response != NULL)
	{
		if (response->proof != NULL)
		{
			qsc_memutils_secure_erase(response->proof, response->prooflen);
			qsc_memutils_alloc_free(response->proof);
		}

		qsc_memutils_secure_erase((uint8_t*)response, sizeof(udif_query_response));
	}
}


bool udif_query_predicate_is_canonical(const udif_query* query)
{
	bool res;

	res = false;

	if (query != NULL)
	{
		if (query_type_is_valid(query->querytype) == true && query->predicate != NULL)
		{
			switch (query->querytype)
			{
				case (uint8_t)udif_query_exist:
				case (uint8_t)udif_query_membership_proof:
				{
					res = (query->predlen == UDIF_OBJECT_SERIAL_SIZE);
					break;
				}
				case (uint8_t)udif_query_owner_binding:
				{
					res = (query->predlen == (UDIF_OBJECT_SERIAL_SIZE + UDIF_SERIAL_NUMBER_SIZE));
					break;
				}
				case (uint8_t)udif_query_attr_bucket:
				{
					res = (query->predlen == (UDIF_OBJECT_SERIAL_SIZE + (2U * sizeof(uint64_t))));
					break;
				}
				default:
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

udif_errors udif_query_evaluate_registry(uint8_t* verdict, uint8_t* proof, size_t* prooflen, const udif_query* query, const udif_registry_state* registry, const udif_capability* capability, const uint8_t* subjectser, uint64_t ctime)
{
	UDIF_ASSERT(verdict != NULL);
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(subjectser != NULL);

	udif_registry_leaf leaf = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t attrmax;
	uint64_t attrmin;
	udif_errors err;

	err = udif_error_invalid_input;

	if (verdict != NULL && query != NULL && subjectser != NULL)
	{
		*verdict = (uint8_t)udif_verdict_deny;

		if (udif_query_predicate_is_canonical(query) == false)
		{
			err = udif_error_invalid_request;
		}
		else if (udif_query_is_fresh(query, ctime) == false)
		{
			err = udif_error_time_window;
		}
		else
		{
			err = udif_error_none;

			if (capability != NULL && udif_query_validate_authorization(query, capability, subjectser) == true)
			{
				if (registry != NULL && registry->initialized == true)
				{
					switch (query->querytype)
					{
						case (uint8_t)udif_query_exist:
						{
							*verdict = (udif_registry_get_leaf(&leaf, registry, query->predicate) == udif_error_none) ? (uint8_t)udif_verdict_yes : (uint8_t)udif_verdict_no;
							break;
						}
						case (uint8_t)udif_query_owner_binding:
						{
							qsc_memutils_copy(owner, query->predicate + UDIF_OBJECT_SERIAL_SIZE, UDIF_SERIAL_NUMBER_SIZE);

							if (qsc_memutils_are_equal(owner, registry->ownerser, UDIF_SERIAL_NUMBER_SIZE) == true &&
								udif_registry_get_leaf(&leaf, registry, query->predicate) == udif_error_none &&
								((leaf.flags & UDIF_REGISTRY_FLAG_ACTIVE) != 0U))
							{
								*verdict = (uint8_t)udif_verdict_yes;
							}
							else
							{
								*verdict = (uint8_t)udif_verdict_no;
							}
							break;
						}
						case (uint8_t)udif_query_attr_bucket:
						{
							attrmin = qsc_intutils_le8to64(query->predicate + UDIF_OBJECT_SERIAL_SIZE);
							attrmax = qsc_intutils_le8to64(query->predicate + UDIF_OBJECT_SERIAL_SIZE + sizeof(uint64_t));

							if (attrmin <= attrmax && udif_registry_get_leaf(&leaf, registry, query->predicate) == udif_error_none &&
								(uint64_t)leaf.flags >= attrmin && (uint64_t)leaf.flags <= attrmax)
							{
								*verdict = (uint8_t)udif_verdict_yes;
							}
							else
							{
								*verdict = (uint8_t)udif_verdict_no;
							}
							break;
						}
						case (uint8_t)udif_query_membership_proof:
						{
							if (udif_registry_get_leaf(&leaf, registry, query->predicate) == udif_error_none)
							{
								if (proof != NULL && prooflen != NULL)
								{
									*verdict = (uint8_t)udif_verdict_yes;
									err = udif_registry_generate_proof(proof, prooflen, registry, query->predicate);
								}
								else
								{
									*verdict = (uint8_t)udif_verdict_no;
								}
							}
							else
							{
								*verdict = (uint8_t)udif_verdict_no;
							}
							break;
						}
						default:
						{
							err = udif_error_invalid_request;
							break;
						}
					}
				}
				else
				{
					*verdict = (uint8_t)udif_verdict_no;

					if (prooflen != NULL)
					{
						*prooflen = 0U;
					}
				}
			}
			else if (prooflen != NULL)
			{
				*prooflen = 0U;
			}
		}
	}

	qsc_memutils_secure_erase((uint8_t*)&leaf, sizeof(udif_registry_leaf));
	qsc_memutils_secure_erase(owner, sizeof(owner));

	return err;
}

bool udif_query_validate_authorization(const udif_query* query, const udif_capability* capability, const uint8_t* targser)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(targser != NULL);

	uint8_t capdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint32_t verb;
	bool res;

	res = false;
	verb = 0U;

	if (query != NULL && capability != NULL && targser != NULL)
	{
		if (udif_policy_query_verb(query->querytype, &verb) == true)
		{
			/* verify capability reference matches */
			if (udif_capability_compute_digest(capdigest, capability) == udif_error_none)
			{
				if (qsc_memutils_are_equal(query->capabilityref, capdigest, UDIF_CRYPTO_HASH_SIZE) == true)
				{
					/* verify capability is issued to target */
					if (qsc_memutils_are_equal(capability->issuedto, targser, UDIF_SERIAL_NUMBER_SIZE) == true)
					{
						/* verify the required query verb under intra-domain scope */
						res = udif_capability_grants_permission(capability, verb, (uint32_t)udif_scope_intra_domain, qsc_timestamp_datetime_utc());
					}
				}
			}
		}

		qsc_memutils_secure_erase(capdigest, UDIF_CRYPTO_HASH_SIZE);
	}

	return res;
}

bool udif_query_verify_response_signature(const udif_query_response* response, const uint8_t* respverkey)
{
	UDIF_ASSERT(response != NULL);
	UDIF_ASSERT(respverkey != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (response != NULL && respverkey != NULL)
	{
		udif_query_response_compute_digest(digest1, response, NULL);
		mlen = 0U;

		if (udif_signature_verify(digest2, &mlen, response->signature, UDIF_SIGNED_HASH_SIZE, respverkey) == true)
		{
			if (mlen == UDIF_CRYPTO_HASH_SIZE)
			{
				res = qsc_memutils_are_equal(digest1, digest2, sizeof(digest1));
			}

			qsc_memutils_secure_erase(digest2, UDIF_CRYPTO_HASH_SIZE);
		}

		qsc_memutils_secure_erase(digest1, UDIF_CRYPTO_HASH_SIZE);
	}

	return res;
}

bool udif_query_verify_response(const udif_query_response* response, const udif_query* query, const uint8_t* respverkey)
{
	UDIF_ASSERT(response != NULL);
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(respverkey != NULL);

	uint8_t qdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (response != NULL && query != NULL && respverkey != NULL)
	{
		if (qsc_memutils_are_equal(response->queryid, query->queryid, UDIF_QUERY_ID_SIZE) == true)
		{
			udif_query_compute_digest(qdigest, query);

			if (qsc_memutils_are_equal(response->querydigest, qdigest, UDIF_CRYPTO_HASH_SIZE) == true)
			{
				res = udif_query_verify_response_signature(response, respverkey);
			}

			qsc_memutils_secure_erase(qdigest, sizeof(qdigest));
		}
	}

	return res;
}
