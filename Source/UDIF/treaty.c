#include "treaty.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

udif_errors udif_treaty_accept(udif_treaty* treaty, const uint8_t* domsigkeyb, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(treaty != NULL);
	UDIF_ASSERT(domsigkeyb != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE];
	udif_errors err;

	err = udif_error_invalid_input;

	if (treaty != NULL && domsigkeyb != NULL && rng_generate != NULL)
	{
		size_t smlen;

		/* verify treaty is pending domain B signature is empty */
		if (udif_treaty_is_pending(treaty) == true)
		{
			/* compute digest */
			udif_treaty_compute_digest(digest, treaty);

			/* domain B signs */
			smlen = 0U;

			if (udif_signature_sign(treaty->domsigb, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, domsigkeyb, rng_generate) == true)
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
				err = udif_error_signature_invalid;
			}
		}
		else
		{
			err = udif_error_invalid_state;
		}

		qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
	}

	return err;
}

bool udif_treaty_allows_scope(const udif_treaty* treaty, uint32_t scope)
{
	UDIF_ASSERT(treaty != NULL);

	bool res;

	res = false;

	if (treaty != NULL && scope < UDIF_TREATY_SCOPE_MAX)
	{
		res = ((treaty->scopebitmap & scope) != 0U);
	}

	return res;
}

void udif_treaty_clear(udif_treaty* treaty)
{
	if (treaty != NULL)
	{
		qsc_memutils_clear((uint8_t*)treaty, sizeof(udif_treaty));
	}
}

bool udif_treaty_compare(const udif_treaty* a, const udif_treaty* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = (qsc_memutils_are_equal((const uint8_t*)a, (const uint8_t*)b, sizeof(udif_treaty)) == true);
	}

	return res;
}

udif_errors udif_treaty_create_proposal(udif_treaty* treaty, const uint8_t* treatyid, const uint8_t* domsera, const uint8_t* domserb, uint32_t scopebitmap,
	uint64_t validfrom, uint64_t validto, uint32_t policy, const uint8_t* domsigkeya, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(treaty != NULL);
	UDIF_ASSERT(treatyid != NULL);
	UDIF_ASSERT(domsera != NULL);
	UDIF_ASSERT(domserb != NULL);
	UDIF_ASSERT(domsigkeya != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (treaty != NULL && treatyid != NULL && domsera != NULL && domserb != NULL && domsigkeya != NULL && rng_generate != NULL)
	{
		size_t smlen;

		/* validate parameters */
		if (validto > validfrom)
		{
			if ((validto - validfrom) <= UDIF_TREATY_MAX_DURATION)
			{
				/* domains must be different */
				if (qsc_memutils_are_equal(domsera, domserb, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					qsc_memutils_clear((uint8_t*)treaty, sizeof(udif_treaty));
					qsc_memutils_copy(treaty->treatyid, treatyid, UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_copy(treaty->domsera, domsera, UDIF_SERIAL_NUMBER_SIZE);
					qsc_memutils_copy(treaty->domserb, domserb, UDIF_SERIAL_NUMBER_SIZE);
					treaty->scopebitmap = scopebitmap;
					treaty->validfrom = validfrom;
					treaty->validto = validto;
					treaty->policy = policy;

					/* compute digest */
					udif_treaty_compute_digest(digest, treaty);

					/* domain A signs */
					smlen = 0U;

					if (udif_signature_sign(treaty->domsiga, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, domsigkeya, rng_generate) == true)
					{
						if (smlen == UDIF_SIGNED_HASH_SIZE)
						{
							/* domain B signature is empty */
							qsc_memutils_clear(treaty->domsigb, UDIF_SIGNED_HASH_SIZE);

							err = udif_error_none;
						}
						else
						{
							err = udif_error_signature_invalid;
						}
					}
					else
					{
						err = udif_error_signature_invalid;
					}
				}
				else
				{
					err = udif_error_invalid_input;
				}

				qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
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

udif_errors udif_treaty_compute_digest(uint8_t* digest, const udif_treaty* treaty)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(treaty != NULL);

	qsc_keccak_state kstate = { 0U };
	uint8_t buf[sizeof(uint64_t)] = { 0U };
	udif_errors err;

	err = udif_error_encode_failure;

	if (digest != NULL && treaty != NULL)
	{
		qsc_sha3_initialize(&kstate);

		/* hash all fields except signatures */
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, treaty->treatyid, UDIF_CRYPTO_HASH_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, treaty->domsera, UDIF_SERIAL_NUMBER_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, treaty->domserb, UDIF_SERIAL_NUMBER_SIZE, QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_intutils_le32to8(buf, treaty->scopebitmap);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint32_t), QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_intutils_le64to8(buf, treaty->validfrom);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint64_t), QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_intutils_le64to8(buf, treaty->validto);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint64_t), QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_intutils_le32to8(buf, treaty->policy);
		qsc_keccak_update(&kstate, qsc_keccak_rate_256, buf, sizeof(uint32_t), QSC_KECCAK_PERMUTATION_ROUNDS);

		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, digest);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_treaty_deserialize(udif_treaty* treaty, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(treaty != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (input != NULL && treaty != NULL && inplen >= UDIF_TREATY_STRUCTURE_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(treaty->domsiga, input, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(treaty->domsigb, input + pos, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(treaty->domsera, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(treaty->domserb, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(treaty->treatyid, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		treaty->validfrom = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		treaty->validto = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		treaty->policy = qsc_intutils_le8to32(input + pos);
		pos += UDIF_TREATY_POLICY_VERSION_SIZE;
		treaty->scopebitmap = qsc_intutils_le8to32(input + pos);
		pos += UDIF_TREATY_SCOPE_QUERY_SIZE;

		err = udif_error_none;
	}

	return err;
}

size_t udif_treaty_encoded_size(const udif_treaty* treaty)
{
	UDIF_ASSERT(treaty != NULL);

	size_t tlen;

	tlen = 0U;

	if (treaty != NULL)
	{
		/* fixed size encoding */
		tlen = UDIF_TREATY_STRUCTURE_SIZE;
	}

	return tlen;
}

uint64_t udif_treaty_get_duration(const udif_treaty* treaty)
{
	UDIF_ASSERT(treaty != NULL);

	uint64_t duration;

	duration = 0U;

	if (treaty != NULL && treaty->validto > treaty->validfrom)
	{
		duration = treaty->validto - treaty->validfrom;
	}

	return duration;
}

bool udif_treaty_is_active(const udif_treaty* treaty, uint64_t ctime)
{
	UDIF_ASSERT(treaty != NULL);

	bool res;

	res = false;

	if (treaty != NULL)
	{
		/* treaty must not be pending */
		if (udif_treaty_is_pending(treaty) == false)
		{
			/* check time window */
			if (ctime >= treaty->validfrom && ctime <= treaty->validto)
			{
				res = true;
			}
		}
	}

	return res;
}

bool udif_treaty_is_expired(const udif_treaty* treaty, uint64_t currtime)
{
	UDIF_ASSERT(treaty != NULL);

	bool res;

	res = true;

	if (treaty != NULL)
	{
		res = (currtime > treaty->validto);
	}

	return res;
}

bool udif_treaty_is_participant(const udif_treaty* treaty, const uint8_t* entityser)
{
	UDIF_ASSERT(treaty != NULL);
	UDIF_ASSERT(entityser != NULL);

	bool res;

	res = false;

	if (treaty != NULL && entityser != NULL)
	{
		/* check if entity is domain A */
		if (qsc_memutils_are_equal(treaty->domsera, entityser, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			res = true;
		}

		/* check if entity is domain B */
		else if (qsc_memutils_are_equal(treaty->domserb, entityser, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			res = true;
		}
	}

	return res;
}

bool udif_treaty_is_pending(const udif_treaty* treaty)
{
	UDIF_ASSERT(treaty != NULL);

	bool res;

	res = false;

	if (treaty != NULL)
	{
		/* check if domain B signature is all zeros */
		res = qsc_memutils_zeroed(treaty->domsigb, UDIF_SIGNED_HASH_SIZE);
	}

	return res;
}

udif_errors udif_treaty_serialize(uint8_t* output, size_t outlen, const udif_treaty* treaty)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(treaty != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && treaty != NULL && outlen >= UDIF_TREATY_STRUCTURE_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output + pos, treaty->domsiga, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, treaty->domsigb, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, treaty->domsera, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, treaty->domserb, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, treaty->treatyid, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, treaty->validfrom);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, treaty->validto);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le32to8(output + pos, treaty->policy);
		pos += UDIF_TREATY_POLICY_VERSION_SIZE;
		qsc_intutils_le32to8(output + pos, treaty->scopebitmap);
		pos += UDIF_TREATY_SCOPE_QUERY_SIZE;

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_treaty_validate(const udif_treaty* treaty)
{
	UDIF_ASSERT(treaty != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (treaty != NULL)
	{
		/* validate time range */
		if (treaty->validto > treaty->validfrom)
		{
			/* validate duration */
			if ((treaty->validto - treaty->validfrom) <= UDIF_TREATY_MAX_DURATION)
			{
				/* validate domains are different */
				if (qsc_memutils_are_equal(treaty->domsera, treaty->domserb, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					/* validate scope bitmap is not empty */
					if (treaty->scopebitmap != 0U)
					{
						err = udif_error_none;
					}
				}
			}
		}
	}

	return err;
}

bool udif_treaty_verify(const udif_treaty* treaty, const uint8_t* domverkeya, const uint8_t* domverkeyb)
{
	UDIF_ASSERT(treaty != NULL);
	UDIF_ASSERT(domverkeya != NULL);
	UDIF_ASSERT(domverkeyb != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest3[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (treaty != NULL && domverkeya != NULL && domverkeyb != NULL)
	{
		size_t mlen;

		/* compute digest */
		if (udif_treaty_compute_digest(digest1, treaty) == udif_error_none)
		{
			/* verify domain A signature */
			mlen = 0U;

			if (udif_signature_verify(digest2, &mlen, treaty->domsiga, UDIF_SIGNED_HASH_SIZE, domverkeya) == true)
			{
				if (mlen == UDIF_CRYPTO_HASH_SIZE)
				{
					if (qsc_memutils_are_equal(digest1, digest2, sizeof(digest1)) == true)
					{
						mlen = 0U;

						/* verify domain B signature */
						if (udif_signature_verify(digest3, &mlen, treaty->domsigb, UDIF_SIGNED_HASH_SIZE, domverkeyb) == true)
						{
							if (mlen == UDIF_CRYPTO_HASH_SIZE)
							{
								res = qsc_memutils_are_equal(digest1, digest3, sizeof(digest1));
							}

							qsc_memutils_clear(digest3, UDIF_CRYPTO_HASH_SIZE);
						}
					}
				}

				qsc_memutils_clear(digest2, UDIF_CRYPTO_HASH_SIZE);
			}

			qsc_memutils_clear(digest1, UDIF_CRYPTO_HASH_SIZE);
		}
	}

	return res;
}
