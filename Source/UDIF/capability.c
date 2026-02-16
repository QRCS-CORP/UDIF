#include "udif.h"
#include "capability.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"

bool udif_capability_allows_scope(const udif_capability* capability, uint32_t scope)
{
	UDIF_ASSERT(capability != NULL);

	bool res;

	res = false;

	if (capability != NULL && scope < 32U)
	{
		res = ((capability->scopebitmap & (1ULL << scope)) != 0U);
	}

	return res;
}

bool udif_capability_allows_verb(const udif_capability* capability, uint32_t verb)
{
	UDIF_ASSERT(capability != NULL);

	bool res;

	res = false;

	if (capability != NULL && verb < 32U)
	{
		res = ((capability->verbsbitmap & (1ULL << verb)) != 0U);
	}

	return res;
}

void udif_capability_clear(udif_capability* capability)
{
	if (capability != NULL)
	{
		qsc_memutils_clear((uint8_t*)capability, sizeof(udif_capability));
	}
}

udif_errors udif_capability_create(udif_capability* capability, uint32_t verbsbitmap, uint32_t scopebitmap, const uint8_t* issuedto,
	const uint8_t* issuedby, uint64_t validto, uint32_t policy, const uint8_t* issuerkey)
{
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(issuedto != NULL);
	UDIF_ASSERT(issuedby != NULL);
	UDIF_ASSERT(issuerkey != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (capability != NULL && issuedto != NULL && issuedby != NULL && issuerkey != NULL)
	{
		qsc_memutils_clear((uint8_t*)capability, sizeof(udif_capability));

		capability->verbsbitmap = verbsbitmap;
		capability->scopebitmap = scopebitmap;
		qsc_memutils_copy(capability->issuedto, issuedto, UDIF_SERIAL_NUMBER_SIZE);
		qsc_memutils_copy(capability->issuedby, issuedby, UDIF_SERIAL_NUMBER_SIZE);
		capability->validto = validto;
		capability->policy = policy;

		/* compute digest */
		err = udif_capability_compute_digest(capability->digest, capability);

		if (err == udif_error_none)
		{
			/* generate KMAC tag */
			qsc_kmac256_compute(capability->tag, UDIF_CRYPTO_MAC_SIZE, capability->digest, UDIF_CRYPTO_HASH_SIZE, issuerkey, UDIF_CRYPTO_KEY_SIZE,
				(const uint8_t*)UDIF_LABEL_CAP_DIGEST, sizeof(UDIF_LABEL_CAP_DIGEST) - 1U);
		}
	}

	return err;
}

udif_errors udif_capability_compute_digest(uint8_t* digest, const udif_capability* capability)
{
	uint8_t buf[UDIF_CAPABILITY_SIGNED_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;
	pos = 0U;

	if (digest != NULL && capability != NULL)
	{
		qsc_memutils_copy(buf + pos, capability->issuedby, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(buf + pos, capability->issuedto, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, capability->scopebitmap);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		qsc_intutils_le64to8(buf + pos, capability->validto);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(buf + pos, capability->verbsbitmap);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		qsc_intutils_le32to8(buf + pos, capability->policy);

		/* compute digest */
		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_CAP_DIGEST, sizeof(UDIF_LABEL_CAP_DIGEST) - 1U, NULL, 0U);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_capability_deserialize(udif_capability* capability, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;

	if (input != NULL && capability != NULL && inplen >= UDIF_CAPABILITY_ENCODED_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(capability->digest, input, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(capability->tag, input + pos, UDIF_CRYPTO_MAC_SIZE);
		pos += UDIF_CRYPTO_MAC_SIZE;
		qsc_memutils_copy(capability->issuedby, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(capability->issuedto, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		capability->scopebitmap = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		capability->validto = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		capability->verbsbitmap = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		capability->policy = qsc_intutils_le8to32(input + pos);
		pos += UDIF_CAPABILITY_POLICY_SIZE;

		err = udif_error_none;
	}

	return err;
}

bool udif_capability_grants_permission(const udif_capability* capability, uint32_t verb, uint32_t scope, uint64_t ctime)
{
	UDIF_ASSERT(capability != NULL);

	bool res;

	res = false;

	if (capability != NULL)
	{
		/* check expiration */
		if (udif_capability_is_expired(capability, ctime) == false)
		{
			/* check verb */
			if (udif_capability_allows_verb(capability, verb) == true)
			{
				/* check scope */
				res = udif_capability_allows_scope(capability, scope);
			}
		}
	}

	return res;
}

bool udif_capability_is_expired(const udif_capability* capability, uint64_t ctime)
{
	UDIF_ASSERT(capability != NULL);

	bool res;

	res = true;

	if (capability != NULL)
	{
		res = (ctime > capability->validto);
	}

	return res;
}

udif_errors udif_capability_serialize(uint8_t* output, size_t outlen, const udif_capability* capability)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(capability != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && capability != NULL && outlen >= UDIF_CAPABILITY_ENCODED_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output, capability->digest, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, capability->tag, UDIF_CRYPTO_MAC_SIZE);
		pos += UDIF_CRYPTO_MAC_SIZE;
		qsc_memutils_copy(output + pos, capability->issuedby, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, capability->issuedto, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, capability->scopebitmap);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		qsc_intutils_le64to8(output + pos, capability->validto);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, capability->verbsbitmap);
		pos += UDIF_CAPABILITY_BITMAP_SIZE;
		qsc_intutils_le32to8(output + pos, capability->policy);
		pos += UDIF_CAPABILITY_POLICY_SIZE;

		err = udif_error_none;
	}

	return err;
}

bool udif_capability_verify(const udif_capability* capability, const uint8_t* issuerkey)
{
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(issuerkey != NULL);

	udif_capability tcap = { 0U };
	uint8_t ctag[UDIF_CRYPTO_MAC_SIZE] = { 0U };
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (capability != NULL && issuerkey != NULL)
	{
		/* make a copy to recompute digest */
		qsc_memutils_copy((uint8_t*)&tcap, (const uint8_t*)capability, sizeof(udif_capability));

		/* recompute digest */
		if (udif_capability_compute_digest(digest, &tcap) == udif_error_none)
		{
			/* verify digest matches */
			if (qsc_memutils_are_equal(digest, capability->digest, UDIF_CRYPTO_HASH_SIZE) == true)
			{
				/* recompute KMAC tag */
				qsc_kmac256_compute(ctag, UDIF_CRYPTO_MAC_SIZE, digest, UDIF_CRYPTO_HASH_SIZE, issuerkey, UDIF_CRYPTO_KEY_SIZE,
					(const uint8_t*)UDIF_LABEL_CAP_DIGEST, sizeof(UDIF_LABEL_CAP_DIGEST) - 1U);

				res = (qsc_intutils_verify(ctag, capability->tag, UDIF_CRYPTO_MAC_SIZE) == 0);
				qsc_memutils_clear(ctag, UDIF_CRYPTO_MAC_SIZE);
			}

			qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_clear((uint8_t*)&tcap, sizeof(udif_capability));
		}
	}

	return res;
}
