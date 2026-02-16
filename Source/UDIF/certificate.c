#include "certificate.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

bool udif_certificate_check_capability_inheritance(const uint8_t* childbitmap, const uint8_t* parentbitmap)
{
	UDIF_ASSERT(childbitmap != NULL);
	UDIF_ASSERT(parentbitmap != NULL);

	bool res;

	res = true;

	if (childbitmap != NULL && parentbitmap != NULL)
	{
		/* check that child caps are subset of parent caps */
		for (size_t i = 0; i < UDIF_CAPABILITY_MASK_SIZE; ++i)
		{
			/* if child has a bit that parent doesn't, inheritance fails */
			if ((childbitmap[i] & ~parentbitmap[i]) != 0)
			{
				res = false;
				break;
			}
		}
	}
	else
	{
		res = false;
	}

	return res;
}

void udif_certificate_clear(udif_certificate* cert)
{
	if (cert != NULL)
	{
		qsc_memutils_clear((uint8_t*)cert, sizeof(udif_certificate));
	}
}

bool udif_certificate_compare(const udif_certificate* a, const udif_certificate* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = (qsc_memutils_are_equal((const uint8_t*)a, (const uint8_t*)b, sizeof(udif_certificate)) == true);
	}

	return res;
}

udif_errors udif_certificate_compute_digest(uint8_t* digest, const udif_certificate* cert)
{
	uint8_t buf[UDIF_CERTIFICATE_SIGNING_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (cert != NULL && digest != NULL)
	{
		pos = 0U;

		qsc_memutils_copy(buf, cert->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(buf + pos, cert->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(buf + pos, cert->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, cert->valid.from);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(buf + pos, cert->valid.to);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(buf + pos, cert->capability, UDIF_CAPABILITY_MASK_SIZE);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le32to8(buf + pos, cert->policy);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		buf[pos] = cert->role;
		pos += UDIF_ROLE_SIZE;
		buf[pos] = cert->suiteid;

		/* compute digest and sign with parent key */
		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_CERT_DIGEST, sizeof(UDIF_LABEL_CERT_DIGEST) - 1U, NULL, 0U);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_deserialize(udif_certificate* cert, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (input != NULL && cert != NULL && inplen >= UDIF_CERTIFICATE_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(cert->signature, input, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(cert->verkey, input + pos, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(cert->issuer, input + pos, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(cert->serial, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		cert->valid.from = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		cert->valid.to = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(cert->capability, input + pos, UDIF_CAPABILITY_MASK_SIZE);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		cert->policy = qsc_intutils_le8to32(input + pos);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		cert->role = input[pos];
		pos += UDIF_ROLE_SIZE;
		cert->suiteid = input[pos];

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_generate(udif_certificate* cert, udif_signature_keypair* keypair, const udif_certificate* parentcert,
	const uint8_t* parentsigkey, udif_roles role, const uint8_t* serial, udif_valid_time* valid, const uint8_t* capability,
	uint32_t policy, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(keypair != NULL);
	UDIF_ASSERT(parentcert != NULL);
	UDIF_ASSERT(parentsigkey != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(capability != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (cert != NULL && keypair != NULL && parentcert != NULL && parentsigkey != NULL && serial != NULL && capability != NULL && valid != NULL && rng_generate != NULL)
	{
		/* verify capability inheritance */
		if (udif_certificate_check_capability_inheritance(capability, parentcert->capability) == true)
		{
			/* verify parent validity period encompasses child */
			if (valid->from >= parentcert->valid.from && valid->to <= parentcert->valid.to)
			{
				qsc_memutils_clear((uint8_t*)cert, sizeof(udif_certificate));
				qsc_memutils_clear((uint8_t*)keypair, sizeof(udif_signature_keypair));

				/* generate signature keypair */
				udif_signature_generate_keypair(keypair->verkey, keypair->sigkey, rng_generate);

				if (parentcert->suiteid == UDIF_SUITE_ID)
				{
					cert->suiteid = parentcert->suiteid;
					cert->role = role;
					qsc_memutils_copy(cert->serial, serial, UDIF_SERIAL_NUMBER_SIZE);
					qsc_memutils_copy(cert->issuer, parentcert->serial, UDIF_SERIAL_NUMBER_SIZE);

					if (valid->to >= valid->from)
					{
						cert->valid.from = valid->from;
						cert->valid.to = valid->to;
						qsc_memutils_copy(cert->verkey, keypair->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
						cert->policy = policy;
						qsc_memutils_copy(cert->capability, capability, UDIF_CAPABILITY_MASK_SIZE);

						err = udif_certificate_sign(cert, parentsigkey, rng_generate);
					}
				}
			}
		}
	}

	return err;
}

udif_errors udif_certificate_root_generate(udif_certificate* rcert, udif_signature_keypair* keypair, const uint8_t* serial,
	udif_valid_time* valid, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(rcert != NULL);
	UDIF_ASSERT(keypair != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(valid != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t fullcap[UDIF_CAPABILITY_MASK_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (rcert != NULL && keypair != NULL && serial != NULL && valid != NULL && rng_generate != NULL)
	{
		/* clear structures */
		qsc_memutils_clear((uint8_t*)rcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)keypair, sizeof(udif_signature_keypair));

		/* generate signature keypair */
		udif_signature_generate_keypair(keypair->verkey, keypair->sigkey, rng_generate);

		/* set certificate fields */
		rcert->suiteid = UDIF_SUITE_ID;
		rcert->role = (uint8_t)udif_role_root;

		/* on the root we copy the serial to the issuer unless pki compatability is enabled */
#if !defined(UDIF_CERTIFICATE_PKI_ENABLED)
		qsc_memutils_copy(rcert->issuer, serial, UDIF_SERIAL_NUMBER_SIZE);
#endif
		qsc_memutils_copy(rcert->serial, serial, UDIF_SERIAL_NUMBER_SIZE);

		if (valid->to >= valid->from)
		{
			rcert->valid.from = valid->from;
			rcert->valid.to = valid->to;

			qsc_memutils_copy(rcert->verkey, keypair->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
			rcert->policy = 0U;

			/* root gets all capabilities */
			qsc_memutils_clear(fullcap, UDIF_CAPABILITY_MASK_SIZE);
			qsc_memutils_set_value(fullcap, UDIF_CAPABILITY_MASK_SIZE, 0xFFU);
			qsc_memutils_copy(rcert->capability, fullcap, UDIF_CAPABILITY_MASK_SIZE);

			/* compute digest and self-sign */
			err = udif_certificate_sign(rcert, keypair->sigkey, rng_generate);
		}
	}

	return err;
}

bool udif_certificate_is_expired(const udif_certificate* cert, uint64_t curtime)
{
	UDIF_ASSERT(cert != NULL);

	bool res;

	res = true;

	if (cert != NULL)
	{
		res = (curtime < cert->valid.from || curtime > cert->valid.to);
	}

	return res;
}

bool udif_certificate_is_valid(const udif_certificate* cert, const udif_certificate* issuer, uint64_t curtime)
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (cert != NULL && issuer != NULL)
	{
		/* check expiration */
		if (udif_certificate_is_expired(cert, curtime) == false)
		{
			/* verify signature and chain */
			res = udif_certificate_verify_chain(cert, issuer);
		}
	}

	return res;
}

udif_errors udif_certificate_serialize(uint8_t* output, size_t outlen, const udif_certificate* cert)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0U);
	UDIF_ASSERT(cert != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && cert != NULL && outlen >= UDIF_CERTIFICATE_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output, cert->signature, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, cert->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, cert->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, cert->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, cert->valid.from);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, cert->valid.to);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(output + pos, cert->capability, UDIF_CAPABILITY_MASK_SIZE);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le32to8(output + pos, cert->policy);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		output[pos] = cert->role;
		pos += UDIF_ROLE_SIZE;
		output[pos] = cert->suiteid;

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_sign(udif_certificate* cert, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t smlen;
	udif_errors err;

	err = udif_error_encode_failure;

	if (cert != NULL && sigkey != NULL && rng_generate != NULL)
	{
		smlen = 0U;

		err = udif_certificate_compute_digest(digest, cert);

		if (err == udif_error_none)
		{
			if (udif_signature_sign(cert->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, sigkey, rng_generate) == true)
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
	}

	return err;
}

bool udif_certificate_verify(const udif_certificate* cert, const udif_certificate* issuer)
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(issuer != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (cert != NULL && issuer != NULL)
	{
		/* verify issuer serial matches */
		if (qsc_memutils_are_equal(cert->issuer, issuer->serial, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			/* verify suite id matches */
			if (cert->suiteid == issuer->suiteid)
			{
				/* compute digest */
				if (udif_certificate_compute_digest(digest1, cert) == udif_error_none)
				{
					/* verify signature */
					mlen = 0U;
					res = udif_signature_verify(digest2, &mlen, cert->signature, UDIF_SIGNED_HASH_SIZE, issuer->verkey);

					if (mlen == UDIF_CRYPTO_HASH_SIZE)
					{
						res = qsc_memutils_are_equal(digest1, digest2, sizeof(digest1));
					}

					qsc_memutils_clear(digest1, UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_clear(digest2, UDIF_CRYPTO_HASH_SIZE);
				}
			}
		}
	}

	return res;
}

bool udif_certificate_verify_chain(const udif_certificate* cert, const udif_certificate* issuer)
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (cert != NULL && issuer != NULL)
	{
		/* verify signature */
		if (udif_certificate_verify(cert, issuer) == true)
		{
			/* verify capability inheritance */
			if (udif_certificate_check_capability_inheritance(cert->capability, issuer->capability) == true)
			{
				/* verify validity period is within parent's */
				if (cert->valid.from >= issuer->valid.from && cert->valid.to <= issuer->valid.to)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

bool udif_certificate_verify_root_chain(const udif_certificate* cert, const udif_certificate* issuer)
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (cert != NULL && issuer != NULL)
	{
		/* verify signature */
		if (udif_certificate_verify(cert, issuer) == true)
		{
			/* verify capability inheritance */
			if (udif_certificate_check_capability_inheritance(cert->capability, issuer->capability) == true)
			{
				/* verify validity period is within parent's */
				if (cert->valid.from >= issuer->valid.from && cert->valid.to <= issuer->valid.to)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

void udif_certificate_keypair_clear(udif_signature_keypair* keypair)
{
	if (keypair != NULL)
	{
		qsc_memutils_clear((uint8_t*)keypair, sizeof(udif_signature_keypair));
	}
}
