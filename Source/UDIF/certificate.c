#include "certificate.h"
#include "capability.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

static bool certificate_csr_time_valid(uint64_t timestamp, uint64_t curtime)
{
	bool res;

	res = false;

	if (timestamp <= (curtime + UDIF_TIME_WINDOW_SECONDS))
	{
		if ((timestamp + UDIF_TIME_WINDOW_SECONDS) >= curtime)
		{
			res = true;
		}
	}

	return res;
}

bool udif_certificate_role_transition_valid(udif_roles parentrole, udif_roles childrole)
{
	bool res;

	res = false;

	if (parentrole == udif_role_root)
	{
		res = (childrole == udif_role_ubc);
	}
	else if (parentrole == udif_role_ubc)
	{
		res = (childrole == udif_role_ubc || childrole == udif_role_ugc);
	}
	else if (parentrole == udif_role_ugc)
	{
		res = (childrole == udif_role_client);
	}
	else
	{
		res = false;
	}

	return res;
}

udif_errors udif_certificate_csr_compute_digest(uint8_t* digest, const udif_certificate_csr* csr)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(csr != NULL);

	uint8_t buf[UDIF_CERTIFICATE_CSR_SIGNING_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (digest != NULL && csr != NULL)
	{
		pos = 0U;

		qsc_memutils_copy(buf, csr->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(buf + pos, csr->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, csr->valid.from);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(buf + pos, csr->valid.to);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(buf + pos, csr->capability);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le64to8(buf + pos, csr->policy);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		qsc_intutils_le64to8(buf + pos, csr->timestamp);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(buf + pos, csr->nonce, UDIF_CERTIFICATE_CSR_NONCE_SIZE);
		pos += UDIF_CERTIFICATE_CSR_NONCE_SIZE;
		buf[pos] = (uint8_t)csr->role;
		pos += UDIF_ROLE_SIZE;
		buf[pos] = csr->suiteid;

		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_CERT_DIGEST, sizeof(UDIF_LABEL_CERT_DIGEST) - 1U, NULL, 0U);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_csr_create(udif_certificate_csr* csr, const uint8_t* serial, const uint8_t* verkey, const uint8_t* sigkey, 
	udif_roles role, const udif_valid_time* valid, uint64_t capability, uint64_t policy, uint64_t timestamp, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(csr != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(verkey != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(valid != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t smlen;
	udif_errors err;

	err = udif_error_invalid_input;

	if (csr != NULL && serial != NULL && verkey != NULL && sigkey != NULL && valid != NULL && rng_generate != NULL)
	{
		if (valid->to >= valid->from && capability != 0U && role != udif_role_none && role != udif_role_root)
		{
			qsc_memutils_clear((uint8_t*)csr, sizeof(udif_certificate_csr));
			qsc_memutils_copy(csr->serial, serial, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(csr->verkey, verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
			csr->valid.from = valid->from;
			csr->valid.to = valid->to;
			csr->capability = capability;
			csr->policy = policy;
			csr->timestamp = timestamp;
			csr->role = role;
			csr->suiteid = UDIF_SUITE_ID;

			if (rng_generate(csr->nonce, UDIF_CERTIFICATE_CSR_NONCE_SIZE) == true)
			{
				smlen = 0U;
				err = udif_certificate_csr_compute_digest(digest, csr);

				if (err == udif_error_none)
				{
					if (udif_signature_sign(csr->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, sigkey, rng_generate) == true)
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
			else
			{
				err = udif_error_internal;
			}
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return err;
}

udif_errors udif_certificate_csr_deserialize(udif_certificate_csr* csr, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(csr != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;

	if (csr != NULL && input != NULL && inplen == UDIF_CERTIFICATE_CSR_SIZE)
	{
		pos = 0U;
		qsc_memutils_clear((uint8_t*)csr, sizeof(udif_certificate_csr));

		qsc_memutils_copy(csr->signature, input, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(csr->verkey, input + pos, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(csr->serial, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		csr->valid.from = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		csr->valid.to = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		csr->capability = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		csr->policy = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		csr->timestamp = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(csr->nonce, input + pos, UDIF_CERTIFICATE_CSR_NONCE_SIZE);
		pos += UDIF_CERTIFICATE_CSR_NONCE_SIZE;
		csr->role = (udif_roles)input[pos];
		pos += UDIF_ROLE_SIZE;
		csr->suiteid = input[pos];

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_csr_issue(udif_certificate* cert, const udif_certificate_csr* csr, const udif_certificate* parentcert, 
	const uint8_t* parentsigkey, uint64_t curtime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(csr != NULL);
	UDIF_ASSERT(parentcert != NULL);
	UDIF_ASSERT(parentsigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (cert != NULL && csr != NULL && parentcert != NULL && parentsigkey != NULL && rng_generate != NULL)
	{
		if (csr->suiteid == UDIF_SUITE_ID && parentcert->suiteid == UDIF_SUITE_ID)
		{
			if (certificate_csr_time_valid(csr->timestamp, curtime) == true)
			{
				if (udif_certificate_csr_verify(csr) == true)
				{
					if (udif_certificate_role_transition_valid(parentcert->role, csr->role) == true)
					{
						if (udif_certificate_check_capability_inheritance(csr->capability, parentcert->capability) == true)
						{
							if (csr->valid.from >= parentcert->valid.from && csr->valid.to <= parentcert->valid.to)
							{
								qsc_memutils_clear((uint8_t*)cert, sizeof(udif_certificate));
								qsc_memutils_copy(cert->verkey, csr->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
								qsc_memutils_copy(cert->serial, csr->serial, UDIF_SERIAL_NUMBER_SIZE);
								qsc_memutils_copy(cert->issuer, parentcert->serial, UDIF_SERIAL_NUMBER_SIZE);
								cert->valid.from = csr->valid.from;
								cert->valid.to = csr->valid.to;
								cert->capability = csr->capability;
								cert->policy = csr->policy;
								cert->role = csr->role;
								cert->suiteid = parentcert->suiteid;
								err = udif_certificate_sign(cert, parentsigkey, rng_generate);
							}
							else
							{
								err = udif_error_certificate_expired;
							}
						}
						else
						{
							err = udif_error_not_authorized;
						}
					}
					else
					{
						err = udif_error_not_authorized;
					}
				}
				else
				{
					err = udif_error_signature_invalid;
				}
			}
			else
			{
				err = udif_error_time_window;
			}
		}
		else
		{
			err = udif_error_suite_mismatch;
		}
	}

	return err;
}

udif_errors udif_certificate_csr_serialize(uint8_t* output, size_t outlen, const udif_certificate_csr* csr)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(csr != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && csr != NULL && outlen >= UDIF_CERTIFICATE_CSR_SIZE)
	{
		pos = 0U;
		qsc_memutils_copy(output, csr->signature, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, csr->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, csr->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, csr->valid.from);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, csr->valid.to);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, csr->capability);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le64to8(output + pos, csr->policy);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		qsc_intutils_le64to8(output + pos, csr->timestamp);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_memutils_copy(output + pos, csr->nonce, UDIF_CERTIFICATE_CSR_NONCE_SIZE);
		pos += UDIF_CERTIFICATE_CSR_NONCE_SIZE;
		output[pos] = (uint8_t)csr->role;
		pos += UDIF_ROLE_SIZE;
		output[pos] = csr->suiteid;
		err = udif_error_none;
	}

	return err;
}

bool udif_certificate_csr_verify(const udif_certificate_csr* csr)
{
	UDIF_ASSERT(csr != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (csr != NULL)
	{
		if (udif_certificate_csr_compute_digest(digest1, csr) == udif_error_none)
		{
			mlen = 0U;
			res = udif_signature_verify(digest2, &mlen, csr->signature, UDIF_SIGNED_HASH_SIZE, csr->verkey);

			if (res == true && mlen == UDIF_CRYPTO_HASH_SIZE)
			{
				res = qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE);
			}
			else
			{
				res = false;
			}
		}
	}

	qsc_memutils_secure_erase(digest1, sizeof(digest1));
	qsc_memutils_secure_erase(digest2, sizeof(digest2));

	return res;
}

bool udif_certificate_check_capability_inheritance(uint64_t childbitmap, uint64_t parentbitmap)
{
	bool res;

	/* if child has a bit that parent doesn't, inheritance fails */
	res = ((childbitmap & ~parentbitmap) == 0U);

	return res;
}

void udif_certificate_clear(udif_certificate* cert)
{
	UDIF_ASSERT(cert != NULL);

	if (cert != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)cert, sizeof(udif_certificate));
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
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(cert != NULL);

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
		qsc_intutils_le64to8(buf + pos, cert->capability);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le64to8(buf + pos, cert->policy);
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

	err = udif_error_decode_failure;

	if (input != NULL && cert != NULL && inplen == UDIF_CERTIFICATE_SIZE)
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
		cert->capability = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		cert->policy = qsc_intutils_le8to64(input + pos);
		pos += UDIF_CERTIFICATE_POLICY_SIZE;
		cert->role = input[pos];
		pos += UDIF_ROLE_SIZE;
		cert->suiteid = input[pos];

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_certificate_generate(udif_certificate* cert, udif_signature_keypair* keypair, const udif_certificate* parentcert, const uint8_t* parentsigkey, 
	udif_roles role, const uint8_t* serial, udif_valid_time* valid, uint64_t capability, uint64_t policy, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(cert != NULL);
	UDIF_ASSERT(keypair != NULL);
	UDIF_ASSERT(parentcert != NULL);
	UDIF_ASSERT(parentsigkey != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(capability != 0U);
	UDIF_ASSERT(rng_generate != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (cert != NULL && keypair != NULL && parentcert != NULL && parentsigkey != NULL && serial != NULL && capability != 0U && valid != NULL && rng_generate != NULL)
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
						cert->capability = capability;
						cert->policy = policy;

						err = udif_certificate_sign(cert, parentsigkey, rng_generate);
					}
				}
			}
		}
	}

	return err;
}

udif_errors udif_certificate_root_generate(udif_certificate* rcert, udif_signature_keypair* keypair, const uint8_t* serial, udif_valid_time* valid, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(rcert != NULL);
	UDIF_ASSERT(keypair != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(valid != NULL);
	UDIF_ASSERT(rng_generate != NULL);

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
			rcert->capability = UDIF_ROOT_CAPABILITIES;
			rcert->policy = UDIF_ROOT_POLICY_DEFAULT;
			qsc_memutils_copy(rcert->verkey, keypair->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);

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
		qsc_intutils_le64to8(output + pos, cert->capability);
		pos += UDIF_CAPABILITY_MASK_SIZE;
		qsc_intutils_le64to8(output + pos, cert->policy);
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

					qsc_memutils_secure_erase(digest1, UDIF_CRYPTO_HASH_SIZE);
					qsc_memutils_secure_erase(digest2, UDIF_CRYPTO_HASH_SIZE);
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
	UDIF_ASSERT(keypair != NULL);

	if (keypair != NULL)
	{
		qsc_memutils_clear((uint8_t*)keypair, sizeof(udif_signature_keypair));
	}
}

udif_errors udif_certificate_generate_root(udif_certificate* cert, const uint8_t* serial, uint64_t validfrom, uint64_t validto, const uint8_t* sigkey, 
	const uint8_t* verkey, bool (*rng_generate)(uint8_t*, size_t))
{
    UDIF_ASSERT(cert != NULL);
    UDIF_ASSERT(serial != NULL);
    UDIF_ASSERT(sigkey != NULL);
    UDIF_ASSERT(rng_generate != NULL);

    udif_errors err;

    err = udif_error_invalid_input;

    if (cert != NULL && serial != NULL && sigkey != NULL && rng_generate != NULL && validto >= validfrom)
    {
        qsc_memutils_clear((uint8_t*)cert, sizeof(udif_certificate));

        cert->suiteid = UDIF_SUITE_ID;
        cert->role = (uint8_t)udif_role_root;
		cert->capability = UDIF_ROOT_CAPABILITIES;
        cert->policy = UDIF_ROOT_POLICY_DEFAULT;
        cert->valid.from = validfrom;
        cert->valid.to = validto;

        /* self-issued: copy serial into issuer field */
        qsc_memutils_copy(cert->serial, serial, UDIF_SERIAL_NUMBER_SIZE);
        qsc_memutils_copy(cert->issuer, serial, UDIF_SERIAL_NUMBER_SIZE);

        /* copy in the verification key */
        qsc_memutils_copy(cert->verkey, verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);

        /* sign the certificate using the caller-supplied signing key */
        err = udif_certificate_sign(cert, sigkey, rng_generate);
    }

    return err;
}

udif_errors udif_certificate_generate_subordinate(udif_certificate* cert, udif_roles role, uint64_t validfrom, uint64_t validto, const uint8_t* verkey)
{
    UDIF_ASSERT(cert != NULL);
    UDIF_ASSERT(verkey != NULL);

    udif_errors err;

    err = udif_error_invalid_input;

    if (cert != NULL && verkey != NULL && validto >= validfrom)
    {
        qsc_memutils_clear((uint8_t*)cert, sizeof(udif_certificate));

        cert->suiteid = UDIF_SUITE_ID;
        cert->role = (uint8_t)role;
        cert->valid.from = validfrom;
        cert->valid.to = validto;

		qsc_csp_generate(cert->serial, UDIF_SERIAL_NUMBER_SIZE);

		if (role == udif_role_ugc)
		{
			cert->capability = UDIF_GC_CAPABILITIES;
			cert->policy = UDIF_GC_POLICY_DEFAULT;
		}
		else if (role == udif_role_ubc)
		{
			cert->capability = UDIF_BC_CAPABILITIES;
			cert->policy = UDIF_BC_POLICY_DEFAULT;
		}
		else if (role == udif_role_client)
		{
			cert->capability = UDIF_CLIENT_CAPABILITIES;
			cert->policy = UDIF_CLIENT_POLICY_DEFAULT;
		}

        qsc_memutils_copy(cert->verkey, verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
    }

    return err;
}

size_t udif_certificate_serialize_store(uint8_t* output, const udif_certificate* cert)
{
    UDIF_ASSERT(output != NULL);
    UDIF_ASSERT(cert != NULL);

    size_t res;
    udif_errors err;

    res = 0U;

    if (output != NULL && cert != NULL)
    {
        err = udif_certificate_serialize(output, UDIF_CERTIFICATE_SIZE, cert);

        if (err == udif_error_none)
        {
            res = UDIF_CERTIFICATE_SIZE;
        }
    }

    return res;
}
