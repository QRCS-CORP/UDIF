#include "udif.h"
#include "anchor.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

udif_errors udif_anchor_create( udif_anchor_record* anchor, const uint8_t* childser, uint64_t sequence, uint64_t timestamp, const uint8_t* regroot, const uint8_t* txroot, 
	const uint8_t* mroot, uint32_t regcount, uint32_t txcount, uint32_t memcount, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(anchor != NULL);
	UDIF_ASSERT(childser != NULL);
	UDIF_ASSERT(regroot != NULL);
	UDIF_ASSERT(txroot != NULL);
	UDIF_ASSERT(mroot != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (anchor != NULL && childser != NULL && regroot != NULL && txroot != NULL && mroot != NULL && sigkey != NULL && rng_generate != NULL && sequence > 0U)
	{
		/* clear structure */
		qsc_memutils_clear((uint8_t*)anchor, sizeof(udif_anchor_record));

		/* set fields */
		qsc_memutils_copy(anchor->childser, childser, UDIF_SERIAL_NUMBER_SIZE);

		anchor->sequence = sequence;
		anchor->timestamp = timestamp;

		if (timestamp != 0U)
		{
			qsc_memutils_copy(anchor->regroot, regroot, UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_copy(anchor->txroot, txroot, UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_copy(anchor->mroot, mroot, UDIF_CRYPTO_HASH_SIZE);
			anchor->regcount = regcount;
			anchor->txcount = txcount;
			anchor->memcount = memcount;

			/* compute digest and sign */
			err = udif_anchor_compute_signature(anchor, sigkey, rng_generate);
		}
		else
		{
			err = udif_error_invalid_state;
		}
	}

	return err;
}

udif_errors udif_anchor_deserialize(udif_anchor_record* anchor, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(input != NULL);
	UDIF_ASSERT(inplen != 0U);
	UDIF_ASSERT(anchor != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;

	if (input != NULL && anchor != NULL && inplen >= UDIF_ANCHOR_RECORD_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(anchor->signature, input, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(anchor->mroot, input + pos, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(anchor->regroot, input + pos, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(anchor->txroot, input + pos, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(anchor->childser, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		anchor->sequence = qsc_intutils_le8to64(input + pos);
		pos += UDIF_ANCHOR_SEQUENCE_SIZE;
		anchor->timestamp = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		anchor->memcount = qsc_intutils_le8to32(input + pos);
		pos += UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER;
		anchor->regcount = qsc_intutils_le8to32(input + pos);
		pos += UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER;
		anchor->txcount = qsc_intutils_le8to32(input + pos);

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_anchor_compute_digest(uint8_t* digest, const udif_anchor_record* anchor)
{
	uint8_t buf[UDIF_ANCHOR_SIGNING_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;
	pos = 0U;

	if (digest != NULL && anchor != NULL)
	{
		qsc_memutils_copy(buf, anchor->mroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(buf + pos, anchor->regroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(buf + pos, anchor->txroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(buf + pos, anchor->childser, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, anchor->timestamp);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le32to8(buf + pos, anchor->memcount);
		pos += UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER;
		qsc_intutils_le32to8(buf + pos, anchor->regcount);
		pos += UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER;
		qsc_intutils_le64to8(buf + pos, anchor->sequence);
		pos += UDIF_ANCHOR_SEQUENCE_SIZE;
		qsc_intutils_le32to8(buf + pos, anchor->txcount);

		/* compute digest and sign with parent key */
		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_ANCHOR, sizeof(UDIF_LABEL_ANCHOR) - 1U, NULL, 0U);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_anchor_compute_signature(udif_anchor_record* anchor, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t smlen;
	udif_errors err;

	/* compute digest and sign */
	err = udif_anchor_compute_digest(digest, anchor);

	if (err == udif_error_none)
	{
		smlen = 0U;

		if (udif_signature_sign(anchor->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, sigkey, rng_generate) == true)
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

	qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);

	return err;
}

void udif_anchor_clear(udif_anchor_record* anchor)
{
	if (anchor != NULL)
	{
		qsc_memutils_clear((uint8_t*)anchor, sizeof(udif_anchor_record));
	}
}

bool udif_anchor_compare(const udif_anchor_record* a, const udif_anchor_record* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = (qsc_memutils_are_equal((const uint8_t*)a, (const uint8_t*)b, sizeof(udif_anchor_record)) == true);
	}

	return res;
}

size_t udif_anchor_encoded_size(const udif_anchor_record* anchor)
{
	UDIF_ASSERT(anchor != NULL);

	size_t alen;

	alen = 0;

	if (anchor != NULL)
	{
		/* estimate: tags + lengths + values */
		alen = UDIF_SIGNED_HASH_SIZE + (UDIF_CRYPTO_HASH_SIZE * 3) + UDIF_SERIAL_NUMBER_SIZE + sizeof(uint64_t) + sizeof(uint64_t) +
			sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
	}

	return alen;
}

bool udif_anchor_is_fresh(const udif_anchor_record* anchor, uint64_t current_time, uint64_t max_age)
{
	UDIF_ASSERT(anchor != NULL);

	uint64_t age;
	bool res;

	res = false;

	if (anchor != NULL)
	{
		if (current_time >= anchor->timestamp)
		{
			age = current_time - anchor->timestamp;
			res = (age <= max_age);
		}
	}

	return res;
}

udif_errors udif_anchor_serialize(uint8_t* output, size_t outlen, const udif_anchor_record* anchor)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0U);
	UDIF_ASSERT(anchor != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && anchor != NULL && outlen >= UDIF_ANCHOR_RECORD_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output, anchor->signature, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, anchor->mroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, anchor->regroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, anchor->txroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, anchor->childser, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, anchor->sequence);
		pos += UDIF_ANCHOR_SEQUENCE_SIZE;
		qsc_intutils_le64to8(output + pos, anchor->timestamp);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le32to8(output + pos, anchor->memcount);
		pos += UDIF_ANCHOR_MEMBERSHIP_EVENT_COUNTER;
		qsc_intutils_le32to8(output + pos, anchor->regcount);
		pos += UDIF_ANCHOR_REGISTRY_OBJECT_COUNTER;
		qsc_intutils_le32to8(output + pos, anchor->txcount);

		err = udif_error_none;
	}

	return err;
}

bool udif_anchor_validate_sequence(const udif_anchor_record* anchor, uint64_t prevseq)
{
	UDIF_ASSERT(anchor != NULL);

	bool res;

	res = false;

	if (anchor != NULL)
	{
		/* if this is the first anchor, prev_seq should be 0 */
		if (prevseq == 0)
		{
			res = true;
		}
		else
		{
			/* sequence must be strictly increasing */
			res = (anchor->sequence > prevseq);
		}
	}

	return res;
}

bool udif_anchor_verify(const udif_anchor_record* anchor, const uint8_t* childverkey, uint64_t expseq)
{
	UDIF_ASSERT(anchor != NULL);
	UDIF_ASSERT(childverkey != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (anchor != NULL && childverkey != NULL)
	{
		size_t mlen;

		/* check sequence if specified */
		if (expseq == 0U || anchor->sequence == expseq)
		{
			/* compute digest */
			udif_anchor_compute_digest(digest1, anchor);

			/* verify signature */
			mlen = 0U;

			res = udif_signature_verify(digest2, &mlen, anchor->signature, UDIF_SIGNED_HASH_SIZE, childverkey);

			if (mlen == UDIF_CRYPTO_HASH_SIZE)
			{
				res = qsc_memutils_are_equal(digest1, digest2, sizeof(digest1));
			}

			/* clear digests */
			qsc_memutils_clear(digest1, UDIF_CRYPTO_HASH_SIZE);
			qsc_memutils_clear(digest2, UDIF_CRYPTO_HASH_SIZE);
		}
	}

	return res;
}

bool udif_anchor_verify_chain(const udif_anchor_record* prevanchor, const udif_anchor_record* nextanchor, const uint8_t* childverkey)
{
	UDIF_ASSERT(prevanchor != NULL);
	UDIF_ASSERT(nextanchor != NULL);
	UDIF_ASSERT(childverkey != NULL);

	bool res;

	res = false;

	if (prevanchor != NULL && nextanchor != NULL && childverkey != NULL)
	{
		/* verify both anchors individually */
		if (udif_anchor_verify(prevanchor, childverkey, 0U) == true)
		{
			if (udif_anchor_verify(nextanchor, childverkey, 0U) == true)
			{
				/* verify child serial matches */
				if (qsc_memutils_are_equal(prevanchor->childser, nextanchor->childser, UDIF_SERIAL_NUMBER_SIZE) == true)
				{
					/* verify sequence is monotonically increasing */
					if (nextanchor->sequence > prevanchor->sequence)
					{
						/* verify timestamp is monotonically increasing */
						res = (nextanchor->timestamp > prevanchor->timestamp);
					}
				}
			}
		}
	}

	return res;
}
