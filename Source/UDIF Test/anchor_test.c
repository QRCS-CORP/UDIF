#include "anchor_test.h"

#include "anchor_test.h"
#include "anchor.h"
#include "udif.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"
#include "consoleutils.h"

static bool anchor_test_create(void)
{
	udif_anchor_record anchor = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 1U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 42U;
	txcount = 17U;
	memcount = 8U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor record */
	err = udif_anchor_create(&anchor, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_create: anchor creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(anchor.childser, childser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("anchor_test_create: child serial mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(anchor.regroot, regroot, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("anchor_test_create: registry root mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(anchor.txroot, txroot, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("anchor_test_create: transaction root mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(anchor.mroot, mroot, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("anchor_test_create: membership root mismatch");
			res = false;
		}
		else if (anchor.sequence != sequence)
		{
			qsc_consoleutils_print_line("anchor_test_create: sequence mismatch");
			res = false;
		}
		else if (anchor.timestamp != timestamp)
		{
			qsc_consoleutils_print_line("anchor_test_create: timestamp mismatch");
			res = false;
		}
		else if (anchor.regcount != regcount)
		{
			qsc_consoleutils_print_line("anchor_test_create: registry count mismatch");
			res = false;
		}
		else if (anchor.txcount != txcount)
		{
			qsc_consoleutils_print_line("anchor_test_create: transaction count mismatch");
			res = false;
		}
		else if (anchor.memcount != memcount)
		{
			qsc_consoleutils_print_line("anchor_test_create: membership count mismatch");
			res = false;
		}
		else
		{
			/* verify signature is not all zeros */
			ret = qsc_memutils_zeroed(anchor.signature, UDIF_SIGNED_HASH_SIZE);

			if (ret == true)
			{
				qsc_consoleutils_print_line("anchor_test_create: signature is all zeros");
				res = false;
			}
		}
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_serialize(void)
{
	udif_anchor_record anchor1 = { 0U };
	udif_anchor_record anchor2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t buffer[UDIF_ANCHOR_RECORD_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 5U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 100U;
	txcount = 50U;
	memcount = 25U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor */
	err = udif_anchor_create(&anchor1, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_serialize: anchor creation failed");
		res = false;
	}
	else
	{
		/* serialize */
		err = udif_anchor_serialize(buffer, sizeof(buffer), &anchor1);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("anchor_test_serialize: serialization failed");
			res = false;
		}
		else
		{
			/* deserialize */
			err = udif_anchor_deserialize(&anchor2, buffer, sizeof(buffer));

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialization failed");
				res = false;
			}
			else if (udif_anchor_compare(&anchor1, &anchor2) == false)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialized anchor does not match original");
				res = false;
			}
			else if (qsc_memutils_are_equal(anchor2.childser, childser, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialized child serial mismatch");
				res = false;
			}
			else if (anchor2.sequence != sequence)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialized sequence mismatch");
				res = false;
			}
			else if (anchor2.timestamp != timestamp)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialized timestamp mismatch");
				res = false;
			}
			else if (anchor2.regcount != regcount)
			{
				qsc_consoleutils_print_line("anchor_test_serialize: deserialized registry count mismatch");
				res = false;
			}
		}
	}

	udif_anchor_clear(&anchor1);
	udif_anchor_clear(&anchor2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_verify(void)
{
	udif_anchor_record anchor = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 3U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 75U;
	txcount = 30U;
	memcount = 12U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor */
	err = udif_anchor_create(&anchor, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_verify: anchor creation failed");
		res = false;
	}
	else
	{
		/* verify anchor with correct key and sequence */
		if (udif_anchor_verify(&anchor, kp.verkey, sequence) == false)
		{
			qsc_consoleutils_print_line("anchor_test_verify: anchor verification failed");
			res = false;
		}
		else
		{
			/* verify anchor with sequence 0 (no sequence check) */
			if (udif_anchor_verify(&anchor, kp.verkey, 3U) == false)
			{
				qsc_consoleutils_print_line("anchor_test_verify: anchor verification without sequence check failed");
				res = false;
			}
			else
			{
				/* verify with wrong sequence should fail */
				if (udif_anchor_verify(&anchor, kp.verkey, sequence + 1U) == true)
				{
					qsc_consoleutils_print_line("anchor_test_verify: verification should fail with wrong sequence");
					res = false;
				}
			}
		}
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_sequence_validation(void)
{
	udif_anchor_record anchor = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 10U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 200U;
	txcount = 100U;
	memcount = 50U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor with sequence 10 */
	err = udif_anchor_create(&anchor, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_sequence_validation: anchor creation failed");
		res = false;
	}
	else
	{
		/* validate sequence after sequence 9 (should pass) */
		if (udif_anchor_validate_sequence(&anchor, 9U) == false)
		{
			qsc_consoleutils_print_line("anchor_test_sequence_validation: valid sequence rejected");
			res = false;
		}
		else
		{
			/* validate sequence as first anchor (prevseq = 0) */
			if (udif_anchor_validate_sequence(&anchor, 0U) == false)
			{
				qsc_consoleutils_print_line("anchor_test_sequence_validation: first anchor sequence validation failed");
				res = false;
			}
			else
			{
				/* validate with same sequence (should fail - not monotonic) */
				if (udif_anchor_validate_sequence(&anchor, 10U) == true)
				{
					qsc_consoleutils_print_line("anchor_test_sequence_validation: non-monotonic sequence should fail");
					res = false;
				}
				else
				{
					/* validate with higher previous sequence (should fail) */
					if (udif_anchor_validate_sequence(&anchor, 11U) == true)
					{
						qsc_consoleutils_print_line("anchor_test_sequence_validation: sequence going backwards should fail");
						res = false;
					}
				}
			}
		}
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_freshness(void)
{
	udif_anchor_record anchor = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint64_t ctime;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 1U;
	ctime = qsc_timestamp_datetime_utc();
	timestamp = ctime;
	regcount = 50U;
	txcount = 25U;
	memcount = 10U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor with current timestamp */
	err = udif_anchor_create(&anchor, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_freshness: anchor creation failed");
		res = false;
	}
	else
	{
		/* check freshness at current time (should be fresh) */
		if (udif_anchor_is_fresh(&anchor, ctime, UDIF_ANCHOR_MAX_AGE_MAX) == false)
		{
			qsc_consoleutils_print_line("anchor_test_freshness: fresh anchor reported as stale");
			res = false;
		}
		else
		{
			/* check with time just beyond max age (should be stale) */
			if (udif_anchor_is_fresh(&anchor, ctime + UDIF_ANCHOR_MAX_AGE_MAX + 1U, UDIF_ANCHOR_MAX_AGE_MAX) == true)
			{
				qsc_consoleutils_print_line("anchor_test_freshness: stale anchor reported as fresh");
				res = false;
			}
			else
			{
				/* check with custom max age */
				if (udif_anchor_is_fresh(&anchor, ctime + 1800U, 3600U) == false)
				{
					qsc_consoleutils_print_line("anchor_test_freshness: anchor within custom max age should be fresh");
					res = false;
				}
			}
		}
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_chain_verification(void)
{
	udif_anchor_record anchor1 = { 0U };
	udif_anchor_record anchor2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t regroot2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot1, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot1, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot1, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(regroot2, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot2, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot2, UDIF_CRYPTO_HASH_SIZE);
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 100U;
	txcount = 50U;
	memcount = 20U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create first anchor with sequence 5 */
	err = udif_anchor_create(&anchor1, childser, 5, timestamp, regroot1, txroot1, mroot1, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_chain_verification: first anchor creation failed");
		res = false;
	}
	else
	{
		/* create second anchor with sequence 6 */
		err = udif_anchor_create(&anchor2, childser, 6, timestamp + 3600, regroot2, txroot2, mroot2, regcount + 10U, txcount + 5U, memcount + 2U, kp.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("anchor_test_chain_verification: second anchor creation failed");
			res = false;
		}
		else
		{
			/* verify valid chain */
			if (udif_anchor_verify_chain(&anchor1, &anchor2, kp.verkey) == false)
			{
				qsc_consoleutils_print_line("anchor_test_chain_verification: valid chain verification failed");
				res = false;
			}
			else
			{
				/* modify sequence to break chain */
				anchor2.sequence = 5;

				if (udif_anchor_verify_chain(&anchor1, &anchor2, kp.verkey) == true)
				{
					qsc_consoleutils_print_line("anchor_test_chain_verification: broken chain should fail verification");
					res = false;
				}
			}
		}
	}

	udif_anchor_clear(&anchor1);
	udif_anchor_clear(&anchor2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_compare_digest(void)
{
	udif_anchor_record anchor1 = { 0U };
	udif_anchor_record anchor2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 7U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 150U;
	txcount = 75U;
	memcount = 30U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create two identical anchors (different signatures) */
	err = udif_anchor_create(&anchor1, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_compare_digest: first anchor creation failed");
		res = false;
	}
	else
	{
		err = udif_anchor_create(&anchor2, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("anchor_test_compare_digest: second anchor creation failed");
			res = false;
		}
		else
		{
			/* compute digests */
			err = udif_anchor_compute_digest(digest1, &anchor1);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("anchor_test_compare_digest: first digest computation failed");
				res = false;
			}
			else
			{
				/* verify digest is not all zeros */
				ret = qsc_memutils_zeroed(digest1, sizeof(digest1));

				if (ret == true)
				{
					qsc_consoleutils_print_line("anchor_test_compare_digest: digest is all zeros");
					res = false;
				}
				else
				{
					err = udif_anchor_compute_digest(digest2, &anchor2);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("anchor_test_compare_digest: second digest computation failed");
						res = false;
					}
					else if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
					{
						qsc_consoleutils_print_line("anchor_test_compare_digest: digests should match for same anchor data");
						res = false;
					}
					else
					{
						/* copy anchor and verify compare */
						qsc_memutils_copy((uint8_t*)&anchor2, (uint8_t*)&anchor1, sizeof(udif_anchor_record));

						if (udif_anchor_compare(&anchor1, &anchor2) == false)
						{
							qsc_consoleutils_print_line("anchor_test_compare_digest: copied anchors should be equal");
							res = false;
						}
					}
				}
			}
			
		}
	}

	udif_anchor_clear(&anchor1);
	udif_anchor_clear(&anchor2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool anchor_test_encoded_size(void)
{
	udif_anchor_record anchor = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t sequence;
	uint64_t timestamp;
	uint32_t regcount;
	uint32_t txcount;
	uint32_t memcount;
	size_t encsize;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(childser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(regroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(txroot, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(mroot, UDIF_CRYPTO_HASH_SIZE);
	sequence = 1U;
	timestamp = qsc_timestamp_datetime_utc();
	regcount = 10U;
	txcount = 5U;
	memcount = 3U;

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create anchor */
	err = udif_anchor_create(&anchor, childser, sequence, timestamp, regroot, txroot, mroot, regcount, txcount, memcount, kp.sigkey, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("anchor_test_encoded_size: anchor creation failed");
		res = false;
	}
	else
	{
		/* get encoded size */
		encsize = udif_anchor_encoded_size(&anchor);

		if (encsize != UDIF_ANCHOR_RECORD_SIZE)
		{
			qsc_consoleutils_print_line("anchor_test_encoded_size: encoded size mismatch");
			res = false;
		}
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

bool anchor_test_run(void)
{
	bool res;

	res = true;

	if (anchor_test_create() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor creation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor creation test has failed.");
		res = false;
	}

	if (anchor_test_serialize() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor serialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor serialization test has failed.");
		res = false;
	}

	if (anchor_test_verify() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor verification test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor verification test has failed.");
		res = false;
	}

	if (anchor_test_sequence_validation() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor sequence validation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor sequence validation test has failed.");
		res = false;
	}

	if (anchor_test_freshness() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor freshness test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor freshness test has failed.");
		res = false;
	}

	if (anchor_test_chain_verification() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor chain verification test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor chain verification test has failed.");
		res = false;
	}

	if (anchor_test_compare_digest() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor digest comparison test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor digest comparison test has failed.");
		res = false;
	}

	if (anchor_test_encoded_size() == true)
	{
		qsc_consoleutils_print_line("Success! Anchor encoding test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Anchor encoding test has failed.");
		res = false;
	}

	return res;
}
