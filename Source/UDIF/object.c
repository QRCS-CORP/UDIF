#include "udif.h"
#include "object.h"
#include "memutils.h"
#include "intutils.h"

void udif_object_clear(udif_object* obj)
{
	if (obj != NULL)
	{
		qsc_memutils_clear((uint8_t*)obj, sizeof(udif_object));
	}
}

bool udif_object_compare(const udif_object* a, const udif_object* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = (qsc_memutils_are_equal((const uint8_t*)a, (const uint8_t*)b, sizeof(udif_object)) == true);
	}

	return res;
}

udif_errors udif_object_compute_digest(uint8_t* digest, const udif_object* obj)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(obj != NULL);

	uint8_t buf[UDIF_OBJECT_SIGNING_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (digest != NULL && obj != NULL)
	{
		pos = 0U;

		qsc_memutils_copy(buf, obj->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(buf + pos, obj->attrroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(buf + pos, obj->creator, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(buf + pos, obj->owner, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, obj->created);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(buf + pos, obj->updated);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le32to8(buf + pos, obj->flags);
		pos += UDIF_OBJECT_FLAG_SIZE;
		qsc_intutils_le32to8(buf + pos, obj->type);

		/* compute digest */
		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_OBJ_DIGEST, sizeof(UDIF_LABEL_OBJ_DIGEST) - 1U, NULL, 0U);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_object_compute_signature(udif_object* obj, const uint8_t* sigkey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	size_t smlen;
	udif_errors err;

	/* compute digest and sign */
	err = udif_object_compute_digest(digest, obj);
	smlen = 0U;

	if (err == udif_error_none)
	{
		if (udif_signature_sign(obj->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, sigkey, rng_generate) == true)
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

udif_errors udif_object_compute_transfer_digest(uint8_t* digest, const uint8_t* objserial, const uint8_t* txid, const uint8_t* toowner, uint64_t timestamp)
{
	UDIF_ASSERT(digest != NULL);
	UDIF_ASSERT(objserial != NULL);
	UDIF_ASSERT(txid != NULL);
	UDIF_ASSERT(toowner != NULL);

	uint8_t buf[UDIF_OBJECT_TRANSFER_SIZE] = { 0U };
	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (digest != NULL && objserial != NULL && txid != NULL && toowner != NULL)
	{
		pos = 0U;

		/* construct: objserial || txid || toowner || timestamp */
		qsc_memutils_copy(buf, objserial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(buf + pos, txid, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(buf + pos, toowner, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(buf + pos, timestamp);
		pos += UDIF_VALID_TIME_SIZE;

		/* domain-separated hash */
		qsc_cshake256_compute(digest, UDIF_CRYPTO_HASH_SIZE, buf, sizeof(buf), (const uint8_t*)UDIF_LABEL_TXID, sizeof(UDIF_LABEL_TXID) - 1U, NULL, 0U);

		/* clear buffer */
		qsc_memutils_clear(buf, pos);
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_object_create(udif_object* obj, const uint8_t* serial, uint32_t type, const uint8_t* creator, const uint8_t* attrroot,
	const uint8_t* owner, const uint8_t* sigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(serial != NULL);
	UDIF_ASSERT(creator != NULL);
	UDIF_ASSERT(attrroot != NULL);
	UDIF_ASSERT(owner != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (obj != NULL && serial != NULL && creator != NULL && attrroot != NULL && owner != NULL && sigkey != NULL && rng_generate != NULL)
	{
		qsc_memutils_clear((uint8_t*)obj, sizeof(udif_object));

		qsc_memutils_copy(obj->serial, serial, UDIF_SERIAL_NUMBER_SIZE);
		obj->type = type;
		qsc_memutils_copy(obj->attrroot, attrroot, UDIF_CRYPTO_HASH_SIZE);
		qsc_memutils_copy(obj->creator, creator, UDIF_SERIAL_NUMBER_SIZE);
		qsc_memutils_copy(obj->owner, owner, UDIF_SERIAL_NUMBER_SIZE);
		obj->created = ctime;
		obj->updated = ctime;
		obj->flags = 0U;

		/* compute digest and sign */
		udif_object_compute_signature(obj, sigkey, rng_generate);

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_object_deserialize(udif_object* obj, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;

	if (input != NULL && obj != NULL && inplen >= UDIF_OBJECT_ENCODED_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(obj->signature, input, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(obj->serial, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(obj->attrroot, input + pos, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(obj->creator, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(obj->owner, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		obj->created = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		obj->updated = qsc_intutils_le8to64(input + pos);
		pos += UDIF_VALID_TIME_SIZE;
		obj->flags = qsc_intutils_le8to32(input + pos);
		pos += UDIF_OBJECT_FLAG_SIZE;
		obj->type = qsc_intutils_le8to32(input + pos);

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_object_destroy(udif_object* obj, const uint8_t* ownersigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(ownersigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (obj != NULL && ownersigkey != NULL && rng_generate != NULL)
	{
		size_t smlen;

		/* set destroyed flag and update timestamp */
		obj->flags |= UDIF_OBJECT_FLAG_DESTROYED;
		obj->updated = ctime;

		/* re-sign object */
		udif_object_compute_digest(digest, obj);
		smlen = 0U;

		if (udif_signature_sign(obj->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, ownersigkey, rng_generate) == true)
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

		qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
	}

	return err;
}

bool udif_object_is_destroyed(const udif_object* obj)
{
	UDIF_ASSERT(obj != NULL);

	bool res;

	res = false;

	if (obj != NULL)
	{
		res = ((obj->flags & UDIF_OBJECT_FLAG_DESTROYED) != 0U);
	}

	return res;
}

udif_errors udif_object_serialize(uint8_t* output, size_t outlen, const udif_object* obj)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(obj != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && obj != NULL && outlen >= UDIF_OBJECT_ENCODED_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output, obj->signature, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, obj->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, obj->attrroot, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, obj->creator, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, obj->owner, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, obj->created);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le64to8(output + pos, obj->updated);
		pos += UDIF_VALID_TIME_SIZE;
		qsc_intutils_le32to8(output + pos, obj->flags);
		pos += UDIF_OBJECT_FLAG_SIZE;
		qsc_intutils_le32to8(output + pos, obj->type);

		err = udif_error_none;
	}

	return err;
}

udif_errors udif_object_transfer(udif_object* obj, udif_transfer_record* transfer, const uint8_t* newowner, const uint8_t* sendsigkey,
	const uint8_t* recvsigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(transfer != NULL);
	UDIF_ASSERT(newowner != NULL);
	UDIF_ASSERT(sendsigkey != NULL);
	UDIF_ASSERT(recvsigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t txdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t objdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t oldowner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (obj != NULL && transfer != NULL && newowner != NULL && sendsigkey != NULL && recvsigkey != NULL && rng_generate != NULL)
	{
		size_t smlen;

		/* check object not destroyed */
		if ((obj->flags & UDIF_OBJECT_FLAG_DESTROYED) == 0U)
		{
			/* save old owner */
			qsc_memutils_copy(oldowner, obj->owner, UDIF_SERIAL_NUMBER_SIZE);

			/* clear transfer structure */
			qsc_memutils_clear((uint8_t*)transfer, sizeof(udif_transfer_record));

			/* set transfer record fields */
			qsc_memutils_copy(transfer->serial, obj->serial, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(transfer->originator, oldowner, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(transfer->owner, newowner, UDIF_SERIAL_NUMBER_SIZE);
			transfer->timestamp = ctime;

			/* compute transfer digest */
			udif_object_compute_transfer_digest(txdigest, obj->serial, oldowner, newowner, ctime);

			qsc_memutils_copy(transfer->txid, txdigest, UDIF_CRYPTO_HASH_SIZE);
			smlen = 0U;

			/* Sender signs transfer */
			if (udif_signature_sign(transfer->sender, &smlen, txdigest, UDIF_CRYPTO_HASH_SIZE, sendsigkey, rng_generate) == true)
			{
				if (smlen == UDIF_SIGNED_HASH_SIZE)
				{
					smlen = 0U;

					/* Receiver signs transfer */
					if (udif_signature_sign(transfer->receiver, &smlen, txdigest, UDIF_CRYPTO_HASH_SIZE, recvsigkey, rng_generate) == true)
					{
						if (smlen == UDIF_SIGNED_HASH_SIZE)
						{
							/* Update object */
							qsc_memutils_copy(obj->owner, newowner, UDIF_SERIAL_NUMBER_SIZE);
							obj->updated = ctime;

							/* Re-sign object with new owner's key */
							udif_object_compute_digest(objdigest, obj);
							smlen = 0U;

							if (udif_signature_sign(obj->signature, &smlen, objdigest, UDIF_CRYPTO_HASH_SIZE, recvsigkey, rng_generate) == true)
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
								/* Rollback on signature failure */
								qsc_memutils_copy(obj->owner, oldowner, UDIF_SERIAL_NUMBER_SIZE);
								err = udif_error_signature_invalid;
							}

							/* Clear object digest */
							qsc_memutils_clear(objdigest, UDIF_CRYPTO_HASH_SIZE);
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
		
		qsc_memutils_clear(txdigest, UDIF_CRYPTO_HASH_SIZE);
		qsc_memutils_clear(oldowner, UDIF_SERIAL_NUMBER_SIZE);
	}

	return err;
}

udif_errors udif_object_update_attributes(udif_object* obj, const uint8_t* newattrroot, const uint8_t* ownersigkey, uint64_t ctime, bool (*rng_generate)(uint8_t*, size_t))
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(newattrroot != NULL);
	UDIF_ASSERT(ownersigkey != NULL);
	UDIF_ASSERT(rng_generate != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_errors err;

	err = udif_error_invalid_input;

	if (obj != NULL && newattrroot != NULL && ownersigkey != NULL && rng_generate != NULL)
	{
		size_t smlen;

		/* check object not destroyed */
		if ((obj->flags & UDIF_OBJECT_FLAG_DESTROYED) == 0U)
		{
			/* update attribute root and timestamp */
			qsc_memutils_copy(obj->attrroot, newattrroot, UDIF_CRYPTO_HASH_SIZE);
			obj->updated = ctime;

			/* re-sign object */
			udif_object_compute_digest(digest, obj);
			smlen = 0U;

			if (udif_signature_sign(obj->signature, &smlen, digest, UDIF_CRYPTO_HASH_SIZE, ownersigkey, rng_generate) == true)
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

			qsc_memutils_clear(digest, UDIF_CRYPTO_HASH_SIZE);
		}
		else
		{
			err = udif_error_invalid_state;
		}
	}

	return err;
}

bool udif_object_verify(const udif_object* obj, const uint8_t* ownerverkey)
{
	UDIF_ASSERT(obj != NULL);
	UDIF_ASSERT(ownerverkey != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (obj != NULL && ownerverkey != NULL)
	{
		size_t mlen;

		/* compute digest */
		udif_object_compute_digest(digest1, obj);

		/* verify signature */
		res = udif_signature_verify(digest2, &mlen, obj->signature, UDIF_SIGNED_HASH_SIZE, ownerverkey);

		if (mlen == UDIF_CRYPTO_HASH_SIZE)
		{
			res = qsc_memutils_are_equal(digest1, digest2, sizeof(digest1));
		}

		/* clear digest */
		qsc_memutils_clear(digest1, UDIF_CRYPTO_HASH_SIZE);
		qsc_memutils_clear(digest2, UDIF_CRYPTO_HASH_SIZE);
	}

	return res;
}

void udif_transfer_clear(udif_transfer_record* transfer)
{
	if (transfer != NULL)
	{
		qsc_memutils_clear((uint8_t*)transfer, sizeof(udif_transfer_record));
	}
}

udif_errors udif_transfer_deserialize(udif_transfer_record* transfer, const uint8_t* input, size_t inlen)
{
	UDIF_ASSERT(transfer != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_decode_failure;
	pos = 0U;

	if (transfer != NULL && input != NULL && inlen >= UDIF_TRANSFER_RECORD_ENCODED_SIZE)
	{
		qsc_memutils_copy(transfer->sender, input + pos, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(transfer->receiver, input + pos, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(transfer->txid, input + pos, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(transfer->serial, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(transfer->originator, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(transfer->owner, input + pos, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		transfer->timestamp = qsc_intutils_le8to64(input + pos);
		
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_transfer_serialize(uint8_t* output, size_t outlen, const udif_transfer_record* transfer)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(transfer != NULL);

	size_t pos;
	udif_errors err;

	err = udif_error_encode_failure;

	if (output != NULL && transfer != NULL && outlen >= UDIF_TRANSFER_RECORD_ENCODED_SIZE)
	{
		pos = 0U;

		qsc_memutils_copy(output + pos, transfer->sender, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, transfer->receiver, UDIF_SIGNED_HASH_SIZE);
		pos += UDIF_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, transfer->txid, UDIF_CRYPTO_HASH_SIZE);
		pos += UDIF_CRYPTO_HASH_SIZE;
		qsc_memutils_copy(output + pos, transfer->serial, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, transfer->originator, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_memutils_copy(output + pos, transfer->owner, UDIF_SERIAL_NUMBER_SIZE);
		pos += UDIF_SERIAL_NUMBER_SIZE;
		qsc_intutils_le64to8(output + pos, transfer->timestamp);

		err = udif_error_none;
	}

	return err;
}

bool udif_transfer_verify(const udif_transfer_record* transfer, const uint8_t* sendverkey, const uint8_t* recvverkey)
{
	UDIF_ASSERT(transfer != NULL);
	UDIF_ASSERT(sendverkey != NULL);
	UDIF_ASSERT(recvverkey != NULL);

	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest3[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (transfer != NULL && sendverkey != NULL && recvverkey != NULL)
	{
		/* compute transfer digest */
		udif_object_compute_transfer_digest(digest1, transfer->serial, transfer->originator, transfer->owner, transfer->timestamp);

		/* verify it matches stored txid */
		if (qsc_memutils_are_equal(digest1, transfer->txid, UDIF_CRYPTO_HASH_SIZE) == true)
		{
			size_t mlen;

			/* verify sender signature */
			mlen = 0U;

			if (udif_signature_verify(digest2, &mlen, transfer->sender, UDIF_SIGNED_HASH_SIZE, sendverkey) == true)
			{
				if (mlen == UDIF_CRYPTO_HASH_SIZE)
				{
					res = qsc_memutils_are_equal(digest1, digest2, sizeof(digest1));

					if (res == true)
					{
						/* verify receiver signature */
						mlen = 0U;

						if (udif_signature_verify(digest3, &mlen, transfer->receiver, UDIF_SIGNED_HASH_SIZE, recvverkey) == true)
						{
							if (mlen == UDIF_CRYPTO_HASH_SIZE)
							{
								res = qsc_memutils_are_equal(digest1, digest3, sizeof(digest1));
							}
						}

						qsc_memutils_clear(digest3, UDIF_CRYPTO_HASH_SIZE);
					}
				}
			}

			qsc_memutils_clear(digest2, UDIF_CRYPTO_HASH_SIZE);
		}

		qsc_memutils_clear(digest1, UDIF_CRYPTO_HASH_SIZE);
	}

	return res;
}
