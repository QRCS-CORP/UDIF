#include "object_test.h"
#include "object.h"
#include "udif.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

static bool object_test_create(void)
{
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate owner keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create object */
	err = udif_object_create(&obj, serial, 0x00000001, creator, attrroot, owner, kp.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_create: object creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(obj.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_create: serial number mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(obj.creator, creator, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_create: creator mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(obj.owner, owner, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_create: owner mismatch");
			res = false;
		}
		else if (qsc_memutils_are_equal(obj.attrroot, attrroot, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_create: attribute root mismatch");
			res = false;
		}
		else if (obj.created != ctime)
		{
			qsc_consoleutils_print_line("object_test_create: creation time mismatch");
			res = false;
		}
		else if (obj.type != 0x00000001)
		{
			qsc_consoleutils_print_line("object_test_create: object type mismatch");
			res = false;
		}
		else
		{
			/* verify signature */
			if (udif_object_verify(&obj, kp.verkey) == false)
			{
				qsc_consoleutils_print_line("object_test_create: signature verification failed");
				res = false;
			}
			else if (udif_object_is_destroyed(&obj) == true)
			{
				qsc_consoleutils_print_line("object_test_create: new object should not be destroyed");
				res = false;
			}
		}
	}

	udif_object_clear(&obj);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_update_attributes(void)
{
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t attrroot2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime1;
	uint64_t ctime2;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot1, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(attrroot2, UDIF_CRYPTO_HASH_SIZE);
	ctime1 = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create object */
	err = udif_object_create(&obj, serial, 0x00000001, creator, attrroot1, owner, kp.sigkey, ctime1, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_update_attributes: object creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(obj.attrroot, attrroot1, UDIF_CRYPTO_HASH_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_update_attributes: initial attribute root mismatch");
			res = false;
		}
		else if (obj.updated != ctime1)
		{
			qsc_consoleutils_print_line("object_test_update_attributes: initial update time should equal creation time");
			res = false;
		}
		else
		{
			/* update attributes */
			ctime2 = qsc_timestamp_datetime_utc();
			err = udif_object_update_attributes(&obj, attrroot2, kp.sigkey, ctime2, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_update_attributes: attribute update failed");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj.attrroot, attrroot2, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_update_attributes: updated attribute root mismatch");
				res = false;
			}
			else if (obj.updated != ctime2)
			{
				qsc_consoleutils_print_line("object_test_update_attributes: update time not changed");
				res = false;
			}
			else if (obj.created != ctime1)
			{
				qsc_consoleutils_print_line("object_test_update_attributes: creation time should not change");
				res = false;
			}
			else
			{
				/* verify signature still valid */
				if (udif_object_verify(&obj, kp.verkey) == false)
				{
					qsc_consoleutils_print_line("object_test_update_attributes: updated object signature invalid");
					res = false;
				}
			}
		}
	}

	udif_object_clear(&obj);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_transfer(void)
{
	udif_object obj = { 0U };
	udif_transfer_record transfer = { 0U };
	udif_signature_keypair kp1 = { 0U };
	udif_signature_keypair kp2 = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner1[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner2[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner1, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner2, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypairs for both owners */
	udif_signature_generate_keypair(kp1.verkey, kp1.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kp2.verkey, kp2.sigkey, qsc_csp_generate);

	/* create object with first owner */
	err = udif_object_create(&obj, serial, 0x00000001, creator, attrroot, owner1, kp1.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_transfer: object creation failed");
		res = false;
	}
	else
	{
		if (qsc_memutils_are_equal(obj.owner, owner1, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("object_test_transfer: initial owner mismatch");
			res = false;
		}
		else if (udif_object_verify(&obj, kp1.verkey) == false)
		{
			qsc_consoleutils_print_line("object_test_transfer: initial owner signature invalid");
			res = false;
		}
		else
		{
			/* transfer to second owner */
			err = udif_object_transfer(&obj, &transfer, owner2, kp1.sigkey, kp2.sigkey, ctime, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_transfer: transfer failed");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj.owner, owner2, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: owner not updated");
				res = false;
			}
			else if (qsc_memutils_are_equal(transfer.owner, owner2, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: transfer owner mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(transfer.originator, owner1, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: transfer originator mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(transfer.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: transfer serial mismatch");
				res = false;
			}
			else if (udif_object_verify(&obj, kp2.verkey) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: new owner signature invalid");
				res = false;
			}
			else if (udif_transfer_verify(&transfer, kp1.verkey, kp2.verkey) == false)
			{
				qsc_consoleutils_print_line("object_test_transfer: transfer signatures invalid");
				res = false;
			}
		}
	}

	udif_object_clear(&obj);
	udif_transfer_clear(&transfer);
	qsc_memutils_clear((uint8_t*)&kp1, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kp2, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_destroy(void)
{
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create object */
	err = udif_object_create(&obj, serial, 0x00000001, creator, attrroot, owner, kp.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_destroy: object creation failed");
		res = false;
	}
	else
	{
		if (udif_object_is_destroyed(&obj) == true)
		{
			qsc_consoleutils_print_line("object_test_destroy: new object should not be destroyed");
			res = false;
		}
		else
		{
			/* destroy object */
			err = udif_object_destroy(&obj, kp.sigkey, ctime, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_destroy: destruction failed");
				res = false;
			}
			else if (udif_object_is_destroyed(&obj) == false)
			{
				qsc_consoleutils_print_line("object_test_destroy: object should be marked destroyed");
				res = false;
			}
			else if (udif_object_verify(&obj, kp.verkey) == false)
			{
				qsc_consoleutils_print_line("object_test_destroy: destroyed object signature should still be valid");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_destroy: serial should remain after destruction");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj.owner, owner, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_destroy: owner should remain after destruction");
				res = false;
			}
		}
	}

	udif_object_clear(&obj);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_serialize(void)
{
	udif_object obj1 = { 0U };
	udif_object obj2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t buffer[UDIF_OBJECT_ENCODED_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create object */
	err = udif_object_create(&obj1, serial, 0x12345678, creator, attrroot, owner, kp.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_serialize: object creation failed");
		res = false;
	}
	else
	{
		/* serialize */
		err = udif_object_serialize(buffer, sizeof(buffer), &obj1);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("object_test_serialize: serialization failed");
			res = false;
		}
		else
		{
			/* deserialize */
			err = udif_object_deserialize(&obj2, buffer, sizeof(buffer));

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialization failed");
				res = false;
			}
			else if (udif_object_compare(&obj1, &obj2) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized object does not match original");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj2.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized serial mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj2.creator, creator, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized creator mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj2.owner, owner, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized owner mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(obj2.attrroot, attrroot, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized attrroot mismatch");
				res = false;
			}
			else if (obj2.type != 0x12345678)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized type mismatch");
				res = false;
			}
			else if (obj2.created != ctime)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized creation time mismatch");
				res = false;
			}
			else if (udif_object_verify(&obj2, kp.verkey) == false)
			{
				qsc_consoleutils_print_line("object_test_serialize: deserialized object signature invalid");
				res = false;
			}
		}
	}

	udif_object_clear(&obj1);
	udif_object_clear(&obj2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_transfer_record(void)
{
	udif_object obj = { 0U };
	udif_transfer_record transfer1 = { 0U };
	udif_transfer_record transfer2 = { 0U };
	udif_signature_keypair kp1 = { 0U };
	udif_signature_keypair kp2 = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner1[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner2[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t buffer[UDIF_TRANSFER_RECORD_ENCODED_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner1, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner2, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypairs */
	udif_signature_generate_keypair(kp1.verkey, kp1.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(kp2.verkey, kp2.sigkey, qsc_csp_generate);

	/* create and transfer object */
	err = udif_object_create(&obj, serial, 0x00000001, creator, attrroot, owner1, kp1.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_transfer_record: object creation failed");
		res = false;
	}
	else
	{
		err = udif_object_transfer(&obj, &transfer1, owner2, kp1.sigkey, kp2.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("object_test_transfer_record: transfer failed");
			res = false;
		}
		else
		{
			/* serialize transfer record */
			err = udif_transfer_serialize(buffer, sizeof(buffer), &transfer1);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_transfer_record: transfer serialization failed");
				res = false;
			}
			else
			{
				/* deserialize transfer record */
				err = udif_transfer_deserialize(&transfer2, buffer, sizeof(buffer));

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: transfer deserialization failed");
					res = false;
				}
				else if (qsc_memutils_are_equal(transfer1.sender, transfer2.sender, UDIF_SIGNED_HASH_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: sender signature mismatch");
					res = false;
				}
				else if (qsc_memutils_are_equal(transfer1.receiver, transfer2.receiver, UDIF_SIGNED_HASH_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: receiver signature mismatch");
					res = false;
				}
				else if (qsc_memutils_are_equal(transfer1.serial, transfer2.serial, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: transfer serial mismatch");
					res = false;
				}
				else if (qsc_memutils_are_equal(transfer1.originator, transfer2.originator, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: transfer originator mismatch");
					res = false;
				}
				else if (qsc_memutils_are_equal(transfer1.owner, transfer2.owner, UDIF_SERIAL_NUMBER_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: transfer owner mismatch");
					res = false;
				}
				else if (transfer1.timestamp != transfer2.timestamp)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: transfer timestamp mismatch");
					res = false;
				}
				else if (udif_transfer_verify(&transfer2, kp1.verkey, kp2.verkey) == false)
				{
					qsc_consoleutils_print_line("object_test_transfer_record: deserialized transfer signatures invalid");
					res = false;
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_transfer_clear(&transfer1);
	udif_transfer_clear(&transfer2);
	qsc_memutils_clear((uint8_t*)&kp1, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&kp2, sizeof(udif_signature_keypair));

	return res;
}

static bool object_test_compare_digest(void)
{
	udif_object obj1 = { 0U };
	udif_object obj2 = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(owner, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* create two identical objects */
	err = udif_object_create(&obj1, serial, 0x00000001, creator, attrroot, owner, kp.sigkey, ctime, qsc_csp_generate);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("object_test_compare_digest: first object creation failed");
		res = false;
	}
	else
	{
		err = udif_object_create(&obj2, serial, 0x00000001, creator, attrroot, owner, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("object_test_compare_digest: second object creation failed");
			res = false;
		}
		else
		{
			/* compute digests */
			err = udif_object_compute_digest(digest1, &obj1);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_test_compare_digest: first digest computation failed");
				res = false;
			}
			else
			{
				err = udif_object_compute_digest(digest2, &obj2);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("object_test_compare_digest: second digest computation failed");
					res = false;
				}
				else if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
				{
					qsc_consoleutils_print_line("object_test_compare_digest: digests should match");
					res = false;
				}
				else
				{
					/* copy object and verify compare */
					qsc_memutils_copy((uint8_t*)&obj2, (uint8_t*)&obj1, sizeof(udif_object));

					if (udif_object_compare(&obj1, &obj2) == false)
					{
						qsc_consoleutils_print_line("object_test_compare_digest: copied objects should be equal");
						res = false;
					}
				}
			}
		}
	}

	udif_object_clear(&obj1);
	udif_object_clear(&obj2);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

bool object_test_run(void)
{
	bool res;

	res = true;

	if (object_test_create() == true)
	{
		qsc_consoleutils_print_line("Success! Object creation test passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object creation test failed.");
		res = false;
	}

	if (object_test_update_attributes() == true)
	{
		qsc_consoleutils_print_line("Success! Object attributes update test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object attributes update test has failed.");
		res = false;
	}

	if (object_test_transfer() == true)
	{
		qsc_consoleutils_print_line("Success! Object transfer test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object transfer test has failed.");
		res = false;
	}

	if (object_test_destroy() == true)
	{
		qsc_consoleutils_print_line("Success! Object destruction test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object destruction test has failed.");
		res = false;
	}

	if (object_test_serialize() == true)
	{
		qsc_consoleutils_print_line("Success! Object serialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object serialization test has failed.");
		res = false;
	}

	if (object_test_transfer_record() == true)
	{
		qsc_consoleutils_print_line("Success! Object record transfer test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object record transfer test has failed.");
		res = false;
	}

	if (object_test_compare_digest() == true)
	{
		qsc_consoleutils_print_line("Success! Object digest comparison test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object digest comparison test has failed.");
		res = false;
	}

	return res;
}
