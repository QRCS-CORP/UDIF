#include "registry_test.h"
#include "registry.h"
#include "object.h"
#include "query.h"
#include "udif.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"
#include "consoleutils.h"

static bool registry_test_initialize(void)
{
	udif_registry_state reg = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;
	bool res;

	res = true;

	/* generate owner serial */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_initialize: initialization failed");
		res = false;
	}
	else
	{
		if (reg.initialized == false)
		{
			qsc_consoleutils_print_line("registry_test_initialize: initialized flag not set");
			res = false;
		}
		else if (qsc_memutils_are_equal(reg.ownerser, ownerser, UDIF_SERIAL_NUMBER_SIZE) == false)
		{
			qsc_consoleutils_print_line("registry_test_initialize: owner serial mismatch");
			res = false;
		}
		else if (reg.capacity != UDIF_REGISTRY_DEFAULT_CAPACITY)
		{
			qsc_consoleutils_print_line("registry_test_initialize: capacity mismatch");
			res = false;
		}
		else if (reg.objcount != 0U)
		{
			qsc_consoleutils_print_line("registry_test_initialize: initial count should be zero");
			res = false;
		}
		else if (reg.leaves == NULL)
		{
			qsc_consoleutils_print_line("registry_test_initialize: leaves not allocated");
			res = false;
		}
		else if (udif_registry_get_count(&reg) != 0)
		{
			qsc_consoleutils_print_line("registry_test_initialize: get_count should return zero");
			res = false;
		}
		else if (udif_registry_get_capacity(&reg) != UDIF_REGISTRY_DEFAULT_CAPACITY)
		{
			qsc_consoleutils_print_line("registry_test_initialize: get_capacity mismatch");
			res = false;
		}
	}

	udif_registry_dispose(&reg);

	return res;
}

static bool registry_test_add_objects(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_add_objects: registry initialization failed");
		res = false;
	}
	else
	{
		/* create object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_add_objects: object creation failed");
			res = false;
		}
		else
		{
			/* add object to registry */
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_add_objects: add object failed");
				res = false;
			}
			else if (udif_registry_get_count(&reg) != 1)
			{
				qsc_consoleutils_print_line("registry_test_add_objects: count should be 1");
				res = false;
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_remove_objects(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_remove_objects: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_remove_objects: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_remove_objects: add object failed");
				res = false;
			}
			else if (udif_registry_get_count(&reg) != 1)
			{
				qsc_consoleutils_print_line("registry_test_remove_objects: count should be 1 after add");
				res = false;
			}
			else
			{
				/* remove object */
				err = udif_registry_remove_object(&reg, objserial);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("registry_test_remove_objects: remove object failed");
					res = false;
				}
				else if (udif_registry_get_count(&reg) != 1U)
				{
					qsc_consoleutils_print_line("registry_test_remove_objects: leaf should remain after remove");
					res = false;
				}
				else if ((reg.leaves[0U].flags & UDIF_REGISTRY_FLAG_DESTROYED) == 0U)
				{
					qsc_consoleutils_print_line("registry_test_remove_objects: destroyed flag not set");
					res = false;
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_update_objects(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t attrroot2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;
	size_t idx;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot1, UDIF_CRYPTO_HASH_SIZE);
	qsc_csp_generate(attrroot2, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_update_objects: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot1, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_update_objects: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_update_objects: add object failed");
				res = false;
			}
			else
			{
				/* get initial digest */
				if (udif_registry_find_object(&reg, objserial, &idx) == false)
				{
					qsc_consoleutils_print_line("registry_test_update_objects: object not found after add");
					res = false;
				}
				else
				{
					err = udif_registry_get_digest_at(digest1, &reg, idx);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("registry_test_update_objects: failed to get initial digest");
						res = false;
					}
					else
					{
						/* update object */
						err = udif_object_update_attributes(&obj, attrroot2, kp.sigkey, ctime, qsc_csp_generate);

						if (err != udif_error_none)
						{
							qsc_consoleutils_print_line("registry_test_update_objects: object update failed");
							res = false;
						}
						else
						{
							err = udif_registry_update_object(&reg, &obj);

							if (err != udif_error_none)
							{
								qsc_consoleutils_print_line("registry_test_update_objects: registry update failed");
								res = false;
							}
							else
							{
								/* get updated digest */
								err = udif_registry_get_digest_at(digest2, &reg, idx);

								if (err != udif_error_none)
								{
									qsc_consoleutils_print_line("registry_test_update_objects: failed to get updated digest");
									res = false;
								}
								else if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == true)
								{
									qsc_consoleutils_print_line("registry_test_update_objects: digest should change after update");
									res = false;
								}
							}
						}
					}
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_find_objects(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t notfoundser[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	size_t idx;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(notfoundser, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_find_objects: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_find_objects: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_find_objects: add object failed");
				res = false;
			}
			else
			{
				/* find existing object */
				if (udif_registry_find_object(&reg, objserial, &idx) == false)
				{
					qsc_consoleutils_print_line("registry_test_find_objects: failed to find existing object");
					res = false;
				}
				else
				{
					/* try to find non-existent object */
					if (udif_registry_find_object(&reg, notfoundser, &idx) == true)
					{
						qsc_consoleutils_print_line("registry_test_find_objects: found non-existent object");
						res = false;
					}
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_compute_root(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t root1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t root2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;
	bool ret;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_compute_root: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_compute_root: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_compute_root: add object failed");
				res = false;
			}
			else
			{
				/* compute root */
				err = udif_registry_compute_root(root1, &reg);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("registry_test_compute_root: root computation failed");
					res = false;
				}
				else
				{
					/* verify root is not all zeros */
					ret = qsc_memutils_zeroed(root1, sizeof(root1));

					if (ret == true)
					{
						qsc_consoleutils_print_line("registry_test_compute_root: root is all zeros");
						res = false;
					}
					else
					{
						/* compute again and verify determinism */
						err = udif_registry_compute_root(root2, &reg);

						if (err != udif_error_none)
						{
							qsc_consoleutils_print_line("registry_test_compute_root: second root computation failed");
							res = false;
						}
						else if (qsc_memutils_are_equal(root1, root2, UDIF_CRYPTO_HASH_SIZE) == false)
						{
							qsc_consoleutils_print_line("registry_test_compute_root: root not deterministic");
							res = false;
						}
					}
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_merkle_proofs(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t root[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t leafdigest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t* proof;
	size_t prooflen;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;
	proof = NULL;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	proof = (uint8_t*)qsc_memutils_malloc(UDIF_QUERY_MAX_PROOF_SIZE);

	if (proof == NULL)
	{
		res = false;
	}

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = (proof == NULL) ? udif_error_internal :
		udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_merkle_proofs: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_merkle_proofs: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_merkle_proofs: add object failed");
				res = false;
			}
			else
			{
				/* compute root */
				err = udif_registry_compute_root(root, &reg);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("registry_test_merkle_proofs: root computation failed");
					res = false;
				}
				else
				{
					/* generate proof */
					prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
					err = udif_registry_generate_proof(proof, &prooflen, &reg, objserial);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("registry_test_merkle_proofs: proof generation failed");
						res = false;
					}
					else
					{
						/* compute registry leaf digest */
						err = udif_registry_get_digest_at(leafdigest, &reg, 0U);

						if (err != udif_error_none)
						{
							qsc_consoleutils_print_line("registry_test_merkle_proofs: leaf digest computation failed");
							res = false;
						}
						else
						{
							/* verify proof */
							if (udif_registry_verify_proof(proof, prooflen, root, leafdigest) == false)
							{
								qsc_consoleutils_print_line("registry_test_merkle_proofs: proof verification failed");
								res = false;
							}
						}
					}
				}
			}
		}
	}

	if (proof != NULL)
	{
		qsc_memutils_alloc_free(proof);
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_resize(void)
{
	udif_registry_state reg = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	size_t newcap;
	udif_errors err;
	bool res;

	res = true;

	/* generate owner serial */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);

	/* initialize registry with small capacity */
	err = udif_registry_initialize(&reg, ownerser, 100);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_resize: registry initialization failed");
		res = false;
	}
	else
	{
		if (udif_registry_get_capacity(&reg) != 100)
		{
			qsc_consoleutils_print_line("registry_test_resize: initial capacity mismatch");
			res = false;
		}
		else
		{
			/* resize to larger capacity */
			newcap = 500;
			err = udif_registry_resize(&reg, newcap);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_resize: resize failed");
				res = false;
			}
			else if (udif_registry_get_capacity(&reg) != newcap)
			{
				qsc_consoleutils_print_line("registry_test_resize: capacity not updated");
				res = false;
			}
		}
	}

	udif_registry_dispose(&reg);

	return res;
}

static bool registry_test_capacity(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	size_t smallcap;
	size_t i;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry with small capacity */
	smallcap = 5;
	err = udif_registry_initialize(&reg, ownerser, smallcap);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_capacity: registry initialization failed");
		res = false;
	}
	else
	{
		if (udif_registry_is_full(&reg) == true)
		{
			qsc_consoleutils_print_line("registry_test_capacity: empty registry should not be full");
			res = false;
		}
		else
		{
			/* fill registry to capacity */
			for (i = 0; i < smallcap; ++i)
			{
				uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };

				qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
				err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("registry_test_capacity: object creation failed");
					res = false;
					break;
				}
				else
				{
					err = udif_registry_add_object(&reg, &obj);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("registry_test_capacity: add object failed");
						res = false;
						break;
					}
				}
			}

			if (res == true)
			{
				if (udif_registry_is_full(&reg) == false)
				{
					qsc_consoleutils_print_line("registry_test_capacity: full registry not reported as full");
					res = false;
				}
				else if (udif_registry_get_count(&reg) != smallcap)
				{
					qsc_consoleutils_print_line("registry_test_capacity: count mismatch");
					res = false;
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

bool registry_test_clear(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	/* generate test data */
	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	/* generate keypair */
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	/* initialize registry */
	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_clear: registry initialization failed");
		res = false;
	}
	else
	{
		/* create and add object */
		err = udif_object_create(&obj, objserial, 0x00000001, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_clear: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_clear: add object failed");
				res = false;
			}
			else if (udif_registry_get_count(&reg) != 1)
			{
				qsc_consoleutils_print_line("registry_test_clear: count should be 1 after add");
				res = false;
			}
			else
			{
				/* clear registry */
				udif_registry_clear(&reg);

				if (udif_registry_get_count(&reg) != 0)
				{
					qsc_consoleutils_print_line("registry_test_clear: count should be 0 after clear");
					res = false;
				}
				else if (udif_registry_get_capacity(&reg) != UDIF_REGISTRY_DEFAULT_CAPACITY)
				{
					qsc_consoleutils_print_line("registry_test_clear: capacity should remain unchanged");
					res = false;
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool registry_test_signed_commit(void)
{
	udif_registry_commit commit;
	udif_signature_keypair keypair;
	uint8_t enc[UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE];
	uint8_t root[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	qsc_memutils_clear((uint8_t*)&commit, sizeof(commit));
	qsc_memutils_clear((uint8_t*)&keypair, sizeof(keypair));
	qsc_memutils_clear(enc, sizeof(enc));

	qsc_csp_generate(root, sizeof(root));
	qsc_csp_generate(ownerser, sizeof(ownerser));
	udif_signature_generate_keypair(keypair.verkey, keypair.sigkey, qsc_csp_generate);
	nowsecs = qsc_timestamp_datetime_utc();

	qsc_memutils_copy(commit.ownerser, ownerser, sizeof(ownerser));
	qsc_memutils_copy(commit.regroot, root, sizeof(root));
	commit.epoch = 7U;
	commit.timestamp = nowsecs;

	err = udif_registry_commit_sign(&commit, keypair.sigkey, qsc_csp_generate);

	if (err == udif_error_none && udif_registry_commit_verify(&commit, keypair.verkey) == true &&
		udif_registry_commit_serialize(enc, sizeof(enc), &commit) == udif_error_none)
	{
		udif_registry_commit decoded;

		qsc_memutils_clear((uint8_t*)&decoded, sizeof(decoded));

		if (udif_registry_commit_deserialize(&decoded, enc, sizeof(enc)) == udif_error_none &&
			udif_registry_commit_verify(&decoded, keypair.verkey) == true)
		{
			decoded.regroot[0U] ^= 0x01U;
			res = (udif_registry_commit_verify(&decoded, keypair.verkey) == false);
		}

		udif_registry_commit_clear(&decoded);
	}

	udif_registry_commit_clear(&commit);
	qsc_memutils_clear((uint8_t*)&keypair, sizeof(keypair));
	qsc_memutils_clear(enc, sizeof(enc));

	return res;
}


static bool registry_test_leaf_serial_is_committed(void)
{
	udif_registry_state reg = { 0U };
	udif_object obj = { 0U };
	udif_signature_keypair kp = { 0U };
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objserial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t root1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t root2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = true;

	qsc_csp_generate(ownerser, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(objserial, UDIF_OBJECT_SERIAL_SIZE);
	qsc_csp_generate(creator, UDIF_SERIAL_NUMBER_SIZE);
	qsc_csp_generate(attrroot, UDIF_CRYPTO_HASH_SIZE);
	ctime = qsc_timestamp_datetime_utc();

	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	err = udif_registry_initialize(&reg, ownerser, UDIF_REGISTRY_DEFAULT_CAPACITY);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: registry initialization failed");
		res = false;
	}
	else
	{
		err = udif_object_create(&obj, objserial, 0x00000001UL, creator, attrroot, ownerser, kp.sigkey, ctime, qsc_csp_generate);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: object creation failed");
			res = false;
		}
		else
		{
			err = udif_registry_add_object(&reg, &obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: add object failed");
				res = false;
			}
			else
			{
				err = udif_registry_compute_root(root1, &reg);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: initial root computation failed");
					res = false;
				}
				else
				{
					reg.leaves[0U].objserial[0U] ^= 0x01U;
					err = udif_registry_compute_root(root2, &reg);

					if (err != udif_error_none)
					{
						qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: mutated root computation failed");
						res = false;
					}
					else if (qsc_memutils_are_equal(root1, root2, UDIF_CRYPTO_HASH_SIZE) == true)
					{
						qsc_consoleutils_print_line("registry_test_leaf_serial_is_committed: objserial mutation did not change registry root");
						res = false;
					}
				}
			}
		}
	}

	udif_object_clear(&obj);
	udif_registry_dispose(&reg);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

bool registry_test_run(void)
{
	bool res;

	res = true;

	if (registry_test_initialize() == true)
	{
		qsc_consoleutils_print_line("Success! Registry initialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry initialization test has failed.");
		res = false;
	}

	if (registry_test_add_objects() == true)
	{
		qsc_consoleutils_print_line("Success! Registry add objects test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry add objects test has failed.");
		res = false;
	}

	if (registry_test_remove_objects() == true)
	{
		qsc_consoleutils_print_line("Success! Registry remove objects test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry remove objects test has failed.");
		res = false;
	}

	if (registry_test_update_objects() == true)
	{
		qsc_consoleutils_print_line("Success! Registry update objects test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry update objects test has failed.");
		res = false;
	}

	if (registry_test_find_objects() == true)
	{
		qsc_consoleutils_print_line("Success! Registry find objects test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry find objects test has failed.");
		res = false;
	}

	if (registry_test_compute_root() == true)
	{
		qsc_consoleutils_print_line("Success! Registry compute root test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry compute root test has failed.");
		res = false;
	}

	if (registry_test_merkle_proofs() == true)
	{
		qsc_consoleutils_print_line("Success! Registry merkle proofs test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry merkle proofs test has failed.");
		res = false;
	}

	if (registry_test_resize() == true)
	{
		qsc_consoleutils_print_line("Success! Registry resize test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry resize test has failed.");
		res = false;
	}

	if (registry_test_capacity() == true)
	{
		qsc_consoleutils_print_line("Success! Registry capacity test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry capacity test has failed.");
		res = false;
	}

	if (registry_test_clear() == true)
	{
		qsc_consoleutils_print_line("Success! Registry clear test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry clear test has failed.");
		res = false;
	}

	if (registry_test_leaf_serial_is_committed() == true)
	{
		qsc_consoleutils_print_line("Success! Registry leaf serial commitment test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry leaf serial commitment test has failed.");
		res = false;
	}

	if (registry_test_signed_commit() == true)
	{
		qsc_consoleutils_print_line("Success! Registry signed commit test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Registry signed commit test has failed.");
		res = false;
	}

	return res;
}


