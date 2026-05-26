#include "object_registry_transaction_test.h"
#include "object.h"
#include "registry.h"
#include "csp.h"
#include "memutils.h"
#include "consoleutils.h"
#include "timestamp.h"

typedef struct object_registry_transaction_test_state
{
	udif_registry_state sender;
	udif_registry_state receiver;
	udif_registry_state third;
	udif_object object;
	udif_transfer_record transfer;
	udif_signature_keypair senderkp;
	udif_signature_keypair receiverkp;
	uint8_t sender_serial[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t receiver_serial[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t third_serial[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t creator_serial[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t object_serial[UDIF_OBJECT_SERIAL_SIZE];
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];
	uint8_t root_before[UDIF_CRYPTO_HASH_SIZE];
	uint8_t root_sender_after[UDIF_CRYPTO_HASH_SIZE];
	uint8_t root_receiver_after[UDIF_CRYPTO_HASH_SIZE];
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE];
	uint8_t proof[UDIF_CRYPTO_HASH_SIZE * 8U];
} object_registry_transaction_test_state;

static void object_registry_transaction_test_fill(uint8_t* output, size_t outlen, uint8_t seed)
{
	size_t i;

	for (i = 0U; i < outlen; ++i)
	{
		output[i] = (uint8_t)(seed + (uint8_t)i);
	}
}

static bool object_registry_transaction_test_initialize(object_registry_transaction_test_state* st)
{
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		qsc_memutils_clear((uint8_t*)st, sizeof(object_registry_transaction_test_state));
		object_registry_transaction_test_fill(st->sender_serial, sizeof(st->sender_serial), 0x10U);
		object_registry_transaction_test_fill(st->receiver_serial, sizeof(st->receiver_serial), 0x30U);
		object_registry_transaction_test_fill(st->third_serial, sizeof(st->third_serial), 0x50U);
		object_registry_transaction_test_fill(st->creator_serial, sizeof(st->creator_serial), 0x70U);
		object_registry_transaction_test_fill(st->object_serial, sizeof(st->object_serial), 0x90U);
		qsc_csp_generate(st->attrroot, sizeof(st->attrroot));
		udif_signature_generate_keypair(st->senderkp.verkey, st->senderkp.sigkey, qsc_csp_generate);
		udif_signature_generate_keypair(st->receiverkp.verkey, st->receiverkp.sigkey, qsc_csp_generate);

		nowsecs = qsc_timestamp_datetime_utc();
		err = udif_registry_initialize(&st->sender, st->sender_serial, 4U);

		if (err == udif_error_none)
		{
			err = udif_registry_initialize(&st->receiver, st->receiver_serial, 4U);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_initialize(&st->third, st->third_serial, 4U);
		}

		if (err == udif_error_none)
		{
			err = udif_object_create(&st->object, st->object_serial, 0x00000001UL, st->creator_serial,
				st->attrroot, st->sender_serial, st->senderkp.sigkey, nowsecs, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_compute_root(st->root_before, &st->sender);
		}

		if (err == udif_error_none)
		{
			err = udif_registry_add_object(&st->sender, &st->object);
		}

		res = (err == udif_error_none);
	}

	return res;
}

static void object_registry_transaction_test_dispose(object_registry_transaction_test_state* st)
{
	if (st != NULL)
	{
		udif_registry_dispose(&st->sender);
		udif_registry_dispose(&st->receiver);
		udif_registry_dispose(&st->third);
		udif_object_clear(&st->object);
		udif_transfer_clear(&st->transfer);
		qsc_memutils_clear((uint8_t*)st, sizeof(object_registry_transaction_test_state));
	}
}

static bool object_registry_transaction_test_lifecycle(void)
{
	object_registry_transaction_test_state* st;
	udif_registry_leaf leaf;
	size_t prooflen;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	st = (object_registry_transaction_test_state*)qsc_memutils_malloc(sizeof(object_registry_transaction_test_state));
	res = false;

	if (st == NULL)
	{
		qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: allocation failed");
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
		res = object_registry_transaction_test_initialize(st);

		if (res == false)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: initialization failed");
		}
		else if (UDIF_OBJECT_SERIAL_SIZE != 32U)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: object serial size is not 32 bytes");
			res = false;
		}
		else if (udif_registry_object_is_active(&st->sender, st->object_serial) == false)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: sender registry leaf is not active");
			res = false;
		}
		else if (udif_registry_compute_root(st->root_sender_after, &st->sender) != udif_error_none ||
			qsc_memutils_are_equal(st->root_before, st->root_sender_after, UDIF_CRYPTO_HASH_SIZE) == true)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: registry root did not change after object insertion");
			res = false;
		}
		else
		{
			nowsecs = qsc_timestamp_datetime_utc();
			err = udif_object_transfer(&st->object, &st->transfer, st->receiver_serial, st->senderkp.sigkey,
				st->receiverkp.sigkey, nowsecs, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: object transfer failed");
				res = false;
			}
			else if (udif_transfer_verify(&st->transfer, st->senderkp.verkey, st->receiverkp.verkey) == false)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: transfer signature verification failed");
				res = false;
			}
			else if (udif_registry_transfer_object(&st->sender, &st->receiver, &st->transfer) != udif_error_none)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: registry transfer failed");
				res = false;
			}
			else if (udif_registry_get_leaf(&leaf, &st->sender, st->object_serial) != udif_error_none ||
				(leaf.flags & UDIF_REGISTRY_FLAG_ACTIVE) != 0U ||
				(leaf.flags & UDIF_REGISTRY_FLAG_TRANSFERRED) == 0U)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: sender leaf transfer state is invalid");
				res = false;
			}
			else if (udif_registry_object_is_active(&st->receiver, st->object_serial) == false)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: receiver registry leaf is not active");
				res = false;
			}
			else if (udif_registry_compute_root(st->root_sender_after, &st->sender) != udif_error_none ||
				udif_registry_compute_root(st->root_receiver_after, &st->receiver) != udif_error_none)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: root computation failed after transfer");
				res = false;
			}
			else
			{
				prooflen = sizeof(st->proof);
				err = udif_registry_generate_proof(st->proof, &prooflen, &st->receiver, st->object_serial);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: membership proof generation failed");
					res = false;
				}
				else if (udif_registry_get_leaf(&leaf, &st->receiver, st->object_serial) != udif_error_none ||
					udif_registry_leaf_digest(st->digest, &leaf) != udif_error_none ||
					udif_registry_verify_proof(st->proof, prooflen, st->root_receiver_after, st->digest) == false)
				{
					qsc_consoleutils_print_line("object_registry_transaction_test_lifecycle: membership proof verification failed");
					res = false;
				}
			}
		}

		object_registry_transaction_test_dispose(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

static bool object_registry_transaction_test_attack_cases(void)
{
	object_registry_transaction_test_state* st;
	udif_transfer_record forged;
	udif_registry_leaf leaf;
	uint8_t saved;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	st = (object_registry_transaction_test_state*)qsc_memutils_malloc(sizeof(object_registry_transaction_test_state));
	res = false;

	if (st == NULL)
	{
		qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: allocation failed");
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&forged, sizeof(udif_transfer_record));
		qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
		res = object_registry_transaction_test_initialize(st);

		if (res == false)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: initialization failed");
		}
		else
		{
			nowsecs = qsc_timestamp_datetime_utc();
			err = udif_object_transfer(&st->object, &st->transfer, st->receiver_serial, st->senderkp.sigkey,
				st->receiverkp.sigkey, nowsecs, qsc_csp_generate);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: transfer creation failed");
				res = false;
			}
			else
			{
				qsc_memutils_copy(&forged, &st->transfer, sizeof(udif_transfer_record));
				qsc_memutils_clear(forged.sender, UDIF_SIGNED_HASH_SIZE);

				if (udif_transfer_verify(&forged, st->senderkp.verkey, st->receiverkp.verkey) == true)
				{
					qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: forged sender signature accepted");
					res = false;
				}
				else
				{
					qsc_memutils_copy(&forged, &st->transfer, sizeof(udif_transfer_record));
					qsc_memutils_clear(forged.receiver, UDIF_SIGNED_HASH_SIZE);

					if (udif_transfer_verify(&forged, st->senderkp.verkey, st->receiverkp.verkey) == true)
					{
						qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: forged receiver signature accepted");
						res = false;
					}
					else
					{
						qsc_memutils_copy(&forged, &st->transfer, sizeof(udif_transfer_record));
						forged.serial[0U] ^= 0x01U;

						if (udif_transfer_verify(&forged, st->senderkp.verkey, st->receiverkp.verkey) == true)
						{
							qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: mutated object serial accepted");
							res = false;
						}
						else
						{
							qsc_memutils_copy(&forged, &st->transfer, sizeof(udif_transfer_record));
							forged.originator[0U] ^= 0x01U;

							if (udif_registry_transfer_object(&st->sender, &st->receiver, &forged) != udif_error_not_authorized)
							{
								qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: non-owner transfer was not rejected");
								res = false;
							}
							else if (udif_registry_transfer_object(&st->sender, &st->receiver, &st->transfer) != udif_error_none)
							{
								qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: valid registry transfer failed");
								res = false;
							}
							else if (udif_registry_transfer_object(&st->sender, &st->receiver, &st->transfer) == udif_error_none)
							{
								qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: duplicate transfer accepted");
								res = false;
							}
							else if (udif_registry_remove_object(&st->receiver, st->object_serial) != udif_error_none ||
								udif_registry_transfer_object(&st->receiver, &st->third, &st->transfer) != udif_error_not_authorized)
							{
								qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: destroyed or wrong-owner transfer check failed");
								res = false;
							}
							else if (udif_registry_get_leaf(&leaf, &st->receiver, st->object_serial) != udif_error_none)
							{
								qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: receiver leaf lookup failed");
								res = false;
							}
							else
							{
								saved = leaf.objdigest[0U];
								leaf.objdigest[0U] ^= 0x01U;

								if (qsc_memutils_are_equal(&saved, leaf.objdigest, 1U) == true)
								{
									qsc_consoleutils_print_line("object_registry_transaction_test_attack_cases: leaf mutation failed");
									res = false;
								}
							}
						}
					}
				}
			}
		}

		qsc_memutils_clear((uint8_t*)&forged, sizeof(udif_transfer_record));
		object_registry_transaction_test_dispose(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

static bool object_registry_transaction_test_owner_binding(void)
{
	object_registry_transaction_test_state* st;
	udif_object outsider;
	udif_errors err;
	bool res;

	st = (object_registry_transaction_test_state*)qsc_memutils_malloc(sizeof(object_registry_transaction_test_state));
	res = false;

	if (st == NULL)
	{
		qsc_consoleutils_print_line("object_registry_transaction_test_owner_binding: allocation failed");
	}
	else
	{
		qsc_memutils_clear((uint8_t*)&outsider, sizeof(udif_object));
		res = object_registry_transaction_test_initialize(st);

		if (res == false)
		{
			qsc_consoleutils_print_line("object_registry_transaction_test_owner_binding: initialization failed");
		}
		else
		{
			qsc_memutils_copy(&outsider, &st->object, sizeof(udif_object));
			qsc_memutils_copy(outsider.owner, st->receiver_serial, UDIF_SERIAL_NUMBER_SIZE);
			err = udif_registry_add_object(&st->sender, &outsider);

			if (err != udif_error_not_authorized)
			{
				qsc_consoleutils_print_line("object_registry_transaction_test_owner_binding: foreign-owned object insertion accepted");
				res = false;
			}
			else
			{
				err = udif_registry_update_object(&st->sender, &outsider);

				if (err != udif_error_not_authorized)
				{
					qsc_consoleutils_print_line("object_registry_transaction_test_owner_binding: foreign-owned object update accepted");
					res = false;
				}
			}
		}

		qsc_memutils_clear((uint8_t*)&outsider, sizeof(udif_object));
		object_registry_transaction_test_dispose(st);
		qsc_memutils_alloc_free(st);
	}

	return res;
}

bool object_registry_transaction_test_run(void)
{
	bool res;

	res = true;

	if (object_registry_transaction_test_lifecycle() == true)
	{
		qsc_consoleutils_print_line("Success! Object registry transaction lifecycle test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object registry transaction lifecycle test has failed.");
		res = false;
	}

	if (object_registry_transaction_test_attack_cases() == true)
	{
		qsc_consoleutils_print_line("Success! Object registry transaction attack test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object registry transaction attack test has failed.");
		res = false;
	}

	if (object_registry_transaction_test_owner_binding() == true)
	{
		qsc_consoleutils_print_line("Success! Object registry owner binding test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Object registry owner binding test has failed.");
		res = false;
	}

	return res;
}
