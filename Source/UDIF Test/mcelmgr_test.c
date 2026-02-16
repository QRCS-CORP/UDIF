#include "mcelmgr_test.h"
#include "mcelmanager.h"
#include "folderutils.h"
#include "memutils.h"
#include "udif.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define TEST_BLOCK_SIZE 10U
#define SMALL_BATCH 5U
#define LARGE_BATCH 100U

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define TEST_BASE_PATH "\\UDIF"
#else
#	define TEST_BASE_PATH "/UDIF"
#endif

static bool delete_directory(const char dir[QSC_SYSTEM_MAX_PATH])
{
	char command[4096] = { 0U };
	int32_t res;

	res = -1;

	if (dir != NULL && qsc_stringutils_string_size(dir) > 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		/* Windows: rd /s /q "path" */
		/* /s = remove subdirectories, /q = quiet (no confirmation) */
		snprintf(command, sizeof(command), "rd /s /q \"%s\" 2>nul", dir);
#else
		/* Linux/macOS: rm -rf path */
		/* -r = recursive, -f = force (no prompts) */
		snprintf(command, sizeof(command), "rm -rf \"%s\"", dir);
#endif

		res = system(command);
	}

	return (res == 0);
}

static void cleanup_test_directory(void)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
	qsc_stringutils_concat_strings(dir, sizeof(dir), TEST_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == true)
	{
		delete_directory(dir);
	}
}

static void setup_test_directory(char dir[QSC_SYSTEM_MAX_PATH])
{
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, TEST_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == false)
	{
		qsc_folderutils_create_directory(dir);
	}
}

static void generate_test_data(uint8_t* buffer, size_t len, uint8_t seed)
{
	for (size_t i = 0U; i < len; i++)
	{
		buffer[i] = (uint8_t)((seed + i) % 256U);
	}
}

static bool mcelmanager_test_initialize_default(void)
{
	udif_mcel_manager* mgr;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	udif_ledger_type active;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* initialize with default config */
	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_initialize_default: initialization failed");
		res = false;
	}
	else
	{
		/* verify active ledger is membership */
		active = udif_mcel_get_active_ledger(mgr);

		if (active != UDIF_LEDGER_MEMBERSHIP)
		{
			qsc_consoleutils_print_line("mcelmanager_test_initialize_default: default active ledger should be membership");
			res = false;
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_initialize_custom(void)
{
	udif_mcel_manager* mgr;
	udif_checkpoint_config config = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool res;

	res = true;

	setup_test_directory(dir);

	/* setup custom configuration */
	config.membinterval = 500U;
	config.transinterval = 1000U;
	config.reginterval = 750U;
	config.blocksize = 50U;
	config.autocheckpointenabled = true;

	/* initialize with custom config */
	mgr = udif_mcel_initialize(dir, &config);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_initialize_custom: initialization with custom config failed");
		res = false;
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_open_existing(void)
{
	udif_mcel_manager* mgr1;
	udif_mcel_manager* mgr2;
	uint8_t sigkey[UDIF_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE] = { 0U };
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* create and add record */
	mgr1 = udif_mcel_initialize(dir, NULL);

	if (mgr1 == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_open_existing: initial creation failed");
		res = false;
	}
	else
	{
		generate_test_data(data, sizeof(data), 1U);
		ret = udif_mcel_add_record(mgr1, data, sizeof(data), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_open_existing: add record failed");
			res = false;
		}
		else
		{
			/* get keypair before dispose */
			ret = udif_mcel_get_keypair(mgr1, sigkey, verkey);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_open_existing: get keypair failed");
				res = false;
			}
			else
			{
				udif_mcel_dispose(mgr1);

				/* reopen existing */
				mgr2 = udif_mcel_open(dir, false, sigkey, verkey);

				if (mgr2 == NULL)
				{
					qsc_consoleutils_print_line("mcelmanager_test_open_existing: reopen failed");
					res = false;
				}
				else
				{
					udif_mcel_dispose(mgr2);
				}
			}
		}
	}

	cleanup_test_directory();
	qsc_memutils_clear(sigkey, sizeof(sigkey));

	return res;
}

static bool mcelmanager_test_open_readonly(void)
{
	udif_mcel_manager* mgr1;
	udif_mcel_manager* mgr2;
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE] = { 0U };
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* create and add record */
	mgr1 = udif_mcel_initialize(dir, NULL);

	if (mgr1 == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_open_readonly: initialization failed");
		res = false;
	}
	else
	{
		generate_test_data(data, sizeof(data), 1U);
		ret = udif_mcel_add_record(mgr1, data, sizeof(data), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_open_readonly: add record failed");
			res = false;
		}
		else
		{
			/* get verify key */
			ret = udif_mcel_get_keypair(mgr1, NULL, verkey);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_open_readonly: get verify key failed");
				res = false;
			}
			else
			{
				udif_mcel_dispose(mgr1);

				/* open readonly */
				mgr2 = udif_mcel_open(dir, true, NULL, verkey);

				if (mgr2 == NULL)
				{
					qsc_consoleutils_print_line("mcelmanager_test_open_readonly: readonly open failed");
					res = false;
				}
				else
				{
					udif_mcel_dispose(mgr2);
				}
			}
		}
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_add_single_record(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[128U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_add_single_record: initialization failed");
		res = false;
	}
	else
	{
		/* generate and add record */
		generate_test_data(data, sizeof(data), 42U);

		ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);
		/* add another record */
		ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_add_single_record: add record failed");
			res = false;
		}
		else if (seq != 1U)
		{
			qsc_consoleutils_print_line("mcelmanager_test_add_single_record: second sequence should be 1");
			res = false;
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_add_batch_records(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_add_batch_records: initialization failed");
		res = false;
	}
	else
	{
		/* add batch of records */
		for (size_t i = 0U; i < SMALL_BATCH; i++)
		{
			generate_test_data(data, sizeof(data), (uint8_t)i);
			ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_add_batch_records: add record failed in batch");
				res = false;
				break;
			}
			else if (seq != i)
			{
				qsc_consoleutils_print_line("mcelmanager_test_add_batch_records: sequence number mismatch");
				res = false;
				break;
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_read_records(void)
{
	udif_mcel_manager* mgr;
	uint8_t writedata[64U] = { 0U };
	uint8_t readdata[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	size_t bytesread;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_read_records: initialization failed");
		res = false;
	}
	else
	{
		/* write record */
		generate_test_data(writedata, sizeof(writedata), 77U);
		ret = udif_mcel_add_record(mgr, writedata, sizeof(writedata), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_read_records: add record failed");
			res = false;
		}
		else
		{
			/* read back */
			ret = udif_mcel_read_record(mgr, seq, readdata, sizeof(readdata), &bytesread);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_read_records: read record failed");
				res = false;
			}
			else if (bytesread != sizeof(writedata))
			{
				qsc_consoleutils_print_line("mcelmanager_test_read_records: bytes read mismatch");
				res = false;
			}
			else if (qsc_memutils_are_equal(readdata, writedata, sizeof(writedata)) == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_read_records: data mismatch");
				res = false;
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_add_encrypted(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[128U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_add_encrypted: initialization failed");
		res = false;
	}
	else
	{
		/* add encrypted record */
		generate_test_data(data, sizeof(data), 99U);
		ret = udif_mcel_add_record(mgr, data, sizeof(data), true, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_add_encrypted: add encrypted record failed");
			res = false;
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_switch_ledgers(void)
{
	udif_mcel_manager* mgr;
	udif_ledger_type active;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: initialization failed");
		res = false;
	}
	else
	{
		/* verify default is membership */
		active = udif_mcel_get_active_ledger(mgr);

		if (active != UDIF_LEDGER_MEMBERSHIP)
		{
			qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: default should be membership");
			res = false;
		}
		else
		{
			/* switch to transaction */
			ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: switch to transaction failed");
				res = false;
			}
			else
			{
				active = udif_mcel_get_active_ledger(mgr);

				if (active != UDIF_LEDGER_TRANSACTION)
				{
					qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: active ledger not transaction");
					res = false;
				}
				else
				{
					/* switch to registry */
					ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_REGISTRY);

					if (ret == false)
					{
						qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: switch to registry failed");
						res = false;
					}
					else
					{
						active = udif_mcel_get_active_ledger(mgr);

						if (active != UDIF_LEDGER_REGISTRY)
						{
							qsc_consoleutils_print_line("mcelmanager_test_switch_ledgers: active ledger not registry");
							res = false;
						}
					}
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_get_ledger_size(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t count;
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: initialization failed");
		res = false;
	}
	else
	{
		/* check initial size */
		ret = udif_mcel_get_ledger_size(mgr, &count);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: get size failed");
			res = false;
		}
		else if (count != 0U)
		{
			qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: initial size should be 0");
			res = false;
		}
		else
		{
			/* add records */
			for (size_t i = 0U; i < SMALL_BATCH; ++i)
			{
				generate_test_data(data, sizeof(data), (uint8_t)i);
				ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

				if (ret == false)
				{
					qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: add record failed");
					res = false;
					break;
				}
			}

			if (res == true)
			{
				/* check updated size */
				ret = udif_mcel_get_ledger_size(mgr, &count);

				if (ret == false)
				{
					qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: get size after adds failed");
					res = false;
				}
				else if (count != SMALL_BATCH)
				{
					qsc_consoleutils_print_line("mcelmanager_test_get_ledger_size: size mismatch");
					res = false;
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_concurrent_ledgers(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t memseq;
	uint64_t txseq;
	uint64_t regseq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: initialization failed");
		res = false;
	}
	else
	{
		/* add to membership */
		generate_test_data(data, sizeof(data), 1U);
		ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &memseq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: add to membership failed");
			res = false;
		}
		else
		{
			/* switch to transaction */
			ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: switch to transaction failed");
				res = false;
			}
			else
			{
				/* add to transaction */
				generate_test_data(data, sizeof(data), 2U);
				ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &txseq);

				if (ret == false)
				{
					qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: add to transaction failed");
					res = false;
				}
				else
				{
					/* switch to registry */
					ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_REGISTRY);

					if (ret == false)
					{
						qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: switch to registry failed");
						res = false;
					}
					else
					{
						/* add to registry */
						generate_test_data(data, sizeof(data), 3U);
						ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &regseq);

						if (ret == false)
						{
							qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: add to registry failed");
							res = false;
						}
						else if (memseq != 0U || txseq != 0U || regseq != 0U)
						{
							qsc_consoleutils_print_line("mcelmanager_test_concurrent_ledgers: sequence numbers should all be 0");
							res = false;
						}
					}
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_auto_seal_block(void)
{
	udif_mcel_manager* mgr;
	udif_checkpoint_config config;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	size_t i;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* configure small block size for auto-seal */
	config.membinterval = 0U;
	config.transinterval = 0U;
	config.reginterval = 0U;
	config.blocksize = TEST_BLOCK_SIZE;
	config.autocheckpointenabled = false;

	mgr = udif_mcel_initialize(dir, &config);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_auto_seal_block: initialization failed");
		res = false;
	}
	else
	{
		/* add enough records to trigger auto-seal */
		for (i = 0U; i < TEST_BLOCK_SIZE + 1U; ++i)
		{
			generate_test_data(data, sizeof(data), (uint8_t)i);
			ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_auto_seal_block: add record failed");
				res = false;
				break;
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_manual_flush(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_manual_flush: initialization failed");
		res = false;
	}
	else
	{
		/* add record */
		generate_test_data(data, sizeof(data), 55U);
		ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_manual_flush: add record failed");
			res = false;
		}
		else
		{
			/* manual flush */
			ret = udif_mcel_flush_block(mgr);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_manual_flush: flush block failed");
				res = false;
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_empty_block_flush(void)
{
	udif_mcel_manager* mgr;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_empty_block_flush: initialization failed");
		res = false;
	}
	else
	{
		/* flush empty block should succeed (no-op) */
		ret = udif_mcel_flush_block(mgr);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_empty_block_flush: empty flush should succeed");
			res = false;
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_flush_all(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_flush_all: initialization failed");
		res = false;
	}
	else
	{
		/* add to membership */
		generate_test_data(data, sizeof(data), 1U);
		ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_flush_all: add to membership failed");
			res = false;
		}
		else
		{
			/* switch and add to transaction */
			ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_flush_all: switch to transaction failed");
				res = false;
			}
			else
			{
				generate_test_data(data, sizeof(data), 2U);
				ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

				if (ret == false)
				{
					qsc_consoleutils_print_line("mcelmanager_test_flush_all: add to transaction failed");
					res = false;
				}
				else
				{
					/* flush all ledgers */
					ret = udif_mcel_flush_all(mgr);

					if (ret == false)
					{
						qsc_consoleutils_print_line("mcelmanager_test_flush_all: flush all failed");
						res = false;
					}
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_manual_checkpoint(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	size_t i;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_manual_checkpoint: initialization failed");
		res = false;
	}
	else
	{
		/* add records */
		for (i = 0U; i < SMALL_BATCH; ++i)
		{
			generate_test_data(data, sizeof(data), (uint8_t)i);
			ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_manual_checkpoint: add record failed");
				res = false;
				break;
			}
		}

		if (res == true)
		{
			/* flush and checkpoint */
			ret = udif_mcel_flush_block(mgr);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_manual_checkpoint: flush failed");
				res = false;
			}
			else
			{
				ret = udif_mcel_create_checkpoint(mgr);

				if (ret == false)
				{
					qsc_consoleutils_print_line("mcelmanager_test_manual_checkpoint: create checkpoint failed");
					res = false;
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_auto_checkpoint(void)
{
	udif_mcel_manager* mgr;
	udif_checkpoint_config config = { 0U };
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	size_t i;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* configure auto checkpoint at small interval */
	config.membinterval = SMALL_BATCH;
	config.transinterval = 0U;
	config.reginterval = 0U;
	config.blocksize = 2U;
	config.autocheckpointenabled = true;

	mgr = udif_mcel_initialize(dir, &config);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_auto_checkpoint: initialization failed");
		res = false;
	}
	else
	{
		/* add enough records to trigger auto checkpoint */
		for (i = 0U; i < SMALL_BATCH + 1U; ++i)
		{
			generate_test_data(data, sizeof(data), (uint8_t)i);
			ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_auto_checkpoint: add record failed");
				res = false;
				break;
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_checkpoint_group(void)
{
	udif_mcel_manager* mgr;
	udif_checkpoint_group group = { 0U };
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	size_t i;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: initialization failed");
		res = false;
	}
	else
	{
		/* add to membership */
		for (i = 0U; i < SMALL_BATCH; ++i)
		{
			generate_test_data(data, sizeof(data), (uint8_t)i);
			ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: add to membership failed");
				res = false;
				break;
			}
		}

		if (res == true)
		{
			/* switch and add to transaction */
			ret = udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: switch to transaction failed");
				res = false;
			}
			else
			{
				for (i = 0U; i < SMALL_BATCH; ++i)
				{
					generate_test_data(data, sizeof(data), (uint8_t)(i + 10U));
					ret = udif_mcel_add_record(mgr, data, sizeof(data), false, &seq);

					if (ret == false)
					{
						qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: add to transaction failed");
						res = false;
						break;
					}
				}

				if (res == true)
				{
					/* create checkpoint group */
					ret = udif_mcel_create_checkpoint_group(mgr, &group);

					if (ret == false)
					{
						qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: create checkpoint group failed");
						res = false;
					}
					else if (group.height == 0U)
					{
						qsc_consoleutils_print_line("mcelmanager_test_checkpoint_group: group height should not be zero");
						res = false;
					}
				}
			}
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_readonly_write_fails(void)
{
	udif_mcel_manager* mgr1;
	udif_mcel_manager* mgr2;
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE] = { 0U };
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	/* create initial manager */
	mgr1 = udif_mcel_initialize(dir, NULL);

	if (mgr1 == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_readonly_write_fails: initialization failed");
		res = false;
	}
	else
	{
		/* get verify key */
		ret = udif_mcel_get_keypair(mgr1, NULL, verkey);

		if (ret == false)
		{
			qsc_consoleutils_print_line("mcelmanager_test_readonly_write_fails: get verify key failed");
			res = false;
		}
		else
		{
			udif_mcel_dispose(mgr1);

			/* open readonly */
			mgr2 = udif_mcel_open(dir, true, NULL, verkey);

			if (mgr2 == NULL)
			{
				qsc_consoleutils_print_line("mcelmanager_test_readonly_write_fails: readonly open failed");
				res = false;
			}
			else
			{
				/* attempt write should fail */
				generate_test_data(data, sizeof(data), 1U);
				ret = udif_mcel_add_record(mgr2, data, sizeof(data), false, &seq);

				if (ret == true)
				{
					qsc_consoleutils_print_line("mcelmanager_test_readonly_write_fails: write in readonly mode should fail");
					res = false;
				}

				udif_mcel_dispose(mgr2);
			}
		}
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_read_nonexistent(void)
{
	udif_mcel_manager* mgr;
	uint8_t data[64U] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	size_t bytesread;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_read_nonexistent: initialization failed");
		res = false;
	}
	else
	{
		/* attempt to read nonexistent record */
		ret = udif_mcel_read_record(mgr, 999U, data, sizeof(data), &bytesread);

		if (ret == true)
		{
			qsc_consoleutils_print_line("mcelmanager_test_read_nonexistent: read of nonexistent should fail");
			res = false;
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

static bool mcelmanager_test_large_record(void)
{
	udif_mcel_manager* mgr;
	uint8_t* data;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	size_t datalen;
	uint64_t seq;
	bool ret;
	bool res;

	res = true;

	setup_test_directory(dir);

	mgr = udif_mcel_initialize(dir, NULL);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcelmanager_test_large_record: initialization failed");
		res = false;
	}
	else
	{
		/* allocate large record */
		datalen = 1024U * 64U;  /* 64KB */
		data = (uint8_t*)malloc(datalen);

		if (data == NULL)
		{
			qsc_consoleutils_print_line("mcelmanager_test_large_record: memory allocation failed");
			res = false;
		}
		else
		{
			/* generate and add large record */
			generate_test_data(data, datalen, 123U);
			ret = udif_mcel_add_record(mgr, data, datalen, false, &seq);

			if (ret == false)
			{
				qsc_consoleutils_print_line("mcelmanager_test_large_record: add large record failed");
				res = false;
			}

			free(data);
		}

		udif_mcel_dispose(mgr);
	}

	cleanup_test_directory();

	return res;
}

bool mcelmgr_test_run(void)
{
	bool res;

	res = true;

	if (mcelmanager_test_initialize_default() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL initialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL initialization test has failed.");
		res = false;
	}

	if (mcelmanager_test_initialize_custom() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL custom initialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL custom initialization test has failed.");
		res = false;
	}

	if (mcelmanager_test_open_readonly() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL read only test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL read only test has failed.");
		res = false;
	}

	if (mcelmanager_test_add_single_record() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL add single record test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL add single record test has failed.");
		res = false;
	}

	if (mcelmanager_test_add_batch_records() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL add batch records test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL add batch records test has failed.");
		res = false;
	}

	if (mcelmanager_test_read_records() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL read records test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL read records test has failed.");
		res = false;
	}

	if (mcelmanager_test_add_encrypted() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL add encrypted record test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL add encrypted record test has failed.");
		res = false;
	}

	if (mcelmanager_test_switch_ledgers() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL switch ledgers test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL switch ledgers test has failed.");
		res = false;
	}

	if (mcelmanager_test_get_ledger_size() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL get ledger size test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL get ledger size test has failed.");
		res = false;
	}

	if (mcelmanager_test_concurrent_ledgers() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL concurrent ledgers test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL concurrent ledgers test has failed.");
		res = false;
	}

	if (mcelmanager_test_auto_seal_block() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL auto seal block test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL auto seal block test has failed.");
		res = false;
	}

	if (mcelmanager_test_manual_flush() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL manual flush test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL manual flush test has failed.");
		res = false;
	}

	if (mcelmanager_test_empty_block_flush() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL empty block flush test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL empty block flush test has failed.");
		res = false;
	}

	if (mcelmanager_test_flush_all() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL flush all test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL flush all test has failed.");
		res = false;
	}

	if (mcelmanager_test_manual_checkpoint() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL manual checkpoint test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL manual checkpoint test has failed.");
		res = false;
	}

	if (mcelmanager_test_auto_checkpoint() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL auto checkpoint test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL auto checkpoint test has failed.");
		res = false;
	}

	if (mcelmanager_test_checkpoint_group() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL checkpoint group test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL checkpoint group test has failed.");
		res = false;
	}

	if (mcelmanager_test_readonly_write_fails() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL readonly write fails test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL readonly write fails test has failed.");
		res = false;
	}

	if (mcelmanager_test_read_nonexistent() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL read nonexistent test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL read nonexistent test has failed.");
		res = false;
	}

	if (mcelmanager_test_large_record() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL large record test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL large record test has failed.");
		res = false;
	}

	return res;
}
