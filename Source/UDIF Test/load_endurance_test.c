#include "load_endurance_test.h"

#include "anchor.h"
#include "capability.h"
#include "csp.h"
#include "folderutils.h"
#include "mcelmanager.h"
#include "memutils.h"
#include "object.h"
#include "query.h"
#include "registry.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"
#include "consoleutils.h"

#define LOAD_ENDURANCE_BASE_PATH "UDIF"
#define LOAD_ENDURANCE_DIRECTORY_PREFIX "loadend_"
#define LOAD_ENDURANCE_OBJECT_COUNT 48U
#define LOAD_ENDURANCE_TRANSFER_ROUNDS 24U
#define LOAD_ENDURANCE_QUERY_ROUNDS 96U
#define LOAD_ENDURANCE_ANCHOR_ROUNDS 8U
#define LOAD_ENDURANCE_INIT_DISPOSE_ROUNDS 16U
#define LOAD_ENDURANCE_RECORD_SIZE 64U

static uint64_t m_load_endurance_directory_counter = 0U;

typedef struct load_endurance_metrics
{
	uint64_t objectscreated;
	uint64_t transfers;
	uint64_t registrycommits;
	uint64_t queries;
	uint64_t anchors;
	uint64_t proofs;
	uint64_t initdispose;
	uint64_t objectms;
	uint64_t transferms;
	uint64_t queryms;
	uint64_t anchorms;
	uint64_t proofms;
} load_endurance_metrics;

typedef struct load_endurance_state
{
	udif_registry_state rega;
	udif_registry_state regb;
	udif_object* objects;
	udif_transfer_record* transfers;
	udif_capability capability;
	udif_signature_keypair keya;
	udif_signature_keypair keyb;
	udif_signature_keypair anchorkey;
	uint8_t issuerkey[UDIF_CRYPTO_KEY_SIZE];
	uint8_t issuerser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t subjectser[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t ownera[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t ownerb[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t creator[UDIF_SERIAL_NUMBER_SIZE];
	uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];
	uint8_t regroota[UDIF_CRYPTO_HASH_SIZE];
	uint8_t regrootb[UDIF_CRYPTO_HASH_SIZE];
	uint8_t proof[UDIF_QUERY_MAX_PROOF_SIZE];
	load_endurance_metrics metrics;
} load_endurance_state;

static void load_endurance_print_metric(const char* name, uint64_t value, const char* suffix)
{
	if (name != NULL)
	{
		qsc_consoleutils_print_safe(name);
		qsc_consoleutils_print_safe(": ");
		qsc_consoleutils_print_ulong(value);

		if (suffix != NULL)
		{
			qsc_consoleutils_print_safe(suffix);
		}

		qsc_consoleutils_print_line("");
	}
}

static void load_endurance_fill(uint8_t* output, size_t outlen, uint8_t seed)
{
	size_t i;

	if (output != NULL)
	{
		for (i = 0U; i < outlen; ++i)
		{
			output[i] = (uint8_t)(seed + (uint8_t)i);
		}
	}
}

static bool load_endurance_delete_directory(const char dir[QSC_SYSTEM_MAX_PATH])
{
	bool res;

	res = false;

	if (dir != NULL && qsc_stringutils_string_size(dir) > 0U)
	{
		res = qsc_folderutils_delete_directory(dir);
	}

	return res;
}

static void load_endurance_cleanup_test_directory(void)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dir);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
#endif
	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, sizeof(dir), LOAD_ENDURANCE_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == true)
	{
		load_endurance_delete_directory(dir);
	}
}

static void load_endurance_setup_test_directory(char dir[QSC_SYSTEM_MAX_PATH])
{
	char num[32U] = { 0U };
	uint64_t nonce;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dir);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
#endif
	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, LOAD_ENDURANCE_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == false)
	{
		qsc_folderutils_create_directory_tree(dir);
	}

	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, LOAD_ENDURANCE_DIRECTORY_PREFIX);
	nonce = qsc_timestamp_epochtime_milliseconds() + m_load_endurance_directory_counter;
	++m_load_endurance_directory_counter;
	qsc_stringutils_uint64_to_string(nonce, num, sizeof(num));
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, num);

	if (qsc_folderutils_directory_exists(dir) == true)
	{
		load_endurance_delete_directory(dir);
	}

	qsc_folderutils_create_directory_tree(dir);
}

static void load_endurance_generate_record(uint8_t* data, size_t datalen, uint8_t tag)
{
	size_t i;

	if (data != NULL)
	{
		for (i = 0U; i < datalen; ++i)
		{
			data[i] = (uint8_t)(tag + (uint8_t)i);
		}
	}
}

static bool load_endurance_state_initialize(load_endurance_state* st)
{
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		qsc_memutils_clear((uint8_t*)st, sizeof(load_endurance_state));
		st->objects = (udif_object*)qsc_memutils_malloc(sizeof(udif_object) * LOAD_ENDURANCE_OBJECT_COUNT);
		st->transfers = (udif_transfer_record*)qsc_memutils_malloc(sizeof(udif_transfer_record) * LOAD_ENDURANCE_TRANSFER_ROUNDS);

		if (st->objects != NULL && st->transfers != NULL)
		{
			qsc_memutils_clear((uint8_t*)st->objects, sizeof(udif_object) * LOAD_ENDURANCE_OBJECT_COUNT);
			qsc_memutils_clear((uint8_t*)st->transfers, sizeof(udif_transfer_record) * LOAD_ENDURANCE_TRANSFER_ROUNDS);
			load_endurance_fill(st->issuerser, sizeof(st->issuerser), 0x10U);
			load_endurance_fill(st->subjectser, sizeof(st->subjectser), 0x20U);
			load_endurance_fill(st->ownera, sizeof(st->ownera), 0x30U);
			load_endurance_fill(st->ownerb, sizeof(st->ownerb), 0x40U);
			load_endurance_fill(st->creator, sizeof(st->creator), 0x50U);
			qsc_csp_generate(st->issuerkey, sizeof(st->issuerkey));
			qsc_csp_generate(st->attrroot, sizeof(st->attrroot));
			udif_signature_generate_keypair(st->keya.verkey, st->keya.sigkey, qsc_csp_generate);
			udif_signature_generate_keypair(st->keyb.verkey, st->keyb.sigkey, qsc_csp_generate);
			udif_signature_generate_keypair(st->anchorkey.verkey, st->anchorkey.sigkey, qsc_csp_generate);
			nowsecs = qsc_timestamp_datetime_utc();
			err = udif_registry_initialize(&st->rega, st->ownera, LOAD_ENDURANCE_OBJECT_COUNT + 16U);

			if (err == udif_error_none)
			{
				err = udif_registry_initialize(&st->regb, st->ownerb, LOAD_ENDURANCE_OBJECT_COUNT + 16U);
			}

			if (err == udif_error_none)
			{
				err = udif_capability_create(&st->capability,
					(uint32_t)(UDIF_CAP_QUERY_EXIST | UDIF_CAP_QUERY_OWNER_BINDING | UDIF_CAP_QUERY_ATTR_BUCKET | UDIF_CAP_PROVE_MEMBERSHIP),
					(uint32_t)(1UL << (uint32_t)udif_scope_intra_domain), st->subjectser, st->issuerser, nowsecs + 3600U, 0U, st->issuerkey);
			}

			res = (err == udif_error_none);
		}
	}

	return res;
}

static void load_endurance_state_dispose(load_endurance_state* st)
{
	if (st != NULL)
	{
		udif_registry_dispose(&st->rega);
		udif_registry_dispose(&st->regb);

		if (st->objects != NULL)
		{
			qsc_memutils_clear((uint8_t*)st->objects, sizeof(udif_object) * LOAD_ENDURANCE_OBJECT_COUNT);
			qsc_memutils_alloc_free(st->objects);
			st->objects = NULL;
		}

		if (st->transfers != NULL)
		{
			qsc_memutils_clear((uint8_t*)st->transfers, sizeof(udif_transfer_record) * LOAD_ENDURANCE_TRANSFER_ROUNDS);
			qsc_memutils_alloc_free(st->transfers);
			st->transfers = NULL;
		}
	}
}

static bool load_endurance_object_registry_phase(load_endurance_state* st)
{
	uint8_t serial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint64_t start;
	uint64_t nowsecs;
	size_t i;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		start = qsc_timerex_stopwatch_start();
		nowsecs = qsc_timestamp_datetime_utc();
		err = udif_error_none;

		for (i = 0U; i < LOAD_ENDURANCE_OBJECT_COUNT && err == udif_error_none; ++i)
		{
			load_endurance_fill(serial, sizeof(serial), (uint8_t)(0x80U + (uint8_t)i));
			err = udif_object_create(&st->objects[i], serial, 1U, st->creator, st->attrroot, st->ownera, st->keya.sigkey, nowsecs + (uint64_t)i, qsc_csp_generate);

			if (err == udif_error_none)
			{
				err = udif_registry_add_object(&st->rega, &st->objects[i]);
			}

			if (err == udif_error_none)
			{
				err = udif_registry_compute_root(st->regroota, &st->rega);
				++st->metrics.objectscreated;
				++st->metrics.registrycommits;
			}
		}

		st->metrics.objectms = qsc_timerex_stopwatch_elapsed(start);
		res = (err == udif_error_none && st->metrics.objectscreated == LOAD_ENDURANCE_OBJECT_COUNT &&
			udif_registry_get_count(&st->rega) == LOAD_ENDURANCE_OBJECT_COUNT);
	}

	return res;
}

static bool load_endurance_transfer_phase(load_endurance_state* st)
{
	uint64_t start;
	uint64_t nowsecs;
	size_t i;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		start = qsc_timerex_stopwatch_start();
		nowsecs = qsc_timestamp_datetime_utc() + 1000U;
		err = udif_error_none;

		for (i = 0U; i < LOAD_ENDURANCE_TRANSFER_ROUNDS && err == udif_error_none; ++i)
		{
			err = udif_object_transfer(&st->objects[i], &st->transfers[i], st->ownerb, st->keya.sigkey, st->keyb.sigkey,
				nowsecs + (uint64_t)i, qsc_csp_generate);

			if (err == udif_error_none && udif_transfer_verify(&st->transfers[i], st->keya.verkey, st->keyb.verkey) == false)
			{
				err = udif_error_signature_invalid;
			}

			if (err == udif_error_none)
			{
				err = udif_registry_transfer_object(&st->rega, &st->regb, &st->transfers[i]);
			}

			if (err == udif_error_none)
			{
				err = udif_registry_compute_root(st->regroota, &st->rega);
			}

			if (err == udif_error_none)
			{
				err = udif_registry_compute_root(st->regrootb, &st->regb);
				++st->metrics.transfers;
				st->metrics.registrycommits += 2U;
			}
		}

		st->metrics.transferms = qsc_timerex_stopwatch_elapsed(start);
		res = (err == udif_error_none && st->metrics.transfers == LOAD_ENDURANCE_TRANSFER_ROUNDS &&
			udif_registry_get_count(&st->regb) == LOAD_ENDURANCE_TRANSFER_ROUNDS);
	}

	return res;
}

static bool load_endurance_query_phase(load_endurance_state* st)
{
	udif_query query;
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t verdict;
	uint64_t start;
	size_t prooflen;
	size_t i;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		start = qsc_timerex_stopwatch_start();
		err = udif_error_none;

		for (i = 0U; i < LOAD_ENDURANCE_QUERY_ROUNDS && err == udif_error_none; ++i)
		{
			qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
			load_endurance_fill(queryid, sizeof(queryid), (uint8_t)(0x20U + (uint8_t)i));
			err = udif_query_create_existence(&query, queryid, st->ownera, st->objects[i % LOAD_ENDURANCE_OBJECT_COUNT].serial,
				qsc_timestamp_datetime_utc(), st->capability.digest);

			if (err == udif_error_none)
			{
				verdict = (uint8_t)udif_verdict_deny;
				prooflen = sizeof(st->proof);
				err = udif_query_evaluate_registry(&verdict, st->proof, &prooflen, &query, &st->rega, &st->capability,
					st->subjectser, qsc_timestamp_datetime_utc());
			}

			if (err == udif_error_none)
			{
				++st->metrics.queries;
			}

			udif_query_clear(&query);
		}

		st->metrics.queryms = qsc_timerex_stopwatch_elapsed(start);
		res = (err == udif_error_none && st->metrics.queries == LOAD_ENDURANCE_QUERY_ROUNDS);
	}

	return res;
}

static bool load_endurance_proof_phase(load_endurance_state* st)
{
	udif_registry_leaf leaf;
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t start;
	size_t prooflen;
	size_t i;
	udif_errors err;
	bool res;

	res = false;

	if (st != NULL)
	{
		start = qsc_timerex_stopwatch_start();
		err = udif_error_none;

		for (i = 0U; i < LOAD_ENDURANCE_TRANSFER_ROUNDS && err == udif_error_none; ++i)
		{
			qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
			prooflen = sizeof(st->proof);
			err = udif_registry_generate_proof(st->proof, &prooflen, &st->regb, st->objects[i].serial);

			if (err == udif_error_none)
			{
				err = udif_registry_get_leaf(&leaf, &st->regb, st->objects[i].serial);
			}

			if (err == udif_error_none)
			{
				err = udif_registry_leaf_digest(digest, &leaf);
			}

			if (err == udif_error_none && udif_registry_verify_proof(st->proof, prooflen, st->regrootb, digest) == false)
			{
				err = udif_error_auth_failure;
			}

			if (err == udif_error_none)
			{
				++st->metrics.proofs;
			}
		}

		st->metrics.proofms = qsc_timerex_stopwatch_elapsed(start);
		res = (err == udif_error_none && st->metrics.proofs == LOAD_ENDURANCE_TRANSFER_ROUNDS);
	}

	qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
	qsc_memutils_clear(digest, sizeof(digest));

	return res;
}

static bool load_endurance_anchor_phase(load_endurance_state* st)
{
	udif_checkpoint_config config = { 0U };
	udif_checkpoint_group group = { 0U };
	udif_anchor_record anchor = { 0U };
	udif_mcel_manager* mgr;
	uint8_t data[LOAD_ENDURANCE_RECORD_SIZE] = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t seq;
	uint64_t start;
	size_t i;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool res;

	res = false;
	mgr = NULL;

	if (st != NULL)
	{
		load_endurance_setup_test_directory(dir);
		config.blocksize = 4U;
		config.autocheckpointenabled = false;
		mgr = udif_mcel_initialize(dir, &config);

		if (mgr != NULL)
		{
			start = qsc_timerex_stopwatch_start();
			res = true;
			load_endurance_fill(childser, sizeof(childser), 0x60U);

			for (i = 0U; i < LOAD_ENDURANCE_ANCHOR_ROUNDS && res == true; ++i)
			{
				load_endurance_generate_record(data, sizeof(data), (uint8_t)i);
				res = (udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_MEMBERSHIP) == true &&
					udif_mcel_add_record(mgr, data, sizeof(data), false, &seq) == true);
				load_endurance_generate_record(data, sizeof(data), (uint8_t)(i + 16U));
				res = (res == true && udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION) == true &&
					udif_mcel_add_record(mgr, data, sizeof(data), false, &seq) == true);
				load_endurance_generate_record(data, sizeof(data), (uint8_t)(i + 32U));
				res = (res == true && udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_REGISTRY) == true &&
					udif_mcel_add_record(mgr, data, sizeof(data), false, &seq) == true);
				res = (res == true && udif_mcel_create_checkpoint_group(mgr, &group) == true);

				if (res == true)
				{
					res = (udif_mcel_create_anchor(mgr, &anchor, childser, i, st->anchorkey.sigkey, qsc_csp_generate) == true &&
						udif_anchor_verify(&anchor, st->anchorkey.verkey, i) == true);
				}

				if (res == true)
				{
					++st->metrics.anchors;
				}
			}

			st->metrics.anchorms = qsc_timerex_stopwatch_elapsed(start);
			res = (res == true && st->metrics.anchors == LOAD_ENDURANCE_ANCHOR_ROUNDS);
		}

		udif_mcel_dispose(mgr);
		load_endurance_delete_directory(dir);
	}

	qsc_memutils_clear(data, sizeof(data));
	qsc_memutils_clear(childser, sizeof(childser));

	return res;
}

static bool load_endurance_init_dispose_phase(load_endurance_state* st)
{
	udif_registry_state reg;
	uint8_t owner[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	size_t i;
	bool res;

	res = true;
	load_endurance_fill(owner, sizeof(owner), 0xA0U);

	for (i = 0U; i < LOAD_ENDURANCE_INIT_DISPOSE_ROUNDS && res == true; ++i)
	{
		qsc_memutils_clear((uint8_t*)&reg, sizeof(udif_registry_state));
		res = (udif_registry_initialize(&reg, owner, 8U) == udif_error_none);
		udif_registry_dispose(&reg);

		if (res == true && st != NULL)
		{
			++st->metrics.initdispose;
		}
	}

	qsc_memutils_clear(owner, sizeof(owner));

	return res;
}

static void load_endurance_print_report(const load_endurance_metrics* metrics)
{
	if (metrics != NULL)
	{
		qsc_consoleutils_print_line("Load/endurance metrics:");
		load_endurance_print_metric("  objects created", metrics->objectscreated, "");
		load_endurance_print_metric("  object phase ms", metrics->objectms, "");
		load_endurance_print_metric("  transfers", metrics->transfers, "");
		load_endurance_print_metric("  transfer phase ms", metrics->transferms, "");
		load_endurance_print_metric("  registry commits", metrics->registrycommits, "");
		load_endurance_print_metric("  queries", metrics->queries, "");
		load_endurance_print_metric("  query phase ms", metrics->queryms, "");
		load_endurance_print_metric("  membership proofs", metrics->proofs, "");
		load_endurance_print_metric("  proof phase ms", metrics->proofms, "");
		load_endurance_print_metric("  anchors", metrics->anchors, "");
		load_endurance_print_metric("  anchor phase ms", metrics->anchorms, "");
		load_endurance_print_metric("  init/dispose cycles", metrics->initdispose, "");
	}
}

bool load_endurance_test_run(void)
{
	load_endurance_state* st;
	bool res;

	res = false;
	st = (load_endurance_state*)qsc_memutils_malloc(sizeof(load_endurance_state));

	if (st == NULL)
	{
		qsc_consoleutils_print_line("Failure! Load/endurance test state allocation failed.");
	}
	else
	{
		res = load_endurance_state_initialize(st);

		if (res == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance state initialization failed.");
		}
		else if (load_endurance_object_registry_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance object registry phase failed.");
			res = false;
		}
		else if (load_endurance_transfer_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance transfer phase failed.");
			res = false;
		}
		else if (load_endurance_query_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance query phase failed.");
			res = false;
		}
		else if (load_endurance_proof_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance proof phase failed.");
			res = false;
		}
		else if (load_endurance_anchor_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance anchor phase failed.");
			res = false;
		}
		else if (load_endurance_init_dispose_phase(st) == false)
		{
			qsc_consoleutils_print_line("Failure! Load/endurance initialize/dispose phase failed.");
			res = false;
		}
		else
		{
			res = true;
		}

		if (res == true)
		{
			load_endurance_print_report(&st->metrics);
			qsc_consoleutils_print_line("Success! Load and endurance tests have passed.");
		}

		load_endurance_state_dispose(st);
		qsc_memutils_clear((uint8_t*)st, sizeof(load_endurance_state));
		qsc_memutils_alloc_free(st);
	}

	load_endurance_cleanup_test_directory();

	return res;
}
