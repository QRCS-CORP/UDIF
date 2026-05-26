#include "mcel_hierarchy_test.h"

#include "anchor.h"
#include "csp.h"
#include "folderutils.h"
#include "mcelmanager.h"
#include "memutils.h"
#include "consoleutils.h"
#include "stringutils.h"
#include "timestamp.h"

#define MCEL_HIER_TEST_BASE_PATH "UDIF"
#define MCEL_HIER_TEST_DIRECTORY_PREFIX "mcelhier_"
#define MCEL_HIER_TEST_RECORD_SIZE 64U

static uint64_t m_mcel_hierarchy_test_directory_counter = 0U;

typedef struct mcel_hierarchy_parent_state
{
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE];
	uint64_t nextseq;
} mcel_hierarchy_parent_state;

static bool mcel_hierarchy_delete_directory(const char dir[QSC_SYSTEM_MAX_PATH])
{
	bool res;

	res = false;

	if (dir != NULL && qsc_stringutils_string_size(dir) > 0U)
	{
		res = qsc_folderutils_delete_directory(dir);
	}

	return res;
}

static void mcel_hierarchy_cleanup_test_directory(void)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dir);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
#endif
	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, sizeof(dir), MCEL_HIER_TEST_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == true)
	{
		mcel_hierarchy_delete_directory(dir);
	}
}

static void mcel_hierarchy_setup_test_directory(char dir[QSC_SYSTEM_MAX_PATH])
{
	char num[32U] = { 0U };
	uint64_t nonce;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dir);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
#endif
	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, MCEL_HIER_TEST_BASE_PATH);

	if (qsc_folderutils_directory_exists(dir) == false)
	{
		qsc_folderutils_create_directory_tree(dir);
	}

	qsc_folderutils_append_delimiter(dir);
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, MCEL_HIER_TEST_DIRECTORY_PREFIX);
	nonce = qsc_timestamp_epochtime_milliseconds() + m_mcel_hierarchy_test_directory_counter;
	++m_mcel_hierarchy_test_directory_counter;
	qsc_stringutils_uint64_to_string(nonce, num, sizeof(num));
	qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, num);

	if (qsc_folderutils_directory_exists(dir) == true)
	{
		mcel_hierarchy_delete_directory(dir);
	}

	qsc_folderutils_create_directory_tree(dir);
}

static void mcel_hierarchy_generate_record(uint8_t* data, size_t datalen, uint8_t tag)
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

static bool mcel_hierarchy_add_record(udif_mcel_manager* mgr, udif_ledger_type ledger, uint8_t tag, uint64_t expseq)
{
	uint8_t data[MCEL_HIER_TEST_RECORD_SIZE] = { 0U };
	uint64_t seq;
	bool res;

	res = false;

	mcel_hierarchy_generate_record(data, sizeof(data), tag);

	if (udif_mcel_set_active_ledger(mgr, ledger) == true)
	{
		if (udif_mcel_add_record(mgr, data, sizeof(data), false, &seq) == true)
		{
			res = (seq == expseq);
		}
	}

	return res;
}

static bool mcel_hierarchy_root_nonzero(const uint8_t* root)
{
	bool res;

	res = false;

	if (root != NULL)
	{
		res = (qsc_memutils_zeroed(root, UDIF_CRYPTO_HASH_SIZE) == false);
	}

	return res;
}

static bool mcel_hierarchy_parent_accept(mcel_hierarchy_parent_state* state, const udif_anchor_record* anchor,
	const uint8_t* childverkey, uint64_t nowsecs, uint64_t maxage)
{
	bool res;

	res = false;

	if (state != NULL && anchor != NULL && childverkey != NULL)
	{
		if (qsc_memutils_are_equal(state->childser, anchor->childser, UDIF_SERIAL_NUMBER_SIZE) == true)
		{
			if (udif_anchor_is_fresh(anchor, nowsecs, maxage) == true)
			{
				if (udif_anchor_verify(anchor, childverkey, state->nextseq) == true)
				{
					++state->nextseq;
					res = true;
				}
			}
		}
	}

	return res;
}

static bool mcel_hierarchy_checkpoint_and_anchor_test(void)
{
	udif_checkpoint_config config = { 0U };
	udif_checkpoint_group group = { 0U };
	udif_mcel_manager* mgr;
	udif_signature_keypair kp = { 0U };
	udif_anchor_record anchor = { 0U };
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t count;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool res;

	res = true;
	mgr = NULL;
	count = 0U;

	mcel_hierarchy_setup_test_directory(dir);
	config.membinterval = 0U;
	config.transinterval = 0U;
	config.reginterval = 0U;
	config.blocksize = 4U;
	config.autocheckpointenabled = false;
	mgr = udif_mcel_initialize(dir, &config);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: manager initialization failed");
		res = false;
	}
	else
	{
		if (mcel_hierarchy_add_record(mgr, UDIF_LEDGER_MEMBERSHIP, 1U, 0U) == false ||
			mcel_hierarchy_add_record(mgr, UDIF_LEDGER_TRANSACTION, 2U, 0U) == false ||
			mcel_hierarchy_add_record(mgr, UDIF_LEDGER_REGISTRY, 3U, 0U) == false)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: record insertion failed");
			res = false;
		}
		else if (udif_mcel_get_ledger_size(mgr, &count) == false || count != 1U)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: registry count mismatch");
			res = false;
		}
		else if (udif_mcel_create_checkpoint_group(mgr, &group) == false)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: checkpoint group creation failed");
			res = false;
		}
		else if (group.membershipseq != 0U || group.transactionseq != 0U || group.registryseq != 0U || group.height != 1U)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: checkpoint sequence or height mismatch");
			res = false;
		}
		else if (mcel_hierarchy_root_nonzero(group.membcommit) == false ||
			mcel_hierarchy_root_nonzero(group.transcommit) == false ||
			mcel_hierarchy_root_nonzero(group.regcommit) == false)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: checkpoint commitment is zero");
			res = false;
		}
		else
		{
			qsc_csp_generate(childser, sizeof(childser));
			udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

			if (udif_mcel_create_anchor(mgr, &anchor, childser, 0U, kp.sigkey, qsc_csp_generate) == false)
			{
				qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: anchor creation failed");
				res = false;
			}
			else if (anchor.sequence != 0U || anchor.memcount != 1U || anchor.txcount != 1U || anchor.regcount != 1U)
			{
				qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: anchor metadata mismatch");
				res = false;
			}
			else if (udif_anchor_verify(&anchor, kp.verkey, 0U) == false)
			{
				qsc_consoleutils_print_line("mcel_hierarchy_checkpoint_and_anchor_test: anchor signature verification failed");
				res = false;
			}
		}
	}

	if (mgr != NULL)
	{
		udif_mcel_dispose(mgr);
	}

	udif_anchor_clear(&anchor);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(kp));
	mcel_hierarchy_cleanup_test_directory();

	return res;
}

static bool mcel_hierarchy_auto_checkpoint_test(void)
{
	udif_checkpoint_config config = { 0U };
	udif_mcel_manager* mgr;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0U };
	bool res;

	res = true;
	mgr = NULL;

	mcel_hierarchy_setup_test_directory(dir);
	config.membinterval = 2U;
	config.transinterval = 2U;
	config.reginterval = 2U;
	config.blocksize = 4U;
	config.autocheckpointenabled = true;
	mgr = udif_mcel_initialize(dir, &config);

	if (mgr == NULL)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_auto_checkpoint_test: manager initialization failed");
		res = false;
	}
	else if (mcel_hierarchy_add_record(mgr, UDIF_LEDGER_MEMBERSHIP, 9U, 0U) == false ||
		mcel_hierarchy_add_record(mgr, UDIF_LEDGER_MEMBERSHIP, 10U, 1U) == false)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_auto_checkpoint_test: automatic checkpoint input records failed");
		res = false;
	}
	else if (mgr->membership->totalcheckpoints == 0U)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_auto_checkpoint_test: automatic checkpoint was not created");
		res = false;
	}

	if (mgr != NULL)
	{
		udif_mcel_dispose(mgr);
	}

	mcel_hierarchy_cleanup_test_directory();

	return res;
}

static bool mcel_hierarchy_parent_chain_test(void)
{
	udif_signature_keypair kp = { 0U };
	udif_anchor_record anchor0 = { 0U };
	udif_anchor_record anchor1 = { 0U };
	udif_anchor_record fork0 = { 0U };
	mcel_hierarchy_parent_state branchparent = { 0U };
	mcel_hierarchy_parent_state rootparent = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t nowsecs;
	bool res;

	res = true;
	nowsecs = qsc_timestamp_datetime_utc();

	qsc_csp_generate(branchparent.childser, sizeof(branchparent.childser));
	qsc_memutils_copy(rootparent.childser, branchparent.childser, sizeof(rootparent.childser));
	branchparent.nextseq = 0U;
	rootparent.nextseq = 0U;
	qsc_csp_generate(regroot, sizeof(regroot));
	qsc_csp_generate(txroot, sizeof(txroot));
	qsc_csp_generate(mroot, sizeof(mroot));
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	if (udif_anchor_create(&anchor0, branchparent.childser, 0U, nowsecs, regroot, txroot, mroot, 1U, 1U, 1U, kp.sigkey, qsc_csp_generate) != udif_error_none ||
		udif_anchor_create(&anchor1, branchparent.childser, 1U, nowsecs + 1U, regroot, txroot, mroot, 2U, 2U, 2U, kp.sigkey, qsc_csp_generate) != udif_error_none ||
		udif_anchor_create(&fork0, branchparent.childser, 0U, nowsecs + 2U, mroot, regroot, txroot, 3U, 3U, 3U, kp.sigkey, qsc_csp_generate) != udif_error_none)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: anchor creation failed");
		res = false;
	}
	else if (mcel_hierarchy_parent_accept(&branchparent, &anchor0, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == false)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: parent rejected genesis anchor");
		res = false;
	}
	else if (mcel_hierarchy_parent_accept(&branchparent, &anchor0, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == true)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: duplicate sequence accepted");
		res = false;
	}
	else if (mcel_hierarchy_parent_accept(&branchparent, &fork0, kp.verkey, nowsecs + 2U, UDIF_ANCHOR_MAX_AGE_MAX) == true)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: forked anchor sequence accepted");
		res = false;
	}
	else if (mcel_hierarchy_parent_accept(&branchparent, &anchor1, kp.verkey, nowsecs + 1U, UDIF_ANCHOR_MAX_AGE_MAX) == false)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: exact next sequence rejected");
		res = false;
	}
	else if (mcel_hierarchy_parent_accept(&rootparent, &anchor0, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == false)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: root-level verifier rejected branch genesis anchor");
		res = false;
	}
	else if (udif_anchor_verify_chain(&anchor0, &anchor1, kp.verkey) == false)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_parent_chain_test: anchor chain traversal failed");
		res = false;
	}

	udif_anchor_clear(&anchor0);
	udif_anchor_clear(&anchor1);
	udif_anchor_clear(&fork0);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(kp));

	return res;
}

static bool mcel_hierarchy_anchor_attack_test(void)
{
	udif_signature_keypair kp = { 0U };
	udif_signature_keypair wrongkp = { 0U };
	udif_anchor_record base = { 0U };
	udif_anchor_record cmp = { 0U };
	mcel_hierarchy_parent_state parent = { 0U };
	uint8_t regroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t txroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t mroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t wrongchild[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t nowsecs;
	bool res;

	res = true;
	nowsecs = qsc_timestamp_datetime_utc();

	qsc_csp_generate(parent.childser, sizeof(parent.childser));
	qsc_csp_generate(wrongchild, sizeof(wrongchild));
	qsc_csp_generate(regroot, sizeof(regroot));
	qsc_csp_generate(txroot, sizeof(txroot));
	qsc_csp_generate(mroot, sizeof(mroot));
	parent.nextseq = 0U;
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(wrongkp.verkey, wrongkp.sigkey, qsc_csp_generate);

	if (udif_anchor_create(&base, parent.childser, 0U, nowsecs, regroot, txroot, mroot, 1U, 1U, 1U, kp.sigkey, qsc_csp_generate) != udif_error_none)
	{
		qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: base anchor creation failed");
		res = false;
	}
	else
	{
		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.txroot[0U] ^= 0x01U;

		if (udif_anchor_verify(&cmp, kp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: substituted txroot accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.mroot[0U] ^= 0x01U;

		if (udif_anchor_verify(&cmp, kp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: substituted mroot accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.regroot[0U] ^= 0x01U;

		if (udif_anchor_verify(&cmp, kp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: substituted regroot accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.signature[0U] ^= 0x01U;

		if (udif_anchor_verify(&cmp, kp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: bad signature accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		qsc_memutils_copy(cmp.childser, wrongchild, sizeof(cmp.childser));

		if (udif_anchor_verify(&cmp, kp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: mutated child serial accepted by signature verifier");
			res = false;
		}

		if (udif_anchor_verify(&base, wrongkp.verkey, 0U) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: wrong verification key accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.sequence = 2U;

		if (mcel_hierarchy_parent_accept(&parent, &cmp, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: skipped sequence accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.timestamp = nowsecs - UDIF_ANCHOR_MAX_AGE_MAX - 1U;
		udif_anchor_compute_signature(&cmp, kp.sigkey, qsc_csp_generate);

		if (mcel_hierarchy_parent_accept(&parent, &cmp, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: stale timestamp accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		cmp.timestamp = nowsecs + 60U;
		udif_anchor_compute_signature(&cmp, kp.sigkey, qsc_csp_generate);

		if (mcel_hierarchy_parent_accept(&parent, &cmp, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: future anchor accepted");
			res = false;
		}

		qsc_memutils_copy((uint8_t*)&cmp, (const uint8_t*)&base, sizeof(cmp));
		qsc_memutils_copy(cmp.childser, wrongchild, sizeof(cmp.childser));
		udif_anchor_compute_signature(&cmp, kp.sigkey, qsc_csp_generate);

		if (mcel_hierarchy_parent_accept(&parent, &cmp, kp.verkey, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == true)
		{
			qsc_consoleutils_print_line("mcel_hierarchy_anchor_attack_test: wrong tunnel peer child serial accepted");
			res = false;
		}
	}

	udif_anchor_clear(&base);
	udif_anchor_clear(&cmp);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(kp));
	qsc_memutils_clear((uint8_t*)&wrongkp, sizeof(wrongkp));

	return res;
}

bool mcel_hierarchy_test_run(void)
{
	bool res;

	res = true;

	if (mcel_hierarchy_checkpoint_and_anchor_test() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL hierarchy checkpoint and anchor test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL hierarchy checkpoint and anchor test has failed.");
		res = false;
	}

	if (mcel_hierarchy_auto_checkpoint_test() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL hierarchy automatic checkpoint test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL hierarchy automatic checkpoint test has failed.");
		res = false;
	}

	if (mcel_hierarchy_parent_chain_test() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL hierarchy parent chain test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL hierarchy parent chain test has failed.");
		res = false;
	}

	if (mcel_hierarchy_anchor_attack_test() == true)
	{
		qsc_consoleutils_print_line("Success! MCEL hierarchy anchor attack test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! MCEL hierarchy anchor attack test has failed.");
		res = false;
	}

	return res;
}
