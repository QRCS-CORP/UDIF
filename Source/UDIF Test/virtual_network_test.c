#include "virtual_network_test.h"

#include "anchor.h"
#include "capability.h"
#include "certificate.h"
#include "certstore.h"
#include "entity.h"
#include "udif.h"
#include "consoleutils.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

typedef struct virtual_network_node
{
	udif_certificate cert;
	udif_signature_keypair keypair;
} virtual_network_node;

typedef struct virtual_network_domain
{
	virtual_network_node root;
	virtual_network_node branch;
	virtual_network_node group;
	virtual_network_node ua1;
	virtual_network_node ua2;
	udif_certstore store;
} virtual_network_domain;

typedef struct virtual_network_state
{
	virtual_network_domain domaina;
	virtual_network_domain domainb;
} virtual_network_state;

static uint64_t virtual_network_branch_capabilities(void)
{
	return (UDIF_BC_CAPABILITIES | UDIF_GC_CAPABILITIES | UDIF_CLIENT_CAPABILITIES);
}

static uint64_t virtual_network_group_capabilities(void)
{
	return (UDIF_GC_CAPABILITIES | UDIF_CLIENT_CAPABILITIES);
}

static void virtual_network_clear_node(virtual_network_node* node)
{
	if (node != NULL)
	{
		udif_certificate_clear(&node->cert);
		qsc_memutils_clear((uint8_t*)&node->keypair, sizeof(udif_signature_keypair));
	}
}


static void virtual_network_dispose_domain(virtual_network_domain* domain)
{
	if (domain != NULL)
	{
		udif_certstore_clear(&domain->store);
		virtual_network_clear_node(&domain->root);
		virtual_network_clear_node(&domain->branch);
		virtual_network_clear_node(&domain->group);
		virtual_network_clear_node(&domain->ua1);
		virtual_network_clear_node(&domain->ua2);
		qsc_memutils_clear((uint8_t*)domain, sizeof(virtual_network_domain));
	}
}

static void virtual_network_dispose(virtual_network_state* state)
{
	if (state != NULL)
	{
		udif_certstore_clear(&state->domaina.store);
		udif_certstore_clear(&state->domainb.store);
		virtual_network_clear_node(&state->domaina.root);
		virtual_network_clear_node(&state->domaina.branch);
		virtual_network_clear_node(&state->domaina.group);
		virtual_network_clear_node(&state->domaina.ua1);
		virtual_network_clear_node(&state->domaina.ua2);
		virtual_network_clear_node(&state->domainb.root);
		virtual_network_clear_node(&state->domainb.branch);
		virtual_network_clear_node(&state->domainb.group);
		virtual_network_clear_node(&state->domainb.ua1);
		virtual_network_clear_node(&state->domainb.ua2);
		qsc_memutils_clear((uint8_t*)state, sizeof(virtual_network_state));
	}
}

static udif_errors virtual_network_create_root(virtual_network_node* node, udif_certstore* store, uint64_t nowsecs)
{
	udif_valid_time vt;
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;

	vt.from = nowsecs;
	vt.to = nowsecs + UDIF_CERTIFICATE_DEFAULT_PERIOD;
	qsc_csp_generate(serial, sizeof(serial));

	err = udif_certificate_root_generate(&node->cert, &node->keypair, serial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		node->cert.capability = UDIF_CAP_CORE_DEFINED_MASK;
		err = udif_certificate_sign(&node->cert, node->keypair.sigkey, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &node->cert, udif_certstore_status_active, nowsecs);
	}

	return err;
}

static udif_errors virtual_network_issue_child_raw(virtual_network_node* child, const virtual_network_node* parent,
	udif_roles role, uint64_t capability, uint64_t policy, uint64_t nowsecs)
{
	udif_certificate_csr csr = { 0U };
	udif_valid_time vt;
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;

	vt.from = nowsecs;
	vt.to = nowsecs + (UDIF_CERTIFICATE_DEFAULT_PERIOD / 2U);
	qsc_csp_generate(serial, sizeof(serial));
	qsc_memutils_clear((uint8_t*)child, sizeof(virtual_network_node));
	udif_signature_generate_keypair(child->keypair.verkey, child->keypair.sigkey, qsc_csp_generate);

	err = udif_certificate_csr_create(&csr, serial, child->keypair.verkey, child->keypair.sigkey,
		role, &vt, capability, policy, nowsecs, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_issue(&child->cert, &csr, &parent->cert, parent->keypair.sigkey, nowsecs, qsc_csp_generate);
	}

	return err;
}

static udif_errors virtual_network_issue_child(virtual_network_node* child, virtual_network_domain* domain, const virtual_network_node* parent,
	udif_roles role, uint64_t capability, uint64_t policy, uint64_t nowsecs)
{
	udif_errors err;

	err = virtual_network_issue_child_raw(child, parent, role, capability, policy, nowsecs);

	if (err == udif_error_none)
	{
		err = udif_certstore_add(&domain->store, &child->cert, udif_certstore_status_active, nowsecs);
	}

	return err;
}

static bool virtual_network_initialize_domain(virtual_network_domain* domain, uint64_t nowsecs)
{
	udif_errors err;
	bool res;

	res = false;
	udif_certstore_initialize(&domain->store);

	err = virtual_network_create_root(&domain->root, &domain->store, nowsecs);

	if (err == udif_error_none)
	{
		err = virtual_network_issue_child(&domain->branch, domain, &domain->root, udif_role_ubc,
			virtual_network_branch_capabilities(), UDIF_BC_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = virtual_network_issue_child(&domain->group, domain, &domain->branch, udif_role_ugc,
			virtual_network_group_capabilities(), UDIF_GC_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = virtual_network_issue_child(&domain->ua1, domain, &domain->group, udif_role_client,
			UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = virtual_network_issue_child(&domain->ua2, domain, &domain->group, udif_role_client,
			UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		res = (udif_certificate_verify_chain(&domain->branch.cert, &domain->root.cert) == true &&
			udif_certificate_verify_chain(&domain->group.cert, &domain->branch.cert) == true &&
			udif_certificate_verify_chain(&domain->ua1.cert, &domain->group.cert) == true &&
			udif_certificate_verify_chain(&domain->ua2.cert, &domain->group.cert) == true &&
			udif_certstore_verify_certificate(&domain->store, domain->ua1.cert.serial, nowsecs) == udif_error_none &&
			udif_certstore_verify_certificate(&domain->store, domain->ua2.cert.serial, nowsecs) == udif_error_none);
	}

	return res;
}

static bool virtual_network_topology_initialize_test(void)
{
	virtual_network_state* state;
	uint64_t nowsecs;
	bool res;

	res = false;
	state = (virtual_network_state*)qsc_memutils_malloc(sizeof(virtual_network_state));

	if (state != NULL)
	{
		qsc_memutils_clear((uint8_t*)state, sizeof(virtual_network_state));
		nowsecs = qsc_timestamp_datetime_utc();
		res = (virtual_network_initialize_domain(&state->domaina, nowsecs) == true &&
			virtual_network_initialize_domain(&state->domainb, nowsecs) == true);

		virtual_network_dispose(state);
		qsc_memutils_alloc_free(state);
	}

	return res;
}

static bool virtual_network_negative_csr_tests(void)
{
	virtual_network_domain* domain;
	virtual_network_node* child;
	udif_certificate_csr* csr;
	udif_valid_time vt;
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	domain = (virtual_network_domain*)qsc_memutils_malloc(sizeof(virtual_network_domain));
	child = (virtual_network_node*)qsc_memutils_malloc(sizeof(virtual_network_node));
	csr = (udif_certificate_csr*)qsc_memutils_malloc(sizeof(udif_certificate_csr));

	if (domain != NULL && child != NULL && csr != NULL)
	{
		qsc_memutils_clear((uint8_t*)domain, sizeof(virtual_network_domain));
		qsc_memutils_clear((uint8_t*)child, sizeof(virtual_network_node));
		qsc_memutils_clear((uint8_t*)csr, sizeof(udif_certificate_csr));
		udif_signature_generate_keypair(child->keypair.verkey, child->keypair.sigkey, qsc_csp_generate);
		nowsecs = qsc_timestamp_datetime_utc();
		vt.from = nowsecs;
		vt.to = nowsecs + (UDIF_CERTIFICATE_DEFAULT_PERIOD / 2U);
		qsc_csp_generate(serial, sizeof(serial));

		if (virtual_network_initialize_domain(domain, nowsecs) == true)
		{
			err = udif_certificate_csr_create(csr, serial, child->keypair.verkey, child->keypair.sigkey,
				udif_role_client, &vt, UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs, qsc_csp_generate);

			if (err == udif_error_none)
			{
				csr->suiteid ^= 0xFFU;
				err = udif_certificate_csr_issue(&child->cert, csr, &domain->group.cert, domain->group.keypair.sigkey, nowsecs, qsc_csp_generate);
				res = (err == udif_error_suite_mismatch);
			}

			if (res == true)
			{
				qsc_csp_generate(serial, sizeof(serial));
				err = udif_certificate_csr_create(csr, serial, child->keypair.verkey, child->keypair.sigkey,
					udif_role_ubc, &vt, UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs, qsc_csp_generate);

				if (err == udif_error_none)
				{
					err = udif_certificate_csr_issue(&child->cert, csr, &domain->group.cert, domain->group.keypair.sigkey, nowsecs, qsc_csp_generate);
					res = (err == udif_error_not_authorized);
				}
				else
				{
					res = false;
				}
			}

			if (res == true)
			{
				qsc_csp_generate(serial, sizeof(serial));
				err = udif_certificate_csr_create(csr, serial, child->keypair.verkey, child->keypair.sigkey,
					udif_role_client, &vt, (UDIF_CLIENT_CAPABILITIES | UDIF_CAP_TREATY_NEGOTIATE),
					UDIF_CLIENT_POLICY_DEFAULT, nowsecs, qsc_csp_generate);

				if (err == udif_error_none)
				{
					err = udif_certificate_csr_issue(&child->cert, csr, &domain->group.cert, domain->group.keypair.sigkey, nowsecs, qsc_csp_generate);
					res = (err == udif_error_not_authorized);
				}
				else
				{
					res = false;
				}
			}

			if (res == true)
			{
				qsc_csp_generate(serial, sizeof(serial));
				err = udif_certificate_csr_create(csr, serial, child->keypair.verkey, child->keypair.sigkey,
					udif_role_client, &vt, UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT,
					nowsecs - (UDIF_TIME_WINDOW_SECONDS + 2U), qsc_csp_generate);

				if (err == udif_error_none)
				{
					err = udif_certificate_csr_issue(&child->cert, csr, &domain->group.cert, domain->group.keypair.sigkey, nowsecs, qsc_csp_generate);
					res = (err == udif_error_time_window);
				}
				else
				{
					res = false;
				}
			}

			if (res == true)
			{
				qsc_csp_generate(serial, sizeof(serial));
				err = udif_certificate_csr_create(csr, serial, child->keypair.verkey, child->keypair.sigkey,
					udif_role_client, &vt, UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs, qsc_csp_generate);

				if (err == udif_error_none)
				{
					csr->signature[0] ^= 0x01U;
					err = udif_certificate_csr_issue(&child->cert, csr, &domain->group.cert, domain->group.keypair.sigkey, nowsecs, qsc_csp_generate);
					res = (err == udif_error_signature_invalid);
				}
				else
				{
					res = false;
				}
			}
		}
	}

	if (child != NULL)
	{
		virtual_network_clear_node(child);
		qsc_memutils_alloc_free(child);
	}

	if (csr != NULL)
	{
		qsc_memutils_clear((uint8_t*)csr, sizeof(udif_certificate_csr));
		qsc_memutils_alloc_free(csr);
	}

	if (domain != NULL)
	{
		virtual_network_dispose_domain(domain);
		qsc_memutils_alloc_free(domain);
	}

	return res;
}

static bool virtual_network_negative_status_tests(void)
{
	virtual_network_domain* domain;
	virtual_network_node* child;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	domain = (virtual_network_domain*)qsc_memutils_malloc(sizeof(virtual_network_domain));
	child = (virtual_network_node*)qsc_memutils_malloc(sizeof(virtual_network_node));
	nowsecs = qsc_timestamp_datetime_utc();

	if (domain != NULL && child != NULL)
	{
		qsc_memutils_clear((uint8_t*)domain, sizeof(virtual_network_domain));
		qsc_memutils_clear((uint8_t*)child, sizeof(virtual_network_node));

		if (virtual_network_initialize_domain(domain, nowsecs) == true)
		{
			err = udif_certstore_set_status(&domain->store, domain->group.cert.serial, udif_certstore_status_suspended, nowsecs);

			if (err == udif_error_none)
			{
				res = (udif_certstore_validate_status(&domain->store, domain->group.cert.serial, nowsecs) == udif_error_not_authorized);
			}

			if (res == true)
			{
				err = udif_certstore_set_status(&domain->store, domain->group.cert.serial, udif_certstore_status_active, nowsecs);
				res = (err == udif_error_none);
			}

			if (res == true)
			{
				err = udif_certstore_set_status(&domain->store, domain->group.cert.serial, udif_certstore_status_revoked, nowsecs);

				if (err == udif_error_none)
				{
					res = (udif_certstore_validate_status(&domain->store, domain->group.cert.serial, nowsecs) == udif_error_certificate_revoked);
				}
			}

			if (res == true)
			{
				res = (udif_certstore_find(&domain->store, domain->ua1.cert.serial) != NULL);
			}
		}
	}

	if (child != NULL)
	{
		virtual_network_clear_node(child);
		qsc_memutils_alloc_free(child);
	}

	if (domain != NULL)
	{
		virtual_network_dispose_domain(domain);
		qsc_memutils_alloc_free(domain);
	}

	return res;
}

static bool virtual_network_duplicate_serial_test(void)
{
	virtual_network_domain* domain;
	uint64_t nowsecs;
	bool res;

	res = false;
	domain = (virtual_network_domain*)qsc_memutils_malloc(sizeof(virtual_network_domain));
	nowsecs = qsc_timestamp_datetime_utc();

	if (domain != NULL)
	{
		qsc_memutils_clear((uint8_t*)domain, sizeof(virtual_network_domain));

		if (virtual_network_initialize_domain(domain, nowsecs) == true)
		{
			res = (udif_certstore_find(&domain->store, domain->ua1.cert.serial) != NULL);
		}

		virtual_network_dispose_domain(domain);
		qsc_memutils_alloc_free(domain);
	}

	return res;
}

static bool virtual_network_genesis_anchor_test(void)
{
	udif_entity_context* parent;
	udif_anchor_record* anchor;
	udif_signature_keypair* kp;
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t zero[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint64_t expseq;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	parent = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));
	anchor = (udif_anchor_record*)qsc_memutils_malloc(sizeof(udif_anchor_record));
	kp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));

	if (parent != NULL && anchor != NULL && kp != NULL)
	{
		qsc_memutils_clear((uint8_t*)parent, sizeof(udif_entity_context));
		qsc_memutils_clear((uint8_t*)anchor, sizeof(udif_anchor_record));
		qsc_memutils_clear((uint8_t*)kp, sizeof(udif_signature_keypair));
		qsc_csp_generate(childser, sizeof(childser));
		udif_signature_generate_keypair(kp->verkey, kp->sigkey, qsc_csp_generate);
		nowsecs = qsc_timestamp_datetime_utc();

		err = udif_entity_anchor_expected_sequence(parent, childser, &expseq);

		if (err == udif_error_none && expseq == 0U)
		{
			err = udif_anchor_create(anchor, childser, 0U, nowsecs, zero, zero, zero, 0U, 0U, 0U, kp->sigkey, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			res = (udif_anchor_verify(anchor, kp->verkey, expseq) == true);
		}

		if (res == true)
		{
			err = udif_entity_anchor_commit_sequence(parent, childser, anchor->sequence);
			res = (err == udif_error_none);
		}

		if (res == true)
		{
			err = udif_entity_anchor_expected_sequence(parent, childser, &expseq);
			res = (err == udif_error_none && expseq == 1U);
		}
	}

	if (anchor != NULL)
	{
		udif_anchor_clear(anchor);
		qsc_memutils_alloc_free(anchor);
	}

	if (kp != NULL)
	{
		qsc_memutils_clear((uint8_t*)kp, sizeof(udif_signature_keypair));
		qsc_memutils_alloc_free(kp);
	}

	if (parent != NULL)
	{
		qsc_memutils_clear((uint8_t*)parent, sizeof(udif_entity_context));
		qsc_memutils_alloc_free(parent);
	}

	return res;
}

bool virtual_network_test_run(void)
{
	bool res;

	res = true;

	if (virtual_network_topology_initialize_test() == true)
	{
		qsc_consoleutils_print_line("Success! Virtual network topology initialization test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Virtual network topology initialization test has failed.");
		res = false;
	}

	if (virtual_network_negative_csr_tests() == true)
	{
		qsc_consoleutils_print_line("Success! Virtual network negative CSR test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Virtual network negative CSR test has failed.");
		res = false;
	}

	if (virtual_network_negative_status_tests() == true)
	{
		qsc_consoleutils_print_line("Success! Virtual network parent status rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Virtual network parent status rejection test has failed.");
		res = false;
	}

	if (virtual_network_duplicate_serial_test() == true)
	{
		qsc_consoleutils_print_line("Success! Virtual network duplicate serial precheck test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Virtual network duplicate serial precheck test has failed.");
		res = false;
	}

	if (virtual_network_genesis_anchor_test() == true)
	{
		qsc_consoleutils_print_line("Success! Virtual network genesis anchor sequence test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Virtual network genesis anchor sequence test has failed.");
		res = false;
	}

	return res;
}
