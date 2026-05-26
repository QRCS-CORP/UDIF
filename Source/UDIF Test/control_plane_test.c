#include "control_plane_test.h"

#include "capability.h"
#include "certificate.h"
#include "certstore.h"
#include "dispatch.h"
#include "entity.h"
#include "message.h"
#include "tunnel.h"
#include "udif.h"
#include "consoleutils.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

typedef struct control_plane_node
{
	udif_certificate cert;
	udif_signature_keypair keypair;
} control_plane_node;

typedef struct control_plane_chain
{
	control_plane_node root;
	control_plane_node branch;
	control_plane_node group;
	control_plane_node client;
} control_plane_chain;

typedef struct control_plane_role_rule
{
	udif_message_type msgtype;
	bool root;
	bool branch;
	bool group;
	bool client;
} control_plane_role_rule;

static uint64_t control_plane_branch_capabilities(void)
{
	return (UDIF_BC_CAPABILITIES | UDIF_GC_CAPABILITIES | UDIF_CLIENT_CAPABILITIES);
}

static uint64_t control_plane_group_capabilities(void)
{
	return (UDIF_GC_CAPABILITIES | UDIF_CLIENT_CAPABILITIES);
}

static void control_plane_clear_node(control_plane_node* node)
{
	if (node != NULL)
	{
		udif_certificate_clear(&node->cert);
		qsc_memutils_clear((uint8_t*)&node->keypair, sizeof(control_plane_node) - sizeof(udif_certificate));
	}
}

static void control_plane_clear_chain(control_plane_chain* chain)
{
	if (chain != NULL)
	{
		control_plane_clear_node(&chain->root);
		control_plane_clear_node(&chain->branch);
		control_plane_clear_node(&chain->group);
		control_plane_clear_node(&chain->client);
		qsc_memutils_clear((uint8_t*)chain, sizeof(control_plane_chain));
	}
}

static udif_errors control_plane_create_root(control_plane_node* node, uint64_t nowsecs)
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

	return err;
}

static udif_errors control_plane_issue_child(control_plane_node* child, const control_plane_node* parent,
	udif_roles role, uint64_t capability, uint64_t policy, uint64_t nowsecs)
{
	udif_certificate_csr csr;
	udif_valid_time vt;
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	udif_errors err;

	qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
	qsc_memutils_clear((uint8_t*)child, sizeof(control_plane_node));
	vt.from = nowsecs;
	vt.to = nowsecs + (UDIF_CERTIFICATE_DEFAULT_PERIOD / 2U);
	qsc_csp_generate(serial, sizeof(serial));
	udif_signature_generate_keypair(child->keypair.verkey, child->keypair.sigkey, qsc_csp_generate);

	err = udif_certificate_csr_create(&csr, serial, child->keypair.verkey, child->keypair.sigkey,
		role, &vt, capability, policy, nowsecs, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_issue(&child->cert, &csr, &parent->cert, parent->keypair.sigkey, nowsecs, qsc_csp_generate);
	}

	qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));

	return err;
}

static bool control_plane_create_chain(control_plane_chain* chain, uint64_t nowsecs)
{
	udif_errors err;
	bool res;

	res = false;
	qsc_memutils_clear((uint8_t*)chain, sizeof(control_plane_chain));
	err = control_plane_create_root(&chain->root, nowsecs);

	if (err == udif_error_none)
	{
		err = control_plane_issue_child(&chain->branch, &chain->root, udif_role_ubc,
			control_plane_branch_capabilities(), UDIF_BC_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = control_plane_issue_child(&chain->group, &chain->branch, udif_role_ugc,
			control_plane_group_capabilities(), UDIF_GC_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = control_plane_issue_child(&chain->client, &chain->group, udif_role_client,
			UDIF_CLIENT_CAPABILITIES, UDIF_CLIENT_POLICY_DEFAULT, nowsecs);
	}

	if (err == udif_error_none)
	{
		res = true;
	}

	return res;
}

static bool control_plane_store_chain(udif_certstore* store, const control_plane_chain* chain, uint64_t nowsecs)
{
	udif_errors err;
	bool res;

	res = false;
	udif_certstore_initialize(store);
	err = udif_certstore_add(store, &chain->root.cert, udif_certstore_status_active, nowsecs);

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &chain->branch.cert, udif_certstore_status_active, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &chain->group.cert, udif_certstore_status_active, nowsecs);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &chain->client.cert, udif_certstore_status_active, nowsecs);
	}

	if (err == udif_error_none)
	{
		res = true;
	}

	return res;
}

static bool control_plane_role_matrix_test(void)
{
	static const control_plane_role_rule rules[] =
	{
		{ udif_msg_cert_enroll_req, true, true, true, false },
		{ udif_msg_cert_enroll_resp, false, true, true, true },
		{ udif_msg_cert_revoke, false, true, true, true },
		{ udif_msg_cert_suspend, false, true, true, true },
		{ udif_msg_cert_resume, false, true, true, true },
		{ udif_msg_cap_grant, false, true, true, true },
		{ udif_msg_cap_revoke, false, true, true, true },
		{ udif_msg_query_req, false, true, true, false },
		{ udif_msg_query_resp, false, true, true, true },
		{ udif_msg_object_create, false, false, true, false },
		{ udif_msg_object_transfer_req, false, false, true, false },
		{ udif_msg_object_transfer_confirm, false, false, true, false },
		{ udif_msg_registry_commit, false, true, true, false },
		{ udif_msg_anchor_push, true, true, false, false },
		{ udif_msg_anchor_ack, false, true, true, false },
		{ udif_msg_treaty_propose, false, true, false, false },
		{ udif_msg_treaty_cosign, false, true, false, false },
		{ udif_msg_treaty_revoke, false, true, false, false },
		{ udif_msg_treaty_query_fwd, false, true, false, false },
		{ udif_msg_treaty_query_resp, false, true, false, false },
		{ udif_msg_error_report, true, true, true, true }
	};
	size_t i;
	bool res;

	res = true;

	for (i = 0U; i < (sizeof(rules) / sizeof(rules[0U])); ++i)
	{
		if (udif_dispatch_is_permitted(udif_role_root, rules[i].msgtype) != rules[i].root ||
			udif_dispatch_is_permitted(udif_role_ubc, rules[i].msgtype) != rules[i].branch ||
			udif_dispatch_is_permitted(udif_role_ugc, rules[i].msgtype) != rules[i].group ||
			udif_dispatch_is_permitted(udif_role_client, rules[i].msgtype) != rules[i].client)
		{
			res = false;
			break;
		}
	}

	return res;
}

static bool control_plane_unauthorized_prehandler_test(void)
{
	udif_entity_context* ctx;
	udif_tunnel tun;
	udif_message msg;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
		qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
		ctx->role = udif_role_client;
		msg.msgtype = udif_msg_anchor_push;
		msg.payload = NULL;
		msg.payloadlen = 0U;
		nowsecs = qsc_timestamp_datetime_utc();
		err = udif_dispatch(ctx, &tun, &msg, nowsecs);
		res = (err == udif_error_not_authorized);
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_alloc_free(ctx);
	}

	return res;
}

static bool control_plane_error_report_no_peer_test(void)
{
	udif_entity_context* ctx;
	udif_tunnel tun;
	udif_message msg;
	uint8_t payload[1U];
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
		qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
		payload[0U] = (uint8_t)udif_error_not_authorized;
		ctx->role = udif_role_client;
		msg.msgtype = udif_msg_error_report;
		msg.payload = payload;
		msg.payloadlen = (uint32_t)sizeof(payload);
		nowsecs = qsc_timestamp_datetime_utc();
		err = udif_dispatch(ctx, &tun, &msg, nowsecs);
		res = (err == udif_error_none);
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_alloc_free(ctx);
	}

	return res;
}

static bool control_plane_peer_status_and_chain_test(void)
{
	control_plane_chain* chain;
	udif_entity_context* ctx;
	udif_tunnel tun;
	udif_message msg;
	uint8_t payload[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
	qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
	res = false;
	chain = (control_plane_chain*)qsc_memutils_malloc(sizeof(control_plane_chain));
	ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));
	nowsecs = qsc_timestamp_datetime_utc();

	if (chain != NULL && ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)chain, sizeof(control_plane_chain));
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));

		if (control_plane_create_chain(chain, nowsecs) == true)
		{
			ctx->role = udif_role_root;
			udif_certstore_initialize(&ctx->certstore);
			qsc_memutils_copy(tun.peerserial, chain->branch.cert.serial, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(payload, chain->client.cert.serial, sizeof(payload));
			msg.msgtype = udif_msg_cert_revoke;
			msg.payload = payload;
			msg.payloadlen = (uint32_t)sizeof(payload);

			/* Store only the peer. Status-only validation would pass here; recursive
			 * chain validation must reject the missing Root issuer before the handler. */
			err = udif_certstore_add(&ctx->certstore, &chain->branch.cert, udif_certstore_status_active, nowsecs);

			if (err == udif_error_none)
			{
				err = udif_dispatch(ctx, &tun, &msg, nowsecs);
				res = (err == udif_error_not_authorized);
			}

			udif_certstore_clear(&ctx->certstore);

			if (res == true)
			{
				res = control_plane_store_chain(&ctx->certstore, chain, nowsecs);
			}

			if (res == true)
			{
				err = udif_certstore_set_status(&ctx->certstore, chain->branch.cert.serial, udif_certstore_status_suspended, nowsecs);
				res = (err == udif_error_none && udif_dispatch(ctx, &tun, &msg, nowsecs) == udif_error_not_authorized);
			}

			if (res == true)
			{
				err = udif_certstore_set_status(&ctx->certstore, chain->branch.cert.serial, udif_certstore_status_active, nowsecs);
				res = (err == udif_error_none);
			}

			if (res == true)
			{
				err = udif_certstore_set_status(&ctx->certstore, chain->branch.cert.serial, udif_certstore_status_revoked, nowsecs);
				res = (err == udif_error_none && udif_dispatch(ctx, &tun, &msg, nowsecs) == udif_error_not_authorized);
			}

			udif_certstore_clear(&ctx->certstore);
		}

		control_plane_clear_chain(chain);
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
	}

	if (chain != NULL)
	{
		qsc_memutils_alloc_free(chain);
	}

	if (ctx != NULL)
	{
		qsc_memutils_alloc_free(ctx);
	}

	qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));

	return res;
}

static bool control_plane_cascade_revocation_test(void)
{
	control_plane_chain* chain;
	udif_certstore* store;
	uint64_t nowsecs;
	udif_errors err;
	bool res;

	res = false;
	chain = (control_plane_chain*)qsc_memutils_malloc(sizeof(control_plane_chain));
	store = (udif_certstore*)qsc_memutils_malloc(sizeof(udif_certstore));
	nowsecs = qsc_timestamp_datetime_utc();

	if (chain != NULL && store != NULL)
	{
		qsc_memutils_clear((uint8_t*)chain, sizeof(control_plane_chain));
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_certstore));

		if (control_plane_create_chain(chain, nowsecs) == true && control_plane_store_chain(store, chain, nowsecs) == true)
		{
			err = udif_certstore_set_status(store, chain->branch.cert.serial, udif_certstore_status_revoked, nowsecs);

			if (err == udif_error_none)
			{
				res = (udif_certstore_get_status(store, chain->branch.cert.serial) == udif_certstore_status_revoked &&
					udif_certstore_get_status(store, chain->group.cert.serial) == udif_certstore_status_revoked &&
					udif_certstore_get_status(store, chain->client.cert.serial) == udif_certstore_status_revoked &&
					udif_certstore_verify_certificate(store, chain->client.cert.serial, nowsecs) == udif_error_certificate_revoked);
			}
		}

		udif_certstore_clear(store);
		qsc_memutils_clear((uint8_t*)store, sizeof(udif_certstore));
		control_plane_clear_chain(chain);
	}

	if (store != NULL)
	{
		qsc_memutils_alloc_free(store);
	}

	if (chain != NULL)
	{
		qsc_memutils_alloc_free(chain);
	}

	return res;
}

bool control_plane_test_run(void)
{
	bool res;

	res = true;

	if (control_plane_role_matrix_test() == true)
	{
		qsc_consoleutils_print_line("Success! Control-plane role matrix test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Control-plane role matrix test has failed.");
		res = false;
	}

	if (control_plane_unauthorized_prehandler_test() == true)
	{
		qsc_consoleutils_print_line("Success! Control-plane unauthorized pre-handler rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Control-plane unauthorized pre-handler rejection test has failed.");
		res = false;
	}

	if (control_plane_error_report_no_peer_test() == true)
	{
		qsc_consoleutils_print_line("Success! Control-plane error report admission test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Control-plane error report admission test has failed.");
		res = false;
	}

	if (control_plane_peer_status_and_chain_test() == true)
	{
		qsc_consoleutils_print_line("Success! Control-plane peer status and chain validation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Control-plane peer status and chain validation test has failed.");
		res = false;
	}

	if (control_plane_cascade_revocation_test() == true)
	{
		qsc_consoleutils_print_line("Success! Control-plane cascade revocation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Control-plane cascade revocation test has failed.");
		res = false;
	}

	return res;
}
