#include "udif.h"
#include "dispatch.h"
#include "entity.h"
#include "certstore.h"
#include "message.h"
#include "tunnel.h"
#include "intutils.h"
#include "memutils.h"
#include "timestamp.h"

/* Role bit flags used by the role-allowance table.
   A message is admissible if (allowed_roles & role_bit) != 0. */
#define ROLE_BIT_ROOT   (1U << 0U)
#define ROLE_BIT_UDC    (1U << 1U)  /* Branch Controller */
#define ROLE_BIT_UIP    (1U << 2U)  /* Group Controller */
#define ROLE_BIT_CLIENT (1U << 3U)  /* User Agent */

/*
 * Role-allowance table.
 *
 * Each row pairs a message type with the set of roles permitted to receive
 * it. Role combinations follow directly from the UDIF specification:
 *   - cert_enroll_req flows upward (parent accepts from child), so it is
 *     received by ROOT, UDC (BC), and UIP (GC).
 *   - cert_enroll_resp and revocation/suspension/resume notices flow
 *     downward, so they are received by UDC, UIP, and CLIENT (UA).
 *   - queries are answered by UIP (GC) and BC; responses flow to the
 *     originator (UA, or upstream in cross-domain cases).
 *   - object operations and registry commits flow to the GC.
 *   - anchors flow upstream (child to parent), so anchor_push arrives
 *     at UDC and ROOT; acks flow back down to UDC and UIP.
 *   - treaty messages are strictly BC <-> BC.
 *   - error_report is universal.
 *   - keepalive is handled by the dispatcher itself and never dispatched
 *     to a handler.
 */
struct role_rule
{
	udif_message_type msgtype;
	uint32_t allowed;
	udif_handler_fn handler;
};

static const struct role_rule role_table[] =
{
	/* certificate lifecycle */
	{ udif_msg_cert_enroll_req, (ROLE_BIT_ROOT | ROLE_BIT_UDC | ROLE_BIT_UIP), udif_handle_cert_enroll_req },
	{ udif_msg_cert_enroll_resp, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cert_enroll_resp },
	{ udif_msg_cert_revoke, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cert_revoke },
	{ udif_msg_cert_suspend, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cert_suspend },
	{ udif_msg_cert_resume, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cert_resume },
	{ udif_msg_cap_grant, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cap_grant },
	{ udif_msg_cap_revoke, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_cap_revoke },

	/* predicate queries */
	{ udif_msg_query_req, (ROLE_BIT_UDC | ROLE_BIT_UIP), udif_handle_query_req },
	{ udif_msg_query_resp, (ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_query_resp },

	/* object and registry */
	{ udif_msg_object_create, ROLE_BIT_UIP, udif_handle_object_create },
	{ udif_msg_object_transfer_req, ROLE_BIT_UIP, udif_handle_object_transfer_req },
	{ udif_msg_object_transfer_confirm, ROLE_BIT_UIP, udif_handle_object_transfer_confirm },
	{ udif_msg_registry_commit, (ROLE_BIT_UDC | ROLE_BIT_UIP), udif_handle_registry_commit },

	/* anchor propagation */
	{ udif_msg_anchor_push, (ROLE_BIT_ROOT | ROLE_BIT_UDC), udif_handle_anchor_push },
	{ udif_msg_anchor_ack, (ROLE_BIT_UDC | ROLE_BIT_UIP), udif_handle_anchor_ack },

	/* peering treaties and cross-domain queries (BC <-> BC) */
	{ udif_msg_treaty_propose, ROLE_BIT_UDC, udif_handle_treaty_propose },
	{ udif_msg_treaty_cosign, ROLE_BIT_UDC, udif_handle_treaty_cosign },
	{ udif_msg_treaty_revoke, ROLE_BIT_UDC, udif_handle_treaty_revoke },
	{ udif_msg_treaty_query_fwd, ROLE_BIT_UDC, udif_handle_treaty_query_fwd },
	{ udif_msg_treaty_query_resp, ROLE_BIT_UDC, udif_handle_treaty_query_resp },

	/* application-level error */
	{ udif_msg_error_report, (ROLE_BIT_ROOT | ROLE_BIT_UDC | ROLE_BIT_UIP | ROLE_BIT_CLIENT), udif_handle_error_report }
};

#define ROLE_TABLE_COUNT (sizeof(role_table) / sizeof(role_table[0U]))

static uint32_t role_to_bit(udif_roles role)
{
	/* map a udif_roles value to a single-bit role flag for table lookup.
	   Roles outside the four Phase-6 operational roles (e.g. udif_role_audit) return 0U. */

	uint32_t res;

	switch (role)
	{
		case udif_role_root:
			res = ROLE_BIT_ROOT;
			break;
		case udif_role_ubc:
			res = ROLE_BIT_UDC;
			break;
		case udif_role_ugc:
			res = ROLE_BIT_UIP;
			break;
		case udif_role_client:
			res = ROLE_BIT_CLIENT;
			break;
		default:
			res = 0U;
			break;
	}

	return res;
}

static const struct role_rule* role_table_lookup(udif_message_type msgtype)
{
	/* locate the row for a given message type. Returns NULL for unknown types. */

	const struct role_rule* res;
	size_t i;

	res = NULL;

	for (i = 0U; i < ROLE_TABLE_COUNT; ++i)
	{
		if (role_table[i].msgtype == msgtype)
		{
			res = &role_table[i];
			break;
		}
	}

	return res;
}

static bool dispatch_error_is_fatal(udif_errors err)
{
	/* determine whether a handler return code is fatal to the tunnel.
	   Fatal codes map to QSTP/transport-level failures; non-fatal codes
	   map to per-request policy denials that keep the session alive. */

	bool res;

	switch (err)
	{
		case udif_error_auth_failure:
		case udif_error_signature_invalid:
		case udif_error_mac_invalid:
		case udif_error_invalid_sequence:
		case udif_error_time_window:
		case udif_error_epoch_mismatch:
		case udif_error_suite_mismatch:
		case udif_error_invalid_state:
		case udif_error_internal:
			res = true;
			break;
		default:
			res = false;
			break;
	}

	return res;
}


static bool dispatch_requires_known_peer(udif_message_type msgtype)
{
	bool res;

	switch (msgtype)
	{
		case udif_msg_keepalive:
		case udif_msg_error_report:
		case udif_msg_cert_enroll_req:
		case udif_msg_cert_enroll_resp:
			res = false;
			break;
		default:
			res = true;
			break;
	}

	return res;
}

static udif_errors dispatch_send_error_report(udif_tunnel* tun, udif_errors reportederr, uint64_t nowsecs)
{
	/* build and send a udif_msg_error_report carrying a single error code byte.
	   Used when a handler returns a non-fatal error. Failure to send the
	   error report is itself a transport failure and is returned to the caller. */

	udif_message errmsg;
	uint8_t payload[1U];
	udif_errors err;

	qsc_memutils_clear((uint8_t*)&errmsg, sizeof(udif_message));
	payload[0U] = (uint8_t)reportederr;

	err = udif_message_init(&errmsg, udif_msg_error_report, payload, (uint32_t)sizeof(payload));

	if (err == udif_error_none)
	{
		err = udif_tunnel_send(tun, &errmsg, nowsecs);
		udif_message_dispose(&errmsg);
	}

	return err;
}

bool udif_dispatch_is_permitted(udif_roles role, udif_message_type msgtype)
{
	const struct role_rule* rule;
	uint32_t rolebit;
	bool res;

	res = false;
	rolebit = role_to_bit(role);

	if (rolebit != 0U)
	{
		rule = role_table_lookup(msgtype);

		if (rule != NULL && (rule->allowed & rolebit) != 0U)
		{
			res = true;
		}
	}

	return res;
}

udif_errors udif_dispatch(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(msg != NULL);

	const struct role_rule* rule;
	uint32_t rolebit;
	udif_errors err;
	udif_errors senderr;

	err = udif_error_invalid_input;

	if (ctx != NULL && tun != NULL && msg != NULL)
	{
		/* keepalives are terminated at the tunnel layer; timer updates already happened inside udif_tunnel_on_receive */
		if (msg->msgtype == udif_msg_keepalive)
		{
			err = udif_error_none;
		}
		else
		{
			rolebit = role_to_bit(ctx->role);

			if (rolebit == 0U)
			{
				err = udif_error_not_authorized;
			}
			else
			{
				rule = role_table_lookup(msg->msgtype);

				if (rule == NULL)
				{
					/* unknown message type */
					err = udif_error_decode_failure;
				}
				else if ((rule->allowed & rolebit) == 0U)
				{
					/* message known but not admissible for this role */
					err = udif_error_not_authorized;
				}
				else if (rule->handler == NULL)
				{
					/* table entry without a bound handler */
					err = udif_error_internal;
				}
				else if (dispatch_requires_known_peer(msg->msgtype) == true &&
					udif_certstore_verify_certificate(&ctx->certstore, tun->peerserial, nowsecs) != udif_error_none)
				{
					err = udif_error_not_authorized;
				}
				else
				{
					err = rule->handler(ctx, tun, msg, nowsecs);

					/* translate a non-fatal handler return into a peer-visible error report; 
					   fatal codes bubble to the caller so the main loop can close the tunnel */
					if (err != udif_error_none && dispatch_error_is_fatal(err) == false)
					{
						senderr = dispatch_send_error_report(tun, err, nowsecs);

						if (senderr == udif_error_none)
						{
							/* report delivered; surface success to the caller so
							   the session continues */
							err = udif_error_none;
						}
						else
						{
							/* failing to send the report is a transport fault */
							err = senderr;
						}
					}
				}
			}
		}
	}

	return err;
}
