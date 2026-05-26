#include "handler.h"
#include "capability.h"
#include "entity.h"
#include "event.h"
#include "message.h"
#include "tunnel.h"
#include "memutils.h"

static bool caphandler_certificate_has_capability(const udif_certificate* cert, uint64_t capability)
{
	bool res;

	res = false;

	if (cert != NULL && capability != 0U)
	{
		res = ((cert->capability & capability) == capability);
	}

	return res;
}

static bool caphandler_peer_has_capability(const udif_entity_context* ctx, const udif_tunnel* tun, uint64_t capability)
{
	const udif_certificate* cert;
	bool res;

	res = false;

	if (ctx != NULL && tun != NULL)
	{
		cert = udif_certstore_find(&ctx->certstore, tun->peerserial);

		if (cert != NULL)
		{
			res = caphandler_certificate_has_capability(cert, capability);
		}
	}

	return res;
}


udif_errors udif_handle_cap_grant(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(msg != NULL);

	udif_capability capability;
	udif_errors err;

	qsc_memutils_clear((uint8_t*)&capability, sizeof(udif_capability));
	err = udif_error_invalid_input;

	if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_CAPABILITY_ENCODED_SIZE)
	{
		err = udif_capability_deserialize(&capability, msg->payload, (size_t)msg->payloadlen);

		if (err == udif_error_none)
		{
			if (qsc_memutils_are_equal(capability.issuedby, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				err = udif_error_not_authorized;
			}
		}

		if (err == udif_error_none)
		{
			if (qsc_memutils_are_equal(capability.issuedto, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				err = udif_error_not_authorized;
			}
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_verify_certificate(&ctx->certstore, tun->peerserial, nowsecs);
		}

		if (err == udif_error_none)
		{
			if (caphandler_peer_has_capability(ctx, tun, UDIF_CAP_ADMIN_ENROLL) == false)
			{
				err = udif_error_not_authorized;
			}
		}

		if (err == udif_error_none)
		{
			if (ctx->hascapabilitykey == false)
			{
				err = udif_error_invalid_state;
			}
		}

		if (err == udif_error_none)
		{
			err = udif_capstore_add_verified(&ctx->capstore, &capability, ctx->capabilitykey, nowsecs);
		}

		if (err == udif_error_none)
		{
			err = udif_event_log(ctx->mcelmgr, UDIF_LEDGER_MEMBERSHIP, udif_audit_event_cap_grant,
				tun->peerserial, capability.issuedto, capability.digest, nowsecs, msg->payload, (size_t)msg->payloadlen);
		}
	}

	udif_capability_clear(&capability);

	return err;
}

udif_errors udif_handle_cap_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(msg != NULL);

	const udif_capability* capability;
	udif_errors err;

	capability = NULL;
	err = udif_error_invalid_input;

	if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_CRYPTO_HASH_SIZE)
	{
		err = udif_certstore_verify_certificate(&ctx->certstore, tun->peerserial, nowsecs);

		if (err == udif_error_none)
		{
			if (caphandler_peer_has_capability(ctx, tun, UDIF_CAP_ADMIN_REVOKE) == false)
			{
				err = udif_error_not_authorized;
			}
		}

		if (err == udif_error_none)
		{
			capability = udif_capstore_find_any(&ctx->capstore, msg->payload);

			if (capability == NULL)
			{
				err = udif_error_object_not_found;
			}
		}

		if (err == udif_error_none)
		{
			if (qsc_memutils_are_equal(capability->issuedby, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
			{
				err = udif_error_not_authorized;
			}
		}

		if (err == udif_error_none)
		{
			if (udif_capstore_set_status(&ctx->capstore, msg->payload, udif_capstore_status_revoked) == false)
			{
				err = udif_error_invalid_state;
			}
		}

		if (err == udif_error_none)
		{
			err = udif_event_log(ctx->mcelmgr, UDIF_LEDGER_MEMBERSHIP, udif_audit_event_cap_revoke,
				tun->peerserial, capability->issuedto, msg->payload, nowsecs, msg->payload, (size_t)msg->payloadlen);
		}
	}

	return err;
}
