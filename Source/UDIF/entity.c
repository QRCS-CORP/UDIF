#include "udif.h"
#include "entity.h"
#include "tunnel.h"
#include "mcelmanager.h"
#include "certificate.h"
#include "certstore.h"
#include "capstore.h"
#include "memutils.h"
#include "qstp.h"

/* ledger-bearing roles (those that keep membership/transaction/registry logs).
   UAs do not maintain ledgers; the Root maintains only membership. */
static bool entity_role_needs_ledgers(udif_roles role)
{
	bool res;

	switch (role)
	{
		case udif_role_root:
		case udif_role_ugc:
		case udif_role_ubc:
			res = true;
			break;
		default:
			res = false;
			break;
	}

	return res;
}

static bool entity_serial_equal(const uint8_t* a, const uint8_t* b)
{
	/* compare 16-byte identifiers via constant-time primitive. */
	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = qsc_memutils_are_equal(a, b, UDIF_SERIAL_NUMBER_SIZE);
	}

	return res;
}

static bool entity_serial_is_zero(const uint8_t* a)
{
	/* zeroed serial constant for treaty-id comparisons. */

	uint8_t zero[UDIF_SERIAL_NUMBER_SIZE] = { 0U };

	return qsc_memutils_are_equal(a, zero, UDIF_SERIAL_NUMBER_SIZE);
}

udif_errors udif_entity_anchor_expected_sequence(const udif_entity_context* ctx, const uint8_t* childser, uint64_t* expseq)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(childser != NULL);
	UDIF_ASSERT(expseq != NULL);

	size_t i;
	udif_errors err;

	err = udif_error_invalid_input;

	if (ctx != NULL && childser != NULL && expseq != NULL)
	{
		*expseq = 0U;
		err = udif_error_none;

		for (i = 0U; i < UDIF_ENTITY_MAX_ANCHOR_STATES; ++i)
		{
			if (ctx->anchorseq[i].used == true && entity_serial_equal(ctx->anchorseq[i].childser, childser) == true)
			{
				*expseq = ctx->anchorseq[i].nextseq;
				break;
			}
		}
	}

	return err;
}

udif_errors udif_entity_anchor_commit_sequence(udif_entity_context* ctx, const uint8_t* childser, uint64_t acceptedseq)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(childser != NULL);

	size_t i;
	size_t freeidx;
	udif_errors err;

	err = udif_error_invalid_input;
	freeidx = UDIF_ENTITY_MAX_ANCHOR_STATES;

	if (ctx != NULL && childser != NULL)
	{
		err = udif_error_registry_full;

		for (i = 0U; i < UDIF_ENTITY_MAX_ANCHOR_STATES; ++i)
		{
			if (ctx->anchorseq[i].used == true)
			{
				if (entity_serial_equal(ctx->anchorseq[i].childser, childser) == true)
				{
					ctx->anchorseq[i].nextseq = acceptedseq + 1U;
					err = udif_error_none;
					break;
				}
			}
			else if (freeidx == UDIF_ENTITY_MAX_ANCHOR_STATES)
			{
				freeidx = i;
			}
		}

		if (err != udif_error_none && freeidx != UDIF_ENTITY_MAX_ANCHOR_STATES)
		{
			qsc_memutils_secure_erase((uint8_t*)&ctx->anchorseq[freeidx], sizeof(udif_anchor_sequence_state));
			qsc_memutils_copy(ctx->anchorseq[freeidx].childser, childser, UDIF_SERIAL_NUMBER_SIZE);
			ctx->anchorseq[freeidx].nextseq = acceptedseq + 1U;
			ctx->anchorseq[freeidx].used = true;
			err = udif_error_none;
		}
	}

	return err;
}


udif_registry_state* udif_entity_registry_find(udif_entity_context* ctx, const uint8_t* ownerser)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(ownerser != NULL);

	size_t i;
	udif_registry_state* reg;

	reg = NULL;

	if (ctx != NULL && ownerser != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_REGISTRIES; ++i)
		{
			if (ctx->registries[i].used == true &&
				entity_serial_equal(ctx->registries[i].ownerser, ownerser) == true)
			{
				reg = &ctx->registries[i].registry;
				break;
			}
		}
	}

	return reg;
}

const udif_registry_state* udif_entity_registry_find_const(const udif_entity_context* ctx, const uint8_t* ownerser)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(ownerser != NULL);

	size_t i;
	const udif_registry_state* reg;

	reg = NULL;

	if (ctx != NULL && ownerser != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_REGISTRIES; ++i)
		{
			if (ctx->registries[i].used == true &&
				entity_serial_equal(ctx->registries[i].ownerser, ownerser) == true)
			{
				reg = &ctx->registries[i].registry;
				break;
			}
		}
	}

	return reg;
}

udif_registry_state* udif_entity_registry_get_or_create(udif_entity_context* ctx, const uint8_t* ownerser, size_t capacity)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(ownerser != NULL);

	size_t i;
	udif_registry_state* reg;

	reg = NULL;

	if (ctx != NULL && ownerser != NULL && capacity > 0U)
	{
		reg = udif_entity_registry_find(ctx, ownerser);

		if (reg == NULL)
		{
			for (i = 0U; i < UDIF_ENTITY_MAX_REGISTRIES; ++i)
			{
				if (ctx->registries[i].used == false)
				{
					if (udif_registry_initialize(&ctx->registries[i].registry, ownerser, capacity) == udif_error_none)
					{
						qsc_memutils_copy(ctx->registries[i].ownerser, ownerser, UDIF_SERIAL_NUMBER_SIZE);
						ctx->registries[i].used = true;
						reg = &ctx->registries[i].registry;
					}

					break;
				}
			}
		}
	}

	return reg;
}

void udif_entity_registry_clear_all(udif_entity_context* ctx)
{
	UDIF_ASSERT(ctx != NULL);

	size_t i;

	if (ctx != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_REGISTRIES; ++i)
		{
			if (ctx->registries[i].used == true)
			{
				udif_registry_dispose(&ctx->registries[i].registry);
				qsc_memutils_secure_erase((uint8_t*)&ctx->registries[i], sizeof(udif_entity_registry_entry));
			}
		}
	}
}

udif_errors udif_entity_init(udif_entity_context* ctx, const udif_entity_config* cfg)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(cfg != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (ctx != NULL && cfg != NULL)
	{
		/* required fields common to all roles */
		if (cfg->selfcert != NULL && cfg->rootcert != NULL && cfg->selfkeypair != NULL && cfg->qstprootcert != NULL && cfg->role != udif_role_none)
		{
			/* non-root roles must supply a parent certificate */
			bool parentok;

			parentok = (cfg->role == udif_role_root) || (cfg->parentcert != NULL);

			/* entities with a listener must supply a QSTP server key */
			if (parentok == true && (cfg->haslistener == false || cfg->qstpserverkey != NULL))
			{
				qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));

				qsc_memutils_copy(&ctx->selfcert, cfg->selfcert, sizeof(udif_certificate));
				qsc_memutils_copy(&ctx->rootcert, cfg->rootcert, sizeof(udif_certificate));
				qsc_memutils_copy(&ctx->selfkeypair, cfg->selfkeypair, sizeof(udif_signature_keypair));

				if (cfg->capabilitykey != NULL)
				{
					qsc_memutils_copy(ctx->capabilitykey, cfg->capabilitykey, UDIF_CRYPTO_KEY_SIZE);
					ctx->hascapabilitykey = true;
				}

				qsc_memutils_copy(&ctx->qstprootcert, cfg->qstprootcert, sizeof(qstp_root_certificate));

				if (cfg->parentcert != NULL)
				{
					qsc_memutils_copy(&ctx->parentcert, cfg->parentcert, sizeof(udif_certificate));
				}

				if (cfg->qstpserverkey != NULL)
				{
					qsc_memutils_copy(&ctx->qstpserverkey, cfg->qstpserverkey, sizeof(qstp_server_signature_key));
				}

				ctx->role = cfg->role;
				ctx->haslistener = cfg->haslistener;
				ctx->tunnels.count = 0U;
				ctx->nextanchorsecs = 0U;
				ctx->mcelmgr = NULL;

				udif_certstore_initialize(&ctx->certstore);
				udif_capstore_initialize(&ctx->capstore);
				udif_treatystore_initialize(&ctx->treatystore);

				(void)udif_certstore_add(&ctx->certstore, &ctx->rootcert, udif_certstore_status_active, ctx->rootcert.valid.from);
				(void)udif_certstore_add(&ctx->certstore, &ctx->selfcert, udif_certstore_status_active, ctx->selfcert.valid.from);

				if (cfg->parentcert != NULL)
				{
					(void)udif_certstore_add(&ctx->certstore, &ctx->parentcert, udif_certstore_status_active, ctx->parentcert.valid.from);
				}

				/* ledger-bearing roles open the MCEL manager */
				if (entity_role_needs_ledgers(cfg->role) == true && cfg->mcelbasepath != NULL)
				{
					ctx->mcelmgr = udif_mcel_initialize(cfg->mcelbasepath, cfg->checkconfig);

					if (ctx->mcelmgr == NULL)
					{
						/* roll back copies that carry sensitive material */
						qsc_memutils_secure_erase((uint8_t*)&ctx->selfkeypair, sizeof(udif_signature_keypair));
						qsc_memutils_secure_erase((uint8_t*)&ctx->qstpserverkey, sizeof(qstp_server_signature_key));
						qsc_memutils_secure_erase((uint8_t*)ctx, sizeof(udif_entity_context));
						err = udif_error_internal;
					}
					else
					{
						ctx->initialized = true;
						err = udif_error_none;
					}
				}
				else
				{
					/* UA or role that does not keep ledgers */
					ctx->initialized = true;
					err = udif_error_none;
				}
			}
		}
	}

	return err;
}

void udif_entity_dispose(udif_entity_context* ctx)
{
	UDIF_ASSERT(ctx != NULL);

	size_t i;

	if (ctx != NULL)
	{
		if (ctx->initialized == true)
		{
			/* close any open tunnels without notifying (caller is shutting down) */
			for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
			{
				if (ctx->tunnels.entries[i].rolepair != udif_rolepair_none)
				{
					udif_tunnel_close(&ctx->tunnels.entries[i], false);
				}
			}

			udif_entity_registry_clear_all(ctx);

			if (ctx->mcelmgr != NULL)
			{
				udif_mcel_dispose(ctx->mcelmgr);
				ctx->mcelmgr = NULL;
			}
		}

		/* zeroize private key material before releasing the structure */
		qsc_memutils_secure_erase((uint8_t*)&ctx->selfkeypair, sizeof(udif_signature_keypair));
		qsc_memutils_secure_erase((uint8_t*)&ctx->qstpserverkey, sizeof(qstp_server_signature_key));
		qsc_memutils_secure_erase((uint8_t*)ctx, sizeof(udif_entity_context));
	}
}

udif_tunnel* udif_entity_add_tunnel(udif_entity_context* ctx, const udif_tunnel* tun)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(tun != NULL);

	size_t i;
	udif_tunnel* res;

	res = NULL;

	if (ctx != NULL && tun != NULL && tun->rolepair != udif_rolepair_none && ctx->tunnels.count < UDIF_ENTITY_MAX_TUNNELS)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
		{
			if (ctx->tunnels.entries[i].rolepair == udif_rolepair_none)
			{
				qsc_memutils_copy(&ctx->tunnels.entries[i], tun, sizeof(udif_tunnel));
				ctx->tunnels.count += 1U;
				res = &ctx->tunnels.entries[i];
				break;
			}
		}
	}

	return res;
}

udif_tunnel* udif_entity_find_tunnel(udif_entity_context* ctx, const uint8_t* peerserial, const uint8_t* treatyid)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(peerserial != NULL);

	size_t i;
	udif_tunnel* cand;
	udif_tunnel* res;

	res = NULL;

	if (ctx != NULL && peerserial != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
		{
			cand = &ctx->tunnels.entries[i];

			if (cand->rolepair != udif_rolepair_none && entity_serial_equal(cand->peerserial, peerserial) == true)
			{
				if (treatyid == NULL)
				{
					/* caller wants any non-treaty tunnel; entries store a zeroed treatyid for non-treaty rolepairs */
					if (cand->rolepair != udif_rolepair_treaty)
					{
						res = cand;
						break;
					}
				}
				else
				{
					/* caller wants a specific treaty tunnel */
					if (cand->rolepair == udif_rolepair_treaty && entity_serial_equal(cand->treatyid, treatyid) == true)
					{
						res = cand;
						break;
					}
				}
			}
		}
	}

	return res;
}

udif_tunnel* udif_entity_find_tunnel_by_qstp(udif_entity_context* ctx, const qstp_connection_state* qstpcns)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(qstpcns != NULL);

	udif_tunnel* res;
	size_t i;

	res = NULL;

	if (ctx != NULL && qstpcns != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
		{
			if (ctx->tunnels.entries[i].rolepair != udif_rolepair_none && ctx->tunnels.entries[i].qstpcns == qstpcns)
			{
				res = &ctx->tunnels.entries[i];
				break;
			}
		}
	}

	return res;
}

void udif_entity_remove_tunnel(udif_entity_context* ctx, udif_tunnel* tun, bool notify)
{
	UDIF_ASSERT(ctx != NULL);
	UDIF_ASSERT(tun != NULL);

	if (ctx != NULL && tun != NULL)
	{
		if (tun->rolepair != udif_rolepair_none)
		{
			udif_tunnel_close(tun, notify);
			qsc_memutils_secure_erase((uint8_t*)tun, sizeof(udif_tunnel));

			if (ctx->tunnels.count != 0U)
			{
				ctx->tunnels.count -= 1U;
			}
		}
	}
}

void udif_entity_tick_tunnels(udif_entity_context* ctx, uint64_t nowsecs)
{
	UDIF_ASSERT(ctx != NULL);

	size_t i;
	udif_errors err;

	if (ctx != NULL)
	{
		for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
		{
			if (ctx->tunnels.entries[i].rolepair != udif_rolepair_none)
			{
				err = udif_tunnel_tick(&ctx->tunnels.entries[i], nowsecs);

				if (err != udif_error_none || ctx->tunnels.entries[i].closing == true)
				{
					qsc_memutils_secure_erase((uint8_t*)&ctx->tunnels.entries[i], sizeof(udif_tunnel));

					if (ctx->tunnels.count != 0U)
					{
						ctx->tunnels.count -= 1U;
					}
				}
			}
		}

		/* suppress unused-variable warning from entity_serial_is_zero in release builds */
		(void)entity_serial_is_zero;
	}
}

udif_tunnel* udif_tunneltable_add(udif_tunnel_table* table, const udif_tunnel* tun)
{
	UDIF_ASSERT(table != NULL);
	UDIF_ASSERT(tun != NULL);

    size_t i;
    udif_tunnel* res;

    res = NULL;

    if (table != NULL && tun != NULL)
    {
        for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (table->entries[i].rolepair == udif_rolepair_none)
            {
                qsc_memutils_copy((uint8_t*)&table->entries[i], (const uint8_t*)tun, sizeof(udif_tunnel));
                ++table->count;
                res = &table->entries[i];
                break;
            }
        }
    }

    return res;
}

udif_tunnel* udif_tunneltable_find(udif_tunnel_table* table, const uint8_t* peerserial, const uint8_t* treatyid)
{
	UDIF_ASSERT(table != NULL);
	UDIF_ASSERT(peerserial != NULL);
	UDIF_ASSERT(treatyid != NULL);

    uint8_t zero[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    size_t i;
    udif_tunnel* res;

    res = NULL;

    if (table != NULL && peerserial != NULL)
    {
        for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (table->entries[i].rolepair != udif_rolepair_none &&
                entity_serial_equal(table->entries[i].peerserial, peerserial) == true)
            {
                if (treatyid == NULL ||
                    entity_serial_equal(treatyid, zero) == true ||
                    entity_serial_equal(table->entries[i].treatyid, treatyid) == true)
                {
                    res = &table->entries[i];
                    break;
                }
            }
        }
    }

    return res;
}

udif_tunnel* udif_tunneltable_find_by_qstp(udif_tunnel_table* table, const qstp_connection_state* qstpcns)
{
	UDIF_ASSERT(table != NULL);
	UDIF_ASSERT(qstpcns != NULL);

    size_t i;
    udif_tunnel* res;

    res = NULL;

    if (table != NULL && qstpcns != NULL)
    {
        for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (table->entries[i].rolepair != udif_rolepair_none && table->entries[i].qstpcns == qstpcns)
            {
                res = &table->entries[i];
                break;
            }
        }
    }

    return res;
}

void udif_tunneltable_remove(udif_tunnel_table* table, udif_tunnel* tun, bool notify)
{
	UDIF_ASSERT(table != NULL);
	UDIF_ASSERT(tun != NULL);

    if (table != NULL && tun != NULL)
    {
        if (tun->rolepair != udif_rolepair_none)
        {
            udif_tunnel_close(tun, notify);
            qsc_memutils_secure_erase((uint8_t*)tun, sizeof(udif_tunnel));

            if (table->count != 0U)
            {
                table->count -= 1U;
            }
        }
    }
}

void udif_tunneltable_tick(udif_tunnel_table* table, uint64_t nowsecs)
{
    size_t i;
    udif_errors err;

    if (table != NULL)
    {
        for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (table->entries[i].rolepair != udif_rolepair_none)
            {
                err = udif_tunnel_tick(&table->entries[i], nowsecs);

                if (err != udif_error_none || table->entries[i].closing == true)
                {
                    qsc_memutils_secure_erase((uint8_t*)&table->entries[i], sizeof(udif_tunnel));

                    if (table->count != 0U)
                    {
                        table->count -= 1U;
                    }
                }
            }
        }
    }
}
