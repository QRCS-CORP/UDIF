#include "handler.h"
#include "anchor.h"
#include "capability.h"
#include "certificate.h"
#include "dispatch.h"
#include "entity.h"
#include "event.h"
#include "message.h"
#include "mcelmanager.h"
#include "object.h"
#include "query.h"
#include "registry.h"
#include "storage.h"
#include "treaty.h"
#include "tunnel.h"
#include "udif.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "timestamp.h"

static udif_errors handler_log_membership(udif_mcel_manager* mgr, udif_event_codes eventcode, const uint8_t* actorser, const uint8_t* subjectser, 
    const uint8_t* contextid, uint64_t nowsecs, const uint8_t* data, size_t datalen)
{
    return udif_event_log(mgr, UDIF_LEDGER_MEMBERSHIP, eventcode, actorser, subjectser, contextid, nowsecs, data, datalen);
}

static udif_errors handler_log_transaction(udif_mcel_manager* mgr, udif_event_codes eventcode, const uint8_t* actorser, const uint8_t* subjectser, 
    const uint8_t* contextid, uint64_t nowsecs, const uint8_t* data, size_t datalen)
{
    return udif_event_log(mgr, UDIF_LEDGER_TRANSACTION, eventcode, actorser, subjectser, contextid, nowsecs, data, datalen);
}

static udif_errors handler_log_registry(udif_mcel_manager* mgr, udif_event_codes eventcode, const uint8_t* actorser, const uint8_t* subjectser, 
    const uint8_t* contextid, uint64_t nowsecs, const uint8_t* data, size_t datalen);

static const uint8_t* handler_treaty_verkey_from_serial(const udif_entity_context* ctx, const uint8_t* serial)
{
    const udif_certificate* cert;
    const uint8_t* res;

    res = NULL;

    if (ctx != NULL && serial != NULL)
    {
        if (qsc_memutils_are_equal(ctx->selfcert.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == true)
        {
            res = ctx->selfcert.verkey;
        }
        else
        {
            cert = udif_certstore_find(&ctx->certstore, serial);

            if (cert != NULL)
            {
                res = cert->verkey;
            }
        }
    }

    return res;
}

static bool handler_treaty_matches_tunnel(const udif_treaty* treaty, const udif_entity_context* ctx, const udif_tunnel* tun)
{
    bool res;

    res = false;

    if (treaty != NULL && ctx != NULL && tun != NULL)
    {
        if (qsc_memutils_are_equal(treaty->domsera, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == true &&
            qsc_memutils_are_equal(treaty->domserb, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == true)
        {
            res = true;
        }
        else if (qsc_memutils_are_equal(treaty->domserb, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == true &&
            qsc_memutils_are_equal(treaty->domsera, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == true)
        {
            res = true;
        }
    }

    return res;
}

static bool handler_time_within_window(uint64_t timestamp, uint64_t nowsecs)
{
    uint64_t age;
    bool res;

    res = false;

    if (nowsecs >= timestamp)
    {
        age = nowsecs - timestamp;
        res = (age <= UDIF_TIME_WINDOW_SECONDS);
    }
    else
    {
        age = timestamp - nowsecs;
        res = (age <= UDIF_TIME_WINDOW_SECONDS);
    }

    return res;
}

static bool handler_certificate_is_direct_child(const udif_entity_context* ctx, const uint8_t* serial)
{
    const udif_certificate* cert;
    bool res;

    res = false;

    if (ctx != NULL && serial != NULL)
    {
        cert = udif_certstore_find(&ctx->certstore, serial);

        if (cert != NULL)
        {
            res = qsc_memutils_are_equal(cert->issuer, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE);
        }
    }

    return res;
}


static bool handler_certificate_has_capability(const udif_certificate* cert, uint64_t capability)
{
    bool res;

    res = false;

    if (cert != NULL && capability != 0U)
    {
        res = ((cert->capability & capability) == capability);
    }

    return res;
}

static bool handler_self_has_capability(const udif_entity_context* ctx, uint64_t capability)
{
    bool res;

    res = false;

    if (ctx != NULL)
    {
        res = handler_certificate_has_capability(&ctx->selfcert, capability);
    }

    return res;
}

static bool handler_peer_has_capability(const udif_entity_context* ctx, const udif_tunnel* tun, uint64_t capability)
{
    const udif_certificate* cert;
    bool res;

    res = false;

    if (ctx != NULL && tun != NULL)
    {
        cert = udif_certstore_find(&ctx->certstore, tun->peerserial);

        if (cert != NULL)
        {
            res = handler_certificate_has_capability(cert, capability);
        }
    }

    return res;
}


static bool handler_peer_is_issuer_of_self(const udif_entity_context* ctx, const udif_tunnel* tun)
{
    const udif_certificate* peer;
    bool res;

    res = false;

    if (ctx != NULL && tun != NULL)
    {
        peer = udif_certstore_find(&ctx->certstore, tun->peerserial);

        if (peer != NULL &&
            qsc_memutils_are_equal(ctx->selfcert.issuer, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == true)
        {
            res = true;
        }
    }

    return res;
}

static udif_errors handler_apply_certificate_status_notice(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, 
    uint64_t nowsecs, udif_certstore_status status, udif_event_codes eventcode, uint8_t msgtype, uint64_t requiredcap)
{
    uint8_t log_record[UDIF_SERIAL_NUMBER_SIZE + 1U] = { 0U };
    const uint8_t* actor;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_SERIAL_NUMBER_SIZE)
    {
        log_record[0U] = msgtype;
        qsc_memutils_copy(log_record + 1U, msg->payload, UDIF_SERIAL_NUMBER_SIZE);

        if (qsc_memutils_are_equal(msg->payload, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == true)
        {
            if (handler_peer_is_issuer_of_self(ctx, tun) == false ||
                handler_peer_has_capability(ctx, tun, requiredcap) == false)
            {
                return udif_error_not_authorized;
            }

            actor = tun->peerserial;

            if (ctx->mcelmgr != NULL)
            {
                err = handler_log_membership(ctx->mcelmgr, eventcode, actor, msg->payload, NULL, nowsecs, log_record, sizeof(log_record));

                if (err != udif_error_none)
                {
                    return err;
                }
            }

            return udif_certstore_set_status(&ctx->certstore, msg->payload, status, nowsecs);
        }

        if (handler_self_has_capability(ctx, requiredcap) == false ||
            handler_certificate_is_direct_child(ctx, msg->payload) == false)
        {
            return udif_error_not_authorized;
        }

        actor = ctx->selfcert.serial;
        err = handler_log_membership(ctx->mcelmgr, eventcode, actor, msg->payload, NULL, nowsecs, log_record, sizeof(log_record));

        if (err == udif_error_none)
        {
            err = udif_certstore_set_status(&ctx->certstore, msg->payload, status, nowsecs);
        }
    }

    return err;
}

static uint64_t handler_query_required_capability(udif_query_types qtype)
{
    uint64_t cap;

    switch (qtype)
    {
        case udif_query_exist:
        {
            cap = UDIF_CAP_QUERY_EXIST;
            break;
        }
        case udif_query_owner_binding:
        {
            cap = UDIF_CAP_QUERY_OWNER_BINDING;
            break;
        }
        case udif_query_attr_bucket:
        {
            cap = UDIF_CAP_QUERY_ATTR_BUCKET;
            break;
        }
        case udif_query_membership_proof:
        {
            cap = UDIF_CAP_PROVE_MEMBERSHIP;
            break;
        }
        default:
        {
            cap = 0U;
            break;
        }
    }

    return cap;
}

static udif_errors handler_verify_query_response(const udif_entity_context* ctx, const udif_tunnel* tun, const udif_query_response* resp, uint64_t nowsecs)
{
    const udif_certificate* cert;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && resp != NULL)
    {
        if (handler_time_within_window(resp->timestamp, nowsecs) == false)
        {
            err = udif_error_time_window;
        }
        else if (qsc_memutils_are_equal(resp->respser, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            err = udif_error_not_authorized;
        }
        else
        {
            err = udif_certstore_verify_certificate((udif_certstore*)&ctx->certstore, resp->respser, nowsecs);

            if (err == udif_error_none)
            {
                cert = udif_certstore_find(&ctx->certstore, resp->respser);

                if (cert != NULL)
                {
                    if (udif_query_verify_response_signature(resp, cert->verkey) == true)
                    {
                        err = udif_error_none;
                    }
                    else
                    {
                        err = udif_error_signature_invalid;
                    }
                }
                else
                {
                    err = udif_error_file_not_found;
                }
            }
        }
    }

    return err;
}

static void handler_log_registry_root(udif_entity_context* ctx, const uint8_t* ownerser, uint64_t nowsecs)
{
    uint8_t root[UDIF_CRYPTO_HASH_SIZE];
    udif_registry_state* reg;

    if (ctx != NULL && ownerser != NULL)
    {
        reg = udif_entity_registry_find(ctx, ownerser);

        if (reg != NULL)
        {
            if (udif_registry_compute_root(root, reg) == udif_error_none)
            {
                (void)handler_log_registry(ctx->mcelmgr, udif_audit_event_registry_commit, ctx->selfcert.serial, ownerser, NULL, nowsecs, root, sizeof(root));
                qsc_memutils_clear(root, sizeof(root));
            }
        }
    }
}

static udif_errors handler_log_registry(udif_mcel_manager* mgr, udif_event_codes eventcode, const uint8_t* actorser, const uint8_t* subjectser, 
    const uint8_t* contextid, uint64_t nowsecs, const uint8_t* data, size_t datalen)
{
    return udif_event_log(mgr, UDIF_LEDGER_REGISTRY, eventcode, actorser, subjectser, contextid, nowsecs, data, datalen);
}

static void handler_registry_rollback_added_object(udif_registry_state* reg, const uint8_t* serial)
{
    size_t index;

    if (reg != NULL && serial != NULL && reg->initialized == true)
    {
        if (udif_registry_find_object(reg, serial, &index) == true && index < reg->objcount)
        {
            if ((index + 1U) < reg->objcount)
            {
                qsc_memutils_move(&reg->leaves[index], &reg->leaves[index + 1U], (reg->objcount - index - 1U) * sizeof(udif_registry_leaf));
            }

            --reg->objcount;
            qsc_memutils_clear((uint8_t*)&reg->leaves[reg->objcount], sizeof(udif_registry_leaf));
        }
    }
}

static void handler_entity_remove_empty_registry(udif_entity_context* ctx, const uint8_t* ownerser)
{
    size_t i;

    if (ctx != NULL && ownerser != NULL)
    {
        for (i = 0U; i < UDIF_ENTITY_MAX_REGISTRIES; ++i)
        {
            if (ctx->registries[i].used == true &&
                qsc_memutils_are_equal(ctx->registries[i].ownerser, ownerser, UDIF_SERIAL_NUMBER_SIZE) == true &&
                ctx->registries[i].registry.objcount == 0U)
            {
                udif_registry_dispose(&ctx->registries[i].registry);
                qsc_memutils_clear((uint8_t*)&ctx->registries[i], sizeof(udif_entity_registry_entry));
                break;
            }
        }
    }
}

udif_errors udif_handle_cert_enroll_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_certificate_csr csr = { 0 };
    udif_certificate cert = { 0 };
    udif_message reply = { 0 };
    uint8_t certbuf[UDIF_CERTIFICATE_SIZE] = { 0U };
    size_t certsz;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_CERTIFICATE_CSR_SIZE)
    {
        if (handler_self_has_capability(ctx, UDIF_CAP_ADMIN_ENROLL) == true)
        {
            err = udif_certificate_csr_deserialize(&csr, msg->payload, (size_t)msg->payloadlen);

            if (err == udif_error_none)
            {
                if (qsc_memutils_are_equal(csr.serial, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == true)
                {
                    if ((csr.role != udif_role_ubc && csr.role != udif_role_ugc) && handler_self_has_capability(ctx, UDIF_CAP_ADMIN_BRANCH_CREATE) == true)
                    {
                        if (udif_certstore_find(&ctx->certstore, csr.serial) == NULL)
                        {
                            err = udif_certificate_csr_issue(&cert, &csr, &ctx->selfcert, ctx->selfkeypair.sigkey, nowsecs, qsc_acp_generate);

                            if (err == udif_error_none)
                            {
                                certsz = udif_certificate_serialize_store(certbuf, &cert);

                                if (certsz != 0U)
                                {
                                    err = udif_certstore_add(&ctx->certstore, &cert, udif_certstore_status_active, nowsecs);

                                    if (err == udif_error_none)
                                    {
                                        err = udif_message_init(&reply, udif_msg_cert_enroll_resp, certbuf, (uint32_t)certsz);

                                        if (err == udif_error_none)
                                        {
                                            err = udif_tunnel_send(tun, &reply, nowsecs);
                                            udif_message_dispose(&reply);
                                        }

                                        if (err == udif_error_none)
                                        {
                                            err = handler_log_membership(ctx->mcelmgr, udif_audit_event_cert_enroll_response, ctx->selfcert.serial, cert.serial, NULL, nowsecs, certbuf, certsz);
                                        }

                                        qsc_memutils_secure_erase(certbuf, sizeof(certbuf));
                                        qsc_memutils_secure_erase((uint8_t*)&csr, sizeof(udif_certificate_csr));
                                        qsc_memutils_secure_erase((uint8_t*)&cert, sizeof(udif_certificate));
                                    }
                                    else
                                    {
                                        qsc_memutils_secure_erase(certbuf, sizeof(certbuf));
                                    }
                                }
                                else
                                {
                                    err = udif_error_encode_failure;
                                }
                            }
                        }
                        else
                        {
                            err = udif_error_invalid_state;
                        }
                    }
                    else
                    {
                        err = udif_error_not_authorized;
                    }
                }
                else
                {
                    err = udif_error_not_authorized;
                }
            }
            else
            {
                err = udif_error_decode_failure;
            }
        }
        else
        {
            err = udif_error_not_authorized;
        }
    }

    return err;
}

udif_errors udif_handle_cert_enroll_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_certificate signedcert = { 0 };
    const udif_certificate* issuer;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_CERTIFICATE_SIZE)
    {
        err = udif_certificate_deserialize(&signedcert, msg->payload, (size_t)msg->payloadlen);

        if (err == udif_error_none)
        {
            if (qsc_memutils_are_equal(signedcert.serial, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == true &&
                qsc_memutils_are_equal(signedcert.issuer, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == true &&
                signedcert.suiteid == UDIF_SUITE_ID)
            {
                issuer = udif_certstore_find(&ctx->certstore, signedcert.issuer);

                if (issuer != NULL)
                {
                    err = udif_certstore_verify_certificate(&ctx->certstore, issuer->serial, nowsecs);

                    if (err == udif_error_none)
                    {
                        if (udif_certificate_role_transition_valid(issuer->role, signedcert.role) == true &&
                            udif_certificate_check_capability_inheritance(signedcert.capability, issuer->capability) == true &&
                            signedcert.valid.from >= issuer->valid.from && signedcert.valid.to <= issuer->valid.to &&
                            udif_certificate_verify_chain(&signedcert, issuer) == true)
                        {
                            ctx->selfcert = signedcert;
                            err = udif_certstore_add(&ctx->certstore, &signedcert, udif_certstore_status_active, nowsecs);

                            if (err == udif_error_none)
                            {
                                err = handler_log_membership(ctx->mcelmgr, udif_audit_event_cert_enroll_response, ctx->selfcert.serial, signedcert.serial, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);
                            }

                            qsc_memutils_secure_erase((uint8_t*)&signedcert, sizeof(udif_certificate));
                        }
                    }
                }
                else
                {
                    err = udif_error_file_not_found;
                }
            }
            else
            {
                err = udif_error_not_authorized;
            }
        }
    }

    return err;
}

udif_errors udif_handle_cert_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    return handler_apply_certificate_status_notice(ctx, tun, msg, nowsecs, udif_certstore_status_revoked, udif_audit_event_cert_revoke, (uint8_t)udif_msg_cert_revoke, UDIF_CAP_ADMIN_REVOKE);
}

udif_errors udif_handle_cert_suspend(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    return handler_apply_certificate_status_notice(ctx, tun, msg, nowsecs, udif_certstore_status_suspended, udif_audit_event_cert_suspend, (uint8_t)udif_msg_cert_suspend, UDIF_CAP_ADMIN_SUSPEND);
}

udif_errors udif_handle_cert_resume(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    return handler_apply_certificate_status_notice(ctx, tun, msg, nowsecs, udif_certstore_status_active, udif_audit_event_cert_resume, (uint8_t)udif_msg_cert_resume, UDIF_CAP_ADMIN_RESUME);
}

udif_errors udif_handle_query_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_query q = { 0 };
    udif_query_response resp = { 0 };
    udif_message reply = { 0 };
    const udif_capability* cap;
    const udif_registry_state* registry;
    uint8_t* proof;
    uint8_t* respbuf;
    size_t prooflen;
    size_t respsz;
    udif_errors err;
    uint8_t verdict;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        proof = NULL;
        respbuf = NULL;

        err = udif_query_deserialize(&q, msg->payload, (size_t)msg->payloadlen);

        if (err == udif_error_none)
        {
            /* replay protection: query timestamp must be within the freshness window */
            if (udif_query_is_fresh(&q, nowsecs) == false)
            {
                udif_query_clear(&q);
                return udif_error_time_window;
            }

            if (handler_peer_has_capability(ctx, tun, handler_query_required_capability(q.querytype)) == false)
            {
                udif_query_clear(&q);
                return udif_error_not_authorized;
            }

            (void)handler_log_membership(ctx->mcelmgr, udif_audit_event_query_request, tun->peerserial, q.targser, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

            proof = (uint8_t*)qsc_memutils_malloc(UDIF_QUERY_MAX_PROOF_SIZE);

            if (proof == NULL)
            {
                udif_query_clear(&q);
                return udif_error_internal;
            }

            prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
            cap = udif_capstore_find(&ctx->capstore, q.capabilityref);
            registry = udif_entity_registry_find_const(ctx, q.targser);
            err = udif_query_evaluate_registry(&verdict, proof, &prooflen, &q, registry, cap, tun->peerserial, nowsecs);

            if (err == udif_error_none)
            {
                err = udif_query_create_response(&resp, &q, verdict, proof, prooflen, ctx->selfcert.serial, ctx->selfkeypair.sigkey, nowsecs, qsc_acp_generate);
            }

            udif_query_clear(&q);
            qsc_memutils_secure_erase(proof, UDIF_QUERY_MAX_PROOF_SIZE);
            qsc_memutils_alloc_free(proof);

            if (err != udif_error_none)
            {
                return (err == udif_error_time_window) ? udif_error_time_window : udif_error_internal;
            }

            respsz = UDIF_QUERY_RESPONSE_STRUCTURE_SIZE + resp.prooflen;
            respbuf = (uint8_t*)qsc_memutils_malloc(respsz);

            if (respbuf == NULL)
            {
                udif_query_response_clear(&resp);
                return udif_error_internal;
            }

            err = udif_query_response_serialize(respbuf, &respsz, &resp);
            udif_query_response_clear(&resp);

            if (err != udif_error_none)
            {
                qsc_memutils_secure_erase(respbuf, respsz);
                qsc_memutils_alloc_free(respbuf);
                return udif_error_encode_failure;
            }

            err = udif_message_init(&reply, udif_msg_query_resp, respbuf, (uint32_t)respsz);
            qsc_memutils_secure_erase(respbuf, respsz);
            qsc_memutils_alloc_free(respbuf);

            if (err == udif_error_none)
            {
                err = udif_tunnel_send(tun, &reply, nowsecs);
                udif_message_dispose(&reply);
            }
        }
        else
        {
            err = udif_error_decode_failure;
        }
    }

    return err;
}

udif_errors udif_handle_query_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_query_response resp;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        qsc_memutils_clear((uint8_t*)&resp, sizeof(udif_query_response));

        err = udif_query_response_deserialize(&resp, msg->payload, (size_t)msg->payloadlen);

        if (err == udif_error_none)
        {
            err = handler_verify_query_response(ctx, tun, &resp, nowsecs);

            if (err == udif_error_none)
            {
                err = handler_log_transaction(ctx->mcelmgr, udif_audit_event_query_response, ctx->selfcert.serial, resp.respser, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);
            }
        }
        else
        {
            err = udif_error_decode_failure;
        }

        udif_query_response_clear(&resp);
    }

    return err;
}

udif_errors udif_handle_object_create(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_object obj;
    const udif_certificate* cert;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        qsc_memutils_clear((uint8_t*)&obj, sizeof(udif_object));

        err = udif_object_deserialize(&obj, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            udif_object_clear(&obj);
            return udif_error_decode_failure;
        }

        if (obj.updated < obj.created ||
            handler_time_within_window(obj.created, nowsecs) == false ||
            handler_time_within_window(obj.updated, nowsecs) == false)
        {
            udif_object_clear(&obj);
            return udif_error_time_window;
        }

        if (qsc_memutils_are_equal(obj.owner, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            udif_object_clear(&obj);
            return udif_error_not_authorized;
        }

        err = udif_certstore_verify_certificate(&ctx->certstore, obj.owner, nowsecs);

        if (err != udif_error_none)
        {
            udif_object_clear(&obj);
            return err;
        }

        if (handler_peer_has_capability(ctx, tun, UDIF_CAP_TX_CREATE) == false)
        {
            udif_object_clear(&obj);
            return udif_error_not_authorized;
        }

        cert = udif_certstore_find(&ctx->certstore, obj.owner);

        if (cert == NULL || udif_object_verify(&obj, cert->verkey) == false)
        {
            udif_object_clear(&obj);
            return udif_error_signature_invalid;
        }

        {
            udif_registry_state* reg;
            bool registry_existed;

            registry_existed = (udif_entity_registry_find(ctx, obj.owner) != NULL);
            reg = udif_entity_registry_get_or_create(ctx, obj.owner, UDIF_REGISTRY_DEFAULT_CAPACITY);

            if (reg == NULL)
            {
                udif_object_clear(&obj);
                return udif_error_internal;
            }

            err = udif_registry_add_object(reg, &obj);

            if (err == udif_error_none)
            {
                err = handler_log_transaction(ctx->mcelmgr, udif_audit_event_object_create, ctx->selfcert.serial, obj.owner, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

                if (err != udif_error_none)
                {
                    handler_registry_rollback_added_object(reg, obj.serial);

                    if (registry_existed == false)
                    {
                        handler_entity_remove_empty_registry(ctx, obj.owner);
                    }
                }
            }
        }

        if (err == udif_error_none)
        {
            handler_log_registry_root(ctx, obj.owner, nowsecs);
        }

        udif_object_clear(&obj);
    }

    return err;
}

udif_errors udif_handle_object_transfer_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_transfer_record transfer = { 0 };
    const udif_certificate* sendcert;
    const udif_certificate* recvcert;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        qsc_memutils_clear((uint8_t*)&transfer, sizeof(udif_transfer_record));

        err = udif_transfer_deserialize(&transfer, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            udif_transfer_clear(&transfer);
            return udif_error_decode_failure;
        }

        if (handler_time_within_window(transfer.timestamp, nowsecs) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_time_window;
        }

        if (qsc_memutils_are_equal(transfer.originator, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_not_authorized;
        }

        err = udif_certstore_verify_certificate(&ctx->certstore, transfer.originator, nowsecs);

        if (err == udif_error_none)
        {
            err = udif_certstore_verify_certificate(&ctx->certstore, transfer.owner, nowsecs);
        }

        if (err != udif_error_none)
        {
            udif_transfer_clear(&transfer);
            return err;
        }

        if (handler_peer_has_capability(ctx, tun, UDIF_CAP_TX_CREATE) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_not_authorized;
        }

        sendcert = udif_certstore_find(&ctx->certstore, transfer.originator);
        recvcert = udif_certstore_find(&ctx->certstore, transfer.owner);

        if (sendcert == NULL || recvcert == NULL || udif_transfer_verify(&transfer, sendcert->verkey, recvcert->verkey) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_signature_invalid;
        }

        /* log the pending transfer */
        err = handler_log_transaction(ctx->mcelmgr, udif_audit_event_object_transfer_request, ctx->selfcert.serial, transfer.originator, transfer.txid, nowsecs, msg->payload, (size_t)msg->payloadlen);

        udif_transfer_clear(&transfer);
    }

    return err;
}

udif_errors udif_handle_object_transfer_confirm(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_transfer_record transfer = { 0 };
    const udif_certificate* sendcert;
    const udif_certificate* recvcert;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        qsc_memutils_clear((uint8_t*)&transfer, sizeof(udif_transfer_record));

        err = udif_transfer_deserialize(&transfer, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            udif_transfer_clear(&transfer);
            return udif_error_decode_failure;
        }

        if (handler_time_within_window(transfer.timestamp, nowsecs) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_time_window;
        }

        if (qsc_memutils_are_equal(transfer.owner, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_not_authorized;
        }

        err = udif_certstore_verify_certificate(&ctx->certstore, transfer.originator, nowsecs);

        if (err == udif_error_none)
        {
            err = udif_certstore_verify_certificate(&ctx->certstore, transfer.owner, nowsecs);
        }

        if (err != udif_error_none)
        {
            udif_transfer_clear(&transfer);
            return err;
        }

        if (handler_peer_has_capability(ctx, tun, UDIF_CAP_TX_ACCEPT) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_not_authorized;
        }

        sendcert = udif_certstore_find(&ctx->certstore, transfer.originator);
        recvcert = udif_certstore_find(&ctx->certstore, transfer.owner);

        if (sendcert == NULL || recvcert == NULL || udif_transfer_verify(&transfer, sendcert->verkey, recvcert->verkey) == false)
        {
            udif_transfer_clear(&transfer);
            return udif_error_signature_invalid;
        }

        {
            udif_registry_state* origin;
            udif_registry_state* dest;
            udif_registry_leaf originleaf = { 0 };

            origin = udif_entity_registry_find(ctx, transfer.originator);
            dest = udif_entity_registry_get_or_create(ctx, transfer.owner, UDIF_REGISTRY_DEFAULT_CAPACITY);

            if (origin == NULL)
            {
                udif_transfer_clear(&transfer);
                return udif_error_object_not_found;
            }

            if (dest == NULL)
            {
                udif_transfer_clear(&transfer);
                return udif_error_internal;
            }

            if (qsc_memutils_are_equal(origin->ownerser, transfer.originator, UDIF_SERIAL_NUMBER_SIZE) == false ||
                qsc_memutils_are_equal(dest->ownerser, transfer.owner, UDIF_SERIAL_NUMBER_SIZE) == false)
            {
                udif_transfer_clear(&transfer);
                return udif_error_not_authorized;
            }

            err = udif_registry_get_leaf(&originleaf, origin, transfer.serial);

            if (err == udif_error_none)
            {
                if ((originleaf.flags & UDIF_REGISTRY_FLAG_ACTIVE) == 0U ||
                    (originleaf.flags & UDIF_REGISTRY_FLAG_DESTROYED) != 0U)
                {
                    err = udif_error_invalid_state;
                }
                else if (udif_registry_find_object(dest, transfer.serial, NULL) == false &&
                    dest->objcount >= dest->capacity)
                {
                    err = udif_error_registry_full;
                }
            }

            if (err == udif_error_none)
            {
                err = handler_log_transaction(ctx->mcelmgr, udif_audit_event_object_transfer_confirm, ctx->selfcert.serial, transfer.owner, transfer.txid, nowsecs, msg->payload, (size_t)msg->payloadlen);
            }

            if (err == udif_error_none)
            {
                err = udif_registry_transfer_object(origin, dest, &transfer);
            }
        }

        if (err == udif_error_none)
        {
            handler_log_registry_root(ctx, transfer.originator, nowsecs);
            handler_log_registry_root(ctx, transfer.owner, nowsecs);
        }

        udif_transfer_clear(&transfer);
    }

    return err;
}

udif_errors udif_handle_registry_commit(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_registry_commit commit = { 0 };
    const udif_certificate* peercert;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_REGISTRY_COMMIT_STRUCTURE_SIZE)
    {
        err = udif_registry_commit_deserialize(&commit, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            udif_registry_commit_clear(&commit);
            return err;
        }

        if (qsc_memutils_are_equal(commit.ownerser, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            udif_registry_commit_clear(&commit);
            return udif_error_not_authorized;
        }

        if (commit.timestamp > (nowsecs + UDIF_TIME_WINDOW_SECONDS) || (nowsecs > commit.timestamp && (nowsecs - commit.timestamp) > UDIF_TIME_WINDOW_SECONDS))
        {
            udif_registry_commit_clear(&commit);
            return udif_error_time_window;
        }

        err = udif_certstore_verify_certificate(&ctx->certstore, commit.ownerser, nowsecs);

        if (err != udif_error_none)
        {
            udif_registry_commit_clear(&commit);
            return err;
        }

        if (handler_peer_has_capability(ctx, tun, UDIF_CAP_REGISTRY_COMMIT) == false)
        {
            udif_registry_commit_clear(&commit);
            return udif_error_not_authorized;
        }

        peercert = udif_certstore_find(&ctx->certstore, commit.ownerser);

        if (peercert == NULL || udif_registry_commit_verify(&commit, peercert->verkey) == false)
        {
            udif_registry_commit_clear(&commit);
            return udif_error_signature_invalid;
        }

        err = handler_log_registry(ctx->mcelmgr, udif_audit_event_registry_commit, ctx->selfcert.serial, commit.ownerser, commit.regroot, nowsecs, msg->payload, (size_t)msg->payloadlen);

        udif_registry_commit_clear(&commit);
    }

    return err;
}

udif_errors udif_handle_anchor_push(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_anchor_record anchor = { 0 };
    udif_message ack = { 0 };
    const udif_certificate* childcert;
    uint8_t ackpayload[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    uint64_t expseq;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        err = udif_anchor_deserialize(&anchor, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            return udif_error_decode_failure;
        }

        /* freshness check: anchor timestamp must be within UDIF_ANCHOR_MAX_AGE_MAX */
        if (udif_anchor_is_fresh(&anchor, nowsecs, UDIF_ANCHOR_MAX_AGE_MAX) == false)
        {
            udif_anchor_clear(&anchor);
            return udif_error_time_window;
        }

        if (qsc_memutils_are_equal(anchor.childser, tun->peerserial, UDIF_SERIAL_NUMBER_SIZE) == false)
        {
            udif_anchor_clear(&anchor);
            return udif_error_not_authorized;
        }

        err = udif_certstore_verify_certificate(&ctx->certstore, anchor.childser, nowsecs);

        if (err != udif_error_none)
        {
            udif_anchor_clear(&anchor);
            return err;
        }

        if (handler_self_has_capability(ctx, UDIF_CAP_LOG_ANCHOR_VERIFY) == false ||
            handler_peer_has_capability(ctx, tun, UDIF_CAP_LOG_ANCHOR_SEND) == false)
        {
            udif_anchor_clear(&anchor);
            return udif_error_not_authorized;
        }

        err = udif_entity_anchor_expected_sequence(ctx, anchor.childser, &expseq);

        if (err != udif_error_none)
        {
            udif_anchor_clear(&anchor);
            return err;
        }

        childcert = udif_certstore_find(&ctx->certstore, anchor.childser);

        if (childcert == NULL || udif_anchor_verify(&anchor, childcert->verkey, expseq) == false)
        {
            udif_anchor_clear(&anchor);
            return udif_error_anchor_invalid;
        }

        /* log the anchor record to the membership ledger */
        err = handler_log_membership(ctx->mcelmgr, udif_audit_event_anchor_push, ctx->selfcert.serial, anchor.childser, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            udif_anchor_clear(&anchor);
            return err;
        }

        err = udif_entity_anchor_commit_sequence(ctx, anchor.childser, anchor.sequence);

        if (err != udif_error_none)
        {
            udif_anchor_clear(&anchor);
            return err;
        }

        /* send an ack: payload is the child serial echoed back */
        qsc_memutils_copy(ackpayload, anchor.childser, UDIF_SERIAL_NUMBER_SIZE);
        udif_anchor_clear(&anchor);

        err = udif_message_init(&ack, udif_msg_anchor_ack, ackpayload, (uint32_t)sizeof(ackpayload));

        if (err == udif_error_none)
        {
            err = udif_tunnel_send(tun, &ack, nowsecs);
            udif_message_dispose(&ack);
        }
    }

    return err;
}

udif_errors udif_handle_anchor_ack(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_errors err;

    (void)tun;
    err = udif_error_invalid_input;

    if (ctx != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen == UDIF_SERIAL_NUMBER_SIZE)
    {
        if (qsc_memutils_are_equal(msg->payload, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == true &&
            handler_self_has_capability(ctx, UDIF_CAP_LOG_ANCHOR_SEND) == true &&
            handler_peer_has_capability(ctx, tun, UDIF_CAP_LOG_ANCHOR_VERIFY) == true)
        {
            /* log the acknowledgement so the audit trail is complete */
            err = handler_log_membership(ctx->mcelmgr, udif_audit_event_anchor_ack, ctx->selfcert.serial, msg->payload, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

        }
        else
        {
            err = udif_error_not_authorized;
        }
    }

    return err;
}

udif_errors udif_handle_treaty_propose(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_treaty treaty = { 0 };
    uint8_t tbuf[UDIF_TREATY_STRUCTURE_SIZE] = { 0U };
    udif_message reply = { 0 };
    size_t tsz;
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        err = udif_treaty_deserialize(&treaty, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            return udif_error_decode_failure;
        }

        /* validate the treaty's structural invariants */
        err = udif_treaty_validate(&treaty);

        if (err != udif_error_none)
        {
            udif_treaty_clear(&treaty);
            return udif_error_treaty_invalid;
        }

        if (udif_treaty_is_expired(&treaty, nowsecs) == true)
        {
            udif_treaty_clear(&treaty);
            return udif_error_certificate_expired;
        }

        if (handler_treaty_matches_tunnel(&treaty, ctx, tun) == false ||
            qsc_memutils_are_equal(treaty.domserb, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == false ||
            handler_self_has_capability(ctx, UDIF_CAP_TREATY_NEGOTIATE) == false ||
            handler_peer_has_capability(ctx, tun, UDIF_CAP_TREATY_NEGOTIATE) == false)
        {
            udif_treaty_clear(&treaty);
            return udif_error_not_authorized;
        }

        if (udif_treaty_verify_proposal(&treaty, handler_treaty_verkey_from_serial(ctx, treaty.domsera)) == false)
        {
            udif_treaty_clear(&treaty);
            return udif_error_signature_invalid;
        }

        /* accept the treaty by co-signing it with our domain signing key */
        err = udif_treaty_accept(&treaty, ctx->selfkeypair.sigkey, qsc_acp_generate);

        if (err != udif_error_none)
        {
            udif_treaty_clear(&treaty);
            return err;
        }

        /* serialize and send the cosign message */
        tsz = udif_treaty_encoded_size(&treaty);

        if (tsz == 0U || tsz > sizeof(tbuf))
        {
            udif_treaty_clear(&treaty);
            return udif_error_encode_failure;
        }

        err = udif_treaty_serialize(tbuf, tsz, &treaty);

        if (err == udif_error_none)
        {
            err = udif_treatystore_add(&ctx->treatystore, &treaty, udif_treatystore_status_active, nowsecs);
        }

        udif_treaty_clear(&treaty);

        if (err != udif_error_none)
        {
            return udif_error_encode_failure;
        }

        err = udif_message_init(&reply, udif_msg_treaty_cosign, tbuf, (uint32_t)tsz);

        if (err == udif_error_none)
        {
            err = udif_tunnel_send(tun, &reply, nowsecs);
            udif_message_dispose(&reply);
        }

        if (err == udif_error_none)
        {
            /* log the accepted treaty proposal */
            handler_log_membership(ctx->mcelmgr, udif_audit_event_treaty_propose, ctx->selfcert.serial, tun->peerserial, NULL, nowsecs, tbuf, tsz);
        }
    }

    return err;
}

udif_errors udif_handle_treaty_cosign(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_treaty treaty = { 0 };
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        err = udif_treaty_deserialize(&treaty, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            return udif_error_decode_failure;
        }

        if (handler_treaty_matches_tunnel(&treaty, ctx, tun) == false ||
            qsc_memutils_are_equal(treaty.domsera, ctx->selfcert.serial, UDIF_SERIAL_NUMBER_SIZE) == false ||
            handler_self_has_capability(ctx, UDIF_CAP_TREATY_NEGOTIATE) == false ||
            handler_peer_has_capability(ctx, tun, UDIF_CAP_TREATY_NEGOTIATE) == false)
        {
            udif_treaty_clear(&treaty);
            return udif_error_not_authorized;
        }

        if (udif_treaty_verify(&treaty, handler_treaty_verkey_from_serial(ctx, treaty.domsera),
            handler_treaty_verkey_from_serial(ctx, treaty.domserb)) == false)
        {
            udif_treaty_clear(&treaty);
            return udif_error_signature_invalid;
        }

        err = udif_treatystore_add(&ctx->treatystore, &treaty, udif_treatystore_status_active, nowsecs);

        if (err == udif_error_none)
        {
            /* Log the cosigned (now active) treaty */
            err = handler_log_membership(ctx->mcelmgr, udif_audit_event_treaty_cosign, ctx->selfcert.serial, tun->peerserial, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);
        }

        udif_treaty_clear(&treaty);
    }

    return err;
}

udif_errors udif_handle_treaty_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        if (msg->payloadlen == UDIF_SERIAL_NUMBER_SIZE)
        {
            if (handler_self_has_capability(ctx, UDIF_CAP_TREATY_NEGOTIATE) == true && handler_peer_has_capability(ctx, tun, UDIF_CAP_TREATY_NEGOTIATE) == true)
            {
                {
                    const udif_treaty* treaty;

                    treaty = udif_treatystore_find(&ctx->treatystore, msg->payload);

                    if (treaty == NULL || handler_treaty_matches_tunnel(treaty, ctx, tun) == false ||
                        udif_treatystore_get_status(&ctx->treatystore, msg->payload) != udif_treatystore_status_active)
                    {
                        return udif_error_treaty_invalid;
                    }
                }

                /* log the revocation event before mutating treaty state; the treaty ID is in the payload */
                err = handler_log_membership(ctx->mcelmgr, udif_audit_event_treaty_revoke, ctx->selfcert.serial, tun->peerserial, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

                if (err == udif_error_none)
                {
                    err = udif_treatystore_set_status(&ctx->treatystore, msg->payload, udif_treatystore_status_revoked, nowsecs);
                }
            }
            else
            {
                err = udif_error_not_authorized;
            }
        }
        else
        {
            err = udif_error_treaty_invalid;
        }
    }

    return err;
}

udif_errors udif_handle_treaty_query_fwd(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_query q = { 0 };
    udif_query_response resp = { 0 };
    udif_message reply = { 0 };
    const udif_capability* cap;
    const udif_registry_state* registry;
    uint8_t* proof;
    uint8_t* respbuf;
    size_t prooflen;
    size_t respsz;
    udif_errors err;
    uint8_t verdict;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        err = udif_query_deserialize(&q, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            return udif_error_decode_failure;
        }

        if (udif_query_is_fresh(&q, nowsecs) == false)
        {
            udif_query_clear(&q);
            return udif_error_time_window;
        }

        if (udif_treatystore_find_active_for_query(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, q.querytype, nowsecs) == NULL ||
            handler_self_has_capability(ctx, UDIF_CAP_TREATY_QUERY_EXEC) == false ||
            handler_peer_has_capability(ctx, tun, UDIF_CAP_TREATY_QUERY_ORIGIN) == false)
        {
            udif_query_clear(&q);
            return udif_error_not_authorized;
        }

        (void)handler_log_membership(ctx->mcelmgr, udif_audit_event_treaty_query_forward, tun->peerserial, q.targser, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);

        proof = (uint8_t*)qsc_memutils_malloc(UDIF_QUERY_MAX_PROOF_SIZE);

        if (proof == NULL)
        {
            udif_query_clear(&q);
            return udif_error_internal;
        }

        prooflen = UDIF_QUERY_MAX_PROOF_SIZE;
        cap = udif_capstore_find(&ctx->capstore, q.capabilityref);
        registry = udif_entity_registry_find_const(ctx, q.targser);
        err = udif_query_evaluate_registry(&verdict, proof, &prooflen, &q, registry, cap, tun->peerserial, nowsecs);

        if (err == udif_error_none)
        {
            err = udif_query_create_response(&resp, &q, verdict, proof, prooflen, ctx->selfcert.serial, ctx->selfkeypair.sigkey, nowsecs, qsc_acp_generate);
        }

        udif_query_clear(&q);
        qsc_memutils_clear(proof, UDIF_QUERY_MAX_PROOF_SIZE);
        qsc_memutils_alloc_free(proof);

        if (err != udif_error_none)
        {
            return (err == udif_error_time_window) ? udif_error_time_window : udif_error_internal;
        }

        respsz = UDIF_QUERY_RESPONSE_STRUCTURE_SIZE + resp.prooflen;
        respbuf = (uint8_t*)qsc_memutils_malloc(respsz);

        if (respbuf == NULL)
        {
            udif_query_response_clear(&resp);
            return udif_error_internal;
        }

        err = udif_query_response_serialize(respbuf, &respsz, &resp);
        udif_query_response_clear(&resp);

        if (err != udif_error_none)
        {
            qsc_memutils_clear(respbuf, respsz);
            qsc_memutils_alloc_free(respbuf);
            return udif_error_encode_failure;
        }

        /* Reply using treaty_query_resp message type */
        err = udif_message_init(&reply, udif_msg_treaty_query_resp, respbuf, (uint32_t)respsz);
        qsc_memutils_clear(respbuf, respsz);
        qsc_memutils_alloc_free(respbuf);

        if (err == udif_error_none)
        {
            err = udif_tunnel_send(tun, &reply, nowsecs);
            udif_message_dispose(&reply);
        }
    }

    return err;
}

udif_errors udif_handle_treaty_query_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    udif_query_response resp = { 0 };
    udif_errors err;

    err = udif_error_invalid_input;

    if (ctx != NULL && tun != NULL && msg != NULL && msg->payload != NULL && msg->payloadlen != 0U)
    {
        err = udif_query_response_deserialize(&resp, msg->payload, (size_t)msg->payloadlen);

        if (err != udif_error_none)
        {
            return udif_error_decode_failure;
        }

        if ((udif_treatystore_find_active_for_query(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, udif_query_exist, nowsecs) == NULL &&
            udif_treatystore_find_active_for_query(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, udif_query_owner_binding, nowsecs) == NULL &&
            udif_treatystore_find_active_for_query(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, udif_query_attr_bucket, nowsecs) == NULL &&
            udif_treatystore_find_active_for_query(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, udif_query_membership_proof, nowsecs) == NULL) ||
            handler_self_has_capability(ctx, UDIF_CAP_TREATY_QUERY_ORIGIN) == false ||
            handler_peer_has_capability(ctx, tun, UDIF_CAP_TREATY_QUERY_EXEC) == false)
        {
            udif_query_response_clear(&resp);
            return udif_error_not_authorized;
        }

        err = udif_treatystore_consume_pending_response(&ctx->treatystore, ctx->selfcert.serial, tun->peerserial, &resp, nowsecs);

        if (err == udif_error_none)
        {
            err = handler_verify_query_response(ctx, tun, &resp, nowsecs);
        }

        if (err == udif_error_none)
        {
            err = handler_log_transaction(ctx->mcelmgr, udif_audit_event_treaty_query_response, ctx->selfcert.serial, resp.respser, NULL, nowsecs, msg->payload, (size_t)msg->payloadlen);
        }

        udif_query_response_clear(&resp);
    }

    return err;
}

udif_errors udif_handle_error_report(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(msg != NULL);

    uint8_t log_record[2U] = { 0U };
    udif_errors err;

    (void)tun;
    err = udif_error_invalid_input;

    if (ctx != NULL && msg != NULL)
    {
        /* build a compact log entry: message_type(1) || error_code(1) */
        log_record[0U] = (uint8_t)udif_msg_error_report;
        log_record[1U] = (msg->payload != NULL && msg->payloadlen >= 1U)
            ? msg->payload[0U]
            : (uint8_t)udif_error_none;

        err = handler_log_membership(ctx->mcelmgr, udif_audit_event_error_report, ctx->selfcert.serial, NULL, NULL, nowsecs, log_record, sizeof(log_record));

        /* errors in error-report logging are silently suppressed to avoid
         * creating a loop through the dispatcher. */
        (void)err;
    }

    return udif_error_none;
}
