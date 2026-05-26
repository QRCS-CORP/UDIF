#include "handler_conformance_test.h"

#include "capability.h"
#include "certificate.h"
#include "certstore.h"
#include "dispatch.h"
#include "entity.h"
#include "mcelmanager.h"
#include "message.h"
#include "object.h"
#include "query.h"
#include "registry.h"
#include "tunnel.h"
#include "udif.h"
#include "consoleutils.h"
#include "folderutils.h"
#include "csp.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

#define HANDLER_CONFORMANCE_TEST_BRANCH_CAPABILITIES (UDIF_CAP_CORE_DEFINED_MASK)
#define HANDLER_CONFORMANCE_TEST_CLIENT_CAPABILITIES (UDIF_CLIENT_CAPABILITIES)
#define HANDLER_CONFORMANCE_TEST_BASE_PATH "UDIF"
#define HANDLER_CONFORMANCE_TEST_DIRECTORY_PREFIX "handler_conf_"

static uint64_t m_handler_conformance_directory_counter = 0U;

typedef struct handler_conformance_node
{
    udif_certificate cert;
    udif_signature_keypair keypair;
} handler_conformance_node;

static void handler_conformance_print(const char* message)
{
    if (message != NULL)
    {
        qsc_consoleutils_print_line(message);
    }
}

static void handler_conformance_clear_node(handler_conformance_node* node)
{
    if (node != NULL)
    {
        udif_certificate_clear(&node->cert);
        qsc_memutils_clear((uint8_t*)&node->keypair, sizeof(handler_conformance_node) - sizeof(udif_certificate));
    }
}


static bool handler_conformance_setup_mcel_directory(char dir[QSC_SYSTEM_MAX_PATH])
{
    char num[32U] = { 0U };
    uint64_t nonce;
    bool res;

    res = false;

    if (dir != NULL)
    {
#if defined(QSC_SYSTEM_OS_WINDOWS)
        qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dir);
#else
        qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dir);
#endif
        qsc_folderutils_append_delimiter(dir);
        qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, HANDLER_CONFORMANCE_TEST_BASE_PATH);

        if (qsc_folderutils_directory_exists(dir) == false)
        {
            qsc_folderutils_create_directory_tree(dir);
        }

        qsc_folderutils_append_delimiter(dir);
        qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, HANDLER_CONFORMANCE_TEST_DIRECTORY_PREFIX);
        nonce = qsc_timestamp_epochtime_milliseconds() + m_handler_conformance_directory_counter;
        ++m_handler_conformance_directory_counter;
        qsc_stringutils_uint64_to_string(nonce, num, sizeof(num));
        qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, num);

        if (qsc_folderutils_directory_exists(dir) == true)
        {
            qsc_folderutils_delete_directory(dir);
        }

        res = qsc_folderutils_create_directory_tree(dir);
    }

    return res;
}

static udif_errors handler_conformance_create_root(handler_conformance_node* node, uint64_t nowsecs)
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

static udif_errors handler_conformance_issue_child(handler_conformance_node* child, const handler_conformance_node* parent,
    udif_roles role, uint64_t capability, uint64_t nowsecs)
{
    udif_certificate_csr csr;
    udif_valid_time vt;
    uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    udif_errors err;

    qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
    qsc_memutils_clear((uint8_t*)child, sizeof(handler_conformance_node));
    vt.from = nowsecs;
    vt.to = nowsecs + (UDIF_CERTIFICATE_DEFAULT_PERIOD / 2U);
    qsc_csp_generate(serial, sizeof(serial));
    udif_signature_generate_keypair(child->keypair.verkey, child->keypair.sigkey, qsc_csp_generate);

    err = udif_certificate_csr_create(&csr, serial, child->keypair.verkey, child->keypair.sigkey,
        role, &vt, capability, 0U, nowsecs, qsc_csp_generate);

    if (err == udif_error_none)
    {
        err = udif_certificate_csr_issue(&child->cert, &csr, &parent->cert, parent->keypair.sigkey, nowsecs, qsc_csp_generate);
    }

    qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));

    return err;
}

static void handler_conformance_init_context(udif_entity_context* ctx, const handler_conformance_node* self)
{
    char dir[QSC_SYSTEM_MAX_PATH] = { 0U };

    qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
    ctx->selfcert = self->cert;
    ctx->selfkeypair = self->keypair;
    ctx->role = self->cert.role;
    udif_certstore_initialize(&ctx->certstore);
    udif_capstore_initialize(&ctx->capstore);
    udif_treatystore_initialize(&ctx->treatystore);

    if (handler_conformance_setup_mcel_directory(dir) == true)
    {
        ctx->mcelmgr = udif_mcel_initialize(dir, NULL);
    }
}

static void handler_conformance_clear_context(udif_entity_context* ctx)
{
    if (ctx != NULL)
    {
        if (ctx->mcelmgr != NULL)
        {
            udif_mcel_dispose(ctx->mcelmgr);
            ctx->mcelmgr = NULL;
        }

        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
    }
}

static void handler_conformance_init_tunnel(udif_tunnel* tun, const uint8_t* peerserial)
{
    qsc_memutils_clear((uint8_t*)tun, sizeof(udif_tunnel));
    qsc_memutils_copy(tun->peerserial, peerserial, UDIF_SERIAL_NUMBER_SIZE);
    tun->rolepair = udif_rolepair_ua_gc;
}

static bool handler_conformance_prepare_root_peer(udif_entity_context* ctx, handler_conformance_node* root,
    handler_conformance_node* peer, uint64_t nowsecs)
{
    udif_errors err;
    bool res;

    res = false;
    err = handler_conformance_create_root(root, nowsecs);

    if (err == udif_error_none)
    {
        err = handler_conformance_issue_child(peer, root, udif_role_ubc,
            HANDLER_CONFORMANCE_TEST_BRANCH_CAPABILITIES, nowsecs);
    }

    if (err == udif_error_none)
    {
        handler_conformance_init_context(ctx, root);
        err = udif_certstore_add(&ctx->certstore, &root->cert, udif_certstore_status_active, nowsecs);
    }

    if (err == udif_error_none)
    {
        err = udif_certstore_add(&ctx->certstore, &peer->cert, udif_certstore_status_active, nowsecs);
    }

    if (err == udif_error_none)
    {
        res = true;
    }

    return res;
}

static bool handler_conformance_enroll_rejects_non_csr_payload(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_tunnel tun;
    udif_message msg;
    uint8_t certbuf[UDIF_CERTIFICATE_SIZE];
    uint64_t nowsecs;
    size_t certsz;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        nowsecs = qsc_timestamp_datetime_utc();

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            handler_conformance_init_tunnel(&tun, peer.cert.serial);
            certsz = udif_certificate_serialize_store(certbuf, &peer.cert);
            err = udif_message_init(&msg, udif_msg_cert_enroll_req, certbuf, (uint32_t)certsz);

            if (err == udif_error_none)
            {
                err = udif_handle_cert_enroll_req(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_invalid_input || err == udif_error_decode_failure);
                udif_message_dispose(&msg);
            }

            qsc_memutils_clear(certbuf, sizeof(certbuf));
        }

        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_enroll_rejects_peer_serial_mismatch(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    handler_conformance_node other;
    udif_certificate_csr csr;
    udif_valid_time vt;
    udif_tunnel tun;
    udif_message msg;
    uint8_t csrbuf[UDIF_CERTIFICATE_CSR_SIZE];
    uint64_t nowsecs;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&other, sizeof(other));
        qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        nowsecs = qsc_timestamp_datetime_utc();

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            vt.from = nowsecs;
            vt.to = nowsecs + 3600U;
            qsc_csp_generate(other.cert.serial, sizeof(other.cert.serial));
            udif_signature_generate_keypair(other.keypair.verkey, other.keypair.sigkey, qsc_csp_generate);
            err = udif_certificate_csr_create(&csr, other.cert.serial, other.keypair.verkey, other.keypair.sigkey,
                udif_role_client, &vt, UDIF_CLIENT_CAPABILITIES, 0U, nowsecs, qsc_csp_generate);

            if (err == udif_error_none)
            {
                err = udif_certificate_csr_serialize(csrbuf, sizeof(csrbuf), &csr);
            }

            if (err == udif_error_none)
            {
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_cert_enroll_req, csrbuf, sizeof(csrbuf));
            }

            if (err == udif_error_none)
            {
                err = udif_handle_cert_enroll_req(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_not_authorized);
                udif_message_dispose(&msg);
            }
        }

        qsc_memutils_clear(csrbuf, sizeof(csrbuf));
        qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_node(&other);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_enroll_rejects_duplicate_serial(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_certificate_csr csr;
    udif_valid_time vt;
    udif_tunnel tun;
    udif_message msg;
    uint8_t csrbuf[UDIF_CERTIFICATE_CSR_SIZE];
    uint64_t nowsecs;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        nowsecs = qsc_timestamp_datetime_utc();

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            vt.from = nowsecs;
            vt.to = nowsecs + 3600U;
            err = udif_certificate_csr_create(&csr, peer.cert.serial, peer.keypair.verkey, peer.keypair.sigkey,
                udif_role_client, &vt, UDIF_CLIENT_CAPABILITIES, 0U, nowsecs, qsc_csp_generate);

            if (err == udif_error_none)
            {
                err = udif_certificate_csr_serialize(csrbuf, sizeof(csrbuf), &csr);
            }

            if (err == udif_error_none)
            {
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_cert_enroll_req, csrbuf, sizeof(csrbuf));
            }

            if (err == udif_error_none)
            {
                err = udif_handle_cert_enroll_req(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_invalid_state);
                udif_message_dispose(&msg);
            }
        }

        qsc_memutils_clear(csrbuf, sizeof(csrbuf));
        qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_registry_commit_rejects_raw_root(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_tunnel tun;
    udif_message msg;
    uint8_t rootbytes[UDIF_CRYPTO_HASH_SIZE];
    uint64_t nowsecs;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        qsc_memutils_clear(rootbytes, sizeof(rootbytes));
        nowsecs = qsc_timestamp_datetime_utc();

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            handler_conformance_init_tunnel(&tun, peer.cert.serial);
            err = udif_message_init(&msg, udif_msg_registry_commit, rootbytes, sizeof(rootbytes));

            if (err == udif_error_none)
            {
                err = udif_handle_registry_commit(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_invalid_input);
                udif_message_dispose(&msg);
            }
        }

        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_query_response_rejects_tamper(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_query query;
    udif_query_response resp;
    udif_tunnel tun;
    udif_message msg;
    uint8_t queryid[UDIF_QUERY_ID_SIZE];
    uint8_t objectser[UDIF_OBJECT_SERIAL_SIZE];
    uint8_t capref[UDIF_CRYPTO_HASH_SIZE];
    uint8_t respbuf[UDIF_QUERY_RESPONSE_STRUCTURE_SIZE];
    uint64_t nowsecs;
    size_t respsz;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&query, sizeof(query));
        qsc_memutils_clear((uint8_t*)&resp, sizeof(resp));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        nowsecs = qsc_timestamp_datetime_utc();
        qsc_csp_generate(queryid, sizeof(queryid));
        qsc_csp_generate(objectser, sizeof(objectser));
        qsc_memutils_clear(capref, sizeof(capref));

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            err = udif_query_create_existence(&query, queryid, root.cert.serial, objectser, nowsecs, capref);

            if (err == udif_error_none)
            {
                err = udif_query_create_response(&resp, &query, udif_verdict_yes, NULL, 0U,
                    peer.cert.serial, peer.keypair.sigkey, nowsecs, qsc_csp_generate);
            }

            if (err == udif_error_none)
            {
                respsz = sizeof(respbuf);
                err = udif_query_response_serialize(respbuf, &respsz, &resp);
            }

            if (err == udif_error_none)
            {
                respbuf[UDIF_SIGNED_HASH_SIZE + UDIF_QUERY_ID_SIZE + UDIF_SERIAL_NUMBER_SIZE] ^= 0x01U;
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_query_resp, respbuf, (uint32_t)respsz);
            }

            if (err == udif_error_none)
            {
                err = udif_handle_query_resp(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_signature_invalid);
                udif_message_dispose(&msg);
            }
        }

        udif_query_response_clear(&resp);
        udif_query_clear(&query);
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_query_request_requires_certificate_capability(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_query query;
    udif_tunnel tun;
    udif_message msg;
    uint8_t queryid[UDIF_QUERY_ID_SIZE];
    uint8_t objectser[UDIF_OBJECT_SERIAL_SIZE];
    uint8_t capref[UDIF_CRYPTO_HASH_SIZE];
    uint8_t querybuf[UDIF_QUERY_STRUCTURE_SIZE + UDIF_OBJECT_SERIAL_SIZE];
    uint64_t nowsecs;
    size_t querysz;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&query, sizeof(query));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        nowsecs = qsc_timestamp_datetime_utc();
        qsc_csp_generate(queryid, sizeof(queryid));
        qsc_csp_generate(objectser, sizeof(objectser));
        qsc_memutils_clear(capref, sizeof(capref));

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            udif_certificate* storedcert;

            storedcert = (udif_certificate*)udif_certstore_find(&ctx->certstore, peer.cert.serial);

            if (storedcert != NULL)
            {
                storedcert->capability &= ~UDIF_CAP_QUERY_EXIST;
            }

            qsc_memutils_copy(query.capabilityref, capref, UDIF_CRYPTO_HASH_SIZE);
            qsc_memutils_copy(query.queryid, queryid, UDIF_QUERY_ID_SIZE);
            qsc_memutils_copy(query.targser, root.cert.serial, UDIF_SERIAL_NUMBER_SIZE);
            query.timeanchor = nowsecs;
            query.querytype = (uint8_t)udif_query_exist;
            query.predlen = UDIF_OBJECT_SERIAL_SIZE;
            query.predicate = (uint8_t*)qsc_memutils_malloc(query.predlen);

            if (query.predicate != NULL)
            {
                qsc_memutils_copy(query.predicate, objectser, UDIF_OBJECT_SERIAL_SIZE);
                err = udif_error_none;
            }
            else
            {
                err = udif_error_internal;
            }

            if (err == udif_error_none)
            {
                querysz = sizeof(querybuf);
                err = udif_query_serialize(querybuf, &querysz, &query);
            }

            if (err == udif_error_none)
            {
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_query_req, querybuf, (uint32_t)querysz);
            }

            if (err == udif_error_none)
            {
                err = udif_handle_query_req(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_not_authorized);
                udif_message_dispose(&msg);
            }
        }
        udif_query_clear(&query);
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}


static bool handler_conformance_status_revoke_cascades(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    handler_conformance_node child;
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
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&child, sizeof(child));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
        nowsecs = qsc_timestamp_datetime_utc();

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            err = handler_conformance_issue_child(&child, &peer, udif_role_ugc,
                HANDLER_CONFORMANCE_TEST_BRANCH_CAPABILITIES, nowsecs);

            if (err == udif_error_none)
            {
                err = udif_certstore_add(&ctx->certstore, &child.cert, udif_certstore_status_active, nowsecs);
            }

            if (err == udif_error_none)
            {
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_cert_revoke, peer.cert.serial, UDIF_SERIAL_NUMBER_SIZE);
            }

            if (err == udif_error_none)
            {
                err = udif_handle_cert_revoke(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_none &&
                    udif_certstore_get_status(&ctx->certstore, peer.cert.serial) == udif_certstore_status_revoked &&
                    udif_certstore_get_status(&ctx->certstore, child.cert.serial) == udif_certstore_status_revoked);
                udif_message_dispose(&msg);
            }
        }

        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_node(&child);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_object_create_rejects_stale_timestamp(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node peer;
    udif_object obj;
    udif_tunnel tun;
    udif_message msg;
    uint8_t objbuf[UDIF_OBJECT_ENCODED_SIZE];
    uint8_t objser[UDIF_OBJECT_SERIAL_SIZE];
    uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];
    uint64_t nowsecs;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&peer, sizeof(peer));
        qsc_memutils_clear((uint8_t*)&obj, sizeof(obj));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
        nowsecs = qsc_timestamp_datetime_utc();
        qsc_csp_generate(objser, sizeof(objser));
        qsc_csp_generate(attrroot, sizeof(attrroot));

        if (handler_conformance_prepare_root_peer(ctx, &root, &peer, nowsecs) == true)
        {
            err = udif_object_create(&obj, objser, 1U, peer.cert.serial, attrroot, peer.cert.serial,
                peer.keypair.sigkey, nowsecs - (UDIF_TIME_WINDOW_SECONDS + 10U), qsc_csp_generate);

            if (err == udif_error_none)
            {
                err = udif_object_serialize(objbuf, sizeof(objbuf), &obj);
            }

            if (err == udif_error_none)
            {
                handler_conformance_init_tunnel(&tun, peer.cert.serial);
                err = udif_message_init(&msg, udif_msg_object_create, objbuf, (uint32_t)sizeof(objbuf));
            }

            if (err == udif_error_none)
            {
                err = udif_handle_object_create(ctx, &tun, &msg, nowsecs);
                res = (err == udif_error_time_window && udif_entity_registry_find(ctx, peer.cert.serial) == NULL);
                udif_message_dispose(&msg);
            }
        }

        udif_object_clear(&obj);
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&peer);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool handler_conformance_transfer_confirm_rejects_stale_timestamp(void)
{
    udif_entity_context* ctx;
    handler_conformance_node root;
    handler_conformance_node sender;
    handler_conformance_node receiver;
    udif_object obj;
    udif_transfer_record transfer;
    udif_tunnel tun;
    udif_message msg;
    uint8_t objser[UDIF_OBJECT_SERIAL_SIZE];
    uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE];
    uint8_t txbuf[UDIF_TRANSFER_RECORD_ENCODED_SIZE];
    uint64_t nowsecs;
    udif_errors err;
    bool res;

    res = false;
    ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

    if (ctx != NULL)
    {
        qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
        qsc_memutils_clear((uint8_t*)&root, sizeof(root));
        qsc_memutils_clear((uint8_t*)&sender, sizeof(sender));
        qsc_memutils_clear((uint8_t*)&receiver, sizeof(receiver));
        qsc_memutils_clear((uint8_t*)&obj, sizeof(obj));
        qsc_memutils_clear((uint8_t*)&transfer, sizeof(transfer));
        qsc_memutils_clear((uint8_t*)&msg, sizeof(msg));
        qsc_memutils_clear((uint8_t*)&tun, sizeof(tun));
        nowsecs = qsc_timestamp_datetime_utc();
        qsc_csp_generate(objser, sizeof(objser));
        qsc_csp_generate(attrroot, sizeof(attrroot));

        if (handler_conformance_prepare_root_peer(ctx, &root, &sender, nowsecs) == true)
        {
            err = handler_conformance_issue_child(&receiver, &root, udif_role_ubc,
                HANDLER_CONFORMANCE_TEST_BRANCH_CAPABILITIES, nowsecs);
        }
        else
        {
            err = udif_error_internal;
        }

        if (err == udif_error_none)
        {
            err = udif_certstore_add(&ctx->certstore, &receiver.cert, udif_certstore_status_active, nowsecs);
        }

        if (err == udif_error_none)
        {
            err = udif_object_create(&obj, objser, 1U, sender.cert.serial, attrroot, sender.cert.serial,
                sender.keypair.sigkey, nowsecs - (UDIF_TIME_WINDOW_SECONDS + 10U), qsc_csp_generate);
        }

        if (err == udif_error_none)
        {
            err = udif_object_transfer(&obj, &transfer, receiver.cert.serial, sender.keypair.sigkey,
                receiver.keypair.sigkey, nowsecs - (UDIF_TIME_WINDOW_SECONDS + 10U), qsc_csp_generate);
        }

        if (err == udif_error_none)
        {
            err = udif_transfer_serialize(txbuf, sizeof(txbuf), &transfer);
        }

        if (err == udif_error_none)
        {
            handler_conformance_init_tunnel(&tun, receiver.cert.serial);
            err = udif_message_init(&msg, udif_msg_object_transfer_confirm, txbuf, (uint32_t)sizeof(txbuf));
        }

        if (err == udif_error_none)
        {
            err = udif_handle_object_transfer_confirm(ctx, &tun, &msg, nowsecs);
            res = (err == udif_error_time_window);
            udif_message_dispose(&msg);
        }

        udif_transfer_clear(&transfer);
        udif_object_clear(&obj);
        handler_conformance_clear_node(&root);
        handler_conformance_clear_node(&sender);
        handler_conformance_clear_node(&receiver);
        handler_conformance_clear_context(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

bool handler_conformance_test_run(void)
{
    bool res;
    bool tres;

    res = true;

    tres = handler_conformance_enroll_rejects_non_csr_payload();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler enrollment rejects non-CSR payload test has passed." :
        "Failure! Handler enrollment rejects non-CSR payload test has failed.");

    tres = handler_conformance_enroll_rejects_peer_serial_mismatch();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler enrollment rejects peer serial mismatch test has passed." :
        "Failure! Handler enrollment rejects peer serial mismatch test has failed.");

    tres = handler_conformance_enroll_rejects_duplicate_serial();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler enrollment rejects duplicate serial test has passed." :
        "Failure! Handler enrollment rejects duplicate serial test has failed.");

    tres = handler_conformance_registry_commit_rejects_raw_root();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler registry commit rejects raw root test has passed." :
        "Failure! Handler registry commit rejects raw root test has failed.");

    tres = handler_conformance_query_response_rejects_tamper();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler query response tamper rejection test has passed." :
        "Failure! Handler query response tamper rejection test has failed.");

    tres = handler_conformance_query_request_requires_certificate_capability();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler query request certificate capability test has passed." :
        "Failure! Handler query request certificate capability test has failed.");

    tres = handler_conformance_status_revoke_cascades();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler certificate revoke cascade state test has passed." :
        "Failure! Handler certificate revoke cascade state test has failed.");

    tres = handler_conformance_object_create_rejects_stale_timestamp();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler object create stale timestamp rejection test has passed." :
        "Failure! Handler object create stale timestamp rejection test has failed.");

    tres = handler_conformance_transfer_confirm_rejects_stale_timestamp();
    res &= tres;
    handler_conformance_print(tres == true ? "Success! Handler transfer confirm stale timestamp rejection test has passed." :
        "Failure! Handler transfer confirm stale timestamp rejection test has failed.");

    return res;
}
