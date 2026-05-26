#include "ua.h"
#include "arrayutils.h"
#include "capability.h"
#include "certificate.h"
#include "commands.h"
#include "dispatch.h"
#include "entity.h"
#include "handler.h"
#include "help.h"
#include "menu.h"
#include "message.h"
#include "object.h"
#include "query.h"
#include "resources.h"
#include "server.h"
#include "tunnel.h"
#include "udif.h"
#include "qstp.h"
#include "client.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

static udif_server_application_state m_ua_state;
static uint64_t m_ua_idle_timer;
static char m_ua_gc_addr[UDIF_STORAGE_ADDRESS_MAX];
static uint16_t m_ua_gc_port;
static bool m_ua_connected;

static void ua_gc_receive_callback(qstp_connection_state* cns, const char* message, size_t msglen)
{
    UDIF_ASSERT(cns != NULL);

    udif_tunnel* tun;
    udif_message msg;
    udif_errors err;
    uint64_t nowsecs;

    if (cns != NULL && message != NULL && msglen != 0U)
    {
        nowsecs = qsc_timestamp_epochtime_seconds();
        tun = udif_tunneltable_find_by_qstp(&m_ua_state.tunnels, cns);

        if (tun != NULL)
        {
            qsc_memutils_clear((uint8_t*)&msg, sizeof(udif_message));
            err = udif_tunnel_on_receive(tun, (const uint8_t*)message, msglen, &msg, nowsecs);

            if (err == udif_error_none)
            {
                udif_entity_context* ectx;

                ectx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));

                if (ectx == NULL)
                {
                    err = udif_error_internal;
                }
                else
                {
                    qsc_memutils_clear((uint8_t*)ectx, sizeof(udif_entity_context));
                    ectx->selfcert = m_ua_state.selfcert;
                    ectx->rootcert = m_ua_state.rootcert;
                    ectx->selfkeypair = m_ua_state.selfkeypair;
                    ectx->mcelmgr = NULL;
                    ectx->role = udif_role_client;

                    err = udif_dispatch(ectx, tun, &msg, nowsecs);
                    qsc_memutils_secure_erase((uint8_t*)ectx, sizeof(udif_entity_context));
                    qsc_memutils_alloc_free(ectx);
                }

                udif_message_dispose(&msg);

                if (err != udif_error_none)
                {
                    udif_tunneltable_remove(&m_ua_state.tunnels, tun, true);
                    m_ua_connected = false;
                }
            }
            else
            {
                udif_tunneltable_remove(&m_ua_state.tunnels, tun, true);
                m_ua_connected = false;
            }
        }
    }
}

static void ua_gc_send_func(qstp_connection_state* cns)
{
    (void)cns;

    while (m_ua_connected == true && m_ua_state.cmdloopstatus != udif_server_loop_stopped)
    {
        qsc_async_thread_sleep(1000U);
        udif_tunneltable_tick(&m_ua_state.tunnels, qsc_timestamp_epochtime_seconds());
    }
}

static udif_tunnel* ua_open_session(void)
{
    udif_tunnel* tun;

    tun = NULL;

    /* check for an existing open tunnel */
    {
        size_t i;
        uint64_t nowsecs;

        nowsecs = qsc_timestamp_epochtime_seconds();

        for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (m_ua_state.tunnels.entries[i].rolepair == udif_rolepair_ua_gc && udif_tunnel_is_open(&m_ua_state.tunnels.entries[i], nowsecs))
            {
                return &m_ua_state.tunnels.entries[i];
            }
        }
    }

    /* open a new session */
    {
        qsc_ipinfo_ipv4_address gcipv4 = { 0 };
        qstp_server_certificate srvcert = { 0 };
        udif_tunnel newtun = { 0 };
        uint8_t zero[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
        uint64_t nowsecs;
        udif_errors err;

        gcipv4 = qsc_ipinfo_ipv4_address_from_string(m_ua_gc_addr);

        m_ua_connected = true;

        /* Connect in background — send func drives tick loop */
        qstp_client_connect_ipv4(&m_ua_state.qstprootcert, &srvcert, &gcipv4, m_ua_gc_port, ua_gc_send_func, ua_gc_receive_callback);

        /* after connect callback has fired, find the tunnel (the receive callback registered it when the first message arrived) */
        nowsecs = qsc_timestamp_epochtime_seconds();

        for (size_t i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
        {
            if (m_ua_state.tunnels.entries[i].rolepair == udif_rolepair_ua_gc && udif_tunnel_is_open(&m_ua_state.tunnels.entries[i], nowsecs))
            {
                tun = &m_ua_state.tunnels.entries[i];
            }
        }

        if (tun == NULL)
        {
            /* connection failed - register an outbound-only tunnel so we can send the enroll request before the first server message */
            err = udif_tunnel_init(&newtun, NULL, zero, udif_rolepair_ua_gc, udif_tunnel_side_client, NULL, nowsecs);

            if (err == udif_error_none)
            {
                tun = udif_tunneltable_add(&m_ua_state.tunnels, &newtun);
            }
        }
    }

    return tun;
}

static void ua_send_enroll_request(udif_tunnel* tun)
{
    UDIF_ASSERT(tun != NULL);

    udif_certificate csr = { 0 };
    udif_message msg = { 0 };
    uint8_t csrbuf[UDIF_CERTIFICATE_SIZE] = { 0U };
    uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    uint64_t validfrom;
    uint64_t validto;
    udif_errors err;
    uint64_t nowsecs;
    size_t csrlen;

    if (tun != NULL)
    {
        nowsecs = qsc_timestamp_epochtime_seconds();
        validfrom = nowsecs;
        validto = validfrom + ((uint64_t)UDIF_CERTIFICATE_VALIDITY_UA * 86400U);

        qsc_acp_generate(serial, sizeof(serial));
        udif_signature_generate_keypair(m_ua_state.selfkeypair.verkey, m_ua_state.selfkeypair.sigkey, qsc_acp_generate);

        err = udif_certificate_generate_subordinate(&csr, udif_role_client, validfrom, validto, m_ua_state.selfkeypair.verkey);

        if (err == udif_error_none)
        {
            csrlen = udif_certificate_serialize_store(csrbuf, &csr);

            if (csrlen > 0U)
            {
                err = udif_message_init(&msg, udif_msg_cert_enroll_req, csrbuf, (uint32_t)csrlen);

                if (err == udif_error_none)
                {
                    err = udif_tunnel_send(tun, &msg, nowsecs);
                    udif_message_dispose(&msg);

                    if (err == udif_error_none)
                    {
                        udif_menu_print_predefined_message(udif_application_log_enroll_success, m_ua_state.mode, m_ua_state.hostname);
                        udif_server_log_write(&m_ua_state, udif_application_log_enroll_success, NULL, 0U);
                    }
                    else
                    {
                        udif_menu_print_predefined_message(udif_application_log_enroll_failure, m_ua_state.mode, m_ua_state.hostname);
                    }
                }
            }
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_cert_generate_failure, m_ua_state.mode, m_ua_state.hostname);
        }
    }
}

static void ua_send_object_create(udif_tunnel* tun, uint32_t objtype)
{
    UDIF_ASSERT(tun != NULL);

    udif_object obj = { 0 };
    udif_message msg = { 0 };
    uint8_t objbuf[UDIF_OBJECT_ENCODED_SIZE] = { 0U };
    uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    uint8_t attrroot[UDIF_CRYPTO_HASH_SIZE] = { 0U };
    uint64_t nowsecs;
    udif_errors err;
    size_t objsz;

    if (tun != NULL)
    {
        nowsecs = qsc_timestamp_epochtime_seconds();
        qsc_acp_generate(serial, sizeof(serial));

        err = udif_object_create(&obj, serial, objtype, m_ua_state.selfcert.serial, attrroot, m_ua_state.selfcert.serial, m_ua_state.selfkeypair.sigkey, nowsecs, qsc_acp_generate);

        if (err == udif_error_none)
        {
            udif_errors _oserr = udif_object_serialize(objbuf, UDIF_OBJECT_ENCODED_SIZE, &obj);
            objsz = (_oserr == udif_error_none) ? UDIF_OBJECT_ENCODED_SIZE : 0U;

            if (objsz > 0U)
            {
                err = udif_message_init(&msg, udif_msg_object_create, objbuf, (uint32_t)objsz);

                if (err == udif_error_none)
                {
                    err = udif_tunnel_send(tun, &msg, nowsecs);
                    udif_message_dispose(&msg);

                    if (err == udif_error_none)
                    {
                        udif_menu_print_message("Object create request sent.", m_ua_state.mode, m_ua_state.hostname);
                    }
                }
            }
        }
        else
        {
            udif_menu_print_message("Object create failed.", m_ua_state.mode, m_ua_state.hostname);
        }

        udif_object_clear(&obj);
    }
}

static void ua_send_query(udif_tunnel* tun, const char* serialhex)
{
    UDIF_ASSERT(tun != NULL);
    UDIF_ASSERT(serialhex != NULL);

    udif_query  q = { 0 };
    udif_message msg = { 0 };
    uint8_t qbuf[UDIF_QUERY_STRUCTURE_SIZE] = { 0U };
    uint8_t objserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
    uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
    uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
    uint64_t nowsecs;
    udif_errors err;
    size_t qsz;
    size_t copylen;

    if (tun != NULL && serialhex != NULL)
    {
        nowsecs = qsc_timestamp_epochtime_seconds();
        qsc_acp_generate(queryid, sizeof(queryid));

        copylen = qsc_stringutils_string_size(serialhex);

        if (copylen > sizeof(objserial))
        {
            copylen = sizeof(objserial);
        }

        qsc_memutils_copy(objserial, (const uint8_t*)serialhex, copylen);

        err = udif_query_create_existence(&q, queryid, m_ua_state.selfcert.serial, objserial, nowsecs, capref);

        if (err == udif_error_none)
        {
            qsz = sizeof(qbuf);
            udif_errors _qserr = udif_query_serialize(qbuf, &qsz, &q);
            if (_qserr != udif_error_none) { qsz = 0U; }

            if (qsz > 0U)
            {
                err = udif_message_init(&msg, udif_msg_query_req, qbuf, (uint32_t)qsz);

                if (err == udif_error_none)
                {
                    err = udif_tunnel_send(tun, &msg, nowsecs);
                    udif_message_dispose(&msg);

                    if (err == udif_error_none)
                    {
                        udif_menu_print_message("Query sent — response will appear above.", m_ua_state.mode, m_ua_state.hostname);
                    }
                }
            }
        }
        else
        {
            udif_menu_print_message("Query creation failed.", m_ua_state.mode, m_ua_state.hostname);
        }

        udif_query_clear(&q);
    }
}

static void ua_set_command_action(const char* command)
{
    UDIF_ASSERT(command != NULL);

    udif_command_actions res;
    size_t clen;

    res  = udif_command_action_unrecognized;
    clen = qsc_stringutils_string_size(command);

    if (clen == 0U)
    {
        res = udif_command_action_none;
    }
    else if (m_ua_state.mode == udif_console_mode_certificate)
    {
        if (qsc_consoleutils_line_equals(command, "exit"))
        {
            res = udif_command_action_certificate_exit; 
        }
        else if (qsc_consoleutils_line_contains(command, "export "))
        {
            res = udif_command_action_certificate_export; 
        }
        else if (qsc_consoleutils_line_equals(command, "help"))
        {
            res = udif_command_action_certificate_help; 
        }
        else if (qsc_consoleutils_line_equals(command, "print"))
        {
            res = udif_command_action_certificate_print; 
        }
    }
    else if (m_ua_state.mode == udif_console_mode_config)
    {
        if (qsc_consoleutils_line_contains(command, "address "))
        {
            res = udif_command_action_config_address; 
        }
        else if (qsc_consoleutils_line_equals(command, "certificate"))
        {
            res = udif_command_action_config_certificate; 
        }
        else if (qsc_consoleutils_line_equals(command, "clear all"))
        {
            res = udif_command_action_config_clear_all; 
        }
        else if (qsc_consoleutils_line_equals(command, "clear config"))
        {
            res = udif_command_action_config_clear_config; 
        }
        else if (qsc_consoleutils_line_equals(command, "clear log"))
        {
            res = udif_command_action_config_clear_log; 
        }
        else if (qsc_consoleutils_line_equals(command, "exit"))
        {
            res = udif_command_action_config_exit; 
        }
        else if (qsc_consoleutils_line_equals(command, "help"))
        {
            res = udif_command_action_config_help; 
        }
        else if (qsc_consoleutils_line_contains(command, "log "))
        {
            res = udif_command_action_config_log; 
        }
        else if (qsc_consoleutils_line_contains(command, "name domain "))
        {
            res = udif_command_action_config_name_domain; 
        }
        else if (qsc_consoleutils_line_contains(command, "name host "))
        {
            res = udif_command_action_config_name_host; 
        }
        else if (qsc_consoleutils_line_contains(command, "retries "))
        {
            res = udif_command_action_config_retries; 
        }
        else if (qsc_consoleutils_line_equals(command, "server"))
        {
            res = udif_command_action_config_server; 
        }
        else if (qsc_consoleutils_line_contains(command, "timeout "))
        {
            res = udif_command_action_config_timeout; 
        }
    }
    else if (m_ua_state.mode == udif_console_mode_server)
    {
        /* UA server mode: enroll, create, query, status, backup, restore, exit, help */
        if (qsc_consoleutils_line_equals(command, "enroll"))
        {
            res = udif_command_action_server_service; 
        }   /* reuse service slot for enroll */
        else if (qsc_consoleutils_line_contains(command, "create "))
        {
            res = udif_command_action_server_anchor; 
        }    /* reuse anchor slot for create */
        else if (qsc_consoleutils_line_contains(command, "query "))
        {
            res = udif_command_action_server_status; 
        }    /* reuse status slot for query */
        else if (qsc_consoleutils_line_equals(command, "backup"))
        {
            res = udif_command_action_server_backup; 
        }
        else if (qsc_consoleutils_line_equals(command, "exit"))
        {
            res = udif_command_action_server_exit; 
        }
        else if (qsc_consoleutils_line_equals(command, "help"))
        {
            res = udif_command_action_server_help; 
        }
        else if (qsc_consoleutils_line_equals(command, "restore"))
        {
            res = udif_command_action_server_restore; 
        }
    }
    else if (m_ua_state.mode == udif_console_mode_enable)
    {
        if (qsc_consoleutils_line_equals(command, "clear screen"))
        {
            res = udif_command_action_enable_clear_screen; 
        }
        else if (qsc_consoleutils_line_equals(command, "config"))
        {
            res = udif_command_action_enable_config; 
        }
        else if (qsc_consoleutils_line_equals(command, "exit"))
        {
            res = udif_command_action_enable_exit; 
        }
        else if (qsc_consoleutils_line_equals(command, "help"))
        {
            res = udif_command_action_enable_help; 
        }
        else if (qsc_consoleutils_line_equals(command, "quit"))
        {
            res = udif_command_action_enable_quit; 
        }
        else if (qsc_consoleutils_line_equals(command, "show config"))
        {
            res = udif_command_action_enable_show_config; 
        }
        else if (qsc_consoleutils_line_equals(command, "show log"))
        {
            res = udif_command_action_enable_show_log; 
        }
    }
    else if (m_ua_state.mode == udif_console_mode_user)
    {
        if (qsc_consoleutils_line_equals(command, "enable"))
        {
            res = udif_command_action_user_enable; 
        }
        else if (qsc_consoleutils_line_equals(command, "help"))
        {
            res = udif_command_action_user_help; 
        }
        else if (qsc_consoleutils_line_equals(command, "quit"))
        {
            res = udif_command_action_user_quit; 
        }
    }

    m_ua_state.action = res;
}

static void ua_command_execute(const char* command)
{
    UDIF_ASSERT(command != NULL);

    const char* arg;
    size_t slen;
    udif_tunnel* gctun;

    switch (m_ua_state.action)
    {
        case udif_command_action_certificate_exit:
        case udif_command_action_config_certificate:
        case udif_command_action_config_exit:
        case udif_command_action_config_server:
        case udif_command_action_server_exit:
        case udif_command_action_enable_config:
        {
            break;
        }
        case udif_command_action_certificate_export:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL) 
            { 
                udif_server_cert_export(&m_ua_state, arg); 
            }

            break;
        }
        case udif_command_action_certificate_help:
        {
            udif_help_print_mode(m_ua_state.cmdprompt, udif_console_mode_certificate, udif_role_client);
            break;
        }
        case udif_command_action_certificate_print:
        {
            udif_server_cert_print(&m_ua_state);
            break;
        }
        case udif_command_action_config_address:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_ip_address(&m_ua_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_clear_all:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_all, m_ua_state.mode, m_ua_state.hostname))
            {
                udif_server_erase_all(&m_ua_state); 
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_ua_state.mode, m_ua_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_clear_config:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_config, m_ua_state.mode, m_ua_state.hostname))
            {
                udif_server_clear_config(&m_ua_state); 
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_ua_state.mode, m_ua_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_clear_log:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_log, m_ua_state.mode, m_ua_state.hostname))
            {
                udif_server_clear_log(&m_ua_state); 
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_ua_state.mode, m_ua_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_help:
        {
            udif_help_print_mode(m_ua_state.cmdprompt, udif_console_mode_config, udif_role_client);
            break;
        }
        case udif_command_action_config_log:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                if (qsc_stringutils_string_contains(arg, "enable"))
                {
                    m_ua_state.loghost = true;  udif_server_log_host(&m_ua_state); 
                }
                else if (qsc_stringutils_string_contains(arg, "disable"))
                {
                    m_ua_state.loghost = false; udif_server_log_host(&m_ua_state); 
                }
                else 
                {
                    udif_help_print_context(m_ua_state.cmdprompt, udif_command_action_config_log); 
                }
            }
            break;
        }
        case udif_command_action_config_name_domain:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_domain_name(&m_ua_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_name_host:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_host_name(&m_ua_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_retries:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_password_retries(&m_ua_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_timeout:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_console_timeout(&m_ua_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_server_service: /* "enroll" */
        {
            gctun = ua_open_session();

            if (gctun != NULL)
            {
                ua_send_enroll_request(gctun); 
            }
            else 
            {
                udif_menu_print_message("Failed to connect to GC.", m_ua_state.mode, m_ua_state.hostname); 
            }

            break;
        }
        case udif_command_action_server_anchor: /* "create <type>" */
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL && qsc_stringutils_is_numeric(arg, qsc_stringutils_string_size(arg)))
            {
                gctun = ua_open_session();

                if (gctun != NULL)
                {
                    ua_send_object_create(gctun, qsc_arrayutils_string_to_uint32(arg, qsc_stringutils_string_size(arg)));
                }
            }
            else
            {
                udif_menu_print_message("Usage: create <object-type-uint32>", m_ua_state.mode, m_ua_state.hostname);
            }

            break;
        }
        case udif_command_action_server_status: /* "query <serial>" */
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                gctun = ua_open_session();

                if (gctun != NULL)
                {
                    ua_send_query(gctun, arg);
                }
            }
            else
            {
                udif_menu_print_message("Usage: query <object-serial>", m_ua_state.mode, m_ua_state.hostname);
            }

            break;
        }
        case udif_command_action_server_backup:
        {
            udif_server_state_backup_save(&m_ua_state);
            udif_menu_print_predefined_message(udif_application_backup_save_success, m_ua_state.mode, m_ua_state.hostname);
            break;
        }
        case udif_command_action_server_help:
        {
            udif_menu_print_message("  enroll - request certificate from GC", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  create [type] - create an object of the given type", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  query [serial] - existence query for an object", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  backup - save a state backup", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  restore - restore state from backup", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  exit - exit to config mode", m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_message("  help - this help", m_ua_state.mode, m_ua_state.hostname);
            break;
        }
        case udif_command_action_server_restore:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_backup_restore_challenge, m_ua_state.mode, m_ua_state.hostname))
            {
                udif_server_state_backup_restore(&m_ua_state); 
            }
            break;
        }
        case udif_command_action_enable_clear_screen:
        {
            qsc_consoleutils_set_window_clear();
            break;
        }
        case udif_command_action_enable_exit:
        {
            udif_server_user_logout(&m_ua_state);
            break;
        }
        case udif_command_action_enable_help:
        {
            udif_help_print_mode(m_ua_state.cmdprompt, udif_console_mode_enable, udif_role_client);
            break;
        }
        case udif_command_action_enable_show_config:
        {
            udif_server_print_configuration(&m_ua_state);
            break;
        }
        case udif_command_action_enable_show_log:
        {
            udif_server_log_print(&m_ua_state);
            break;
        }
        case udif_command_action_user_enable:
        {
            if (udif_server_user_login(&m_ua_state) == true)
            {
                udif_server_cert_load(&m_ua_state);
            }
            else
            {
                udif_ua_stop_server();
                udif_menu_print_predefined_message(udif_application_retries_exceeded, m_ua_state.mode, m_ua_state.hostname);
                udif_menu_print_prompt(m_ua_state.mode, m_ua_state.hostname);
                qsc_consoleutils_get_char();
            }
            break;
        }
        case udif_command_action_user_help:
        {
            udif_help_print_mode(m_ua_state.cmdprompt, udif_console_mode_user, udif_role_client);
            break;
        }
        case udif_command_action_enable_quit:
        case udif_command_action_user_quit:
        {
            m_ua_connected = false;
            m_ua_state.cmdloopstatus = udif_server_loop_stopped;
            udif_server_state_unload(&m_ua_state);
            udif_menu_print_predefined_message(udif_application_quit, m_ua_state.mode, m_ua_state.hostname);
            udif_menu_print_prompt(m_ua_state.mode, m_ua_state.hostname);
            qsc_consoleutils_get_char();
            break;
        }
        case udif_command_action_none:
        {
            break;
        }
        case udif_command_action_unrecognized:
        default:
        {
            udif_menu_print_predefined_message(udif_application_not_recognized, m_ua_state.mode, m_ua_state.hostname);
            udif_help_print_mode(m_ua_state.cmdprompt, m_ua_state.mode, udif_role_client);

            break;
        }
    }
}

static void ua_get_command_mode(const char* command)
{
    UDIF_ASSERT(command != NULL);

    udif_console_modes nmode;

    nmode = m_ua_state.mode;

    switch (m_ua_state.mode)
    {
        case udif_console_mode_certificate:
        {
            if (qsc_consoleutils_line_equals(command, "exit"))
            {
                nmode = udif_console_mode_config; 
            }

            break;
        }
        case udif_console_mode_config:
        {
            if (qsc_consoleutils_line_equals(command, "certificate"))
            {
                nmode = udif_console_mode_certificate;
            }
            else if (qsc_consoleutils_line_equals(command, "server"))
            {
                nmode = udif_console_mode_server;
            }
            else if (qsc_consoleutils_line_equals(command, "exit"))
            {
                nmode = udif_console_mode_enable;
            }

            break;
        }
        case udif_console_mode_server:
        {
            if (qsc_consoleutils_line_equals(command, "exit"))
            {
                nmode = udif_console_mode_config;
            }

            break;
        }
        case udif_console_mode_enable:
        {
            if (qsc_consoleutils_line_equals(command, "config"))
            {
                nmode = udif_console_mode_config;
            }
            else if (qsc_consoleutils_line_equals(command, "exit"))
            {
                nmode = udif_console_mode_user;
            }

            break;
        }
        case udif_console_mode_user:
        {
            if (qsc_consoleutils_line_equals(command, "enable"))
            {
                nmode = udif_console_mode_enable;
            }

            break;
        }
        default:
        {
            break;
        }
    }

    m_ua_state.mode = nmode;
}

static void ua_idle_timer(void)
{
    while (true)
    {
        qsc_async_thread_sleep(60000U);
        qsc_mutex mtx = qsc_async_mutex_lock_ex();

        if (m_ua_state.mode != udif_console_mode_user)
        {
            ++m_ua_idle_timer;

            if (m_ua_idle_timer >= (uint64_t)m_ua_state.timeout)
            {
                m_ua_idle_timer = 0U;
                udif_server_user_logout(&m_ua_state);
                qsc_consoleutils_print_line("");
                udif_menu_print_predefined_message(udif_application_console_timeout_expired, m_ua_state.mode, m_ua_state.hostname);
                udif_menu_print_prompt(m_ua_state.mode, m_ua_state.hostname);
            }
        }

        qsc_async_mutex_unlock_ex(mtx);
    }
}

static void ua_command_loop(char* command)
{
    UDIF_ASSERT(command != NULL);

    m_ua_state.cmdloopstatus = udif_server_loop_started;

    while (true)
    {
        qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

        qsc_mutex mtx = qsc_async_mutex_lock_ex();
        m_ua_idle_timer = 0U;
        qsc_async_mutex_unlock_ex(mtx);

        ua_set_command_action(command);
        ua_command_execute(command);
        ua_get_command_mode(command);

        udif_server_set_command_prompt(&m_ua_state);
        udif_menu_print_prompt(m_ua_state.mode, m_ua_state.hostname);
        qsc_stringutils_clear_string(command);

        if (m_ua_state.cmdloopstatus == udif_server_loop_paused)
        {
            qsc_async_thread_sleep(UDIF_SERVER_PAUSE_INTERVAL);
            continue;
        }
        else if (m_ua_state.cmdloopstatus == udif_server_loop_stopped)
        {
            break;
        }
    }
}

void udif_ua_start_server(void)
{
    char command[QSC_CONSOLE_MAX_LINE] = { 0 };
    qsc_thread idle;

    qsc_memutils_clear((uint8_t*)&m_ua_state, sizeof(udif_server_application_state));
    m_ua_idle_timer = 0U;
    m_ua_connected  = false;
    m_ua_gc_port    = 32121U;
    qsc_stringutils_copy_string(m_ua_gc_addr, sizeof(m_ua_gc_addr), "127.0.0.1");

    udif_server_state_initialize(&m_ua_state, udif_role_client);
    m_ua_state.mcelmgr = NULL;    /* UA has no ledger */

    udif_server_state_load(&m_ua_state);

    qsc_consoleutils_set_virtual_terminal();
    qsc_consoleutils_set_window_size(1000, 600);
    qsc_consoleutils_set_window_title(m_ua_state.wtitle);

    udif_server_print_banner(&m_ua_state);

    ua_get_command_mode(command);
    udif_menu_print_prompt(m_ua_state.mode, m_ua_state.hostname);

    idle = qsc_async_thread_create_noargs(&ua_idle_timer);

    if (idle)
    {
        ua_command_loop(command);
    }
}

void udif_ua_pause_server(void)
{
    m_ua_state.cmdloopstatus = udif_server_loop_paused;
}

void udif_ua_stop_server(void)
{
    m_ua_state.cmdloopstatus = udif_server_loop_stopped;
}
