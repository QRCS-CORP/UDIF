#include "gc.h"
#include "arrayutils.h"
#include "server.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "resources.h"
#include "dispatch.h"
#include "entity.h"
#include "handler.h"
#include "message.h"
#include "tunnel.h"
#include "anchor.h"
#include "mcelmanager.h"
#include "udif.h"
#include "qstp.h"
#include "qstpkeys.h"
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

static udif_server_application_state m_gc_state;
static udif_mcel_manager m_gc_mcel;
static uint64_t m_gc_idle_timer;
static uint16_t m_gc_parent_port;
static char m_gc_parent_addr[UDIF_STORAGE_ADDRESS_MAX];

static void gc_dispatch_message(qstp_connection_state* cns, udif_tunnel* tun, const uint8_t* data, size_t datalen, udif_rolepair rolepair)
{
    udif_message msg;
    udif_errors err;
    uint64_t nowsecs;

    nowsecs = qsc_timestamp_epochtime_seconds();

    if (tun == NULL)
    {
        uint8_t zero[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
        udif_tunnel newtun = { 0 };

        err = udif_tunnel_init(&newtun, cns, zero, rolepair, udif_tunnel_side_server, NULL, nowsecs);

        if (err == udif_error_none)
        {
            tun = udif_tunneltable_add(&m_gc_state.tunnels, &newtun);
        }

        if (tun == NULL)
        {
            udif_server_log_write(&m_gc_state, udif_application_log_allocation_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
            qstp_connection_close(cns, qstp_error_hosts_exceeded, true);
            return;
        }
    }

    qsc_memutils_clear((uint8_t*)&msg, sizeof(udif_message));
    err = udif_tunnel_on_receive(tun, data, datalen, &msg, nowsecs);

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
            ectx->selfcert = m_gc_state.selfcert;
            ectx->rootcert = m_gc_state.rootcert;
            ectx->selfkeypair = m_gc_state.selfkeypair;
            ectx->mcelmgr = m_gc_state.mcelmgr;
            ectx->role = udif_role_ugc;

            err = udif_dispatch(ectx, tun, &msg, nowsecs);
            qsc_memutils_clear((uint8_t*)ectx, sizeof(udif_entity_context));
            qsc_memutils_alloc_free(ectx);
        }

        udif_message_dispose(&msg);

        if (err != udif_error_none)
        {
            udif_server_log_write(&m_gc_state, udif_application_log_dispatch_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
            udif_tunneltable_remove(&m_gc_state.tunnels, tun, true);
        }
    }
    else
    {
        udif_server_log_write(&m_gc_state, udif_application_log_receive_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
        udif_tunneltable_remove(&m_gc_state.tunnels, tun, true);
    }
}

static void gc_server_receive_callback(qstp_connection_state* cns, const char* message, size_t msglen)
{
    UDIF_ASSERT(cns != NULL);

    if (cns == NULL || message == NULL || msglen == 0U ||
        m_gc_state.srvloopstatus == udif_server_loop_paused)
    {
        return;
    }

    udif_tunnel* tun = udif_tunneltable_find_by_qstp(&m_gc_state.tunnels, cns);

    gc_dispatch_message(cns, tun, (const uint8_t*)message, msglen, udif_rolepair_ua_gc);
}

static void gc_server_disconnect_callback(qstp_connection_state* cns)
{
    UDIF_ASSERT(cns != NULL);

    udif_tunnel* tun;

    if (cns == NULL)
    {
        return;
    }

    tun = udif_tunneltable_find_by_qstp(&m_gc_state.tunnels, cns);

    if (tun != NULL)
    {
        udif_tunneltable_remove(&m_gc_state.tunnels, tun, false);
    }
}

static void gc_parent_receive_callback(qstp_connection_state* cns, const char* message, size_t msglen)
{
    UDIF_ASSERT(cns != NULL);

    if (cns == NULL || message == NULL || msglen == 0U)
    {
        return;
    }

    udif_tunnel* tun = udif_tunneltable_find_by_qstp(&m_gc_state.tunnels, cns);

    gc_dispatch_message(cns, tun, (const uint8_t*)message, msglen, udif_rolepair_gc_bc);
}

/* Send function drives the tick loop for the Root trunk */
static void gc_parent_send_func(qstp_connection_state* cns)
{
    uint64_t nowsecs;

    while (m_gc_state.cmdloopstatus != udif_server_loop_stopped)
    {
        qsc_async_thread_sleep(1000U);
        nowsecs = qsc_timestamp_epochtime_seconds();

        /* tick keepalives and ratchet */
        udif_tunneltable_tick(&m_gc_state.tunnels, nowsecs);

        /* anchor cadence */
        if (m_gc_state.nextanchorsecs > 0U && nowsecs >= m_gc_state.nextanchorsecs)
        {
            udif_tunnel* roottun = udif_tunneltable_find_by_qstp(&m_gc_state.tunnels, cns);

            if (roottun != NULL && udif_tunnel_is_open(roottun, nowsecs) == true)
            {
                udif_anchor_record anchor = { 0 };
                udif_message ancmsg = { 0 };
                uint8_t ancbuf[UDIF_ANCHOR_RECORD_SIZE];
                udif_checkpoint_group grp = { 0 };
                udif_errors aerr;
                udif_errors sererr;

                if (udif_mcel_create_checkpoint_group(m_gc_state.mcelmgr, &grp) == true)
                {
                    aerr = udif_anchor_create(&anchor, m_gc_state.selfcert.serial, m_gc_state.nextanchorsecs / UDIF_ANCHOR_INTERVAL_SEC,
                        nowsecs, grp.regcommit, grp.transcommit, grp.membcommit, 0U, 0U, 0U, m_gc_state.selfkeypair.sigkey, qsc_acp_generate);

                    if (aerr == udif_error_none)
                    {
                        size_t ancsz;
                        sererr = udif_anchor_serialize(ancbuf, UDIF_ANCHOR_RECORD_SIZE, &anchor);
                        ancsz = (sererr == udif_error_none) ? UDIF_ANCHOR_RECORD_SIZE : 0U;

                        if (ancsz > 0U)
                        {
                            aerr = udif_message_init(&ancmsg, udif_msg_anchor_push, ancbuf, (uint32_t)ancsz);

                            if (aerr == udif_error_none)
                            {
                                udif_tunnel_send(roottun, &ancmsg, nowsecs);
                                udif_message_dispose(&ancmsg);
                                udif_server_log_write(&m_gc_state, udif_application_log_anchor_push_success, NULL, 0U);
                            }
                        }
                    }
                }
            }

            m_gc_state.nextanchorsecs = nowsecs + UDIF_ANCHOR_INTERVAL_SEC;
        }
    }
}

static void gc_upstream_thread(void)
{
    qsc_ipinfo_ipv4_address rootipv4 = { 0 };
    qstp_server_certificate srvcert  = { 0 };

    rootipv4 = qsc_ipinfo_ipv4_address_from_string(m_gc_parent_addr);
    qstp_server_certificate_extract(&srvcert, &m_gc_state.qstpserverkey);

    /* connect to Root — blocks inside gc_parent_send_func until stopped */
    qstp_client_connect_ipv4(&m_gc_state.qstprootcert, &srvcert, &rootipv4, m_gc_parent_port, gc_parent_send_func, gc_parent_receive_callback);
}

static void gc_downstream_thread(void)
{
    /* qstp_server_start_ipv4 initializes, binds, and listens on the socket
     * internally; we only need to supply a blank socket and our key. */
    qsc_socket lsock = { 0 };

    qstp_server_start_ipv4(&lsock, &m_gc_state.qstpserverkey, gc_server_receive_callback, gc_server_disconnect_callback);
}

static bool gc_service_start(void)
{
    bool res;

    res = false;

    if (m_gc_state.selfcert.serial[0U] == 0U)
    {
        udif_menu_print_predefined_message(udif_application_cert_not_found,
            m_gc_state.mode, m_gc_state.hostname);
        return res;
    }

    if (qsc_async_thread_create_noargs(&gc_upstream_thread) != (qsc_thread)0 &&
        qsc_async_thread_create_noargs(&gc_downstream_thread) != (qsc_thread)0)
    {
        m_gc_state.srvloopstatus = udif_server_loop_started;
        m_gc_state.nextanchorsecs = qsc_timestamp_epochtime_seconds() + UDIF_ANCHOR_INTERVAL_SEC;
        res = true;
    }

    return res;
}

static void gc_dispose(void)
{
    udif_server_state_unload(&m_gc_state);
    m_gc_state.cmdloopstatus = udif_server_loop_stopped;
    m_gc_state.srvloopstatus = udif_server_loop_stopped;
    m_gc_idle_timer = 0U;
}

static void gc_set_command_action(const char* command)
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
    else if (m_gc_state.mode == udif_console_mode_certificate)
    {
        if (qsc_consoleutils_line_equals(command, "exit"))
        {
            res = udif_command_action_certificate_exit; 
        }
        else if (qsc_consoleutils_line_contains(command, "export "))
        {
            res = udif_command_action_certificate_export; 
        }
        else if (qsc_consoleutils_line_contains(command, "generate "))
        {
            res = udif_command_action_certificate_generate; 
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
    else if (m_gc_state.mode == udif_console_mode_config)
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
        else if (qsc_consoleutils_line_contains(command, "port "))
        {
            res = udif_command_action_config_port; 
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
    else if (m_gc_state.mode == udif_console_mode_server)
    {
        if (qsc_consoleutils_line_equals(command, "anchor"))
        {
            res = udif_command_action_server_anchor; 
        }
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
        else if (qsc_consoleutils_line_contains(command, "service "))
        {
            res = udif_command_action_server_service; 
        }
        else if (qsc_consoleutils_line_equals(command, "status"))
        {
            res = udif_command_action_server_status; 
        }
    }
    else if (m_gc_state.mode == udif_console_mode_enable)
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
    else if (m_gc_state.mode == udif_console_mode_user)
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

    m_gc_state.action = res;
}

static void gc_command_execute(const char* command)
{
    UDIF_ASSERT(command != NULL);

    const char* arg;
    size_t slen;

    switch (m_gc_state.action)
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
            if (arg != NULL) { udif_server_cert_export(&m_gc_state, arg); }
            break;
        }
        case udif_command_action_certificate_generate:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL && qsc_stringutils_is_numeric(arg, qsc_stringutils_string_size(arg)))
            {
                uint32_t days;

                days = qsc_arrayutils_string_to_uint32(arg, qsc_stringutils_string_size(arg));

                if (udif_server_cert_generate(&m_gc_state, days) == true)
                {
                    char certpath[UDIF_STORAGE_PATH_MAX] = { 0 };
                    char keypath[UDIF_STORAGE_PATH_MAX] = { 0 };

                    udif_server_cert_path(&m_gc_state, certpath, sizeof(certpath));
                    udif_server_key_path(&m_gc_state, keypath, sizeof(keypath));

                    udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
                    udif_menu_print_text("The public certificate has been saved to: ");
                    udif_menu_print_text_line(certpath);
                    udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
                    udif_menu_print_text("The private key has been saved to: ");
                    udif_menu_print_text_line(keypath);
                    udif_menu_print_message("Sign the certificate with the root server and restart.", m_gc_state.mode, m_gc_state.hostname);
                }
                else
                {
                    udif_menu_print_predefined_message(udif_application_cert_generate_failure, m_gc_state.mode, m_gc_state.hostname);
                }
            }

            break;
        }
        case udif_command_action_certificate_help:
        {
            udif_help_print_mode(m_gc_state.cmdprompt, udif_console_mode_certificate, udif_role_ugc);
            break;
        }
        case udif_command_action_certificate_print:
        {
            udif_server_cert_print(&m_gc_state);
            break;
        }
        case udif_command_action_config_address:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            { 
                udif_server_set_ip_address(&m_gc_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_clear_all:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_all, m_gc_state.mode, m_gc_state.hostname))
            {
                udif_server_erase_all(&m_gc_state); 
            }
            else
            { 
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_gc_state.mode, m_gc_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_clear_config:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_config, m_gc_state.mode, m_gc_state.hostname))
            {
                udif_server_clear_config(&m_gc_state); 
            }
            else
            { 
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_gc_state.mode, m_gc_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_clear_log:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_log, m_gc_state.mode, m_gc_state.hostname))
            {
                udif_server_clear_log(&m_gc_state); 
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_gc_state.mode, m_gc_state.hostname); 
            }

            break;
        }
        case udif_command_action_config_help:
        {
            udif_help_print_mode(m_gc_state.cmdprompt, udif_console_mode_config, udif_role_ugc);
            break;
        }
        case udif_command_action_config_log:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                if (qsc_stringutils_string_contains(arg, "enable"))
                {
                    m_gc_state.loghost = true;  udif_server_log_host(&m_gc_state); 
                }
                else if (qsc_stringutils_string_contains(arg, "disable"))
                {
                    m_gc_state.loghost = false; udif_server_log_host(&m_gc_state); 
                }
                else 
                {
                    udif_help_print_context(m_gc_state.cmdprompt, udif_command_action_config_log); 
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
                udif_server_set_domain_name(&m_gc_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_name_host:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U) 
            { 
                udif_server_set_host_name(&m_gc_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_port:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_port(&m_gc_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_retries:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_password_retries(&m_gc_state, arg, slen); 
            }

            break;
        }
        case udif_command_action_config_timeout:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U) 
            {
                udif_server_set_console_timeout(&m_gc_state, arg, slen);
            }

            break;
        }
        case udif_command_action_server_anchor:
        {
            if (m_gc_state.srvloopstatus != udif_server_loop_started)
            {
                udif_menu_print_predefined_message(udif_application_anchor_not_ready, m_gc_state.mode, m_gc_state.hostname);
            }
            else
            {
                /* force next anchor tick immediately */
                m_gc_state.nextanchorsecs = qsc_timestamp_epochtime_seconds();
                udif_menu_print_predefined_message(udif_application_anchor_push_success, m_gc_state.mode, m_gc_state.hostname);
            }
            break;
        }
        case udif_command_action_server_backup:
        {
            udif_server_state_backup_save(&m_gc_state);
            udif_server_log_write(&m_gc_state, udif_application_log_backup_save, NULL, 0U);
            udif_menu_print_predefined_message(udif_application_backup_save_success, m_gc_state.mode, m_gc_state.hostname);
            break;
        }
        case udif_command_action_server_help:
            udif_help_print_mode(m_gc_state.cmdprompt, udif_console_mode_server, udif_role_ugc);
            break;
        case udif_command_action_server_restore:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_backup_restore_challenge, m_gc_state.mode, m_gc_state.hostname))
            {
                udif_server_state_backup_restore(&m_gc_state);
                udif_server_log_write(&m_gc_state, udif_application_log_backup_restore, NULL, 0U);
            }
            break;
        }
        case udif_command_action_server_service:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = qsc_stringutils_string_size(m_gc_state.hostname);

            if (arg != NULL)
            {
                if (qsc_stringutils_string_contains(arg, "start"))
                {
                    if (m_gc_state.srvloopstatus != udif_server_loop_started)
                    {
                        if (gc_service_start())
                        {
                            udif_menu_print_predefined_message(udif_application_service_start_success, m_gc_state.mode, m_gc_state.hostname);
                            udif_server_log_write(&m_gc_state, udif_application_log_service_started, m_gc_state.hostname, slen);
                        }
                        else
                        {
                            udif_menu_print_predefined_message(udif_application_service_start_failure, m_gc_state.mode, m_gc_state.hostname);
                        }
                    }
                }
                else if (qsc_stringutils_string_contains(arg, "stop"))
                {
                    m_gc_state.srvloopstatus = udif_server_loop_stopped;
                    udif_menu_print_predefined_message(udif_application_service_stopped, m_gc_state.mode, m_gc_state.hostname);
                    udif_server_log_write(&m_gc_state, udif_application_log_service_stopped, m_gc_state.hostname, slen);
                }
                else if (qsc_stringutils_string_contains(arg, "pause"))
                {
                    if (m_gc_state.srvloopstatus == udif_server_loop_started)
                    {
                        m_gc_state.srvloopstatus = udif_server_loop_paused;
                        udif_menu_print_predefined_message(udif_application_service_paused, m_gc_state.mode, m_gc_state.hostname);
                        udif_server_log_write(&m_gc_state, udif_application_log_service_paused, m_gc_state.hostname, slen);
                    }
                }
                else if (qsc_stringutils_string_contains(arg, "resume"))
                {
                    if (m_gc_state.srvloopstatus == udif_server_loop_paused)
                    {
                        m_gc_state.srvloopstatus = udif_server_loop_started;
                        udif_menu_print_predefined_message(udif_application_service_resume_success, m_gc_state.mode, m_gc_state.hostname);
                        udif_server_log_write(&m_gc_state, udif_application_log_service_resumed, m_gc_state.hostname, slen);
                    }
                    else
                    {
                        udif_menu_print_predefined_message(udif_application_service_resume_failure, m_gc_state.mode, m_gc_state.hostname);
                    }
                }
            }
            break;
        }
        case udif_command_action_server_status:
        {
            udif_server_print_status(&m_gc_state);
            break;
        }
        case udif_command_action_enable_clear_screen:
        {
            qsc_consoleutils_set_window_clear();
            break;
        }
        case udif_command_action_enable_exit:
        {
            udif_server_user_logout(&m_gc_state);
            break;
        }
        case udif_command_action_enable_help:
        {
            udif_help_print_mode(m_gc_state.cmdprompt, udif_console_mode_enable, udif_role_ugc);
            break;
        }
        case udif_command_action_enable_show_config:
        {
            udif_server_print_configuration(&m_gc_state);
            break;
        }
        case udif_command_action_enable_show_log:
        {
            udif_server_log_print(&m_gc_state);
            break;
        }
        case udif_command_action_user_enable:
        {
            if (udif_server_user_login(&m_gc_state) == true)
            {
                udif_server_cert_load(&m_gc_state);
            }
            else
            {
                udif_gc_stop_server();
                udif_menu_print_predefined_message(udif_application_retries_exceeded, m_gc_state.mode, m_gc_state.hostname);
                udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
                qsc_consoleutils_get_char();
            }

            break;
        }
        case udif_command_action_user_help:
        {
            udif_help_print_mode(m_gc_state.cmdprompt, udif_console_mode_user, udif_role_ugc);
            break;
        }
        case udif_command_action_enable_quit:
        case udif_command_action_user_quit:
        {
            m_gc_state.cmdloopstatus = udif_server_loop_stopped;
            udif_server_state_unload(&m_gc_state);
            udif_menu_print_predefined_message(udif_application_quit, m_gc_state.mode, m_gc_state.hostname);
            udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
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
            udif_menu_print_predefined_message(udif_application_not_recognized, m_gc_state.mode, m_gc_state.hostname);
            udif_help_print_mode(m_gc_state.cmdprompt, m_gc_state.mode, udif_role_ugc);

            break;
        }
    }
}

static void gc_get_command_mode(const char* command)
{
    UDIF_ASSERT(command != NULL);

    udif_console_modes nmode = m_gc_state.mode;

    switch (m_gc_state.mode)
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

    m_gc_state.mode = nmode;
}

static void gc_idle_timer(void)
{
    while (true)
    {
        qsc_async_thread_sleep(60000U);
        qsc_mutex mtx = qsc_async_mutex_lock_ex();

        if (m_gc_state.mode != udif_console_mode_user)
        {
            ++m_gc_idle_timer;

            if (m_gc_idle_timer >= (uint64_t)m_gc_state.timeout)
            {
                m_gc_idle_timer = 0U;
                udif_server_user_logout(&m_gc_state);
                qsc_consoleutils_print_line("");
                udif_menu_print_predefined_message(udif_application_console_timeout_expired, m_gc_state.mode, m_gc_state.hostname);
                udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
            }
        }

        qsc_async_mutex_unlock_ex(mtx);
    }
}

static void gc_command_loop(char* command)
{
    UDIF_ASSERT(command != NULL);

    m_gc_state.cmdloopstatus = udif_server_loop_started;

    while (true)
    {
        qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

        qsc_mutex mtx = qsc_async_mutex_lock_ex();
        m_gc_idle_timer = 0U;
        qsc_async_mutex_unlock_ex(mtx);

        gc_set_command_action(command);
        gc_command_execute(command);
        gc_get_command_mode(command);

        udif_server_set_command_prompt(&m_gc_state);
        udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);
        qsc_stringutils_clear_string(command);

        if (m_gc_state.cmdloopstatus == udif_server_loop_paused)
        {
            qsc_async_thread_sleep(UDIF_SERVER_PAUSE_INTERVAL);
            continue;
        }
        else if (m_gc_state.cmdloopstatus == udif_server_loop_stopped)
        {
            break;
        }
    }

    gc_dispose();
}

void udif_gc_start_server(void)
{
    char command[QSC_CONSOLE_MAX_LINE] = { 0 };
    qsc_thread idle;

    qsc_memutils_clear((uint8_t*)&m_gc_state, sizeof(udif_server_application_state));
    qsc_memutils_clear((uint8_t*)&m_gc_mcel,  sizeof(udif_mcel_manager));
    m_gc_idle_timer = 0U;
    m_gc_parent_port = 32121U;
    qsc_stringutils_copy_string(m_gc_parent_addr, sizeof(m_gc_parent_addr), "127.0.0.1");

    udif_server_state_initialize(&m_gc_state, udif_role_ugc);
    m_gc_state.mcelmgr = &m_gc_mcel;

    /* Try to load stored config (root address / port may be stored there) */
    udif_server_state_load(&m_gc_state);

    qsc_consoleutils_set_virtual_terminal();
    qsc_consoleutils_set_window_size(1000, 600);
    qsc_consoleutils_set_window_title(m_gc_state.wtitle);

    udif_server_print_banner(&m_gc_state);

    gc_get_command_mode(command);
    udif_menu_print_prompt(m_gc_state.mode, m_gc_state.hostname);

    idle = qsc_async_thread_create_noargs(&gc_idle_timer);

    if (idle != (qsc_thread)0)
    {
        gc_command_loop(command);
    }
}

void udif_gc_pause_server(void)
{
    m_gc_state.cmdloopstatus = udif_server_loop_paused;
}

void udif_gc_stop_server(void)
{
    m_gc_state.cmdloopstatus = udif_server_loop_stopped;
}
