#include "root.h"
#include "arrayutils.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "help.h"
#include "mcelmanager.h"
#include "memutils.h"
#include "menu.h"
#include "message.h"
#include "qstp.h"
#include "qstpkeys.h"
#include "resources.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"
#include "commands.h"
#include "dispatch.h"
#include "entity.h"
#include "handler.h"
#include "server.h"
#include "socketserver.h"
#include "tunnel.h"
#include "udif.h"

static udif_server_application_state m_root_state;
static udif_mcel_manager m_root_mcel;
static uint64_t m_root_idle_timer;

static void root_receive_callback(qstp_connection_state* cns, const char* message, size_t msglen)
{
    UDIF_ASSERT(cns != NULL);
    UDIF_ASSERT(message != NULL);

    udif_tunnel* tun;
    udif_message msg;
    udif_errors err;
    uint64_t nowsecs;

    if (cns != NULL && message != NULL && msglen != 0U)
    {
        if (m_root_state.srvloopstatus != udif_server_loop_paused)
        {
            nowsecs = qsc_timestamp_epochtime_seconds();
            tun = udif_tunneltable_find_by_qstp(&m_root_state.tunnels, cns);

            if (tun == NULL)
            {
                /* first message on a new connection: register tunnel */
                udif_tunnel newtun;
                uint8_t zeroserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };

                qsc_memutils_clear((uint8_t*)&newtun, sizeof(udif_tunnel));
                err = udif_tunnel_init(&newtun, cns, zeroserial, udif_rolepair_bc_root, udif_tunnel_side_server, NULL, nowsecs);

                if (err == udif_error_none)
                {
                    tun = udif_tunneltable_add(&m_root_state.tunnels, &newtun);
                }

                if (tun == NULL)
                {
                    udif_server_log_write(&m_root_state, udif_application_log_allocation_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
                    qstp_connection_close(cns, qstp_error_hosts_exceeded, true);
                    return;
                }

                udif_server_log_write(&m_root_state, udif_application_log_connection_accept, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
            }

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
                    ectx->selfcert = m_root_state.selfcert;
                    ectx->rootcert = m_root_state.rootcert;
                    ectx->selfkeypair = m_root_state.selfkeypair;
                    ectx->mcelmgr = m_root_state.mcelmgr;
                    ectx->role = udif_role_root;

                    err = udif_dispatch(ectx, tun, &msg, nowsecs);
                    qsc_memutils_clear((uint8_t*)ectx, sizeof(udif_entity_context));
                    qsc_memutils_alloc_free(ectx);
                }

                udif_message_dispose(&msg);

                if (err != udif_error_none)
                {
                    udif_server_log_write(&m_root_state, udif_application_log_dispatch_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
                    udif_tunneltable_remove(&m_root_state.tunnels, tun, true);
                }
            }
            else
            {
                udif_server_log_write(&m_root_state, udif_application_log_receive_failure, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
                udif_tunneltable_remove(&m_root_state.tunnels, tun, true);
            }
        }
    }
}

static void root_disconnect_callback(qstp_connection_state* cns)
{
    UDIF_ASSERT(cns != NULL);

    udif_tunnel* tun;

    if (cns != NULL)
    {
        tun = udif_tunneltable_find_by_qstp(&m_root_state.tunnels, cns);

        if (tun != NULL)
        {
            udif_server_log_write(&m_root_state, udif_application_log_connection_close, (const char*)cns->target.address, qsc_stringutils_string_size((const char*)cns->target.address));
            udif_tunneltable_remove(&m_root_state.tunnels, tun, false);
        }
    }
}

static void root_server_thread(void)
{
    /* qstp_server_start_ipv4 handles socket initialization, bind, and listen internally. */
    qsc_socket lsock = { 0 };
    qstp_errors qerr;

    qerr = qstp_server_start_ipv4(&lsock, &m_root_state.qstpserverkey, root_receive_callback, root_disconnect_callback);

    if (qerr != qstp_error_none)
    {
        m_root_state.srvloopstatus = udif_server_loop_stopped;
        udif_server_log_write(&m_root_state, udif_application_log_service_stopped, NULL, 0U);
    }
}

static bool root_service_start(void)
{
    bool res;

    res = false;

    if (m_root_state.selfcert.serial[0U] == 0U)
    {
        udif_menu_print_predefined_message(udif_application_cert_not_found, m_root_state.mode, m_root_state.hostname);
        return res;
    }

    if (qsc_async_thread_create_noargs(&root_server_thread) != (qsc_thread)0)
    {
        m_root_state.srvloopstatus = udif_server_loop_started;
        res = true;
    }

    return res;
}

static void root_dispose(void)
{
    udif_server_state_unload(&m_root_state);
    m_root_state.cmdloopstatus = udif_server_loop_stopped;
    m_root_state.srvloopstatus = udif_server_loop_stopped;
    m_root_idle_timer = 0U;
}

static void root_set_command_action(const char* command)
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
    else if (m_root_state.mode == udif_console_mode_certificate)
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
        else if (qsc_consoleutils_line_contains(command, "sign "))
        {
            res = udif_command_action_certificate_sign;
        }
    }
    else if (m_root_state.mode == udif_console_mode_config)
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
    else if (m_root_state.mode == udif_console_mode_server)
    {
        if (qsc_consoleutils_line_equals(command, "backup"))
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
    else if (m_root_state.mode == udif_console_mode_enable)
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
    else if (m_root_state.mode == udif_console_mode_user)
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

    m_root_state.action = res;
}

static void root_command_execute(const char* command)
{
    UDIF_ASSERT(command != NULL);

    const char* arg;
    size_t slen;

    switch (m_root_state.action)
    {
        case udif_command_action_certificate_exit:
        case udif_command_action_config_certificate:
        case udif_command_action_config_exit:
        case udif_command_action_config_server:
        case udif_command_action_server_exit:
        case udif_command_action_enable_config:
        {
            /* pure mode transitions — nothing to execute */
            break;
        }
        case udif_command_action_certificate_export:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                udif_server_cert_export(&m_root_state, arg);
            }

            break;
        }
        case udif_command_action_certificate_generate:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL && qsc_stringutils_is_numeric(arg, qsc_stringutils_string_size(arg)) == true)
            {
                uint32_t days;

                days = qsc_arrayutils_string_to_uint32(arg, qsc_stringutils_string_size(arg));

                if (udif_server_cert_generate(&m_root_state, days) == true)
                {
                    char certpath[UDIF_STORAGE_PATH_MAX] = { 0 };
                    char keypath[UDIF_STORAGE_PATH_MAX] = { 0 };

                    udif_server_cert_path(&m_root_state, certpath, sizeof(certpath));
                    udif_server_key_path(&m_root_state, keypath, sizeof(keypath));

                    udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
                    qsc_consoleutils_print_safe("The public certificate has been saved to: ");
                    qsc_consoleutils_print_line(certpath);
                    udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
                    qsc_consoleutils_print_safe("The private key has been saved to: ");
                    qsc_consoleutils_print_line(keypath);
                }
                else
                {
                    udif_menu_print_predefined_message(udif_application_cert_generate_failure, m_root_state.mode, m_root_state.hostname);
                }
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_not_recognized, m_root_state.mode, m_root_state.hostname);
                udif_help_print_context(m_root_state.cmdprompt, udif_command_action_certificate_generate);
            }

            break;
        }
        case udif_command_action_certificate_help:
        {
            udif_help_print_mode(m_root_state.cmdprompt, udif_console_mode_certificate, udif_role_root);
            break;
        }
        case udif_command_action_certificate_print:
        {
            udif_server_cert_print(&m_root_state);
            break;
        }
        case udif_command_action_certificate_sign:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                udif_server_cert_sign(&m_root_state, arg);
            }
            else
            {
                udif_help_print_context(m_root_state.cmdprompt, udif_command_action_certificate_sign);
            }

            break;
        }
        case udif_command_action_config_address:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_ip_address(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_config_clear_all:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_all, m_root_state.mode, m_root_state.hostname) == true)
            {
                udif_server_erase_all(&m_root_state);
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_root_state.mode, m_root_state.hostname);
            }

            break;
        }
        case udif_command_action_config_clear_config:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_config, m_root_state.mode, m_root_state.hostname) == true)
            {
                udif_server_clear_config(&m_root_state);
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_root_state.mode, m_root_state.hostname);
            }

            break;
        }
        case udif_command_action_config_clear_log:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_erase_log, m_root_state.mode, m_root_state.hostname) == true)
            {
                udif_server_clear_log(&m_root_state);
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, m_root_state.mode, m_root_state.hostname);
            }

            break;
        }
        case udif_command_action_config_help:
        {
            udif_help_print_mode(m_root_state.cmdprompt, udif_console_mode_config, udif_role_root);
            break;
        }
        case udif_command_action_config_log:
        {
            arg = qsc_stringutils_reverse_sub_string(command, " ");

            if (arg != NULL)
            {
                if (qsc_stringutils_string_contains(arg, "enable") == true)
                {
                    m_root_state.loghost = true;
                    udif_server_log_host(&m_root_state);
                }
                else if (qsc_stringutils_string_contains(arg, "disable") == true)
                {
                    m_root_state.loghost = false;
                    udif_server_log_host(&m_root_state);
                }
                else
                {
                    udif_help_print_context(m_root_state.cmdprompt, udif_command_action_config_log);
                }
            }

            break;
        }
        case udif_command_action_config_name_domain:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_domain_name(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_config_name_host:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_host_name(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_config_port:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_port(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_config_retries:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_password_retries(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_config_timeout:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = (arg != NULL) ? qsc_stringutils_string_size(arg) : 0U;

            if (slen > 0U)
            {
                udif_server_set_console_timeout(&m_root_state, arg, slen);
            }

            break;
        }
        case udif_command_action_server_backup:
        {
            udif_server_state_backup_save(&m_root_state);
            udif_server_log_write(&m_root_state, udif_application_log_backup_save, NULL, 0U);
            udif_menu_print_predefined_message(udif_application_backup_save_success, m_root_state.mode, m_root_state.hostname);
            break;
        }
        case udif_command_action_server_help:
        {
            udif_help_print_mode(m_root_state.cmdprompt, udif_console_mode_server, udif_role_root);
            break;
        }
        case udif_command_action_server_restore:
        {
            if (udif_menu_print_predefined_message_confirm(udif_application_backup_restore_challenge, m_root_state.mode, m_root_state.hostname) == true)
            {
                udif_server_state_backup_restore(&m_root_state);
                udif_server_log_write(&m_root_state, udif_application_log_backup_restore, NULL, 0U);
            }

            break;
        }
        case udif_command_action_server_service:
        {
            arg  = qsc_stringutils_reverse_sub_string(command, " ");
            slen = qsc_stringutils_string_size(m_root_state.hostname);

            if (arg != NULL)
            {
                if (qsc_stringutils_string_contains(arg, "start") == true)
                {
                    if (m_root_state.srvloopstatus != udif_server_loop_started)
                    {
                        if (root_service_start() == true)
                        {
                            udif_menu_print_predefined_message(udif_application_service_start_success, m_root_state.mode, m_root_state.hostname);
                            udif_server_log_write(&m_root_state, udif_application_log_service_started, m_root_state.hostname, slen);
                        }
                        else
                        {
                            udif_menu_print_predefined_message(udif_application_service_start_failure, m_root_state.mode, m_root_state.hostname);
                        }
                    }
                }
                else if (qsc_stringutils_string_contains(arg, "stop") == true)
                {
                    m_root_state.srvloopstatus = udif_server_loop_stopped;
                    udif_menu_print_predefined_message(udif_application_service_stopped, m_root_state.mode, m_root_state.hostname);
                    udif_server_log_write(&m_root_state, udif_application_log_service_stopped, m_root_state.hostname, slen);
                }
                else if (qsc_stringutils_string_contains(arg, "pause") == true)
                {
                    if (m_root_state.srvloopstatus == udif_server_loop_started)
                    {
                        m_root_state.srvloopstatus = udif_server_loop_paused;
                        udif_menu_print_predefined_message(udif_application_service_paused, m_root_state.mode, m_root_state.hostname);
                        udif_server_log_write(&m_root_state, udif_application_log_service_paused, m_root_state.hostname, slen);
                    }
                }
                else if (qsc_stringutils_string_contains(arg, "resume") == true)
                {
                    if (m_root_state.srvloopstatus == udif_server_loop_paused)
                    {
                        m_root_state.srvloopstatus = udif_server_loop_started;
                        udif_menu_print_predefined_message(udif_application_service_resume_success, m_root_state.mode, m_root_state.hostname);
                        udif_server_log_write(&m_root_state, udif_application_log_service_resumed, m_root_state.hostname, slen);
                    }
                    else
                    {
                        udif_menu_print_predefined_message(udif_application_service_resume_failure, m_root_state.mode, m_root_state.hostname);
                    }
                }
                else
                {
                    udif_menu_print_predefined_message(udif_application_not_recognized, m_root_state.mode, m_root_state.hostname);
                }
            }

            break;
        }
        case udif_command_action_server_status:
        {
            udif_server_print_status(&m_root_state);
            break;
        }
        case udif_command_action_enable_clear_screen:
        {
            qsc_consoleutils_set_window_clear();
            break;
        }
        case udif_command_action_enable_exit:
        {
            udif_server_user_logout(&m_root_state);
            break;
        }
        case udif_command_action_enable_help:
        {
            udif_help_print_mode(m_root_state.cmdprompt, udif_console_mode_enable, udif_role_root);
            break;
        }
        case udif_command_action_enable_show_config:
        {
            udif_server_print_configuration(&m_root_state);
            break;
        }
        case udif_command_action_enable_show_log:
        {
            udif_server_log_print(&m_root_state);
            break;
        }
        case udif_command_action_user_enable:
        {
            if (udif_server_user_login(&m_root_state) == true)
            {
                udif_server_cert_load(&m_root_state);
            }
            else
            {
                udif_root_stop_server();
                udif_menu_print_predefined_message(udif_application_retries_exceeded, m_root_state.mode, m_root_state.hostname);
                udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
                qsc_consoleutils_get_char();
            }

            break;
        }
        case udif_command_action_user_help:
        {
            udif_help_print_mode(m_root_state.cmdprompt, udif_console_mode_user, udif_role_root);
            break;
        }
        case udif_command_action_enable_quit:
        case udif_command_action_user_quit:
        {
            m_root_state.cmdloopstatus = udif_server_loop_stopped;
            udif_server_state_unload(&m_root_state);
            udif_menu_print_predefined_message(udif_application_quit, m_root_state.mode, m_root_state.hostname);
            udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
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
            udif_menu_print_predefined_message(udif_application_not_recognized, m_root_state.mode, m_root_state.hostname);
            udif_help_print_mode(m_root_state.cmdprompt, m_root_state.mode, udif_role_root);
            break;
        }
    }
}

static void root_get_command_mode(const char* command)
{
    UDIF_ASSERT(command != NULL);

    udif_console_modes nmode;

    nmode = m_root_state.mode;

    switch (m_root_state.mode)
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

    m_root_state.mode = nmode;
}

static void root_idle_timer(void)
{
    const uint32_t MINUTE_MS = 60000U;

    while (true)
    {
        qsc_async_thread_sleep(MINUTE_MS);

        qsc_mutex mtx = qsc_async_mutex_lock_ex();

        if (m_root_state.mode != udif_console_mode_user)
        {
            ++m_root_idle_timer;

            if (m_root_idle_timer >= (uint64_t)m_root_state.timeout)
            {
                m_root_idle_timer = 0U;
                udif_server_user_logout(&m_root_state);
                qsc_consoleutils_print_line("");
                udif_menu_print_predefined_message(udif_application_console_timeout_expired, m_root_state.mode, m_root_state.hostname);
                udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
            }
        }

        qsc_async_mutex_unlock_ex(mtx);
    }
}

static void root_command_loop(char* command)
{
    UDIF_ASSERT(command != NULL);

    m_root_state.cmdloopstatus = udif_server_loop_started;

    while (true)
    {
        qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

        /* reset idle counter on every keystroke */
        qsc_mutex mtx = qsc_async_mutex_lock_ex();
        m_root_idle_timer = 0U;
        qsc_async_mutex_unlock_ex(mtx);

        root_set_command_action(command);
        root_command_execute(command);
        root_get_command_mode(command);

        udif_server_set_command_prompt(&m_root_state);
        udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);
        qsc_stringutils_clear_string(command);

        if (m_root_state.cmdloopstatus == udif_server_loop_paused)
        {
            qsc_async_thread_sleep(UDIF_SERVER_PAUSE_INTERVAL);
            continue;
        }
        else if (m_root_state.cmdloopstatus == udif_server_loop_stopped)
        {
            break;
        }
    }

    root_dispose();
}

void udif_root_start_server(void)
{
    char command[QSC_CONSOLE_MAX_LINE] = { 0 };
    qsc_thread idle;

    qsc_memutils_clear((uint8_t*)&m_root_state, sizeof(udif_server_application_state));
    qsc_memutils_clear((uint8_t*)&m_root_mcel,  sizeof(udif_mcel_manager));
    m_root_idle_timer = 0U;

    udif_server_state_initialize(&m_root_state, udif_role_root);
    m_root_state.mcelmgr = &m_root_mcel;

    qsc_consoleutils_set_virtual_terminal();
    qsc_consoleutils_set_window_size(1000, 600);
    qsc_consoleutils_set_window_title(m_root_state.wtitle);

    udif_server_print_banner(&m_root_state);

    root_get_command_mode(command);
    udif_menu_print_prompt(m_root_state.mode, m_root_state.hostname);

    idle = qsc_async_thread_create_noargs(&root_idle_timer);

    if (idle != (qsc_thread)0)
    {
        root_command_loop(command);
    }
}

void udif_root_pause_server(void)
{
    m_root_state.cmdloopstatus = udif_server_loop_paused;
}

void udif_root_stop_server(void)
{
    m_root_state.cmdloopstatus = udif_server_loop_stopped;
}
