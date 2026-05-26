#include "server.h"
#include "arrayutils.h"
#include "acp.h"
#include "async.h"
#include "capability.h"
#include "certificate.h"
#include "commands.h"
#include "consoleutils.h"
#include "entity.h"
#include "fileutils.h"
#include "folderutils.h"
#include "help.h"
#include "ipinfo.h"
#include "logger.h"
#include "mcelmanager.h"
#include "memutils.h"
#include "menu.h"
#include "netutils.h"
#include "resources.h"
#include "stringutils.h"
#include "timestamp.h"
#include "tunnel.h"
#include "udif.h"
#include "qstp.h"
#include "qstpkeys.h"

#define UDIF_CRED_HASH_SIZE  32U

/* Root Authority */
static const char ROOT_APPLICATION_BANNER[] =
    "UDIF Root Authority v1.0\n"
    "QRCS Corp. 2025-2026. All rights reserved.\n"
    "A post-quantum UDIF trust anchor.\n"
    "Type 'help' for command options.\n"
    "One command per line, press enter to run.";
static const char ROOT_APPLICATION_NAME[] = "Root";
static const char ROOT_APPLICATION_PATH[] = "\\Root";
static const char ROOT_FILENAME_CONFIG[] = "\\userconfig.rtcfg";
static const char ROOT_CERT_NAME[] = "udif-root.cert";
static const char ROOT_KEY_NAME_PRI[] = "udif-root.key";
static const char ROOT_KEY_NAME_PUB[] = "qstp-root.key";
static const char ROOT_PROMPT_DEFAULT[] = "Root> ";
static const char ROOT_WINDOW_TITLE[] = "UDIF Root Authority v1.0";

/* Branch Controller */
static const char BC_APPLICATION_BANNER[] =
    "UDIF Branch Controller v1.0\n"
    "QRCS Corp. 2025-2026. All rights reserved.\n"
    "A post-quantum UDIF branch authority.\n"
    "Type 'help' for command options.\n"
    "One command per line, press enter to run.";
static const char BC_APPLICATION_NAME[] = "BC";
static const char BC_APPLICATION_PATH[] = "\\BC";
static const char BC_FILENAME_CONFIG[] = "\\userconfig.bccfg";
static const char BC_CERT_NAME[] = "udif-bc.cert";
static const char BC_KEY_NAME_PRI[] = "udif-bc.key";
static const char BC_KEY_NAME_PUB[] = "qstp-server.key";
static const char BC_PROMPT_DEFAULT[] = "BC> ";
static const char BC_WINDOW_TITLE[] = "UDIF Branch Controller v1.0";

/* Group Controller */
static const char GC_APPLICATION_BANNER[] =
    "UDIF Group Controller v1.0\n"
    "QRCS Corp. 2025-2026. All rights reserved.\n"
    "A post-quantum UDIF group authority.\n"
    "Type 'help' for command options.\n"
    "One command per line, press enter to run.";
static const char GC_APPLICATION_NAME[] = "GC";
static const char GC_APPLICATION_PATH[] = "\\GC";
static const char GC_FILENAME_CONFIG[] = "\\userconfig.gccfg";
static const char GC_CERT_NAME[] = "udif-gc.cert";
static const char GC_KEY_NAME_PRI[] = "udif-gc.key";
static const char GC_KEY_NAME_PUB[] = "qstp-server.key";
static const char GC_PROMPT_DEFAULT[] = "GC> ";
static const char GC_WINDOW_TITLE[] = "UDIF Group Controller v1.0";

/* User Agent */
static const char UA_APPLICATION_BANNER[] =
    "UDIF User Agent v1.0\n"
    "QRCS Corp. 2025-2026. All rights reserved.\n"
    "A post-quantum UDIF user identity agent.\n"
    "Type 'help' for command options.\n"
    "One command per line, press enter to run.";
static const char UA_APPLICATION_NAME[] = "UA";
static const char UA_APPLICATION_PATH[] = "\\UA";
static const char UA_FILENAME_CONFIG[] = "\\userconfig.uacfg";
static const char UA_CERT_NAME[] = "udif-ua.cert";
static const char UA_KEY_NAME_PRI[] = "udif-ua.key";
static const char UA_KEY_NAME_PUB[] = "";   /* UA has no QSTP server key */
static const char UA_PROMPT_DEFAULT[] = "UA> ";
static const char UA_WINDOW_TITLE[] = "UDIF User Agent v1.0";

/* shared subdirectory names */
static const char UDIF_STORAGE_ROOT_PATH[] = "\\UDIF";
static const char UDIF_CERT_STORE_PATH[] = "\\certs";
static const char UDIF_DATA_PATH[] = "\\data";
static const char UDIF_BACKUP_PATH[] = "\\backup";

void udif_server_storage_directory(const udif_server_application_state* state, char* dpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(dpath != NULL);
    UDIF_ASSERT(pathlen >= UDIF_STORAGE_PATH_MAX);

    if (state != NULL && dpath != NULL && pathlen >= UDIF_STORAGE_PATH_MAX)
    {
#if defined(QSC_SYSTEM_OS_WINDOWS)
        qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, dpath);
#else
        qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, dpath);
#endif

        if (qsc_folderutils_directory_exists(dpath) == true)
        {
            qsc_stringutils_concat_strings(dpath, pathlen, UDIF_STORAGE_ROOT_PATH);

            if (qsc_folderutils_directory_exists(dpath) == false)
            {
                qsc_folderutils_create_directory(dpath);
            }

            qsc_stringutils_concat_strings(dpath, pathlen, state->aplpath);

            if (qsc_folderutils_directory_exists(dpath) == false)
            {
                qsc_folderutils_create_directory(dpath);
            }
        }
    }
}

void udif_server_cert_directory(const udif_server_application_state* state, char* dpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(dpath != NULL);

    if (state != NULL && dpath != NULL)
    {
        udif_server_storage_directory(state, dpath, pathlen);
        qsc_stringutils_concat_strings(dpath, pathlen, UDIF_CERT_STORE_PATH);

        if (qsc_folderutils_directory_exists(dpath) == false)
        {
            qsc_folderutils_create_directory(dpath);
        }

        qsc_folderutils_append_delimiter(dpath);
    }
}

void udif_server_cert_path(const udif_server_application_state* state, char* fpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(fpath != NULL);

    if (state != NULL && fpath != NULL)
    {
        udif_server_cert_directory(state, fpath, pathlen);
        qsc_stringutils_concat_strings(fpath, pathlen, state->certname);
    }
}

void udif_server_key_path(const udif_server_application_state* state, char* fpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(fpath != NULL);

    if (state != NULL && fpath != NULL)
    {
        udif_server_cert_directory(state, fpath, pathlen);
        qsc_stringutils_concat_strings(fpath, pathlen, state->keynamepri);
    }
}

void udif_server_config_path(const udif_server_application_state* state, char* fpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(fpath != NULL);

    if (state != NULL && fpath != NULL)
    {
        udif_server_storage_directory(state, fpath, pathlen);
        qsc_stringutils_concat_strings(fpath, pathlen, state->cfgname);
    }
}

void udif_server_data_path(const udif_server_application_state* state, char* dpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(dpath != NULL);

    if (state != NULL && dpath != NULL)
    {
        udif_server_storage_directory(state, dpath, pathlen);
        qsc_stringutils_concat_strings(dpath, pathlen, UDIF_DATA_PATH);

        if (qsc_folderutils_directory_exists(dpath) == false)
        {
            qsc_folderutils_create_directory(dpath);
        }
    }
}

void udif_server_backup_directory(const udif_server_application_state* state, char* dpath, size_t pathlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(dpath != NULL);

    if (state != NULL && dpath != NULL)
    {
        udif_server_storage_directory(state, dpath, pathlen);
        qsc_stringutils_concat_strings(dpath, pathlen, UDIF_BACKUP_PATH);

        if (qsc_folderutils_directory_exists(dpath) == false)
        {
            qsc_folderutils_create_directory(dpath);
        }

        qsc_folderutils_append_delimiter(dpath);
    }
}

static void server_state_serialize(const udif_server_application_state* state, char* output, size_t outlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(output != NULL);

    char tmp[32U] = { 0 };

    if (state != NULL && output != NULL && outlen > 0U)
    {
        qsc_memutils_clear((uint8_t*)output, outlen);

        qsc_stringutils_concat_strings(output, outlen, "domain=");
        qsc_stringutils_concat_strings(output, outlen, state->domain);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_stringutils_concat_strings(output, outlen, "hostname=");
        qsc_stringutils_concat_strings(output, outlen, state->hostname);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_stringutils_concat_strings(output, outlen, "localip=");
        qsc_stringutils_concat_strings(output, outlen, state->localip);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_stringutils_concat_strings(output, outlen, "username=");
        qsc_stringutils_concat_strings(output, outlen, state->username);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_memutils_clear((uint8_t*)tmp, sizeof(tmp));
        qsc_stringutils_int_to_string((int32_t)state->port, tmp, sizeof(tmp));
        qsc_stringutils_concat_strings(output, outlen, "port=");
        qsc_stringutils_concat_strings(output, outlen, tmp);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_memutils_clear((uint8_t*)tmp, sizeof(tmp));
        qsc_stringutils_int_to_string((int32_t)state->timeout, tmp, sizeof(tmp));
        qsc_stringutils_concat_strings(output, outlen, "timeout=");
        qsc_stringutils_concat_strings(output, outlen, tmp);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_memutils_clear((uint8_t*)tmp, sizeof(tmp));
        qsc_stringutils_int_to_string((int32_t)state->retries, tmp, sizeof(tmp));
        qsc_stringutils_concat_strings(output, outlen, "retries=");
        qsc_stringutils_concat_strings(output, outlen, tmp);
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_stringutils_concat_strings(output, outlen, "loghost=");
        qsc_stringutils_concat_strings(output, outlen, state->loghost ? "1" : "0");
        qsc_stringutils_concat_strings(output, outlen, "\n");

        qsc_stringutils_concat_strings(output, outlen, "joined=");
        qsc_stringutils_concat_strings(output, outlen, state->joined ? "1" : "0");
        qsc_stringutils_concat_strings(output, outlen, "\n");
    }
}

static void server_state_parse_line(udif_server_application_state* state, const char* line, size_t linelen)
{
    /* parse a single "key=value\n" line from the config buffer into state. */
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(line != NULL);

    if (state == NULL || line == NULL || linelen == 0U)
    {
        return;
    }

    if (qsc_stringutils_string_contains(line, "domain=") == true)
    {
        qsc_stringutils_copy_string(state->domain, sizeof(state->domain), line + 7U);
    }
    else if (qsc_stringutils_string_contains(line, "hostname=") == true)
    {
        qsc_stringutils_copy_string(state->hostname, sizeof(state->hostname), line + 9U);
    }
    else if (qsc_stringutils_string_contains(line, "localip=") == true)
    {
        qsc_stringutils_copy_string(state->localip, sizeof(state->localip), line + 8U);
    }
    else if (qsc_stringutils_string_contains(line, "username=") == true)
    {
        qsc_stringutils_copy_string(state->username, sizeof(state->username), line + 9U);
    }
    else if (qsc_stringutils_string_contains(line, "port=") == true)
    {
        state->port = qsc_arrayutils_string_to_uint16(line + 5U, qsc_stringutils_string_size(line + 5U));
    }
    else if (qsc_stringutils_string_contains(line, "timeout=") == true)
    {
        state->timeout = qsc_arrayutils_string_to_uint16(line + 8U, qsc_stringutils_string_size(line + 8U));
    }
    else if (qsc_stringutils_string_contains(line, "retries=") == true)
    {
        state->retries = qsc_arrayutils_string_to_uint8(line + 8U, qsc_stringutils_string_size(line + 8U));
    }
    else if (qsc_stringutils_string_contains(line, "loghost=") == true)
    {
        state->loghost = (line[8U] == '1');
    }
    else if (qsc_stringutils_string_contains(line, "joined=") == true)
    {
        state->joined = (line[7U] == '1');
    }
}

void udif_server_state_initialize(udif_server_application_state* state, udif_roles role)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(role != udif_role_none);

    if (state != NULL && role != udif_role_none)
    {
        /* zero all mutable fields */
        qsc_memutils_clear((uint8_t*)state->cmdprompt, sizeof(state->cmdprompt));
        qsc_memutils_clear((uint8_t*)state->domain, sizeof(state->domain));
        qsc_memutils_clear((uint8_t*)state->hostname, sizeof(state->hostname));
        qsc_memutils_clear((uint8_t*)state->localip, sizeof(state->localip));
        qsc_memutils_clear((uint8_t*)state->logpath, sizeof(state->logpath));
        qsc_memutils_clear((uint8_t*)state->username, sizeof(state->username));
        qsc_memutils_clear((uint8_t*)&state->selfcert, sizeof(udif_certificate));
        qsc_memutils_clear((uint8_t*)&state->parentcert, sizeof(udif_certificate));
        qsc_memutils_clear((uint8_t*)&state->rootcert, sizeof(udif_certificate));
        qsc_memutils_clear((uint8_t*)&state->selfkeypair, sizeof(udif_signature_keypair));
        qsc_memutils_clear((uint8_t*)&state->qstprootcert, sizeof(qstp_root_certificate));
        qsc_memutils_clear((uint8_t*)&state->qstpserverkey, sizeof(qstp_server_signature_key));
        qsc_memutils_clear((uint8_t*)&state->qstprootkey, sizeof(qstp_root_signature_key));
        qsc_memutils_clear((uint8_t*)&state->tunnels, sizeof(udif_tunnel_table));

        state->mcelmgr = NULL;
        state->nextanchorsecs = 0U;
        state->action = udif_command_action_none;
        state->mode = udif_console_mode_user;
        state->cmdloopstatus = udif_server_loop_stopped;
        state->srvloopstatus = udif_server_loop_stopped;
        state->joined = false;
        state->loghost = true;
        state->role = role;

        /* set role-specific static resource pointers */
        if (role == udif_role_root)
        {
            state->aplpath = ROOT_APPLICATION_PATH;
            state->banner = ROOT_APPLICATION_BANNER;
            state->cfgname = ROOT_FILENAME_CONFIG;
            state->srvname = ROOT_APPLICATION_NAME;
            state->certname = ROOT_CERT_NAME;
            state->keynamepri = ROOT_KEY_NAME_PRI;
            state->keynamepub = ROOT_KEY_NAME_PUB;
            state->promptdef = ROOT_PROMPT_DEFAULT;
            state->wtitle = ROOT_WINDOW_TITLE;
            state->port = 32119U;
        }
        else if (role == udif_role_ubc)
        {
            state->aplpath = BC_APPLICATION_PATH;
            state->banner = BC_APPLICATION_BANNER;
            state->cfgname = BC_FILENAME_CONFIG;
            state->srvname = BC_APPLICATION_NAME;
            state->certname = BC_CERT_NAME;
            state->keynamepri = BC_KEY_NAME_PRI;
            state->keynamepub = BC_KEY_NAME_PUB;
            state->promptdef = BC_PROMPT_DEFAULT;
            state->wtitle = BC_WINDOW_TITLE;
            state->port = 32120U;
        }
        else if (role == udif_role_ugc)
        {
            state->aplpath = GC_APPLICATION_PATH;
            state->banner = GC_APPLICATION_BANNER;
            state->cfgname = GC_FILENAME_CONFIG;
            state->srvname = GC_APPLICATION_NAME;
            state->certname = GC_CERT_NAME;
            state->keynamepri = GC_KEY_NAME_PRI;
            state->keynamepub = GC_KEY_NAME_PUB;
            state->promptdef = GC_PROMPT_DEFAULT;
            state->wtitle = GC_WINDOW_TITLE;
            state->port = 32121U;
        }
        else
        {
            /* UA and any other role */
            state->aplpath = UA_APPLICATION_PATH;
            state->banner = UA_APPLICATION_BANNER;
            state->cfgname = UA_FILENAME_CONFIG;
            state->srvname = UA_APPLICATION_NAME;
            state->certname = UA_CERT_NAME;
            state->keynamepri = UA_KEY_NAME_PRI;
            state->keynamepub = UA_KEY_NAME_PUB;
            state->promptdef = UA_PROMPT_DEFAULT;
            state->wtitle = UA_WINDOW_TITLE;
            state->port = 0U;     /* UA has no listen port */
        }

        /* default scalars */
        state->timeout = UDIF_DEFAULT_SESSION_TIMEOUT;
        state->retries = UDIF_DEFAULT_AUTH_RETRIES;

        /* auto-detect local network info */
        {
            qsc_ipinfo_ipv4_address ipv4 = { 0 };
            qsc_netutils_get_ipv4_address(&ipv4);
            qsc_ipinfo_ipv4_address_to_string(state->localip, &ipv4);
        }

        qsc_netutils_get_domain_name(state->domain);

        /* set initial hostname to the server name */
        qsc_stringutils_copy_string(state->hostname, sizeof(state->hostname), state->srvname);

        /* build the initial command prompt */
        qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->promptdef);

        /* compute log path: <storage dir>\udif-activity.log */
        {
            char lpath[UDIF_STORAGE_PATH_MAX] = { 0 };

            udif_server_storage_directory(state, lpath, sizeof(lpath));
            qsc_folderutils_append_delimiter(lpath);
            qsc_stringutils_concat_strings(lpath, sizeof(lpath), UDIF_LOGGER_FILE);
            qsc_stringutils_copy_string(state->logpath, sizeof(state->logpath), lpath);
        }
    }
}

bool udif_server_state_store(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL)
    {
        char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };
        char buf[UDIF_STORAGE_PATH_MAX * 4U] = { 0 };

        udif_server_config_path(state, fpath, sizeof(fpath));
        server_state_serialize(state, buf, sizeof(buf));

        res = qsc_fileutils_copy_stream_to_file(fpath, buf, qsc_stringutils_string_size(buf));
    }

    return res;
}

bool udif_server_state_load(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL)
    {
        char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

        udif_server_config_path(state, fpath, sizeof(fpath));
        res = qsc_fileutils_exists(fpath);

        if (res == true)
        {
            char buf[UDIF_STORAGE_PATH_MAX * 4U] = { 0 };
            size_t flen;

            flen = qsc_fileutils_copy_file_to_stream(fpath, buf, sizeof(buf));

            if (flen > 0U)
            {
                /* parse line-by-line */
                char line[UDIF_STORAGE_PATH_MAX] = { 0 };
                size_t pos;
                size_t lstart;

                pos    = 0U;
                lstart = 0U;

                while (pos <= flen)
                {
                    if (pos == flen || buf[pos] == '\n')
                    {
                        size_t llen = pos - lstart;

                        if (llen > 0U && llen < sizeof(line))
                        {
                            qsc_memutils_clear((uint8_t*)line, sizeof(line));
                            qsc_memutils_copy((uint8_t*)line, (const uint8_t*)(buf + lstart), llen);
                            server_state_parse_line(state, line, llen);
                        }

                        lstart = pos + 1U;
                    }

                    ++pos;
                }

                udif_server_set_command_prompt(state);
            }
        }
    }

    return res;
}

void udif_server_state_unload(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        /* securely erase all key material */
        qsc_memutils_secure_erase((uint8_t*)state->selfkeypair.sigkey, UDIF_ASYMMETRIC_SIGNING_KEY_SIZE);
        qsc_memutils_secure_erase((uint8_t*)state->selfkeypair.verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
        qsc_memutils_secure_erase((uint8_t*)&state->qstpserverkey, sizeof(qstp_server_signature_key));
        qsc_memutils_secure_erase((uint8_t*)&state->qstprootkey, sizeof(qstp_root_signature_key));

        /* dispose MCEL manager if present */
        if (state->mcelmgr != NULL)
        {
            udif_mcel_dispose(state->mcelmgr);
            state->mcelmgr = NULL;
        }

        /* reset to defaults, preserving role */
        udif_roles saved_role = state->role;
        udif_server_state_initialize(state, saved_role);
    }
}

void udif_server_state_backup_save(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        char bcdir[UDIF_STORAGE_PATH_MAX] = { 0 };
        char src[UDIF_STORAGE_PATH_MAX] = { 0 };
        char dst[UDIF_STORAGE_PATH_MAX] = { 0 };

        udif_server_backup_directory(state, bcdir, sizeof(bcdir));

        /* backup config */
        udif_server_config_path(state, src, sizeof(src));

        if (qsc_fileutils_exists(src) == true)
        {
            qsc_stringutils_copy_string(dst, sizeof(dst), bcdir);
            qsc_stringutils_concat_strings(dst, sizeof(dst), state->cfgname);
            qsc_fileutils_file_copy(src, dst);
        }

        /* backup UDIF cert */
        qsc_memutils_clear((uint8_t*)src, sizeof(src));
        qsc_memutils_clear((uint8_t*)dst, sizeof(dst));
        udif_server_cert_path(state, src, sizeof(src));

        if (qsc_fileutils_exists(src) == true)
        {
            qsc_stringutils_copy_string(dst, sizeof(dst), bcdir);
            qsc_stringutils_concat_strings(dst, sizeof(dst), state->certname);
            qsc_fileutils_file_copy(src, dst);
        }

        /* backup UDIF private key */
        qsc_memutils_clear((uint8_t*)src, sizeof(src));
        qsc_memutils_clear((uint8_t*)dst, sizeof(dst));
        udif_server_key_path(state, src, sizeof(src));

        if (qsc_fileutils_exists(src) == true)
        {
            qsc_stringutils_copy_string(dst, sizeof(dst), bcdir);
            qsc_stringutils_concat_strings(dst, sizeof(dst), state->keynamepri);
            qsc_fileutils_file_copy(src, dst);
        }

        /* backup log */
        qsc_memutils_clear((uint8_t*)src, sizeof(src));
        qsc_memutils_clear((uint8_t*)dst, sizeof(dst));
        qsc_stringutils_copy_string(src, sizeof(src), state->logpath);

        if (qsc_fileutils_exists(src) == true)
        {
            qsc_stringutils_copy_string(dst, sizeof(dst), bcdir);
            qsc_stringutils_concat_strings(dst, sizeof(dst), UDIF_LOGGER_FILE);
            qsc_fileutils_file_copy(src, dst);
        }
    }
}

void udif_server_state_backup_restore(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        char bcdir[UDIF_STORAGE_PATH_MAX] = { 0 };
        char src[UDIF_STORAGE_PATH_MAX] = { 0 };
        char dst[UDIF_STORAGE_PATH_MAX] = { 0 };

        udif_server_backup_directory(state, bcdir, sizeof(bcdir));

        /* restore config */
        qsc_stringutils_copy_string(src, sizeof(src), bcdir);
        qsc_stringutils_concat_strings(src, sizeof(src), state->cfgname);

        if (qsc_fileutils_exists(src) == true)
        {
            udif_server_config_path(state, dst, sizeof(dst));
            qsc_fileutils_file_copy(src, dst);
        }

        /* restore cert */
        qsc_memutils_clear((uint8_t*)src, sizeof(src));
        qsc_memutils_clear((uint8_t*)dst, sizeof(dst));
        qsc_stringutils_copy_string(src, sizeof(src), bcdir);
        qsc_stringutils_concat_strings(src, sizeof(src), state->certname);

        if (qsc_fileutils_exists(src) == true)
        {
            udif_server_cert_path(state, dst, sizeof(dst));
            qsc_fileutils_file_copy(src, dst);
        }

        /* restore private key */
        qsc_memutils_clear((uint8_t*)src, sizeof(src));
        qsc_memutils_clear((uint8_t*)dst, sizeof(dst));
        qsc_stringutils_copy_string(src, sizeof(src), bcdir);
        qsc_stringutils_concat_strings(src, sizeof(src), state->keynamepri);

        if (qsc_fileutils_exists(src) == true)
        {
            udif_server_key_path(state, dst, sizeof(dst));
            qsc_fileutils_file_copy(src, dst);
        }
    }
}

void udif_server_print_banner(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_consoleutils_print_line(state->banner);
        qsc_consoleutils_print_line("");
    }
}

void udif_server_print_configuration(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    static const char DEFVAL[] = "NOT-SET";
    char ib[16U] = { 0 };

    if (state != NULL)
    {
        const char* pmt = state->cmdprompt;

        udif_menu_print_prompt(state->mode, state->hostname);
        qsc_consoleutils_print_line("--- Configuration ---");

        {
            const char* pts[3U] = { pmt, "Domain: ", (qsc_stringutils_string_size(state->domain)  > 0U ? state->domain  : DEFVAL) };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }
        {
            const char* pts[3U] = { pmt, "Host name: ", (qsc_stringutils_string_size(state->hostname) > 0U ? state->hostname : DEFVAL) };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }
        {
            const char* pts[3U] = { pmt, "IP address: ", (qsc_stringutils_string_size(state->localip)  > 0U ? state->localip  : DEFVAL) };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        qsc_stringutils_int_to_string((int32_t)state->port, ib, sizeof(ib));
        {
            const char* pts[3U] = { pmt, "Port: ", ib };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        {
            const char* pts[3U] = { pmt, "Activity logging: ", (state->loghost ? "enabled" : "disabled") };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        qsc_memutils_clear((uint8_t*)ib, sizeof(ib));
        qsc_stringutils_int_to_string((int32_t)state->timeout, ib, sizeof(ib));
        {
            const char* pts[3U] = { pmt, "Idle timeout (min):", ib };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        qsc_memutils_clear((uint8_t*)ib, sizeof(ib));
        qsc_stringutils_int_to_string((int32_t)state->retries, ib, sizeof(ib));
        {
            const char* pts[3U] = { pmt, "Auth retries: ", ib };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        {
            const char* pts[3U] = { pmt, "Enrolled: ", (state->joined ? "yes" : "no") };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        {
            const char* rolename = udif_role_to_string(state->role);
            const char* pts[3U]  = { pmt, "Role: ", (rolename != NULL ? rolename : "unknown") };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        /* cert summary */
        if (state->selfcert.serial[0U] != 0U)
        {
            const char* pts[2U] = { pmt, "UDIF certificate:  installed" };
            qsc_consoleutils_print_concatenated_line(pts, 2U);
        }
        else
        {
            const char* pts[2U] = { pmt, "UDIF certificate:  not installed (use: config > certificate > generate)" };
            qsc_consoleutils_print_concatenated_line(pts, 2U);
        }
    }
}

void udif_server_print_status(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    char ibuf[16U] = { 0 };

    if (state != NULL)
    {
        const char* pmt = state->cmdprompt;

        udif_menu_print_prompt(state->mode, state->hostname);
        qsc_consoleutils_print_line("--- Service Status ---");

        {
            const char* svcstate = (state->srvloopstatus == udif_server_loop_started) ? "running" :
                                   (state->srvloopstatus == udif_server_loop_paused)  ? "paused"  : "stopped";
            const char* pts[3U]  = { pmt, "Service: ", svcstate };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        qsc_stringutils_int_to_string((int32_t)state->tunnels.count, ibuf, sizeof(ibuf));
        {
            const char* pts[3U] = { pmt, "Active tunnels: ", ibuf };
            qsc_consoleutils_print_concatenated_line(pts, 3U);
        }

        /* per-tunnel lines */
        {
            size_t i;

            for (i = 0U; i < UDIF_ENTITY_MAX_TUNNELS; ++i)
            {
                if (state->tunnels.entries[i].rolepair != udif_rolepair_none)
                {
                    const char* rp;

                    switch (state->tunnels.entries[i].rolepair)
                    {
                        case udif_rolepair_bc_root:
                        {
                            rp = "Root trunk";
                            break;
                        }
                        case udif_rolepair_gc_bc:
                        {
                            rp = "BC upstream";
                            break;
                        }
                        case udif_rolepair_ua_gc:
                        {
                            rp = "UA connection";
                            break;
                        }
                        case udif_rolepair_bc_bc:
                        {
                            rp = "BC peer";
                            break;
                        }
                        default:
                        {
                            rp = "treaty";
                            break;
                        }
                    }

                    const char* pts[3U] = { pmt, "  Tunnel: ", rp };
                    qsc_consoleutils_print_concatenated_line(pts, 3U);
                }
            }
        }
    }
}

void udif_server_set_command_prompt(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_stringutils_clear_string(state->cmdprompt);
        qsc_stringutils_copy_string(state->cmdprompt, sizeof(state->cmdprompt), state->hostname);

        switch (state->mode)
        {
            case udif_console_mode_config:
            {
                qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), udif_menu_get_prompt(udif_console_mode_config));
                break;
            }
            case udif_console_mode_certificate:
            {
                qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), udif_menu_get_prompt(udif_console_mode_certificate));
                break;
            }
            case udif_console_mode_server:
            {
                qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), udif_menu_get_prompt(udif_console_mode_server));
                break;
            }
            case udif_console_mode_enable:
            {
                qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), udif_menu_get_prompt(udif_console_mode_enable));
                break;
            }
            case udif_console_mode_user:
            default:
            {
                qsc_stringutils_concat_strings(state->cmdprompt, sizeof(state->cmdprompt), udif_menu_get_prompt(udif_console_mode_user));
                break;
            }
        }
    }
}

static void server_credential_path(const udif_server_application_state* state, char* fpath, size_t pathlen)
{
    udif_server_storage_directory(state, fpath, pathlen);
    qsc_stringutils_concat_strings(fpath, pathlen, "\\credentials.dat");
}

static void server_hash_password(const char* username, size_t ulen, const char* password, size_t plen, uint8_t* hash)
{
    /* SHA3-256 KDF: H(username || ":" || password) */
    uint8_t tmp[UDIF_STORAGE_USERNAME_MAX + UDIF_STORAGE_PASSWORD_MAX + 2U] = { 0 };
    size_t tlen;

    tlen = 0U;
    qsc_memutils_copy(tmp + tlen, (const uint8_t*)username, ulen);
    tlen += ulen;
    tmp[tlen] = (uint8_t)':';
    ++tlen;
    qsc_memutils_copy(tmp + tlen, (const uint8_t*)password, plen);
    tlen += plen;

    qsc_sha3_compute256(hash, tmp, tlen);
    qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

bool udif_server_user_login(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    char credpath[UDIF_STORAGE_PATH_MAX] = { 0 };
    char cmsg[UDIF_STORAGE_PASSWORD_MAX] = { 0 };
    size_t slen;
    bool res;

    res = false;

    if (state == NULL)
    {
        return res;
    }

    server_credential_path(state, credpath, sizeof(credpath));

    if (qsc_fileutils_exists(credpath) == false)
    {
        /* ---- FIRST RUN ---- */
        udif_menu_print_predefined_message(udif_application_first_login, udif_console_mode_user, state->hostname);

        /* choose user name */
        while (true)
        {
            udif_menu_print_predefined_message(udif_application_choose_name, udif_console_mode_user, state->hostname);
            udif_menu_print_prompt(udif_console_mode_user, state->hostname);
            slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

            if (slen >= UDIF_STORAGE_USERNAME_MIN && slen <= UDIF_STORAGE_USERNAME_MAX)
            {
                qsc_stringutils_copy_substring(state->username, UDIF_STORAGE_USERNAME_MAX, cmsg, slen);
                break;
            }
        }

        qsc_stringutils_clear_string(cmsg);

        /* choose password and write credentials */
        while (true)
        {
            udif_menu_print_predefined_message(udif_application_choose_password, udif_console_mode_user, state->hostname);
            udif_menu_print_prompt(udif_console_mode_user, state->hostname);
            size_t plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

            if (plen >= UDIF_STORAGE_PASSWORD_MIN && plen <= UDIF_STORAGE_PASSWORD_MAX)
            {
                uint8_t hash[UDIF_CRED_HASH_SIZE];
                uint8_t cred[1U + UDIF_STORAGE_USERNAME_MAX + UDIF_CRED_HASH_SIZE] = { 0 };
                size_t ulen = qsc_stringutils_string_size(state->username);

                server_hash_password(state->username, ulen, cmsg, plen, hash);
                cred[0U] = (uint8_t)ulen;
                qsc_memutils_copy(cred + 1U, (const uint8_t*)state->username, ulen);
                qsc_memutils_copy(cred + 1U + ulen, hash, UDIF_CRED_HASH_SIZE);
                qsc_fileutils_copy_stream_to_file(credpath, (const char*)cred, 1U + ulen + UDIF_CRED_HASH_SIZE);
                qsc_memutils_secure_erase(hash, sizeof(hash));
                qsc_memutils_secure_erase(cred, sizeof(cred));
                break;
            }
        }

        qsc_memutils_secure_erase((uint8_t*)cmsg, sizeof(cmsg));
        udif_menu_print_predefined_message(udif_application_password_set, udif_console_mode_user, state->hostname);

        /* choose host name */
        while (true)
        {
            udif_menu_print_predefined_message(udif_application_challenge_hostname, udif_console_mode_user, state->hostname);
            udif_menu_print_prompt(udif_console_mode_user, state->hostname);
            slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

            if (slen >= UDIF_STORAGE_HOSTNAME_MIN && slen <= UDIF_STORAGE_HOSTNAME_MAX)
            {
                qsc_stringutils_clear_string(state->hostname);
                qsc_stringutils_copy_substring(state->hostname, UDIF_STORAGE_HOSTNAME_MAX, cmsg, slen);
                udif_menu_print_predefined_message(udif_application_challenge_hostname_success, udif_console_mode_user, state->hostname);
                break;
            }
        }

        /* persist the configuration */
        udif_server_state_store(state);
        udif_logger_initialize(state->logpath);
        udif_server_log_write(state, udif_application_log_service_started, state->hostname, qsc_stringutils_string_size(state->hostname));

        res = true;
    }
    else
    {
        /* ---- SUBSEQUENT RUNS: verify credentials ---- */
        uint8_t stored[1U + UDIF_STORAGE_USERNAME_MAX + UDIF_CRED_HASH_SIZE] = { 0 };
        size_t flen;

        flen = qsc_fileutils_copy_file_to_stream(credpath, (char*)stored, sizeof(stored));
        res  = false;

        if (flen > UDIF_CRED_HASH_SIZE + 1U)
        {
            size_t rctr;

            rctr = 0U;

            while (rctr < (size_t)state->retries)
            {
                size_t ulen;
                size_t plen;

                ++rctr;
                qsc_memutils_clear((uint8_t*)cmsg, sizeof(cmsg));
                udif_menu_print_predefined_message(udif_application_challenge_user, udif_console_mode_user, state->hostname);
                udif_menu_print_prompt(udif_console_mode_user, state->hostname);
                ulen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

                if (ulen >= UDIF_STORAGE_USERNAME_MIN && ulen <= UDIF_STORAGE_USERNAME_MAX)
                {
                    /* verify user name matches stored */
                    size_t stored_ulen = (size_t)stored[0U];

                    if (ulen == stored_ulen && qsc_memutils_are_equal((const uint8_t*)cmsg, stored + 1U, ulen) == true)
                    {
                        qsc_memutils_copy((uint8_t*)state->username, (const uint8_t*)cmsg, ulen);

                        /* now verify password */
                        qsc_memutils_clear((uint8_t*)cmsg, sizeof(cmsg));
                        udif_menu_print_predefined_message(udif_application_challenge_password, udif_console_mode_user, state->hostname);
                        udif_menu_print_prompt(udif_console_mode_user, state->hostname);
                        plen = qsc_consoleutils_masked_password(cmsg, sizeof(cmsg));

                        if (plen >= UDIF_STORAGE_PASSWORD_MIN)
                        {
                            uint8_t hash[UDIF_CRED_HASH_SIZE];
                            const uint8_t* stored_hash = stored + 1U + stored_ulen;

                            server_hash_password(state->username, ulen, cmsg, plen, hash);

                            if (qsc_memutils_are_equal(hash, stored_hash, UDIF_CRED_HASH_SIZE) == true)
                            {
                                res = true;
                                qsc_memutils_secure_erase(hash, sizeof(hash));
                                qsc_memutils_secure_erase((uint8_t*)cmsg, sizeof(cmsg));
                                break;
                            }

                            qsc_memutils_secure_erase(hash, sizeof(hash));
                        }

                        udif_menu_print_predefined_message(udif_application_challenge_password_failure, udif_console_mode_user, state->hostname);
                    }
                    else
                    {
                        udif_menu_print_predefined_message(udif_application_challenge_user_failure, udif_console_mode_user, state->hostname);
                    }
                }
            }

            if (res == false)
            {
                udif_menu_print_predefined_message(udif_application_retries_exceeded, udif_console_mode_user, state->hostname);
            }
        }

        qsc_memutils_secure_erase(stored, sizeof(stored));
        qsc_memutils_secure_erase((uint8_t*)cmsg, sizeof(cmsg));

        if (res == true)
        {
            /* load persisted config */
            udif_server_state_load(state);
            udif_server_log_write(state, udif_application_log_service_started, state->hostname, qsc_stringutils_string_size(state->hostname));
        }
    }

    return res;
}

void udif_server_user_logout(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_clear((uint8_t*)state->username, sizeof(state->username));
        state->mode = udif_console_mode_user;
        udif_server_set_command_prompt(state);
    }
}

bool udif_server_set_ip_address(udif_server_application_state* state, const char* address, size_t addlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(address != NULL);

    bool res;

    res = false;

    if (state != NULL && address != NULL && addlen != 0U)
    {
        if (addlen >= UDIF_STORAGE_ADDRESS_MIN && addlen <= UDIF_STORAGE_ADDRESS_MAX)
        {
            qsc_ipinfo_ipv4_address ipv4 = qsc_ipinfo_ipv4_address_from_string(address);
            (void)ipv4;

            qsc_stringutils_clear_string(state->localip);
            qsc_stringutils_copy_substring(state->localip, UDIF_STORAGE_ADDRESS_MAX, address, addlen);
            udif_server_state_store(state);
            udif_server_log_write(state, udif_application_log_config_erased, address, addlen);
            udif_menu_print_predefined_message(udif_application_address_change_success, state->mode, state->hostname);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_address_change_failure, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_set_host_name(udif_server_application_state* state, const char* name, size_t namelen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(name != NULL);

    bool res;

    res = false;

    if (state != NULL && name != NULL && namelen != 0U)
    {
        if (namelen >= UDIF_STORAGE_HOSTNAME_MIN && namelen <= UDIF_STORAGE_HOSTNAME_MAX)
        {
            qsc_stringutils_clear_string(state->hostname);
            qsc_stringutils_copy_substring(state->hostname, UDIF_STORAGE_HOSTNAME_MAX, name, namelen);
            udif_server_set_command_prompt(state);
            udif_server_state_store(state);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_hostname_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_set_domain_name(udif_server_application_state* state, const char* name, size_t namelen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(name != NULL);

    bool res;

    res = false;

    if (state != NULL && name != NULL && namelen != 0U)
    {
        if (namelen >= UDIF_STORAGE_DOMAINNAME_MIN && namelen <= UDIF_STORAGE_DOMAINNAME_MAX)
        {
            qsc_stringutils_clear_string(state->domain);
            qsc_stringutils_copy_substring(state->domain, UDIF_STORAGE_DOMAINNAME_MAX, name, namelen);
            udif_server_state_store(state);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_domain_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_set_port(udif_server_application_state* state, const char* snum, size_t numlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(snum != NULL);

    bool res;

    res = false;

    if (state != NULL && snum != NULL && numlen != 0U)
    {
        uint32_t pval = qsc_arrayutils_string_to_uint32(snum, numlen);

        if (pval >= 1024U && pval <= 65535U)
        {
            state->port = (uint16_t)pval;
            udif_server_state_store(state);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_port_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_set_console_timeout(udif_server_application_state* state, const char* snum, size_t numlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(snum != NULL);

    bool res;

    res = false;

    if (state != NULL && snum != NULL && numlen != 0U)
    {
        uint32_t tval = qsc_arrayutils_string_to_uint32(snum, numlen);

        if (tval >= UDIF_STORAGE_TIMEOUT_MIN && tval <= UDIF_STORAGE_TIMEOUT_MAX)
        {
            state->timeout = (uint16_t)tval;
            udif_server_state_store(state);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_timeout_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_set_password_retries(udif_server_application_state* state, const char* snum, size_t numlen)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(snum != NULL);

    bool res;

    res = false;

    if (state != NULL && snum != NULL && numlen != 0U)
    {
        uint32_t rval = qsc_arrayutils_string_to_uint32(snum, numlen);

        if (rval >= UDIF_STORAGE_RETRIES_MIN && rval <= UDIF_STORAGE_RETRIES_MAX)
        {
            state->retries = (uint8_t)rval;
            udif_server_state_store(state);
            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_retry_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

void udif_server_log_host(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        state->loghost = !state->loghost;

        if (state->loghost == true)
        {
            udif_logger_initialize(state->logpath);
            udif_menu_print_predefined_message(udif_application_logging_enabled, state->mode, state->hostname);
            udif_server_log_write(state, udif_application_log_service_started, state->hostname, qsc_stringutils_string_size(state->hostname));
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_logging_disabled, state->mode, state->hostname);
        }

        udif_server_state_store(state);
    }
}

bool udif_server_cert_generate(udif_server_application_state* state, uint32_t validdays)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL && validdays >= UDIF_CERTIFICATE_VALIDITY_MIN && validdays <= UDIF_CERTIFICATE_VALIDITY_MAX)
    {
        char certpath[UDIF_STORAGE_PATH_MAX] = { 0 };
        char keypath[UDIF_STORAGE_PATH_MAX]  = { 0 };

        udif_server_cert_path(state, certpath, sizeof(certpath));
        udif_server_key_path(state, keypath,   sizeof(keypath));

        /* warn if overwriting */
        if (qsc_fileutils_exists(certpath) == true)
        {
            res = udif_menu_print_predefined_message_confirm(udif_application_cert_generate_key_overwrite, state->mode, state->hostname);

            if (res == false)
            {
                udif_menu_print_predefined_message(udif_application_operation_aborted, state->mode, state->hostname);
                return res;
            }
        }

        /* generate the UDIF keypair */
        udif_signature_generate_keypair(state->selfkeypair.verkey, state->selfkeypair.sigkey, qsc_acp_generate);

        if (state->role == udif_role_root)
        {
            /* root: self-signed certificate */
            uint8_t serial[UDIF_SERIAL_NUMBER_SIZE];
            uint64_t validfrom;
            uint64_t validto;
            udif_errors err;

            qsc_acp_generate(serial, sizeof(serial));
            validfrom = qsc_timestamp_epochtime_seconds();
            validto = validfrom + ((uint64_t)validdays * 86400U);

            err = udif_certificate_generate_root(&state->selfcert, serial, validfrom, validto, state->selfkeypair.sigkey, state->selfkeypair.verkey, qsc_acp_generate);

            if (err == udif_error_none)
            {
                qsc_memutils_copy((uint8_t*)&state->rootcert, (const uint8_t*)&state->selfcert, sizeof(udif_certificate));

                /* generate the QSTP root key */
                qstp_root_key_generate(&state->qstprootkey, state->hostname, validdays);
                qstp_server_key_generate(&state->qstpserverkey, state->hostname, validdays);
                qstp_root_certificate_extract(&state->qstprootcert, &state->qstprootkey);
                res = true;
            }
        }
        else
        {
            /* subordinate: generate an unsigned CSR; signing happens upstream */
            uint8_t serial[UDIF_SERIAL_NUMBER_SIZE];
            uint64_t validfrom;
            uint64_t validto;
            udif_errors err;

            qsc_acp_generate(serial, sizeof(serial));
            validfrom = qsc_timestamp_epochtime_seconds();
            validto = validfrom + ((uint64_t)validdays * 86400U);

            err = udif_certificate_generate_subordinate(&state->selfcert, state->role, validfrom, validto, state->selfkeypair.verkey);

            if (err == udif_error_none)
            {
                /* generate the QSTP server key */
                qstp_server_key_generate(&state->qstpserverkey, state->hostname, validdays);
                res = true;
            }
        }

        if (res == true)
        {
            uint8_t rawcert[UDIF_CERTIFICATE_SIZE];
            size_t certsz;

            certsz = udif_certificate_serialize_store(rawcert, &state->selfcert);
            res = (certsz > 0U);

            if (res == true)
            {
                res = qsc_fileutils_copy_stream_to_file(certpath, (const char*)rawcert, certsz);
            }

            if (res == true)
            {
                /* write the private key */
                res = qsc_fileutils_copy_stream_to_file(keypath, (const char*)state->selfkeypair.sigkey, UDIF_ASYMMETRIC_SIGNING_KEY_SIZE);
            }

            if (res == true)
            {
                udif_menu_print_predefined_message(udif_application_cert_generate_success, state->mode, state->hostname);
                udif_server_log_write(state, udif_application_log_generate_success, NULL, 0U);
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_cert_generate_failure, state->mode, state->hostname);
                udif_server_log_write(state, udif_application_log_generate_failure, NULL, 0U);
            }
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_cert_generate_failure, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_cert_export(const udif_server_application_state* state, const char* dpath) 
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(dpath != NULL);

    bool res;

    res = false;

    if (state != NULL && dpath != NULL)
    {
        if (qsc_folderutils_directory_exists(dpath) == true)
        {
            char src[UDIF_STORAGE_PATH_MAX] = { 0 };
            char dst[UDIF_STORAGE_PATH_MAX] = { 0 };

            udif_server_cert_path(state, src, sizeof(src));

            if (qsc_fileutils_exists(src) == true)
            {
                qsc_stringutils_copy_string(dst, sizeof(dst), dpath);

                if (qsc_folderutils_directory_has_delimiter(dst) == false)
                {
                    qsc_folderutils_append_delimiter(dst);
                }

                qsc_stringutils_concat_strings(dst, sizeof(dst), state->certname);
                res = qsc_fileutils_file_copy(src, dst);

                if (res == true)
                {
                    udif_menu_print_predefined_message(udif_application_cert_export_success, state->mode, state->hostname);
                }
                else
                {
                    udif_menu_print_predefined_message(udif_application_cert_export_failure, state->mode, state->hostname);
                }
            }
            else
            {
                udif_menu_print_predefined_message(udif_application_cert_not_found, state->mode, state->hostname);
            }
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_cert_path_invalid, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_cert_load(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL)
    {
        char certpath[UDIF_STORAGE_PATH_MAX] = { 0 };
        char keypath[UDIF_STORAGE_PATH_MAX]  = { 0 };

        udif_server_cert_path(state, certpath, sizeof(certpath));
        udif_server_key_path(state, keypath,   sizeof(keypath));

        if (qsc_fileutils_exists(certpath) == true)
        {
            uint8_t rawcert[UDIF_CERTIFICATE_SIZE] = { 0 };
            size_t nr;

            nr = qsc_fileutils_copy_file_to_stream(certpath, (char*)rawcert, sizeof(rawcert));

            if (nr > 0U)
            {
                udif_errors derr;

                derr = udif_certificate_deserialize(&state->selfcert, rawcert, nr);

                if (derr == udif_error_none)
                {
                    /* load private key if present */
                    if (qsc_fileutils_exists(keypath) == true)
                    {
                        nr = qsc_fileutils_copy_file_to_stream(keypath, (char*)state->selfkeypair.sigkey, UDIF_ASYMMETRIC_SIGNING_KEY_SIZE);
                        res = (nr == UDIF_ASYMMETRIC_SIGNING_KEY_SIZE);

                        if (res == true)
                        {
                            qsc_memutils_copy(state->selfkeypair.verkey, state->selfcert.verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
                        }
                    }
                    else
                    {
                        /* cert present but no key — enrolled externally */
                        qsc_memutils_copy(state->selfkeypair.verkey, state->selfcert.verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
                        res = true;
                    }
                }
                else
                {
                    udif_menu_print_predefined_message(udif_application_cert_invalid, state->mode, state->hostname);
                }
            }
        }
    }

    return res;
}

bool udif_server_cert_sign(udif_server_application_state* state, const char* fpath)
{
    UDIF_ASSERT(state != NULL);
    UDIF_ASSERT(fpath != NULL);

    bool res;

    res = false;

    if (state != NULL && fpath != NULL)
    {
        if (state->role != udif_role_root)
        {
            udif_menu_print_predefined_message(udif_application_authorization_failure, state->mode, state->hostname);
            return res;
        }

        if (qsc_fileutils_exists(fpath) == false)
        {
            udif_menu_print_predefined_message(udif_application_cert_not_found, state->mode, state->hostname);
            return res;
        }

        {
            uint8_t rawcsr[UDIF_CERTIFICATE_SIZE] = { 0 };
            size_t nr;

            nr = qsc_fileutils_copy_file_to_stream(fpath, (char*)rawcsr, sizeof(rawcsr));

            if (nr > 0U)
            {
                udif_certificate csr;
                udif_errors err;

                qsc_memutils_clear((uint8_t*)&csr, sizeof(csr));
                err = udif_certificate_deserialize(&csr, rawcsr, nr);

                if (err == udif_error_none)
                {
                    err = udif_certificate_sign(&csr, state->selfkeypair.sigkey, qsc_acp_generate);

                    if (err == udif_error_none)
                    {
                        uint8_t signed_raw[UDIF_CERTIFICATE_SIZE];
                        size_t signed_sz;

                        signed_sz = udif_certificate_serialize(signed_raw, sizeof(signed_raw), &csr);
                        res = (signed_sz > 0U);

                        if (res == true)
                        {
                            res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)signed_raw, signed_sz);
                        }

                        if (res == true)
                        {
                            udif_menu_print_predefined_message(udif_application_cert_sign_success, state->mode, state->hostname);
                            udif_server_log_write(state, udif_application_log_sign_success, NULL, 0U);
                        }
                    }
                }

                if (res == false)
                {
                    udif_menu_print_predefined_message(udif_application_cert_sign_failure, state->mode, state->hostname);
                    udif_server_log_write(state, udif_application_log_sign_failure, NULL, 0U);
                }
            }
        }
    }

    return res;
}

bool udif_server_cert_print(const udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL)
    {
        if (state->selfcert.serial[0U] != 0U)
        {
            char hexbuf[UDIF_SERIAL_NUMBER_SIZE * 2U + 1U] = { 0 };
            const char* pmt = state->cmdprompt;

            udif_menu_print_prompt(state->mode, state->hostname);
            qsc_consoleutils_print_line("--- Certificate ---");

            /* serial */
            qsc_intutils_bin_to_hex(state->selfcert.serial, hexbuf, UDIF_SERIAL_NUMBER_SIZE);
            {
                const char* pts[3U] = { pmt, "Serial: ", hexbuf };
                qsc_consoleutils_print_concatenated_line(pts, 3U);
            }

            /* role */
            {
                const char* rname = udif_role_to_string(state->selfcert.role);
                const char* pts[3U] = { pmt, "Role: ", (rname != NULL ? rname : "unknown") };
                qsc_consoleutils_print_concatenated_line(pts, 3U);
            }

            /* valid-from and valid-to */
            {
                char ts[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
                qsc_timestamp_seconds_to_datetime(state->selfcert.valid.from, ts);
                const char* pts[3U] = { pmt, "Valid from: ", ts };
                qsc_consoleutils_print_concatenated_line(pts, 3U);
            }
            {
                char ts[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
                qsc_timestamp_seconds_to_datetime(state->selfcert.valid.to, ts);
                const char* pts[3U] = { pmt, "Valid to: ", ts };
                qsc_consoleutils_print_concatenated_line(pts, 3U);
            }

            /* public key fingerprint (first 16 bytes as hex) */
            {
                char fp[33U] = { 0 };
                qsc_intutils_bin_to_hex(state->selfcert.verkey, fp, 16U);
                const char* pts[3U] = { pmt, "Key fingerprint: ", fp };
                qsc_consoleutils_print_concatenated_line(pts, 3U);
            }

            res = true;
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_cert_not_found, state->mode, state->hostname);
        }
    }

    return res;
}

bool udif_server_log_write(udif_server_application_state* state, udif_application_messages msgtype, const char* message, size_t msglen)
{
    UDIF_ASSERT(state != NULL);

    bool res;

    res = false;

    if (state != NULL && state->loghost == true)
    {
        if (udif_logger_exists(state->logpath) == false)
        {
            udif_logger_initialize(state->logpath);
        }

        res = (udif_logger_write_decorated_time_stamped_message(state->logpath, msgtype, message, msglen) > 0U);
    }

    return res;
}

void udif_server_log_print(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        if (udif_logger_exists(state->logpath) == true && qsc_fileutils_get_size(state->logpath) > 0U)
        {
            char buf[UDIF_APPLICATION_MESSAGE_STRING_SIZE * 2U] = { 0 };
            int64_t len;
            size_t  ctr;

            ctr = 0U;

            while (true)
            {
                len = qsc_fileutils_read_line(state->logpath, buf, sizeof(buf), ctr);

                if (len > 0)
                {
                    udif_menu_print_prompt(udif_console_mode_enable, state->hostname);
                    qsc_consoleutils_print_line(buf);
                    qsc_stringutils_clear_string(buf);
                }
                else if (len < 0)
                {
                    break;
                }

                ++ctr;
            }
        }
        else
        {
            udif_menu_print_predefined_message(udif_application_log_empty, state->mode, state->hostname);
        }
    }
}

void udif_server_clear_config(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

        udif_server_config_path(state, fpath, sizeof(fpath));

        if (qsc_fileutils_exists(fpath) == true)
        {
            qsc_fileutils_erase(fpath);
            qsc_fileutils_delete(fpath);
        }

        udif_server_state_initialize(state, state->role);
        udif_menu_print_predefined_message(udif_application_configuration_erased, state->mode, state->hostname);
    }
}

void udif_server_clear_log(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        if (qsc_fileutils_exists(state->logpath) == true)
        {
            qsc_fileutils_erase(state->logpath);
            qsc_fileutils_delete(state->logpath);
        }

        udif_logger_initialize(state->logpath);
        udif_menu_print_predefined_message(udif_application_log_erased, state->mode, state->hostname);
    }
}

void udif_server_erase_all(udif_server_application_state* state)
{
    UDIF_ASSERT(state != NULL);

    if (state != NULL)
    {
        char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

        /* erase log */
        udif_server_clear_log(state);

        /* erase cert and key */
        qsc_memutils_clear((uint8_t*)fpath, sizeof(fpath));
        udif_server_cert_path(state, fpath, sizeof(fpath));

        if (qsc_fileutils_exists(fpath) == true)
        {
            qsc_fileutils_erase(fpath);
            qsc_fileutils_delete(fpath);
        }

        qsc_memutils_clear((uint8_t*)fpath, sizeof(fpath));
        udif_server_key_path(state, fpath, sizeof(fpath));

        if (qsc_fileutils_exists(fpath) == true)
        {
            qsc_fileutils_erase(fpath);
            qsc_fileutils_delete(fpath);
        }

        /* erase config */
        udif_server_clear_config(state);

        udif_menu_print_predefined_message(udif_application_system_erased, state->mode, state->hostname);
    }
}
