#include "help.h"
#include "resources.h"
#include "consoleutils.h"

static void help_print_line(const char* prompt, const char* line)
{
    UDIF_ASSERT(prompt != NULL);
    UDIF_ASSERT(line != NULL);

    qsc_consoleutils_print_safe(prompt);
    qsc_consoleutils_print_line(line);
}

void udif_help_print_context(const char* prompt, udif_command_actions command)
{
    UDIF_ASSERT(prompt != NULL);

    if (prompt != NULL)
    {
        size_t idx;

        idx = (size_t)command;

        if (idx < UDIF_APPLICATION_HELP_STRING_DEPTH)
        {
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[idx]);
        }
    }
}

void udif_help_print_mode(const char* prompt, udif_console_modes mode, udif_roles role)
{
    UDIF_ASSERT(prompt != NULL);

    if (prompt != NULL)
    {
        if (mode == udif_console_mode_user)
        {
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_user_enable]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_user_help]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_user_quit]);
        }
        else if (mode == udif_console_mode_enable)
        {
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_clear_screen]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_config]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_exit]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_help]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_quit]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_show_config]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_enable_show_log]);
        }
        else if (mode == udif_console_mode_config)
        {
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_address]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_certificate]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_clear_all]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_clear_config]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_clear_log]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_exit]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_help]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_log]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_name_domain]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_name_host]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_port]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_retries]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_server]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_config_timeout]);
        }
        else if (mode == udif_console_mode_certificate)
        {
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_exit]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_export]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_generate]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_help]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_print]);

            /* sign is only meaningful at the Root — subordinates receive signed certs from parent */
            if (role == udif_role_root)
            {
                help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_certificate_sign]);
            }
        }
        else if (mode == udif_console_mode_server)
        {
            /* anchor push to parent only makes sense for BC, GC; Root has no parent */
            if (role != udif_role_root)
            {
                help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_anchor]);
            }

            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_backup]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_exit]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_help]);
            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_restore]);

            /* service control only for entities that run a listener (Root, BC, GC) */
            if (role == udif_role_root || role == udif_role_ugc  || role == udif_role_ubc)
            {
                help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_service]);
            }

            help_print_line(prompt, UDIF_APPLICATION_HELP_STRINGS[udif_command_action_server_status]);
        }
    }
}
