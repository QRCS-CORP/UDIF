#include "menu.h"
#include "consoleutils.h"
#include "resources.h"
#include "server.h"
#include "stringutils.h"

#define UDIF_MENU_PROMPT_BUF (UDIF_STORAGE_PROMPT_MAX + 1U)

const char* udif_menu_get_prompt(udif_console_modes mode)
{
    return UDIF_APPLICATION_MODE_STRINGS[(size_t)mode];
}

void udif_menu_print_prompt(udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(host != NULL);

    char pmt[UDIF_MENU_PROMPT_BUF] = { 0 };

    if (host != NULL)
    {
        qsc_stringutils_concat_and_copy(pmt, sizeof(pmt), host, UDIF_APPLICATION_MODE_STRINGS[(size_t)mode]);
        qsc_consoleutils_print_safe(pmt);
    }
}

void udif_menu_print_predefined_message(udif_application_messages msgnum, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(host != NULL);

    if (host != NULL)
    {
        size_t idx;

        idx = (size_t)msgnum;

        if (idx < UDIF_APPLICATION_MESSAGE_STRING_DEPTH)
        {
            udif_menu_print_prompt(mode, host);
            qsc_consoleutils_print_line(UDIF_APPLICATION_MESSAGE_STRINGS[idx]);
        }
    }
}

bool udif_menu_print_predefined_message_confirm(udif_application_messages msgnum, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(host != NULL);

    char ans[8U] = { 0 };
    bool res;

    res = false;

    if (host != NULL)
    {
        udif_menu_print_predefined_message(msgnum, mode, host);
        udif_menu_print_prompt(mode, host);

        if (qsc_consoleutils_get_line(ans, sizeof(ans)) > 0U)
        {
            if (ans[0U] == 'y' || ans[0U] == 'Y')
            {
                res = true;
            }
        }
    }

    return res;
}

void udif_menu_print_predefined_text(udif_application_messages msgnum, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(host != NULL);

    if (host != NULL)
    {
        size_t idx;

        idx = (size_t)msgnum;

        if (idx < UDIF_APPLICATION_MESSAGE_STRING_DEPTH)
        {
            udif_menu_print_prompt(mode, host);
            qsc_consoleutils_print_safe(UDIF_APPLICATION_MESSAGE_STRINGS[idx]);
        }
    }
}

void udif_menu_print_message(const char* message, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(message != NULL);
    UDIF_ASSERT(host != NULL);

    if (message != NULL && host != NULL)
    {
        udif_menu_print_prompt(mode, host);

        if (qsc_stringutils_string_size(message) > 0U)
        {
            qsc_consoleutils_print_line(message);
        }
    }
}

bool udif_menu_print_message_confirm(const char* message, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(message != NULL);
    UDIF_ASSERT(host != NULL);

    char ans[8U] = { 0 };
    bool res;

    res = false;

    if (message != NULL && host != NULL)
    {
        udif_menu_print_message(message, mode, host);
        udif_menu_print_prompt(mode, host);

        if (qsc_consoleutils_get_line(ans, sizeof(ans)) > 0U)
        {
            if (ans[0U] == 'y' || ans[0U] == 'Y')
            {
                res = true;
            }
        }
    }

    return res;
}

void udif_menu_print_prompt_text(const char* message, udif_console_modes mode, const char* host)
{
    UDIF_ASSERT(message != NULL);
    UDIF_ASSERT(host != NULL);

    if (message != NULL && host != NULL)
    {
        udif_menu_print_prompt(mode, host);

        if (qsc_stringutils_string_size(message) > 0U)
        {
            qsc_consoleutils_print_safe(message);
        }
    }
}

void udif_menu_print_text(const char* message)
{
    UDIF_ASSERT(message != NULL);

    if (message != NULL)
    {
        if (qsc_stringutils_string_size(message) > 0U)
        {
            qsc_consoleutils_print_safe(message);
        }
    }
}

void udif_menu_print_text_line(const char* message)
{
    UDIF_ASSERT(message != NULL);

    if (message != NULL)
    {
        if (qsc_stringutils_string_size(message) > 0U)
        {
            qsc_consoleutils_print_line(message);
        }
    }
}

void udif_menu_print_prompt_empty(void)
{
    qsc_consoleutils_print_safe("udif> ");
}
