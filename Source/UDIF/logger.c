#include "logger.h"
#include "resources.h"
#include "async.h"
#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

/* single newline appended after every log entry */
static const char UDIF_LOG_NEWLINE[2U] = { 10U, 0U };

void udif_logger_initialize(const char* path)
{
    UDIF_ASSERT(path != NULL);

    if (path != NULL)
    {
        if (qsc_fileutils_exists(path) == false)
        {
            udif_logger_reset(path);
        }
    }
}

void udif_logger_reset(const char* path)
{
    UDIF_ASSERT(path != NULL);

    if (path != NULL)
    {
        if (udif_logger_exists(path) == true)
        {
            qsc_fileutils_erase(path);
        }
        else
        {
            qsc_fileutils_create(path);
        }
    }
}

bool udif_logger_dispose(const char* path)
{
    UDIF_ASSERT(path != NULL);

    bool res;

    res = false;

    if (path != NULL)
    {
        res = qsc_fileutils_exists(path);

        if (res == true)
        {
            res = qsc_fileutils_delete(path);
        }
    }

    return res;
}

bool udif_logger_exists(const char* path)
{
    UDIF_ASSERT(path != NULL);

    bool res;

    res = false;

    if (path != NULL)
    {
        if (qsc_stringutils_is_empty(path) == false)
        {
            res = qsc_fileutils_exists(path);
        }
    }

    return res;
}

size_t udif_logger_write_message(const char* path, const char* message, size_t msglen)
{
    UDIF_ASSERT(path != NULL);
    UDIF_ASSERT(message != NULL);
    UDIF_ASSERT(msglen != 0U);

    size_t len;

    len = 0U;

    if (path != NULL && message != NULL && msglen != 0U)
    {
        if (qsc_fileutils_exists(path) == true)
        {
            qsc_mutex mtx;

            mtx = qsc_async_mutex_lock_ex();

            if (qsc_fileutils_append_to_file(path, message, msglen) == true)
            {
                qsc_fileutils_append_to_file(path, UDIF_LOG_NEWLINE, 1U);
                len = msglen + 1U;
            }

            qsc_async_mutex_unlock_ex(mtx);
        }
    }

    return len;
}

size_t udif_logger_write_decorated_message(const char* path, udif_application_messages msgtype, const char* message, size_t msglen)
{
    UDIF_ASSERT(path != NULL);

    size_t len;

    len = 0U;

    if (path != NULL)
    {
        if (qsc_fileutils_exists(path) == true)
        {
            char lmsg[UDIF_APPLICATION_MESSAGE_STRING_SIZE + 256U] = { 0 };
            size_t idx;

            idx = (size_t)msgtype;

            if (idx < UDIF_APPLICATION_MESSAGE_STRING_DEPTH)
            {
                qsc_stringutils_copy_string(lmsg, sizeof(lmsg), UDIF_APPLICATION_MESSAGE_STRINGS[idx]);

                if (message != NULL && msglen != 0U)
                {
                    qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
                }

                len = udif_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
            }
        }
    }

    return len;
}

size_t udif_logger_write_decorated_time_stamped_message(const char* path,
    udif_application_messages msgtype, const char* message, size_t msglen)
{
    UDIF_ASSERT(path != NULL);

    size_t len;

    len = 0U;

    if (path != NULL)
    {
        if (qsc_fileutils_exists(path) == true)
        {
            char lmsg[UDIF_APPLICATION_MESSAGE_STRING_SIZE + 256U] = { 0 };
            size_t idx;

            len = udif_logger_time_stamp(lmsg, sizeof(lmsg));
            idx = (size_t)msgtype;

            if (idx < UDIF_APPLICATION_MESSAGE_STRING_DEPTH)
            {
                qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), UDIF_APPLICATION_MESSAGE_STRINGS[idx]);

                if (message != NULL && msglen != 0U)
                {
                    qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
                }

                len += udif_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
            }
        }
    }

    return len;
}

size_t udif_logger_write_time_stamped_message(const char* path, const char* message, size_t msglen)
{
    UDIF_ASSERT(path != NULL);

    size_t len;

    len = 0U;

    if (path != NULL)
    {
        if (qsc_fileutils_exists(path) == true)
        {
            char lmsg[UDIF_APPLICATION_MESSAGE_STRING_SIZE + 256U] = { 0 };

            len = udif_logger_time_stamp(lmsg, sizeof(lmsg));

            if (message != NULL && msglen != 0U)
            {
                qsc_stringutils_concat_strings(lmsg, sizeof(lmsg), message);
            }

            len += udif_logger_write_message(path, lmsg, qsc_stringutils_string_size(lmsg));
        }
    }

    return len;
}

size_t udif_logger_read_all(const char* path, char* output, size_t outlen)
{
    UDIF_ASSERT(path != NULL);
    UDIF_ASSERT(output != NULL);
    UDIF_ASSERT(outlen != 0U);

    size_t len;

    len = 0U;

    if (path != NULL && output != NULL && outlen != 0U)
    {
        if (qsc_fileutils_exists(path) == true)
        {
            qsc_mutex mtx;

            mtx = qsc_async_mutex_lock_ex();
            len = qsc_fileutils_copy_file_to_stream(path, output, outlen);
            qsc_async_mutex_unlock_ex(mtx);
        }
    }

    return len;
}

size_t udif_logger_time_stamp(char* output, size_t outlen)
{
    UDIF_ASSERT(output != NULL);
    UDIF_ASSERT(outlen != 0U);

    size_t len;

    len = 0U;

    if (output != NULL && outlen != 0U)
    {
        char tsc[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

        qsc_timestamp_current_datetime(tsc);
        len = qsc_stringutils_string_size(tsc);

        if (len > 0U)
        {
            len = (len <= outlen) ? len : outlen;
            qsc_memutils_copy((uint8_t*)output, (const uint8_t*)tsc, len);
        }
    }

    return len;
}
