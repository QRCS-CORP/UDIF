#include "storage.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <time.h>

/* Ledger namespace directory names */
static const char* UDIF_MCEL_LEDGER_NAMES[] = 
{
    "membership",
    "transaction",
    "registry"
};

typedef struct mcel_store_callbacks
{
    void* context;
    bool (*write)(void*, const uint8_t*, size_t, const uint8_t*, size_t);
    bool (*read)(void*, const uint8_t*, size_t, uint8_t*, size_t, size_t*);
    bool (*append)(void*, const uint8_t*, size_t, const uint8_t*, size_t, uint64_t*);
    bool (*size)(void*, const uint8_t*, size_t, uint64_t*);
    bool (*flush)(void*, const uint8_t*, size_t);
} mcel_store_callbacks;

bool udif_storage_resolve_path(const udif_storage_context* ctx, const uint8_t* loc, size_t loclen, char* outpath, size_t outpathlen)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(loc != NULL);
    UDIF_ASSERT(outpath != NULL);
    UDIF_ASSERT(ctx->initialized);

    char locstr[UDIF_STORAGE_MAX_PATH] = { 0U };
    bool res;

    res = false;

    if (ctx != NULL && loc != NULL && outpath != NULL && ctx->initialized)
    {
        if (loclen > 0U && loclen <= 256U)
        {
            qsc_memutils_copy(locstr, loc, loclen);

            /* build path: base_path/ledger_name/location */
            qsc_stringutils_copy_string(outpath, outpathlen, ctx->basepath);
            qsc_folderutils_append_delimiter(outpath);
            qsc_stringutils_concat_strings(outpath, outpathlen, UDIF_MCEL_LEDGER_NAMES[ctx->currentledger]);
            qsc_folderutils_append_delimiter(outpath);
            qsc_stringutils_concat_strings(outpath, outpathlen, locstr);
            res = true;
        }
    }

    return res;
}

bool udif_storage_get_handle(udif_storage_context* ctx, const char* path, qsc_fileutils_mode mode, FILE** outfp)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(path != NULL);
    UDIF_ASSERT(outfp != NULL);

    FILE* fp;
    size_t i;
    size_t slen;
    bool res;

    res = false;

    if (ctx != NULL && path != NULL && outfp != NULL)
    {
        fp = NULL;

        /* check if handle is already cached */
        for (i = 0U; i < ctx->handlecount; i++)
        {
            slen = qsc_stringutils_string_size(ctx->handles[i].path);

            if (ctx->handles[i].isopen && qsc_stringutils_compare_strings(ctx->handles[i].path, path, slen) == true)
            {
                ctx->handles[i].lastaccess = (uint64_t)time(NULL);
                *outfp = ctx->handles[i].fp;
                res = true;
                break;
            }
        }
        
        if (!res)
        {
            /* open new file */
            fp = qsc_fileutils_open(path, mode, true);

            if (fp != NULL)
            {
                /* cache the handle if space available */
                if (ctx->handlecount < UDIF_STORAGE_MAX_HANDLES)
                {
                    i = ctx->handlecount;
                    ctx->handles[i].fp = fp;
                    qsc_memutils_copy(ctx->handles[i].path, path, UDIF_STORAGE_MAX_PATH - 1U);
                    ctx->handles[i].path[UDIF_STORAGE_MAX_PATH - 1U] = '\0';
                    ctx->handles[i].lastaccess = (uint64_t)time(NULL);
                    ctx->handles[i].isopen = true;
                    ctx->handlecount++;
                    *outfp = fp;
                    res = true;
                }
                else
                {
                    uint64_t oldest;
                    size_t lruidx;

                    /* cache is full, evict LRU handle */
                    lruidx = 0U;
                    oldest = ctx->handles[0U].lastaccess;

                    for (i = 1U; i < ctx->handlecount; i++)
                    {
                        if (ctx->handles[i].lastaccess < oldest)
                        {
                            oldest = ctx->handles[i].lastaccess;
                            lruidx = i;
                        }
                    }

                    /* close LRU handle */
                    if (ctx->handles[lruidx].isopen)
                    {
                        qsc_fileutils_close(ctx->handles[lruidx].fp);
                    }

                    /* replace with new handle */
                    ctx->handles[lruidx].fp = fp;
                    qsc_memutils_copy(ctx->handles[lruidx].path, path, UDIF_STORAGE_MAX_PATH - 1U);
                    ctx->handles[lruidx].path[UDIF_STORAGE_MAX_PATH - 1U] = '\0';
                    ctx->handles[lruidx].lastaccess = (uint64_t)time(NULL);
                    ctx->handles[lruidx].isopen = true;
                    *outfp = fp;
                    res = true;
                }
            }
        }
    }

    return res;
}

void udif_storage_evict_handle(udif_storage_context* ctx, const char* path)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(path != NULL);

    size_t slen;

    if (ctx != NULL && path != NULL)
    {
        for (size_t i = 0U; i < ctx->handlecount; ++i)
        {
            slen = qsc_stringutils_string_size(ctx->handles[i].path);

            if (ctx->handles[i].isopen && qsc_stringutils_compare_strings(ctx->handles[i].path, path, slen) == true)
            {
                qsc_fileutils_close(ctx->handles[i].fp);
                ctx->handles[i].isopen = false;
                break;
            }
        }
    }
}

void udif_storage_close_all_handles(udif_storage_context* ctx)
{
    UDIF_ASSERT(ctx != NULL);

    if (ctx != NULL)
    {
        for (size_t i = 0U; i < ctx->handlecount; i++)
        {
            if (ctx->handles[i].isopen)
            {
                qsc_fileutils_close(ctx->handles[i].fp);
                ctx->handles[i].isopen = false;
            }
        }

        ctx->handlecount = 0U;
    }
}

static bool udif_storage_extract_directory(const char* path, char* dirpath, size_t dirpathlen)
{
    UDIF_ASSERT(path != NULL);
    UDIF_ASSERT(dirpath != NULL);

    int64_t spos;
    size_t slen;
    bool res;

    res = false;

    if (path != NULL && dirpath != NULL && dirpathlen > 0U)
    {
        slen = qsc_stringutils_string_size(path);
        spos = qsc_stringutils_reverse_find_string(path, QSC_FILEUTILS_DIRECTORY_SEPERATOR, slen);

        if (spos > 0 && spos <= (int64_t)dirpathlen)
        {
            qsc_memutils_copy(dirpath, path, spos);
            dirpath[spos] = '\0';
            res = true;
        }
    }

    return res;
}

udif_errors udif_storage_initialize(udif_storage_context* ctx, const char* basepath)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(basepath != NULL);

    char lpath[UDIF_STORAGE_MAX_PATH] = { 0U };
    char mpath[UDIF_STORAGE_MAX_PATH] = { 0U };
    udif_errors res;
    bool ret;

    res = udif_error_none;

    if (ctx != NULL && basepath != NULL)
    {
        qsc_memutils_clear(ctx, sizeof(udif_storage_context));

        /* copy base path */
        qsc_memutils_copy(ctx->basepath, basepath, UDIF_STORAGE_MAX_PATH - 1U);
        ctx->basepath[UDIF_STORAGE_MAX_PATH - 1U] = '\0';

        /* create base directory */
        ret = qsc_folderutils_create_directory_tree(ctx->basepath);

        if (ret == true)
        {
            /* create ledger subdirectories */
            for (size_t i = 0U; i < 3U; ++i)
            {
                qsc_stringutils_copy_string(lpath, sizeof(lpath), ctx->basepath);
                qsc_folderutils_append_delimiter(lpath);
                qsc_stringutils_concat_strings(lpath, sizeof(lpath), UDIF_MCEL_LEDGER_NAMES[i]);

                ret = qsc_folderutils_create_directory_tree(lpath);

                if (ret == true)
                {
                    /* create mcel subdirectory */
                    qsc_stringutils_copy_string(mpath, sizeof(mpath), lpath);
                    qsc_folderutils_append_delimiter(mpath);
                    qsc_stringutils_concat_strings(mpath, sizeof(mpath), "mcel");

                    if (qsc_folderutils_directory_exists(mpath) == false)
                    {
                        ret = qsc_folderutils_create_directory(mpath);

                        if (ret == false)
                        {
                            res = udif_error_file_create_failed;
                            break;
                        }
                    }
                }
                else
                {
                    res = udif_error_file_create_failed;
                    break;
                }
            }

            if (res == udif_error_none)
            {
                ctx->currentledger = UDIF_LEDGER_MEMBERSHIP;
                ctx->initialized = true;
            }
        }
        else
        {
            res = udif_error_file_create_failed;
        }
    }
    else
    {
        res = udif_error_invalid_parameter;
    }

    return res;
}

void udif_storage_set_ledger(udif_storage_context* ctx, udif_ledger_type ledgertype)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(ctx->initialized);
    UDIF_ASSERT(ledgertype <= UDIF_LEDGER_REGISTRY);

    if (ctx != NULL && ctx->initialized && ledgertype <= UDIF_LEDGER_REGISTRY)
    {
        ctx->currentledger = ledgertype;
    }
}

void udif_storage_get_callbacks(udif_storage_context* ctx, void* callbacks)
{
    UDIF_ASSERT(ctx != NULL);
    UDIF_ASSERT(callbacks != NULL);
    UDIF_ASSERT(ctx->initialized);

    if (ctx != NULL && callbacks != NULL && ctx->initialized)
    {
        mcel_store_callbacks* cb;

        cb = (mcel_store_callbacks*)callbacks;
        cb->context = ctx;
        cb->write = udif_storage_write;
        cb->read = udif_storage_read;
        cb->append = udif_storage_append;
        cb->size = udif_storage_size;
        cb->flush = udif_storage_flush;
    }
}

void udif_storage_dispose(udif_storage_context* ctx)
{
    UDIF_ASSERT(ctx != NULL);

    if (ctx != NULL && ctx->initialized)
    {
        udif_storage_close_all_handles(ctx);
        qsc_memutils_clear(ctx, sizeof(udif_storage_context));
    }
}

bool udif_storage_write(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen)
{
    UDIF_ASSERT(context != NULL);
    UDIF_ASSERT(loc != NULL);
    UDIF_ASSERT(data != NULL);

    udif_storage_context* ctx;
    char path[UDIF_STORAGE_MAX_PATH] = { 0U };
    char dir[UDIF_STORAGE_MAX_PATH] = { 0U };
    bool ret;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL)
    {
        ctx = (udif_storage_context*)context;

        if (ctx->initialized)
        {
            /* resolve path */
            ret = udif_storage_resolve_path(ctx, loc, loclen, path, sizeof(path));

            if (ret == true)
            {
                /* extract directory from path and create it */
                ret = udif_storage_extract_directory(path, dir, sizeof(dir));

                if (ret == true)
                {
                    res = qsc_folderutils_create_directory_tree(dir);
                }

                if (res == true)
                {
                    /* write file */
                    res = (qsc_fileutils_safe_write(path, 0U, (const char*)data, datalen) == datalen);
                }
            }
        }
    }

    return res;
}

bool udif_storage_read(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread)
{
    UDIF_ASSERT(context != NULL);
    UDIF_ASSERT(loc != NULL);
    UDIF_ASSERT(data != NULL);
    UDIF_ASSERT(outread != NULL);

    udif_storage_context* ctx;
    char path[UDIF_STORAGE_MAX_PATH] = { 0U };
    bool ret;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL && outread != NULL)
    {
        ctx = (udif_storage_context*)context;

        if (ctx->initialized)
        {
            /* resolve path */
            ret = udif_storage_resolve_path(ctx, loc, loclen, path, sizeof(path));

            if (ret == true)
            {
                /* read file */
                *outread = qsc_fileutils_safe_read(path, 0U, (char*)data, datalen);
                res = (*outread > 0U);
            }
        }
    }

    return res;
}

bool udif_storage_append(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos)
{
    UDIF_ASSERT(context != NULL);
    UDIF_ASSERT(loc != NULL);
    UDIF_ASSERT(data != NULL);

    udif_storage_context* ctx;
    char dir[UDIF_STORAGE_MAX_PATH] = { 0U };
    char path[UDIF_STORAGE_MAX_PATH] = { 0U };
    bool ret;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL)
    {
        ctx = (udif_storage_context*)context;

        if (ctx->initialized)
        {
            /* resolve path */
            ret = udif_storage_resolve_path(ctx, loc, loclen, path, sizeof(path));

            if (ret == true)
            {
                /* extract directory from path and create it */
                ret = udif_storage_extract_directory(path, dir, sizeof(dir));

                if (ret == true)
                {
                    res = qsc_folderutils_create_directory_tree(dir);
                }

                if (res == true)
                {
                    /* get position and append to file */
                    *outpos = qsc_fileutils_get_size(path);
                    res = qsc_fileutils_append_to_file(path, (const char*)data, datalen);
                }
            }
        }
    }

    return res;
}

bool udif_storage_size(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen)
{
    UDIF_ASSERT(context != NULL);
    UDIF_ASSERT(loc != NULL);
    UDIF_ASSERT(outlen != NULL);

    udif_storage_context* ctx;
    char path[UDIF_STORAGE_MAX_PATH] = { 0U };
    bool res;

    res = false;

    if (context != NULL && loc != NULL && outlen != NULL)
    {
        ctx = (udif_storage_context*)context;

        if (ctx->initialized)
        {
            res = udif_storage_resolve_path(ctx, loc, loclen, path, sizeof(path));

            if (res == true)
            {
                *outlen = qsc_fileutils_get_size(path);
            }
        }
    }

    return res;
}

bool udif_storage_flush(void* context, const uint8_t* loc, size_t loclen)
{
    UDIF_ASSERT(context != NULL);
    UDIF_ASSERT(loc != NULL);

    udif_storage_context* ctx;
    char path[UDIF_STORAGE_MAX_PATH] = { 0U };
    size_t slen;
    bool res;

    res = false;

    if (context != NULL && loc != NULL)
    {
        ctx = (udif_storage_context*)context;

        if (ctx->initialized)
        {
            res = udif_storage_resolve_path(ctx, loc, loclen, path, sizeof(path));

            if (res == true)
            {
                /* find cached handle and flush if present */
                for (size_t i = 0U; i < ctx->handlecount; ++i)
                {
                    if (ctx->handles[i].isopen == true)
                    {
                        slen = qsc_stringutils_string_size(path);

                        if (qsc_stringutils_compare_strings(ctx->handles[i].path, path, slen) == true)
                        {
                            qsc_fileutils_flush(ctx->handles[i].fp);
                            break;
                        }
                    }
                }
            }
        }
    }

    return res;
}
