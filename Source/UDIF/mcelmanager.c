/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 */

#include "mcelmanager.h"
#include "mcel.h"
#include "acp.h"
#include "folderutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include <time.h>

 /* Internal constants */
#define DEFAULT_MEMBERSHIP_INTERVAL 1000U
#define DEFAULT_TRANSACTION_INTERVAL 10000U
#define DEFAULT_REGISTRY_INTERVAL 5000U
#define MAX_RECORD_PATH (QSC_SYSTEM_MAX_PATH)
#define MAX_BLOCK_BUFFER 65536U

static const char* get_ledger_namespace(udif_ledger_type type)
{
    switch (type)
    {
        case UDIF_LEDGER_MEMBERSHIP:
            return "membership";
        case UDIF_LEDGER_TRANSACTION:
            return "transaction";
        case UDIF_LEDGER_REGISTRY:
            return "registry";
        default:
            return "unknown";
    }
}

static udif_mcel_ledger* get_active_ledger(udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    udif_mcel_ledger* pres;

    pres = NULL;

    if (mgr != NULL)
    {
        switch (mgr->actledger)
        {
        case UDIF_LEDGER_MEMBERSHIP:
            pres = mgr->membership;
            break;
        case UDIF_LEDGER_TRANSACTION:
            pres = mgr->transaction;
            break;
        case UDIF_LEDGER_REGISTRY:
            pres = mgr->registry;
            break;
        default:
            pres = NULL;
        }
    }

    return pres;
}

static uint64_t get_checkpoint_interval(const udif_mcel_manager* mgr, udif_ledger_type type)
{
    MCEL_ASSERT(mgr != NULL);

    uint64_t res;

    res = 0U;

    if (mgr != NULL)
    {
        switch (type)
        {
        case UDIF_LEDGER_MEMBERSHIP:
            res = mgr->checkconfig.membinterval;
            break;
        case UDIF_LEDGER_TRANSACTION:
            res = mgr->checkconfig.transinterval;
            break;
        case UDIF_LEDGER_REGISTRY:
            res = mgr->checkconfig.reginterval;
            break;
        default:
            res = 0U;
        }
    }

    return res;
}

static bool should_checkpoint(const udif_mcel_manager* mgr, const udif_mcel_ledger* ledger)
{
    MCEL_ASSERT(mgr != NULL);
    MCEL_ASSERT(ledger != NULL);

    uint64_t ival;
    uint64_t recs;
    bool res;

    res = false;

    if (mgr != NULL && ledger != NULL)
    {
        if (mgr->checkconfig.autocheckpointenabled == true && ledger != NULL)
        {
            ival = get_checkpoint_interval(mgr, ledger->type);

            if (ival != 0 && ledger->totalrecords != 0U)
            {
                recs = ledger->totalrecords - ledger->firstrecordincheckpoint;
                res = (recs >= ival);
            }
        }
    }

    return res;
}

static void storage_get_record_path(char* recpath, size_t pathlen, uint64_t seq)
{
    char num[32U] = { 0U };

    qsc_stringutils_concat_strings(recpath, pathlen, "records");
    qsc_folderutils_append_delimiter(recpath);
    qsc_stringutils_uint64_to_string(seq, num, sizeof(num));
    qsc_stringutils_concat_strings(recpath, pathlen, num);
    qsc_stringutils_concat_strings(recpath, pathlen, ".rec");
}

static bool storage_write_cb(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen)
{
    MCEL_ASSERT(context != NULL);
    MCEL_ASSERT(loc != NULL);
    MCEL_ASSERT(data != NULL);

    udif_storage_context* storage;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL)
    {
        storage = (udif_storage_context*)context;
        res = udif_storage_write(storage, loc, loclen, data, datalen);
    }

    return res;
}

static bool storage_read_cb(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread)
{
    MCEL_ASSERT(context != NULL);
    MCEL_ASSERT(loc != NULL);
    MCEL_ASSERT(data != NULL);
    MCEL_ASSERT(outread != NULL);

    udif_storage_context* storage;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL && outread != NULL)
    {
        storage = (udif_storage_context*)context;
        res = udif_storage_read(storage, loc, loclen, data, datalen, outread);
    }

    return res;
}

static bool storage_append_cb(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos)
{
    MCEL_ASSERT(context != NULL);
    MCEL_ASSERT(loc != NULL);
    MCEL_ASSERT(data != NULL);

    udif_storage_context* storage;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && data != NULL)
    {
        storage = (udif_storage_context*)context;
        res = udif_storage_append(storage, loc, loclen, data, datalen, outpos);
    }

    return res;
}

static bool storage_size_cb(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen)
{
    MCEL_ASSERT(context != NULL);
    MCEL_ASSERT(loc != NULL);
    MCEL_ASSERT(outlen != NULL);

    udif_storage_context* storage;
    bool res;

    res = false;

    if (context != NULL && loc != NULL && outlen != NULL)
    {
        storage = (udif_storage_context*)context;
        res = udif_storage_size(storage, loc, loclen, outlen);
    }

    return res;
}

static bool storage_flush_cb(void* context, const uint8_t* loc, size_t loclen)
{
    MCEL_ASSERT(context != NULL);
    MCEL_ASSERT(loc != NULL);

    udif_storage_context* storage;
    bool res;

    res = false;

    if (context != NULL && loc != NULL)
    {
        storage = (udif_storage_context*)context;
        res = udif_storage_flush(storage, loc, loclen);
    }

    return res;
}

static void setup_storage_callbacks(mcel_store_callbacks* callbacks, udif_storage_context* storage)
{
    MCEL_ASSERT(callbacks != NULL);
    MCEL_ASSERT(storage != NULL);

    callbacks->context = storage;
    callbacks->write = storage_write_cb;
    callbacks->read = storage_read_cb;
    callbacks->append = storage_append_cb;
    callbacks->size = storage_size_cb;
    callbacks->flush = storage_flush_cb;
}

static udif_mcel_ledger* create_ledger(udif_storage_context* storage, udif_ledger_type type, const uint8_t* verkey, uint32_t blocklen)
{
    udif_mcel_ledger* ledger;
    mcel_store_callbacks callbacks;
    uint8_t headbuf[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    bool ret;

    /* allocate ledger */
    ledger = (udif_mcel_ledger*)qsc_memutils_malloc(sizeof(udif_mcel_ledger));

    if (ledger != NULL)
    {
        qsc_memutils_clear(ledger, sizeof(udif_mcel_ledger));

        /* set ledger type and namespace */
        ledger->type = type;
        qsc_stringutils_copy_string(ledger->namespaceid, sizeof(ledger->namespaceid), get_ledger_namespace(type));

        /* setup storage callbacks */
        setup_storage_callbacks(&callbacks, storage);

        /* set active ledger in storage */
        udif_storage_set_ledger(storage, type);

        /* initialize MCEL ledger state */
        ret = mcel_ledger_initialize(&ledger->mcelstate, &callbacks, (const uint8_t*)ledger->namespaceid,
            qsc_stringutils_string_size(ledger->namespaceid), verkey, headbuf, sizeof(headbuf));

        if (ret == true)
        {
            /* allocate commitment batch buffer */
            ledger->commitscap = blocklen;
            ledger->reccommits = (uint8_t*)qsc_memutils_malloc(MCEL_BLOCK_HASH_SIZE * blocklen);

            if (ledger->reccommits != NULL)
            {
                qsc_memutils_clear(ledger->reccommits, MCEL_BLOCK_HASH_SIZE * blocklen);

                /* initialize sequences */
                ledger->nextrecordseq = 0U;
                ledger->nextblockseq = 0U;
                ledger->nextcheckpointseq = 0U;
                ledger->firstrecordinblock = 0U;
                ledger->firstrecordincheckpoint = 0U;
                ledger->commitscount = 0U;
                ledger->haveblockroot = false;

                /* initialize statistics */
                ledger->totalrecords = 0U;
                ledger->totalblocks = 0U;
                ledger->totalcheckpoints = 0U;
            }
            else
            {
                qsc_memutils_alloc_free(ledger);
                ledger = NULL;
            }
        }
        else
        {
            qsc_memutils_alloc_free(ledger);
            ledger = NULL;
        }
    }

    return ledger;
}

static void destroy_ledger(udif_mcel_ledger* ledger)
{
    if (ledger != NULL)
    {
        if (ledger->reccommits != NULL)
        {
            qsc_memutils_clear(ledger->reccommits, MCEL_BLOCK_HASH_SIZE * ledger->commitscap);
            qsc_memutils_alloc_free(ledger->reccommits);
        }

        qsc_memutils_clear(ledger, sizeof(udif_mcel_ledger));
        qsc_memutils_alloc_free(ledger);
    }
}

static bool seal_block_internal(udif_mcel_manager* mgr, udif_mcel_ledger* ledger)
{
    mcel_block_header blkhdr = { 0U };
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blockbuf[MAX_BLOCK_BUFFER] = { 0U };
    uint64_t outlen;
    uint64_t timestamp;
    bool res;
    bool ret;

    res = false;

    if (ledger->commitscount != 0U)
    {
        /* fill block header */
        qsc_memutils_clear(&blkhdr, sizeof(mcel_block_header));
        qsc_memutils_copy(blkhdr.keyid, mgr->keyid, MCEL_BLOCK_KEYID_SIZE);
        blkhdr.block_sequence = ledger->nextblockseq;
        blkhdr.first_record_seq = ledger->firstrecordinblock;

        timestamp = (uint64_t)time(NULL);
        blkhdr.timestamp = timestamp;
        blkhdr.record_count = (uint32_t)ledger->commitscount;
        blkhdr.flags = 0U;
        blkhdr.version = MCEL_BLOCK_VERSION;
        outlen = 0U;

        /* seal block */
        ret = mcel_ledger_seal_block(&ledger->mcelstate, blkroot, blkcommit, &blkhdr, ledger->reccommits,
            ledger->commitscount, blockbuf, sizeof(blockbuf), &outlen);

        if (ret == true)
        {
            /* save block root for checkpoint */
            qsc_memutils_copy(ledger->lastblockroot, blkroot, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_copy(ledger->lastblockcommit, blkcommit, MCEL_BLOCK_HASH_SIZE);
            ledger->haveblockroot = true;

            /* update tracking */
            ++ledger->nextblockseq;
            ++ledger->totalblocks;
            ledger->firstrecordinblock = ledger->nextrecordseq;

            /* reset batch */
            ledger->commitscount = 0U;
            qsc_memutils_clear(ledger->reccommits, MCEL_BLOCK_HASH_SIZE * ledger->commitscap);
            res = true;
        }
    }
    else
    {
        res = true;
    }

    return res;
}

static bool seal_checkpoint_internal(udif_mcel_manager* mgr, udif_mcel_ledger* ledger)
{
    mcel_checkpoint_header chkhdr = { 0U };
    uint8_t chkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t bundlebuf[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint64_t outpos;
    uint64_t timestamp;
    bool res;
    bool ret;

    res = false;
    ret = ledger->haveblockroot;

    /* ensure we have a block root */
    if (ret == false)
    {
        ret = seal_block_internal(mgr, ledger);
    }

    if (ret == true)
    {
        /* fill checkpoint header */
        qsc_memutils_clear(&chkhdr, sizeof(mcel_checkpoint_header));
        qsc_memutils_copy(chkhdr.keyid, mgr->keyid, MCEL_CHECKPOINT_KEYID_SIZE);
        chkhdr.chk_sequence = ledger->nextcheckpointseq;
        chkhdr.first_record_seq = ledger->firstrecordincheckpoint;

        timestamp = (uint64_t)time(NULL);
        chkhdr.timestamp = timestamp;
        chkhdr.record_count = (uint32_t)(ledger->totalrecords - ledger->firstrecordincheckpoint);
        chkhdr.flags = 0;
        chkhdr.version = MCEL_CHECKPOINT_VERSION;
        outpos = 0U;

        /* seal checkpoint */
        ret = mcel_ledger_seal_checkpoint(&ledger->mcelstate, chkcommit, &chkhdr, ledger->lastblockroot, mgr->sigkey, 
            bundlebuf, sizeof(bundlebuf), &outpos);

        if (ret == true)
        {
            /* update tracking */
            ++ledger->nextcheckpointseq;
            ++ledger->totalcheckpoints;
            ledger->firstrecordincheckpoint = ledger->totalrecords;
            res = true;
        }
    }

    return res;
}

void udif_mcel_get_default_config(udif_checkpoint_config* config)
{
    MCEL_ASSERT(config != NULL);

    if (config != NULL)
    {
        config->membinterval = DEFAULT_MEMBERSHIP_INTERVAL;
        config->transinterval = DEFAULT_TRANSACTION_INTERVAL;
        config->reginterval = DEFAULT_REGISTRY_INTERVAL;
        config->blocksize = UDIF_MCEL_DEFAULT_BLOCK_SIZE;
        config->autocheckpointenabled = true;
    }
}

udif_mcel_manager* udif_mcel_initialize(const char* basepath, const udif_checkpoint_config* config)
{
    MCEL_ASSERT(basepath != NULL);

    udif_mcel_manager* mgr;
    udif_checkpoint_config defconfig = { 0U };
    udif_errors err;

    mgr = NULL;

    if (basepath != NULL)
    {
        /* allocate manager */
        mgr = (udif_mcel_manager*)qsc_memutils_malloc(sizeof(udif_mcel_manager));

        if (mgr != NULL)
        {
            qsc_memutils_clear(mgr, sizeof(udif_mcel_manager));

            /* initialize storage backend */
            err = udif_storage_initialize(&mgr->storage, basepath);

            if (err == udif_error_none)
            {
                /* generate Dilithium keypair */
                mcel_signature_generate_keypair(mgr->verkey, mgr->sigkey, qsc_acp_generate);

                /* compute key identifier (hash of public key) */
                qsc_sha3_compute256(mgr->keyid, mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);

                /* set checkpoint configuration */
                if (config != NULL)
                {
                    qsc_memutils_copy(&mgr->checkconfig, config, sizeof(udif_checkpoint_config));
                }
                else
                {
                    udif_mcel_get_default_config(&defconfig);
                    qsc_memutils_copy(&mgr->checkconfig, &defconfig, sizeof(udif_checkpoint_config));
                }

                /* initialize three ledgers */
                mgr->membership = create_ledger(&mgr->storage, UDIF_LEDGER_MEMBERSHIP, mgr->verkey, mgr->checkconfig.blocksize);
                mgr->transaction = create_ledger(&mgr->storage, UDIF_LEDGER_TRANSACTION, mgr->verkey, mgr->checkconfig.blocksize);
                mgr->registry = create_ledger(&mgr->storage, UDIF_LEDGER_REGISTRY, mgr->verkey, mgr->checkconfig.blocksize);

                if (mgr->membership != NULL && mgr->transaction != NULL && mgr->registry != NULL)
                {
                    /* set initial state */
                    mgr->actledger = UDIF_LEDGER_MEMBERSHIP;
                    mgr->initialized = true;
                    mgr->readonly = false;
                }
                else
                {
                    if (mgr->membership != NULL)
                    {
                        destroy_ledger(mgr->membership);
                    }

                    if (mgr->transaction != NULL)
                    {
                        destroy_ledger(mgr->transaction);
                    }

                    if (mgr->registry != NULL)
                    {
                        destroy_ledger(mgr->registry);
                    }

                    qsc_memutils_clear(mgr->sigkey, MCEL_ASYMMETRIC_SIGNING_KEY_SIZE);
                    qsc_memutils_clear(mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);

                    udif_storage_dispose(&mgr->storage);
                    qsc_memutils_alloc_free(mgr);
                    mgr = NULL;
                }
            }
            else
            {
                qsc_memutils_alloc_free(mgr);
                mgr = NULL;
            }
        }
    }

    return mgr;
}

udif_mcel_manager* udif_mcel_open(const char* basepath, bool readonly, const uint8_t* sigkey, const uint8_t* verkey)
{
    MCEL_ASSERT(basepath != NULL);

    udif_mcel_manager* mgr;
    udif_checkpoint_config defconfig = { 0U };
    udif_errors err;

    mgr = NULL;

    if (basepath != NULL)
    {
        /* allocate manager */
        mgr = (udif_mcel_manager*)qsc_memutils_malloc(sizeof(udif_mcel_manager));

        if (mgr != NULL)
        {
            qsc_memutils_clear(mgr, sizeof(udif_mcel_manager));

            /* initialize storage backend */
            err = udif_storage_initialize(&mgr->storage, basepath);

            if (err == udif_error_none)
            {
                /* copy keys */
                qsc_memutils_copy(mgr->verkey, verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);

                if (readonly == false)
                {
                    qsc_memutils_copy(mgr->sigkey, sigkey, MCEL_ASYMMETRIC_SIGNING_KEY_SIZE);
                }

                /* compute key identifier */
                qsc_sha3_compute256(mgr->keyid, mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);

                /* set default checkpoint configuration */
                udif_mcel_get_default_config(&defconfig);
                qsc_memutils_copy(&mgr->checkconfig, &defconfig, sizeof(udif_checkpoint_config));

                /* open three ledgers */
                mgr->membership = create_ledger(&mgr->storage, UDIF_LEDGER_MEMBERSHIP, mgr->verkey, mgr->checkconfig.blocksize);
                mgr->transaction = create_ledger(&mgr->storage, UDIF_LEDGER_TRANSACTION, mgr->verkey, mgr->checkconfig.blocksize);
                mgr->registry = create_ledger(&mgr->storage, UDIF_LEDGER_REGISTRY, mgr->verkey, mgr->checkconfig.blocksize);

                if (mgr->membership != NULL && mgr->transaction != NULL && mgr->registry != NULL)
                {
                    /* set initial state */
                    mgr->actledger = UDIF_LEDGER_MEMBERSHIP;
                    mgr->initialized = true;
                    mgr->readonly = readonly;
                }
                else
                {
                    if (mgr->membership != NULL)
                    {
                        destroy_ledger(mgr->membership);
                    }

                    if (mgr->transaction != NULL)
                    {
                        destroy_ledger(mgr->transaction);
                    }

                    if (mgr->registry != NULL)
                    {
                        destroy_ledger(mgr->registry);
                    }

                    qsc_memutils_clear(mgr->sigkey, MCEL_ASYMMETRIC_SIGNING_KEY_SIZE);
                    qsc_memutils_clear(mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);
                    udif_storage_dispose(&mgr->storage);
                    qsc_memutils_alloc_free(mgr);
                    mgr = NULL;
                }
            }
            else
            {
                qsc_memutils_alloc_free(mgr);
                mgr = NULL;
            }
        }
    }

    return mgr;
}

void udif_mcel_dispose(udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    if (mgr != NULL)
    {
        /* flush all pending blocks */
        udif_mcel_flush_all(mgr);

        /* destroy ledgers */
        if (mgr->membership != NULL)
        {
            destroy_ledger(mgr->membership);
        }

        if (mgr->transaction != NULL)
        {
            destroy_ledger(mgr->transaction);
        }

        if (mgr->registry != NULL)
        {
            destroy_ledger(mgr->registry);
        }

        /* clear and free keys */
        qsc_memutils_clear(mgr->sigkey, MCEL_ASYMMETRIC_SIGNING_KEY_SIZE);
        qsc_memutils_clear(mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);

        /* dispose storage */
        udif_storage_dispose(&mgr->storage);

        /* clear and free manager */
        qsc_memutils_clear(mgr, sizeof(udif_mcel_manager));
        qsc_memutils_alloc_free(mgr);
    }
}

bool udif_mcel_set_active_ledger(udif_mcel_manager* mgr, udif_ledger_type ledger)
{
    MCEL_ASSERT(mgr != NULL);

    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true)
    {
        if (ledger == UDIF_LEDGER_MEMBERSHIP || ledger == UDIF_LEDGER_TRANSACTION || ledger == UDIF_LEDGER_REGISTRY)
        {
            mgr->actledger = ledger;
            udif_storage_set_ledger(&mgr->storage, ledger);
            res = true;
        }
    }

    return res;
}

udif_ledger_type udif_mcel_get_active_ledger(const udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    udif_ledger_type res;

    res = UDIF_LEDGER_MEMBERSHIP;

    if (mgr != NULL && mgr->initialized == true)
    {
        res = mgr->actledger;
    }

    return res;
}

bool udif_mcel_add_record(udif_mcel_manager* mgr, const uint8_t* data, size_t datalen, bool encrypted, uint64_t* outseq)
{
    MCEL_ASSERT(mgr != NULL);
    MCEL_ASSERT(data != NULL);
    MCEL_ASSERT(outseq != NULL);

    udif_mcel_ledger* ledger;
    mcel_record_header rechdr = { 0U };
    uint8_t pldcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t reccommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    char recpath[MAX_RECORD_PATH] = { 0U };
    uint64_t seq;
    uint64_t timestamp;
    bool res;
    bool ret;

    res = false;

    if (mgr != NULL && mgr->initialized == true && data != NULL && mgr->readonly == false)
    {
        ledger = get_active_ledger(mgr);

        if (ledger != NULL)
        {
            /* get sequence number */
            seq = ledger->nextrecordseq;

            /* store actual record data */
            storage_get_record_path(recpath, sizeof(recpath), seq);
            ret = udif_storage_write(&mgr->storage, (const uint8_t*)recpath, qsc_stringutils_string_size(recpath), data, datalen);

            if (ret == true)
            {
                /* compute payload commitment */
                ret = mcel_payload_commit(pldcommit, encrypted, data, datalen);

                if (ret == true)
                {
                    /* fill record header */
                    qsc_memutils_clear(&rechdr, sizeof(mcel_record_header));
                    qsc_memutils_copy(rechdr.keyid, mgr->keyid, MCEL_RECORD_KEYID_SIZE);
                    rechdr.sequence = seq;

                    timestamp = (uint64_t)time(NULL);
                    rechdr.timestamp = timestamp;
                    rechdr.payload_len = (uint32_t)datalen;
                    rechdr.type = mcel_record_type_event;
                    rechdr.flags = encrypted ? MCEL_RECORD_FLAG_ENCRYPTED : 0;
                    rechdr.version = MCEL_RECORD_VERSION;

                    /* compute record commitment */
                    ret = mcel_record_commit(reccommit, &rechdr, pldcommit);

                    if (ret == true)
                    {
                        /* add commitment to batch buffer */
                        if (ledger->commitscount >= ledger->commitscap)
                        {
                            /* batch is full seal block first */
                            if (seal_block_internal(mgr, ledger) == false)
                            {
                                ret = false;
                            }
                        }

                        if (ret == true)
                        {
                            qsc_memutils_copy(&ledger->reccommits[ledger->commitscount * MCEL_BLOCK_HASH_SIZE], reccommit, MCEL_BLOCK_HASH_SIZE);
                            ++ledger->commitscount;

                            /* update tracking */
                            ++ledger->nextrecordseq;
                            ++ledger->totalrecords;

                            /* check if automatic checkpoint needed */
                            if (should_checkpoint(mgr, ledger))
                            {
                                seal_checkpoint_internal(mgr, ledger);
                            }

                            /* return sequence number */
                            if (outseq != NULL)
                            {
                                *outseq = seq;
                            }

                            res = true;
                        }
                    }
                }
            }
        }
    }

    return res;
}

bool udif_mcel_read_record(udif_mcel_manager* mgr, uint64_t sequence, uint8_t* data, size_t datalen, size_t* outread)
{
    MCEL_ASSERT(mgr != NULL);
    MCEL_ASSERT(data != NULL);
    MCEL_ASSERT(outread != NULL);

    char recpath[MAX_RECORD_PATH] = { 0U };
    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && data != NULL && outread != NULL)
    {
        /* read record data from storage */
        storage_get_record_path(recpath, sizeof(recpath), sequence);
        res = udif_storage_read(&mgr->storage, (const uint8_t*)recpath, qsc_stringutils_string_size(recpath), data, datalen, outread);
    }

    return res;
}

bool udif_mcel_get_ledger_size(const udif_mcel_manager* mgr, uint64_t* outcount)
{
    MCEL_ASSERT(mgr != NULL);
    MCEL_ASSERT(outcount != NULL);

    const udif_mcel_ledger* ledger;
    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && outcount != NULL)
    {
        ledger = (const udif_mcel_ledger*)get_active_ledger((udif_mcel_manager*)mgr);

        if (ledger != NULL)
        {
            *outcount = ledger->totalrecords;
            res = true;
        }
    }

    return res;
}

bool udif_mcel_flush_block(udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    udif_mcel_ledger* ledger;
    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && mgr->readonly == false)
    {
        ledger = get_active_ledger(mgr);

        if (ledger != NULL)
        {
            res = seal_block_internal(mgr, ledger);
        }
    }

    return res;
}

bool udif_mcel_create_checkpoint(udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    udif_mcel_ledger* ledger;
    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && mgr->readonly == false)
    {
        ledger = get_active_ledger(mgr);

        if (ledger != NULL)
        {
            res = seal_checkpoint_internal(mgr, ledger);
        }
    }

    return res;
}

bool udif_mcel_create_checkpoint_group(udif_mcel_manager* mgr, udif_checkpoint_group* outgroup)
{
    MCEL_ASSERT(mgr != NULL);
    MCEL_ASSERT(outgroup != NULL);

    udif_checkpoint_group group;
    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && mgr->readonly == false)
    {
        qsc_memutils_clear(&group, sizeof(udif_checkpoint_group));

        /* create checkpoint for each ledger */
        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_MEMBERSHIP);
        res = seal_checkpoint_internal(mgr, mgr->membership);

        if (res && mgr->membership->mcelstate.have_head)
        {
            qsc_memutils_copy(group.membcommit, mgr->membership->mcelstate.head_commit, MCEL_BLOCK_HASH_SIZE);
            group.membershipseq = mgr->membership->nextcheckpointseq - 1U;
        }

        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);
        res = seal_checkpoint_internal(mgr, mgr->transaction) && res;

        if (res && mgr->transaction->mcelstate.have_head)
        {
            qsc_memutils_copy(group.transcommit, mgr->transaction->mcelstate.head_commit, MCEL_BLOCK_HASH_SIZE);
            group.transactionseq = mgr->transaction->nextcheckpointseq - 1U;
        }

        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_REGISTRY);
        res = seal_checkpoint_internal(mgr, mgr->registry) && res;

        if (res && mgr->registry->mcelstate.have_head)
        {
            qsc_memutils_copy(group.regcommit, mgr->registry->mcelstate.head_commit, MCEL_BLOCK_HASH_SIZE);
            group.registryseq = mgr->registry->nextcheckpointseq - 1U;
        }

        if (res == true)
        {
            /* set group metadata */
            group.height = mgr->membership->totalrecords;

            if (mgr->transaction->totalrecords > group.height)
            {
                group.height = mgr->transaction->totalrecords;
            }

            if (mgr->registry->totalrecords > group.height)
            {
                group.height = mgr->registry->totalrecords;
            }

            group.timestamp = (uint64_t)time(NULL);

            /* return group */
            if (outgroup != NULL)
            {
                qsc_memutils_copy(outgroup, &group, sizeof(udif_checkpoint_group));
            }
        }
    }

    return res;
}

bool udif_mcel_flush_all(udif_mcel_manager* mgr)
{
    MCEL_ASSERT(mgr != NULL);

    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true && mgr->readonly == false)
    {
        /* flush each ledger */
        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_MEMBERSHIP);
        res = seal_block_internal(mgr, mgr->membership);

        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_TRANSACTION);
        res = seal_block_internal(mgr, mgr->transaction) && res;

        udif_mcel_set_active_ledger(mgr, UDIF_LEDGER_REGISTRY);
        res = seal_block_internal(mgr, mgr->registry) && res;

        /* flush storage */
        udif_storage_flush(&mgr->storage, (const uint8_t*)"records", 7);
    }

    return res;
}

bool udif_mcel_get_keypair(const udif_mcel_manager* mgr, uint8_t* sigkey, uint8_t* verkey)
{
    MCEL_ASSERT(mgr != NULL);

    bool res;

    res = false;

    if (mgr != NULL && mgr->initialized == true)
    {
        if (sigkey != NULL)
        {
            qsc_memutils_copy(sigkey, mgr->sigkey, MCEL_ASYMMETRIC_SIGNING_KEY_SIZE);
            res = true;
        }

        if (verkey != NULL)
        {
            qsc_memutils_copy(verkey, mgr->verkey, MCEL_ASYMMETRIC_VERIFY_KEY_SIZE);
            res = true;
        }
    }

    return res;
}
