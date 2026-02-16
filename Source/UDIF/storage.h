/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef UDIF_STORAGE_H
#define UDIF_STORAGE_H

#include "udifcommon.h"
#include "udif.h"
#include "fileutils.h"

/**
 * \file storage.h
 * \brief UDIF file-based storage backend for MCEL integration
 *
 * This module implements the storage backend required by MCEL's
 * mcel_store_callbacks interface. It provides file-based persistence
 * for ledger records, blocks, checkpoints, and indexes.
 *
 * The storage backend manages three separate ledger namespaces:
 * - Membership ledger (certificates, capabilities, treaties)
 * - Transaction ledger (object operations, queries)
 * - Registry ledger (object ownership records)
 *
 * Storage Layout:
 *   <base_path>/
 *     membership/
 *       mcel/records      - Append-only membership events
 *       mcel/blocks       - Sealed membership blocks
 *       mcel/checkpoints  - Signed membership checkpoints
 *       mcel/head         - Current checkpoint head
 *     transaction/
 *       mcel/records      - Append-only transaction events
 *       mcel/blocks       - Sealed transaction blocks
 *       mcel/checkpoints  - Signed transaction checkpoints
 *       mcel/head         - Current checkpoint head
 *     registry/
 *       mcel/records      - Append-only registry events
 *       mcel/blocks       - Sealed registry blocks
 *       mcel/checkpoints  - Signed registry checkpoints
 *       mcel/head         - Current checkpoint head
 */

/*!
 * \def UDIF_STORAGE_MAX_PATH
 * \brief Maximum file path length
 */
#define UDIF_STORAGE_MAX_PATH 512U

/*!
 * \def UDIF_STORAGE_MAX_HANDLES
 * \brief Maximum number of cached file handles
 */
#define UDIF_STORAGE_MAX_HANDLES 16U

/*!
 * \enum udif_ledger_type
 * \brief Ledger namespace identifiers
 */
typedef enum udif_ledger_type
{
    UDIF_LEDGER_MEMBERSHIP = 0U,        /*!< Membership ledger namespace */
    UDIF_LEDGER_TRANSACTION = 1U,       /*!< Transaction ledger namespace */
    UDIF_LEDGER_REGISTRY = 2U           /*!< Registry ledger namespace */
} udif_ledger_type;

/*!
 * \struct udif_file_handle
 * \brief Cached file handle with metadata
 */
typedef struct udif_file_handle
{
    FILE* fp;                           /*!< File pointer */
    char path[UDIF_STORAGE_MAX_PATH];   /*!< Full file path */
    uint64_t lastaccess;                /*!< Last access timestamp (for LRU) */
    bool isopen;                        /*!< Handle is currently open */
} udif_file_handle;

/*!
 * \struct udif_storage_context
 * \brief File-based storage context for MCEL integration
 *
 * This context implements the mcel_store_callbacks interface using
 * a file-based backend with cached file handles for performance.
 */
typedef struct udif_storage_context
{
    char basepath[UDIF_STORAGE_MAX_PATH];                   /*!< Base directory for all ledgers */
    udif_file_handle handles[UDIF_STORAGE_MAX_HANDLES];     /*!< Cached file handles */
    size_t handlecount;                                     /*!< Number of cached handles */
    udif_ledger_type currentledger;                         /*!< Current active ledger namespace */
    bool initialized;                                       /*!< Storage is initialized */
} udif_storage_context;

/*!
 * \brief Initialize storage context
 *
 * Creates the base directory structure and initializes the storage context.
 * This must be called before any storage operations.
 *
 * \param ctx: The storage context to initialize
 * \param basepath: [const] The base directory path (e.g., "/var/udif/ledgers/entity_serial")
 *
 * \return Returns udif_error_none on success
 */
UDIF_EXPORT_API udif_errors udif_storage_initialize(udif_storage_context* ctx, const char* basepath);

/*!
 * \brief Set active ledger namespace
 *
 * Switches the storage context to operate on a specific ledger namespace.
 * All subsequent storage operations will use this namespace until changed.
 *
 * \param ctx: The storage context
 * \param ledgertype: The ledger namespace to activate
 */
UDIF_EXPORT_API void udif_storage_set_ledger(udif_storage_context* ctx, udif_ledger_type ledgertype);

/*!
 * \brief Get MCEL store callbacks for this context
 *
 * Returns a populated mcel_store_callbacks structure that can be passed
 * to MCEL initialization functions.
 *
 * \param ctx: The storage context
 * \param callbacks: The output callbacks structure
 */
UDIF_EXPORT_API void udif_storage_get_callbacks(udif_storage_context* ctx, void* callbacks);

/*!
 * \brief Dispose storage context
 *
 * Closes all cached file handles and frees resources.
 *
 * \param ctx: The storage context to dispose
 */
UDIF_EXPORT_API void udif_storage_dispose(udif_storage_context* ctx);

/*!
 * \brief Write complete object to storage
 *
 * Overwrites the entire content at a logical location.
 * Creates parent directories if necessary.
 *
 * \param context: The storage context
 * \param loc: [const] The logical location identifier
 * \param loclen: The location identifier length
 * \param data: [const] The data to write
 * \param datalen: The data length
 *
 * \return Returns true on success
 */
UDIF_EXPORT_API bool udif_storage_write(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen);

/*!
 * \brief Read complete object from storage
 *
 * Reads the entire content at a logical location into a buffer.
 *
 * \param context: The storage context
 * \param loc: [const] The logical location identifier
 * \param loclen: The location identifier length
 * \param data: The output buffer
 * \param datalen: The output buffer length
 * \param outread: Pointer to receive bytes read
 *
 * \return Returns true on success
 */
UDIF_EXPORT_API bool udif_storage_read(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread);

/*!
 * \brief Append data to append-only object
 *
 * Appends data to the end of an append-only file and returns the position.
 * Creates the file if it doesn't exist.
 *
 * \param context: The storage context
 * \param loc: [const] The logical location identifier
 * \param loclen: The location identifier length
 * \param data: [const] The data to append
 * \param datalen: The data length
 * \param outpos: Pointer to receive append position (can be NULL)
 *
 * \return Returns true on success
 */
UDIF_EXPORT_API bool udif_storage_append(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos);

/*!
 * \brief Get object size
 *
 * Returns the size in bytes of an object at a logical location.
 *
 * \param context: The storage context
 * \param loc: [const] The logical location identifier
 * \param loclen: The location identifier length
 * \param outlen: Pointer to receive size in bytes
 *
 * \return Returns true on success
 */
UDIF_EXPORT_API bool udif_storage_size(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen);

/*!
 * \brief Flush buffered data
 *
 * Forces all buffered data for a logical location to be written to disk.
 *
 * \param context: The storage context
 * \param loc: [const] The logical location identifier
 * \param loclen: The location identifier length
 *
 * \return Returns true on success
 */
UDIF_EXPORT_API bool udif_storage_flush(void* context, const uint8_t* loc, size_t loclen);

/* === Internal Helper Functions === */

/*!
 * \brief Resolve logical location to file path
 *
 * Converts an MCEL logical location to a full file system path
 * based on the current ledger namespace.
 *
 * \param ctx: [const] The storage context
 * \param loc: [const] The logical location
 * \param loclen: The location length
 * \param outpath: The output path buffer
 * \param outpathlen: The output path buffer length
 *
 * \return Returns true on success
 */
bool udif_storage_resolve_path(const udif_storage_context* ctx, const uint8_t* loc, size_t loclen, char* outpath, size_t outpathlen);

/*!
 * \brief Create directory recursively
 *
 * Creates all parent directories needed for a path.
 *
 * \param path: [const] The directory path
 *
 * \return Returns true on success
 */
bool udif_storage_mkdir_recursive(const char* path);

/*!
 * \brief Get or open cached file handle
 *
 * Returns a cached file handle for a path, opening it if necessary.
 * Uses LRU eviction if cache is full.
 *
 * \param ctx: The storage context
 * \param path: [const] The file path
 * \param mode: [const] The open mode string
 * \param outfp: Pointer to receive FILE*
 *
 * \return Returns true on success
 */
bool udif_storage_get_handle(udif_storage_context* ctx, const char* path, qsc_fileutils_mode mode, FILE** outfp);

/*!
 * \brief Close and evict a cached handle
 *
 * Closes a file handle and removes it from the cache.
 *
 * \param ctx: The storage context
 * \param path: [const] The file path to evict
 */
void udif_storage_evict_handle(udif_storage_context* ctx, const char* path);

/*!
 * \brief Close all cached handles
 *
 * Closes all cached file handles (used during dispose).
 *
 * \param ctx: The storage context
 */
void udif_storage_close_all_handles(udif_storage_context* ctx);

#endif /* UDIF_STORAGE_H */
