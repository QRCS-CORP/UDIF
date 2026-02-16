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

#ifndef UDIF_MCEL_MANAGER_H
#define UDIF_MCEL_MANAGER_H

#include "storage.h"
#include "mcel.h"

 /**
 * \file mcel_manager.h
 * \brief UDIF MCEL Manager - Record-oriented API over MCEL commitment ledger
 *
 * MCEL is a commitment-based ledger that stores cryptographic commitments,
 * not actual records. This manager provides a simplified record-oriented API:
 *
 * Architecture:
 * 1. Application stores actual record data via UDIF storage
 * 2. MCEL computes and stores record commitments
 * 3. Manager batches commitments into blocks (Merkle trees)
 * 4. Manager seals checkpoints (signed block roots)
 * 5. Coordinates checkpoints across 3 ledgers for UDIF anchors
 */

 /* MCEL constants */
#define UDIF_MCEL_BLOCK_HASH_SIZE 32U
#define UDIF_MCEL_KEYID_SIZE 32U
#define UDIF_MCEL_DEFAULT_BLOCK_SIZE 100U

/*!
 * \struct udif_checkpoint_config
 * \brief Configuration for automatic checkpoint creation
 */
typedef struct udif_checkpoint_config
{
    uint64_t membinterval;              /*!< Checkpoint every N records (0 = manual) */
    uint64_t transinterval;             /*!< Checkpoint every N records (0 = manual) */
    uint64_t reginterval;               /*!< Checkpoint every N records (0 = manual) */
    uint32_t blocksize;                 /*!< Records per block */
    bool autocheckpointenabled;         /*!< Enable automatic checkpointing */
} udif_checkpoint_config;

/*!
 * \struct udif_checkpoint_group
 * \brief Coordinated checkpoint across all three ledgers
 */
typedef struct udif_checkpoint_group
{
    uint8_t membcommit[UDIF_MCEL_BLOCK_HASH_SIZE];  /*!< Membership checkpoint commitment */
    uint8_t regcommit[UDIF_MCEL_BLOCK_HASH_SIZE];   /*!< Registry checkpoint commitment */
    uint8_t transcommit[UDIF_MCEL_BLOCK_HASH_SIZE]; /*!< Transaction checkpoint commitment */
    uint64_t height;                    /*!< Maximum records across all ledgers */
    uint64_t membershipseq;             /*!< Membership checkpoint sequence number */
    uint64_t registryseq;               /*!< Registry checkpoint sequence number */
    uint64_t timestamp;                 /*!< Creation timestamp */
    uint64_t transactionseq;            /*!< Transaction checkpoint sequence number */
} udif_checkpoint_group;

/*!
 * \struct udif_mcel_ledger
 * \brief Per-ledger state tracking
 */
typedef struct udif_mcel_ledger
{
    mcel_ledger_state mcelstate;        /*!< CEL ledger state */
    udif_ledger_type type;              /*!< Ledger type */
    uint8_t lastblockroot[MCEL_BLOCK_HASH_SIZE];    /*!< Block tracking */
    uint8_t lastblockcommit[MCEL_BLOCK_HASH_SIZE];  /*!< Block tracking */
    char namespaceid[64U];              /*!< Ledger namespace */
    uint64_t nextblockseq;              /*!< Next block sequence number */
    uint64_t nextcheckpointseq;         /*!< Next checkpoint sequence number */
    uint64_t firstrecordinblock;        /*!< First record seq in current block */
    uint64_t firstrecordincheckpoint;   /*!< First record seq in last checkpoint */
    uint64_t nextrecordseq;             /*!< Next record sequence number */
    uint8_t* reccommits;                /*!< Array of 32-byte commitments */
    uint64_t totalblocks;               /*!< Total blocks */
    uint64_t totalcheckpoints;          /*!< Total checkpoints */
    uint64_t totalrecords;              /*!< Total records */
    size_t commitscap;                  /*!< Capacity in number of commits */
    size_t commitscount;                /*!< Current number of commits */
    bool haveblockroot;                 /*!< Ledger has a block root */
} udif_mcel_ledger;

/*!
 * \struct udif_mcel_manager
 * \brief MCEL manager implementation
 */
typedef struct udif_mcel_manager
{
    udif_ledger_type actledger;         /*!< Active ledger */
    udif_checkpoint_config checkconfig; /*!< Checkpoint configuration */
    udif_storage_context storage;       /*!< Storage backend */
    udif_mcel_ledger* membership;       /*!< Membership ledger */
    udif_mcel_ledger* registry;         /*!< Registry ledger */
    udif_mcel_ledger* transaction;      /*!< Transaction ledger */
    uint8_t keyid[UDIF_MCEL_KEYID_SIZE];    /*!< Key identifier */
    uint8_t sigkey[MCEL_ASYMMETRIC_SIGNING_KEY_SIZE];   /*!< Signature signing key */
    uint8_t verkey[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE];    /*!< Signature verification key */
    bool initialized;                   /*!< Initialized flag */
    bool readonly;                      /*!< Readonly flag */
} udif_mcel_manager;

/*!
 * \brief Initialize MCEL manager
 *
 * Creates storage backend, initializes three MCEL ledgers,
 * generates signature keypair, and sets up checkpoint configuration.
 *
 * \param basepath: Base directory for all ledgers
 * \param config: Checkpoint configuration (NULL for defaults)
 *
 * \return Allocated manager or NULL on failure
 */
udif_mcel_manager* udif_mcel_initialize(const char* basepath, const udif_checkpoint_config* config);

/*!
 * \brief Open existing MCEL ledgers
 *
 * Loads existing ledgers and verifies checkpoint integrity.
 *
 * \param basepath: Base directory for all ledgers
 * \param readonly: Open in read-only mode
 * \param sigkey: signing key
 * \param verkey: verify key
 *
 * \return Allocated manager or NULL on failure
 */
udif_mcel_manager* udif_mcel_open(const char* basepath, bool readonly, const uint8_t* sigkey, const uint8_t* verkey);

/*!
 * \brief Dispose MCEL manager
 *
 * Flushes pending blocks, closes all ledgers, clears keys.
 *
 * \param mgr: MCEL manager context (can be NULL)
 */
void udif_mcel_dispose(udif_mcel_manager* mgr);

/*!
 * \brief Set active ledger
 *
 * Switches context to operate on a specific ledger.
 *
 * \param mgr: MCEL manager context
 * \param ledger: Ledger to make active
 *
 * \return true on success
 */
bool udif_mcel_set_active_ledger(udif_mcel_manager* mgr, udif_ledger_type ledger);

/*!
 * \brief Get active ledger type
 *
 * \param mgr: MCEL manager context
 *
 * \return Currently active ledger type
 */
udif_ledger_type udif_mcel_get_active_ledger(const udif_mcel_manager* mgr);

/*!
 * \brief Add record to active ledger
 *
 * Stores record data, computes commitment, batches into blocks.
 * Automatically seals blocks and creates checkpoints based on config.
 *
 * \param mgr: MCEL manager context
 * \param data: Record payload data
 * \param datalen: Record data length
 * \param encrypted: True if payload is encrypted
 * \param outseq: Record sequence number (can be NULL)
 *
 * \return true on success
 */
bool udif_mcel_add_record(udif_mcel_manager* mgr, const uint8_t* data, size_t datalen, bool encrypted, uint64_t* outseq);

/*!
 * \brief Read record from active ledger
 *
 * Reads actual record data from storage (not MCEL commitment).
 *
 * \param mgr: MCEL manager context
 * \param sequence: Record sequence number
 * \param data: Buffer for record data
 * \param datalen: Buffer size
 * \param outread: Actual bytes read
 *
 * \return true on success
 */
bool udif_mcel_read_record(udif_mcel_manager* mgr, uint64_t sequence, uint8_t* data, size_t datalen, size_t* outread);

/*!
 * \brief Get ledger record count
 *
 * Returns the total number of records in the active ledger.
 *
 * \param mgr: MCEL manager context
 * \param outcount: Record count
 *
 * \return true on success
 */
bool udif_mcel_get_ledger_size(const udif_mcel_manager* mgr, uint64_t* outcount);

/* === Block & Checkpoint Operations === */

/*!
 * \brief Flush pending records to block
 *
 * Seals current batch of records into a block.
 * Called automatically when batch is full.
 *
 * \param mgr: MCEL manager context
 *
 * \return true on success
 */
bool udif_mcel_flush_block(udif_mcel_manager* mgr);

/*!
 * \brief Create checkpoint for active ledger
 *
 * Seals a checkpoint from the latest block root.
 * Called automatically based on checkpoint interval config.
 *
 * \param mgr: MCEL manager context
 *
 * \return true on success
 */
bool udif_mcel_create_checkpoint(udif_mcel_manager* mgr);

/*!
 * \brief Create coordinated checkpoint across all ledgers
 *
 * Creates checkpoints for all three ledgers at their current heights.
 * Used to create UDIF anchor records.
 *
 * \param mgr: MCEL manager context
 * \param outgroup: Created checkpoint group (can be NULL)
 *
 * \return true on success
 */
bool udif_mcel_create_checkpoint_group(udif_mcel_manager* mgr, udif_checkpoint_group* outgroup);

/*!
 * \brief Get default checkpoint configuration
 *
 * Returns recommended checkpoint intervals for typical usage.
 *
 * \param config: Default configuration
 */
void udif_mcel_get_default_config(udif_checkpoint_config* config);

/*!
 * \brief Flush all ledgers
 *
 * Flushes pending blocks for all three ledgers to storage.
 *
 * \param mgr: MCEL manager context
 *
 * \return true on success
 */
bool udif_mcel_flush_all(udif_mcel_manager* mgr);

/*!
 * \brief Get keypair from manager
 *
 * Retrieves the signature keypair for external use.
 *
 * \param mgr: MCEL manager context
 * \param sigkey: Buffer for signing key
 * \param verkey: Buffer for verify key
 *
 * \return true on success
 */
bool udif_mcel_get_keypair(const udif_mcel_manager* mgr, uint8_t* sigkey, uint8_t* verkey);

#endif
