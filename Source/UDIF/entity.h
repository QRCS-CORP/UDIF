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

#ifndef UDIF_ENTITY_H
#define UDIF_ENTITY_H

#include "udif.h"
#include "certificate.h"
#include "certstore.h"
#include "capstore.h"
#include "treatystore.h"
#include "mcelmanager.h"
#include "registry.h"
#include "tunnel.h"
#include "qstp.h"

/**
 * \file entity.h
 * \brief Runtime state for a UDIF entity process (Root, BC, GC, or UA).
 *
 * A udif_entity_context is the single in-memory representation of
 * everything a running entity needs to serve or issue UDIF operations:
 * its own UDIF certificate and signing key, its QSTP certificate and
 * signing key (the two-layer certificate model from Phase 5), the trust
 * anchors it validates against, the udif_mcel_manager that holds the
 * three ledgers and storage backend, and the tunnel table enumerating
 * active QSTP sessions.
 *
 * Every handler receives a pointer to this structure; the dispatcher
 * uses the role field to decide which messages the entity is allowed to
 * accept. Role is expressed using the existing udif_roles enum defined
 * in udif.h, with the following mapping to the UDIF specification:
 *
 *   udif_role_root    - Root Authority
 *   udif_role_ugc     - Group Controller
 *   udif_role_ubc     - Branch Controller
 *   udif_role_client  - User Agent
 *
 * The prototype is single-threaded from the entity's perspective.
 * QSTP's receive thread delivers payloads via a callback that marshals
 * them through the dispatcher; send operations happen on the main
 * thread. Implementations that require concurrent access must add their
 * own synchronization.
 */

/*!
 * \def UDIF_ENTITY_MAX_TUNNELS
 * \brief Maximum number of simultaneous tunnels per entity in the prototype.
 */
#define UDIF_ENTITY_MAX_TUNNELS 64U

/*!
 * \def UDIF_ENTITY_MAX_ANCHOR_STATES
 * \brief Maximum number of tracked child anchor sequence states.
 */
#define UDIF_ENTITY_MAX_ANCHOR_STATES 64U

/*!
 * \def UDIF_ENTITY_MAX_REGISTRIES
 * \brief Maximum number of runtime UA registries tracked by one entity.
 */
#define UDIF_ENTITY_MAX_REGISTRIES 64U

/* Tunnel table */

/*!
 * \struct udif_tunnel_table
 * \brief Flat fixed-capacity table of active tunnels.
 *
 * The prototype uses a simple array for clarity; production deployments
 * would use a hash keyed by (peerserial, treatyid). Entries with
 * rolepair == udif_rolepair_none are free slots.
 */
UDIF_EXPORT_API typedef struct udif_tunnel_table
{
	udif_tunnel entries[UDIF_ENTITY_MAX_TUNNELS];	/*!< Fixed-capacity array of tunnel records */
	size_t count;									/*!< Number of occupied entries */
} udif_tunnel_table;


/*!
 * \struct udif_anchor_sequence_state
 * \brief Expected anchor sequence for a child entity.
 */
UDIF_EXPORT_API typedef struct udif_anchor_sequence_state
{
	uint8_t childser[UDIF_SERIAL_NUMBER_SIZE];	/*!< Child certificate serial */
	uint64_t nextseq;							/*!< Next expected 0-indexed anchor sequence */
	bool used;									/*!< Entry is allocated */
} udif_anchor_sequence_state;


/*!
 * \struct udif_entity_registry_entry
 * \brief Runtime registry slot keyed by owner certificate serial.
 */
UDIF_EXPORT_API typedef struct udif_entity_registry_entry
{
	uint8_t ownerser[UDIF_SERIAL_NUMBER_SIZE];	/*!< Owner certificate serial */
	udif_registry_state registry;				/*!< Runtime registry state */
	bool used;									/*!< Entry is allocated */
} udif_entity_registry_entry;

/* Entity context */

/*!
 * \struct udif_entity_context
 * \brief Aggregate runtime state for a single UDIF entity process.
 *
 * Owned by the entity's main loop. Handlers receive a non-owning pointer
 * and may read or mutate any field subject to the usual thread-safety
 * rules of the host application.
 *
 * QSTP certificates (qstprootcert and qstpserverkey) are only populated
 * for entities that accept incoming QSTP connections (Root, BC, GC). A
 * UA that only initiates outbound tunnels needs only the root certificate
 * against which to validate the server.
 */
UDIF_EXPORT_API typedef struct udif_entity_context
{
	udif_certificate selfcert;					/*!< This entity's signed UDIF certificate */
	udif_certificate parentcert;				/*!< Parent UDIF certificate; zeroed for Root */
	udif_certificate rootcert;					/*!< Domain UDIF trust anchor */
	udif_certstore certstore;					/*!< Runtime certificate status store */
	udif_capstore capstore;						/*!< Runtime capability-token store */
	udif_treatystore treatystore;				/*!< Runtime cross-domain treaty store */
	udif_signature_keypair selfkeypair;			/*!< This entity's UDIF long-term signing keypair */
	uint8_t capabilitykey[UDIF_CRYPTO_KEY_SIZE]; /*!< Local capability KMAC verification key */
	bool hascapabilitykey;						/*!< True when capabilitykey is configured */
	qstp_root_certificate qstprootcert;			/*!< QSTP trust anchor for the transport layer */
	qstp_server_signature_key qstpserverkey;	/*!< QSTP server signing key (populated for listeners) */
	udif_mcel_manager* mcelmgr;					/*!< MCEL manager (holds membership, registry, transaction ledgers and storage); NULL for UA */
	udif_tunnel_table tunnels;					/*!< Active tunnels */
	udif_anchor_sequence_state anchorseq[UDIF_ENTITY_MAX_ANCHOR_STATES]; /*!< Expected child anchor sequences */
	udif_entity_registry_entry registries[UDIF_ENTITY_MAX_REGISTRIES];	/*!< Runtime per-UA registries */
	uint64_t nextanchorsecs;					/*!< UTC seconds at which next anchor is due; 0 for UA */
	udif_roles role;							/*!< Fixed at init; governs handler admissibility */
	bool haslistener;							/*!< True if this entity accepts inbound QSTP connections */
	bool initialized;							/*!< Initialization flag */
} udif_entity_context;

/*!
 * \struct udif_entity_config
 * \brief Initialization parameters for a UDIF entity process.
 *
 * All certificate, key, and path buffers referenced here are copied into
 * the resulting context; the caller retains ownership of the inputs.
 */
UDIF_EXPORT_API typedef struct udif_entity_config
{
	const udif_certificate* selfcert;			/*!< This entity's signed certificate */
	const udif_certificate* parentcert;			/*!< Parent certificate; NULL for Root */
	const udif_certificate* rootcert;			/*!< Domain trust anchor */
	const udif_signature_keypair* selfkeypair;	/*!< This entity's signing keypair */
	const uint8_t* capabilitykey;				/*!< Optional capability KMAC verification key */
	const qstp_root_certificate* qstprootcert;	/*!< QSTP trust anchor */
	const qstp_server_signature_key* qstpserverkey;	/*!< QSTP server key (required if haslistener) */
	const char* mcelbasepath;					/*!< Base directory for MCEL ledgers; NULL for UA */
	const udif_checkpoint_config* checkconfig;	/*!< Checkpoint configuration (NULL for defaults) */
	udif_roles role;							/*!< Entity role */
	bool haslistener;							/*!< True if this entity accepts inbound QSTP connections */
} udif_entity_config;

/* Anchor sequence state */

/*!
 * \brief Resolve the expected anchor sequence for a child.
 *
 * Unknown children are treated as genesis children and therefore expect
 * sequence 0.
 *
 * \param ctx: The entity context.
 * \param childser: [const] The child certificate serial.
 * \param expseq: The output expected sequence.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_entity_anchor_expected_sequence(const udif_entity_context* ctx, const uint8_t* childser, uint64_t* expseq);

/*!
 * \brief Commit an accepted anchor sequence for a child.
 *
 * Stores the next expected sequence after a verified anchor has been accepted.
 *
 * \param ctx: The entity context.
 * \param childser: [const] The child certificate serial.
 * \param acceptedseq: The accepted sequence value.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_entity_anchor_commit_sequence(udif_entity_context* ctx, const uint8_t* childser, uint64_t acceptedseq);

/* Lifecycle */

/*!
 * \brief Initialize an entity context from configuration.
 *
 * Initializes the MCEL manager (for roles that keep ledgers), copies
 * certificates and keys, clears the tunnel table, and sets
 * nextanchorsecs according to role and profile. Returns an error if
 * any resource cannot be opened.
 *
 * \param ctx: The output context
 * \param cfg: [const] The configuration
 *
 * \return Returns udif_error_none on success, udif_error_invalid_input on bad
 *         arguments, udif_error_internal on MCEL or storage failure.
 */
UDIF_EXPORT_API udif_errors udif_entity_init(udif_entity_context* ctx, const udif_entity_config* cfg);

/*!
 * \brief Tear down an entity context.
 *
 * Closes all tunnels, disposes the MCEL manager, and zeroizes private
 * key material. Idempotent. Safe to call on a zero-initialized context.
 *
 * \param ctx: The context (may be NULL)
 */
UDIF_EXPORT_API void udif_entity_dispose(udif_entity_context* ctx);

/* Runtime registry state */

/*!
 * \brief Find a runtime registry by owner serial.
 *
 * \param ctx: The entity context.
 * \param ownerser: [const] The owner certificate serial.
 *
 * \return Returns the registry on success, or NULL if no registry exists.
 */
UDIF_EXPORT_API udif_registry_state* udif_entity_registry_find(udif_entity_context* ctx, const uint8_t* ownerser);

/*!
 * \brief Find a runtime registry by owner serial.
 *
 * \param ctx: [const] The entity context.
 * \param ownerser: [const] The owner certificate serial.
 *
 * \return Returns the registry on success, or NULL if no registry exists.
 */
UDIF_EXPORT_API const udif_registry_state* udif_entity_registry_find_const(const udif_entity_context* ctx, const uint8_t* ownerser);

/*!
 * \brief Resolve or create a runtime registry by owner serial.
 *
 * \param ctx: The entity context.
 * \param ownerser: [const] The owner certificate serial.
 * \param capacity: Initial capacity when a new registry is created.
 *
 * \return Returns the registry on success, or NULL on failure.
 */
UDIF_EXPORT_API udif_registry_state* udif_entity_registry_get_or_create(udif_entity_context* ctx, const uint8_t* ownerser, size_t capacity);

/*!
 * \brief Clear and dispose all runtime registries.
 *
 * \param ctx: The entity context.
 */
UDIF_EXPORT_API void udif_entity_registry_clear_all(udif_entity_context* ctx);

/* Tunnel table operations */

/*!
 * \brief Insert a tunnel into the entity's tunnel table.
 *
 * The tunnel's storage is copied into the table entry.
 *
 * \param ctx: The entity context
 * \param tun: [const] The fully initialized tunnel
 *
 * \return Returns a pointer to the stored tunnel entry on success, NULL if the table is full.
 */
UDIF_EXPORT_API udif_tunnel* udif_entity_add_tunnel(udif_entity_context* ctx, const udif_tunnel* tun);

/*!
 * \brief Find a tunnel by peer serial and optional treaty id.
 *
 * When treatyid is NULL, matches the first non-treaty tunnel with the
 * given peer serial. When treatyid is non-NULL, matches only treaty
 * tunnels with the given treaty id.
 *
 * \param ctx: The entity context
 * \param peerserial: [const] The 16-byte peer certificate serial
 * \param treatyid: [const] The 16-byte treaty id (may be NULL)
 *
 * \return Returns a pointer to the matching tunnel, or NULL if none.
 */
UDIF_EXPORT_API udif_tunnel* udif_entity_find_tunnel(udif_entity_context* ctx, const uint8_t* peerserial, const uint8_t* treatyid);

/*!
 * \brief Look up the tunnel associated with a QSTP connection.
 *
 * Used by QSTP receive callbacks to resolve the inbound connection back
 * to the UDIF tunnel record.
 *
 * \param ctx: The entity context
 * \param qstpcns: The QSTP connection
 *
 * \return Returns a pointer to the matching tunnel, or NULL if none.
 */
UDIF_EXPORT_API udif_tunnel* udif_entity_find_tunnel_by_qstp(udif_entity_context* ctx, const qstp_connection_state* qstpcns);

/*!
 * \brief Remove a tunnel from the table, closing it if still open.
 *
 * \param ctx: The entity context
 * \param tun: The tunnel entry (previously returned from add/find)
 * \param notify: If true, instructs QSTP to notify the remote peer of the close
 */
UDIF_EXPORT_API void udif_entity_remove_tunnel(udif_entity_context* ctx, udif_tunnel* tun, bool notify);

/*!
 * \brief Drive timers for every tunnel in the table.
 *
 * Calls udif_tunnel_tick on each occupied entry; removes any that fail
 * or that have exceeded idle teardown. Intended to be invoked once per
 * second from the main event loop.
 *
 * \param ctx: The entity context
 * \param nowsecs: The current UTC seconds
 */
UDIF_EXPORT_API void udif_entity_tick_tunnels(udif_entity_context* ctx, uint64_t nowsecs);

/* Tunnel-table convenience wrappers
 * The following functions accept a bare udif_tunnel_table* instead of
 * udif_entity_context*.  They are used by the role modules (bc.c, gc.c,
 * root.c, ua.c) which maintain tunnel state directly inside
 * udif_server_application_state::tunnels.  Each wrapper builds a
 * minimal temporary entity_context containing only the tunnel table,
 * then delegates to the corresponding full-context function.
 */

/*!
 * \brief Add a tunnel — tunnel-table variant.
 * \see udif_entity_add_tunnel
 */
UDIF_EXPORT_API udif_tunnel* udif_tunneltable_add(udif_tunnel_table* table, const udif_tunnel* tun);

/*!
 * \brief Find a tunnel by peer serial — tunnel-table variant.
 * \see udif_entity_find_tunnel
 */
UDIF_EXPORT_API udif_tunnel* udif_tunneltable_find(udif_tunnel_table* table, const uint8_t* peerserial, const uint8_t* treatyid);

/*!
 * \brief Find a tunnel by QSTP connection — tunnel-table variant.
 * \see udif_entity_find_tunnel_by_qstp
 */
UDIF_EXPORT_API udif_tunnel* udif_tunneltable_find_by_qstp(udif_tunnel_table* table, const qstp_connection_state* qstpcns);

/*!
 * \brief Remove a tunnel — tunnel-table variant.
 * \see udif_entity_remove_tunnel
 */
UDIF_EXPORT_API void udif_tunneltable_remove(udif_tunnel_table* table, udif_tunnel* tun, bool notify);

/*!
 * \brief Tick all tunnels — tunnel-table variant.
 * \see udif_entity_tick_tunnels
 */
UDIF_EXPORT_API void udif_tunneltable_tick(udif_tunnel_table* table, uint64_t nowsecs);

#endif
