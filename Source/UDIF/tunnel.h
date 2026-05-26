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

#ifndef UDIF_TUNNEL_H
#define UDIF_TUNNEL_H

#include "udif.h"
#include "message.h"
#include "qstp.h"

/**
 * \file tunnel.h
 * \brief UDIF tunnel abstraction over a QSTP secure channel.
 *
 * A udif_tunnel wraps a single QSTP connection and adds UDIF-specific
 * lifecycle policy: per-role-pair behavior, application-level keepalives
 * (required because QSTP no longer provides them), idle teardown, and
 * for BC<->BC trunks, scheduled QSTP rekey triggers that invoke
 * qstp_send_symmetric_ratchet_request.
 *
 * Data flow. QSTP is callback-driven, so tunnel I/O is not a symmetric
 * send/recv pair. On the send path, udif_tunnel_send encodes a udif_message,
 * prepends a canonical UDIF tunnel record header, calls qstp_encrypt_packet
 * to seal the resulting inner record, serializes the packet, and writes it
 * to the underlying socket. On the receive path, QSTP's receive thread
 * decrypts the next packet and invokes a registered callback; that callback
 * (installed by the entity's main loop) calls udif_tunnel_on_receive, which
 * validates the UDIF inner header, decodes the payload as a udif_message,
 * and hands it to the dispatcher. There is no blocking udif_tunnel_recv.
 *
 * Formal transport profile. UDIF delegates outer handshake authentication,
 * packet confidentiality, packet integrity, and channel rekeying to QSTP.
 * UDIF does not pass a separate associated-data pointer into QSTP. Instead,
 * the UDIF header is an inner, encrypted, and authenticated record prefix:
 *
 *     QSTP-Seal(UDIF-Header || UDIF-Message)
 *
 * The QSTP authentication tag therefore covers the UDIF header because the
 * header is part of the sealed plaintext. UDIF then validates suite, epoch,
 * sequence, time window, and record class after successful QSTP authentication
 * and before dispatch. This is the normative implementation profile for this
 * codebase. The written UDIF specification and formal analysis should describe
 * this QSTP-wrapped inner-header model rather than an independent UDIF AEAD
 * header passed as external AAD.
 */

/* UDIF-over-QSTP transport profile */

/*!
 * \def UDIF_TRANSPORT_PROFILE_QSTP_INNER_HEADER
 * \brief The normative UDIF transport profile implemented by this codebase.
 *
 * A value of one indicates that UDIF records are sealed by QSTP as
 * inner records of the form UDIF-Header || UDIF-Message.
 */
#define UDIF_TRANSPORT_PROFILE_QSTP_INNER_HEADER 1U

/*!
 * \def UDIF_TRANSPORT_HEADER_EXTERNAL_AAD
 * \brief Indicates whether UDIF passes the record header as external AEAD AAD.
 *
 * This implementation does not use a separate external-AAD parameter. The
 * UDIF header is protected as part of the QSTP-sealed plaintext.
 */
#define UDIF_TRANSPORT_HEADER_EXTERNAL_AAD 0U

/*!
 * \def UDIF_TRANSPORT_RATCHET_DELEGATED_TO_QSTP
 * \brief Indicates whether branch-trunk rekeying is delegated to QSTP.
 */
#define UDIF_TRANSPORT_RATCHET_DELEGATED_TO_QSTP 1U

/* UDIF record header */

/*!
 * \def UDIF_TUNNEL_RECORD_HEADER_SIZE
 * \brief Canonical UDIF transport record header size in bytes.
 */
#define UDIF_TUNNEL_RECORD_HEADER_SIZE 26U

/*!
 * \def UDIF_TUNNEL_TIME_WINDOW_SECONDS
 * \brief Maximum accepted sender clock skew in seconds.
 */
#define UDIF_TUNNEL_TIME_WINDOW_SECONDS 60U

/*!
 * \def UDIF_TUNNEL_FLAG_DATA
 * \brief Tunnel record carries application data.
 */
#define UDIF_TUNNEL_FLAG_DATA 0x01U

/*!
 * \def UDIF_TUNNEL_FLAG_KEEPALIVE
 * \brief Tunnel record carries an application keepalive.
 */
#define UDIF_TUNNEL_FLAG_KEEPALIVE 0x02U

/*!
 * \def UDIF_TUNNEL_FLAG_CLOSE
 * \brief Tunnel record carries an orderly close notification.
 */
#define UDIF_TUNNEL_FLAG_CLOSE 0x04U

/*!
 * \def UDIF_TUNNEL_FLAG_CONTROL
 * \brief Tunnel record carries control-plane data.
 */
#define UDIF_TUNNEL_FLAG_CONTROL 0x08U

/*!
 * \struct udif_tunnel_record_header
 * \brief Canonical UDIF transport record header.
 */
UDIF_EXPORT_API typedef struct udif_tunnel_record_header
{
	uint64_t sequence;		/*!< Strictly monotonic receive sequence for the current epoch */
	uint64_t utctime;		/*!< Sender UTC timestamp in seconds */
	uint64_t epoch;			/*!< Tunnel epoch counter */
	uint8_t flags;			/*!< UDIF_TUNNEL_FLAG_* bitmask */
	uint8_t suiteid;		/*!< Compile-time suite identifier */
} udif_tunnel_record_header;

/* Cadence macros */

/*!
 * \def UDIF_KEEPALIVE_INTERVAL_A_SECONDS
 * \brief Keepalive send interval (seconds) for Profile-A (Authority/Root).
 */
#define UDIF_KEEPALIVE_INTERVAL_A_SECONDS 300U

/*!
 * \def UDIF_KEEPALIVE_INTERVAL_E_SECONDS
 * \brief Keepalive send interval (seconds) for Profile-E (Enterprise).
 */
#define UDIF_KEEPALIVE_INTERVAL_E_SECONDS 120U

/*!
 * \def UDIF_KEEPALIVE_INTERVAL_U_SECONDS
 * \brief Keepalive send interval (seconds) for Profile-U (User/Edge).
 */
#define UDIF_KEEPALIVE_INTERVAL_U_SECONDS 120U

/*!
 * \def UDIF_KEEPALIVE_INTERVAL_SECONDS
 * \brief Default keepalive interval (seconds). Override at compile time to select a profile.
 */
#if !defined(UDIF_KEEPALIVE_INTERVAL_SECONDS)
#	define UDIF_KEEPALIVE_INTERVAL_SECONDS UDIF_KEEPALIVE_INTERVAL_E_SECONDS
#endif

/*!
 * \def UDIF_IDLE_TEARDOWN_MULTIPLIER
 * \brief Multiplier applied to the keepalive interval to derive the idle teardown threshold.
 */
#define UDIF_IDLE_TEARDOWN_MULTIPLIER 2U

/*!
 * \def UDIF_IDLE_TEARDOWN_SECONDS
 * \brief Computed idle teardown threshold in seconds.
 */
#define UDIF_IDLE_TEARDOWN_SECONDS (UDIF_KEEPALIVE_INTERVAL_SECONDS * UDIF_IDLE_TEARDOWN_MULTIPLIER)

/*!
 * \def UDIF_RATCHET_INTERVAL_SECONDS
 * \brief BC<->BC trunk QSTP rekey interval in seconds.
 */
#define UDIF_RATCHET_INTERVAL_SECONDS 3600U

/*!
 * \def UDIF_RATCHET_JITTER_SECONDS
 * \brief Ratchet jitter bound in seconds (+/- 5 minutes per spec).
 */
#define UDIF_RATCHET_JITTER_SECONDS 300U

/* Role-pair and side enums */

/*!
 * \enum udif_rolepair
 * \brief Identifies the trust-tree relationship a tunnel spans.
 *
 * Role-pair governs lifecycle policy: which tunnels use QSTP rekeying,
 * which are ephemeral, and which carry a treaty identifier.
 */
typedef enum udif_rolepair
{
	udif_rolepair_none = 0U,					/*!< Uninitialized */
	udif_rolepair_ua_gc = 1U,					/*!< UA <-> GC; ephemeral; UA is client; no periodic ratchet */
	udif_rolepair_gc_bc = 2U,					/*!< GC <-> BC; persistent; GC is client; no periodic ratchet */
	udif_rolepair_bc_bc = 3U,					/*!< BC <-> BC trunk; persistent; hourly QSTP rekey */
	udif_rolepair_bc_root = 4U,					/*!< BC <-> Root; persistent; BC is client; no periodic ratchet */
	udif_rolepair_treaty = 5U					/*!< Treaty tunnel; separate QSTP session; treaty-id tagged */
} udif_rolepair;

/*!
 * \enum udif_tunnel_side
 * \brief Which end of a tunnel this entity occupies.
 *
 * The client side is responsible for triggering QSTP rekeying on ratcheting
 * role pairs. Both sides maintain independent keepalive timers.
 */
typedef enum udif_tunnel_side
{
	udif_tunnel_side_client = 0U,				/*!< Client end (initiator) */
	udif_tunnel_side_server = 1U				/*!< Server end (listener) */
} udif_tunnel_side;

/* Tunnel state */

/*!
 * \struct udif_tunnel
 * \brief Per-connection UDIF state layered atop a QSTP channel.
 *
 * The qstpcns field is held by reference; its lifetime is managed through
 * the QSTP API. The tunnel record pairs it with UDIF-specific policy state
 * for the duration of the session.
 */
UDIF_EXPORT_API typedef struct udif_tunnel
{
	uint8_t peerserial[UDIF_SERIAL_NUMBER_SIZE];/*!< Remote entity certificate serial */
	uint8_t treatyid[UDIF_SERIAL_NUMBER_SIZE];	/*!< Treaty identifier; all-zero if rolepair != treaty */
	qstp_connection_state* qstpcns;				/*!< Underlying QSTP channel; not owned */
	uint64_t txsequence;						/*!< Next transmit sequence for the current UDIF epoch */
	uint64_t rxsequence;						/*!< Next required receive sequence for the current UDIF epoch */
	uint64_t epoch;								/*!< Current UDIF tunnel epoch */
	uint64_t lastrxsecs;						/*!< UTC seconds of last successful receive */
	uint64_t lasttxsecs;						/*!< UTC seconds of last successful send */
	uint64_t keepalivedeadline;					/*!< UTC seconds at which next keepalive should be sent */
	uint64_t idledeadline;						/*!< UTC seconds past which session is torn down */
	uint64_t ratchetdeadline;					/*!< UTC seconds at which next ratchet is scheduled; 0 if non-ratcheting */
	udif_rolepair rolepair;						/*!< Role relationship */
	udif_tunnel_side side;						/*!< Client or server end */
	bool closing;								/*!< Set true once a close has been initiated */
} udif_tunnel;

/* Record header helpers */

/*!
 * \brief Serialize a UDIF tunnel record header.
 *
 * \param output: The output buffer.
 * \param outlen: The length of the output buffer.
 * \param header: [const] The header to serialize.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_record_header_serialize(uint8_t* output, size_t outlen, const udif_tunnel_record_header* header);

/*!
 * \brief Deserialize a UDIF tunnel record header.
 *
 * \param header: The output header.
 * \param input: [const] The encoded header.
 * \param inlen: The length of the encoded header.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_record_header_deserialize(udif_tunnel_record_header* header, const uint8_t* input, size_t inlen);

/*!
 * \brief Validate a received UDIF tunnel record header against tunnel state.
 *
 * \param tun: [const] The tunnel state.
 * \param header: [const] The decoded header.
 * \param nowsecs: Current UTC seconds.
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_record_header_validate(const udif_tunnel* tun, const udif_tunnel_record_header* header, uint64_t nowsecs);

/*!
 * \brief Return the UDIF tunnel record flag for a message type.
 *
 * \param msgtype: The UDIF message type.
 *
 * \return Returns a UDIF_TUNNEL_FLAG_* value.
 */
UDIF_EXPORT_API uint8_t udif_tunnel_record_flag(udif_message_type msgtype);

/* Tunnel lifecycle */

/*!
 * \brief Initialize a freshly-opened tunnel record.
 *
 * Call after the QSTP handshake has completed and a qstp_connection_state
 * is available. Populates timers from nowsecs and role-pair policy. Does
 * not take ownership of qstpcns.
 *
 * For non-ratcheting role pairs, ratchetdeadline is set to 0. For treaty
 * tunnels, treatyid is copied in; for other role pairs, treatyid may be
 * NULL and is zeroed.
 *
 * \param tun: The tunnel record to initialize
 * \param qstpcns: The established QSTP connection
 * \param peerserial: [const] The 16-byte serial of the remote certificate
 * \param rolepair: The role-pair classification
 * \param side: Which end this entity occupies
 * \param treatyid: [const] The 16-byte treaty id (required when rolepair == udif_rolepair_treaty; may be NULL otherwise)
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns udif_error_none on success, udif_error_invalid_input on bad arguments.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_init(udif_tunnel* tun, qstp_connection_state* qstpcns, const uint8_t* peerserial,
	udif_rolepair rolepair, udif_tunnel_side side, const uint8_t* treatyid, uint64_t nowsecs);

/*!
 * \brief Close the tunnel and clear its state.
 *
 * Invokes qstp_connection_close on qstpcns if still open, marks the tunnel
 * closing, and zeroes timer fields. Idempotent.
 *
 * \param tun: The tunnel (may be NULL)
 * \param notify: If true, instructs QSTP to notify the remote peer of the close
 */
UDIF_EXPORT_API void udif_tunnel_close(udif_tunnel* tun, bool notify);

/* Send and receive */

/*!
 * \brief Encode and send a UDIF message over the tunnel.
 *
 * Serializes msg to canonical form, hands it to qstp_encrypt_packet for
 * sealing, serializes the resulting qstp_network_packet via
 * qstp_packet_to_stream, and writes the bytes to the underlying socket
 * via qsc_socket_send. On success updates lasttxsecs and pushes
 * keepalivedeadline forward to lasttxsecs + UDIF_KEEPALIVE_INTERVAL_SECONDS.
 *
 * \param tun: The open tunnel
 * \param msg: [const] The message to send
 * \param nowsecs: The current UTC seconds (for timer updates)
 *
 * \return Returns udif_error_none on success, udif_error_invalid_state if the
 *         tunnel is closing, udif_error_encode_failure on UDIF serialization
 *         failure, udif_error_internal on QSTP or socket failure.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_send(udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Process an inbound decrypted payload delivered by QSTP.
 *
 * Intended to be invoked from inside the receive_callback passed to
 * qstp_client_connect_ipv4 or qstp_server_start_ipv4. The bytes supplied
 * are the plaintext payload produced by qstp_decrypt_packet; QSTP has
 * already validated the outer QSTP packet and authentication tag. This
 * function validates the inner UDIF record header before decoding the
 * udif_message.
 *
 * Decodes the inner UDIF message and writes it to outmsg (caller-owned;
 * caller must dispose with udif_message_dispose). On success updates
 * lastrxsecs and pushes idledeadline forward to lastrxsecs +
 * UDIF_IDLE_TEARDOWN_SECONDS. Keepalives are surfaced to the caller
 * rather than swallowed so the dispatcher can update telemetry.
 *
 * \param tun: The tunnel the payload arrived on
 * \param input: [const] The decrypted payload bytes
 * \param inplen: The length of the decrypted payload in bytes
 * \param outmsg: The output message (caller disposes on success)
 * \param nowsecs: The current UTC seconds (for timer updates)
 *
 * \return Returns udif_error_none on success, udif_error_decode_failure on a
 *         malformed frame, udif_error_invalid_state if the tunnel is closing.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_on_receive(udif_tunnel* tun, const uint8_t* input, size_t inplen, udif_message* outmsg, uint64_t nowsecs);

/* Timer tick: keepalive, idle teardown, QSTP rekey */

/*!
 * \brief Drive per-tunnel timers forward.
 *
 * Should be called periodically (once per second is adequate) from the
 * entity's event loop, for every tunnel in the tunnel table. Performs,
 * in order:
 *
 *  1. If nowsecs >= keepalivedeadline, sends udif_msg_keepalive and
 *     advances keepalivedeadline by UDIF_KEEPALIVE_INTERVAL_SECONDS.
 *  2. If nowsecs >= idledeadline, closes the tunnel (peer silent too long).
 *  3. If rolepair == udif_rolepair_bc_bc and side == udif_tunnel_side_client
 *     and nowsecs >= ratchetdeadline, invokes
 *     qstp_send_symmetric_ratchet_request on qstpcns and advances
 *     ratchetdeadline by UDIF_RATCHET_INTERVAL_SECONDS with jitter in
 *     [-UDIF_RATCHET_JITTER_SECONDS, +UDIF_RATCHET_JITTER_SECONDS].
 *
 * Idempotent within a single second. If a timer action fails fatally, the
 * tunnel's closing flag is set and the caller should remove the tunnel
 * from the table.
 *
 * \param tun: The tunnel
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns udif_error_none on success, or the error code from a failed timer action.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_tick(udif_tunnel* tun, uint64_t nowsecs);

/*!
 * \brief Force an immediate keepalive send, independent of the timer.
 *
 * Useful for diagnostics and for probing a tunnel before issuing a
 * latency-sensitive request.
 *
 * \param tun: The open tunnel
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns udif_error_none on success.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_send_keepalive(udif_tunnel* tun, uint64_t nowsecs);

/*!
 * \brief Force an immediate ratchet trigger on a BC<->BC trunk.
 *
 * Valid only when rolepair == udif_rolepair_bc_bc and side ==
 * udif_tunnel_side_client. Advances ratchetdeadline on success.
 *
 * \param tun: The open trunk tunnel
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns udif_error_none on success, udif_error_invalid_request if the
 *         role-pair or side is wrong for a manual ratchet trigger.
 */
UDIF_EXPORT_API udif_errors udif_tunnel_trigger_ratchet(udif_tunnel* tun, uint64_t nowsecs);

/* Introspection */

/*!
 * \brief Check whether the tunnel is open and operational.
 *
 * A tunnel is operational when qstpcns is non-NULL, closing is false,
 * and nowsecs < idledeadline.
 *
 * \param tun: [const] The tunnel (may be NULL; returns false)
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns true if operational, false otherwise.
 */
UDIF_EXPORT_API bool udif_tunnel_is_open(const udif_tunnel* tun, uint64_t nowsecs);

#endif
