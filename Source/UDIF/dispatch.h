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

#ifndef UDIF_DISPATCH_H
#define UDIF_DISPATCH_H

#include "udif.h"
#include "entity.h"
#include "message.h"
#include "tunnel.h"

/**
 * \file dispatch.h
 * \brief UDIF application-layer dispatcher and per-message handler signatures.
 *
 * The dispatcher is the single ingress point for decoded UDIF messages.
 * It enforces role-based admissibility against the running entity's
 * udif_roles value (a UA will not honor udif_msg_cert_enroll_req, a GC
 * will not honor udif_msg_anchor_push, and so on), then invokes the
 * handler registered for the message type. Handlers are pure functions
 * of (entity state, tunnel, decoded message, current time) and emit
 * zero, one, or more response messages by calling udif_tunnel_send
 * directly on the supplied tunnel.
 *
 * Correlation is carried inside each message's canonical payload (query
 * id, certificate serial, treaty id, object serial) rather than at the
 * framing layer. The dispatcher does not track outstanding requests.
 *
 * Handlers return a tri-state outcome via udif_errors:
 *   - udif_error_none on success
 *   - a fatal code (udif_error_auth_failure, udif_error_invalid_sequence,
 *     udif_error_mac_invalid) causes the dispatcher's caller to close
 *     the tunnel
 *   - a non-fatal code (udif_error_not_authorized, udif_error_object_not_found,
 *     udif_error_invalid_request) causes the dispatcher to emit a
 *     udif_msg_error_report on the tunnel and leave it open
 */

/*!
 * \typedef udif_handler_fn
 * \brief Function-pointer type for a UDIF message handler.
 *
 * \param ctx: The entity context
 * \param tun: The tunnel on which the message arrived. Handlers send replies
 *             by calling udif_tunnel_send on this tunnel or another tunnel
 *             resolved via udif_entity_find_tunnel.
 * \param msg: [const] The decoded inbound message. Payload is owned by the
 *             dispatcher and must not be freed by the handler.
 * \param nowsecs: The current UTC seconds, passed to udif_tunnel_send for timer
 *                 updates and embedded in outbound payload timestamps.
 *
 * \return Returns udif_error_none on success, a fatal error code to signal
 *         the caller to close the tunnel, or a non-fatal error code which
 *         the dispatcher will surface as udif_msg_error_report.
 */
typedef udif_errors(*udif_handler_fn)(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Dispatch a decoded UDIF message to the appropriate handler.
 *
 * Steps performed:
 *   1. If msg->msgtype is udif_msg_keepalive, returns immediately
 *      (timer updates are already handled by udif_tunnel_on_receive).
 *   2. Looks up (ctx->role, msg->msgtype) in the role-allowance table.
 *      Returns udif_error_not_authorized if the combination is rejected.
 *   3. For peer-authenticated control messages, validates the tunnel peer
 *      certificate with recursive chain verification and active status checks
 *      before invoking the message handler.
 *   4. Invokes the handler registered for msg->msgtype.
 *   5. If the handler returns a non-fatal error, emits a udif_msg_error_report
 *      on the tunnel. If it returns a fatal error, returns the error to the
 *      caller so the main loop can close the tunnel.
 *
 * \param ctx: The entity context
 * \param tun: The tunnel the message arrived on
 * \param msg: [const] The decoded message
 * \param nowsecs: The current UTC seconds
 *
 * \return Returns udif_error_none on success, or a fatal transport-class error.
 */
UDIF_EXPORT_API udif_errors udif_dispatch(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Check whether a role is permitted to receive a message type.
 *
 * Exposed for testing and for pre-send checks in operator CLIs.
 *
 * \param role: The entity role
 * \param msgtype: The message type code
 *
 * \return Returns true if permitted, false if rejected by the role-allowance table.
 */
UDIF_EXPORT_API bool udif_dispatch_is_permitted(udif_roles role, udif_message_type msgtype);

/*!
 * \brief Handle an inbound CSR from a subordinate.
 *
 * Permitted for: udif_role_root, udif_role_ubc (BC), udif_role_ugc (GC).
 *
 * Validates the CSR signature and requested capability scope, signs the
 * certificate via udif_certificate_generate, commits the issuance event
 * to the membership log, and sends udif_msg_cert_enroll_resp back on tun.
 */
UDIF_EXPORT_API udif_errors udif_handle_cert_enroll_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle an inbound signed certificate from a parent.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Verifies the parent's signature via udif_certificate_verify, installs the
 * certificate locally as selfcert, and commits the receipt event to the
 * local membership log (if the role keeps one).
 */
UDIF_EXPORT_API udif_errors udif_handle_cert_enroll_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a revocation notice from a parent.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Installs the revocation locally; on BC and GC, cascades to subordinates by
 * closing their tunnels and rejecting future traffic from them.
 */
UDIF_EXPORT_API udif_errors udif_handle_cert_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a suspension notice from a parent.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Marks the subject suspended locally; blocks outbound requests until a
 * resume notice is received.
 */
UDIF_EXPORT_API udif_errors udif_handle_cert_suspend(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a resumption notice from a parent.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Clears a prior suspension, logs the event, and permits traffic to resume.
 */
UDIF_EXPORT_API udif_errors udif_handle_cert_resume(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a parent-issued capability grant.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Verifies the capability digest and KMAC tag with the configured capability
 * verification key, installs the token in the runtime capability store, and
 * logs the grant event.
 */
UDIF_EXPORT_API udif_errors udif_handle_cap_grant(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a capability revocation notice.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC), udif_role_client (UA).
 *
 * Marks the referenced capability digest as revoked in the runtime capability
 * store and logs the revocation event.
 */
UDIF_EXPORT_API udif_errors udif_handle_cap_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a predicate query from a subordinate or peer.
 *
 * Permitted for: udif_role_ugc (GC), udif_role_ubc (BC).
 *
 * Verifies the querying entity's signature and capability via
 * udif_query_validate_authorization, evaluates the predicate against the
 * local ledger and registry state, emits udif_msg_query_resp with the
 * appropriate verdict and optional Merkle proof, and logs the exchange
 * to the membership log.
 *
 * For cross-domain queries, the handler validates the treaty scope and
 * forwards via udif_msg_treaty_query_fwd on the appropriate treaty tunnel
 * resolved through udif_entity_find_tunnel.
 */
UDIF_EXPORT_API udif_errors udif_handle_query_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a predicate query response from a controller.
 *
 * Permitted for: udif_role_client (UA), udif_role_ugc (GC) when forwarding on
 * behalf of a UA, udif_role_ubc (BC) for cross-domain.
 *
 * Verifies the responder's signature via udif_query_verify_response, matches
 * the response to a pending request via the queryid embedded in the payload,
 * and surfaces the verdict to the local application layer or operator CLI.
 */
UDIF_EXPORT_API udif_errors udif_handle_query_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle an object creation request from a UA.
 *
 * Permitted for: udif_role_ugc (GC).
 *
 * Validates the UA's signature via udif_object_verify and its capability,
 * commits the object to storage, updates the UA's registry root via
 * udif_registry_add_object, appends a creation event to the transaction
 * log, and returns a signed commit acknowledgement.
 */
UDIF_EXPORT_API udif_errors udif_handle_object_create(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle the sender-signed transfer request.
 *
 * Permitted for: udif_role_ugc (GC).
 *
 * Validates the sender UA's signature and ownership, records the pending
 * transfer, and forwards the request to the receiver UA's tunnel (if
 * connected) for counter-signature. If the receiver is in a different
 * group under the same BC, the GC routes via the BC.
 */
UDIF_EXPORT_API udif_errors udif_handle_object_transfer_req(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle the receiver-signed transfer confirmation.
 *
 * Permitted for: udif_role_ugc (GC).
 *
 * Validates both UA signatures via udif_transfer_verify (sender on the
 * original request, receiver on the confirmation), applies the ownership
 * change, commits the transfer event to the transaction log, updates both
 * UAs' registries, and sends signed commit acknowledgements to both parties.
 */
UDIF_EXPORT_API udif_errors udif_handle_object_transfer_confirm(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a registry root commit notification.
 *
 * Permitted for: udif_role_ugc (GC) receiving from UA, udif_role_ubc (BC)
 * receiving from GC.
 *
 * Records the updated registry root and binds it into the local
 * membership log for inclusion in the next anchor record.
 */
UDIF_EXPORT_API udif_errors udif_handle_registry_commit(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle an inbound anchor record from a child controller.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_root.
 *
 * Verifies the child's signature via udif_anchor_verify, enforces strictly
 * increasing anchor sequence via udif_anchor_validate_sequence, commits the
 * anchor digest to the local membership log, and sends udif_msg_anchor_ack
 * back on tun.
 */
UDIF_EXPORT_API udif_errors udif_handle_anchor_push(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle an anchor acknowledgement from a parent.
 *
 * Permitted for: udif_role_ubc (BC), udif_role_ugc (GC).
 *
 * Records successful upstream commit of the referenced anchor sequence.
 * Failure to receive an acknowledgement within the profile's cadence
 * window is surfaced to the operator as a health warning.
 */
UDIF_EXPORT_API udif_errors udif_handle_anchor_ack(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a treaty proposal from a peer BC.
 *
 * Permitted for: udif_role_ubc (BC).
 *
 * Validates the proposing BC's signature via udif_treaty_verify (single-side,
 * since Domain B has not signed yet), presents the terms to the operator
 * (or applies an automatic policy), and either returns udif_msg_treaty_cosign
 * or a udif_msg_error_report with a decline code.
 */
UDIF_EXPORT_API udif_errors udif_handle_treaty_propose(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a treaty co-signature from the peer BC.
 *
 * Permitted for: udif_role_ubc (BC).
 *
 * Validates both signatures via udif_treaty_verify, commits the final
 * treaty to the local membership log, and activates the treaty for
 * cross-domain queries.
 */
UDIF_EXPORT_API udif_errors udif_handle_treaty_cosign(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a treaty revocation.
 *
 * Permitted for: udif_role_ubc (BC).
 *
 * Validates the revoking BC's signature, marks the treaty revoked,
 * closes the associated treaty tunnel, and logs the revocation.
 */
UDIF_EXPORT_API udif_errors udif_handle_treaty_revoke(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a forwarded cross-domain query from a peer BC.
 *
 * Permitted for: udif_role_ubc (BC).
 *
 * Validates that the treaty is active via udif_treaty_is_active and that
 * the query's predicate family is in the treaty scope bitmap via
 * udif_treaty_allows_scope. Evaluates the predicate locally (or routes it
 * to the appropriate GC), logs the forwarded query, and replies with
 * udif_msg_treaty_query_resp on the same treaty tunnel.
 */
UDIF_EXPORT_API udif_errors udif_handle_treaty_query_fwd(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a cross-domain query response from a peer BC.
 *
 * Permitted for: udif_role_ubc (BC).
 *
 * Validates the peer BC's signature, logs the response, and relays the
 * verdict back to the originating GC (and ultimately the UA that issued
 * the cross-domain query).
 */
UDIF_EXPORT_API udif_errors udif_handle_treaty_query_resp(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

/*!
 * \brief Handle a non-fatal error report from a peer.
 *
 * Permitted for: all roles.
 *
 * Surfaces the error to the operator CLI and updates telemetry counters.
 * Does not reply.
 */
UDIF_EXPORT_API udif_errors udif_handle_error_report(udif_entity_context* ctx, udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs);

#endif
