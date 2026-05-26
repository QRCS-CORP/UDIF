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

#ifndef UDIF_CAPABILITY_H
#define UDIF_CAPABILITY_H

#include "udif.h"

/**
* \file capability.h
* \brief UDIF capability token management
*
* This module implements capability-based access control for UDIF.
* Capabilities are unforgeable tokens that grant specific permissions
* to entities. They use KMAC-256 for authentication.
*
* Capabilities define:
* - Verbs: What operations are allowed
* - Scopes: Where operations can be performed
* - Subject: Who holds the capability
* - Issuer: Who granted the capability
* - Validity: When the capability expires
*/

/*!
 * \def UDIF_CAP_QUERY_EXIST
 * \brief Grants permission to issue existence queries.
 *
 * Allows the holder to query whether a User Agent or Object exists within the
 * authorized local, domain, or treaty scope. Responses are limited to minimal
 * disclosure yes/no semantics.
 */
#define UDIF_CAP_QUERY_EXIST (UINT64_C(1) << 0)

/*!
 * \def UDIF_CAP_QUERY_OWNER_BINDING
 * \brief Grants permission to query object ownership binding.
 *
 * Allows the holder to query whether a specified Object is currently bound to,
 * or owned by, a specified User Agent within the authorized scope.
 */
#define UDIF_CAP_QUERY_OWNER_BINDING (UINT64_C(1) << 1)

/*!
 * \def UDIF_CAP_QUERY_ATTR_BUCKET
 * \brief Grants permission to query predefined attribute buckets.
 *
 * Allows the holder to evaluate approved attribute-bucket predicates, such as
 * active, suspended, destroyed, or other profile-defined bucket states, without
 * exposing raw attribute values.
 */
#define UDIF_CAP_QUERY_ATTR_BUCKET (UINT64_C(1) << 2)

/*!
 * \def UDIF_CAP_PROVE_MEMBERSHIP
 * \brief Grants permission to request Merkle membership proofs.
 *
 * Allows the holder to request membership or registry proofs for Objects,
 * registries, or committed records where such proofs are authorized by policy.
 */
#define UDIF_CAP_PROVE_MEMBERSHIP (UINT64_C(1) << 3)

/*!
 * \def UDIF_CAP_FORWARD_QUERY
 * \brief Grants permission to forward authorized queries.
 *
 * Allows a Group Controller or Branch Controller to forward queries upstream
 * or across treaty peers, subject to scope, treaty, and policy restrictions.
 */
#define UDIF_CAP_FORWARD_QUERY (UINT64_C(1) << 4)

/*!
 * \def UDIF_CAP_ADMIN_ENROLL
 * \brief Grants permission to enroll subordinate entities.
 *
 * Allows the holder to enroll new User Agents, Group Controllers, or subordinate
 * Branch Controllers, depending on the holder role and parent-issued scope.
 */
#define UDIF_CAP_ADMIN_ENROLL (UINT64_C(1) << 5)

/*!
 * \def UDIF_CAP_ADMIN_SUSPEND
 * \brief Grants permission to suspend subordinate certificates.
 *
 * Allows the holder to temporarily suspend User Agents, Group Controllers, or
 * Branch Controllers pending audit, investigation, or policy review.
 */
#define UDIF_CAP_ADMIN_SUSPEND (UINT64_C(1) << 6)

/*!
 * \def UDIF_CAP_ADMIN_RESUME
 * \brief Grants permission to resume suspended subordinate certificates.
 *
 * Allows the holder to restore a previously suspended User Agent, Group
 * Controller, or Branch Controller when policy and audit conditions are met.
 */
#define UDIF_CAP_ADMIN_RESUME (UINT64_C(1) << 7)

/*!
 * \def UDIF_CAP_ADMIN_REVOKE
 * \brief Grants permission to revoke subordinate certificates.
 *
 * Allows the holder to permanently revoke User Agent, Group Controller, or
 * Branch Controller certificates within the holder's delegated authority.
 */
#define UDIF_CAP_ADMIN_REVOKE (UINT64_C(1) << 8)

/*!
 * \def UDIF_CAP_ADMIN_BRANCH_CREATE
 * \brief Grants permission to create subordinate branches or groups.
 *
 * Allows a Branch Controller to instantiate a subordinate Branch Controller or
 * Group Controller. This bit should not be granted to User Agents.
 */
#define UDIF_CAP_ADMIN_BRANCH_CREATE (UINT64_C(1) << 9)

/*!
 * \def UDIF_CAP_ADMIN_BRANCH_RETIRE
 * \brief Grants permission to retire or prune subordinate branches.
 *
 * Allows a Branch Controller to permanently retire, prune, or decommission a
 * subordinate branch according to policy and audit requirements.
 */
#define UDIF_CAP_ADMIN_BRANCH_RETIRE (UINT64_C(1) << 10)

/*!
 * \def UDIF_CAP_REGISTRY_COMMIT
 * \brief Grants permission to commit registry roots.
 *
 * Allows User Agents to commit their own registry roots, or Group Controllers
 * to commit group registry state, depending on role and delegated scope.
 */
#define UDIF_CAP_REGISTRY_COMMIT (UINT64_C(1) << 11)

/*!
 * \def UDIF_CAP_TX_CREATE
 * \brief Grants permission to originate transaction events.
 *
 * Allows the holder to originate transaction events, including object creation,
 * object update, or object transfer initiation, subject to role and ownership
 * checks.
 */
#define UDIF_CAP_TX_CREATE (UINT64_C(1) << 12)

/*!
 * \def UDIF_CAP_TX_ACCEPT
 * \brief Grants permission to accept incoming transaction transfers.
 *
 * Allows the holder to co-sign and accept incoming object transfers or other
 * transaction events requiring counterparty acceptance.
 */
#define UDIF_CAP_TX_ACCEPT (UINT64_C(1) << 13)

/*!
 * \def UDIF_CAP_LOG_ANCHOR_SEND
 * \brief Grants permission to generate and send Anchor Records upstream.
 *
 * Allows a Group Controller or Branch Controller to generate signed Anchor
 * Records and submit them to its parent authority.
 */
#define UDIF_CAP_LOG_ANCHOR_SEND (UINT64_C(1) << 14)

/*!
 * \def UDIF_CAP_LOG_ANCHOR_VERIFY
 * \brief Grants permission to verify and append child Anchor Records.
 *
 * Allows a parent controller to verify signed Anchor Records received from
 * subordinate controllers and append accepted anchors to its logs.
 */
#define UDIF_CAP_LOG_ANCHOR_VERIFY (UINT64_C(1) << 15)

/*!
 * \def UDIF_CAP_TREATY_NEGOTIATE
 * \brief Grants permission to negotiate and sign Peering Treaties.
 *
 * Allows an authorized Branch Controller or Group Controller to negotiate,
 * approve, and sign treaty records with a peer domain controller.
 */
#define UDIF_CAP_TREATY_NEGOTIATE (UINT64_C(1) << 16)

/*!
 * \def UDIF_CAP_TREATY_QUERY_EXEC
 * \brief Grants permission to execute treaty-scoped queries.
 *
 * Allows the holder to process incoming treaty queries within the predicate
 * families and bounds explicitly allowed by a valid Peering Treaty.
 */
#define UDIF_CAP_TREATY_QUERY_EXEC (UINT64_C(1) << 17)

/*!
 * \def UDIF_CAP_TREATY_QUERY_ORIGIN
 * \brief Grants permission to originate treaty-scoped queries.
 *
 * Allows the holder to originate cross-domain treaty queries to a peer domain,
 * subject to a valid treaty, predicate scope, and policy epoch.
 */
#define UDIF_CAP_TREATY_QUERY_ORIGIN (UINT64_C(1) << 18)

/*!
 * \def UDIF_CAP_TELEMETRY_EXPORT
 * \brief Grants permission to export telemetry counters.
 *
 * Allows the holder to export authorized telemetry counters in Anchor Records.
 * Telemetry export must not disclose raw identifiers, attributes, or private
 * transaction contents.
 */
#define UDIF_CAP_TELEMETRY_EXPORT (UINT64_C(1) << 19)

/*!
 * \def UDIF_CAP_ERROR_REPORT
 * \brief Grants permission to issue signed error events into logs.
 *
 * Allows the holder to create signed error reports or audit events and append
 * them to the appropriate membership, transaction, or operational log.
 */
#define UDIF_CAP_ERROR_REPORT (UINT64_C(1) << 20)

/*!
 * \def UDIF_CAP_RESERVED_FUTURE_CORE_MASK
 * \brief Reserved capability bits for future UDIF core extensions.
 *
 * Bits 21 through 31 are reserved for future UDIF core capability assignments.
 * These bits must be zero in UDIF v1 certificates and capability tokens unless
 * a later core revision explicitly defines them.
 */
#define UDIF_CAP_RESERVED_FUTURE_CORE_MASK (UINT64_C(0x00000000FFE00000))

/*!
 * \def UDIF_CAP_RESERVED_PROFILE_MASK
 * \brief Reserved capability bits for profile-specific extensions.
 *
 * Bits 32 through 63 are reserved for profile-specific, jurisdictional, audit,
 * privacy, or zero-knowledge extension profiles. Core implementations must not
 * assign conflicting meanings to these bits.
 */
#define UDIF_CAP_RESERVED_PROFILE_MASK (UINT64_C(0xFFFFFFFF00000000))

/*!
 * \def UDIF_CAP_QUERY_MASK
 * \brief Mask of all core predicate-query capabilities.
 */
#define UDIF_CAP_QUERY_MASK \
    (UDIF_CAP_QUERY_EXIST | \
     UDIF_CAP_QUERY_OWNER_BINDING | \
     UDIF_CAP_QUERY_ATTR_BUCKET | \
     UDIF_CAP_PROVE_MEMBERSHIP)

/*!
 * \def UDIF_CAP_ADMIN_MASK
 * \brief Mask of all core administrative capabilities.
 */
#define UDIF_CAP_ADMIN_MASK \
    (UDIF_CAP_ADMIN_ENROLL | \
     UDIF_CAP_ADMIN_SUSPEND | \
     UDIF_CAP_ADMIN_RESUME | \
     UDIF_CAP_ADMIN_REVOKE | \
     UDIF_CAP_ADMIN_BRANCH_CREATE | \
     UDIF_CAP_ADMIN_BRANCH_RETIRE)

/*!
 * \def UDIF_CAP_TRANSACTION_MASK
 * \brief Mask of all core transaction and registry capabilities.
 */
#define UDIF_CAP_TRANSACTION_MASK \
    (UDIF_CAP_REGISTRY_COMMIT | \
     UDIF_CAP_TX_CREATE | \
     UDIF_CAP_TX_ACCEPT)

/*!
 * \def UDIF_CAP_ANCHOR_MASK
 * \brief Mask of all core anchoring capabilities.
 */
#define UDIF_CAP_ANCHOR_MASK \
    (UDIF_CAP_LOG_ANCHOR_SEND | \
     UDIF_CAP_LOG_ANCHOR_VERIFY)

/*!
 * \def UDIF_CAP_TREATY_MASK
 * \brief Mask of all core treaty capabilities.
 */
#define UDIF_CAP_TREATY_MASK \
    (UDIF_CAP_TREATY_NEGOTIATE | \
     UDIF_CAP_TREATY_QUERY_EXEC | \
     UDIF_CAP_TREATY_QUERY_ORIGIN)

/*!
 * \def UDIF_CAP_AUDIT_MASK
 * \brief Mask of core audit-support capabilities.
 */
#define UDIF_CAP_AUDIT_MASK \
    (UDIF_CAP_TELEMETRY_EXPORT | \
     UDIF_CAP_ERROR_REPORT)


/*!
 * \def UDIF_ROOT_CAPABILITIES
 * \brief Default capability mask for a UDIF Root certificate.
 *
 * The Root capability mask grants only domain-anchor and top-level issuance
 * authority. It permits the Root to issue, suspend, resume, revoke, create, and
 * retire subordinate branch authorities, and to verify Anchor Records submitted
 * by immediate children.
 *
 * The Root mask intentionally excludes User Agent, object ownership, registry
 * mutation, transaction origination, and treaty-query capabilities. The Root is
 * the trust anchor and policy origin for the domain; operational authority is
 * delegated to Branch Controllers and Group Controllers through signed
 * subordinate certificates.
 *
 * \warning This mask is an issuer-side maximum for Root operation. It must not
 * be copied blindly into subordinate certificates.
 */
#define UDIF_ROOT_CAPABILITIES \
    (UDIF_CAP_ADMIN_ENROLL | \
     UDIF_CAP_ADMIN_SUSPEND | \
     UDIF_CAP_ADMIN_RESUME | \
     UDIF_CAP_ADMIN_REVOKE | \
     UDIF_CAP_ADMIN_BRANCH_CREATE | \
     UDIF_CAP_ADMIN_BRANCH_RETIRE | \
     UDIF_CAP_LOG_ANCHOR_VERIFY)

/*!
 * \def UDIF_BC_CAPABILITIES
 * \brief Default capability mask for a UDIF Branch Controller certificate.
 *
 * The Branch Controller capability mask grants authority to administer a
 * subordinate branch or group subtree. It permits enrollment and lifecycle
 * control of subordinate certificates, creation and retirement of subordinate
 * branches or groups, forwarding of authorized queries, generation of upstream
 * Anchor Records, verification of child Anchor Records, export of permitted
 * telemetry counters, and issuance of signed operational error reports.
 *
 * This mask is appropriate for a Branch Controller operating in branch-admin
 * mode. A Branch Controller operating as a Group Controller should instead use
 * the Group Controller capability mask.
 *
 * Treaty capabilities are excluded from this default mask. They should be
 * granted only when a valid Peering Treaty and parent policy explicitly permit
 * cross-domain operation.
 */
#define UDIF_BC_CAPABILITIES \
    (UDIF_CAP_FORWARD_QUERY | \
     UDIF_CAP_ADMIN_ENROLL | \
     UDIF_CAP_ADMIN_SUSPEND | \
     UDIF_CAP_ADMIN_RESUME | \
     UDIF_CAP_ADMIN_REVOKE | \
     UDIF_CAP_ADMIN_BRANCH_CREATE | \
     UDIF_CAP_ADMIN_BRANCH_RETIRE | \
     UDIF_CAP_LOG_ANCHOR_SEND | \
     UDIF_CAP_LOG_ANCHOR_VERIFY | \
     UDIF_CAP_TELEMETRY_EXPORT | \
     UDIF_CAP_ERROR_REPORT)

/*!
 * \def UDIF_GC_CAPABILITIES
 * \brief Default capability mask for a UDIF Group Controller certificate.
 *
 * The Group Controller capability mask grants authority to administer User
 * Agents within a group. It permits enrollment, suspension, resumption, and
 * revocation of User Agent certificates, forwarding of authorized queries,
 * registry-root commitment on behalf of the managed group, generation of
 * upstream Anchor Records, export of permitted telemetry counters, and issuance
 * of signed operational error reports.
 *
 * The mask intentionally excludes branch creation and branch retirement because
 * a Group Controller directly manages User Agents and must not create
 * subordinate administrative branches.
 *
 * Transaction origination and acceptance are excluded by default because those
 * capabilities belong to User Agents as object owners. The Group Controller
 * validates, logs, and anchors transaction evidence, but it does not own objects
 * and should not receive object-owner transaction rights unless a specific
 * implementation profile defines a separate service-actor role.
 */
#define UDIF_GC_CAPABILITIES \
    (UDIF_CAP_FORWARD_QUERY | \
     UDIF_CAP_ADMIN_ENROLL | \
     UDIF_CAP_ADMIN_SUSPEND | \
     UDIF_CAP_ADMIN_RESUME | \
     UDIF_CAP_ADMIN_REVOKE | \
     UDIF_CAP_REGISTRY_COMMIT | \
     UDIF_CAP_LOG_ANCHOR_SEND | \
     UDIF_CAP_TELEMETRY_EXPORT | \
     UDIF_CAP_ERROR_REPORT)

/*!
 * \def UDIF_CLIENT_CAPABILITIES
 * \brief Default capability mask for a UDIF client or User Agent certificate.
 *
 * The client capability mask grants only end-entity rights. It permits minimal
 * predicate queries, membership-proof requests where authorized, registry-root
 * commitment for the client's own registry, transaction creation, transaction
 * acceptance, and signed error reporting.
 *
 * A client must not receive administrative, branch-management, anchor-verifier,
 * treaty-negotiation, or query-forwarding capabilities. User Agents are leaf
 * entities in the UDIF hierarchy and cannot administer other certificates or
 * interact laterally outside their Group Controller.
 *
 * \note In a stricter deployment profile, UDIF_CAP_PROVE_MEMBERSHIP may be
 * removed from this default and issued only through a separate GC-signed
 * capability token.
 */
#define UDIF_CLIENT_CAPABILITIES \
    (UDIF_CAP_QUERY_EXIST | \
     UDIF_CAP_QUERY_OWNER_BINDING | \
     UDIF_CAP_QUERY_ATTR_BUCKET | \
     UDIF_CAP_PROVE_MEMBERSHIP | \
     UDIF_CAP_REGISTRY_COMMIT | \
     UDIF_CAP_TX_CREATE | \
     UDIF_CAP_TX_ACCEPT | \
     UDIF_CAP_ERROR_REPORT)

/*!
 * \def UDIF_CAP_CORE_DEFINED_MASK
 * \brief Mask of all UDIF v1 core-defined capability bits.
 *
 * Includes all normative UDIF v1 capability bits from bit 0 through bit 20.
 */
#define UDIF_CAP_CORE_DEFINED_MASK \
    (UDIF_CAP_QUERY_EXIST | \
     UDIF_CAP_QUERY_OWNER_BINDING | \
     UDIF_CAP_QUERY_ATTR_BUCKET | \
     UDIF_CAP_PROVE_MEMBERSHIP | \
     UDIF_CAP_FORWARD_QUERY | \
     UDIF_CAP_ADMIN_ENROLL | \
     UDIF_CAP_ADMIN_SUSPEND | \
     UDIF_CAP_ADMIN_RESUME | \
     UDIF_CAP_ADMIN_REVOKE | \
     UDIF_CAP_ADMIN_BRANCH_CREATE | \
     UDIF_CAP_ADMIN_BRANCH_RETIRE | \
     UDIF_CAP_REGISTRY_COMMIT | \
     UDIF_CAP_TX_CREATE | \
     UDIF_CAP_TX_ACCEPT | \
     UDIF_CAP_LOG_ANCHOR_SEND | \
     UDIF_CAP_LOG_ANCHOR_VERIFY | \
     UDIF_CAP_TREATY_NEGOTIATE | \
     UDIF_CAP_TREATY_QUERY_EXEC | \
     UDIF_CAP_TREATY_QUERY_ORIGIN | \
     UDIF_CAP_TELEMETRY_EXPORT | \
     UDIF_CAP_ERROR_REPORT)

/*!
 * \def UDIF_TREATY_ORIGIN_CAPABILITIES
 * \brief Optional capability overlay for originating treaty-scoped queries.
 *
 * Grants the ability to originate treaty queries and forward them to a peer
 * domain. This mask must be applied only when an active Peering Treaty and
 * parent policy explicitly authorize the predicate family and peer scope.
 */
#define UDIF_TREATY_ORIGIN_CAPABILITIES (UDIF_CAP_FORWARD_QUERY | UDIF_CAP_TREATY_QUERY_ORIGIN)

/*!
 * \def UDIF_TREATY_EXEC_CAPABILITIES
 * \brief Optional capability overlay for executing treaty-scoped queries.
 *
 * Grants the ability to process treaty queries received from a peer domain.
 * This mask must be constrained by the Peering Treaty, local policy, and the
 * certificate's role.
 */
#define UDIF_TREATY_EXEC_CAPABILITIES (UDIF_CAP_TREATY_QUERY_EXEC)

/*!
 * \def UDIF_TREATY_ADMIN_CAPABILITIES
 * \brief Optional capability overlay for treaty negotiation.
 *
 * Grants the ability to negotiate and sign Peering Treaties. This capability
 * should normally be restricted to authorized Branch Controllers or specially
 * designated Group Controllers.
 */
#define UDIF_TREATY_ADMIN_CAPABILITIES (UDIF_CAP_TREATY_NEGOTIATE)

/*!
 * \def UDIF_CAP_NONE
 * \brief Empty capability mask.
 *
 * Represents the UDIF default-deny state. A certificate or capability token
 * with this mask grants no operational rights.
 */
#define UDIF_CAP_NONE (UINT64_C(0))

/*!
 * \def UDIF_CAP_ALL_CORE
 * \brief Mask containing all UDIF v1 core-defined capabilities.
 *
 * This mask is intended for validation, testing, and issuer-side policy
 * construction. It should not be assigned blindly to subordinate certificates.
 */
#define UDIF_CAP_ALL_CORE (UDIF_CAP_CORE_DEFINED_MASK)

/*! \def UDIF_CAPABILITY_BITMAP_SIZE
 * \brief Capability bitmap size in bytes (64-bit)
 */
#define UDIF_CAPABILITY_POLICY_SIZE 8U

/*! \def UDIF_CAPABILITY_ENCODED_SIZE
 * \brief The capability structure encoded size
 */
#define UDIF_CAPABILITY_ENCODED_SIZE (UDIF_CRYPTO_HASH_SIZE + \
	UDIF_CRYPTO_MAC_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_CAPABILITY_POLICY_SIZE)

/*! \def UDIF_CAPABILITY_SIGNED_SIZE
 * \brief The capability structure signed size
 */
#define UDIF_CAPABILITY_SIGNED_SIZE (UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_SERIAL_NUMBER_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_VALID_TIME_SIZE + \
	UDIF_CAPABILITY_BITMAP_SIZE + \
	UDIF_CAPABILITY_POLICY_SIZE)

/*!
* \struct udif_capability
* \brief Capability token
*
* A capability token grants specific permissions to an entity.
* It is authenticated with KMAC-256 and can be verified by the issuer.
*/
UDIF_EXPORT_API typedef struct udif_capability
{
	uint8_t digest[UDIF_CRYPTO_HASH_SIZE];		/*!< Capability digest */
	uint8_t tag[UDIF_CRYPTO_MAC_SIZE];			/*!< KMAC authentication tag */
	uint8_t issuedby[UDIF_SERIAL_NUMBER_SIZE];	/*!< Issuer serial */
	uint8_t issuedto[UDIF_SERIAL_NUMBER_SIZE];	/*!< Recipient serial */
	uint64_t scopebitmap;						/*!< Allowed operation scopes */
	uint64_t validto;							/*!< Expiration time */
	uint64_t verbsbitmap;						/*!< Allowed operation verbs */
	uint64_t policy;							/*!< Policy version */
} udif_capability;


/** \cond NO_DOCUMENT */

static const char UDIF_CAPABILITY_ERROR_STRINGS[][UDIF_ERROR_STRING_SIZE] =
{
	"No error",
	"Capability denied by policy",
	"Empty capability mask",
	"Conflicting capability bits"
};

/** \endcond NO_DOCUMENT */

/*!
 * \enum udif_capability_id
 * \brief Canonical capability identifiers (bit positions map to the mask).
 */
typedef enum udif_capability_id
{
	udif_capability_issue_certificate = 0x00U,  /*!< Issue subordinate certificates */
	udif_capability_revoke_certificate = 0x01U,	/*!< Revoke certificates */
	udif_capability_issue_token = 0x02U,		/*!< Issue capability/attestation tokens */
	udif_capability_validate_token = 0x03U,		/*!< Validate tokens and claims */
	udif_capability_register_issuer = 0x04U,	/*!< Register issuer domain codes */
	udif_capability_rotate_keys = 0x05U,		/*!< Rotate root/issuer keys */
	udif_capability_directory_query = 0x06U,	/*!< Query directory / discovery */
	udif_capability_audit_logging_access = 0x07U,	/*!< Access audit logs */
	udif_capability_admin = 0x08U				/*!< Administrative override */
} udif_capability_id;

/*!
* \enum udif_capability_verbs
* \brief Capability permission verbs (bit positions)
*/
typedef enum udif_capability_verbs
{
	udif_capability_query_exist = 0U,			/*!< Query existence */
	udif_capability_query_owner_binding = 1U,	/*!< Query owner binding */
	udif_capability_query_attr_bucket = 2U,		/*!< Query attribute bucket */
	udif_capability_prove_membership = 3U,		/*!< Prove membership */
	udif_capability_forward_query = 4U,			/*!< Forward query */
	udif_capability_admin_enroll = 5U,			/*!< Enroll entity */
	udif_capability_admin_suspend = 6U,			/*!< Suspend entity */
	udif_capability_admin_resume = 7U,			/*!< Resume entity */
	udif_capability_admin_revoke = 8U,			/*!< Revoke entity */
	udif_capability_admin_branch_create = 9U,	/*!< Create branch */
	udif_capability_admin_branch_retire = 10U,	/*!< Retire branch */
	udif_capability_registry_commit = 11U,		/*!< Commit registry */
	udif_capability_tx_create = 12U,            /*!< Create transaction */
	udif_capability_tx_accept = 13U,            /*!< Accept transaction */
	udif_capability_logging_anchor_send = 14U,  /*!< Send anchor */
	udif_capability_logging_anchor_verify = 15U,/*!< Verify anchor */
	udif_capability_treaty_negotiate = 16U,     /*!< Negotiate treaty */
	udif_capability_treaty_query_exec = 17U,    /*!< Execute treaty query */
	udif_capability_treaty_query_origin = 18U,  /*!< Originate treaty query */
	udif_capability_telemetry_export = 19U,     /*!< Export telemetry */
	udif_capability_error_report = 20U          /*!< Report error */
} udif_capability_verbs;

/*!
* \enum udif_capability_scopes
* \brief Capability scope flags
*/
typedef enum udif_capability_scopes
{
	udif_scope_local = 0U,						/*!< Local only */
	udif_scope_intra_domain = 1U,				/*!< Intra-domain */
	udif_scope_treaty = 2U						/*!< Cross-domain treaty */
} udif_capability_scopes;

/*!
 * \def UDIF_CAPABILITY_ALL
 * \brief Full capability bitmap granting all defined verb bits.
 *
 * Used when generating root or first-level subordinate certificates that
 * require unrestricted operational capabilities within the domain.
 * Covers all 21 defined verbs (bits 0-20).
 */
#define UDIF_CAPABILITY_ALL UINT64_C(0x00000000001FFFFF)

/*!
* \brief Check if capability allows a scope
*
* Tests if a specific operation scope is granted.
*
* \param capability: [const] The capability
* \param scope: The scope to check
*
* \return Returns true if allowed
*/
UDIF_EXPORT_API bool udif_capability_allows_scope(const udif_capability* capability, uint32_t scope);

/*!
* \brief Check if capability allows a verb
*
* Tests if a specific operation verb is granted.
*
* \param capability: [const] The capability
* \param verb: The verb to check (bit position)
*
* \return Returns true if allowed
*/
UDIF_EXPORT_API bool udif_capability_allows_verb(const udif_capability* capability, uint32_t verb);

/*!
* \brief Clear a capability
*
* Zeros out a capability structure.
*
* \param capability: The capability to clear
*/
UDIF_EXPORT_API void udif_capability_clear(udif_capability* capability);

/*!
* \brief Create a capability token
*
* Creates a new capability token authenticated with KMAC-256.
*
* \param capability: The output capability structure
* \param verbsbitmap: The allowed operation verbs
* \param scopebitmap: The allowed operation scopes
* \param issuedto: [const] The recipient serial (16 bytes)
* \param issuedby: [const] The issuer serial (16 bytes)
* \param validto: The expiration time (UTC seconds)
* \param policy: The policy version number
* \param issuerkey: [const] The issuer's MAC key
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_create(udif_capability* capability, uint32_t verbsbitmap, uint32_t scopebitmap, const uint8_t* issuedto,
	const uint8_t* issuedby, uint64_t validto, uint32_t policy, const uint8_t* issuerkey);

/*!
* \brief Compute object digest
*
* Computes the canonical digest for an object, does not include the signature and hash.
*
* \param digest: The output digest (32 bytes)
* \param capability: The output capability structure
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_compute_digest(uint8_t* digest, const udif_capability* capability);

/*!
* \brief Deserialize a capability
*
* Decodes a capability from canonical TLV format.
*
* \param capability: The output capability structure
* \param input: [const] The input buffer
* \param inplen: The input buffer length
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_deserialize(udif_capability* capability, const uint8_t* input, size_t inplen);

/*!
* \brief Check if capability grants permission
*
* Comprehensive check: verb, scope, and expiration.
*
* \param capability: [const] The capability
* \param verb: The required verb
* \param scope: The required scope
* \param ctime: The current time
*
* \return Returns true if permission granted
*/
UDIF_EXPORT_API bool udif_capability_grants_permission(const udif_capability* capability, uint32_t verb, uint32_t scope, uint64_t ctime);

/*!
* \brief Check if capability is expired
*
* Tests if a capability has expired.
*
* \param capability: [const] The capability
* \param ctime: The current time (UTC seconds)
*
* \return Returns true if expired
*/
UDIF_EXPORT_API bool udif_capability_is_expired(const udif_capability* capability, uint64_t ctime);

/*!
* \brief Serialize a capability
*
* Encodes a capability to canonical TLV format.
*
* \param output: The output buffer
* \param outlen: The output buffer LENGTH
* \param capability: [const] The capability to serialize
*
* \return Returns udif_error_none on success
*/
UDIF_EXPORT_API udif_errors udif_capability_serialize(uint8_t* output, size_t outlen, const udif_capability* capability);

/*!
* \brief Verify a capability token
*
* Verifies the KMAC authentication tag on a capability.
*
* \param capability: [const] The capability to verify
* \param issuerkey: [const] The issuer's MAC key
*
* \return Returns true if valid
*/
UDIF_EXPORT_API bool udif_capability_verify(const udif_capability* capability, const uint8_t* issuerkey);

#endif
