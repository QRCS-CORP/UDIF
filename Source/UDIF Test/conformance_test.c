#include "conformance_test.h"
#include "anchor.h"
#include "capability.h"
#include "certificate.h"
#include "dispatch.h"
#include "entity.h"
#include "message.h"
#include "object.h"
#include "query.h"
#include "registry.h"
#include "treaty.h"
#include "tunnel.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "consoleutils.h"

static void conformance_test_fill(uint8_t* output, size_t outlen, uint8_t seed)
{
	uint8_t val;
	size_t i;

	if (output != NULL)
	{
		val = seed;

		for (i = 0U; i < outlen; ++i)
		{
			output[i] = val;
			val = (uint8_t)(val + 1U);
		}
	}
}

static bool conformance_test_constants(void)
{
	bool res;

	res = true;

	if (UDIF_CERT_SERIAL_SIZE != 16U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: certificate serial size mismatch");
		res = false;
	}
	else if (UDIF_OBJECT_SERIAL_SIZE != 32U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: object serial size mismatch");
		res = false;
	}
	else if (UDIF_QUERY_ID_SIZE != 16U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: query id size mismatch");
		res = false;
	}
	else if (UDIF_TX_ID_SIZE != 32U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: transaction id size mismatch");
		res = false;
	}
	else if (UDIF_REGISTRY_LEAF_ENCODED_SIZE != ((2U * UDIF_CRYPTO_HASH_SIZE) + UDIF_OBJECT_SERIAL_SIZE + UDIF_REGISTRY_LEAF_FLAGS_SIZE + UDIF_VALID_TIME_SIZE))
	{
		qsc_consoleutils_print_line("conformance_test_constants: registry leaf size mismatch");
		res = false;
	}
	else if (UDIF_TUNNEL_RECORD_HEADER_SIZE != 26U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: tunnel header size mismatch");
		res = false;
	}
	else if (UDIF_TRANSPORT_PROFILE_QSTP_INNER_HEADER != 1U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: transport profile mismatch");
		res = false;
	}
	else if (UDIF_TRANSPORT_HEADER_EXTERNAL_AAD != 0U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: transport AAD mode mismatch");
		res = false;
	}
	else if (UDIF_TRANSPORT_RATCHET_DELEGATED_TO_QSTP != 1U)
	{
		qsc_consoleutils_print_line("conformance_test_constants: transport ratchet delegation mismatch");
		res = false;
	}

	return res;
}


static bool conformance_test_certificate_decode_lengths(void)
{
	uint8_t enc[UDIF_CERTIFICATE_SIZE + 1U] = { 0U };
	udif_certificate cert;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&cert, sizeof(udif_certificate));
	conformance_test_fill(enc, sizeof(enc), 0x13U);

	err = udif_certificate_deserialize(&cert, enc, UDIF_CERTIFICATE_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_certificate_decode_lengths: exact certificate decode rejected");
		res = false;
	}

	err = udif_certificate_deserialize(&cert, enc, UDIF_CERTIFICATE_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_certificate_decode_lengths: truncated certificate accepted");
		res = false;
	}

	err = udif_certificate_deserialize(&cert, enc, UDIF_CERTIFICATE_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_certificate_decode_lengths: trailing certificate bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_capability_decode_lengths(void)
{
	uint8_t enc[UDIF_CAPABILITY_ENCODED_SIZE + 1U] = { 0U };
	udif_capability capability;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&capability, sizeof(udif_capability));
	conformance_test_fill(enc, sizeof(enc), 0x17U);

	err = udif_capability_deserialize(&capability, enc, UDIF_CAPABILITY_ENCODED_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_capability_decode_lengths: exact capability decode rejected");
		res = false;
	}

	err = udif_capability_deserialize(&capability, enc, UDIF_CAPABILITY_ENCODED_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_capability_decode_lengths: truncated capability accepted");
		res = false;
	}

	err = udif_capability_deserialize(&capability, enc, UDIF_CAPABILITY_ENCODED_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_capability_decode_lengths: trailing capability bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_object_decode_lengths(void)
{
	uint8_t enc[UDIF_OBJECT_ENCODED_SIZE + 1U] = { 0U };
	udif_object obj;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&obj, sizeof(udif_object));
	conformance_test_fill(enc, sizeof(enc), 0x11U);

	err = udif_object_deserialize(&obj, enc, UDIF_OBJECT_ENCODED_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_object_decode_lengths: exact object decode rejected");
		res = false;
	}

	err = udif_object_deserialize(&obj, enc, UDIF_OBJECT_ENCODED_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_object_decode_lengths: truncated object accepted");
		res = false;
	}

	err = udif_object_deserialize(&obj, enc, UDIF_OBJECT_ENCODED_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_object_decode_lengths: trailing object bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_transfer_decode_lengths(void)
{
	uint8_t enc[UDIF_TRANSFER_RECORD_ENCODED_SIZE + 1U] = { 0U };
	udif_transfer_record transfer;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&transfer, sizeof(udif_transfer_record));
	conformance_test_fill(enc, sizeof(enc), 0x22U);

	err = udif_transfer_deserialize(&transfer, enc, UDIF_TRANSFER_RECORD_ENCODED_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_transfer_decode_lengths: exact transfer decode rejected");
		res = false;
	}

	err = udif_transfer_deserialize(&transfer, enc, UDIF_TRANSFER_RECORD_ENCODED_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_transfer_decode_lengths: truncated transfer accepted");
		res = false;
	}

	err = udif_transfer_deserialize(&transfer, enc, UDIF_TRANSFER_RECORD_ENCODED_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_transfer_decode_lengths: trailing transfer bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_anchor_decode_lengths(void)
{
	uint8_t enc[UDIF_ANCHOR_RECORD_SIZE + 1U] = { 0U };
	udif_anchor_record anchor;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&anchor, sizeof(udif_anchor_record));
	conformance_test_fill(enc, sizeof(enc), 0x33U);

	err = udif_anchor_deserialize(&anchor, enc, UDIF_ANCHOR_RECORD_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_anchor_decode_lengths: exact anchor decode rejected");
		res = false;
	}

	err = udif_anchor_deserialize(&anchor, enc, UDIF_ANCHOR_RECORD_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_anchor_decode_lengths: truncated anchor accepted");
		res = false;
	}

	err = udif_anchor_deserialize(&anchor, enc, UDIF_ANCHOR_RECORD_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_anchor_decode_lengths: trailing anchor bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_treaty_decode_lengths(void)
{
	uint8_t enc[UDIF_TREATY_STRUCTURE_SIZE + 1U] = { 0U };
	udif_treaty treaty;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&treaty, sizeof(udif_treaty));
	conformance_test_fill(enc, sizeof(enc), 0x44U);

	err = udif_treaty_deserialize(&treaty, enc, UDIF_TREATY_STRUCTURE_SIZE);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_treaty_decode_lengths: exact treaty decode rejected");
		res = false;
	}

	err = udif_treaty_deserialize(&treaty, enc, UDIF_TREATY_STRUCTURE_SIZE - 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_treaty_decode_lengths: truncated treaty accepted");
		res = false;
	}

	err = udif_treaty_deserialize(&treaty, enc, UDIF_TREATY_STRUCTURE_SIZE + 1U);

	if (err != udif_error_decode_failure)
	{
		qsc_consoleutils_print_line("conformance_test_treaty_decode_lengths: trailing treaty bytes accepted");
		res = false;
	}

	return res;
}

static bool conformance_test_query_decode_lengths(void)
{
	uint8_t enc[UDIF_QUERY_STRUCTURE_SIZE + UDIF_OBJECT_SERIAL_SIZE + 1U] = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objser[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_query query;
	udif_query dec;
	udif_errors err;
	size_t enclen;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
	qsc_memutils_clear((uint8_t*)&dec, sizeof(udif_query));
	conformance_test_fill(queryid, sizeof(queryid), 0x51U);
	conformance_test_fill(targser, sizeof(targser), 0x61U);
	conformance_test_fill(objser, sizeof(objser), 0x71U);
	conformance_test_fill(capref, sizeof(capref), 0x81U);

	err = udif_query_create_existence(&query, queryid, targser, objser, 1000U, capref);
	enclen = sizeof(enc);

	if (err == udif_error_none)
	{
		err = udif_query_serialize(enc, &enclen, &query);
	}

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_query_decode_lengths: query serialize failed");
		res = false;
	}
	else
	{
		err = udif_query_deserialize(&dec, enc, enclen);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("conformance_test_query_decode_lengths: exact query decode rejected");
			res = false;
		}

		udif_query_clear(&dec);
		err = udif_query_deserialize(&dec, enc, enclen - 1U);

		if (err != udif_error_decode_failure)
		{
			qsc_consoleutils_print_line("conformance_test_query_decode_lengths: truncated query accepted");
			res = false;
		}

		udif_query_clear(&dec);
		err = udif_query_deserialize(&dec, enc, enclen + 1U);

		if (err != udif_error_decode_failure)
		{
			qsc_consoleutils_print_line("conformance_test_query_decode_lengths: trailing query bytes accepted");
			res = false;
		}
	}

	udif_query_clear(&dec);
	udif_query_clear(&query);

	return res;
}

static bool conformance_test_query_response_decode_lengths(void)
{
	uint8_t enc[UDIF_QUERY_RESPONSE_STRUCTURE_SIZE + 33U] = { 0U };
	uint8_t proof[32U] = { 0U };
	uint8_t queryid[UDIF_QUERY_ID_SIZE] = { 0U };
	uint8_t targser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t objser[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	uint8_t capref[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t respser[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t sigkey[UDIF_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
	uint8_t verkey[UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE] = { 0U };
	udif_query query;
	udif_query_response response;
	udif_query_response dec;
	udif_errors err;
	size_t enclen;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&query, sizeof(udif_query));
	qsc_memutils_clear((uint8_t*)&response, sizeof(udif_query_response));
	qsc_memutils_clear((uint8_t*)&dec, sizeof(udif_query_response));
	conformance_test_fill(queryid, sizeof(queryid), 0x91U);
	conformance_test_fill(targser, sizeof(targser), 0xA1U);
	conformance_test_fill(objser, sizeof(objser), 0xB1U);
	conformance_test_fill(capref, sizeof(capref), 0xC1U);
	conformance_test_fill(respser, sizeof(respser), 0xD1U);
	conformance_test_fill(proof, sizeof(proof), 0xE1U);
	udif_signature_generate_keypair(verkey, sigkey, qsc_csp_generate);

	err = udif_query_create_existence(&query, queryid, targser, objser, 1000U, capref);

	if (err == udif_error_none)
	{
		err = udif_query_create_response(&response, &query, udif_verdict_yes, proof, sizeof(proof), respser, sigkey, 1000U, qsc_csp_generate);
	}

	enclen = sizeof(enc);

	if (err == udif_error_none)
	{
		err = udif_query_response_serialize(enc, &enclen, &response);
	}

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_query_response_decode_lengths: response serialize failed");
		res = false;
	}
	else
	{
		err = udif_query_response_deserialize(&dec, enc, enclen);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("conformance_test_query_response_decode_lengths: exact response decode rejected");
			res = false;
		}

		udif_query_response_clear(&dec);
		err = udif_query_response_deserialize(&dec, enc, enclen - 1U);

		if (err != udif_error_decode_failure)
		{
			qsc_consoleutils_print_line("conformance_test_query_response_decode_lengths: truncated response accepted");
			res = false;
		}

		udif_query_response_clear(&dec);
		err = udif_query_response_deserialize(&dec, enc, enclen + 1U);

		if (err != udif_error_decode_failure)
		{
			qsc_consoleutils_print_line("conformance_test_query_response_decode_lengths: trailing response bytes accepted");
			res = false;
		}
	}

	udif_query_response_clear(&dec);
	udif_query_response_clear(&response);
	udif_query_clear(&query);
	qsc_memutils_clear(sigkey, sizeof(sigkey));
	qsc_memutils_clear(verkey, sizeof(verkey));

	return res;
}

static bool conformance_test_message_decode_lengths(void)
{
	uint8_t payload[4U] = { 1U, 2U, 3U, 4U };
	uint8_t enc[UDIF_MESSAGE_HEADER_SIZE + sizeof(payload) + 1U] = { 0U };
	udif_message msg;
	udif_message dec;
	udif_errors err;
	size_t written;
	size_t consumed;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&msg, sizeof(udif_message));
	qsc_memutils_clear((uint8_t*)&dec, sizeof(udif_message));

	err = udif_message_init(&msg, udif_msg_error_report, payload, (uint32_t)sizeof(payload));
	written = 0U;

	if (err == udif_error_none)
	{
		err = udif_message_encode(enc, sizeof(enc), &msg, &written);
	}

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_message_decode_lengths: message encode failed");
		res = false;
	}
	else
	{
		consumed = 0U;
		err = udif_message_decode(&dec, enc, written, &consumed);

		if (err != udif_error_none || consumed != written)
		{
			qsc_consoleutils_print_line("conformance_test_message_decode_lengths: exact message decode rejected");
			res = false;
		}

		udif_message_dispose(&dec);
		err = udif_message_decode(&dec, enc, written - 1U, &consumed);

		if (err != udif_error_decode_failure)
		{
			qsc_consoleutils_print_line("conformance_test_message_decode_lengths: truncated message accepted");
			res = false;
		}

		udif_message_dispose(&dec);
		enc[written] = 0xAAU;
		err = udif_message_decode(&dec, enc, written + 1U, &consumed);

		if (err != udif_error_none || consumed != written)
		{
			qsc_consoleutils_print_line("conformance_test_message_decode_lengths: framed message with trailing transport bytes not consumed correctly");
			res = false;
		}
	}

	udif_message_dispose(&dec);
	udif_message_dispose(&msg);

	return res;
}


static bool conformance_test_role_mapping(void)
{
	const char* bname;
	const char* gname;
	bool res;

	res = true;
	bname = udif_role_to_string(udif_role_ubc);
	gname = udif_role_to_string(udif_role_ugc);

	if (bname == NULL || qsc_stringutils_compare_strings(bname, "branch", 7U) == false)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: branch role string mismatch");
		res = false;
	}
	else if (gname == NULL || qsc_stringutils_compare_strings(gname, "group", 6U) == false)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: group role string mismatch");
		res = false;
	}
	else if (udif_dispatch_is_permitted(udif_role_ubc, udif_msg_treaty_propose) == false)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: branch treaty dispatch rejected");
		res = false;
	}
	else if (udif_dispatch_is_permitted(udif_role_ugc, udif_msg_treaty_propose) == true)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: group treaty dispatch accepted");
		res = false;
	}
	else if (udif_dispatch_is_permitted(udif_role_ugc, udif_msg_object_create) == false)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: group object dispatch rejected");
		res = false;
	}
	else if (udif_dispatch_is_permitted(udif_role_ubc, udif_msg_object_create) == true)
	{
		qsc_consoleutils_print_line("conformance_test_role_mapping: branch object dispatch accepted");
		res = false;
	}

	return res;
}


static bool conformance_test_anchor_signature_encoding(void)
{
	uint8_t serialized[UDIF_ANCHOR_RECORD_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_anchor_record anchor;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&anchor, sizeof(udif_anchor_record));
	conformance_test_fill(anchor.signature, sizeof(anchor.signature), 0x10U);
	conformance_test_fill(anchor.mroot, sizeof(anchor.mroot), 0x20U);
	conformance_test_fill(anchor.regroot, sizeof(anchor.regroot), 0x30U);
	conformance_test_fill(anchor.txroot, sizeof(anchor.txroot), 0x40U);
	conformance_test_fill(anchor.childser, sizeof(anchor.childser), 0x50U);
	anchor.sequence = 0x0102030405060708ULL;
	anchor.timestamp = 0x1112131415161718ULL;
	anchor.memcount = 0x21222324UL;
	anchor.regcount = 0x31323334UL;
	anchor.txcount = 0x41424344UL;

	err = udif_anchor_serialize(serialized, sizeof(serialized), &anchor);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_anchor_signature_encoding: anchor serialize failed");
		res = false;
	}
	else
	{
		err = udif_anchor_compute_digest(digest1, &anchor);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("conformance_test_anchor_signature_encoding: anchor digest failed");
			res = false;
		}
		else
		{
			qsc_cshake256_compute(digest2, UDIF_CRYPTO_HASH_SIZE, serialized + UDIF_SIGNED_HASH_SIZE, UDIF_ANCHOR_SIGNING_SIZE,
				(const uint8_t*)UDIF_LABEL_ANCHOR, sizeof(UDIF_LABEL_ANCHOR) - 1U, NULL, 0U);

			if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("conformance_test_anchor_signature_encoding: digest does not match serialized signature-excluded body");
				res = false;
			}
		}
	}

	qsc_memutils_clear(digest1, sizeof(digest1));
	qsc_memutils_clear(digest2, sizeof(digest2));

	return res;
}

static bool conformance_test_treaty_signature_encoding(void)
{
	uint8_t serialized[UDIF_TREATY_STRUCTURE_SIZE] = { 0U };
	uint8_t digest1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t digest2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	udif_treaty treaty;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&treaty, sizeof(udif_treaty));
	conformance_test_fill(treaty.domsiga, sizeof(treaty.domsiga), 0x60U);
	conformance_test_fill(treaty.domsigb, sizeof(treaty.domsigb), 0x70U);
	conformance_test_fill(treaty.domsera, sizeof(treaty.domsera), 0x80U);
	conformance_test_fill(treaty.domserb, sizeof(treaty.domserb), 0x90U);
	conformance_test_fill(treaty.treatyid, sizeof(treaty.treatyid), 0xA0U);
	treaty.validfrom = 0x0102030405060708ULL;
	treaty.validto = 0x1112131415161718ULL;
	treaty.policy = 0x21222324UL;
	treaty.scopebitmap = 0x31323334UL;

	err = udif_treaty_serialize(serialized, sizeof(serialized), &treaty);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_treaty_signature_encoding: treaty serialize failed");
		res = false;
	}
	else
	{
		err = udif_treaty_compute_digest(digest1, &treaty);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("conformance_test_treaty_signature_encoding: treaty digest failed");
			res = false;
		}
		else
		{
			qsc_sha3_compute256(digest2, serialized + (2U * UDIF_SIGNED_HASH_SIZE), UDIF_TREATY_STRUCTURE_SIZE - (2U * UDIF_SIGNED_HASH_SIZE));

			if (qsc_memutils_are_equal(digest1, digest2, UDIF_CRYPTO_HASH_SIZE) == false)
			{
				qsc_consoleutils_print_line("conformance_test_treaty_signature_encoding: digest does not match serialized signature-excluded body");
				res = false;
			}
		}
	}

	qsc_memutils_clear(digest1, sizeof(digest1));
	qsc_memutils_clear(digest2, sizeof(digest2));

	return res;
}

static bool conformance_test_registry_leaf_encoding(void)
{
	uint8_t enc[UDIF_REGISTRY_LEAF_ENCODED_SIZE] = { 0U };
	udif_registry_leaf leaf;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&leaf, sizeof(udif_registry_leaf));
	conformance_test_fill(leaf.objdigest, sizeof(leaf.objdigest), 0x11U);
	conformance_test_fill(leaf.ownerdigest, sizeof(leaf.ownerdigest), 0x22U);
	conformance_test_fill(leaf.objserial, sizeof(leaf.objserial), 0x33U);
	leaf.flags = UDIF_REGISTRY_FLAG_ACTIVE;
	leaf.timestamp = 0x0102030405060708ULL;

	err = udif_registry_leaf_encode(enc, &leaf);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: leaf encode failed");
		res = false;
	}
	else if (qsc_memutils_are_equal(enc, leaf.objdigest, UDIF_CRYPTO_HASH_SIZE) == false)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: object digest not first");
		res = false;
	}
	else if (qsc_memutils_are_equal(enc + UDIF_CRYPTO_HASH_SIZE, leaf.ownerdigest, UDIF_CRYPTO_HASH_SIZE) == false)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: owner digest not second");
		res = false;
	}
	else if (qsc_memutils_are_equal(enc + (2U * UDIF_CRYPTO_HASH_SIZE), leaf.objserial, UDIF_OBJECT_SERIAL_SIZE) == false)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: object serial not third");
		res = false;
	}
	else if (qsc_intutils_le8to32(enc + (2U * UDIF_CRYPTO_HASH_SIZE) + UDIF_OBJECT_SERIAL_SIZE) != leaf.flags)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: flags not little-endian");
		res = false;
	}
	else if (qsc_intutils_le8to64(enc + (2U * UDIF_CRYPTO_HASH_SIZE) + UDIF_OBJECT_SERIAL_SIZE + UDIF_REGISTRY_LEAF_FLAGS_SIZE) != leaf.timestamp)
	{
		qsc_consoleutils_print_line("conformance_test_registry_leaf_encoding: timestamp not little-endian");
		res = false;
	}

	return res;
}

static bool conformance_test_entity_registry_transfer(void)
{
	udif_entity_context* ctx;
	udif_object* obj;
	udif_transfer_record* transfer;
	udif_registry_state* dst;
	udif_registry_state* src;
	uint8_t root[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t ownera[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t ownerb[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t serial[UDIF_OBJECT_SERIAL_SIZE] = { 0U };
	udif_errors err;
	bool res;

	res = true;
	ctx = (udif_entity_context*)qsc_memutils_malloc(sizeof(udif_entity_context));
	obj = (udif_object*)qsc_memutils_malloc(sizeof(udif_object));
	transfer = (udif_transfer_record*)qsc_memutils_malloc(sizeof(udif_transfer_record));

	if (ctx == NULL || obj == NULL || transfer == NULL)
	{
		qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: memory allocation failed");
		res = false;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_clear((uint8_t*)obj, sizeof(udif_object));
		qsc_memutils_clear((uint8_t*)transfer, sizeof(udif_transfer_record));
		conformance_test_fill(ownera, sizeof(ownera), 0x21U);
		conformance_test_fill(ownerb, sizeof(ownerb), 0x41U);
		conformance_test_fill(serial, sizeof(serial), 0x61U);

		src = udif_entity_registry_get_or_create(ctx, ownera, 4U);
		dst = udif_entity_registry_get_or_create(ctx, ownerb, 4U);

		if (src == NULL || dst == NULL)
		{
			qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: registry creation failed");
			res = false;
		}
		else
		{
			qsc_memutils_copy(obj->serial, serial, UDIF_OBJECT_SERIAL_SIZE);
			qsc_memutils_copy(obj->creator, ownera, UDIF_SERIAL_NUMBER_SIZE);
			qsc_memutils_copy(obj->owner, ownera, UDIF_SERIAL_NUMBER_SIZE);
			obj->updated = 100U;
			err = udif_registry_add_object(src, obj);

			if (err != udif_error_none)
			{
				qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: registry add failed");
				res = false;
			}
			else if (udif_registry_object_is_active(src, serial) == false)
			{
				qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: source object is not active");
				res = false;
			}
			else
			{
				qsc_memutils_copy(transfer->serial, serial, UDIF_OBJECT_SERIAL_SIZE);
				qsc_memutils_copy(transfer->originator, ownera, UDIF_SERIAL_NUMBER_SIZE);
				qsc_memutils_copy(transfer->owner, ownerb, UDIF_SERIAL_NUMBER_SIZE);
				transfer->timestamp = 200U;
				err = udif_registry_transfer_object(src, dst, transfer);

				if (err != udif_error_none)
				{
					qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: registry transfer failed");
					res = false;
				}
				else if (udif_registry_object_is_active(src, serial) == true)
				{
					qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: source object remained active");
					res = false;
				}
				else if (udif_registry_object_is_active(dst, serial) == false)
				{
					qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: destination object is not active");
					res = false;
				}
				else if (udif_registry_compute_root(root, dst) != udif_error_none)
				{
					qsc_consoleutils_print_line("conformance_test_entity_registry_transfer: destination root failed");
					res = false;
				}
				else
				{
					/* test passed */
				}
			}
		}

		udif_entity_registry_clear_all(ctx);
		qsc_memutils_clear((uint8_t*)ctx, sizeof(udif_entity_context));
		qsc_memutils_clear((uint8_t*)obj, sizeof(udif_object));
		qsc_memutils_clear((uint8_t*)transfer, sizeof(udif_transfer_record));
	}

	if (ctx != NULL)
	{
		qsc_memutils_alloc_free(ctx);
	}

	if (obj != NULL)
	{
		qsc_memutils_alloc_free(obj);
	}

	if (transfer != NULL)
	{
		qsc_memutils_alloc_free(transfer);
	}

	qsc_memutils_clear(root, sizeof(root));

	return res;
}

bool conformance_test_run(void)
{
	bool res;

	res = true;

	if (conformance_test_constants() == false)
	{
		res = false;
	}

	if (conformance_test_certificate_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_capability_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_object_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_transfer_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_anchor_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_treaty_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_query_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_query_response_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_message_decode_lengths() == false)
	{
		res = false;
	}

	if (conformance_test_role_mapping() == false)
	{
		res = false;
	}

	if (conformance_test_anchor_signature_encoding() == false)
	{
		res = false;
	}

	if (conformance_test_treaty_signature_encoding() == false)
	{
		res = false;
	}

	if (conformance_test_registry_leaf_encoding() == false)
	{
		res = false;
	}

	if (conformance_test_entity_registry_transfer() == false)
	{
		res = false;
	}

	return res;
}
