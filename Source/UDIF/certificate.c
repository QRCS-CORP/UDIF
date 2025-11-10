#include "certificate.h"
#include "crypto.h"
#include "acp.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"
#if defined(UDIF_DEBUG_TESTS_RUN)
#include "consoleutils.h"
#endif

udif_configuration_sets udif_certificate_algorithm_decode(const char* name)
{
	UDIF_ASSERT(name != NULL);

	udif_configuration_sets cset;

	cset = udif_configuration_set_none;

	if (name != NULL)
	{
		if (qsc_stringutils_compare_strings("dilithium-s1_kyber-s1_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_dilithium1_kyber1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s3_kyber-s3_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_dilithium3_kyber3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s5_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_dilithium5_kyber5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("dilithium-s5_kyber-s6_rcs-512_sha3-512", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_dilithium5_kyber6_rcs512_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1f_mceliece-s1_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-1s_mceliece-s1_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3f_mceliece-s3_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-3s_mceliece-s3_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s5_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s5_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s6_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s6_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5f_mceliece-s7_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
		}
		else if (qsc_stringutils_compare_strings("sphincs-5s_mceliece-s7_rcs-256_sha3-256", name, UDIF_PROTOCOL_SET_SIZE))
		{
			cset = udif_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
		}
		else
		{
			cset = udif_configuration_set_none;
		}
	}

	return cset;
}

void udif_certificate_algorithm_encode(char* name, udif_configuration_sets conf)
{
	UDIF_ASSERT(name != NULL);

	if (name != NULL)
	{
		if (conf == udif_configuration_set_dilithium1_kyber1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "dilithium-s1_kyber-s1_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_dilithium3_kyber3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "dilithium-s3_kyber-s3_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_dilithium5_kyber5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s5_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_dilithium5_kyber6_rcs512_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "dilithium-s5_kyber-s6_rcs-512_sha3-512");
		}
		else if (conf == udif_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-1f_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-1s_mceliece-s1_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-3f_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-3s_mceliece-s3_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s5_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s6_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5f_mceliece-s7_rcs-256_sha3-256");
		}
		else if (conf == udif_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256)
		{
			qsc_stringutils_copy_string(name, UDIF_PROTOCOL_SET_SIZE, "sphincs-5s_mceliece-s7_rcs-256_sha3-256");
		}
	}
}

bool udif_certificate_algorithm_enabled(udif_configuration_sets conf)
{
	UDIF_ASSERT(conf != 0);

	return (conf == UDIF_CONFIGURATION_SET);
}

bool udif_certificate_child_are_equal(const udif_child_certificate* a, const udif_child_certificate* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version && a->designation == b->designation &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, UDIF_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, UDIF_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal(a->csig, b->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE) == true)
					{
						if (qsc_memutils_are_equal(a->rootser, b->rootser, UDIF_CERTIFICATE_SERIAL_SIZE) == true)
						{
							if (qsc_memutils_are_equal(a->capability, b->capability, UDIF_CAPABILITY_MASK_SIZE) == true)
							{
								res = qsc_memutils_are_equal(a->verkey, b->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
							}
						}
					}
				}
			}
		}
	}

	return res;
}

void udif_certificate_child_copy(udif_child_certificate* output, const udif_child_certificate* input)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(input != NULL);

	if (output != NULL && input != NULL)
	{
		qsc_memutils_copy(output->capability, input->capability, UDIF_CAPABILITY_MASK_SIZE);
		qsc_memutils_copy(output->csig, input->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE);
		qsc_memutils_copy(output->verkey, input->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_copy(output->issuer, input->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(output->serial, input->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(output->rootser, input->rootser, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(&output->expiration, &input->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(&output->designation, &input->designation, UDIF_CERTIFICATE_DESIGNATION_SIZE);
		qsc_memutils_copy(&output->algorithm, &input->algorithm, UDIF_CERTIFICATE_ALGORITHM_SIZE);
		qsc_memutils_copy(&output->version, &input->version, UDIF_CERTIFICATE_VERSION_SIZE);

	}
}

void udif_certificate_child_create(udif_child_certificate* child, const uint8_t* pubkey, const udif_certificate_expiration* expiration, 
	const char* issuer, udif_network_designations designation, const uint8_t* capability)
{
	UDIF_ASSERT(child != NULL);
	UDIF_ASSERT(pubkey != NULL);
	UDIF_ASSERT(expiration != NULL);
	UDIF_ASSERT(issuer != NULL);

	if (child != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		qsc_memutils_clear(child, UDIF_CERTIFICATE_CHILD_SIZE);
		child->algorithm = (uint8_t)UDIF_CONFIGURATION_SET;
		qsc_stringutils_copy_string(child->issuer, UDIF_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&child->expiration, expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(child->verkey, pubkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(child->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		child->designation = (uint8_t)designation;
		child->version = (uint8_t)udif_version_set_one_zero;
		qsc_memutils_copy(child->capability, capability, UDIF_CAPABILITY_MASK_SIZE);
	}
}

bool udif_certificate_child_decode(udif_child_certificate* child, const char enck[UDIF_CHILD_CERTIFICATE_STRING_SIZE])
{
	UDIF_ASSERT(child != NULL);
	UDIF_ASSERT(enck != NULL);

	bool res;

	res = false;

	if (child != NULL && enck != NULL)
	{
		char tmpvk[UDIF_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char tmpsg[UDIF_SIGNATURE_ENCODING_SIZE + ((UDIF_SIGNATURE_ENCODING_SIZE / 64U) + 1U)] = { 0 };
		const char* penc;
		size_t slen;

		penc = enck;
		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_HEADER) + qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX) + 1U;
		qsc_intutils_hex_to_bin(penc, child->serial, UDIF_CERTIFICATE_SERIAL_SIZE * 2U);
		penc += (UDIF_CERTIFICATE_SERIAL_SIZE * 2U);

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(child->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX) + 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		child->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->algorithm = udif_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_VERSION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, UDIF_ACTIVE_VERSION_STRING, slen) == true)
		{
			child->version = udif_version_set_one_zero;
		}
		else
		{
			child->version = udif_version_set_none;
		}

		penc += slen;
		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		child->designation = udif_certificate_designation_decode(penc);
		penc += slen;
		++penc;

		penc += slen;
		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX) + 1U;
		slen = UDIF_CAPABILITY_MASK_SIZE;
		qsc_memutils_copy(child->capability, penc, slen);
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		slen = qsc_stringutils_find_string(penc, "\n");
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX) + 1U;
		slen = sizeof(tmpsg);
		qsc_stringutils_remove_line_breaks(tmpsg, sizeof(tmpsg), penc, slen);
		res = qsc_encoding_base64_decode(child->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE, tmpsg, UDIF_SIGNATURE_ENCODING_SIZE);
		penc += slen;

		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, UDIF_CHILD_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(child->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, UDIF_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void udif_certificate_child_deserialize(udif_child_certificate* child, const uint8_t* input)
{
	UDIF_ASSERT(child != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;

	if (child != NULL && input != NULL)
	{
		qsc_memutils_copy(child->csig, input, UDIF_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = UDIF_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(child->verkey, input + pos, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(child->issuer, input + pos, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(child->serial, input + pos, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(child->rootser, input + pos, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&child->expiration, input + pos, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		pos += UDIF_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&child->designation, input + pos, UDIF_CERTIFICATE_DESIGNATION_SIZE);
		pos += UDIF_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(&child->algorithm, input + pos, UDIF_CERTIFICATE_ALGORITHM_SIZE);
		pos += UDIF_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(&child->version, input + pos, UDIF_CERTIFICATE_VERSION_SIZE);
		pos += UDIF_CERTIFICATE_VERSION_SIZE;
		qsc_memutils_copy(&child->capability, input + pos, UDIF_CAPABILITY_MASK_SIZE);
	}
}

size_t udif_certificate_child_encode(char enck[UDIF_CHILD_CERTIFICATE_STRING_SIZE], const udif_child_certificate* child)
{
	UDIF_ASSERT(enck != NULL);
	UDIF_ASSERT(child != NULL);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && child != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[UDIF_CERTIFICATE_SERIAL_SIZE * 2U] = { 0 };
		char scap[(UDIF_CAPABILITY_MASK_SIZE * 2U) + 1U] = { 0 };
		char tmpvk[UDIF_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char tmpsg[UDIF_SIGNATURE_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, UDIF_CHILD_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(child->issuer);
		qsc_memutils_copy((enck + spos), child->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->serial, hexid, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(child->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), UDIF_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;

		if (child->version == udif_version_set_one_zero)
		{
			slen = qsc_stringutils_string_size(UDIF_ACTIVE_VERSION_STRING);
			qsc_memutils_copy((enck + spos), UDIF_ACTIVE_VERSION_STRING, slen);
		}
		else
		{
			const char defv[] = "0x00";
			slen = qsc_stringutils_string_size(defv);
			qsc_memutils_copy((enck + spos), defv, slen);
		}

		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += udif_certificate_designation_encode((enck + spos), child->designation);
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX, slen);
		spos += slen;
		qsc_encoding_hex_encode(child->capability, sizeof(child->capability), scap, sizeof(scap));
		slen = UDIF_CAPABILITY_MASK_SIZE * 2;
		qsc_memutils_copy((enck + spos), scap, slen);
		spos += UDIF_CAPABILITY_MASK_SIZE * 2;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(child->rootser, hexid, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_ROOT_HASH_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		//size_t enclen = qsc_encoding_base64_encoded_size(sizeof(child->csig));
		slen = UDIF_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_encoding_base64_encode(tmpsg, UDIF_SIGNATURE_ENCODING_SIZE, child->csig, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), UDIF_CHILD_CERTIFICATE_STRING_SIZE - spos, UDIF_CERTIFICATE_LINE_LENGTH, tmpsg, sizeof(tmpsg));
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		size_t enclen = qsc_encoding_base64_encoded_size(slen);
		qsc_encoding_base64_encode(tmpvk, UDIF_VERIFICATION_KEY_ENCODING_SIZE, child->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), UDIF_ROOT_CERTIFICATE_STRING_SIZE - spos, UDIF_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void udif_certificate_child_erase(udif_child_certificate* child)
{
	UDIF_ASSERT(child != NULL);

	if (child != NULL)
	{
		qsc_memutils_clear(child->csig, UDIF_ASYMMETRIC_SIGNATURE_SIZE);
		qsc_memutils_clear(child->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_memutils_clear(child->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(child->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(child->rootser, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(&child->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_clear(&child->capability, UDIF_CAPABILITY_MASK_SIZE);
		child->designation = (uint8_t)udif_network_designation_none;
		child->algorithm = (uint8_t)udif_configuration_set_none;
		child->version = (uint8_t)udif_version_set_one_zero;
	}
}

bool udif_certificate_child_file_to_struct(const char* fpath, udif_child_certificate* child)
{
	UDIF_ASSERT(fpath != NULL);
	UDIF_ASSERT(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t schild[UDIF_CERTIFICATE_CHILD_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)schild, UDIF_CERTIFICATE_CHILD_SIZE) == UDIF_CERTIFICATE_CHILD_SIZE)
			{
				udif_certificate_child_deserialize(child, schild);
				res = true;
			}
		}
	}

	return res;
}

void udif_certificate_child_hash(uint8_t* output, const udif_child_certificate* child)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(child != NULL);

	if (output != NULL && child != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0U };

		qsc_sha3_initialize(&hstate);
		nbuf[0U] = child->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = child->designation;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));

		qsc_intutils_le64to8(nbuf, child->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, child->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));

		qsc_sha3_update(&hstate, qsc_keccak_rate_256, (const uint8_t*)child->capability, qsc_stringutils_string_size((const char*)child->capability));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, (const uint8_t*)child->issuer, qsc_stringutils_string_size((const char*)child->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, child->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
	}
}

bool udif_certificate_child_is_valid(const udif_child_certificate* child)
{
	UDIF_ASSERT(child != NULL);

	bool res;

	res = false;

	if (child != NULL)
	{
		if (child->algorithm == UDIF_CONFIGURATION_SET &&
			child->designation != udif_network_designation_none &&
			child->version == UDIF_ACTIVE_VERSION &&
			qsc_memutils_zeroed(child->capability, UDIF_CAPABILITY_MASK_SIZE) == false &&
			qsc_memutils_zeroed(child->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE) == false &&
			qsc_memutils_zeroed(child->rootser, UDIF_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->serial, UDIF_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(child->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= child->expiration.from && nsec <= child->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

bool udif_certificate_child_message_verify(uint8_t* message, size_t* msglen, const uint8_t* signature, size_t siglen, const udif_child_certificate* child)
{
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != NULL);
	UDIF_ASSERT(signature != NULL);
	UDIF_ASSERT(siglen != 0U);
	UDIF_ASSERT(child != NULL);

	bool res;

	res = false;
	*msglen = 0U;

	if (message != NULL && msglen != NULL && signature != NULL && siglen != 0 && child != NULL)
	{
		res = udif_signature_verify(message, msglen, signature, siglen, child->verkey);
	}

	return res;
}

void udif_certificate_child_serialize(uint8_t* output, const udif_child_certificate* child)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(child != NULL);

	size_t pos;

	if (output != NULL && child != NULL)
	{
		qsc_memutils_copy(output, child->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = UDIF_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, child->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, child->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, child->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, child->rootser, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &child->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		pos += UDIF_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &child->designation, UDIF_CERTIFICATE_DESIGNATION_SIZE);
		pos += UDIF_CERTIFICATE_DESIGNATION_SIZE;
		qsc_memutils_copy(output + pos, &child->algorithm, UDIF_CERTIFICATE_ALGORITHM_SIZE);
		pos += UDIF_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(output + pos, &child->version, UDIF_CERTIFICATE_VERSION_SIZE);
		pos += UDIF_CERTIFICATE_VERSION_SIZE;
		qsc_memutils_copy(output + pos, &child->capability, UDIF_CAPABILITY_MASK_SIZE);
	}
}

bool udif_certificate_signature_hash_verify(const uint8_t* signature, size_t siglen, const uint8_t* message, size_t msglen, const udif_child_certificate* lcert)
{
	UDIF_ASSERT(signature != NULL);
	UDIF_ASSERT(siglen != 0U);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);
	UDIF_ASSERT(lcert != NULL);

	size_t mlen;
	bool res;

	mlen = 0U;
	res = false;

	if (signature != NULL && siglen != 0 && message != NULL && msglen != 0 && lcert != NULL)
	{
		uint8_t rhash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

		res = udif_signature_verify(rhash, &mlen, signature, siglen, lcert->verkey);

		if (res == true && mlen == UDIF_CERTIFICATE_HASH_SIZE)
		{
			uint8_t lhash[UDIF_CERTIFICATE_HASH_SIZE] = { 0 };

			qsc_sha3_compute256(lhash, message, msglen);
			res = qsc_memutils_are_equal(rhash, lhash, UDIF_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool udif_certificate_child_struct_to_file(const char* fpath, const udif_child_certificate* child)
{
	UDIF_ASSERT(fpath != NULL);
	UDIF_ASSERT(child != NULL);

	bool res;

	res = false;

	if (fpath != NULL && child != NULL)
	{
		uint8_t schild[UDIF_CERTIFICATE_CHILD_SIZE] = { 0U };

		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		udif_certificate_child_serialize(schild, child);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)schild, sizeof(schild));
	}

	return res;
}

udif_network_designations udif_certificate_designation_decode(const char* sdsg)
{
	UDIF_ASSERT(sdsg != NULL);

	udif_network_designations dsg;

	dsg = udif_network_designation_none;

	if (sdsg != NULL)
	{
		if (qsc_stringutils_find_string(sdsg, UDIF_NETWORK_DESIGNATION_UGC) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = udif_network_designation_ugc;
		}
		else if (qsc_stringutils_find_string(sdsg, UDIF_NETWORK_DESIGNATION_CLIENT) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = udif_network_designation_client;
		}
		else if (qsc_stringutils_find_string(sdsg, UDIF_NETWORK_DESIGNATION_IDG) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = udif_network_designation_idg;
		}
		else if (qsc_stringutils_find_string(sdsg, UDIF_NETWORK_DESIGNATION_URA) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = udif_network_designation_ura;
		}
		else if (qsc_stringutils_find_string(sdsg, UDIF_NETWORK_DESIGNATION_ALL) != QSC_STRINGUTILS_TOKEN_NOT_FOUND)
		{
			dsg = udif_network_designation_all;
		}
		else
		{
			dsg = udif_network_designation_none;
		}
	}

	return dsg;
}

size_t udif_certificate_designation_encode(char* sdsg, udif_network_designations designation)
{
	UDIF_ASSERT(sdsg != NULL);

	if (sdsg != NULL)
	{
		if (designation == udif_network_designation_ugc)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_UGC);
		}
		else if (designation == udif_network_designation_client)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_CLIENT);
		}
		else if (designation == udif_network_designation_ubc)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_UBC);
		}
		else if (designation == udif_network_designation_idg)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_IDG);
		}
		else if (designation == udif_network_designation_ura)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_URA);
		}
		else if (designation == udif_network_designation_all)
		{
			qsc_stringutils_copy_string(sdsg, UDIF_NETWORK_DESIGNATION_SIZE, UDIF_NETWORK_DESIGNATION_ALL);
		}
	}

	return qsc_stringutils_string_size(sdsg);
}

void udif_certificate_expiration_set_days(udif_certificate_expiration* expiration, uint16_t start, uint16_t duration)
{
	UDIF_ASSERT(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + (start * 24U * 60U * 60U);
		expiration->to = expiration->from + (duration * 24U * 60U * 60U);
	}
}

void udif_certificate_expiration_set_seconds(udif_certificate_expiration* expiration, uint64_t start, uint64_t period)
{
	UDIF_ASSERT(expiration != NULL);

	if (expiration != NULL)
	{
		expiration->from = qsc_timestamp_datetime_utc() + start;
		expiration->to = expiration->from + period;
	}
}

bool udif_certificate_expiration_time_verify(const udif_certificate_expiration* expiration)
{
	UDIF_ASSERT(expiration != NULL);

	uint64_t nsec;
	bool res;

	res = false;

	if (expiration != NULL)
	{
		nsec = qsc_timestamp_datetime_utc();

		if (nsec >= expiration->from && nsec <= expiration->to)
		{
			res = true;
		}
	}

	return res;
}

size_t udif_certificate_message_hash_sign(uint8_t* signature, const uint8_t* sigkey, const uint8_t* message, size_t msglen)
{
	UDIF_ASSERT(signature != NULL);
	UDIF_ASSERT(sigkey != NULL);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);

	size_t slen;

	slen = 0;

	if (signature != NULL && sigkey != NULL && message != NULL && msglen != 0U)
	{
		uint8_t hash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

		qsc_sha3_compute256(hash, message, msglen);
		udif_signature_sign(signature, &slen, hash, sizeof(hash), sigkey, qsc_acp_generate);
	}

	return slen;
}

bool udif_certificate_root_compare(const udif_root_certificate* a, const udif_root_certificate* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && a->version == b->version &&
			a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, UDIF_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, UDIF_CERTIFICATE_SERIAL_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

void udif_certificate_root_create(udif_root_certificate* root, const uint8_t* pubkey, const udif_certificate_expiration* expiration, const char* issuer)
{
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(pubkey != NULL);
	UDIF_ASSERT(expiration != NULL);
	UDIF_ASSERT(issuer != NULL);

	if (root != NULL && pubkey != NULL && expiration != NULL && issuer != NULL)
	{
		root->algorithm = (uint8_t)UDIF_CONFIGURATION_SET;
		root->version = UDIF_ACTIVE_VERSION;
		qsc_memutils_set_value(root->capability, sizeof(root->capability), 0xFF);
		qsc_stringutils_copy_string(root->issuer, UDIF_CERTIFICATE_ISSUER_SIZE, issuer);
		qsc_memutils_copy(&root->expiration, expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_copy(root->verkey, pubkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_acp_generate(root->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
	}
}

bool udif_certificate_root_decode(udif_root_certificate* root, const char* enck)
{
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(enck != NULL);

	const char* penc;
	size_t slen;
	bool res;

	res = false;

	if (root != NULL && enck != NULL)
	{
		char tmpvk[UDIF_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		penc = enck;
		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_HEADER) + qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX) + 1U;
		slen = UDIF_CERTIFICATE_SERIAL_SIZE;

		qsc_intutils_hex_to_bin(penc, root->serial, UDIF_CERTIFICATE_SERIAL_SIZE * 2U);
		penc += (UDIF_CERTIFICATE_SERIAL_SIZE * 2U);

		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		qsc_memutils_copy(root->issuer, penc, slen);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX) + 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE;
		qsc_memutils_copy(dtm, penc, slen);
		root->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");
		root->algorithm = udif_certificate_algorithm_decode(penc);
		penc += slen;

		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_VERSION_PREFIX) + 1U;
		slen = qsc_stringutils_find_string(penc, "\n");

		if (qsc_stringutils_compare_strings(penc, UDIF_ACTIVE_VERSION_STRING, slen) == true)
		{
			root->version = udif_version_set_one_zero;
		}
		else
		{
			root->version = udif_version_set_none;
		}
		penc += slen;

		penc += slen;
		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_CAPABILITY_MASK_PREFIX) + 1U;
		slen = UDIF_CAPABILITY_MASK_SIZE;
		qsc_memutils_copy(root->capability, penc, slen);
		penc += slen;
		++penc;

		penc += qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) + 1U;
		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), penc, UDIF_ROOT_CERTIFICATE_STRING_SIZE);
		res = qsc_encoding_base64_decode(root->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE, tmpvk, UDIF_VERIFICATION_KEY_ENCODING_SIZE);
	}

	return res;
}

void udif_certificate_root_deserialize(udif_root_certificate* root, const uint8_t* input)
{
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;

	if (root != NULL && input != NULL)
	{
		qsc_memutils_copy(root->verkey, input, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(root->issuer, input + pos, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(root->serial, input + pos, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(&root->expiration, input + pos, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		pos += UDIF_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&root->algorithm, input + pos, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(&root->version, input + pos, sizeof(uint8_t));
		pos += UDIF_CERTIFICATE_VERSION_SIZE;
		qsc_memutils_copy(&root->capability, input + pos, UDIF_CAPABILITY_MASK_SIZE);
	}
}

size_t udif_certificate_root_encode(char* enck, const udif_root_certificate* root)
{
	UDIF_ASSERT(enck != NULL);
	UDIF_ASSERT(root != NULL);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && root != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hexid[UDIF_CERTIFICATE_SERIAL_SIZE * 2U] = { 0 };
		char scap[(UDIF_CAPABILITY_MASK_SIZE * 2U) + 1U] = { 0 };
		char tmpvk[UDIF_VERIFICATION_KEY_ENCODING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_HEADER);
		qsc_memutils_copy(enck, UDIF_ROOT_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(root->issuer);
		qsc_memutils_copy((enck + spos), root->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(root->serial, hexid, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hexid);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_ALGORITHM_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_CONFIG_STRING);
		qsc_memutils_copy((enck + spos), UDIF_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_VERSION_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_ACTIVE_VERSION_STRING);
		qsc_memutils_copy((enck + spos), UDIF_ACTIVE_VERSION_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_CHILD_CERTIFICATE_CAPABILITY_MASK_PREFIX, slen);
		spos += slen;
		qsc_encoding_hex_encode(root->capability, sizeof(root->capability), scap, sizeof(scap));
		slen = UDIF_CAPABILITY_MASK_SIZE * 2;
		qsc_memutils_copy((enck + spos), scap, slen);
		spos += UDIF_CAPABILITY_MASK_SIZE * 2;
		enck[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_PUBLICKEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
		slen = UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, UDIF_VERIFICATION_KEY_ENCODING_SIZE, root->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), UDIF_ROOT_CERTIFICATE_STRING_SIZE - spos, UDIF_CERTIFICATE_LINE_LENGTH, tmpvk, sizeof(tmpvk));

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_FOOTER);
		qsc_memutils_copy((enck + spos), UDIF_ROOT_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void udif_certificate_root_erase(udif_root_certificate* root)
{
	UDIF_ASSERT(root != NULL);

	if (root != NULL)
	{
		root->algorithm = udif_configuration_set_none;
		root->version = udif_version_set_none;
		qsc_memutils_clear(root->capability, UDIF_CAPABILITY_MASK_SIZE);
		qsc_memutils_clear(&root->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		qsc_memutils_clear(root->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(root->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(root->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	}
}

bool udif_certificate_root_file_to_struct(const char* fpath, udif_root_certificate* root)
{
	UDIF_ASSERT(fpath != NULL);
	UDIF_ASSERT(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL && root != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t sroot[UDIF_CERTIFICATE_ROOT_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)sroot, UDIF_CERTIFICATE_ROOT_SIZE) == UDIF_CERTIFICATE_ROOT_SIZE)
			{
				udif_certificate_root_deserialize(root, sroot);
				res = udif_certificate_root_is_valid(root);
			}
		}
	}

	return res;
}

void udif_certificate_root_hash(uint8_t* output, const udif_root_certificate* root)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(root != NULL);

	if (output != NULL && root != NULL)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t nbuf[sizeof(uint64_t)] = { 0U };

		qsc_sha3_initialize(&hstate);
		nbuf[0U] = root->algorithm;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = root->version;
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, root->expiration.from);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, root->expiration.to);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->capability, UDIF_CAPABILITY_MASK_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, (const uint8_t*)root->issuer, qsc_stringutils_string_size((const char*)root->issuer));
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&hstate, qsc_keccak_rate_256, root->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, output);
		qsc_keccak_dispose(&hstate);
	}
}

bool udif_certificate_root_is_valid(const udif_root_certificate* root)
{
	UDIF_ASSERT(root != NULL);

	bool res;

	res = false;

	if (root != NULL)
	{
		if (root->algorithm == UDIF_CONFIGURATION_SET &&
			root->version == UDIF_ACTIVE_VERSION &&
			qsc_memutils_zeroed(root->capability, UDIF_CAPABILITY_MASK_SIZE) == false &&
			qsc_memutils_zeroed(root->issuer, UDIF_CERTIFICATE_ISSUER_SIZE) == false &&
			qsc_memutils_zeroed(root->serial, UDIF_CERTIFICATE_SERIAL_SIZE) == false &&
			qsc_memutils_zeroed(root->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE) == false)
		{
			uint64_t nsec;

			nsec = qsc_timestamp_datetime_utc();

			if (nsec >= root->expiration.from && nsec <= root->expiration.to)
			{
				res = true;
			}
		}
	}

	return res;
}

void udif_certificate_root_serialize(uint8_t* output, const udif_root_certificate* root)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(root != NULL);

	size_t pos;

	if (output != NULL && root != NULL)
	{
		qsc_memutils_copy(output, root->verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, root->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos += UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, root->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, &root->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		pos += UDIF_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &root->algorithm, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(output + pos, &root->version, sizeof(uint8_t));
		pos += UDIF_CERTIFICATE_VERSION_SIZE;
		qsc_memutils_copy(output + pos, &root->capability, UDIF_CAPABILITY_MASK_SIZE);
	}
}

size_t udif_certificate_root_sign(udif_child_certificate* child, const udif_root_certificate* root, const uint8_t* rsigkey)
{
	UDIF_ASSERT(child != NULL);
	UDIF_ASSERT(root != NULL);
	UDIF_ASSERT(rsigkey != NULL);

	size_t slen;

	slen = 0U;

	if (child != NULL && root != NULL && rsigkey != NULL)
	{
		uint8_t hash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

		qsc_memutils_copy(child->rootser, root->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		udif_certificate_child_hash(hash, child);
		udif_signature_sign(child->csig, &slen, hash, sizeof(hash), rsigkey, qsc_acp_generate);
	}

	return slen;
}

bool udif_certificate_root_signature_verify(const udif_child_certificate* child, const udif_root_certificate* root)
{
	UDIF_ASSERT(child != NULL);
	UDIF_ASSERT(root != NULL);

	size_t mlen;
	bool res;

	res = false;
	mlen = 0U;

	if (child != NULL && root != NULL)
	{
		uint8_t msg[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

		res = udif_signature_verify(msg, &mlen, child->csig, UDIF_CERTIFICATE_SIGNED_HASH_SIZE, root->verkey);

		if (res == true)
		{
			uint8_t hash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

			udif_certificate_child_hash(hash, child);

			res = qsc_memutils_are_equal(msg, hash, UDIF_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool udif_certificate_root_struct_to_file(const char* fpath, const udif_root_certificate* root)
{
	UDIF_ASSERT(fpath != NULL);
	UDIF_ASSERT(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL)
	{
		uint8_t sroot[UDIF_CERTIFICATE_ROOT_SIZE] = { 0U };

		udif_certificate_root_serialize(sroot, root);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)sroot, sizeof(sroot));
	}

	return res;
}

void udif_certificate_signature_generate_keypair(udif_signature_keypair* keypair)
{
	UDIF_ASSERT(keypair != NULL);

	if (keypair != NULL)
	{
		udif_signature_generate_keypair(keypair->pubkey, keypair->prikey, qsc_acp_generate);
	}
}

size_t udif_certificate_signature_sign_message(uint8_t* signature, const uint8_t* message, size_t msglen, const uint8_t* prikey)
{
	UDIF_ASSERT(signature != NULL);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);
	UDIF_ASSERT(prikey != NULL);

	size_t slen;

	slen = 0U;

	if (signature != NULL && message != NULL && msglen != 0 && prikey != NULL)
	{
		slen = msglen + UDIF_ASYMMETRIC_SIGNATURE_SIZE;
		udif_signature_sign(signature, &slen, message, msglen, prikey, qsc_acp_generate);
	}

	return slen;
}

bool udif_certificate_signature_verify_message(const uint8_t* message, size_t msglen, const uint8_t* signature, size_t siglen, const uint8_t* pubkey)
{
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);
	UDIF_ASSERT(signature != NULL);
	UDIF_ASSERT(pubkey != NULL);

	size_t mlen;
	bool res;

	res = false;

	if (message != NULL && msglen != 0U && signature != NULL && pubkey != NULL)
	{
		uint8_t tmsg[UDIF_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		mlen = UDIF_CRYPTO_SYMMETRIC_HASH_SIZE;

		res = udif_signature_verify(tmsg, &mlen, signature, siglen, pubkey);

		if (res == true)
		{
			res = qsc_memutils_are_equal(message, tmsg, mlen);
		}
	}

	return res;
}

/** \cond */

#if defined(UDIF_DEBUG_TESTS_RUN)
static void get_encoded_sizes()
{
	udif_signature_keypair ckp = { 0 };
	udif_child_certificate child = { 0 };
	udif_signature_keypair skp = { 0 };
	udif_root_certificate root = { 0 };
	udif_certificate_expiration exp = { 0 };
	char cenc[UDIF_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };
	char renc[UDIF_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };
	char rname[UDIF_CERTIFICATE_ISSUER_SIZE] = "URA-1";
	char name[UDIF_PROTOCOL_SET_SIZE] = { 0 };
	size_t len;

	udif_certificate_signature_generate_keypair(&skp);
	udif_certificate_expiration_set_days(&exp, 0, 30);
	udif_certificate_root_create(&root, (const uint8_t*)skp.pubkey, &exp, rname);

	udif_certificate_signature_generate_keypair(&ckp);
	udif_certificate_expiration_set_days(&exp, 0, 100);
	udif_certificate_child_create(&child, (const uint8_t*)ckp.pubkey, &exp, "UBC-1", udif_network_designation_aps);
	udif_certificate_root_sign(&child, &root, skp.prikey);

	qsc_consoleutils_print_safe("parameters: ");
	qsc_consoleutils_print_line(UDIF_CONFIG_STRING);

	len = qsc_encoding_base64_encoded_size(sizeof(skp.pubkey));
	qsc_consoleutils_print_safe("pk: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = qsc_encoding_base64_encoded_size(sizeof(child.csig));
	qsc_consoleutils_print_safe("sig: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = udif_certificate_child_encode(cenc, &child);
	qsc_consoleutils_print_safe("child: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");

	len = udif_certificate_root_encode(renc, &root);
	qsc_consoleutils_print_safe("root: ");
	qsc_consoleutils_print_uint((uint32_t)len);
	qsc_consoleutils_print_line("");
}

static void certificate_child_print(const udif_child_certificate* child)
{
	UDIF_ASSERT(child != NULL);

	char cenc[UDIF_CHILD_CERTIFICATE_STRING_SIZE] = { 0 };

	udif_certificate_child_encode(cenc, child);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

static void certificate_root_print(const udif_root_certificate* root)
{
	UDIF_ASSERT(root != NULL);

	char cenc[UDIF_ROOT_CERTIFICATE_STRING_SIZE] = { 0 };

	udif_certificate_root_encode(cenc, root);
	qsc_consoleutils_print_line(cenc);
	qsc_consoleutils_print_line("");
}

bool udif_certificate_functions_test()
{
	udif_signature_keypair skp = { 0 };
	udif_root_certificate root = { 0 };
	udif_certificate_expiration exp = { 0 };
	bool res;

	qsc_consoleutils_print_line("Printing encoded sizes of certificate fields");
	get_encoded_sizes();

	udif_certificate_signature_generate_keypair(&skp);
	udif_certificate_expiration_set_days(&exp, 0, 30);
	udif_certificate_root_create(&root, skp.pubkey, &exp, "ARS-1");
	res = udif_certificate_root_is_valid(&root);

	certificate_root_print(&root);

	if (res == true)
	{
		udif_root_certificate rcpy = { 0 };
		uint8_t srt[UDIF_CERTIFICATE_ROOT_SIZE] = { 0U };
		
		udif_certificate_root_serialize(srt, &root);
		udif_certificate_root_deserialize(&rcpy, srt);
		res = udif_certificate_root_compare(&root, &rcpy);

		if (res == true)
		{
			udif_signature_keypair ckp = { 0 };
			udif_child_certificate child = { 0 };
			udif_child_certificate ccpy = { 0 };

			udif_certificate_signature_generate_keypair(&ckp);
			udif_certificate_expiration_set_days(&exp, 0, 100U);
			udif_certificate_child_create(&child, ckp.pubkey, &exp, "UGC-1", udif_network_designation_aps);
			udif_certificate_root_sign(&child, &root, skp.prikey);
			certificate_child_print(&child);
			res = udif_certificate_child_is_valid(&child);

			if (res == true)
			{
				res = udif_certificate_root_signature_verify(&child, &root);

				if (res == true)
				{
					uint8_t sct[UDIF_CERTIFICATE_CHILD_SIZE] = { 0U };

					udif_certificate_child_serialize(sct, &child);
					udif_certificate_child_deserialize(&ccpy, sct);
					res = udif_certificate_child_are_equal(&child, &ccpy);
				}
			}
		}
	}

	return res;
}

#endif

/** \endcond */
