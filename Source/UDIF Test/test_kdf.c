#include "udiftestcommon.h"
#include "udif.h"
#include "sha3.h"
#include "memutils.h"

bool test_kdf_hash(void)
{
	uint8_t output1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t output2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t input[32U] = { 0U };
	bool res;

	qsc_cshake256_compute(output1, sizeof(output1), input, sizeof(input), (const uint8_t*)UDIF_LABEL_SESS_KDF, sizeof(UDIF_LABEL_SESS_KDF) - 1U, NULL, 0U);
	qsc_cshake256_compute(output2, sizeof(output2), input, sizeof(input), (const uint8_t*)UDIF_LABEL_SESS_KDF, sizeof(UDIF_LABEL_SESS_KDF) - 1U, NULL, 0U);
	res = qsc_memutils_are_equal(output1, output2, sizeof(output1));

	return res;
}

bool test_kdf_session_keys(void)
{
	uint8_t output1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t output2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t input[32U] = { 0U };
	bool res;

	input[0U] = 1U;
	qsc_cshake256_compute(output1, sizeof(output1), input, sizeof(input), (const uint8_t*)UDIF_LABEL_SESS_KDF, sizeof(UDIF_LABEL_SESS_KDF) - 1U, NULL, 0U);
	input[0U] = 2U;
	qsc_cshake256_compute(output2, sizeof(output2), input, sizeof(input), (const uint8_t*)UDIF_LABEL_SESS_KDF, sizeof(UDIF_LABEL_SESS_KDF) - 1U, NULL, 0U);
	res = (qsc_memutils_are_equal(output1, output2, sizeof(output1)) == false);

	return res;
}

bool test_kdf_ratchet(void)
{
	uint8_t output1[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t output2[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint8_t input[32U] = { 0U };
	bool res;

	qsc_cshake256_compute(output1, sizeof(output1), input, sizeof(input), (const uint8_t*)UDIF_LABEL_RATCHET, sizeof(UDIF_LABEL_RATCHET) - 1U, NULL, 0U);
	qsc_cshake256_compute(output2, sizeof(output2), input, sizeof(input), (const uint8_t*)UDIF_LABEL_SESS_KDF, sizeof(UDIF_LABEL_SESS_KDF) - 1U, NULL, 0U);
	res = (qsc_memutils_are_equal(output1, output2, sizeof(output1)) == false);

	return res;
}
