/* UDIF Test Suite - KDF Module Tests */

#include "test_common.h"
#include "udif.h"
#include "memutils.h"

bool test_kdf_hash(void)
{
	TEST_START("KDF - Domain-Separated Hash");

	uint8_t output1[UDIF_HASH_SIZE];
	uint8_t output2[UDIF_HASH_SIZE];
	uint8_t input[32];

	qsc_memutils_clear(input, sizeof(input));

	udif_kdf_hash(output1, UDIF_HASH_SIZE, "TEST:LABEL", input, sizeof(input));
	TEST_ASSERT(output1[0] != 0 || output1[31] != 0, "Hash output is all zeros");

	udif_kdf_hash(output2, UDIF_HASH_SIZE, "TEST:LABEL", input, sizeof(input));
	TEST_ASSERT(qsc_memutils_are_equal(output1, output2, UDIF_HASH_SIZE), 
		"Hash not deterministic");

	udif_kdf_hash(output2, UDIF_HASH_SIZE, "TEST:DIFFERENT", input, sizeof(input));
	TEST_ASSERT(!qsc_memutils_are_equal(output1, output2, UDIF_HASH_SIZE),
		"Different labels produce same output");

	TEST_PASS("KDF hash");
}

bool test_kdf_session_keys(void)
{
	TEST_START("KDF - Session Key Derivation");

	uint8_t tx_key[UDIF_CRYPTO_KEY_SIZE];
	uint8_t tx_nonce[UDIF_SYMMETRIC_NONCE_SIZE];
	uint8_t rx_key[UDIF_CRYPTO_KEY_SIZE];
	uint8_t rx_nonce[UDIF_SYMMETRIC_NONCE_SIZE];
	uint8_t ratchet_state[UDIF_HASH_SIZE];
	uint8_t ikm[64];
	uint8_t transcript[128];

	for (int i = 0; i < 64; i++) ikm[i] = (uint8_t)i;
	for (int i = 0; i < 128; i++) transcript[i] = (uint8_t)(i ^ 0xAA);

	udif_kdf_session_keys(tx_key, tx_nonce, rx_key, rx_nonce, ratchet_state,
		ikm, sizeof(ikm), transcript, sizeof(transcript), true);

	TEST_ASSERT(tx_key[0] != 0, "TX key is zero");
	TEST_ASSERT(!qsc_memutils_are_equal(tx_key, rx_key, UDIF_CRYPTO_KEY_SIZE),
		"TX and RX keys identical");

	TEST_PASS("Session keys derived");
}

bool test_kdf_ratchet(void)
{
	TEST_START("KDF - Ratchet");

	uint8_t tx_key[UDIF_CRYPTO_KEY_SIZE];
	uint8_t tx_nonce[UDIF_SYMMETRIC_NONCE_SIZE];
	uint8_t rx_key[UDIF_CRYPTO_KEY_SIZE];
	uint8_t rx_nonce[UDIF_SYMMETRIC_NONCE_SIZE];
	uint8_t new_state[UDIF_HASH_SIZE];
	uint8_t old_state[UDIF_HASH_SIZE];
	uint8_t kem_secret[UDIF_KEM_SECRET_SIZE];
	uint8_t session_id[UDIF_HASH_SIZE];

	for (int i = 0; i < UDIF_HASH_SIZE; i++) {
		old_state[i] = (uint8_t)i;
		session_id[i] = (uint8_t)(i ^ 0xFF);
	}
	for (int i = 0; i < UDIF_KEM_SECRET_SIZE; i++) {
		kem_secret[i] = (uint8_t)(i * 2);
	}

	udif_kdf_ratchet(tx_key, tx_nonce, rx_key, rx_nonce, new_state,
		old_state, kem_secret, UDIF_KEM_SECRET_SIZE,
		session_id, UDIF_HASH_SIZE, 1, true);

	TEST_ASSERT(!qsc_memutils_are_equal(new_state, old_state, UDIF_HASH_SIZE),
		"Ratchet state unchanged");

	TEST_PASS("Ratchet derivation");
}
