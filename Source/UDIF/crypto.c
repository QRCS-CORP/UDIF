#include "crypto.h"
#include "acp.h"
#include "cpuidex.h"
#include "intutils.h"
#include "memutils.h"
#include "netutils.h"
#include "scb.h"
#include "sysutils.h"

uint8_t* udif_crypto_secure_memory_allocate(size_t length)
{
	UDIF_ASSERT(length != 0U);

	uint8_t* pblk;

	pblk = NULL;

	if (length != 0U)
	{
		pblk = qsc_memutils_secure_malloc(length);

		if (pblk != NULL)
		{
			qsc_memutils_secure_erase(pblk, length);
		}
	}

	return pblk;
}

void udif_crypto_secure_memory_deallocate(uint8_t* block, size_t length)
{
	UDIF_ASSERT(block != NULL);
	UDIF_ASSERT(length != 0U);

	if (block != NULL && length != 0U)
	{
		qsc_memutils_secure_erase(block, length);
		qsc_memutils_secure_free(block, length);
		block = NULL;
	}
}

void udif_crypto_generate_application_keychain(uint8_t* seed, size_t seedlen, const char* password, size_t passlen, const char* username, size_t userlen)
{
	UDIF_ASSERT(seed != NULL);
	UDIF_ASSERT(seedlen != 0U);
	UDIF_ASSERT(password != NULL);
	UDIF_ASSERT(passlen != 0U);
	UDIF_ASSERT(username != NULL);
	UDIF_ASSERT(userlen != 0U);

	if (seed != NULL && seedlen != 0U && password != NULL && passlen != 0U && username != NULL && userlen != 0U)
	{
		uint8_t salt[QSC_SHA3_256_HASH_SIZE] = { 0 };
		uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
		qsc_scb_state scbx = { 0 };

		udif_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_cshake256_compute(phash, sizeof(phash), (const uint8_t*)password, passlen, NULL, 0U, (const uint8_t*)username, userlen);

		/* use cost based kdf to generate the stored comparison value */
		qsc_scb_initialize(&scbx, phash, sizeof(phash), salt, sizeof(salt), UDIF_CRYPTO_PHASH_CPU_COST, UDIF_CRYPTO_PHASH_MEMORY_COST);
		qsc_scb_generate(&scbx, seed, seedlen);
		qsc_scb_dispose(&scbx);
	}
}

bool udif_crypto_decrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(seed != NULL);
	UDIF_ASSERT(input != NULL);
	UDIF_ASSERT(length != 0U);

	bool res;

	res = false;

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		udif_cipher_state ctx = { 0 };

		const udif_cipher_keyparams kp = {
			.key = seed,
			.keylen = UDIF_CRYPTO_SYMMETRIC_KEY_SIZE,
			.nonce = (uint8_t*)seed + UDIF_CRYPTO_SYMMETRIC_KEY_SIZE,
			.info = NULL,
			.infolen = 0 };

		udif_cipher_initialize(&ctx, &kp, false);
		res = udif_cipher_transform(&ctx, output, input, length);
		udif_cipher_dispose(&ctx);
	}

	return res;
}

void udif_crypto_encrypt_stream(uint8_t* output, const uint8_t* seed, const uint8_t* input, size_t length)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(seed != NULL);
	UDIF_ASSERT(input != NULL);
	UDIF_ASSERT(length != 0U);

	udif_cipher_state ctx = { 0 };

	if (output != NULL && seed != NULL && input != NULL && length != 0U)
	{
		const udif_cipher_keyparams kp = {
		.key = seed,
		.keylen = UDIF_CRYPTO_SYMMETRIC_KEY_SIZE,
		.nonce = (uint8_t*)seed + UDIF_CRYPTO_SYMMETRIC_KEY_SIZE,
		.info = NULL,
		.infolen = 0U };

		udif_cipher_initialize(&ctx, &kp, true);
		udif_cipher_transform(&ctx, output, input, length);
		udif_cipher_dispose(&ctx);
	}
}

void udif_crypto_generate_application_salt(uint8_t* output, size_t outlen)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0U);

	if (output != NULL && outlen != 0U)
	{
		uint8_t buff[QSC_SYSUTILS_SYSTEM_NAME_MAX + QSC_USERNAME_SYSTEM_NAME_MAX + QSC_NETUTILS_MAC_ADDRESS_SIZE] = { 0U };
		size_t pos;

		pos = qsc_sysutils_computer_name((char*)buff);
		pos += qsc_sysutils_user_name((char*)buff + pos);

		qsc_netutils_get_mac_address(buff + pos);
		pos += QSC_NETUTILS_MAC_ADDRESS_SIZE;

		qsc_shake256_compute(output, outlen, buff, pos);
	}
}

void udif_crypto_generate_hash_code(uint8_t* output, const uint8_t* message, size_t msglen)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);

	if (output != NULL && message != NULL && msglen != 0U)
	{
		qsc_sha3_compute256(output, message, msglen);
	}
}

void udif_crypto_generate_mac_code(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0U);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != 0U);
	UDIF_ASSERT(key != NULL);
	UDIF_ASSERT(keylen != 0U);

	if (output != NULL && outlen != 0U && message != NULL && msglen != 0 && key != NULL && keylen != 0U)
	{
		qsc_kmac256_compute(output, outlen, message, msglen, key, keylen, NULL, 0U);
	}
}

void udif_crypto_hash_password(uint8_t* output, size_t outlen, const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0U);
	UDIF_ASSERT(username != NULL);
	UDIF_ASSERT(userlen != 0U);
	UDIF_ASSERT(password != NULL);
	UDIF_ASSERT(passlen != 0U);

	if (output != NULL && outlen != 0U && username != NULL && userlen != 0U && password != NULL && passlen != 0U)
	{
		uint8_t salt[UDIF_CRYPTO_SYMMETRIC_TOKEN_SIZE] = { 0U };

		udif_crypto_generate_application_salt(salt, sizeof(salt));
		qsc_kmac256_compute(output, outlen, username, userlen, password, passlen, salt, sizeof(salt));
	}
}

bool udif_crypto_password_minimum_check(const char* password, size_t passlen)
{
	UDIF_ASSERT(password != NULL);
	UDIF_ASSERT(passlen != 0U);

	bool res;
	uint8_t hsp;
	uint8_t lsp;
	uint8_t nsp;

	res = false;
	hsp = 0;
	lsp = 0;
	nsp = 0;

	if (password != NULL && passlen != 0U)
	{
		if (passlen >= UDIF_STORAGE_PASSWORD_MIN && passlen <= UDIF_STORAGE_PASSWORD_MAX)
		{
			for (size_t i = 0U; i < passlen; ++i)
			{
				if (((uint8_t)password[i] >= 65 && (uint8_t)password[i] <= 90) ||
					((uint8_t)password[i] >= 97 && (uint8_t)password[i] <= 122))
				{
					++lsp;
				}

				if (((uint8_t)password[i] >= 33 && (uint8_t)password[i] <= 46) ||
					((uint8_t)password[i] >= 58 && (uint8_t)password[i] <= 64))
				{
					++hsp;
				}

				if ((uint8_t)password[i] >= 48 && (uint8_t)password[i] <= 57)
				{
					++nsp;
				}
			}

			if ((lsp > 0 && hsp > 0 && nsp > 0) && (lsp + hsp + nsp) >= 8)
			{
				res = true;
			}
		}
	}

	return res;
}

bool udif_crypto_password_verify(const uint8_t* username, size_t userlen, const uint8_t* password, size_t passlen, const uint8_t* hash, size_t hashlen)
{
	UDIF_ASSERT(username != NULL);
	UDIF_ASSERT(userlen != 0U);
	UDIF_ASSERT(password != NULL);
	UDIF_ASSERT(passlen != 0U);
	UDIF_ASSERT(hash != NULL);
	UDIF_ASSERT(hashlen != 0U);

	bool res;

	res = false;

	if (username != NULL && userlen != 0U && password != NULL && passlen != 0 && hash != NULL && hashlen != 0U)
	{
		uint8_t tmph[UDIF_CRYPTO_SYMMETRIC_HASH_SIZE] = { 0U };

		udif_crypto_hash_password(tmph, sizeof(tmph), (const uint8_t*)username, userlen, (const uint8_t*)password, passlen);
		res = qsc_memutils_are_equal(tmph, hash, hashlen);
	}

	return res;
}
