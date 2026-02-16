/* UDIF Test Suite - Encoding Module Tests */

#include "test_common.h"
#include "memutils.h"

bool test_encode_basic(void)
{
	TEST_START("Encoding - Basic Uvarint");

	uint8_t buf[16];
	size_t written, consumed;
	uint64_t value, decoded;

	/* Test small value */
	value = 127;
	written = udif_encode_uvarint(buf, value);
	TEST_ASSERT(written == 1, "Uvarint 127 should be 1 byte");
	TEST_ASSERT(buf[0] == 127, "Uvarint 127 value incorrect");

	consumed = udif_decode_uvarint(&decoded, buf, written);
	TEST_ASSERT(consumed == written, "Uvarint consumed bytes mismatch");
	TEST_ASSERT(decoded == value, "Uvarint decode mismatch");

	/* Test large value */
	value = 0x123456789ABCDEF0ULL;
	written = udif_encode_uvarint(buf, value);
	TEST_ASSERT(written == 9, "Uvarint large value should be 9 bytes");

	consumed = udif_decode_uvarint(&decoded, buf, written);
	TEST_ASSERT(consumed == written, "Large consumed mismatch");
	TEST_ASSERT(decoded == value, "Uvarint large decode mismatch");

	TEST_PASS("Uvarint encoding/decoding");
}

bool test_encode_tlv(void)
{
	TEST_START("Encoding - TLV Basic");

	uint8_t buf[256];
	uint8_t data[32];
	const uint8_t* value_ptr;
	uint64_t tag;
	size_t written, vallen, consumed;

	/* Fill test data */
	for (int i = 0; i < 32; i++) {
		data[i] = (uint8_t)i;
	}

	/* Encode TLV */
	written = udif_encode_tlv(buf, sizeof(buf), 42, data, 32);
	TEST_ASSERT(written > 0, "TLV encoding failed");

	/* Decode TLV */
	bool result = udif_decode_tlv(&tag, &value_ptr, &vallen, buf, written, &consumed);
	TEST_ASSERT(result == true, "TLV decoding failed");
	TEST_ASSERT(tag == 42, "TLV tag mismatch");
	TEST_ASSERT(vallen == 32, "TLV value length mismatch");
	TEST_ASSERT(qsc_memutils_are_equal(value_ptr, data, 32), "TLV value mismatch");

	TEST_PASS("TLV encoding/decoding");
}

bool test_encode_integers(void)
{
	TEST_START("Encoding - Integer TLV");

	uint8_t buf[256];
	size_t written;
	uint32_t val32 = 0x12345678;
	uint64_t val64 = 0x123456789ABCDEF0ULL;
	uint32_t decoded32;
	uint64_t decoded64;

	/* Test uint32 */
	written = udif_encode_tlv_uint32(buf, sizeof(buf), 10, val32);
	TEST_ASSERT(written > 0, "uint32 TLV encoding failed");

	bool result = udif_decode_tlv_uint32(&decoded32, buf, written, 10);
	TEST_ASSERT(result == true, "uint32 TLV decoding failed");
	TEST_ASSERT(decoded32 == val32, "uint32 value mismatch");

	/* Test uint64 */
	written = udif_encode_tlv_uint64(buf, sizeof(buf), 20, val64);
	TEST_ASSERT(written > 0, "uint64 TLV encoding failed");

	result = udif_decode_tlv_uint64(&decoded64, buf, written, 20);
	TEST_ASSERT(result == true, "uint64 TLV decoding failed");
	TEST_ASSERT(decoded64 == val64, "uint64 value mismatch");

	TEST_PASS("Integer TLV encoding/decoding");
}
