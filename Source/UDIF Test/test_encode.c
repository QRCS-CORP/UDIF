#include "udiftestcommon.h"
#include "intutils.h"
#include "memutils.h"

bool test_encode_basic(void)
{
	uint8_t buf[8U] = { 0U };
	uint64_t val;
	bool res;

	val = 0x0102030405060708ULL;
	qsc_intutils_le64to8(buf, val);
	res = (qsc_intutils_le8to64(buf) == val);

	return res;
}

bool test_encode_tlv(void)
{
	uint8_t left[32U] = { 0U };
	uint8_t right[32U] = { 0U };
	bool res;
	size_t i;

	for (i = 0U; i < sizeof(left); ++i)
	{
		left[i] = (uint8_t)i;
	}

	qsc_memutils_copy(right, left, sizeof(left));
	res = qsc_memutils_are_equal(left, right, sizeof(left));

	return res;
}

bool test_encode_integers(void)
{
	uint8_t buf[4U] = { 0U };
	uint32_t val;
	bool res;

	val = 0x12345678UL;
	qsc_intutils_le32to8(buf, val);
	res = (qsc_intutils_le8to32(buf) == val);

	return res;
}
