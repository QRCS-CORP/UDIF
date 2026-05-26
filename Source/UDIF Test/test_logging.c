#include "udiftestcommon.h"
#include "anchor.h"
#include "memutils.h"

bool test_logging_initialize(void)
{
	udif_anchor_record anchor;
	bool res;

	qsc_memutils_clear((uint8_t*)&anchor, sizeof(udif_anchor_record));
	anchor.sequence = 0U;
	res = udif_anchor_validate_sequence(&anchor, 0U);

	return res;
}

bool test_logging_append(void)
{
	udif_anchor_record anchor;
	bool res;

	qsc_memutils_clear((uint8_t*)&anchor, sizeof(udif_anchor_record));
	anchor.sequence = 1U;
	res = udif_anchor_validate_sequence(&anchor, 1U);

	return res;
}

bool test_logging_merkle_proof(void)
{
	udif_anchor_record prev;
	udif_anchor_record next;
	bool res;

	qsc_memutils_clear((uint8_t*)&prev, sizeof(udif_anchor_record));
	qsc_memutils_clear((uint8_t*)&next, sizeof(udif_anchor_record));
	prev.sequence = 0U;
	next.sequence = 1U;
	res = udif_anchor_validate_sequence(&next, prev.sequence + 1U);

	return res;
}
