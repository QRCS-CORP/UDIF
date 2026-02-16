#include "udif.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"

bool udif_suite_is_valid(uint8_t suiteid)
{
	return (suiteid == UDIF_SUITE_ID);
}

const char* udif_error_to_string(udif_errors error)
{
	const char* res;

	if ((size_t)error < UDIF_ERROR_STRING_DEPTH - 1U)
	{
		res = UDIF_ERROR_STRINGS[(size_t)error];
	}
	else
	{
		res = UDIF_ERROR_STRINGS[UDIF_ERROR_STRING_DEPTH - 1U];
	}

	return res;
}