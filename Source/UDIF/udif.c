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

const char* udif_role_to_string(udif_roles role)
{
	static const char* const ROLE_NAMES[] =
	{
		"none",       /* udif_role_none   = 0 */
		"root",       /* udif_role_root   = 1 */
		"group",      /* udif_role_ugc    = 2 */
		"branch",     /* udif_role_ubc    = 3 */
		"server",     /* udif_role_uor    = 4 */
		"client",     /* udif_role_client = 5 */
		"auditor",    /* udif_role_audit  = 6 */
		"revoked",    /* udif_role_revoked= 7 */
		"any"         /* udif_role_any    = 8 */
	};
	static const size_t ROLE_NAME_COUNT = sizeof(ROLE_NAMES) / sizeof(ROLE_NAMES[0]);

	const char* res;

	if ((size_t)role < ROLE_NAME_COUNT)
	{
		res = ROLE_NAMES[(size_t)role];
	}
	else
	{
		res = NULL;
	}

	return res;
}
