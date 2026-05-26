#include "policy.h"
#include "memutils.h"

bool udif_policy_query_verb(uint8_t querytype, uint32_t* verb)
{
	UDIF_ASSERT(verb != NULL);

	bool res;

	res = false;

	if (verb != NULL)
	{
		switch (querytype)
		{
			case (uint8_t)udif_query_exist:
			{
				*verb = (uint32_t)udif_capability_query_exist;
				res = true;
				break;
			}
			case (uint8_t)udif_query_owner_binding:
			{
				*verb = (uint32_t)udif_capability_query_owner_binding;
				res = true;
				break;
			}
			case (uint8_t)udif_query_attr_bucket:
			{
				*verb = (uint32_t)udif_capability_query_attr_bucket;
				res = true;
				break;
			}
			case (uint8_t)udif_query_membership_proof:
			{
				*verb = (uint32_t)udif_capability_prove_membership;
				res = true;
				break;
			}
			default:
			{
				*verb = 0U;
				break;
			}
		}
	}

	return res;
}

bool udif_policy_certificate_allows(const udif_certificate* certificate, uint32_t verb)
{
	UDIF_ASSERT(certificate != NULL);

	bool res;

	res = false;

	if (certificate != NULL && verb < 64U)
	{
		res = ((certificate->capability & (UINT64_C(1) << verb)) != 0U);
	}

	return res;
}

udif_policy_decision udif_policy_authorize(const udif_certificate* caller, const udif_capability* capability,
	uint32_t verb, uint32_t scope, uint64_t ctime)
{
	UDIF_ASSERT(caller != NULL);
	UDIF_ASSERT(capability != NULL);

	udif_policy_decision decision;

	decision = udif_policy_deny;

	if (caller != NULL && capability != NULL)
	{
		if (caller->role != udif_role_revoked && caller->role != udif_role_none)
		{
			if (ctime >= caller->valid.from && ctime <= caller->valid.to)
			{
				if (udif_policy_certificate_allows(caller, verb) == true)
				{
					if (qsc_memutils_are_equal(capability->issuedto, caller->serial, UDIF_SERIAL_NUMBER_SIZE) == true)
					{
						if (udif_capability_grants_permission(capability, verb, scope, ctime) == true)
						{
							decision = udif_policy_permit;
						}
					}
				}
			}
		}
	}

	return decision;
}

udif_policy_decision udif_policy_authorize_query(const udif_query* query, const udif_certificate* caller, const udif_capability* capability, uint32_t scope, uint64_t ctime)
{
	UDIF_ASSERT(query != NULL);
	UDIF_ASSERT(caller != NULL);
	UDIF_ASSERT(capability != NULL);

	uint8_t digest[UDIF_CRYPTO_HASH_SIZE] = { 0U };
	uint32_t verb;
	udif_policy_decision decision;

	decision = udif_policy_deny;
	verb = 0U;

	if (query != NULL && caller != NULL && capability != NULL)
	{
		if (udif_policy_query_verb(query->querytype, &verb) == true)
		{
			if (udif_capability_compute_digest(digest, capability) == udif_error_none)
			{
				if (qsc_memutils_are_equal(query->capabilityref, digest, UDIF_CRYPTO_HASH_SIZE) == true)
				{
					decision = udif_policy_authorize(caller, capability, verb, scope, ctime);
				}
			}
		}

		qsc_memutils_clear(digest, sizeof(digest));
	}

	return decision;
}
