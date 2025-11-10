#include "topology.h"
#include "async.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#if defined(UDIF_DEBUG_MODE)
#	include "acp.h"
#endif

void udif_topology_address_from_issuer(char* address, const char* issuer, const udif_topology_list_state* list)
{
	UDIF_ASSERT(address != NULL);
	UDIF_ASSERT(issuer != NULL);
	UDIF_ASSERT(list != NULL);

	size_t clen;

	if (address != NULL && issuer != NULL && list != NULL && list->topology != NULL && list->count > 0U)
	{
		for (size_t i = 0; i < list->count; ++i)
		{
			clen = qsc_stringutils_string_size(issuer);

			if (clen > 0U)
			{
				udif_topology_node_state node = { 0 };

				if (udif_topology_list_item(list, &node, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)node.issuer, (const uint8_t*)issuer, clen) == true)
					{
						qsc_memutils_copy(address, node.address, UDIF_CERTIFICATE_ADDRESS_SIZE);
						break;
					}
				}
			}
		}
	}
}

uint8_t* udif_topology_child_add_empty_node(udif_topology_list_state* list)
{
	UDIF_ASSERT(list != NULL);

	uint8_t* nptr;
	uint8_t* ttmp;
	size_t nctx;

	nptr = NULL;
	ttmp = NULL;

	if (list != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nctx = list->count + 1U;

		if (list->topology != NULL)
		{
			ttmp = qsc_memutils_realloc(list->topology, nctx * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ttmp != NULL)
			{
				list->topology = ttmp;
			}
		}
		else
		{
			list->topology = qsc_memutils_malloc(nctx * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
		}

		nptr = (uint8_t*)(list->topology + (list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE));

		qsc_memutils_clear(nptr, UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
		++list->count;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return nptr;
}

void udif_topology_child_add_item(udif_topology_list_state* list, const udif_topology_node_state* node)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);

	uint8_t* nptr;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		udif_topology_node_remove_duplicate(list, node->issuer);

		nptr = udif_topology_child_add_empty_node(list);
		udif_topology_node_serialize(nptr, node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool udif_topology_canonical_to_issuer_name(char* issuer, size_t isslen, const char* domain, const char* cname)
{
	UDIF_ASSERT(issuer != NULL);
	UDIF_ASSERT(isslen != 0U);
	UDIF_ASSERT(domain != NULL);
	UDIF_ASSERT(cname != NULL);

	size_t len;
	int64_t pos;
	bool res;

	const char EXT[] = ".ccert";
	const char SEP[] = "_";

	res = false;

	if (issuer != NULL && isslen != 0 && domain != NULL && cname != NULL)
	{
		len = qsc_stringutils_string_size(cname) + 
			qsc_stringutils_string_size(domain) + 
			qsc_stringutils_string_size(EXT) +
			qsc_stringutils_string_size(SEP);

		if (isslen >= len)
		{
			pos = qsc_stringutils_string_size(domain);
			qsc_stringutils_copy_substring(issuer, isslen, domain, pos);
			qsc_stringutils_concat_strings(issuer, isslen, SEP);
			qsc_stringutils_concat_strings(issuer, isslen, cname);
			qsc_stringutils_to_uppercase(issuer);
			qsc_stringutils_concat_strings(issuer, isslen, EXT);
			res = true;
		}
	}

	return res;
}

bool udif_topology_issuer_to_canonical_name(char* cname, size_t namelen, const char* issuer)
{
	UDIF_ASSERT(cname != NULL);
	UDIF_ASSERT(namelen != 0U);
	UDIF_ASSERT(issuer != NULL);

	size_t len;
	int64_t pos;
	bool res;

	res = false;

	if (cname != NULL && namelen != 0U && issuer != NULL)
	{
		len = qsc_stringutils_string_size(issuer);

		if (len < namelen)
		{
			pos = qsc_stringutils_find_string(issuer, "_");

			if (pos > 0)
			{
				qsc_stringutils_copy_substring(cname, namelen, issuer, pos);
				qsc_stringutils_concat_strings(cname, namelen, ".");
				len = qsc_stringutils_find_string(issuer, ".");

				if (len > 0U)
				{
					++pos;
					qsc_stringutils_copy_substring(cname + pos, namelen, issuer + pos, len - pos);
					qsc_stringutils_to_lowercase(cname);
					res = true;
				}
			}
		}
	}

	return res;
}

void udif_topology_child_register(udif_topology_list_state* list, const udif_child_certificate* ccert, const char* address)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(ccert != NULL);
	UDIF_ASSERT(address != NULL);

	udif_topology_node_state node = { 0 };
	uint8_t* nptr;

	nptr = NULL;

	if (list != NULL && ccert != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		udif_topology_node_remove_duplicate(list, ccert->issuer);

		qsc_memutils_copy(node.issuer, ccert->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, ccert->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, UDIF_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(&node.expiration, &ccert->expiration, UDIF_CERTIFICATE_EXPIRATION_SIZE);
		node.designation = ccert->designation;
		udif_certificate_child_hash(node.chash, ccert);

		nptr = udif_topology_child_add_empty_node(list);
		udif_topology_node_serialize(nptr, &node);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

void udif_topology_list_clone(const udif_topology_list_state* tlist, udif_topology_list_state* tcopy)
{
	for (size_t i = 0U; i < tlist->count; ++i)
	{
		udif_topology_node_state node = { 0 };
		uint8_t* nptr;

		if (udif_topology_list_item(tlist, &node, i) == true)
		{
			nptr = udif_topology_child_add_empty_node(tcopy);
			udif_topology_node_serialize(nptr, &node);
		}
	}
}

void udif_topology_list_deserialize(udif_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	if (list != NULL && input != NULL)
	{
		cnt = (size_t)qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);

		for (size_t i = 0U; i < cnt; ++i)
		{
			udif_topology_node_state node = { 0 };
			uint8_t* nptr;

			if (pos >= inplen)
			{
				break;
			}

			udif_topology_node_deserialize(&node, input + pos);
			nptr = udif_topology_child_add_empty_node(list);
			udif_topology_node_serialize(nptr, &node);

			pos += UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}
}
 
void udif_topology_list_dispose(udif_topology_list_state* list)
{
	UDIF_ASSERT(list != NULL);

	if (list != NULL)
	{
		if (list->topology != NULL)
		{
			qsc_memutils_clear(list->topology, list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
			qsc_memutils_alloc_free(list->topology);
			list->topology = NULL;
			list->count = 0U;
		}
	}
}

void udif_topology_list_initialize(udif_topology_list_state* list)
{
	UDIF_ASSERT(list != NULL);

	if (list != NULL)
	{
		list->count = 0U;
		list->topology = NULL;
	}
}

bool udif_topology_list_item(const udif_topology_list_state* list, udif_topology_node_state* node, size_t index)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && index < list->count)
	{
		const uint8_t* nptr;
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		nptr = (uint8_t*)(list->topology + (index * UDIF_NETWORK_TOPOLOGY_NODE_SIZE));
		udif_topology_node_deserialize(node, nptr);
		res = true;

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

size_t udif_topology_list_remove_duplicates(udif_topology_list_state* list)
{
	UDIF_ASSERT(list != NULL);

	uint8_t* np1;
	uint8_t* np2;
	uint8_t* ntop;
	size_t ctr;
	size_t len;
	size_t pos;
	qsc_mutex mtx;

	ctr = 0U;

	if (list != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		pos = 0U;
		len = list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
		ntop = (uint8_t*)qsc_memutils_malloc(len);

		if (ntop != NULL)
		{
			uint8_t* ptmp;

			qsc_memutils_clear(ntop, len);

			for (size_t i = 0U; i < list->count; ++i)
			{
				bool res;

				np1 = (uint8_t*)(list->topology + (i * UDIF_NETWORK_TOPOLOGY_NODE_SIZE));
				np2 = NULL;
				res = false;

				for (size_t j = i + 1U; j < list->count; ++j)
				{
					np2 = (uint8_t*)(list->topology + (j * UDIF_NETWORK_TOPOLOGY_NODE_SIZE));

					if (qsc_memutils_are_equal(np1, np2, UDIF_NETWORK_TOPOLOGY_NODE_SIZE) == true)
					{
						res = true;
						break;
					}
				}

				if (res == false)
				{
					qsc_memutils_copy(ntop + pos, np1, UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
					pos += UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
					++ctr;
				}
			}

			ptmp = qsc_memutils_realloc(list->topology, ctr * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);

			if (ptmp != NULL)
			{
				list->topology = ptmp;
				qsc_memutils_copy(list->topology, ntop, ctr * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count = (uint32_t)ctr;
			}

			qsc_memutils_alloc_free(ntop);
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return ctr;
}

size_t udif_topology_list_server_count(const udif_topology_list_state* list, udif_network_designations ntype)
{
	UDIF_ASSERT(list != NULL);

	size_t cnt;

	cnt = 0U;

	if (list != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype)
				{
					++cnt;
				}
			}
		}
	}

	return cnt;
}

size_t udif_topology_list_serialize(uint8_t* output, const udif_topology_list_state* list)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(list != NULL);

	size_t pos;

	pos = 0U;

	if (output != NULL && list != NULL)
	{
		qsc_intutils_le32to8(output, list->count);
		pos += sizeof(uint32_t);

		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state node = { 0 };

			if (udif_topology_list_item(list, &node, i) == true)
			{
				udif_topology_node_serialize(output + pos, &node);
				pos += UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
			}
		}
	}

	return pos;
}

size_t udif_topology_list_size(const udif_topology_list_state* list)
{
	UDIF_ASSERT(list != NULL);

	size_t rlen;

	rlen = 0U;

	if (list != NULL)
	{
		if (list->count > 0U)
		{
			rlen = sizeof(uint32_t) + (list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
		}
	}

	return rlen;
}

size_t udif_topology_list_update_pack(uint8_t* output, const udif_topology_list_state* list, udif_network_designations ntype)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(list != NULL);

	size_t pos;

	pos = 0U;

	if (output != NULL && list != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == ntype || ntype == udif_network_designation_all)
				{
					udif_topology_node_serialize(output + pos, &ntmp);
					pos += UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
				}
			}
		}
	}

	return pos;
}

size_t udif_topology_list_update_unpack(udif_topology_list_state* list, const uint8_t* input, size_t inplen)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	cnt = 0U;

	if (list != NULL && input != NULL && inplen >= UDIF_NETWORK_TOPOLOGY_NODE_SIZE)
	{
		pos = 0U;
		cnt = inplen / UDIF_NETWORK_TOPOLOGY_NODE_SIZE;

		for (size_t i = 0U; i < cnt; ++i)
		{
			udif_topology_node_state node = { 0 };
			uint8_t* nptr;

			udif_topology_node_deserialize(&node, input + pos);
			nptr = udif_topology_child_add_empty_node(list);
			udif_topology_node_serialize(nptr, &node);
			pos += UDIF_NETWORK_TOPOLOGY_NODE_SIZE;
		}
	}

	return cnt;
}

size_t udif_topology_ordered_server_list(udif_topology_list_state* olist, const udif_topology_list_state* tlist, udif_network_designations ntype)
{
	UDIF_ASSERT(olist != NULL);
	UDIF_ASSERT(tlist != NULL);

	size_t dcnt;
	size_t scnt;

	scnt = 0U;

	if (olist != NULL && tlist != NULL)
	{
		qsc_list_state slst = { 0 };
		udif_topology_node_state node = { 0 };

		dcnt = udif_topology_list_server_count(tlist, ntype);

		if (dcnt > 0U)
		{
			/* iterate through the topology list and add nodes of the device type */
			qsc_list_initialize(&slst, UDIF_CERTIFICATE_SERIAL_SIZE);

			for (size_t i = 0U; i < tlist->count; ++i)
			{
				udif_topology_list_item(tlist, &node, i);

				if (node.designation == ntype || ntype == udif_network_designation_all)
				{
					qsc_list_add(&slst, node.serial);
				}
			}

			if (slst.count > 0U)
			{
				uint8_t sern[UDIF_CERTIFICATE_SERIAL_SIZE] = { 0U };

				scnt = slst.count;

				/* sort the list of serial numbers */
				qsc_list_sort(&slst);

				/* fill the output topology state with nodes ordered by serial number  */
				for (size_t i = 0U; i < slst.count; ++i)
				{
					qsc_list_item(&slst, sern, i);

					if (udif_topology_node_find(tlist, &node, sern) == true)
					{
						udif_topology_child_add_item(olist, &node);
					}
				}
			}
		}
	}

	return scnt;
}

void udif_topology_node_add_alias(udif_topology_node_state* node, const char* alias)
{
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(alias != NULL);

	size_t apos;
	size_t ilen;

	if (node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= UDIF_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		ilen = qsc_stringutils_string_size(node->issuer);

		if (ilen >= UDIF_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			apos = qsc_stringutils_find_string(node->issuer, UDIF_TOPOLOGY_ALIAS_DELIMITER);

			if (apos > 0U)
			{
				qsc_memutils_clear(node->issuer + apos, ilen - apos);
				qsc_stringutils_concat_strings(node->issuer, UDIF_CERTIFICATE_ISSUER_SIZE, UDIF_TOPOLOGY_ALIAS_DELIMITER);
			}
		}

		qsc_stringutils_concat_strings(node->issuer, UDIF_CERTIFICATE_ISSUER_SIZE, alias);

		qsc_async_mutex_unlock_ex(mtx);
	}
}

bool udif_topology_nodes_are_equal(const udif_topology_node_state* a, const udif_topology_node_state* b)
{
	UDIF_ASSERT(a != NULL);
	UDIF_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (qsc_memutils_are_equal((const uint8_t*)a->address, (const uint8_t*)b->address, UDIF_CERTIFICATE_ADDRESS_SIZE) == true)
		{
			if (qsc_memutils_are_equal(a->chash, b->chash, UDIF_CERTIFICATE_HASH_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, UDIF_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, UDIF_CERTIFICATE_ISSUER_SIZE) == true)
					{
						if (a->expiration.from == b->expiration.from && a->expiration.to == b->expiration.to)
						{
							if (a->designation == b->designation)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	return res;
}

void udif_topology_node_clear(udif_topology_node_state* node)
{
	UDIF_ASSERT(node != NULL);

	if (node != NULL)
	{
		qsc_memutils_clear(node->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_clear(node->address, UDIF_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_clear(node->chash, UDIF_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_clear(node->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		node->expiration.from = 0U;
		node->expiration.to = 0U;
		node->designation = udif_network_designation_none;
	}
}

void udif_topology_node_copy(const udif_topology_node_state* source, udif_topology_node_state* destination)
{
	UDIF_ASSERT(source != NULL);
	UDIF_ASSERT(destination != NULL);

	if (source != NULL && destination != NULL)
	{
		qsc_memutils_copy(destination->issuer, source->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(destination->address, source->address, UDIF_CERTIFICATE_ADDRESS_SIZE);
		qsc_memutils_copy(destination->chash, source->chash, UDIF_CRYPTO_SYMMETRIC_HASH_SIZE);
		qsc_memutils_copy(destination->serial, source->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		destination->expiration.from = source->expiration.from;
		destination->expiration.to = source->expiration.to;
		destination->designation = source->designation;
	}
}

void udif_topology_node_deserialize(udif_topology_node_state* node, const uint8_t* input)
{
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(input != NULL);

	size_t pos;
	
	if (node != NULL && input != NULL)
	{
		qsc_memutils_copy(node->issuer, input, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos = UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(node->serial, input + pos, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(node->address, input + pos, UDIF_CERTIFICATE_ADDRESS_SIZE);
		pos += UDIF_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(node->chash, input + pos, UDIF_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += UDIF_CRYPTO_SYMMETRIC_HASH_SIZE;
		node->expiration.from = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->expiration.to = qsc_intutils_le8to64(input + pos);
		pos += sizeof(uint64_t);
		node->designation = input[pos];
	}
}

bool udif_topology_node_find(const udif_topology_list_state* list, udif_topology_node_state* node, const uint8_t* serial)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && serial != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					udif_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_find_address(const udif_topology_list_state* list, udif_topology_node_state* node, const char* address)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(address != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && address != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128((const uint8_t*)ntmp.address, (const uint8_t*)address) == true)
				{
					udif_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}
		
		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_find_alias(const udif_topology_list_state* list, udif_topology_node_state* node, const char* alias)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(alias != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL && alias != NULL && qsc_stringutils_string_size(alias) >= UDIF_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_stringutils_string_contains(ntmp.issuer, alias) == true)
				{
					udif_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_find_ads(const udif_topology_list_state* list, udif_topology_node_state* node)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);

	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == udif_network_designation_ugc)
				{
					udif_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_find_issuer(const udif_topology_list_state* list, udif_topology_node_state* node, const char* issuer)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);
	UDIF_ASSERT(issuer != NULL);

	size_t clen;
	bool res;

	res = false;

	if (list != NULL && node != NULL && issuer != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();
		clen = qsc_stringutils_string_size(issuer);

		if (clen >= UDIF_TOPOLOGY_NODE_MINIMUM_ISSUER_SIZE)
		{
			int64_t nlen;

			nlen = qsc_stringutils_find_string(issuer, UDIF_TOPOLOGY_ALIAS_DELIMITER);
			clen = (nlen > 0 && nlen < (int64_t)clen) ? (size_t)nlen : clen;

			for (size_t i = 0U; i < list->count; ++i)
			{
				udif_topology_node_state ntmp = { 0 };

				if (udif_topology_list_item(list, &ntmp, i) == true)
				{
					if (qsc_memutils_are_equal((const uint8_t*)ntmp.issuer, (const uint8_t*)issuer, clen) == true)
					{
						udif_topology_node_copy(&ntmp, node);
						res = true;
						break;
					}
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_find_root(const udif_topology_list_state* list, udif_topology_node_state* node)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(node != NULL);
	
	bool res;

	res = false;

	if (list != NULL && node != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (ntmp.designation == udif_network_designation_ura)
				{
					udif_topology_node_copy(&ntmp, node);
					res = true;
					break;
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool udif_topology_node_exists(const udif_topology_list_state* list, const uint8_t* serial)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(serial != NULL);

	bool res;

	res = false;

	if (list != NULL && serial != NULL)
	{
		res = (udif_topology_node_get_index(list, serial) != UDIF_TOPOLOGY_NODE_NOT_FOUND);
	}

	return res;
}

int32_t udif_topology_node_get_index(const udif_topology_list_state* list, const uint8_t* serial)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(serial != NULL);

	int32_t res;

	res = UDIF_TOPOLOGY_NODE_NOT_FOUND;

	if (list != NULL && serial != NULL)
	{
		for (size_t i = 0U; i < list->count; ++i)
		{
			udif_topology_node_state ntmp = { 0 };

			if (udif_topology_list_item(list, &ntmp, i) == true)
			{
				if (qsc_memutils_are_equal_128(ntmp.serial, serial) == true)
				{
					res = (int32_t)i;
					break;
				}
			}
		}
	}

	return res;
}

void udif_topology_node_remove(udif_topology_list_state* list, const uint8_t* serial)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(serial != NULL);

	int32_t lpos;
	int32_t npos;

	if (list != NULL && serial != NULL)
	{
		if (list->count > 0U)
		{
			npos = udif_topology_node_get_index(list, serial);

			if (npos >= 0)
			{
				uint8_t* ttmp;

				lpos = list->count - 1;

				if (npos != lpos && lpos > 0)
				{
					qsc_memutils_copy(list->topology + (npos * UDIF_NETWORK_TOPOLOGY_NODE_SIZE), list->topology + (lpos * UDIF_NETWORK_TOPOLOGY_NODE_SIZE), UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
				}

				qsc_memutils_clear(list->topology + (lpos * UDIF_NETWORK_TOPOLOGY_NODE_SIZE), UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
				list->count -= 1U;

				if (list->count > 0U)
				{
					/* resize the array */
					ttmp = qsc_memutils_realloc(list->topology, list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
				}
				else
				{
					/* array placeholder */
					ttmp = qsc_memutils_realloc(list->topology, sizeof(uint8_t));
				}

				if (ttmp != NULL)
				{
					list->topology = ttmp;
				}
			}
		}
	}
}

void udif_topology_node_remove_duplicate(udif_topology_list_state* list, const char* issuer)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(issuer != NULL);

	if (list != NULL && issuer != NULL)
	{
		udif_topology_node_state rnode = { 0 };

		if (udif_topology_node_find_issuer(list, &rnode, issuer) == true)
		{
			/* delete the node from the database */
			udif_topology_node_remove(list, rnode.serial);
		}
	}
}

size_t udif_topology_node_serialize(uint8_t* output, const udif_topology_node_state* node)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(node != NULL);

	size_t pos;
	
	pos = 0U;

	if (output != NULL && node != NULL)
	{
		qsc_memutils_copy(output, node->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		pos = UDIF_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, node->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		pos += UDIF_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, node->address, UDIF_CERTIFICATE_ADDRESS_SIZE);
		pos += UDIF_CERTIFICATE_ADDRESS_SIZE;
		qsc_memutils_copy(output + pos, node->chash, UDIF_CRYPTO_SYMMETRIC_HASH_SIZE);
		pos += UDIF_CRYPTO_SYMMETRIC_HASH_SIZE;
		qsc_intutils_le64to8(output + pos, node->expiration.from);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(output + pos, node->expiration.to);
		pos += sizeof(uint64_t);
		output[pos] = (uint8_t)node->designation;
		pos += sizeof(uint8_t);
	}

	return pos;
}

bool udif_topology_node_verify_ads(const udif_topology_list_state* list, const udif_child_certificate* ccert)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(ccert != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL)
	{
		udif_topology_node_state node = { 0 };

		if (udif_topology_node_find_ads(list, &node) == true)
		{
			uint8_t lhash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

			udif_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, UDIF_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool udif_topology_node_verify_issuer(const udif_topology_list_state* list, const udif_child_certificate* ccert, const char* issuer)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(ccert != NULL);
	UDIF_ASSERT(issuer != NULL);

	bool res;

	res = false;

	if (list != NULL && ccert != NULL && issuer != NULL)
	{
		udif_topology_node_state node = { 0 };

		if (udif_topology_node_find_issuer(list, &node, issuer) == true)
		{
			uint8_t lhash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

			udif_certificate_child_hash(lhash, ccert);
			res = (qsc_memutils_are_equal(lhash, node.chash, UDIF_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

bool udif_topology_node_verify_root(const udif_topology_list_state* list, const udif_root_certificate* rcert)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(rcert != NULL);

	bool res; 

	res = false;

	if (list != NULL && rcert != NULL)
	{
		udif_topology_node_state node = { 0 };

		if (udif_topology_node_find_root(list, &node) == true)
		{
			uint8_t lhash[UDIF_CERTIFICATE_HASH_SIZE] = { 0U };

			udif_certificate_root_hash(lhash, rcert);
			res = (qsc_memutils_are_equal(lhash, node.chash, UDIF_CERTIFICATE_HASH_SIZE) == true);
		}
	}

	return res;
}

void udif_topology_root_register(udif_topology_list_state* list, const udif_root_certificate* rcert, const char* address)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(rcert != NULL);
	UDIF_ASSERT(address != NULL);

	udif_topology_node_state node = { 0 };
	uint8_t* nptr;
	
	if (list != NULL && rcert != NULL && address != NULL)
	{
		qsc_memutils_copy(node.issuer, rcert->issuer, UDIF_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(node.serial, rcert->serial, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(node.address, address, UDIF_CERTIFICATE_ADDRESS_SIZE);
		udif_certificate_root_hash(node.chash, rcert);
		qsc_memutils_copy(&node.expiration, &rcert->expiration, sizeof(udif_certificate_expiration));
		node.designation = udif_network_designation_ura;

		nptr = udif_topology_child_add_empty_node(list);
		udif_topology_node_serialize(nptr, &node);
	}
}

size_t udif_topology_list_to_string(const udif_topology_list_state* list, char* output, size_t outlen)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(outlen != 0);

	size_t slen;
	size_t spos;

	spos = 0U;

	if (list != NULL && output != NULL && outlen != 0U)
	{
		if (list->count * UDIF_TOPOLOGY_NODE_ENCODED_SIZE <= outlen)
		{
			for (size_t i = 0U; i < list->count; ++i)
			{
				udif_topology_node_state ntmp = { 0 };

				udif_topology_list_item(list, &ntmp, i);
				slen = udif_topology_node_encode(&ntmp, output + spos);
				spos += slen;
			}
		}
	}

	return spos;
}

size_t udif_topology_node_encode(const udif_topology_node_state* node, char output[UDIF_TOPOLOGY_NODE_ENCODED_SIZE])
{
	size_t slen;
	size_t spos;

	spos = 0U;

	if (node != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX);
		qsc_memutils_copy(output, UDIF_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(node->issuer);
		qsc_memutils_copy(output + spos, node->issuer, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_CHILD_CERTIFICATE_ADDRESS_PREFIX, slen);
		spos += slen;

		if (qsc_ipinfo_get_address_type(node->address) == qsc_ipinfo_address_type_ipv4)
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, (uint8_t*)node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}
		else
		{
			slen = qsc_stringutils_string_size(node->address);
			qsc_memutils_copy(output + spos, node->address, slen);
			spos += slen;
			output[spos] = '\n';
			++spos;
		}

		slen = qsc_stringutils_string_size(UDIF_ROOT_CERTIFICATE_HASH_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_ROOT_CERTIFICATE_HASH_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->chash, output + spos, UDIF_CERTIFICATE_HASH_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = UDIF_CERTIFICATE_HASH_SIZE * 2U;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(node->serial, output + spos, UDIF_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(output + spos);
		slen = UDIF_CERTIFICATE_SERIAL_SIZE * 2U;
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_CHILD_CERTIFICATE_DESIGNATION_PREFIX, slen);
		spos += slen;
		spos += udif_certificate_designation_encode(output + spos, node->designation);
		output[spos] = '\n';
		++spos;

		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.from, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
		qsc_memutils_copy(output + spos, UDIF_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(node->expiration.to, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy(output + spos, dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;
	}

	return spos;
}

void udif_topology_from_file(const char* fpath, udif_topology_list_state* list)
{
	UDIF_ASSERT(fpath != NULL);
	UDIF_ASSERT(list != NULL);

	uint8_t* lbuf;
	size_t flen;

	if (fpath != NULL && list != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			flen = qsc_fileutils_get_size(fpath);

			if (flen > 0U)
			{
				lbuf = (uint8_t*)qsc_memutils_malloc(flen);

				if (lbuf != NULL)
				{
					qsc_fileutils_copy_file_to_stream(fpath, (char*)lbuf, flen);
					udif_topology_list_deserialize(list, lbuf, flen);
					qsc_memutils_alloc_free(lbuf);
				}
			}
		}
	}
}

void udif_topology_to_file(const udif_topology_list_state* list, const char* fpath)
{
	UDIF_ASSERT(list != NULL);
	UDIF_ASSERT(fpath != NULL);

	uint8_t* pbuf;
	size_t flen;

	if (list != NULL && fpath != NULL)
	{
		flen = sizeof(uint32_t) + (list->count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
		pbuf = (uint8_t*)qsc_memutils_malloc(flen);

		if (pbuf != NULL)
		{
			udif_topology_list_serialize(pbuf, list);
			qsc_fileutils_copy_stream_to_file(fpath, (const char*)pbuf, flen);
			qsc_memutils_alloc_free(pbuf);
		}
	}
}

#if defined(UDIF_DEBUG_MODE)
typedef struct topology_device_package
{
	udif_signature_keypair akp;
	udif_signature_keypair ckp;
	udif_signature_keypair dkp;
	udif_signature_keypair mkp;
	udif_signature_keypair rkp;
	udif_child_certificate acrt;
	udif_child_certificate ccrt;
	udif_child_certificate dcrt;
	udif_child_certificate mcrt;
	udif_root_certificate root;
	udif_topology_node_state ande;
	udif_topology_node_state and2;
	udif_topology_node_state and3;
	udif_topology_node_state and4;
	udif_topology_node_state and5;
	udif_topology_node_state and6;
	udif_topology_node_state and7;
	udif_topology_node_state and8;
	udif_topology_node_state cnde;
	udif_topology_node_state dnde;
	udif_topology_node_state mnde;
	udif_topology_list_state list;
} topology_device_package;

static void topology_load_child_node(udif_topology_list_state* list, udif_topology_node_state* node, const udif_child_certificate* ccert)
{
	uint8_t ipa[UDIF_CERTIFICATE_ADDRESS_SIZE] = { 192U, 168U, 1U };

	qsc_acp_generate(ipa + 3U, 1U);
	udif_topology_child_register(list, ccert, ipa);
	udif_topology_node_find(list, node, (const uint8_t*)ccert->serial);
}

static void topology_device_destroy(topology_device_package* spkg)
{
	udif_topology_list_dispose(&spkg->list);
}

static void topology_device_instantiate(topology_device_package* spkg)
{
	udif_certificate_expiration exp = { 0 };
	uint8_t cap[16] = { 0x01 };

	/* generate the root certificate */
	udif_certificate_signature_generate_keypair(&spkg->rkp);
	udif_certificate_expiration_set_days(&exp, 0U, 30U);
	udif_certificate_root_create(&spkg->root, spkg->rkp.pubkey, &exp, "XYZ/ARS-1:rds1.xyz.com");
	
	/* create the aps responder */
	udif_certificate_signature_generate_keypair(&spkg->akp);
	udif_certificate_expiration_set_days(&exp, 0U, 100U);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-1:aps1.xyz.com", udif_network_designation_ubc, cap);
	udif_certificate_root_sign(&spkg->acrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->ande, &spkg->acrt);

	/* aps copies for list test */
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-2:aps2.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and2, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-3:aps3.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and3, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-4:aps4.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and4, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-5:aps5.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and5, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-6:aps6.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and6, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-7:aps7.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and7, &spkg->acrt);
	udif_certificate_child_create(&spkg->acrt, spkg->akp.pubkey, &exp, "XYZ/APS-8:aps8.xyz.com", udif_network_designation_ugc, cap);
	topology_load_child_node(&spkg->list, &spkg->and8, &spkg->acrt);

	/* create a client */
	udif_certificate_signature_generate_keypair(&spkg->ckp);
	udif_certificate_expiration_set_days(&exp, 0U, 100U);
	udif_certificate_child_create(&spkg->ccrt, spkg->ckp.pubkey, &exp, "XYZ/Client-1:client1.xyz.com", udif_network_designation_client, cap);
	udif_certificate_root_sign(&spkg->ccrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->cnde, &spkg->ccrt);

	/* create the ads */
	udif_certificate_signature_generate_keypair(&spkg->dkp);
	udif_certificate_expiration_set_days(&exp, 0U, 100U);
	udif_certificate_child_create(&spkg->dcrt, spkg->dkp.pubkey, &exp, "XYZ/ADC-1:ads1.xyz.com", udif_network_designation_ubc, cap);
	udif_certificate_root_sign(&spkg->dcrt, &spkg->root, spkg->rkp.prikey);
	topology_load_child_node(&spkg->list, &spkg->dnde, &spkg->dcrt);
}

static bool topology_find_test(topology_device_package* spkg)
{
	udif_topology_node_state tand = { 0 };
	udif_topology_node_state tmnd = { 0 };
	bool res;

	res = false;

	if (spkg != NULL)
	{
		/* test find related functions */
		udif_topology_node_find(&spkg->list, &tand, spkg->ande.serial);

		if (udif_topology_nodes_are_equal(&tand, &spkg->ande) == true)
		{
			udif_topology_node_find_alias(&spkg->list, &tmnd, "mas1.xyz.com");

			if (udif_topology_nodes_are_equal(&tmnd, &spkg->mnde) == true)
			{
				udif_topology_node_find_issuer(&spkg->list, &tand, spkg->ande.issuer);

				if (udif_topology_nodes_are_equal(&tand, &spkg->ande) == true)
				{
					udif_topology_node_add_alias(&spkg->cnde, "client.xyz.com");

					if (qsc_stringutils_string_contains(spkg->cnde.issuer, "client.xyz.com") == true)
					{
						res = true;
					}
				}
			}
		}
	}

	return res;
}

static bool topology_serialization_test(topology_device_package* spkg)
{
	udif_topology_list_state lstc = { 0 };
	udif_topology_node_state itma;
	udif_topology_node_state itmb;
	uint8_t* lbuf;
	size_t mlen;
	bool res;
	
	res = false;

	if (spkg != NULL)
	{
		mlen = sizeof(uint32_t) + (spkg->list.count * UDIF_NETWORK_TOPOLOGY_NODE_SIZE);
		lbuf = (uint8_t*)qsc_memutils_malloc(mlen);

		if (lbuf != NULL)
		{
			udif_topology_list_serialize(lbuf, &spkg->list);
			udif_topology_list_initialize(&lstc);
			udif_topology_list_deserialize(&lstc, lbuf, mlen);
			qsc_memutils_alloc_free(lbuf);
			res = true;

			for (size_t i = 0; i < lstc.count; ++i)
			{
				if (udif_topology_list_item(&lstc, &itma, i) == true)
				{
					if (udif_topology_list_item(&spkg->list, &itmb, i) == true)
					{
						if (udif_topology_nodes_are_equal(&itma, &itmb) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			if (res == true)
			{
				udif_topology_node_state ncpy = { 0 };
				uint8_t nser[UDIF_NETWORK_TOPOLOGY_NODE_SIZE] = { 0U };

				for (size_t i = 0U; i < lstc.count; ++i)
				{
					if (udif_topology_list_item(&lstc, &itma, i) == true)
					{
						udif_topology_node_serialize(nser, &itma);
						udif_topology_node_deserialize(&ncpy, nser);

						if (udif_topology_nodes_are_equal(&itma, &ncpy) == false)
						{
							res = false;
							break;
						}
					}
				}
			}

			udif_topology_list_dispose(&lstc);
		}
	}

	return res;
}

static bool topology_sorted_list_test(topology_device_package* spkg)
{
	udif_topology_list_state olst = { 0 };
	udif_topology_node_state itma;
	udif_topology_node_state itmb;
	size_t acnt;
	size_t ncnt;
	bool res;

	/* test the count */
	acnt = udif_topology_list_server_count(&spkg->list, udif_network_designation_ubc);
	ncnt = udif_topology_ordered_server_list(&olst, &spkg->list, udif_network_designation_ubc);

	res = (acnt == ncnt);

	if (res == true)
	{
		/* test the sort */
		for (size_t i = 0U; i < olst.count - 1U; ++i)
		{
			udif_topology_list_item(&olst, &itma, i);
			udif_topology_list_item(&olst, &itmb, i + 1U);

			if (qsc_memutils_greater_than_le128(itma.serial, itmb.serial) == false)
			{
				res = false;
				break;
			}
		}

		udif_topology_list_dispose(&olst);
	}

	return res;
}

bool udif_topology_functions_test(void)
{
	topology_device_package spkg = { 0 };
	bool res;

	res = false;
	topology_device_instantiate(&spkg);

	/* test the find functions */
	if (topology_find_test(&spkg) == true)
	{
		/* test add, remove, and serialization functions */
		if (topology_serialization_test(&spkg) == true)
		{
			/* test sort and ordered list */
			if (topology_sorted_list_test(&spkg) == true)
			{
				res = true;
			}
		}
	}

	topology_device_destroy(&spkg);

	return res;
}
#endif
