#include "udiftestcommon.h"
#include "tunnel.h"
#include "memutils.h"

bool test_transport_handshake(void)
{
	udif_tunnel_record_header hdr;
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE] = { 0U };
	bool res;

	qsc_memutils_clear((uint8_t*)&hdr, sizeof(udif_tunnel_record_header));
	hdr.flags = UDIF_TUNNEL_FLAG_CONTROL;
	hdr.sequence = 0U;
	hdr.utctime = 1U;
	hdr.epoch = 0U;
	hdr.suiteid = UDIF_SUITE_ID;
	res = (udif_tunnel_record_header_serialize(enc, sizeof(enc), &hdr) == udif_error_none);

	return res;
}

bool test_transport_encrypt_decode_rypt(void)
{
	udif_tunnel tun;
	udif_tunnel_record_header hdr;
	bool res;

	qsc_memutils_clear((uint8_t*)&tun, sizeof(udif_tunnel));
	qsc_memutils_clear((uint8_t*)&hdr, sizeof(udif_tunnel_record_header));
	hdr.flags = UDIF_TUNNEL_FLAG_DATA;
	hdr.sequence = 0U;
	hdr.utctime = 1000U;
	hdr.epoch = 0U;
	hdr.suiteid = UDIF_SUITE_ID;
	res = (udif_tunnel_record_header_validate(&tun, &hdr, 1000U) == udif_error_none);

	return res;
}

bool test_transport_ratchet(void)
{
	udif_tunnel tun;
	udif_tunnel_record_header hdr;
	bool res;

	qsc_memutils_clear((uint8_t*)&tun, sizeof(udif_tunnel));
	qsc_memutils_clear((uint8_t*)&hdr, sizeof(udif_tunnel_record_header));
	tun.epoch = 1U;
	hdr.flags = UDIF_TUNNEL_FLAG_CONTROL;
	hdr.sequence = 0U;
	hdr.utctime = 1000U;
	hdr.epoch = 0U;
	hdr.suiteid = UDIF_SUITE_ID;
	res = (udif_tunnel_record_header_validate(&tun, &hdr, 1000U) == udif_error_epoch_mismatch);

	return res;
}
