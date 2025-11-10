#include "udif.h"
#include "certificate.h"
#include "resources.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

void udif_connection_close(qsc_socket* rsock, udif_network_errors err, bool notify)
{
	UDIF_ASSERT(rsock != NULL);

	if (rsock != NULL)
	{
		if (qsc_socket_is_connected(rsock) == true)
		{
			if (notify == true)
			{
				udif_network_packet resp = { 0 };
				uint8_t spct[UDIF_PACKET_HEADER_SIZE + sizeof(uint8_t)] = { 0U };

				/* send a disconnect message */
				resp.flag = udif_network_flag_tunnel_connection_terminate;
				resp.sequence = UDIF_PACKET_SEQUENCE_TERMINATOR;
				resp.msglen = 1U;
				udif_packet_header_serialize(&resp, spct);

				spct[UDIF_PACKET_HEADER_SIZE] = (uint8_t)err;

				qsc_socket_send(rsock, spct, sizeof(spct), qsc_socket_send_flag_none);
			}

			/* close the socket */
			qsc_socket_shut_down(rsock, qsc_socket_shut_down_flag_both);
			qsc_socket_close_socket(rsock);
		}
	}
}

udif_protocol_errors udif_decrypt_packet(udif_connection_state* pcns, uint8_t* message, size_t* msglen, const udif_network_packet* packetin)
{
	UDIF_ASSERT(pcns != NULL);
	UDIF_ASSERT(packetin != NULL);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(msglen != NULL);

	udif_protocol_errors merr;

	if (pcns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		*msglen = 0U;
		pcns->rxseq += 1U;

		if (udif_packet_time_valid(packetin) == true)
		{
			if (packetin->sequence == pcns->rxseq)
			{
				if (pcns->exflag == udif_network_flag_tunnel_session_established)
				{
					uint8_t hdr[UDIF_PACKET_HEADER_SIZE] = { 0U };

					/* serialize the header and add it to the ciphers associated data */
					udif_packet_header_serialize(packetin, hdr);
					udif_cipher_set_associated(&pcns->rxcpr, hdr, UDIF_PACKET_HEADER_SIZE);
					*msglen = packetin->msglen - UDIF_CRYPTO_SYMMETRIC_MAC_SIZE;

					/* authenticate then decrypt the data */
					if (udif_cipher_transform(&pcns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						merr = udif_protocol_error_none;
					}
					else
					{
						*msglen = 0U;
						merr = udif_protocol_error_authentication_failure;
					}
				}
				else
				{
					merr = udif_protocol_error_packet_header_invalid;
				}
			}
			else
			{
				merr = udif_protocol_error_packet_unsequenced;
			}
		}
		else
		{
			merr = udif_protocol_error_message_time_invalid;
		}
	}
	else
	{
		merr = udif_protocol_error_invalid_request;
	}

	return merr;
}

udif_protocol_errors udif_encrypt_packet(udif_connection_state* pcns, udif_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	UDIF_ASSERT(pcns != NULL);
	UDIF_ASSERT(message != NULL);
	UDIF_ASSERT(packetout != NULL);

	udif_protocol_errors merr;

	if (pcns != NULL && message != NULL && packetout != NULL)
	{
		if (pcns->exflag == udif_network_flag_tunnel_session_established && msglen != 0U)
		{
			uint8_t hdr[UDIF_PACKET_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			pcns->txseq += 1U;
			packetout->flag = udif_network_flag_tunnel_encrypted_message;
			packetout->msglen = (uint32_t)msglen + UDIF_CRYPTO_SYMMETRIC_MAC_SIZE;
			packetout->sequence = pcns->txseq;
			udif_packet_set_utc_time(packetout);

			/* serialize the header and add it to the ciphers associated data */
			udif_packet_header_serialize(packetout, hdr);
			udif_cipher_set_associated(&pcns->txcpr, hdr, UDIF_PACKET_HEADER_SIZE);
			/* encrypt the message */
			udif_cipher_transform(&pcns->txcpr, packetout->pmessage, message, msglen);

			merr = udif_protocol_error_none;
		}
		else
		{
			merr = udif_protocol_error_channel_down;
		}
	}
	else
	{
		merr = udif_protocol_error_invalid_request;
	}

	return merr;
}

const char* udif_network_error_to_string(udif_network_errors err)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)err < UDIF_ERROR_STRING_DEPTH)
	{
		dsc = UDIF_NETWORK_ERROR_STRINGS[(size_t)err];
	}

	return dsc;
}

const char* udif_protocol_error_to_string(udif_protocol_errors err)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)err < UDIF_ERROR_STRING_DEPTH)
	{
		dsc = UDIF_PROTOCOL_ERROR_STRINGS[(size_t)err];
	}

	return dsc;
}

void udif_packet_clear(udif_network_packet* packet)
{
	qsc_memutils_clear(packet->pmessage, packet->msglen);
	packet->flag = (uint8_t)udif_network_flag_none;
	packet->msglen = 0U;
	packet->sequence = 0U;
}

void udif_packet_error_message(udif_network_packet* packet, udif_protocol_errors error)
{
	UDIF_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = udif_network_flag_system_error_condition;
		packet->pmessage[0U] = (uint8_t)error;
		packet->msglen = 1U;
		packet->sequence = UDIF_PACKET_SEQUENCE_TERMINATOR;
	}
}

void udif_packet_header_deserialize(const uint8_t* header, udif_network_packet* packet)
{
	UDIF_ASSERT(header != NULL);
	UDIF_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = sizeof(uint8_t);
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += sizeof(uint32_t);
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += sizeof(uint64_t);
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void udif_packet_header_serialize(const udif_network_packet* packet, uint8_t* header)
{
	UDIF_ASSERT(header != NULL);
	UDIF_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = sizeof(uint8_t);
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += sizeof(uint32_t);
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void udif_packet_set_utc_time(udif_network_packet* packet)
{
	packet->utctime = qsc_timestamp_datetime_utc();
}

bool udif_packet_time_valid(const udif_network_packet* packet)
{
	uint64_t ltime;

	ltime = qsc_timestamp_datetime_utc();

	return (ltime >= packet->utctime - UDIF_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + UDIF_PACKET_TIME_THRESHOLD);
}

size_t udif_packet_to_stream(const udif_network_packet* packet, uint8_t* pstream)
{
	UDIF_ASSERT(packet != NULL);
	UDIF_ASSERT(pstream != NULL);

	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		size_t pos;

		pstream[0U] = packet->flag;
		pos = sizeof(uint8_t);
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += sizeof(uint32_t);
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += sizeof(uint64_t);
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += sizeof(uint64_t);

		if (packet->msglen <= UDIF_MESSAGE_MAX_SIZE)
		{
			qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
			res = pos + packet->msglen;
		}
	}

	return res;
}

void udif_stream_to_packet(const uint8_t* pstream, udif_network_packet* packet)
{
	UDIF_ASSERT(packet != NULL);
	UDIF_ASSERT(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		size_t pos;

		packet->flag = pstream[0U];
		pos = sizeof(uint8_t);
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += sizeof(uint32_t);
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += sizeof(uint64_t);
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += sizeof(uint64_t);

		if (packet->msglen <= UDIF_MESSAGE_MAX_SIZE)
		{
			qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
		}
	}
}

void udif_connection_state_dispose(udif_connection_state* pcns)
{
	UDIF_ASSERT(pcns != NULL);

	if (pcns != NULL)
	{
		udif_cipher_dispose(&pcns->rxcpr);
		udif_cipher_dispose(&pcns->txcpr);
		qsc_memutils_clear((uint8_t*)&pcns->target, sizeof(qsc_socket));
		pcns->rxseq = 0U;
		pcns->txseq = 0U;
		pcns->instance = 0U;
		pcns->exflag = udif_network_flag_none;
	}
}
