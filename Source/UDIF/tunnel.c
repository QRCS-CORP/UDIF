#include "udif.h"
#include "tunnel.h"
#include "message.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "socketbase.h"
#include "socketflags.h"
#include "timestamp.h"
#include "qstp.h"
#include "client.h"

static uint64_t tunnel_next_ratchet_deadline(uint64_t nowsecs)
{
	uint8_t rnd[4U] = { 0U };
	uint64_t span;
	uint64_t base;
	uint32_t val;
	uint64_t res;

	span = (uint64_t)(2U * UDIF_RATCHET_JITTER_SECONDS) + 1U;
	base = nowsecs + (uint64_t)UDIF_RATCHET_INTERVAL_SECONDS - (uint64_t)UDIF_RATCHET_JITTER_SECONDS;

	if (qsc_csp_generate(rnd, sizeof(rnd)) == true)
	{
		val = qsc_intutils_le8to32(rnd);
		res = base + ((uint64_t)val % span);
	}
	else
	{
		/* fall back to center (no jitter) on RNG failure */
		res = nowsecs + (uint64_t)UDIF_RATCHET_INTERVAL_SECONDS;
	}

	qsc_memutils_secure_erase(rnd, sizeof(rnd));

	return res;
}

uint8_t udif_tunnel_record_flag(udif_message_type msgtype)
{
	uint8_t res;

	res = UDIF_TUNNEL_FLAG_DATA;

	if (msgtype == udif_msg_keepalive)
	{
		res = UDIF_TUNNEL_FLAG_KEEPALIVE;
	}
	else if (msgtype == udif_msg_anchor_push || msgtype == udif_msg_anchor_ack ||
		msgtype == udif_msg_cert_enroll_req || msgtype == udif_msg_cert_enroll_resp ||
		msgtype == udif_msg_cert_revoke || msgtype == udif_msg_cert_suspend ||
		msgtype == udif_msg_cert_resume || msgtype == udif_msg_cap_grant ||
		msgtype == udif_msg_cap_revoke || msgtype == udif_msg_treaty_propose ||
		msgtype == udif_msg_treaty_cosign || msgtype == udif_msg_treaty_revoke)
	{
		res = UDIF_TUNNEL_FLAG_CONTROL;
	}
	else
	{
		res = UDIF_TUNNEL_FLAG_DATA;
	}

	return res;
}

udif_errors udif_tunnel_record_header_serialize(uint8_t* output, size_t outlen, const udif_tunnel_record_header* header)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(header != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && header != NULL && outlen >= (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE)
	{
		output[0U] = header->flags;
		qsc_intutils_le64to8(output + 1U, header->sequence);
		qsc_intutils_le64to8(output + 9U, header->utctime);
		qsc_intutils_le64to8(output + 17U, header->epoch);
		output[25U] = header->suiteid;
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_tunnel_record_header_deserialize(udif_tunnel_record_header* header, const uint8_t* input, size_t inlen)
{
	UDIF_ASSERT(header != NULL);
	UDIF_ASSERT(input != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (header != NULL && input != NULL && inlen == (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE)
	{
		header->flags = input[0U];
		header->sequence = qsc_intutils_le8to64(input + 1U);
		header->utctime = qsc_intutils_le8to64(input + 9U);
		header->epoch = qsc_intutils_le8to64(input + 17U);
		header->suiteid = input[25U];
		err = udif_error_none;
	}

	return err;
}

udif_errors udif_tunnel_record_header_validate(const udif_tunnel* tun, const udif_tunnel_record_header* header, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(header != NULL);

	uint64_t diff;
	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL && header != NULL)
	{
		if (header->suiteid != UDIF_SUITE_ID)
		{
			err = udif_error_suite_mismatch;
		}
		else if (header->epoch != tun->epoch)
		{
			err = udif_error_epoch_mismatch;
		}
		else if (header->sequence != tun->rxsequence)
		{
			err = udif_error_invalid_sequence;
		}
		else
		{
			if (nowsecs >= header->utctime)
			{
				diff = nowsecs - header->utctime;
			}
			else
			{
				diff = header->utctime - nowsecs;
			}

			if (diff > (uint64_t)UDIF_TUNNEL_TIME_WINDOW_SECONDS)
			{
				err = udif_error_time_window;
			}
			else
			{
				err = udif_error_none;
			}
		}
	}

	return err;
}

udif_errors udif_tunnel_init(udif_tunnel* tun, qstp_connection_state* qstpcns, const uint8_t* peerserial, udif_rolepair rolepair, udif_tunnel_side side, const uint8_t* treatyid, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(qstpcns != NULL);
	UDIF_ASSERT(peerserial != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL && qstpcns != NULL && peerserial != NULL && rolepair != udif_rolepair_none)
	{
		/* treaty tunnels must carry a non-NULL treaty id */
		if (rolepair != udif_rolepair_treaty || treatyid != NULL)
		{
			qsc_memutils_clear((uint8_t*)tun, sizeof(udif_tunnel));

			qsc_memutils_copy(tun->peerserial, peerserial, UDIF_SERIAL_NUMBER_SIZE);

			if (rolepair == udif_rolepair_treaty && treatyid != NULL)
			{
				qsc_memutils_copy(tun->treatyid, treatyid, UDIF_SERIAL_NUMBER_SIZE);
			}

			tun->qstpcns = qstpcns;
			tun->txsequence = 0U;
			tun->rxsequence = 0U;
			tun->epoch = 0U;
			tun->rolepair = rolepair;
			tun->side = side;
			tun->lastrxsecs = nowsecs;
			tun->lasttxsecs = nowsecs;
			tun->keepalivedeadline = nowsecs + (uint64_t)UDIF_KEEPALIVE_INTERVAL_SECONDS;
			tun->idledeadline = nowsecs + (uint64_t)UDIF_IDLE_TEARDOWN_SECONDS;

			if (rolepair == udif_rolepair_bc_bc && side == udif_tunnel_side_client)
			{
				tun->ratchetdeadline = tunnel_next_ratchet_deadline(nowsecs);
			}
			else
			{
				tun->ratchetdeadline = 0U;
			}

			tun->closing = false;
			err = udif_error_none;
		}
	}

	return err;
}

void udif_tunnel_close(udif_tunnel* tun, bool notify)
{
	UDIF_ASSERT(tun != NULL);

	if (tun != NULL)
	{
		if (tun->closing == false)
		{
			tun->closing = true;

			if (tun->qstpcns != NULL)
			{
				qstp_connection_close(tun->qstpcns, qstp_error_none, notify);
			}

			tun->keepalivedeadline = 0U;
			tun->idledeadline = 0U;
			tun->ratchetdeadline = 0U;
		}
	}
}

udif_errors udif_tunnel_send(udif_tunnel* tun, const udif_message* msg, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(msg != NULL);

	uint8_t* plain;
	uint8_t* record;
	uint8_t* stream;
	qstp_network_packet pkt;
	qstp_errors qerr;
	size_t plainlen;
	size_t recordlen;
	size_t streamcap;
	size_t streamlen;
	size_t sent;
	size_t written;
	udif_errors err;

	err = udif_error_invalid_input;
	plain = NULL;
	record = NULL;
	stream = NULL;
	qsc_memutils_clear((uint8_t*)&pkt, sizeof(qstp_network_packet));

	if (tun != NULL && msg != NULL)
	{
		if (tun->closing == true || tun->qstpcns == NULL)
		{
			err = udif_error_invalid_state;
		}
		else if (qsc_socket_is_connected(&tun->qstpcns->target) == false)
		{
			err = udif_error_invalid_state;
		}
		else
		{
			plainlen = udif_message_encoded_size(msg);
			recordlen = plainlen + (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE;

			if (plainlen != 0U && recordlen + (size_t)QSTP_MACTAG_SIZE <= (size_t)QSTP_PACKET_MESSAGE_MAX)
			{
				plain = (uint8_t*)qsc_memutils_malloc(plainlen);
				record = (uint8_t*)qsc_memutils_malloc(recordlen);

				if (plain != NULL && record != NULL)
				{
					err = udif_message_encode(plain, plainlen, msg, &written);

					if (err == udif_error_none && written == plainlen)
					{
						udif_tunnel_record_header hdr;

						hdr.flags = udif_tunnel_record_flag(msg->msgtype);
						hdr.sequence = tun->txsequence;
						hdr.utctime = nowsecs;
						hdr.epoch = tun->epoch;
						hdr.suiteid = UDIF_SUITE_ID;

						err = udif_tunnel_record_header_serialize(record, recordlen, &hdr);

						if (err == udif_error_none)
						{
							qsc_memutils_copy(record + UDIF_TUNNEL_RECORD_HEADER_SIZE, plain, plainlen);
							streamcap = (size_t)QSTP_PACKET_HEADER_SIZE + recordlen + (size_t)QSTP_MACTAG_SIZE;
							stream = (uint8_t*)qsc_memutils_malloc(streamcap);

							if (stream != NULL)
							{
								pkt.pmessage = stream + QSTP_PACKET_HEADER_SIZE;
								qerr = qstp_encrypt_packet(tun->qstpcns, &pkt, record, recordlen);

								if (qerr == qstp_error_none)
								{
									qstp_packet_header_serialize(&pkt, stream);
									streamlen = (size_t)QSTP_PACKET_HEADER_SIZE + (size_t)pkt.msglen;

									sent = qsc_socket_send(&tun->qstpcns->target, stream, streamlen, qsc_socket_send_flag_none);

									if (sent == streamlen)
									{
										tun->txsequence += 1U;
										tun->lasttxsecs = nowsecs;
										tun->keepalivedeadline = nowsecs + (uint64_t)UDIF_KEEPALIVE_INTERVAL_SECONDS;
										err = udif_error_none;
									}
									else
									{
										err = udif_error_internal;
									}
								}
								else
								{
									err = udif_error_internal;
								}

								qsc_memutils_secure_erase(stream, streamcap);
								qsc_memutils_alloc_free(stream);
							}
							else
							{
								err = udif_error_internal;
							}
						}
					}

					qsc_memutils_secure_erase(record, recordlen);
					qsc_memutils_alloc_free(record);
					qsc_memutils_secure_erase(plain, plainlen);
					qsc_memutils_alloc_free(plain);
				}
				else
				{
					err = udif_error_internal;

					if (record != NULL)
					{
						qsc_memutils_secure_erase(record, recordlen);
						qsc_memutils_alloc_free(record);
					}

					if (plain != NULL)
					{
						qsc_memutils_secure_erase(plain, plainlen);
						qsc_memutils_alloc_free(plain);
					}
				}
			}
			else
			{
				err = udif_error_encode_failure;
			}
		}
	}

	return err;
}

udif_errors udif_tunnel_on_receive(udif_tunnel* tun, const uint8_t* input, size_t inplen, udif_message* outmsg, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);
	UDIF_ASSERT(input != NULL);
	UDIF_ASSERT(inplen != 0U);
	UDIF_ASSERT(outmsg != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL && input != NULL && inplen != 0U && outmsg != NULL)
	{
		if (tun->closing == true)
		{
			err = udif_error_invalid_state;
		}
		else if (inplen <= (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE)
		{
			err = udif_error_decode_failure;
		}
		else
		{
			udif_tunnel_record_header hdr;

			err = udif_tunnel_record_header_deserialize(&hdr, input, (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE);

			if (err == udif_error_none)
			{
				err = udif_tunnel_record_header_validate(tun, &hdr, nowsecs);
			}

			if (err == udif_error_none)
			{
				size_t msglen;
				size_t consumed;

				msglen = inplen - (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE;
				consumed = 0U;
				err = udif_message_decode(outmsg, input + UDIF_TUNNEL_RECORD_HEADER_SIZE, msglen, &consumed);

				if (err == udif_error_none && consumed != msglen)
				{
					udif_message_dispose(outmsg);
					err = udif_error_decode_failure;
				}
			}

			if (err == udif_error_none)
			{
				if (hdr.flags != udif_tunnel_record_flag(outmsg->msgtype))
				{
					err = udif_error_invalid_request;
				}
			}

			if (err == udif_error_none)
			{
				tun->rxsequence += 1U;
				tun->lastrxsecs = nowsecs;
				tun->idledeadline = nowsecs + (uint64_t)UDIF_IDLE_TEARDOWN_SECONDS;
			}
		}
	}

	return err;
}

udif_errors udif_tunnel_send_keepalive(udif_tunnel* tun, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);

	udif_message msg = { 0 };
	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL)
	{
		err = udif_message_init(&msg, udif_msg_keepalive, NULL, 0U);

		if (err == udif_error_none)
		{
			err = udif_tunnel_send(tun, &msg, nowsecs);
			udif_message_dispose(&msg);
		}
	}

	return err;
}

udif_errors udif_tunnel_trigger_ratchet(udif_tunnel* tun, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL)
	{
		if (tun->closing == true || tun->qstpcns == NULL)
		{
			err = udif_error_invalid_state;
		}
		else if (tun->rolepair != udif_rolepair_bc_bc || tun->side != udif_tunnel_side_client)
		{
			err = udif_error_invalid_request;
		}
		else
		{
			if (qstp_send_symmetric_ratchet_request(tun->qstpcns) == true)
			{
				tun->epoch += 1U;
				tun->txsequence = 0U;
				tun->rxsequence = 0U;
				tun->ratchetdeadline = tunnel_next_ratchet_deadline(nowsecs);
				tun->lasttxsecs = nowsecs;
				err = udif_error_none;
			}
			else
			{
				err = udif_error_internal;
			}
		}
	}

	return err;
}

udif_errors udif_tunnel_tick(udif_tunnel* tun, uint64_t nowsecs)
{
	UDIF_ASSERT(tun != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (tun != NULL)
	{
		if (tun->closing == true || tun->qstpcns == NULL)
		{
			err = udif_error_invalid_state;
		}
		else
		{
			err = udif_error_none;

			/* 1. send a keepalive if the TX-idle interval has elapsed */
			if (nowsecs >= tun->keepalivedeadline)
			{
				err = udif_tunnel_send_keepalive(tun, nowsecs);

				if (err != udif_error_none)
				{
					tun->closing = true;
				}
			}

			/* 2. tear down if the peer has been silent too long */
			if (err == udif_error_none && nowsecs >= tun->idledeadline)
			{
				tun->closing = true;
				err = udif_error_invalid_state;
			}

			/* 3. trigger QSTP rekeying on BC<->BC trunks (client side only) */
			if (err == udif_error_none && tun->rolepair == udif_rolepair_bc_bc
				&& tun->side == udif_tunnel_side_client && tun->ratchetdeadline != 0U
				&& nowsecs >= tun->ratchetdeadline)
			{
				if (qstp_send_symmetric_ratchet_request(tun->qstpcns) == true)
				{
					tun->epoch += 1U;
					tun->txsequence = 0U;
					tun->rxsequence = 0U;
					tun->ratchetdeadline = tunnel_next_ratchet_deadline(nowsecs);
					tun->lasttxsecs = nowsecs;
					tun->keepalivedeadline = nowsecs + (uint64_t)UDIF_KEEPALIVE_INTERVAL_SECONDS;
				}
				else
				{
					tun->closing = true;
					err = udif_error_internal;
				}
			}
		}
	}

	return err;
}

bool udif_tunnel_is_open(const udif_tunnel* tun, uint64_t nowsecs)
{
	bool res;

	res = false;

	if (tun != NULL)
	{
		if (tun->qstpcns != NULL && tun->closing == false && nowsecs < tun->idledeadline)
		{
			res = true;
		}
	}

	return res;
}
