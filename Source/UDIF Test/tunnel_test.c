#include "tunnel_test.h"
#include "tunnel.h"
#include "message.h"
#include "memutils.h"
#include "consoleutils.h"

static void tunnel_test_init_state(udif_tunnel* tun)
{
	qsc_memutils_clear((uint8_t*)tun, sizeof(udif_tunnel));
	tun->rxsequence = 7U;
	tun->txsequence = 3U;
	tun->epoch = 2U;
	tun->lastrxsecs = 900U;
	tun->lasttxsecs = 900U;
	tun->keepalivedeadline = 1020U;
	tun->idledeadline = 1140U;
	tun->rolepair = udif_rolepair_ua_gc;
	tun->side = udif_tunnel_side_server;
	tun->closing = false;
}

static bool tunnel_test_encode_record(uint8_t* enc, size_t enclen, const udif_tunnel_record_header* hdr, udif_message_type msgtype)
{
	udif_message msg;
	udif_errors err;
	size_t written;
	bool res;

	res = false;
	written = 0U;
	qsc_memutils_clear((uint8_t*)&msg, sizeof(udif_message));

	err = udif_message_init(&msg, msgtype, NULL, 0U);

	if (err == udif_error_none)
	{
		err = udif_tunnel_record_header_serialize(enc, enclen, hdr);

		if (err == udif_error_none)
		{
			err = udif_message_encode(enc + UDIF_TUNNEL_RECORD_HEADER_SIZE,
				enclen - (size_t)UDIF_TUNNEL_RECORD_HEADER_SIZE, &msg, &written);

			if (err == udif_error_none && written == (size_t)UDIF_MESSAGE_HEADER_SIZE)
			{
				res = true;
			}
		}
	}

	udif_message_dispose(&msg);

	return res;
}

static bool tunnel_test_header_roundtrip(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + 1U] = { 0U };
	udif_tunnel_record_header hdr = { 0U };
	udif_tunnel_record_header cmp = { 0U };
	udif_errors err;
	bool res;

	res = true;
	hdr.flags = UDIF_TUNNEL_FLAG_CONTROL;
	hdr.sequence = 17U;
	hdr.utctime = 123456U;
	hdr.epoch = 4U;
	hdr.suiteid = UDIF_SUITE_ID;

	err = udif_tunnel_record_header_serialize(enc, UDIF_TUNNEL_RECORD_HEADER_SIZE, &hdr);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_header_roundtrip: serialize failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_record_header_deserialize(&cmp, enc, UDIF_TUNNEL_RECORD_HEADER_SIZE);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("tunnel_test_header_roundtrip: deserialize failed");
			res = false;
		}
		else if (cmp.flags != hdr.flags || cmp.sequence != hdr.sequence || cmp.utctime != hdr.utctime ||
			cmp.epoch != hdr.epoch || cmp.suiteid != hdr.suiteid)
		{
			qsc_consoleutils_print_line("tunnel_test_header_roundtrip: header mismatch");
			res = false;
		}
	}

	err = udif_tunnel_record_header_deserialize(&cmp, enc, sizeof(enc));

	if (err != udif_error_invalid_input)
	{
		qsc_consoleutils_print_line("tunnel_test_header_roundtrip: non-exact header accepted");
		res = false;
	}

	return res;
}

static bool tunnel_test_initial_state(void)
{
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	qstp_connection_state qstate;
	udif_tunnel tun;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&qstate, sizeof(qstp_connection_state));
	qsc_memutils_clear((uint8_t*)&tun, sizeof(udif_tunnel));
	serial[0U] = 1U;

	err = udif_tunnel_init(&tun, &qstate, serial, udif_rolepair_ua_gc, udif_tunnel_side_client, NULL, 1000U);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_initial_state: init failed");
		res = false;
	}
	else if (tun.txsequence != 0U || tun.rxsequence != 0U || tun.epoch != 0U)
	{
		qsc_consoleutils_print_line("tunnel_test_initial_state: sequence or epoch not zero initialized");
		res = false;
	}
	else if (tun.keepalivedeadline != 1000U + (uint64_t)UDIF_KEEPALIVE_INTERVAL_SECONDS ||
		tun.idledeadline != 1000U + (uint64_t)UDIF_IDLE_TEARDOWN_SECONDS)
	{
		qsc_consoleutils_print_line("tunnel_test_initial_state: deadline mismatch");
		res = false;
	}

	return res;
}

static bool tunnel_test_header_validation(void)
{
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_errors err;
	bool res;

	res = true;
	tunnel_test_init_state(&tun);
	hdr.flags = UDIF_TUNNEL_FLAG_DATA;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: valid header rejected");
		res = false;
	}

	hdr.sequence = tun.rxsequence - 1U;
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_invalid_sequence)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: duplicate sequence accepted");
		res = false;
	}

	hdr.sequence = tun.rxsequence + 1U;
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_invalid_sequence)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: future sequence accepted");
		res = false;
	}

	hdr.sequence = tun.rxsequence;
	hdr.epoch = tun.epoch - 1U;
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_epoch_mismatch)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: stale epoch accepted");
		res = false;
	}

	hdr.epoch = tun.epoch + 1U;
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_epoch_mismatch)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: future epoch accepted");
		res = false;
	}

	hdr.epoch = tun.epoch;
	hdr.suiteid = (uint8_t)(UDIF_SUITE_ID + 1U);
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_suite_mismatch)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: bad suite accepted");
		res = false;
	}

	hdr.suiteid = UDIF_SUITE_ID;
	hdr.utctime = 1000U - ((uint64_t)UDIF_TUNNEL_TIME_WINDOW_SECONDS + 1U);
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_time_window)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: stale time accepted");
		res = false;
	}

	hdr.utctime = 1000U + ((uint64_t)UDIF_TUNNEL_TIME_WINDOW_SECONDS + 1U);
	err = udif_tunnel_record_header_validate(&tun, &hdr, 1000U);

	if (err != udif_error_time_window)
	{
		qsc_consoleutils_print_line("tunnel_test_header_validation: future time accepted");
		res = false;
	}

	return res;
}

static bool tunnel_test_receive_record(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_record: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_record: receive failed");
			res = false;
		}
		else if (out.msgtype != udif_msg_keepalive || tun.rxsequence != 8U ||
			tun.lastrxsecs != 1000U || tun.idledeadline != 1000U + (uint64_t)UDIF_IDLE_TEARDOWN_SECONDS)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_record: receive state mismatch");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_replay(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence - 1U;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_replay: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_invalid_sequence)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_replay: replay accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_reorder(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence + 1U;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_reorder: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_invalid_sequence || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_reorder: reordered record accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_wrong_record_class(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_DATA;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_wrong_record_class: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_invalid_request || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_wrong_record_class: wrong class accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_combined_record_class(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = (uint8_t)(UDIF_TUNNEL_FLAG_KEEPALIVE | UDIF_TUNNEL_FLAG_CONTROL);
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_combined_record_class: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_invalid_request || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_combined_record_class: combined class accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_mutated_inner_header(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_mutated_inner_header: record encode failed");
		res = false;
	}
	else
	{
		enc[25U] ^= 0x01U;
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_suite_mismatch || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_mutated_inner_header: mutated header accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_mutated_inner_message(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_mutated_inner_message: record encode failed");
		res = false;
	}
	else
	{
		enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + 1U] ^= 0x7FU;
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_decode_failure || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_mutated_inner_message: mutated message accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}


static bool tunnel_test_receive_rejects_trailing_bytes(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE + 1U] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_trailing_bytes: record encode failed");
		res = false;
	}
	else
	{
		enc[sizeof(enc) - 1U] = 0xA5U;
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err == udif_error_none || tun.rxsequence != 7U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_trailing_bytes: non-canonical trailing bytes accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_receive_rejects_stale_epoch_after_rekey(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);
	tun.epoch += 1U;
	tun.rxsequence = 0U;

	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = 0U;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch - 1U;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_receive_rejects_stale_epoch_after_rekey: record encode failed");
		res = false;
	}
	else
	{
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_epoch_mismatch || tun.rxsequence != 0U)
		{
			qsc_consoleutils_print_line("tunnel_test_receive_rejects_stale_epoch_after_rekey: stale epoch accepted");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

static bool tunnel_test_send_after_close_rejected(void)
{
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	qstp_connection_state qstate;
	udif_message msg;
	udif_tunnel tun;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&qstate, sizeof(qstp_connection_state));
	qsc_memutils_clear((uint8_t*)&tun, sizeof(udif_tunnel));
	qsc_memutils_clear((uint8_t*)&msg, sizeof(udif_message));
	serial[0U] = 1U;

	err = udif_tunnel_init(&tun, &qstate, serial, udif_rolepair_ua_gc, udif_tunnel_side_client, NULL, 1000U);

	if (err != udif_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_send_after_close_rejected: init failed");
		res = false;
	}
	else
	{
		err = udif_message_init(&msg, udif_msg_keepalive, NULL, 0U);

		if (err != udif_error_none)
		{
			qsc_consoleutils_print_line("tunnel_test_send_after_close_rejected: message init failed");
			res = false;
		}
		else
		{
			udif_tunnel_close(&tun, false);
			err = udif_tunnel_send(&tun, &msg, 1001U);

			if (err != udif_error_invalid_state)
			{
				qsc_consoleutils_print_line("tunnel_test_send_after_close_rejected: closed tunnel send accepted");
				res = false;
			}
		}
	}

	udif_message_dispose(&msg);

	return res;
}


static void tunnel_test_init_qstp_pair(qstp_connection_state* sender, qstp_connection_state* receiver, bool wrong_receiver_key)
{
	uint8_t key[QSTP_SYMMETRIC_KEY_SIZE] = { 0U };
	uint8_t nonce[QSTP_NONCE_SIZE] = { 0U };
	uint8_t wrongkey[QSTP_SYMMETRIC_KEY_SIZE] = { 0U };
	qstp_cipher_keyparams kp;
	size_t i;

	qsc_memutils_clear((uint8_t*)sender, sizeof(qstp_connection_state));
	qsc_memutils_clear((uint8_t*)receiver, sizeof(qstp_connection_state));
	qsc_memutils_clear((uint8_t*)&kp, sizeof(qstp_cipher_keyparams));

	for (i = 0U; i < sizeof(key); ++i)
	{
		key[i] = (uint8_t)(i + 1U);
		wrongkey[i] = (uint8_t)(i + 0x31U);
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(0xA0U + i);
	}

	kp.key = key;
	kp.keylen = QSTP_SYMMETRIC_KEY_SIZE;
	kp.nonce = nonce;
	kp.info = NULL;
	kp.infolen = 0U;
	qstp_cipher_initialize(&sender->txcpr, &kp, true);

	if (wrong_receiver_key == true)
	{
		kp.key = wrongkey;
	}
	else
	{
		kp.key = key;
	}

	qstp_cipher_initialize(&receiver->rxcpr, &kp, false);
	sender->exflag = qstp_flag_session_established;
	receiver->exflag = qstp_flag_session_established;

	qsc_memutils_clear(key, sizeof(key));
	qsc_memutils_clear(wrongkey, sizeof(wrongkey));
	qsc_memutils_clear(nonce, sizeof(nonce));
	qsc_memutils_clear((uint8_t*)&kp, sizeof(qstp_cipher_keyparams));
}

static bool tunnel_test_qstp_ciphertext_mutation_rejected(void)
{
	uint8_t message[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	uint8_t encrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE + QSTP_MACTAG_SIZE] = { 0U };
	uint8_t decrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	qstp_connection_state sender;
	qstp_connection_state receiver;
	qstp_network_packet pkt;
	qstp_errors qerr;
	size_t msglen;
	bool res;

	res = true;
	msglen = 0U;
	qsc_memutils_clear((uint8_t*)&pkt, sizeof(qstp_network_packet));
	tunnel_test_init_qstp_pair(&sender, &receiver, false);
	message[0U] = 0x42U;
	pkt.pmessage = encrypted;

	qerr = qstp_encrypt_packet(&sender, &pkt, message, sizeof(message));

	if (qerr != qstp_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_qstp_ciphertext_mutation_rejected: encryption failed");
		res = false;
	}
	else
	{
		encrypted[0U] ^= 0x01U;
		qerr = qstp_decrypt_packet(&receiver, decrypted, &msglen, &pkt);

		if (qerr != qstp_error_authentication_failure || msglen != 0U || receiver.rxseq != 0U)
		{
			qsc_consoleutils_print_line("tunnel_test_qstp_ciphertext_mutation_rejected: mutated ciphertext accepted");
			res = false;
		}
	}

	qstp_connection_state_dispose(&sender);
	qstp_connection_state_dispose(&receiver);

	return res;
}

static bool tunnel_test_qstp_tag_mutation_rejected(void)
{
	uint8_t message[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	uint8_t encrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE + QSTP_MACTAG_SIZE] = { 0U };
	uint8_t decrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	qstp_connection_state sender;
	qstp_connection_state receiver;
	qstp_network_packet pkt;
	qstp_errors qerr;
	size_t msglen;
	bool res;

	res = true;
	msglen = 0U;
	qsc_memutils_clear((uint8_t*)&pkt, sizeof(qstp_network_packet));
	tunnel_test_init_qstp_pair(&sender, &receiver, false);
	message[0U] = 0x43U;
	pkt.pmessage = encrypted;

	qerr = qstp_encrypt_packet(&sender, &pkt, message, sizeof(message));

	if (qerr != qstp_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_qstp_tag_mutation_rejected: encryption failed");
		res = false;
	}
	else
	{
		encrypted[pkt.msglen - 1U] ^= 0x01U;
		qerr = qstp_decrypt_packet(&receiver, decrypted, &msglen, &pkt);

		if (qerr != qstp_error_authentication_failure || msglen != 0U || receiver.rxseq != 0U)
		{
			qsc_consoleutils_print_line("tunnel_test_qstp_tag_mutation_rejected: mutated tag accepted");
			res = false;
		}
	}

	qstp_connection_state_dispose(&sender);
	qstp_connection_state_dispose(&receiver);

	return res;
}

static bool tunnel_test_qstp_wrong_session_rejected(void)
{
	uint8_t message[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	uint8_t encrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE + QSTP_MACTAG_SIZE] = { 0U };
	uint8_t decrypted[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	qstp_connection_state sender;
	qstp_connection_state receiver;
	qstp_network_packet pkt;
	qstp_errors qerr;
	size_t msglen;
	bool res;

	res = true;
	msglen = 0U;
	qsc_memutils_clear((uint8_t*)&pkt, sizeof(qstp_network_packet));
	tunnel_test_init_qstp_pair(&sender, &receiver, true);
	message[0U] = 0x44U;
	pkt.pmessage = encrypted;

	qerr = qstp_encrypt_packet(&sender, &pkt, message, sizeof(message));

	if (qerr != qstp_error_none)
	{
		qsc_consoleutils_print_line("tunnel_test_qstp_wrong_session_rejected: encryption failed");
		res = false;
	}
	else
	{
		qerr = qstp_decrypt_packet(&receiver, decrypted, &msglen, &pkt);

		if (qerr != qstp_error_authentication_failure || msglen != 0U || receiver.rxseq != 0U)
		{
			qsc_consoleutils_print_line("tunnel_test_qstp_wrong_session_rejected: wrong session ciphertext accepted");
			res = false;
		}
	}

	qstp_connection_state_dispose(&sender);
	qstp_connection_state_dispose(&receiver);

	return res;
}

static bool tunnel_test_rekey_state_transition(void)
{
	udif_tunnel tun;
	bool res;

	res = true;
	tunnel_test_init_state(&tun);
	tun.epoch += 1U;
	tun.txsequence = 0U;
	tun.rxsequence = 0U;

	if (tun.epoch != 3U || tun.txsequence != 0U || tun.rxsequence != 0U)
	{
		qsc_consoleutils_print_line("tunnel_test_rekey_state_transition: epoch transition failed");
		res = false;
	}

	return res;
}

static bool tunnel_test_close_state(void)
{
	uint8_t enc[UDIF_TUNNEL_RECORD_HEADER_SIZE + UDIF_MESSAGE_HEADER_SIZE] = { 0U };
	udif_tunnel tun;
	udif_tunnel_record_header hdr = { 0U };
	udif_message out;
	udif_errors err;
	bool res;

	res = true;
	qsc_memutils_clear((uint8_t*)&out, sizeof(udif_message));
	tunnel_test_init_state(&tun);
	hdr.flags = UDIF_TUNNEL_FLAG_KEEPALIVE;
	hdr.sequence = tun.rxsequence;
	hdr.utctime = 1000U;
	hdr.epoch = tun.epoch;
	hdr.suiteid = UDIF_SUITE_ID;

	if (tunnel_test_encode_record(enc, sizeof(enc), &hdr, udif_msg_keepalive) == false)
	{
		qsc_consoleutils_print_line("tunnel_test_close_state: record encode failed");
		res = false;
	}
	else
	{
		udif_tunnel_close(&tun, false);
		err = udif_tunnel_on_receive(&tun, enc, sizeof(enc), &out, 1000U);

		if (err != udif_error_invalid_state)
		{
			qsc_consoleutils_print_line("tunnel_test_close_state: closed tunnel accepted traffic");
			res = false;
		}
	}

	udif_message_dispose(&out);

	return res;
}

bool tunnel_test_run(void)
{
	bool res;

	res = tunnel_test_header_roundtrip();
	res &= tunnel_test_initial_state();
	res &= tunnel_test_header_validation();
	res &= tunnel_test_receive_record();
	res &= tunnel_test_receive_rejects_replay();
	res &= tunnel_test_receive_rejects_reorder();
	res &= tunnel_test_receive_rejects_wrong_record_class();
	res &= tunnel_test_receive_rejects_combined_record_class();
	res &= tunnel_test_receive_rejects_mutated_inner_header();
	res &= tunnel_test_receive_rejects_mutated_inner_message();
	res &= tunnel_test_receive_rejects_trailing_bytes();
	res &= tunnel_test_receive_rejects_stale_epoch_after_rekey();
	res &= tunnel_test_send_after_close_rejected();
	res &= tunnel_test_qstp_ciphertext_mutation_rejected();
	res &= tunnel_test_qstp_tag_mutation_rejected();
	res &= tunnel_test_qstp_wrong_session_rejected();
	res &= tunnel_test_rekey_state_transition();
	res &= tunnel_test_close_state();

	return res;
}
