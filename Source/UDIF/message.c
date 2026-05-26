#include "udif.h"
#include "message.h"
#include "intutils.h"
#include "memutils.h"

udif_errors udif_message_init(udif_message* msg, udif_message_type msgtype, const uint8_t* payload, uint32_t payloadlen)
{
	UDIF_ASSERT(msg != NULL);

	udif_errors err;

	err = udif_error_invalid_input;

	if (msg != NULL)
	{
		if (payloadlen <= UDIF_MESSAGE_PAYLOAD_MAX)
		{
			/* empty message: payload pointer must be NULL when payloadlen is zero,
			   otherwise the source pointer must be valid */
			if ((payloadlen == 0U && payload == NULL) || (payloadlen != 0U && payload != NULL))
			{
				qsc_memutils_clear((uint8_t*)msg, sizeof(udif_message));
				msg->msgtype = msgtype;
				msg->payloadlen = payloadlen;
				msg->payload = NULL;

				if (payloadlen == 0U)
				{
					err = udif_error_none;
				}
				else
				{
					msg->payload = (uint8_t*)qsc_memutils_malloc((size_t)payloadlen);

					if (msg->payload != NULL)
					{
						qsc_memutils_copy(msg->payload, payload, (size_t)payloadlen);
						err = udif_error_none;
					}
					else
					{
						msg->payloadlen = 0U;
						err = udif_error_internal;
					}
				}
			}
		}
		else
		{
			err = udif_error_encode_failure;
		}
	}

	return err;
}

void udif_message_dispose(udif_message* msg)
{
	if (msg != NULL)
	{
		if (msg->payload != NULL && msg->payloadlen != 0U)
		{
			/* zero payload bytes before release in case they carry sensitive content */
			qsc_memutils_clear(msg->payload, (size_t)msg->payloadlen);
			qsc_memutils_alloc_free(msg->payload);
		}

		qsc_memutils_clear((uint8_t*)msg, sizeof(udif_message));
	}
}

udif_errors udif_message_encode(uint8_t* output, size_t outlen, const udif_message* msg, size_t* written)
{
	UDIF_ASSERT(output != NULL);
	UDIF_ASSERT(msg != NULL);

	size_t required;
	size_t pos;
	udif_errors err;

	err = udif_error_invalid_input;

	if (output != NULL && msg != NULL)
	{
		if (msg->payloadlen <= UDIF_MESSAGE_PAYLOAD_MAX)
		{
			required = (size_t)UDIF_MESSAGE_HEADER_SIZE + (size_t)msg->payloadlen;

			if (outlen >= required)
			{
				pos = 0U;

				/* layout: msgtype (1) | version (1) | payloadlen (4 LE) | payload */
				output[pos] = (uint8_t)msg->msgtype;
				pos += 1U;
				output[pos] = (uint8_t)UDIF_MESSAGE_VERSION;
				pos += 1U;
				qsc_intutils_le32to8(output + pos, msg->payloadlen);
				pos += 4U;

				if (msg->payloadlen != 0U && msg->payload != NULL)
				{
					qsc_memutils_copy(output + pos, msg->payload, (size_t)msg->payloadlen);
				}

				if (written != NULL)
				{
					*written = required;
				}

				err = udif_error_none;
			}
			else
			{
				err = udif_error_encode_failure;
			}
		}
		else
		{
			err = udif_error_encode_failure;
		}
	}

	return err;
}

udif_errors udif_message_decode(udif_message* msg, const uint8_t* input, size_t inplen, size_t* consumed)
{
	UDIF_ASSERT(msg != NULL);
	UDIF_ASSERT(input != NULL);
	UDIF_ASSERT(inplen != 0U);

	size_t required;
	size_t pos;
	uint32_t payloadlen;
	uint8_t msgtype;
	uint8_t version;
	udif_errors err;

	err = udif_error_decode_failure;

	if (msg != NULL && input != NULL && inplen >= (size_t)UDIF_MESSAGE_HEADER_SIZE)
	{
		pos = 0U;
		msgtype = input[pos];
		pos += 1U;
		version = input[pos];
		pos += 1U;
		payloadlen = qsc_intutils_le8to32(input + pos);
		pos += 4U;

		if (version == (uint8_t)UDIF_MESSAGE_VERSION && payloadlen <= UDIF_MESSAGE_PAYLOAD_MAX)
		{
			required = (size_t)UDIF_MESSAGE_HEADER_SIZE + (size_t)payloadlen;

			if (inplen >= required)
			{
				qsc_memutils_clear((uint8_t*)msg, sizeof(udif_message));
				msg->msgtype = (udif_message_type)msgtype;
				msg->payloadlen = payloadlen;
				msg->payload = NULL;

				if (payloadlen == 0U)
				{
					if (consumed != NULL)
					{
						*consumed = required;
					}

					err = udif_error_none;
				}
				else
				{
					msg->payload = (uint8_t*)qsc_memutils_malloc((size_t)payloadlen);

					if (msg->payload != NULL)
					{
						qsc_memutils_copy(msg->payload, input + pos, (size_t)payloadlen);

						if (consumed != NULL)
						{
							*consumed = required;
						}

						err = udif_error_none;
					}
					else
					{
						msg->payloadlen = 0U;
						err = udif_error_internal;
					}
				}
			}
		}
	}

	return err;
}

size_t udif_message_encoded_size(const udif_message* msg)
{
	size_t total;

	total = 0U;

	if (msg != NULL)
	{
		total = (size_t)UDIF_MESSAGE_HEADER_SIZE + (size_t)msg->payloadlen;
	}

	return total;
}

const char* udif_message_type_name(udif_message_type msgtype)
{
	const char* name;

	switch (msgtype)
	{
		case udif_msg_none:
		{
			name = "none";
			break;
		}
		case udif_msg_keepalive:
		{
			name = "keepalive";
			break;
		}
		case udif_msg_cert_enroll_req:
		{
			name = "cert_enroll_req";
			break;
		}
		case udif_msg_cert_enroll_resp:
		{
			name = "cert_enroll_resp";
			break;
		}
		case udif_msg_cert_revoke:
		{
			name = "cert_revoke";
			break;
		}
		case udif_msg_cert_suspend:
		{
			name = "cert_suspend";
			break;
		}
		case udif_msg_cert_resume:
		{
			name = "cert_resume";
			break;
		}
		case udif_msg_query_req:
		{
			name = "query_req";
			break;
		}
		case udif_msg_query_resp:
		{
			name = "query_resp";
			break;
		}
		case udif_msg_object_create:
		{
			name = "object_create";
			break;
		}
		case udif_msg_object_transfer_req:
		{
			name = "object_transfer_req";
			break;
		}
		case udif_msg_object_transfer_confirm:
		{
			name = "object_transfer_confirm";
			break;
		}
		case udif_msg_registry_commit:
		{
			name = "registry_commit";
			break;
		}
		case udif_msg_anchor_push:
		{
			name = "anchor_push";
			break;
		}
		case udif_msg_anchor_ack:
		{
			name = "anchor_ack";
			break;
		}
		case udif_msg_treaty_propose:
		{
			name = "treaty_propose";
			break;
		}
		case udif_msg_treaty_cosign:
		{
			name = "treaty_cosign";
			break;
		}
		case udif_msg_treaty_revoke:
		{
			name = "treaty_revoke";
			break;
		}
		case udif_msg_treaty_query_fwd:
		{
			name = "treaty_query_fwd";
			break;
		}
		case udif_msg_treaty_query_resp:
		{
			name = "treaty_query_resp";
			break;
		}
		case udif_msg_error_report:
		{
			name = "error_report";
			break;
		}
		default:
		{
			name = "unknown";
			break;
		}
	}

	return name;
}
