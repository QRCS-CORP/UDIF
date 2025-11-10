#include "ura.h"
#include "server.h"
#include "certificate.h"
#include "commands.h"
#include "help.h"
#include "menu.h"
#include "udif.h"
#include "resources.h"
#include "topology.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timerex.h"
#include "timestamp.h"

/** \cond */
typedef struct ura_receive_state
{
	qsc_socket csock;
} ura_receive_state;
/** \endcond */

static udif_server_application_state m_ura_application_state = { 0 };
static udif_server_server_loop_status m_ura_command_loop_status;
static udif_server_server_loop_status m_ura_server_loop_status;
static uint64_t m_ura_idle_timer;

/* rds functions */

static bool ura_certificate_export(const char* dpath)
{
	UDIF_ASSERT(dpath != NULL);

	bool res;

	res = udif_server_root_certificate_export(&m_ura_application_state, dpath);

	return res;
}

static bool ura_server_load_root(void)
{
	bool res;

	res = false;

	/* load the root certificate */
	if (udif_server_topology_root_fetch(&m_ura_application_state, &m_ura_application_state.root) == true)
	{
		res = udif_topology_node_verify_root(&m_ura_application_state.tlist, &m_ura_application_state.root);
	}

	return res;
}

static bool ura_certificate_generate_root(const char* sprd)
{
	UDIF_ASSERT(sprd != NULL); 

	uint64_t period;
	bool res;

	res = false;

	/* generate a certificate and write to file */
	if (qsc_stringutils_is_numeric(sprd, qsc_stringutils_string_size(sprd)) == true)
	{
		char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

		udif_server_certificate_path(&m_ura_application_state, fpath, sizeof(fpath), m_ura_application_state.issuer);
		period = qsc_stringutils_string_to_int(sprd);
		period *= UDIF_PERIOD_DAY_TO_SECONDS;

		if (period >= UDIF_CERTIFICATE_MINIMUM_PERIOD || period <= UDIF_CERTIFICATE_MAXIMUM_PERIOD)
		{
			if (qsc_fileutils_exists(fpath) == true)
			{
				/* file exists, overwrite challenge */
				if (udif_menu_print_predefined_message_confirm(udif_application_generate_key_overwrite, m_ura_application_state.mode, m_ura_application_state.hostname) == true)
				{
					/* remove the node entry */
					udif_topology_node_remove(&m_ura_application_state.tlist, m_ura_application_state.root.serial);
					/* delete the original */
					qsc_fileutils_delete(fpath);
					/* create the certificate and copy the signing key to state */
					udif_server_root_certificate_generate(&m_ura_application_state, &m_ura_application_state.root, period);
					/* write the certificate to file */
					udif_server_root_certificate_store(&m_ura_application_state, &m_ura_application_state.root);
					/* store the state */
					res = udif_server_state_store(&m_ura_application_state);
					res = ura_server_load_root();
				}
				else
				{
					udif_menu_print_predefined_message(udif_application_operation_aborted, m_ura_application_state.mode, m_ura_application_state.hostname);
					res = false;
				}
			}
			else
			{
				udif_server_root_certificate_generate(&m_ura_application_state, &m_ura_application_state.root, period);
				udif_server_root_certificate_store(&m_ura_application_state, &m_ura_application_state.root);
				res = udif_server_state_store(&m_ura_application_state);
				res = ura_server_load_root();
			}
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_invalid_input, m_ura_application_state.mode, m_ura_application_state.hostname);
		}
	}

	return res;
}

static bool ura_certificate_sign(const char* fpath)
{
	UDIF_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (qsc_fileutils_exists(fpath) == true && 
		qsc_stringutils_string_contains(fpath, UDIF_CERTIFICATE_CHILD_EXTENSION) == true)
	{
		udif_child_certificate child = { 0 };

		if (udif_certificate_child_file_to_struct(fpath, &child) == true)
		{
			if (udif_certificate_root_sign(&child, &m_ura_application_state.root, m_ura_application_state.sigkey) == UDIF_CERTIFICATE_SIGNED_HASH_SIZE)
			{
				res = udif_certificate_child_struct_to_file(fpath, &child);
			}
		}
	}

	return res;
}

static udif_protocol_errors ads_remote_signing_response(qsc_socket* csock, const udif_network_packet* packetin)
{
	UDIF_ASSERT(csock != NULL);
	UDIF_ASSERT(packetin != NULL);

	udif_topology_node_state dnode = { 0 };
	udif_protocol_errors merr;

	if (m_ura_application_state.joined == true)
	{
		if (udif_topology_node_find(&m_ura_application_state.tlist, &dnode, m_ura_application_state.ads.serial) == true)
		{
			if (qsc_memutils_are_equal((const uint8_t*)dnode.address, (const uint8_t*)csock->address, UDIF_CERTIFICATE_ADDRESS_SIZE) == true)
			{
				//udif_child_certificate rcert = { 0 };
				(void)packetin;
				// TODO
				//udif_network_remote_signing_response_state rsr = {
				//	.csock = csock,
				//	.dcert = &m_ura_application_state.ads,
				//	.rcert = &rcert,
				//	.root = &m_ura_application_state.root,
				//	.sigkey = m_ura_application_state.sigkey
				//};

				//merr = udif_network_remote_signing_response(&rsr, packetin);
				merr = udif_protocol_error_invalid_request;
			}
			else
			{
				merr = udif_protocol_error_invalid_request;
			}
		}
		else
		{
			merr = udif_protocol_error_node_not_found;
		}
	}
	else
	{
		merr = udif_protocol_error_certificate_not_found;
	}

	return merr;
}

static void ura_server_dispose(void)
{
	udif_server_state_initialize(&m_ura_application_state, udif_network_designation_ura);
	m_ura_command_loop_status = udif_server_loop_status_stopped;
	m_ura_server_loop_status = udif_server_loop_status_stopped;
	m_ura_idle_timer = 0U;
}

static bool ura_server_load_ads(void)
{
	bool res;

	res = false;

	/* load the ads certificate */
	if (udif_server_topology_adc_fetch(&m_ura_application_state, &m_ura_application_state.ads) == true)
	{
		/* check the ads certificate structure */
		if (udif_certificate_child_is_valid(&m_ura_application_state.ads) == true)
		{
			/* verify the root signature */
			if (udif_certificate_root_signature_verify(&m_ura_application_state.ads, &m_ura_application_state.root) == true)
			{
				/* verify a hash of the certificate against the hash stored on the topological node */
				res = udif_topology_node_verify_ads(&m_ura_application_state.tlist, &m_ura_application_state.ads);
			}
		}
	}

	return res;
}

static bool ura_server_adc_dialogue(void)
{
	char cmsg[UDIF_STORAGE_PATH_MAX] = { 0 };
	char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };
	size_t slen;
	uint8_t rctr;
	bool res;

	res = false;
	rctr = 0U;

	while (res == false)
	{
		++rctr;

		if (rctr > 3U)
		{
			break;
		}

		udif_menu_print_predefined_message(udif_application_adc_certificate_path_success, udif_console_mode_server, m_ura_application_state.hostname);
		udif_menu_print_prompt(udif_console_mode_server, m_ura_application_state.hostname);
		slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

		if (slen >= UDIF_STORAGE_FILEPATH_MIN && 
			slen <= UDIF_STORAGE_FILEPATH_MAX &&
			qsc_fileutils_exists(cmsg) == true &&
			qsc_stringutils_string_contains(cmsg, UDIF_CERTIFICATE_CHILD_EXTENSION))
		{
			udif_child_certificate ccert = { 0 };

			if (udif_certificate_child_file_to_struct(cmsg, &ccert) == true)
			{
				if (udif_certificate_child_is_valid(&ccert) == true && 
					udif_certificate_root_signature_verify(&ccert, &m_ura_application_state.root) == true)
				{
					/* get the ADC ip address */
					qsc_memutils_clear(cmsg, sizeof(cmsg));
					udif_menu_print_predefined_message(udif_application_adc_certificate_address_challenge, udif_console_mode_server, m_ura_application_state.hostname);
					udif_menu_print_prompt(udif_console_mode_server, m_ura_application_state.hostname);
					slen = qsc_consoleutils_get_line(cmsg, sizeof(cmsg)) - 1U;

					if (slen >= QSC_IPINFO_IPV4_MINLEN)
					{
#if defined(UDIF_NETWORK_PROTOCOL_IPV6)
						qsc_ipinfo_ipv6_address tadd;

						tadd = qsc_ipinfo_ipv6_address_from_string(cmsg);

						if (qsc_ipinfo_ipv6_address_is_valid(&tadd) == true)
						{
#else
						qsc_ipinfo_ipv4_address tadd;

						tadd = qsc_ipinfo_ipv4_address_from_string(cmsg);

						if (qsc_ipinfo_ipv4_address_is_valid(&tadd) == true)
						{
#endif
							udif_topology_node_state rnode = { 0 };

							/* add the node to the topology */
							udif_topology_child_register(&m_ura_application_state.tlist, &ccert, cmsg);
							udif_server_topology_to_file(&m_ura_application_state);

							if (udif_topology_node_find(&m_ura_application_state.tlist, &rnode, ccert.serial) == true)
							{
								/* copy the certificate to file */
								udif_server_certificate_path(&m_ura_application_state, fpath, sizeof(fpath), rnode.issuer);

								if (udif_certificate_child_struct_to_file(fpath, &ccert) == true)
								{
									/* copy certificate to state */
									udif_certificate_child_copy(&m_ura_application_state.ads, &ccert);
									m_ura_application_state.joined = true;
									/* store the state */
									res = udif_server_state_store(&m_ura_application_state);
									break;
								}
							}
						}
					}
				}
				else
				{
					udif_menu_print_predefined_message(udif_application_adc_certificate_path_failure, udif_console_mode_server, m_ura_application_state.hostname);
				}
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_certificate_not_found, udif_console_mode_server, m_ura_application_state.hostname);
			}
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_certificate_not_found, udif_console_mode_server, m_ura_application_state.hostname);
		}
	}

	return res;
}

static void ura_receive_loop(void* ras)
{
	UDIF_ASSERT(ras != NULL);

	udif_network_packet pkt = { 0 };
	uint8_t* buff;
	ura_receive_state* pras;
	const char* cmsg;
	size_t mlen;
	size_t plen;
	udif_protocol_errors merr;

	merr = udif_protocol_error_none;

	if (ras != NULL)
	{
		pras = (ura_receive_state*)ras;
		buff = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

		if (buff != NULL)
		{
			uint8_t hdr[UDIF_PACKET_HEADER_SIZE] = { 0U };

			mlen = 0U;
			plen = qsc_socket_peek(&pras->csock, hdr, UDIF_PACKET_HEADER_SIZE);

			if (plen == UDIF_PACKET_HEADER_SIZE)
			{
				udif_packet_header_deserialize(hdr, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= UDIF_MESSAGE_MAX_SIZE)
				{
					plen = pkt.msglen + UDIF_PACKET_HEADER_SIZE;
					buff = (uint8_t*)qsc_memutils_realloc(buff, plen);

					if (buff != NULL)
					{
						qsc_memutils_clear(buff, plen);
						mlen = qsc_socket_receive(&pras->csock, buff, plen, qsc_socket_receive_flag_wait_all);
					}
					else
					{
						merr = udif_protocol_error_memory_allocation;
						udif_server_log_write_message(&m_ura_application_state, udif_application_log_allocation_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
				}
				else
				{
					merr = udif_protocol_error_invalid_request;
					udif_server_log_write_message(&m_ura_application_state, udif_application_log_receive_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
				}

				if (mlen > 0U)
				{
					pkt.pmessage = buff + UDIF_PACKET_HEADER_SIZE;

					if (pkt.flag == udif_network_flag_network_remote_signing_request)
					{
						merr = ads_remote_signing_response(&pras->csock, &pkt);

						if (merr == udif_protocol_error_none)
						{
							udif_server_log_write_message(&m_ura_application_state, udif_application_log_remote_signing_success, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
						else
						{
							cmsg = udif_protocol_error_to_string(merr);

							if (cmsg != NULL)
							{
								udif_logger_write_time_stamped_message(m_ura_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
							}

							udif_server_log_write_message(&m_ura_application_state, udif_application_log_remote_signing_failure, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
					else if (pkt.flag == udif_network_flag_system_error_condition)
					{
						/* log the error condition */
						cmsg = udif_protocol_error_to_string((udif_protocol_errors)pkt.pmessage[0U]);

						if (cmsg != NULL)
						{
							udif_logger_write_time_stamped_message(m_ura_application_state.logpath, cmsg, qsc_stringutils_string_size(cmsg));
						}

						udif_server_log_write_message(&m_ura_application_state, udif_application_log_remote_reported_error, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
					}
					else
					{
						qsc_socket_exceptions err = qsc_socket_get_last_error();

						if (err != qsc_socket_exception_success)
						{
							/* fatal socket errors */
							if (err == qsc_socket_exception_circuit_reset ||
								err == qsc_socket_exception_circuit_terminated ||
								err == qsc_socket_exception_circuit_timeout ||
								err == qsc_socket_exception_dropped_connection ||
								err == qsc_socket_exception_network_failure ||
								err == qsc_socket_exception_shut_down)
							{
								udif_server_log_write_message(&m_ura_application_state, udif_application_log_connection_terminated, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							// TODO
							//udif_network_send_error(&pras->csock, udif_protocol_error_invalid_request);
							udif_server_log_write_message(&m_ura_application_state, udif_application_log_remote_invalid_request, (const char*)pras->csock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					}
				}
			}

			qsc_memutils_alloc_free(buff);
		}

		// TODO
		/* close the connection and dispose of the socket */
		//udif_network_socket_dispose(&pras->csock);

		/* free the socket from memory */
		qsc_memutils_alloc_free(pras);
		pras = NULL;
	}
}

#if defined(UDIF_NETWORK_PROTOCOL_IPV6)

static void ura_ipv6_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv6_address_from_string(m_ura_application_state.localip);

	if (qsc_ipinfo_ipv6_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv6(&lsock, &addt, UDIF_APPLICATION_ARS_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						ura_receive_state* ras;

						ras = (ura_receive_state*)qsc_memutils_malloc(sizeof(ura_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								udif_server_log_write_message(&m_ura_application_state, udif_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&ura_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								udif_server_log_write_message(&m_ura_application_state, udif_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							break;
						}
					};
				}
			}
		}
	}
}

#else

static void ura_ipv4_server_start(void)
{
	qsc_socket lsock = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions serr;

	addt = qsc_ipinfo_ipv4_address_from_string(m_ura_application_state.localip);

	if (qsc_ipinfo_ipv4_address_is_valid(&addt) == true)
	{
		qsc_socket_server_initialize(&lsock);
		serr = qsc_socket_create(&lsock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (serr == qsc_socket_exception_success)
		{
			serr = qsc_socket_bind_ipv4(&lsock, &addt, UDIF_APPLICATION_UBC_PORT);

			if (serr == qsc_socket_exception_success)
			{
				serr = qsc_socket_listen(&lsock, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (serr == qsc_socket_exception_success)
				{
					while (true)
					{
						ura_receive_state* ras;

						ras = (ura_receive_state*)qsc_memutils_malloc(sizeof(ura_receive_state));

						if (ras != NULL)
						{
							qsc_memutils_clear(&ras->csock, sizeof(qsc_socket));

							if (serr == qsc_socket_exception_success)
							{
								serr = qsc_socket_accept(&lsock, &ras->csock);
							}

							if (serr == qsc_socket_exception_success)
							{
								qsc_async_thread_create(&ura_receive_loop, ras);
							}
							else
							{
								/* free the resources if connect fails */
								qsc_memutils_alloc_free(ras);
								udif_server_log_write_message(&m_ura_application_state, udif_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
							}
						}
						else
						{
							/* exit on memory allocation failure */
							udif_server_log_write_message(&m_ura_application_state, udif_application_log_allocation_failure, (const char*)lsock.address, QSC_SOCKET_ADDRESS_MAX_SIZE);
						}
					};
				}
			}
		}
	}
}

#endif

static bool ura_server_service_start(void)
{
#if defined(UDIF_NETWORK_PROTOCOL_IPV6)
	/* start the main receive loop on a new thread */
	if (qsc_async_thread_create_noargs(&ura_ipv6_server_start))
#else
	if (qsc_async_thread_create_noargs(&ura_ipv4_server_start))
#endif
	{
		m_ura_server_loop_status = udif_server_loop_status_started;
	}

	return (m_ura_server_loop_status == udif_server_loop_status_started);
}

/* application functions */

static void ura_get_command_mode(const char* command)
{
	UDIF_ASSERT(command != NULL);

	udif_console_modes nmode;

	nmode = m_ura_application_state.mode;

	switch (m_ura_application_state.mode)
	{
		case udif_console_mode_config:
		{
			if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				nmode = udif_console_mode_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				nmode = udif_console_mode_server;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = udif_console_mode_enable;
			}

			break;
		}
		case udif_console_mode_certificate:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = udif_console_mode_config;
			}

			break;
		}
		case udif_console_mode_server:
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = udif_console_mode_config;
			}

			break;
		}
		case udif_console_mode_enable:
		{
			if (qsc_consoleutils_line_equals(command, "config"))
			{
				nmode = udif_console_mode_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				nmode = udif_console_mode_user;
			}

			break;
		}
		case udif_console_mode_user:
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				nmode = udif_console_mode_enable;
			}
			else if (qsc_stringutils_string_size(command) > 0U)
			{
				nmode = udif_console_mode_user;
			}

			break;
		}
		default:
		{
		}
	}

	m_ura_application_state.mode = nmode;
}

static void ura_set_command_action(const char* command)
{
	UDIF_ASSERT(command != NULL);

	udif_command_actions res;
	size_t clen;

	res = udif_command_action_command_unrecognized;
	clen = qsc_stringutils_string_size(command);

	if (clen == 0U || clen > QSC_CONSOLE_MAX_LINE)
	{
		res = udif_command_action_none;
	}
	else
	{
		if (m_ura_application_state.mode == udif_console_mode_config)
		{
			if (qsc_consoleutils_line_equals(command, "clear all"))
			{
				res = udif_command_action_config_clear_all;
			}
			else if (qsc_consoleutils_line_equals(command, "clear config"))
			{
				res = udif_command_action_config_clear_config;
			}
			else if (qsc_consoleutils_line_equals(command, "clear log"))
			{
				res = udif_command_action_config_clear_log;
			}
			else if (qsc_consoleutils_line_equals(command, "certificate"))
			{
				res = udif_command_action_config_certificate;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = udif_command_action_config_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = udif_command_action_config_help;
			}
			else if (qsc_consoleutils_line_contains(command, "log "))
			{
				res = udif_command_action_config_log_host;
			}
			else if (qsc_consoleutils_line_contains(command, "address "))
			{
				res = udif_command_action_config_address;
			}
			else if (qsc_consoleutils_line_contains(command, "name domain "))
			{
				res = udif_command_action_config_name_domain;
			}
			else if (qsc_consoleutils_line_contains(command, "name host "))
			{
				res = udif_command_action_config_name_host;
			}
			else if (qsc_consoleutils_line_contains(command, "retries "))
			{
				res = udif_command_action_config_retries;
			}
			else if (qsc_consoleutils_line_equals(command, "server"))
			{
				res = udif_command_action_config_server;
			}
			else if (qsc_consoleutils_line_contains(command, "timeout "))
			{
				res = udif_command_action_config_timeout;
			}
		}
		else if (m_ura_application_state.mode == udif_console_mode_certificate)
		{
			if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = udif_command_action_certificate_exit;
			}
			else if (qsc_consoleutils_line_contains(command, "export "))
			{
				res = udif_command_action_certificate_export;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = udif_command_action_certificate_help;
			}
			else if (qsc_consoleutils_line_contains(command, "generate "))
			{
				res = udif_command_action_certificate_generate;
			}
			else if (qsc_consoleutils_line_equals(command, "print"))
			{
				res = udif_command_action_certificate_import;
			}
			else if (qsc_consoleutils_line_contains(command, "sign "))
			{
				res = udif_command_action_certificate_sign;
			}
		}
		else if (m_ura_application_state.mode == udif_console_mode_server)
		{
			if (qsc_consoleutils_line_equals(command, "backup"))
			{
				res = udif_command_action_server_backup;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = udif_command_action_server_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = udif_command_action_server_help;
			}
			else if (qsc_consoleutils_line_equals(command, "restore"))
			{
				res = udif_command_action_server_restore;
			}
			else if (qsc_consoleutils_line_contains(command, "service "))
			{
				res = udif_command_action_server_service;
			}
		}
		else if (m_ura_application_state.mode == udif_console_mode_enable)
		{
			if (qsc_consoleutils_line_equals(command, "clear"))
			{
				res = udif_command_action_enable_clear_screen;
			}
			else if (qsc_consoleutils_line_equals(command, "show config"))
			{
				res = udif_command_action_enable_show_config;
			}
			else if (qsc_consoleutils_line_equals(command, "show log"))
			{
				res = udif_command_action_enable_show_log;
			}
			else if (qsc_consoleutils_line_equals(command, "config"))
			{
				res = udif_command_action_enable_config;
			}
			else if (qsc_consoleutils_line_equals(command, "exit"))
			{
				res = udif_command_action_enable_exit;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = udif_command_action_enable_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = udif_command_action_enable_quit;
			}
		}
		else if (m_ura_application_state.mode == udif_console_mode_user)
		{
			if (qsc_consoleutils_line_equals(command, "enable"))
			{
				res = udif_command_action_user_enable;
			}
			else if (qsc_consoleutils_line_equals(command, "help"))
			{
				res = udif_command_action_user_help;
			}
			else if (qsc_consoleutils_line_equals(command, "quit"))
			{
				res = udif_command_action_user_quit;
			}
		}
	}

	m_ura_application_state.action = res;
}

static void ura_command_execute(const char* command)
{
	UDIF_ASSERT(command != NULL);

	const char* cmsg;
	size_t slen;
	bool res;

	switch (m_ura_application_state.action)
	{
	case udif_command_action_certificate_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_certificate_export:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = ura_certificate_export(cmsg);

			if (res == true)
			{
				udif_menu_print_predefined_message(udif_application_root_copy_success, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_root_copy_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_certificate_generate:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(m_ura_application_state.username);

		if (cmsg != NULL)
		{
			res = ura_certificate_generate_root(cmsg);

			if (res == true)
			{
				char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

				udif_server_certificate_path(&m_ura_application_state, fpath, sizeof(fpath), m_ura_application_state.issuer);
				udif_menu_print_predefined_message(udif_application_generate_key_success, m_ura_application_state.mode, m_ura_application_state.hostname);
				udif_menu_print_message(fpath, m_ura_application_state.mode, m_ura_application_state.hostname);
				udif_server_log_write_message(&m_ura_application_state, udif_application_log_generate_success, m_ura_application_state.username, slen);
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_generate_key_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
				udif_server_log_write_message(&m_ura_application_state, udif_application_log_generate_failure, m_ura_application_state.username, slen);
			}
		}

		break;
	}
	case udif_command_action_certificate_help:
	{
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_certificate, m_ura_application_state.srvtype);
		break;
	}
	case udif_command_action_certificate_import:
	{
		char fpath[UDIF_STORAGE_PATH_MAX] = { 0 };

		res = false;
		udif_server_certificate_path(&m_ura_application_state, fpath, sizeof(fpath), m_ura_application_state.issuer);

		if (qsc_fileutils_exists(fpath) == true)
		{
			res = udif_server_root_certificate_print(fpath, sizeof(fpath));
		}

		if (res == false)
		{
			udif_menu_print_predefined_message(udif_application_client_pubkey_path_invalid, m_ura_application_state.mode, m_ura_application_state.hostname);
		}

		break;
	}
	case udif_command_action_certificate_sign:
	{
		res = false;
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			res = ura_certificate_sign(cmsg);
			slen = qsc_stringutils_string_size(m_ura_application_state.username);

			if (res == true)
			{
				udif_server_log_write_message(&m_ura_application_state, udif_application_root_sign_success, m_ura_application_state.username, slen);
				udif_menu_print_predefined_message(udif_application_root_sign_success, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
			else
			{
				udif_server_log_write_message(&m_ura_application_state, udif_application_root_sign_failure, m_ura_application_state.username, slen);
				udif_menu_print_predefined_message(udif_application_root_sign_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_config_address:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);
			res = udif_server_set_ip_address(&m_ura_application_state, cmsg, slen);

			if (res == true)
			{
				udif_menu_print_predefined_message(udif_application_address_change_success, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_address_change_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_config_clear:
	{
		/* show clear help */
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_clear_all);
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_clear_config);
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_clear_log);

		break;
	}
	case udif_command_action_config_log:
	{
		/* show log help */
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_log_host);

		break;
	}
	case udif_command_action_config_name:
	{
		/* show name help */
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_name_domain);
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_name_host);

		break;
	}
	case udif_command_action_config_clear_all:
	{
		if (udif_menu_print_predefined_message_confirm(udif_application_erase_erase_all, m_ura_application_state.mode, m_ura_application_state.hostname) == true)
		{
			udif_server_erase_all(&m_ura_application_state);
			udif_menu_print_predefined_message(udif_application_system_erased, m_ura_application_state.mode, m_ura_application_state.hostname);
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_operation_aborted, m_ura_application_state.mode, m_ura_application_state.hostname);
		}

		break;
	}
	case udif_command_action_config_clear_config:
	{
		if (udif_menu_print_predefined_message_confirm(udif_application_erase_config, udif_console_mode_config, m_ura_application_state.hostname) == true)
		{
			udif_server_log_write_message(&m_ura_application_state, udif_application_log_configuration_erased, m_ura_application_state.username, qsc_stringutils_string_size(m_ura_application_state.username));
			udif_server_clear_config(&m_ura_application_state);
			udif_menu_print_predefined_message(udif_application_configuration_erased, m_ura_application_state.mode, m_ura_application_state.hostname);
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_operation_aborted, m_ura_application_state.mode, m_ura_application_state.hostname);
		}

		break;
	}
	case udif_command_action_config_clear_log:
	{
		if (udif_menu_print_predefined_message_confirm(udif_application_erase_log, udif_console_mode_config, m_ura_application_state.hostname) == true)
		{
			udif_server_clear_log(&m_ura_application_state);
			udif_menu_print_predefined_message(udif_application_log_erased, m_ura_application_state.mode, m_ura_application_state.hostname);
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_operation_aborted, m_ura_application_state.mode, m_ura_application_state.hostname);
		}

		break;
	}
	case udif_command_action_config_certificate:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_config_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_config_help:
	{
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_config, m_ura_application_state.srvtype);
		break;
	}
	case udif_command_action_config_log_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			if (qsc_stringutils_string_contains(cmsg, "enable"))
			{
				/* enable logging */
				m_ura_application_state.loghost = true;
				udif_server_log_host(&m_ura_application_state);
				udif_menu_print_predefined_message(udif_application_logging_enabled, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
			else if (qsc_stringutils_string_contains(cmsg, "disable"))
			{
				/* disable logging */
				m_ura_application_state.loghost = false;
				udif_server_log_host(&m_ura_application_state);
				udif_menu_print_predefined_message(udif_application_logging_disabled, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_not_recognized, m_ura_application_state.mode, m_ura_application_state.hostname);
				udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_log_host);
			}
		}
		else
		{
			udif_menu_print_predefined_message(udif_application_not_recognized, m_ura_application_state.mode, m_ura_application_state.hostname);
			udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_config_log_host);
		}

		break;
	}
	case udif_command_action_config_name_domain:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (udif_server_set_domain_name(&m_ura_application_state, cmsg, slen) == false)
			{
				udif_menu_print_predefined_message(udif_application_domain_invalid, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_config_name_host:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (udif_server_set_host_name(&m_ura_application_state, cmsg, slen) == false)
			{
				udif_menu_print_predefined_message(udif_application_hostname_invalid, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_config_retries:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");
		slen = qsc_stringutils_string_size(cmsg);

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (udif_server_set_password_retries(&m_ura_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				udif_menu_print_predefined_message(udif_application_retry_invalid, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_config_server:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_config_timeout:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(cmsg);

			if (udif_server_set_console_timeout(&m_ura_application_state, cmsg, slen) == false)
			{
				/* invalid message */
				udif_menu_print_predefined_message(udif_application_timeout_invalid, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_enable_clear_screen:
	{
		/* clear the screen */
		qsc_consoleutils_set_window_clear();
		break;
	}
	case udif_command_action_enable_config:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_enable_exit:
	{
		udif_server_user_logout(&m_ura_application_state);

		break;
	}
	case udif_command_action_enable_help:
	{
		/* show enable help */
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_enable, m_ura_application_state.srvtype);

		break;
	}
	case udif_command_action_enable_quit:
	{
		/* quit the application */
		m_ura_command_loop_status = udif_server_loop_status_stopped;
		udif_server_state_unload(&m_ura_application_state);
		udif_menu_print_predefined_message(udif_application_application_quit, m_ura_application_state.mode, m_ura_application_state.hostname);
		udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case udif_command_action_enable_show_config:
	{
		/* show config */
		udif_server_print_configuration(&m_ura_application_state);
		break;
	}
	case udif_command_action_enable_show_log:
	{
		/* read the user log */
		udif_server_log_print(&m_ura_application_state);
		break;
	}
	case udif_command_action_help_enable_all:
	{
		/* show enable help */
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_enable, m_ura_application_state.srvtype);

		break;
	}
	case udif_command_action_help_enable_show:
	{
		/* show help */
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_enable_show_config);
		udif_help_print_context(m_ura_application_state.cmdprompt, udif_command_action_enable_show_log);

		break;
	}
	case udif_command_action_help_enable_user:
	{
		/* show enable user help */
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_user, m_ura_application_state.srvtype);

		break;
	}
	case udif_command_action_server_backup:
	{
		slen = qsc_stringutils_string_size(m_ura_application_state.hostname);
		udif_server_state_backup_save(&m_ura_application_state);
		udif_server_log_write_message(&m_ura_application_state, udif_application_log_state_backup, m_ura_application_state.hostname, slen);
		udif_menu_print_predefined_message(udif_application_server_backup_save_confirmation, m_ura_application_state.mode, m_ura_application_state.hostname);

		break;
	}
	case udif_command_action_server_exit:
	{
		/* mode change, do nothing */
		break;
	}
	case udif_command_action_server_help:
	{
		/* show config-server help */
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_server, m_ura_application_state.srvtype);
		break;
	}
	case udif_command_action_server_restore:
	{
		bool dres;

		/* notify that server is already joined to a network */
		dres = udif_menu_print_predefined_message_confirm(udif_application_server_backup_restore_challenge, m_ura_application_state.mode, m_ura_application_state.hostname);
			
		if (dres == true)
		{
			udif_server_state_backup_restore(&m_ura_application_state);
			slen = qsc_stringutils_string_size(m_ura_application_state.hostname);
			udif_server_log_write_message(&m_ura_application_state, udif_application_log_state_restore, m_ura_application_state.hostname, slen);
		}

		break;
	}
	case udif_command_action_server_service:
	{
		cmsg = qsc_stringutils_reverse_sub_string(command, " ");

		if (cmsg != NULL)
		{
			slen = qsc_stringutils_string_size(m_ura_application_state.hostname);

			if (qsc_stringutils_string_contains(cmsg, "start"))
			{
				if (m_ura_server_loop_status != udif_server_loop_status_started)
				{
					if (m_ura_application_state.joined == false)
					{
						ura_server_adc_dialogue();
					}

					if (ura_server_service_start() == true &&
						m_ura_server_loop_status == udif_server_loop_status_started)
					{
						udif_menu_print_predefined_message(udif_application_server_service_start_success, m_ura_application_state.mode, m_ura_application_state.hostname);
						udif_server_log_write_message(&m_ura_application_state, udif_application_log_service_started, m_ura_application_state.hostname, slen);
					}
					else
					{
						udif_menu_print_predefined_message(udif_application_server_service_start_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
					}
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "stop"))
			{
				if (m_ura_server_loop_status == udif_server_loop_status_started)
				{
					m_ura_server_loop_status = udif_server_loop_status_stopped;
					udif_menu_print_predefined_message(udif_application_server_service_stopped, m_ura_application_state.mode, m_ura_application_state.hostname);
					udif_server_log_write_message(&m_ura_application_state, udif_application_log_service_stopped, m_ura_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "pause"))
			{
				if (m_ura_server_loop_status != udif_server_loop_status_paused)
				{
					m_ura_server_loop_status = udif_server_loop_status_paused;
					udif_menu_print_predefined_message(udif_application_server_service_paused, m_ura_application_state.mode, m_ura_application_state.hostname);
					udif_server_log_write_message(&m_ura_application_state, udif_application_log_service_paused, m_ura_application_state.hostname, slen);
				}
			}
			else if (qsc_stringutils_string_contains(cmsg, "resume"))
			{
				if (m_ura_server_loop_status == udif_server_loop_status_paused)
				{
					m_ura_server_loop_status = udif_server_loop_status_started;
					udif_menu_print_predefined_message(udif_application_server_service_resume_success, m_ura_application_state.mode, m_ura_application_state.hostname);
					udif_server_log_write_message(&m_ura_application_state, udif_application_log_service_resumed, m_ura_application_state.hostname, slen);
				}
				else
				{
					udif_menu_print_predefined_message(udif_application_server_service_resume_failure, m_ura_application_state.mode, m_ura_application_state.hostname);
				}
			}
			else
			{
				udif_menu_print_predefined_message(udif_application_not_recognized, m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		break;
	}
	case udif_command_action_user_enable:
	{
		/* user login */
		if (udif_server_user_login(&m_ura_application_state) == true)
		{
			if (ura_server_load_root() == true)
			{
				m_ura_application_state.joined = ura_server_load_ads();
			}
		}
		else
		{
			udif_ura_stop_server();
			udif_menu_print_predefined_message(udif_application_retries_exceeded, m_ura_application_state.mode, m_ura_application_state.hostname);
			udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);
			qsc_consoleutils_get_char();
		}

		break;
	}
	case udif_command_action_user_help:
	{
		/* show user help */
		udif_help_print_mode(m_ura_application_state.cmdprompt, udif_console_mode_user, m_ura_application_state.srvtype);

		break;
	}
	case udif_command_action_user_quit:
	{
		m_ura_command_loop_status = udif_server_loop_status_stopped;
		udif_server_state_unload(&m_ura_application_state);
		udif_menu_print_predefined_message(udif_application_application_quit, m_ura_application_state.mode, m_ura_application_state.hostname);
		udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);
		qsc_consoleutils_get_char();

		break;
	}
	case udif_command_action_none:
	{
		/* empty return, do nothing */
		break;
	}
	case udif_command_action_command_unrecognized:
	{
		/* partial command */
		udif_menu_print_predefined_message(udif_application_not_recognized, m_ura_application_state.mode, m_ura_application_state.hostname);
		udif_help_print_mode(m_ura_application_state.cmdprompt, m_ura_application_state.mode, m_ura_application_state.srvtype);
		break;
	}
	default:
	{
		udif_help_print_mode(m_ura_application_state.cmdprompt, m_ura_application_state.mode, m_ura_application_state.srvtype);
	}
	}
}

static void ura_idle_timer(void)
{
	const uint32_t MMSEC = 60U * 1000U;

	while (true)
	{
		qsc_async_thread_sleep(MMSEC);
		qsc_mutex mtx = qsc_async_mutex_lock_ex();

		if (m_ura_application_state.mode != udif_console_mode_user)
		{
			++m_ura_idle_timer;

			if (m_ura_idle_timer >= m_ura_application_state.timeout)
			{
				udif_server_user_logout(&m_ura_application_state);
				m_ura_idle_timer = 0;
				qsc_consoleutils_print_line("");
				udif_menu_print_predefined_message(udif_application_console_timeout_expired, m_ura_application_state.mode, m_ura_application_state.hostname);
				udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	};
}

static void ura_command_loop(char* command)
{
	UDIF_ASSERT(command != NULL);

	m_ura_command_loop_status = udif_server_loop_status_started;

	while (true)
	{
		qsc_consoleutils_get_line(command, QSC_CONSOLE_MAX_LINE);

		/* lock the mutex */
		qsc_mutex mtx = qsc_async_mutex_lock_ex();
		m_ura_idle_timer = 0U;
		qsc_async_mutex_unlock_ex(mtx);

		ura_set_command_action(command);
		ura_command_execute(command);
		ura_get_command_mode(command);

		udif_server_set_command_prompt(&m_ura_application_state);
		udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);
		qsc_stringutils_clear_string(command);

		if (m_ura_command_loop_status == udif_server_loop_status_paused)
		{
			qsc_async_thread_sleep(UDIF_STORAGE_SERVER_PAUSE_INTERVAL);
			continue;
		}
		else if (m_ura_command_loop_status == udif_server_loop_status_stopped)
		{
			break;
		}
	}

	ura_server_dispose();
}

void udif_ura_pause_server(void)
{
	m_ura_command_loop_status = udif_server_loop_status_paused;
}

void udif_ura_start_server(void)
{
	char command[QSC_CONSOLE_MAX_LINE] = { 0 };
	qsc_thread idle;

	/* initialize the server */
	udif_server_state_initialize(&m_ura_application_state, udif_network_designation_ura);

	/* set the window parameters */
	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_size(1000, 600);
	qsc_consoleutils_set_window_title(m_ura_application_state.wtitle);

	/* application banner */
	udif_server_print_banner(&m_ura_application_state);

	/* load the command prompt */
	ura_get_command_mode(command);
	udif_menu_print_prompt(m_ura_application_state.mode, m_ura_application_state.hostname);

	/* start the idle timer */
	m_ura_idle_timer = 0U;
	idle = qsc_async_thread_create_noargs(&ura_idle_timer);

	if(idle)
	{
		/* command loop */
		ura_command_loop(command);
	}
}

void udif_ura_stop_server(void)
{
	m_ura_command_loop_status = udif_server_loop_status_stopped;
}

#if defined(UDIF_DEBUG_TESTS_RUN)
bool udif_ura_appserv_test(void)
{
	return false;
}
#endif
