#include "certificate_test.h"
#include "certificate.h"
#include "udif.h"
#include "csp.h"
#include "memutils.h"
#include "timestamp.h"

static bool certificate_test_generate_root(void)
{
	udif_certificate rcert = { 0U };
	udif_signature_keypair kp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	const char* pstr;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;

	/* set certificate expiration time */
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	/* generate test serial */
	qsc_csp_generate(serial, UDIF_SERIAL_NUMBER_SIZE);

	/* generate root certificate */
	err = udif_certificate_root_generate(&rcert, &kp, serial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		if (rcert.role == (uint8_t)udif_role_root)
		{
			if (qsc_memutils_are_equal(rcert.serial, serial, UDIF_SERIAL_NUMBER_SIZE) == true)
			{
				if (udif_certificate_verify(&rcert, &rcert) == true)
				{
					res = true;
				}
				else
				{
					qsc_consoleutils_print_line("Error: Root certificate Rsignature verification failed.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("Error: Root certificate role is incorrect.");
			}
		}
		else
		{
			qsc_consoleutils_print_line("Error: Root certificate serial number is incorrect.");
		}
	}
	else
	{
		qsc_consoleutils_print_line("Root certificate generation test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

	udif_certificate_clear(&rcert);
	qsc_memutils_clear((uint8_t*)&kp, sizeof(udif_signature_keypair));

	return res;
}

static bool certificate_test_generate_subordinate(void)
{
	udif_certificate rcert = { 0U };
	udif_certificate ccert = { 0U };
	udif_signature_keypair rkp = { 0U };
	udif_signature_keypair ckp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t root_serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t branch_serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capability[UDIF_CAPABILITY_BITMAP_SIZE] = { 0U };
	const char* pstr;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;

	/* set certificate expiration time */
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	/* generate root */
	qsc_csp_generate(root_serial, UDIF_SERIAL_NUMBER_SIZE);
	err = udif_certificate_root_generate(&rcert, &rkp, root_serial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		/* generate branch */
		qsc_csp_generate(branch_serial, UDIF_SERIAL_NUMBER_SIZE);
		qsc_memutils_clear(capability, UDIF_CAPABILITY_BITMAP_SIZE);
		/* grant all capabilities */
		capability[0U] = 0xFF;

		err = udif_certificate_generate(&ccert, &ckp, &rcert, rkp.sigkey, udif_role_uip, branch_serial, &vt, capability, 1U, qsc_csp_generate);

		if (err == udif_error_none)
		{
			if (ccert.role == udif_role_uip)
			{
				if (qsc_memutils_are_equal(ccert.issuer, root_serial, UDIF_SERIAL_NUMBER_SIZE) == true)
				{
					if (udif_certificate_verify(&ccert, &rcert) == true)
					{
						res = true;
					}
					else
					{
						qsc_consoleutils_print_line("UIP child certificate signature is invalid.");
					}
				}
				else
				{
					qsc_consoleutils_print_line("UIP child certificate issuer serial mismatch.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("UIP child certificate role designation is incorrect.");
			}
		}
		else
		{
			qsc_consoleutils_print_line("UIP child certificate generation test failed with error: ");
			pstr = udif_error_to_string(err);
			qsc_consoleutils_print_line(pstr);
		}
	}
	else
	{
		qsc_consoleutils_print_line("UIP child certificate generation test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

	udif_certificate_clear(&rcert);
	udif_certificate_clear(&ccert);

	qsc_memutils_clear((uint8_t*)&rkp, sizeof(udif_signature_keypair));
	qsc_memutils_clear((uint8_t*)&ckp, sizeof(udif_signature_keypair));

	return res;
}

static bool certificate_test_verify_chain(void)
{
	udif_certificate cert1 = { 0U };
	udif_certificate cert2 = { 0U };
	udif_certificate cert3 = { 0U };
	udif_signature_keypair kps1 = { 0U };
	udif_signature_keypair kps2 = { 0U };
	udif_signature_keypair kps3 = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t serial1[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t serial2[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t serial3[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t capability[UDIF_CAPABILITY_BITMAP_SIZE] = { 0U };
	const char* pstr;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	/* setup capability bitmap */
	qsc_memutils_clear(capability, UDIF_CAPABILITY_BITMAP_SIZE);
	capability[0U] = 0xFF;

	/* generate root */
	qsc_csp_generate(serial1, UDIF_SERIAL_NUMBER_SIZE);
	err = udif_certificate_root_generate(&cert1, &kps1, serial1, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		/* generate branch */
		qsc_csp_generate(serial2, UDIF_SERIAL_NUMBER_SIZE);
		err = udif_certificate_generate(&cert2, &kps2, &cert1, kps1.sigkey, udif_role_uip, serial2, &vt, capability, 1, qsc_csp_generate);

		if (err == udif_error_none)
		{
			/* generate UA */
			qsc_csp_generate(serial3, UDIF_SERIAL_NUMBER_SIZE);
			err = udif_certificate_generate(&cert3, &kps3, &cert2, kps2.sigkey, udif_role_uis, serial3, &vt, capability, 1, qsc_csp_generate);

			if (err == udif_error_none)
			{
				if (udif_certificate_verify_chain(&cert2, &cert1) == true)
				{
					if (udif_certificate_verify_chain(&cert3, &cert2) == true)
					{
						res = true;
					}
					else
					{
						qsc_consoleutils_print_line("UIP to UIS chain verification failed.");
					}
				}
				else
				{
					qsc_consoleutils_print_line("Root to UIP chain verification failed.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("UIS certificate generation test failed with error: ");
				pstr = udif_error_to_string(err);
				qsc_consoleutils_print_line(pstr);
			}
		}
		else
		{
			qsc_consoleutils_print_line("UIP certificate generation test failed with error: ");
			pstr = udif_error_to_string(err);
			qsc_consoleutils_print_line(pstr);
		}
	}
	else
	{
		qsc_consoleutils_print_line("Root certificate generation test failed with error: ");
		pstr = udif_error_to_string(err);
		qsc_consoleutils_print_line(pstr);
	}

	return res;
}

bool certificate_test_run(void)
{
	bool res;

	res = true;

	if (certificate_test_generate_root() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate root creation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate root creation test has failed.");
		res = false;
	}

	if (certificate_test_generate_subordinate() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate branch creation test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate branch creation test has failed.");
		res = false;
	}

	if (certificate_test_verify_chain() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate chaining test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate chaining test has failed.");
		res = false;
	}

	return res;
}
