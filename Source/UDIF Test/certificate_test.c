#include "certificate_test.h"
#include "certificate.h"
#include "certstore.h"
#include "capability.h"
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
	uint64_t capability;
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
		capability = UDIF_ROOT_CAPABILITIES;

		err = udif_certificate_generate(&ccert, &ckp, &rcert, rkp.sigkey, udif_role_ubc, branch_serial, &vt, capability, 1U, qsc_csp_generate);

		if (err == udif_error_none)
		{
			if (ccert.role == udif_role_ubc)
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
	uint64_t capability;
	const char* pstr;
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	capability = UDIF_ROOT_CAPABILITIES;

	/* generate root */
	qsc_csp_generate(serial1, UDIF_SERIAL_NUMBER_SIZE);
	err = udif_certificate_root_generate(&cert1, &kps1, serial1, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		/* generate branch */
		qsc_csp_generate(serial2, UDIF_SERIAL_NUMBER_SIZE);
		err = udif_certificate_generate(&cert2, &kps2, &cert1, kps1.sigkey, udif_role_ubc, serial2, &vt, capability, 1, qsc_csp_generate);

		if (err == udif_error_none)
		{
			/* generate UA */
			qsc_csp_generate(serial3, UDIF_SERIAL_NUMBER_SIZE);
			err = udif_certificate_generate(&cert3, &kps3, &cert2, kps2.sigkey, udif_role_uor, serial3, &vt, capability, 1, qsc_csp_generate);

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


static bool certificate_test_csr_roundtrip(void)
{
	udif_certificate_csr csr1 = { 0U };
	udif_certificate_csr csr2 = { 0U };
	udif_signature_keypair kp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t enc[UDIF_CERTIFICATE_CSR_SIZE] = { 0U };
	uint8_t serial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	qsc_csp_generate(serial, sizeof(serial));
	udif_signature_generate_keypair(kp.verkey, kp.sigkey, qsc_csp_generate);

	err = udif_certificate_csr_create(&csr1, serial, kp.verkey, kp.sigkey, udif_role_ubc, &vt,
		UDIF_ROOT_CAPABILITIES, UDIF_BC_POLICY_DEFAULT, ctime, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_serialize(enc, sizeof(enc), &csr1);
	}

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_deserialize(&csr2, enc, sizeof(enc));
	}

	if (err == udif_error_none)
	{
		res = udif_certificate_csr_verify(&csr2);
	}

	qsc_memutils_clear((uint8_t*)&kp, sizeof(kp));

	return res;
}

static bool certificate_test_csr_issue(void)
{
	udif_certificate rootcert = { 0U };
	udif_certificate childcert = { 0U };
	udif_certificate_csr csr = { 0U };
	udif_signature_keypair rootkp = { 0U };
	udif_signature_keypair childkp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t rootserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t childserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	qsc_csp_generate(rootserial, sizeof(rootserial));
	qsc_csp_generate(childserial, sizeof(childserial));

	err = udif_certificate_root_generate(&rootcert, &rootkp, rootserial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		udif_signature_generate_keypair(childkp.verkey, childkp.sigkey, qsc_csp_generate);
		err = udif_certificate_csr_create(&csr, childserial, childkp.verkey, childkp.sigkey,
			udif_role_ubc, &vt, UDIF_ROOT_CAPABILITIES, UDIF_BC_POLICY_DEFAULT, ctime, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_issue(&childcert, &csr, &rootcert, rootkp.sigkey, ctime, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		res = udif_certificate_verify_chain(&childcert, &rootcert);
	}

	qsc_memutils_clear((uint8_t*)&rootkp, sizeof(rootkp));
	qsc_memutils_clear((uint8_t*)&childkp, sizeof(childkp));

	return res;
}

static bool certificate_test_csr_reject_role(void)
{
	udif_certificate gccert = { 0U };
	udif_certificate childcert = { 0U };
	udif_certificate_csr csr = { 0U };
	udif_signature_keypair gckp = { 0U };
	udif_signature_keypair childkp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t gcserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t childserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	qsc_csp_generate(gcserial, sizeof(gcserial));
	qsc_csp_generate(childserial, sizeof(childserial));
	udif_signature_generate_keypair(gckp.verkey, gckp.sigkey, qsc_csp_generate);
	udif_signature_generate_keypair(childkp.verkey, childkp.sigkey, qsc_csp_generate);

	qsc_memutils_clear((uint8_t*)&gccert, sizeof(gccert));
	qsc_memutils_copy(gccert.serial, gcserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_memutils_copy(gccert.issuer, gcserial, UDIF_SERIAL_NUMBER_SIZE);
	qsc_memutils_copy(gccert.verkey, gckp.verkey, UDIF_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	gccert.valid.from = vt.from;
	gccert.valid.to = vt.to;
	gccert.capability = UDIF_GC_CAPABILITIES;
	gccert.policy = UDIF_GC_POLICY_DEFAULT;
	gccert.role = udif_role_ugc;
	gccert.suiteid = UDIF_SUITE_ID;
	err = udif_certificate_sign(&gccert, gckp.sigkey, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_create(&csr, childserial, childkp.verkey, childkp.sigkey,
			udif_role_ubc, &vt, UDIF_GC_CAPABILITIES, UDIF_BC_POLICY_DEFAULT, ctime, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		err = udif_certificate_csr_issue(&childcert, &csr, &gccert, gckp.sigkey, ctime, qsc_csp_generate);
		res = (err == udif_error_not_authorized);
	}

	qsc_memutils_clear((uint8_t*)&gckp, sizeof(gckp));
	qsc_memutils_clear((uint8_t*)&childkp, sizeof(childkp));

	return res;
}


static bool certificate_test_status_store(void)
{
	udif_certstore* store;
	udif_certificate rootcert = { 0U };
	udif_certificate childcert = { 0U };
	udif_signature_keypair rootkp = { 0U };
	udif_signature_keypair childkp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t rootserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t childserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	store = NULL;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	store = (udif_certstore*)qsc_memutils_malloc(sizeof(udif_certstore));

	if (store != NULL)
	{
		udif_certstore_initialize(store);
	}
	qsc_csp_generate(rootserial, sizeof(rootserial));
	qsc_csp_generate(childserial, sizeof(childserial));

	err = (store == NULL) ? udif_error_internal :
		udif_certificate_root_generate(&rootcert, &rootkp, rootserial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_generate(&childcert, &childkp, &rootcert, rootkp.sigkey,
			udif_role_ubc, childserial, &vt, UDIF_ROOT_CAPABILITIES, UDIF_BC_POLICY_DEFAULT, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &rootcert, udif_certstore_status_active, ctime);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &childcert, udif_certstore_status_active, ctime);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_verify_certificate(store, childserial, ctime);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_set_status(store, childserial, udif_certstore_status_suspended, ctime);
	}

	if (err == udif_error_none)
	{
		res = (udif_certstore_validate_status(store, childserial, ctime) == udif_error_not_authorized);
	}

	if (res == true)
	{
		err = udif_certstore_set_status(store, childserial, udif_certstore_status_revoked, ctime);

		if (err == udif_error_none)
		{
			res = (udif_certstore_validate_status(store, childserial, ctime) == udif_error_certificate_revoked);
		}
		else
		{
			res = false;
		}
	}

	if (store != NULL)
	{
		udif_certstore_clear(store);
		qsc_memutils_alloc_free(store);
	}
	qsc_memutils_clear((uint8_t*)&rootkp, sizeof(rootkp));
	qsc_memutils_clear((uint8_t*)&childkp, sizeof(childkp));

	return res;
}

static bool certificate_test_recursive_status_store(void)
{
	udif_certstore* store;
	udif_certificate* rootcert;
	udif_certificate* branchcert;
	udif_certificate* gccert;
	udif_certificate* clientcert;
	udif_signature_keypair* rootkp;
	udif_signature_keypair* branchkp;
	udif_signature_keypair* gckp;
	udif_signature_keypair* clientkp;
	udif_valid_time vt = { 0U };
	uint8_t rootserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t branchserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t gcserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t clientserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	store = NULL;
	rootcert = NULL;
	branchcert = NULL;
	gccert = NULL;
	clientcert = NULL;
	rootkp = NULL;
	branchkp = NULL;
	gckp = NULL;
	clientkp = NULL;

	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	store = (udif_certstore*)qsc_memutils_malloc(sizeof(udif_certstore));
	rootcert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	branchcert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	gccert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	clientcert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	rootkp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	branchkp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	gckp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	clientkp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));

	if (store != NULL && rootcert != NULL && branchcert != NULL && gccert != NULL && clientcert != NULL &&
		rootkp != NULL && branchkp != NULL && gckp != NULL && clientkp != NULL)
	{
		udif_certstore_initialize(store);
		qsc_memutils_clear((uint8_t*)rootcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)branchcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)gccert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)clientcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)rootkp, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)branchkp, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)gckp, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)clientkp, sizeof(udif_signature_keypair));

		qsc_csp_generate(rootserial, sizeof(rootserial));
		qsc_csp_generate(branchserial, sizeof(branchserial));
		qsc_csp_generate(gcserial, sizeof(gcserial));
		qsc_csp_generate(clientserial, sizeof(clientserial));

		err = udif_certificate_root_generate(rootcert, rootkp, rootserial, &vt, qsc_csp_generate);

		if (err == udif_error_none)
		{
			err = udif_certificate_generate(branchcert, branchkp, rootcert, rootkp->sigkey,
				udif_role_ubc, branchserial, &vt, rootcert->capability, UDIF_BC_POLICY_DEFAULT, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_certificate_generate(gccert, gckp, branchcert, branchkp->sigkey,
				udif_role_ugc, gcserial, &vt, branchcert->capability, UDIF_GC_POLICY_DEFAULT, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_certificate_generate(clientcert, clientkp, gccert, gckp->sigkey,
				udif_role_client, clientserial, &vt, gccert->capability, UDIF_CLIENT_POLICY_DEFAULT, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, rootcert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, branchcert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, gccert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, clientcert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_verify_certificate(store, clientserial, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_set_status(store, branchserial, udif_certstore_status_revoked, ctime);
		}

		if (err == udif_error_none)
		{
			res = (udif_certstore_get_status(store, gcserial) == udif_certstore_status_revoked &&
				udif_certstore_get_status(store, clientserial) == udif_certstore_status_revoked &&
				udif_certstore_verify_certificate(store, clientserial, ctime) == udif_error_certificate_revoked);
		}
	}

	if (store != NULL)
	{
		udif_certstore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	if (rootcert != NULL)
	{
		qsc_memutils_alloc_free(rootcert);
	}

	if (branchcert != NULL)
	{
		qsc_memutils_alloc_free(branchcert);
	}

	if (gccert != NULL)
	{
		qsc_memutils_alloc_free(gccert);
	}

	if (clientcert != NULL)
	{
		qsc_memutils_alloc_free(clientcert);
	}

	if (rootkp != NULL)
	{
		qsc_memutils_alloc_free(rootkp);
	}

	if (branchkp != NULL)
	{
		qsc_memutils_alloc_free(branchkp);
	}

	if (gckp != NULL)
	{
		qsc_memutils_alloc_free(gckp);
	}

	if (clientkp != NULL)
	{
		qsc_memutils_alloc_free(clientkp);
	}

	return res;
}


static bool certificate_test_revoked_status_is_irreversible(void)
{
	udif_certstore* store;
	udif_certificate rootcert = { 0U };
	udif_certificate childcert = { 0U };
	udif_signature_keypair rootkp = { 0U };
	udif_signature_keypair childkp = { 0U };
	udif_valid_time vt = { 0U };
	uint8_t rootserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t childserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	store = NULL;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	store = (udif_certstore*)qsc_memutils_malloc(sizeof(udif_certstore));

	if (store != NULL)
	{
		udif_certstore_initialize(store);
	}

	qsc_csp_generate(rootserial, sizeof(rootserial));
	qsc_csp_generate(childserial, sizeof(childserial));

	err = (store == NULL) ? udif_error_internal :
		udif_certificate_root_generate(&rootcert, &rootkp, rootserial, &vt, qsc_csp_generate);

	if (err == udif_error_none)
	{
		err = udif_certificate_generate(&childcert, &childkp, &rootcert, rootkp.sigkey,
			udif_role_ubc, childserial, &vt, UDIF_ROOT_CAPABILITIES, UDIF_BC_POLICY_DEFAULT, qsc_csp_generate);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &rootcert, udif_certstore_status_active, ctime);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_add(store, &childcert, udif_certstore_status_active, ctime);
	}

	if (err == udif_error_none)
	{
		err = udif_certstore_set_status(store, childserial, udif_certstore_status_revoked, ctime);
	}

	if (err == udif_error_none)
	{
		/* Revocation is permanent; resume must not restore the same certificate to active. */
		err = udif_certstore_set_status(store, childserial, udif_certstore_status_active, ctime);
		res = (err != udif_error_none &&
			udif_certstore_get_status(store, childserial) == udif_certstore_status_revoked &&
			udif_certstore_validate_status(store, childserial, ctime) == udif_error_certificate_revoked);
	}

	if (store != NULL)
	{
		udif_certstore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	qsc_memutils_clear((uint8_t*)&rootkp, sizeof(rootkp));
	qsc_memutils_clear((uint8_t*)&childkp, sizeof(childkp));

	return res;
}

static bool certificate_test_suspended_parent_blocks_active_child(void)
{
	udif_certstore* store;
	udif_certificate* rootcert;
	udif_certificate* branchcert;
	udif_certificate* gccert;
	udif_signature_keypair* rootkp;
	udif_signature_keypair* branchkp;
	udif_signature_keypair* gckp;
	udif_valid_time vt = { 0U };
	uint8_t rootserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t branchserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint8_t gcserial[UDIF_SERIAL_NUMBER_SIZE] = { 0U };
	uint64_t ctime;
	udif_errors err;
	bool res;

	res = false;
	store = NULL;
	rootcert = NULL;
	branchcert = NULL;
	gccert = NULL;
	rootkp = NULL;
	branchkp = NULL;
	gckp = NULL;
	ctime = qsc_timestamp_datetime_utc();
	vt.from = ctime;
	vt.to = ctime + UDIF_CERTIFICATE_DEFAULT_PERIOD;

	store = (udif_certstore*)qsc_memutils_malloc(sizeof(udif_certstore));
	rootcert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	branchcert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	gccert = (udif_certificate*)qsc_memutils_malloc(sizeof(udif_certificate));
	rootkp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	branchkp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));
	gckp = (udif_signature_keypair*)qsc_memutils_malloc(sizeof(udif_signature_keypair));

	if (store != NULL && rootcert != NULL && branchcert != NULL && gccert != NULL &&
		rootkp != NULL && branchkp != NULL && gckp != NULL)
	{
		udif_certstore_initialize(store);
		qsc_memutils_clear((uint8_t*)rootcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)branchcert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)gccert, sizeof(udif_certificate));
		qsc_memutils_clear((uint8_t*)rootkp, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)branchkp, sizeof(udif_signature_keypair));
		qsc_memutils_clear((uint8_t*)gckp, sizeof(udif_signature_keypair));

		qsc_csp_generate(rootserial, sizeof(rootserial));
		qsc_csp_generate(branchserial, sizeof(branchserial));
		qsc_csp_generate(gcserial, sizeof(gcserial));

		err = udif_certificate_root_generate(rootcert, rootkp, rootserial, &vt, qsc_csp_generate);

		if (err == udif_error_none)
		{
			err = udif_certificate_generate(branchcert, branchkp, rootcert, rootkp->sigkey,
				udif_role_ubc, branchserial, &vt, rootcert->capability, UDIF_BC_POLICY_DEFAULT, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_certificate_generate(gccert, gckp, branchcert, branchkp->sigkey,
				udif_role_ugc, gcserial, &vt, branchcert->capability, UDIF_GC_POLICY_DEFAULT, qsc_csp_generate);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, rootcert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, branchcert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_add(store, gccert, udif_certstore_status_active, ctime);
		}

		if (err == udif_error_none)
		{
			err = udif_certstore_set_status(store, branchserial, udif_certstore_status_suspended, ctime);
		}

		if (err == udif_error_none)
		{
			res = (udif_certstore_get_status(store, gcserial) == udif_certstore_status_active &&
				udif_certstore_verify_certificate(store, gcserial, ctime) == udif_error_not_authorized);
		}
	}

	if (store != NULL)
	{
		udif_certstore_clear(store);
		qsc_memutils_alloc_free(store);
	}

	if (rootcert != NULL)
	{
		qsc_memutils_alloc_free(rootcert);
	}

	if (branchcert != NULL)
	{
		qsc_memutils_alloc_free(branchcert);
	}

	if (gccert != NULL)
	{
		qsc_memutils_alloc_free(gccert);
	}

	if (rootkp != NULL)
	{
		qsc_memutils_alloc_free(rootkp);
	}

	if (branchkp != NULL)
	{
		qsc_memutils_alloc_free(branchkp);
	}

	if (gckp != NULL)
	{
		qsc_memutils_alloc_free(gckp);
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

	if (certificate_test_csr_roundtrip() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate CSR roundtrip test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate CSR roundtrip test has failed.");
		res = false;
	}

	if (certificate_test_csr_issue() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate CSR issue test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate CSR issue test has failed.");
		res = false;
	}

	if (certificate_test_csr_reject_role() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate CSR role rejection test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate CSR role rejection test has failed.");
		res = false;
	}

	if (certificate_test_status_store() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate status store test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate status store test has failed.");
		res = false;
	}

	if (certificate_test_recursive_status_store() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate recursive status store test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate recursive status store test has failed.");
		res = false;
	}

	if (certificate_test_revoked_status_is_irreversible() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate revoked status irreversible test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate revoked status irreversible test has failed.");
		res = false;
	}

	if (certificate_test_suspended_parent_blocks_active_child() == true)
	{
		qsc_consoleutils_print_line("Success! Certificate suspended parent blocks child test has passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Certificate suspended parent blocks child test has failed.");
		res = false;
	}

	return res;
}
