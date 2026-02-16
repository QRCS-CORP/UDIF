#include "udif_test.h"
#include "anchor_test.h"
#include "capability_test.h"
#include "certificate_test.h"
#include "mcelmgr_test.h"
#include "object_test.h"
#include "query_test.h"
#include "registry_test.h"
#include "treaty_test.h"
#include "consoleutils.h"
#include "stringutils.h"


static void udif_test_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
		}
	}
}

static void print_title(void)
{
	udif_test_print_message("*****************************************************");
	udif_test_print_message("* UDIF: Universal Digital Identity Framework Tests	 *");
	udif_test_print_message("*                                                   *");
	udif_test_print_message("* Release:   v1.0.0.0 (A1)                          *");
	udif_test_print_message("* License:   QRCS-PL                                *");
	udif_test_print_message("* Date:      February 17, 2026                      *");
	udif_test_print_message("* Contact:   contact@qrcscorp.ca                    *");
	udif_test_print_message("*****************************************************");
	udif_test_print_message("");
}

bool udif_test_suite_run(void)
{
	bool res;

	res = anchor_test_run();
	res &= capability_test_run();
	res &= certificate_test_run();
	res &= mcelmgr_test_run();
	res &= object_test_run();
	res &= query_test_run();
	res &= registry_test_run();
	res &= treaty_test_run();

	return res;
}

int main(void)
{
	print_title();

	udif_test_print_message("Testing the UDIF internal functions.");
	udif_test_print_message("");

	if (udif_test_suite_run() == true)
	{
		udif_test_print_message("Success! The UDIF internal functions tests have passed.");
	}
	else
	{
		udif_test_print_message("Failure! The UDIF internal functions tests have failed");
	}

	udif_test_print_message("");
	udif_test_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}