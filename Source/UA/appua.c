/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 * QRCS-PREL, 2025-2026. Non-commercial evaluation use only.
 * Written by: John G. Underhill  Contact: contact@qrcscorp.ca
 */

/*!
 * \file appua.c
 * \brief UDIF UA application entry point.
 *
 * The entire application starts here. All logic lives in the UDIF
 * static library (ua.c). This file is the sole source in the
 * Visual Studio console project for the UA entity.
 */

//#include "appua.h"
#include "ua.h"

int main(void)
{
	udif_ua_start_server();

	return 0;
}
