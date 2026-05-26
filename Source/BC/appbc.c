/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 * QRCS-PREL, 2025-2026. Non-commercial evaluation use only.
 * Written by: John G. Underhill  Contact: contact@qrcscorp.ca
 */

/*!
 * \file appbc.c
 * \brief UDIF BC application entry point.
 *
 * The entire application starts here. All logic lives in the UDIF
 * static library (bc.c). This file is the sole source in the
 * Visual Studio console project for the BC entity.
 */

//#include "appbc.h"
#include "bc.h"

int main(void)
{
	udif_bc_start_server();

	return 0;
}
