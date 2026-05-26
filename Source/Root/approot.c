/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 * QRCS-PREL, 2025-2026. Non-commercial evaluation use only.
 * Written by: John G. Underhill  Contact: contact@qrcscorp.ca
 */

/*!
 * \file approot.c
 * \brief UDIF ROOT application entry point.
 *
 * The entire application starts here. All logic lives in the UDIF
 * static library (root.c). This file is the sole source in the
 * Visual Studio console project for the ROOT entity.
 */

#include "root.h"

int main(void)
{
	udif_root_start_server();

	return 0;
}
