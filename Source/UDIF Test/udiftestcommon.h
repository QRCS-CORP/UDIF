#ifndef UDIF_TEST_COMMON_H
#define UDIF_TEST_COMMON_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "consoleutils.h"

/*!
* \def UDIF_TEST_ASSERT
* \brief Assertion macro for debug builds
*/
#if defined(_DEBUG)
#	include <assert.h>
#	define UDIF_TEST_ASSERT(x) assert(x)
#else
#	define UDIF_TEST_ASSERT(x)
#endif

#endif
