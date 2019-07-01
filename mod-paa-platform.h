/*****************************************************
 * Copyright (C) 2019 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * You may not copy or use this file, in either source code or executable
 * form, except in compliance with terms set by Ping Identity Corporation.
 * For further information please contact:
 *
 * Ping Identity Corporation
 * 1001 17th St Suite 100
 * Denver, CO 80202
 * 303.468.2900
 * http://www.pingidentity.com
 *
 ****************************************************/

/**
 * Platform-specific definitions
 *
 * @file mod-paa-platform.h
 */
#ifndef _MOD_PAA_PLATFORM_H_
#define _MOD_PAA_PLATFORM_H_ 1

#ifdef _WIN32

#include <io.h>

#define PRI64 "I64"

#define PRIu64 PRI64 "u"
#define PRId64 PRI64 "d"
#define PRIx64 PRI64 "x"

#define CMD_FUNC(func) ((cmd_func)func)

#else

#include <unistd.h>
#include <inttypes.h>

#define CMD_FUNC(func) (func)

#endif

#endif
