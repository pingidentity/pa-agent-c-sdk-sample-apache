/*
 * ***************************************************
 *  Copyright (C) 2016 Ping Identity Corporation
 *  All rights reserved.
 *
 *  The contents of this file are the property of Ping Identity Corporation.
 *  You may not copy or use this file, in either source code or executable
 *  form, except in compliance with terms set by Ping Identity Corporation.
 *  For further information please contact:
 *
 *  Ping Identity Corporation
 *  1099 18th St Suite 2950
 *  Denver, CO 80202
 *  303.468.2900
 *  http://www.pingidentity.com
 * *****************************************************
 */

/**
 * Header for Apache implementation of the paa_client_request and 
 * paa_client_response interfaces.
 *
 * @file apache-http-server-facade.h
 */
#ifndef _APACHE_HTTP_SERVER_FACADE_H_
#define _APACHE_HTTP_SERVER_FACADE_H_ 1

#include "httpd.h"
#include "paa-http-server-facade.h"

/** Macro to explicitly avoid unused variable compiler warnings */
#define USE(x) ((void)x)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure that is the "impl" of the paa_client_request interface
 */
typedef struct apache_client_req_struct {
    /** The request record for the request currently being processed */
    request_rec *rec;

    /** 
     * The full normalized uri, cached for ease of access and simplified 
     * error handling
     */
    const char *full_normalized_uri;

    /** A flag indicating whether the end-of-stream has been reached */
    int eos_reached;
} apache_client_req;

/**
 * Initializes a paa_client_request structure to use the apache_client_req impl
 *
 * @param intf the interface
 * @param impl the implementation
 */
void apache_client_req_init(paa_client_request *intf,
        apache_client_req *impl);

/**
 * Structure that is the "impl" of the paa_client_response interface
 */
typedef struct apache_client_resp_struct {
    /** The request record for the request currently being processed */
    request_rec *rec;
} apache_client_resp;

/**
 * Initializes a paa_client_response structure to use the apache_client_resp 
 * impl
 *
 * @param intf the interface
 * @param impl the implementation
 */
void apache_client_resp_init(paa_client_response *intf, 
        apache_client_resp *impl);

/** The MSGID to pass to paa_log for the Apache PAA */
extern const char * const APACHE_MSGID;

#ifdef __cplusplus
} // "C"
#endif

#endif // _APACHE_HTTP_SERVER_FACADE_H_
