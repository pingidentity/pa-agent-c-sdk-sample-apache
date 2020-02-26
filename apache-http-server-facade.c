/*****************************************************
 * Copyright (C) 2020 Ping Identity Corporation
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
 * https://www.pingidentity.com
 *
 ****************************************************/

/**
 * PAA HTTP server facade implementation for Apache
 *
 * @file apache-http-server-facade.c
 */

#include "util_filter.h"
#include "http_protocol.h"

#include "paa-log.h"
#include "paa-util.h"

#include "apache-http-server-facade.h"

/* Equivalent of ASCII "AP24" */
#if (MODULE_MAGIC_COOKIE == 0x41503234UL)
  #define APACHE24

/* Equivalent of ASCII "AP22" */
#elif (MODULE_MAGIC_COOKIE == 0x41503232UL)
  #define APACHE22

#endif

const char * const APACHE_MSGID = "PAA_APACHE";

static const size_t READ_FAILURE = (size_t)-1;

static
size_t read_cb(unsigned char *dst, size_t size, void *data)
{
    apache_client_req *req_wrapper;
    apr_bucket_brigade *brigade;
    size_t size_written, write_buffer_len;
    request_rec *rec;

    req_wrapper = (apache_client_req *)data;
    rec = req_wrapper->rec;

    if (req_wrapper->eos_reached) {
        // This handles the case where end-of-stream was reached, but data was written during
        // that callback invocation
        return 0;
    }

    write_buffer_len = size;
    size_written = 0;
    do {
        apr_status_t result;
        apr_bucket *bucket;
        apr_size_t left_to_write = write_buffer_len - size_written;

        brigade = apr_brigade_create(rec->pool, rec->connection->bucket_alloc);
        if (brigade == NULL) {
            paa_log(rec->pool, APACHE_MSGID, PAA_ERROR,
                    "failed to create brigade to read client request body");
            size_written = READ_FAILURE;
            break;
        }

        result = ap_get_brigade(rec->input_filters, brigade, AP_MODE_READBYTES,
                APR_BLOCK_READ, left_to_write);
        if (result != APR_SUCCESS) {
            paa_log_error(rec->pool, APACHE_MSGID, PAA_ERROR, result,
                    "failed to obtain input brigade to read client request body");
            size_written = READ_FAILURE;
            apr_brigade_destroy(brigade);
            break;
        }

        for (bucket = APR_BRIGADE_FIRST(brigade);
                bucket != APR_BRIGADE_SENTINEL(brigade);
                bucket = APR_BUCKET_NEXT(bucket))
        {
            if (APR_BUCKET_IS_EOS(bucket)) {
                req_wrapper->eos_reached = 1;
                break;
            }

            // Need to ignore metadata
            if (APR_BUCKET_IS_METADATA(bucket)) {
                continue;
            }

            const char *bucket_buf = NULL;
            size_t actual_read = 0;
            result = apr_bucket_read(bucket, &bucket_buf, &actual_read, APR_BLOCK_READ);
            if (result != APR_SUCCESS) {
                paa_log_error(rec->pool, APACHE_MSGID, PAA_ERROR, result,
                        "failed to read client request body data");
                size_written = READ_FAILURE;
                break;
            }

            // Sanity check: even though a specific amount was requested in ap_get_brigade,
            // make sure that more data wasn't allocated than requested
            if (actual_read > write_buffer_len) {
                paa_log(rec->pool, APACHE_MSGID, PAA_ERROR, "more data available than requested");
                size_written = READ_FAILURE;
                break;
            }else{
                memcpy(dst, bucket_buf, actual_read); 
            }

            size_written += actual_read;
        }
        // Cleanup the data used by the current brigade
        apr_brigade_destroy(brigade);
    }while(0);

    return size_written;
}

static
size_t agent_resp_apache_write_cb(const unsigned char *src, size_t size, void *userdata)
{
    request_rec *r = (request_rec *)userdata;
    size_t total_to_read = size;
    
    size_t size_read;
    if (total_to_read > 0) {
        do {
            apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
            if (bb == NULL) {
                paa_log(r->pool, APACHE_MSGID, PAA_ERROR,
                        "failed to create brigade to write agent response");

                size_read = 0;
                break;
            }
            
            apr_status_t result = ap_fwrite(r->output_filters, bb, (const char *)src,
                    total_to_read);
            if (result != APR_SUCCESS) {
                paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR, result,
                        "failed to write agent response data");
                size_read = 0;
                break;
            }

            result = ap_fflush(r->output_filters, bb);
            if (result != APR_SUCCESS) {
                paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR, result,
                        "failed to flush agent response data");
                size_read = 0;
                break;
            }

            size_read = total_to_read;
        }while(0);
    }else{
        size_read = 0;
    }

    return size_read;
}

static
inline
apache_client_req *req_impl(const paa_client_request *req)
{
    return ((apache_client_req *)req->impl);
}

static
inline
apache_client_resp *resp_impl(const paa_client_response *resp)
{
    return ((apache_client_resp *)resp->impl);
}

static
paa_client_response_write_cb client_response_get_write_cb(const paa_client_response *resp)
{
    USE(resp);

    return agent_resp_apache_write_cb;
}

static
void *client_response_get_write_data(const paa_client_response *resp)
{
    return resp_impl(resp)->rec;
}

static
paa_client_request_read_cb client_request_get_read_cb(const paa_client_request *req)
{
    USE(req);

    return read_cb;
}

static
void *client_request_get_read_data(const paa_client_request *req)
{
    return req_impl(req);
}

static
const char *client_request_get_method(const paa_client_request *req)
{
    return req_impl(req)->rec->method;
}

static
const char *client_request_get_normalized_uri(const paa_client_request *req)
{
    return req_impl(req)->full_normalized_uri;
}

static
const char *client_request_get_raw_uri(const paa_client_request *req)
{
    return req_impl(req)->rec->unparsed_uri;
}

static
const char *client_request_get_remote_ip(const paa_client_request *req)
{
    char *ip = 
    #ifdef APACHE24
        req_impl(req)->rec->connection->client_ip;
    #else
        req_impl(req)->rec->connection->remote_ip;
    #endif

    return ip;
}

static
const char *client_request_get_scheme(const paa_client_request *req)
{
    return ap_http_scheme(req_impl(req)->rec);
}

static
const char *client_request_get_scope(const paa_client_request *req)
{
    USE(req);
    return "";
}

struct client_req_iter_data
{
    paa_header_cb cb;
    void *userdata;
    apr_status_t result;
};

static
int client_request_header_iter(void *reqdata, const char *key, const char *value)
{
    apr_status_t result;
    struct client_req_iter_data *iter_data;
    
    iter_data = (struct client_req_iter_data *)reqdata;

    result = iter_data->cb(key, value, iter_data->userdata);
    if (result != APR_EAGAIN) {
        iter_data->result = result;
        return 0;
    }

    iter_data->result = APR_SUCCESS;
    return 1;
}

static
apr_status_t client_request_enumerate_headers(const paa_client_request *req, paa_header_cb cb,
        void *userdata)
{
    struct client_req_iter_data iter_data;
    iter_data.cb = cb;
    iter_data.userdata = userdata;
    iter_data.result = APR_SUCCESS;

    int iter_result = apr_table_do(client_request_header_iter, &iter_data,
            req_impl(req)->rec->headers_in, NULL);
    if (iter_result == 0) {  
        paa_log(req_impl(req)->rec->pool, APACHE_MSGID,
                PAA_DEBUG, "client request header callback returned early");
    }

    return iter_data.result;
}

// Note:
// The data passed to these functions is guaranteed to have the same lifetime as the request.
// This allows the apr_table_*n functions to be applied instead of their counterparts that copy
// the data.

static
apr_status_t client_request_get_header_values(const paa_client_request *req,
        const char *name,
        paa_header_cb cb,
        void *userdata)
{
    struct client_req_iter_data iter_data;
    iter_data.cb = cb;
    iter_data.userdata = userdata;
    iter_data.result = APR_SUCCESS;

    int iter_result = apr_table_do(client_request_header_iter, &iter_data,
            req_impl(req)->rec->headers_in, name, NULL);
    if (iter_result == 0) {  
        paa_log(req_impl(req)->rec->pool, APACHE_MSGID,
                PAA_TRACE, "client request header callback returned early");
    }

    return iter_data.result;
}

static
apr_status_t client_request_set_header(const paa_client_request *req, const char *name,
        const char *value)
{
    if (strcasecmp(name, HTTP_CONTENT_TYPE) == 0) {
        ap_set_content_type(req_impl(req)->rec, value);
    }

    apr_table_setn(req_impl(req)->rec->headers_in, name, value);

    return APR_SUCCESS;
}

static
apr_status_t client_request_add_header(const paa_client_request *req, const char *name,
        const char *value)
{
    if (strcasecmp(name, HTTP_CONTENT_TYPE) == 0) {
        // append does not make sense for Content-Type since an HTTP message can have only one
        // Content-Type -- appending will likely confuse Apache in unknown ways
        ap_set_content_type(req_impl(req)->rec, value);

        apr_table_setn(req_impl(req)->rec->headers_in, name, value);
    }else{
        apr_table_addn(req_impl(req)->rec->headers_in, name, value);

        if (strcasecmp(HTTP_COOKIE, name) == 0) {
            // Collapse the cookie headers into a single header field
            const char *cookie_value = paa_util_apr_table_getm(req_impl(req)->rec->pool,
                    req_impl(req)->rec->headers_in,
                    name,
                    ';');
            apr_table_setn(req_impl(req)->rec->headers_in, HTTP_COOKIE, cookie_value);
        }
    }

    return APR_SUCCESS;
}

static
apr_status_t client_request_set_req_var(const paa_client_request *req, const char *name,
        const char *value)
{
    apr_table_setn(req_impl(req)->rec->subprocess_env, name, value);

    return APR_SUCCESS;
}

static
apr_status_t client_request_remove_header(const paa_client_request *req, const char *name)
{
    apr_table_unset(req_impl(req)->rec->headers_in, name);

    return APR_SUCCESS;
}

static
apr_status_t client_request_remove_req_var(const paa_client_request *req, const char *name)
{
    apr_table_unset(req_impl(req)->rec->subprocess_env, name);

    return APR_SUCCESS;
}

static
apr_status_t client_request_set_user(const paa_client_request *req, const char *name)
{
    req_impl(req)->rec->user = (char *)name;

    return APR_SUCCESS;
}

static
const char *client_request_get_user(const paa_client_request *req)
{
    return req_impl(req)->rec->user;
}

static
apr_status_t client_response_replacing(const paa_client_response *resp)
{
    apr_table_clear(resp_impl(resp)->rec->headers_out);
    apr_table_clear(resp_impl(resp)->rec->err_headers_out);

    return APR_SUCCESS;
}

static
apr_status_t client_response_set_header(const paa_client_response *resp, const char *name,
        const char *value)
{
    if (strcasecmp(name, HTTP_CONTENT_TYPE) == 0) {
        ap_set_content_type(resp_impl(resp)->rec, value);
    }

    apr_table_setn(resp_impl(resp)->rec->headers_out, name, value);

    return APR_SUCCESS;
}

static
apr_status_t client_response_add_header(const paa_client_response *resp, const char *name,
        const char *value)
{
    if (strcasecmp(name, HTTP_CONTENT_TYPE) == 0) {
        // append does not make sense for Content-Type since a message can have only one
        // Content-Type -- appending will likely confuse Apache in unknown ways
        ap_set_content_type(resp_impl(resp)->rec, value);

        apr_table_setn(resp_impl(resp)->rec->headers_out, name, value);
    }else{
        apr_table_addn(resp_impl(resp)->rec->headers_out, name, value);
    }

    return APR_SUCCESS;
}

static
apr_status_t client_response_remove_header(const paa_client_response *resp, const char *name)
{
    if (strcasecmp(name, HTTP_CONTENT_TYPE) == 0) {
        ap_set_content_type(resp_impl(resp)->rec, NULL);
    }

    apr_table_unset(resp_impl(resp)->rec->headers_out, name);

    return APR_SUCCESS;
}

static
apr_status_t client_response_set_status(const paa_client_response *resp, int status,
        const char *reason)
{
    USE(reason);

    // Apache doesn't require that the reason string be set -- if unset, it will set it to the
    // standard value which is acceptable (and desired)
    resp_impl(resp)->rec->status = status;

    return APR_SUCCESS;
}

struct client_response_iter_data
{
    paa_header_cb cb;
    void *userdata;
    apr_status_t result;
};

static
int client_response_header_iter(void *reqdata, const char *key, const char *value)
{
    apr_status_t result;
    struct client_response_iter_data *iter_data;
    
    iter_data = (struct client_response_iter_data *)reqdata;

    result = iter_data->cb(key, value, iter_data->userdata);
    if (result != APR_EAGAIN) {
        iter_data->result = result;
        return 0;
    }

    iter_data->result = APR_SUCCESS;
    return 1;
}

static
apr_status_t 
client_response_enumerate_headers(const paa_client_response *resp, paa_header_cb cb,
        void *userdata)
{
    struct client_response_iter_data iter_data;
    iter_data.cb = cb;
    iter_data.userdata = userdata;
    iter_data.result = APR_SUCCESS;

    int iter_result = apr_table_do(client_response_header_iter, &iter_data,
            resp_impl(resp)->rec->headers_out, NULL);
    if (iter_result == 0) {  
        paa_log(resp_impl(resp)->rec->pool, APACHE_MSGID, PAA_DEBUG,
                "client response header callback returned early for standard headers");
    }

    iter_result = apr_table_do(client_response_header_iter, &iter_data,
            resp_impl(resp)->rec->err_headers_out, NULL);
    if (iter_result == 0) {
        paa_log(resp_impl(resp)->rec->pool, APACHE_MSGID, PAA_DEBUG,
                "client response header callback returned early for error headers");
    }

    return iter_data.result;
}

static
int client_response_get_status(const paa_client_response *resp)
{
    return resp_impl(resp)->rec->status;
}

void apache_client_req_init(paa_client_request *intf,
                            apache_client_req *impl)
{
    intf->impl = (void *)impl;
    intf->get_method = client_request_get_method;
    intf->get_normalized_uri = client_request_get_normalized_uri;
    intf->get_raw_uri = client_request_get_raw_uri;
    intf->get_remote_ip = client_request_get_remote_ip;
    intf->get_scheme = client_request_get_scheme;
    intf->get_scope = client_request_get_scope;
    intf->enumerate_headers = client_request_enumerate_headers;
    intf->get_header_values = client_request_get_header_values;
    intf->set_header = client_request_set_header;
    intf->add_header = client_request_add_header;
    intf->remove_header = client_request_remove_header;
    intf->set_req_var = client_request_set_req_var;
    intf->remove_req_var = client_request_remove_req_var;
    intf->set_user = client_request_set_user;
    intf->get_user = client_request_get_user;
    intf->get_read_cb = client_request_get_read_cb;
    intf->get_read_data = client_request_get_read_data;

}

void apache_client_resp_init(paa_client_response *intf,
                             apache_client_resp *impl)
{
    intf->impl = impl;
    intf->get_status = client_response_get_status;
    intf->set_header = client_response_set_header;
    intf->add_header = client_response_add_header;
    intf->remove_header = client_response_remove_header;
    intf->enumerate_headers = client_response_enumerate_headers;
    intf->replacing = client_response_replacing;
    intf->set_status = client_response_set_status;
    intf->get_write_cb = client_response_get_write_cb;
    intf->get_write_data = client_response_get_write_data;
}
