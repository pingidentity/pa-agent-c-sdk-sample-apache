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
 * PAA Apache module
 *
 * @file mod_paa.c
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "ap_mpm.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "apr_thread_proc.h"
#include "apr_base64.h"

#include "paa-log.h"
#include "paa-http-client-curl.h"
#include "paa-config-filesystem.h"
#include "paa-cache-zmq.h"
#include "paa-cache-standalone.h"
#include "paa.h"

#include "apache-http-server-facade.h"

#include "mod-paa-platform.h"

/* Equivalent of ASCII "AP24" */
#if (MODULE_MAGIC_COOKIE == 0x41503234UL)
  #define APACHE24

/* Equivalent of ASCII "AP22" */
#elif (MODULE_MAGIC_COOKIE == 0x41503232UL)
  #define APACHE22

#endif

// constants
static
const char * const SET_RESPONSE_HEADERS_FILTER = "SET_RESPONSE_HEADERS";

static
const char * const APACHE_DISABLE_MONITORING = "agent.apache.monitoring.disabled";

static
const char * const PAA_TRACE_LOGGING = "agent.logging.trace";

static
const char * const APACHE_TEST_CONNECTION = "agent.apache.test.connection";

static
const char * const APACHE_PAA_VERSION = "1.4.0";

static
const char * const CACHE_TYPE_PROPERTY = "agent.cache.type";

static
const char * const AUTO_TYPE = "AUTO";

static
const char * const ZMQ_TYPE = "ZMQ";

static
const char * const STANDALONE_TYPE = "STANDALONE";

static const int MAX_SERVERS_FOR_ZMQ_CACHE = 16;

static
const char * const PAA_ENABLE_NOTE = "paa-enable-note";

// Globals
// Enable per-module logging configuration, if available
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(paa);
#else
extern module AP_DECLARE_DATA paa_module;
#endif


static 
const paa_cache *cache = NULL;

static
server_rec *global_server_log_handle = NULL;

static
apr_threadkey_t *thread_key = NULL;

static
int paa_trace_logging_enabled = 0;

static
int paa_apache_monitoring_disabled = 0; // enabled by default

static
int paa_test_pa_connection = 1; // enabled by default

// Data structures //
typedef enum {
	PAA_CACHE_ZMQ,
	PAA_CACHE_STANDALONE
} paa_cache_type_e;

typedef
struct paa_req_config_struct {
    const paa_agent_response *agent_resp;
} paa_req_config;

typedef
struct paa_server_config_struct {
    apr_array_header_t *properties_files;
    const char *cert_dir;
    const char *cert_path;
    const paa_config *config;
    const paa_http_client *http_client;
	paa_cache_type_e configured_cache_type;
	const char *paa_enabled_note_name;
} paa_server_config;

/* This config will be created for the global config
   and VirualHost cases. */
typedef
struct paa_dir_config_struct {
    int paa_enabled;
} paa_dir_config;

// Prototypes //

void paa_ap_log_error(
    const char *file,
    int	line,
    int	level,
    apr_status_t status,
    const server_rec *s,
    const char *fmt,
    const char *msg
);

void paa_ap_log_rerror(
    const char *file,
    int	line,
    int	level,
    apr_status_t status,
    const request_rec *r,
    const char *fmt,
    const char *msg
);

int paa_get_log_level_from_server_rec(server_rec *srec);

void apache_paa_log_msg(const char *file,
        int line,
        apr_pool_t *pool,
        const char *msgid,
        paa_log_level level,
        apr_status_t error_code,
        const char *format,
        va_list va_args);

paa_log_level apache_paa_get_log_level();

void test_pingaccess_connection(const paa_http_client *client, apr_pool_t *parent_pool);

apr_status_t validate_cache_config(paa_server_config *server_config, apr_pool_t *pool);

static
int parse_enable_note(const char *paa_enable_note);

// Apache-specific library function implementations //

static const char * const NORMAL_MSG_FORMAT = "[paa] %s";
static const char * const MONITOR_MSG_FORMAT = "[paa-monitoring] %s";

/**
 * The header_parser hook for the PAA module--essentially the "main" function for the module.
 *
 * @param r the request record for the current request
 *
 * @return the standard result of the hook
 */
static
int paa_header_parser(request_rec *r)
{
    apache_client_req req_wrapper;
    req_wrapper.rec = r;
    req_wrapper.eos_reached = 0;
    req_wrapper.full_normalized_uri = NULL;

    paa_client_request client_req;
    apache_client_req_init(&client_req, &req_wrapper);

    apache_client_resp resp_wrapper;
    resp_wrapper.rec = r;

    paa_client_response client_resp;
    apache_client_resp_init(&client_resp, &resp_wrapper);

    int hook_result;

    do {
        apr_status_t result;

        paa_server_config *server_config = 
            (paa_server_config *)ap_get_module_config(r->server->module_config, &paa_module);

		paa_dir_config *dir_config =
			(paa_dir_config *)ap_get_module_config(r->per_dir_config, &paa_module);

        if (server_config == NULL) {
            paa_log(r->pool, APACHE_MSGID, PAA_ERROR, "failed to obtain PAA server configuration");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (dir_config == NULL) {
            paa_log(r->pool, APACHE_MSGID, PAA_ERROR, "failed to obtain PAA directory configuration");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

		apr_table_t *notes = r->notes;
		const char *paa_enable_note_value = apr_table_get(notes, server_config->paa_enabled_note_name);
		int enable_note = -1;
		if(paa_enable_note_value != NULL){
			enable_note = parse_enable_note(paa_enable_note_value);
		}

		// In order to log the request context, paa_pa_log_rerror must be used.
        if((enable_note == 0) || (enable_note == -1 && !dir_config->paa_enabled)){
			paa_ap_log_rerror(__FILE__, __LINE__, APLOG_DEBUG, APR_SUCCESS, r,
				   	NORMAL_MSG_FORMAT, "agent not enabled");
        	hook_result = OK;
            break;
        }

        if (cache == NULL) {
            paa_log(r->pool, APACHE_MSGID, PAA_ERROR,
                    "PAA cache unavailable, refusing to process request");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (server_config->http_client == NULL) {
            paa_log(r->pool, APACHE_MSGID, PAA_ERROR,
                    "PAA HTTP client was not initialized, refusing to process request");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (thread_key == NULL) {
            paa_log(r->pool, APACHE_MSGID, PAA_ERROR, "thread private key unavailable");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        result = apr_threadkey_private_set(r, thread_key);
        if (result != APR_SUCCESS) {
            paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR, result,
                    "failed to set thread private key");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        // create the normalized uri and store it for later use
        req_wrapper.full_normalized_uri = apr_psprintf(r->pool, "%s", r->parsed_uri.path);
        if (req_wrapper.full_normalized_uri == NULL) {
            paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR, APR_ENOMEM,
                    "failed to create normalized uri");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        const paa_agent_response *agent_resp = NULL;
        result = paa_submit_agent_request(r->pool,
                server_config->http_client,
                server_config->config,
                cache,
                &client_req,
                &client_resp,
                &agent_resp);
        if (result != APR_SUCCESS) {
            paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR, 
                    result, "failed to submit agent request");
            hook_result = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (paa_agent_response_req_allowed(agent_resp)) {
            result = paa_client_request_modify(r->pool, &client_req, agent_resp);
            if (result != APR_SUCCESS) {
                paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR,
                        result, "failed to modify client request");
                hook_result = HTTP_INTERNAL_SERVER_ERROR;
                break;
            }

            // Attach the agent response to the request to modify the response headers later on
            paa_req_config *req_config = (paa_req_config *)
                apr_palloc(r->pool, sizeof(paa_req_config));
            if (req_config == NULL) {
                paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR,
                        APR_ENOMEM, "failed to allocate request config");
                hook_result = HTTP_INTERNAL_SERVER_ERROR;
                break;
            }
            req_config->agent_resp = agent_resp;
            ap_set_module_config(r->request_config, &paa_module, req_config);
        }else{
            // sanity check for an issue where the response wasn't sent
            if (r->status == 0) {
                paa_log(r->pool, APACHE_MSGID, PAA_ERROR, "response from PingAccess not injected");
                hook_result = HTTP_INTERNAL_SERVER_ERROR;
                break;
            }

            // submit_agent_request internally has modified the client response
            paa_log(r->pool, APACHE_MSGID, PAA_DEBUG, "agent response sent verbatim to client");
            hook_result = DONE;
            break;
        }

        hook_result = OK;
    }while(0);

    apr_threadkey_private_set(NULL, thread_key);

    return hook_result;
}

apr_status_t paa_set_response_headers(request_rec *r)
{
    apr_status_t result;

    const paa_req_config *req_config;

    req_config =
      (paa_req_config*)ap_get_module_config(r->request_config, &paa_module);

    if (req_config != NULL && req_config->agent_resp != NULL) {
        apache_client_resp response_wrapper;
        response_wrapper.rec = r;

        paa_client_response client_resp;
        apache_client_resp_init(&client_resp, &response_wrapper);

        if (paa_agent_response_modifies_response(req_config->agent_resp)) {
            result = paa_client_response_modify(r->pool, &client_resp,
                    req_config->agent_resp);
            if (result != APR_SUCCESS) {
                paa_log_error(r->pool, APACHE_MSGID, PAA_ERROR,
                        result, "failed to modify response headers");
            }
        }else{
            result = APR_SUCCESS;
            paa_log(r->pool, APACHE_MSGID, PAA_DEBUG,
                    "agent response being returned verbatim, not modifying headers");
        }
    }else{
        paa_log(r->pool, APACHE_MSGID, PAA_DEBUG,
                "agent response dictates NO changes to client response");
        result = APR_SUCCESS;
    }

    return result;
}

static
int parse_enable_note(const char *paa_enable_note)
{
	if (strcmp(paa_enable_note, "on") == 0) {
		return 1;
	}
	if (strcmp(paa_enable_note, "off") == 0) {
		return 0;
	}
	return -1;
}

apr_status_t paa_set_response_headers_filter(ap_filter_t *filter, apr_bucket_brigade *in)
{
    apr_status_t result;

    do {
        result = apr_threadkey_private_set(filter->r, thread_key);
        if (result != APR_SUCCESS) {
            paa_log_error(filter->r->pool, APACHE_MSGID,
                    PAA_ERROR, result, "failed to set thread private key");
            break;
        }

        result = paa_set_response_headers(filter->r);
        if (result != APR_SUCCESS) {
            break;
        }
    }while(0);

    if (result != APR_SUCCESS) {
        apr_bucket *error_bucket = ap_bucket_error_create(HTTP_INTERNAL_SERVER_ERROR,
                NULL, filter->r->pool, filter->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(in, error_bucket);
    }

    // This is a one-shot filter that runs on the first input brigade only
    ap_remove_output_filter(filter);

    apr_threadkey_private_set(NULL, thread_key);

    return ap_pass_brigade(filter->next, in);
}

void paa_insert_filters(request_rec *r)
{
    paa_req_config *req_config = (paa_req_config *)
        ap_get_module_config(r->request_config, &paa_module);

    if (req_config != NULL 
            && req_config->agent_resp != NULL 
            && paa_agent_response_modifies_response(req_config->agent_resp)) 
    {
        // Only insert filter if modifications to the response headers need to occur
        ap_add_output_filter(SET_RESPONSE_HEADERS_FILTER, NULL, r, r->connection);
    }
}

void paa_insert_error_filters(request_rec *r)
{
    paa_req_config *req_config = (paa_req_config *)
        ap_get_module_config(r->request_config, &paa_module);
    if (req_config != NULL && 
        req_config->agent_resp != NULL && 
        paa_agent_response_modifies_response(req_config->agent_resp)) 
    {
        // Only insert filter if modifications to the response headers need to occur
        ap_add_output_filter(SET_RESPONSE_HEADERS_FILTER, NULL, r, r->connection);
    }
}

static
apr_status_t log_handle_cleanup(void *handledata)
{
    USE(handledata);

    global_server_log_handle = NULL;

    return APR_SUCCESS;
}

static
void set_global_log_handle(apr_pool_t *pool, server_rec *s)
{
    global_server_log_handle = s;

    apr_pool_cleanup_register(pool, global_server_log_handle, log_handle_cleanup, apr_pool_cleanup_null);
}

static
void noop_threadkey_free(void *unused)
{
    USE(unused);
}

void paa_child_init(apr_pool_t *pool, server_rec *s)
{

	set_global_log_handle(pool, s);

    apr_status_t result;
    do {
        result = apr_threadkey_private_create(&thread_key, noop_threadkey_free, pool);
        if (result != APR_SUCCESS) {
            paa_log_error(pool, APACHE_MSGID, PAA_ERROR, result,
                    "failed to create thread private key");
            break;
        }

        paa_server_config *server_config =
            (paa_server_config *)ap_get_module_config(s->module_config, &paa_module);
        if (server_config == NULL) {
            paa_log(pool, APACHE_MSGID, PAA_ERROR, "failed to obtain PAA server configuration");
            break;
        }

        char *errmsg = NULL;
        result = paa_http_client_curl_create(pool,
                server_config->config,
                server_config->cert_path,
                &errmsg,
                &(server_config->http_client));
        if (result != APR_SUCCESS) {
            paa_log_error(pool, APACHE_MSGID, PAA_ERROR, result,
                    "failed to initialize PAA HTTP client: %s",
                    errmsg);
            break;
        }

        test_pingaccess_connection(server_config->http_client, pool);

		if (server_config->configured_cache_type == PAA_CACHE_ZMQ) {
			result = paa_cache_zmq_create(pool,
					server_config->config,
					&cache);
			paa_log(pool, APACHE_MSGID, PAA_INFO, "using caching mechanism ZMQ");
		} else {
			result = paa_cache_standalone_create(pool,
					server_config->config,
					&cache);
			paa_log(pool, APACHE_MSGID, PAA_INFO, "using caching mechanism STANDALONE");
		}
		if (result != APR_SUCCESS) {
			paa_log_error(pool, APACHE_MSGID, PAA_ERROR, result,
					"failed to initialize PAA policy cache");
			break;
		}


        // copy all global config to each virtual host
        server_rec *virt = s->next;
        while (virt != NULL)
        {
            paa_server_config *virt_config =
                (paa_server_config *)ap_get_module_config(virt->module_config, &paa_module);

            // Only update the virtual host config if it differs from main server config
            if (virt_config != server_config)
            {
                virt_config->http_client = server_config->http_client;
                virt_config->properties_files = server_config->properties_files;
                virt_config->cert_dir = server_config->cert_dir;
                virt_config->cert_path = server_config->cert_path;
                virt_config->config = server_config->config;
				virt_config->paa_enabled_note_name = server_config->paa_enabled_note_name;
                // Don't set paa_enabled, this is a per-virtual host setting
            }

            virt = virt->next;

        }

        result = APR_SUCCESS;
    }while(0);

    if (result != APR_SUCCESS) {
        cache = NULL;
    }

}

static
void test_conn_status_cb(unsigned int status, const char *reason, void *userdata)
{
    USE(status);
    USE(reason);
    USE(userdata);
}

static
void test_conn_header_cb(const char *name, const char *value, void *userdata)
{
    USE(name);
    USE(value);
    USE(userdata);
}

static
size_t test_conn_body_cb(const unsigned char *src,
        size_t size,
        void *userdata)
{
    USE(src);
    USE(userdata);

    return size;
}

static
size_t test_conn_request_body_cb(unsigned char *dst, size_t size, void *userdata)
{
    USE(dst);
    USE(size);
    USE(userdata);

    return 0;
}

static
paa_client_request_read_cb test_conn_get_read_cb(const paa_client_request *req)
{
    USE(req);
    return test_conn_request_body_cb;
}

static
void * test_conn_get_read_data(const paa_client_request *req)
{
    USE(req);
    return NULL;
}

/**
 * Tests the connection to the PingAccess policy server using the specified HTTP client
 *
 * @param client the client
 * @param parent_pool the parent pool in which a subpool will be created
 */
void test_pingaccess_connection(const paa_http_client *client, apr_pool_t *parent_pool)
{
    if (paa_test_pa_connection) {

        apr_status_t result;
        apr_pool_t *request_pool = NULL;
        do {
            result = apr_pool_create(&request_pool, parent_pool);
            if (result != APR_SUCCESS) {
                break;
            }

            const paa_http_context *context = NULL;
            result = client->create_context(client, request_pool, &context);
            if (result != APR_SUCCESS) {
                break;
            }
            context->set_resp_pool(context, request_pool);
            context->set_resp_status_cb(context, test_conn_status_cb);
            context->set_resp_header_cb(context, test_conn_header_cb);
            context->set_resp_body_cb(context, test_conn_body_cb);

            const paa_http_request *request = NULL;
            result = context->create_request_handle(context, &request);
            if (result != APR_SUCCESS) {
                break;
            }

            // Configure the request to be sent to the PingAccess policy server heartbeat endpoint
            request->set_include_client_request_body(request, 0);
            request->set_request_uri(request, "/pa/heartbeat.ping");
            request->set_request_method(request, HTTP_GET_METHOD);

            paa_client_request req;
            req.get_read_cb = test_conn_get_read_cb;
            req.get_read_data = test_conn_get_read_data;

            result = context->send_request(context, &req);
            if (result != APR_SUCCESS) {
                break;
            }

            paa_log(request_pool, APACHE_MSGID, PAA_DEBUG,
                    "successfully connected to PingAccess policy server");
        }while(0);

        if (result != APR_SUCCESS) {
            paa_log_error(parent_pool, APACHE_MSGID, PAA_ERROR, result,
                    "failed to connect to PingAccess policy server");
        }

        if (request_pool != NULL) {
            apr_pool_destroy(request_pool);
            request_pool = NULL;
        }

    }
}

int paa_post_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    USE(plog);

    apr_status_t result;

    set_global_log_handle(pool, s);

    // Initialize the configuration
    paa_server_config *server_config =
        (paa_server_config *)ap_get_module_config(s->module_config, &paa_module);
    if (server_config == NULL) {
        paa_log(pool, APACHE_MSGID, PAA_ERROR, "failed to retrieve PAA server config");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (server_config->properties_files->nelts <= 0) {
        paa_log(pool, APACHE_MSGID, PAA_ERROR, "PAA properties files were not specified");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (server_config->cert_dir == NULL) {
        paa_log(pool, APACHE_MSGID, PAA_ERROR,
                "Directory for PAA trust certificates was not specified");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    const char **prop_files_array = (const char **)apr_palloc(ptemp,
            sizeof(const char *)*server_config->properties_files->nelts);
    int i;
    for (i = 0; i < server_config->properties_files->nelts; ++i) {
        prop_files_array[i] = ((const char **)server_config->properties_files->elts)[i];
    }

    char *errmsg = NULL;
    result = paa_config_filesystem_create(pool,
            prop_files_array,
            server_config->properties_files->nelts,
            &errmsg,
            &(server_config->config));
    if (result != APR_SUCCESS) {
        paa_log_error(pool, APACHE_MSGID, PAA_ERROR, result,
                "failed to initialize PAA configuration: %s",
                errmsg);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

	if (validate_cache_config(server_config, pool) != APR_SUCCESS) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

    result = paa_curl_create_cert_file(pool,
            server_config->config,
            server_config->cert_dir,
            &(server_config->cert_path));

    if (result != APR_SUCCESS && !APR_STATUS_IS_EEXIST(result)) {
        paa_log_error(pool, APACHE_MSGID, PAA_ERROR, result,
                "failed to create trust store certificate file");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (APR_STATUS_IS_EEXIST(result)) {
        // This is an acceptable case, translate it into APR_SUCCESS
        result = APR_SUCCESS;
    }

    // Enable trace logging -- if specified
    const char *trace_logging = server_config->config->get_value(server_config->config,
            PAA_TRACE_LOGGING);
    if (trace_logging != NULL) {
        char *invalid = NULL;
        paa_trace_logging_enabled = (int)apr_strtoi64(trace_logging, &invalid, 10);
        if (invalid == NULL || *invalid != '\0') {
            paa_log(ptemp, APACHE_MSGID, PAA_ERROR, "failed to enable trace logging");
            paa_trace_logging_enabled = 0;
            // proceed with processing, this is not critical
        }else{
            paa_log(ptemp, APACHE_MSGID,
                    PAA_INFO, "trace logging set to = %d", paa_trace_logging_enabled);
        }
    }

    const char *test_connection = server_config->config->get_value(server_config->config,
            APACHE_TEST_CONNECTION);
    if (test_connection != NULL) {
        char *invalid = NULL;
        paa_test_pa_connection = (int)apr_strtoi64(test_connection, &invalid, 10);
        if (invalid == NULL || *invalid != '\0') {
            // fallback to the default value
            paa_test_pa_connection = 1;
            paa_log(pool, APACHE_MSGID, PAA_ERROR, "invalid test PingAccess connection value");
            // proceed with processing, this is not critical
        }else{
            paa_log(ptemp, APACHE_MSGID, PAA_INFO,
                    "test PingAccess connection set to = %d", paa_test_pa_connection);
        }
    }

    // Disable monitoring -- if specified
    const char *monitoring_disable = server_config->config->get_value(server_config->config,
            APACHE_DISABLE_MONITORING);
    if (monitoring_disable != NULL) {
        char *invalid = NULL;
        paa_apache_monitoring_disabled = (int)apr_strtoi64(monitoring_disable, &invalid, 10);
        if (invalid == NULL || *invalid != '\0') {
            paa_apache_monitoring_disabled = 0;
            paa_log(pool, APACHE_MSGID, PAA_ERROR, "invalid monitoring disabled value");
            return HTTP_INTERNAL_SERVER_ERROR;
        }else{
            paa_log(ptemp, APACHE_MSGID, PAA_INFO,
                    "monitoring disable set to = %d", paa_apache_monitoring_disabled);
        }
    }

    paa_log(ptemp, APACHE_MSGID, PAA_INFO, "PAA SDK version %s",
            paa_get_version());
    paa_log(ptemp, APACHE_MSGID, PAA_INFO, "Apache PAA version %s",
            APACHE_PAA_VERSION);

    return OK;
}

apr_status_t validate_cache_config(paa_server_config *server_config, apr_pool_t *pool)
{
	const char *cache_type;
	const char *errmsg;

	cache_type = server_config->config->get_value(server_config->config, CACHE_TYPE_PROPERTY);
	if (cache_type != NULL) {
		if (strcmp(AUTO_TYPE, cache_type) != 0 &&
			strcmp(ZMQ_TYPE, cache_type) != 0 &&
			strcmp(STANDALONE_TYPE, cache_type) != 0)
		{
			errmsg = apr_psprintf(pool, "invalid %s value in PingAccess agent properties file, "
				"must be one of %s, %s, or %s",
				CACHE_TYPE_PROPERTY,
				AUTO_TYPE,
				ZMQ_TYPE,
				STANDALONE_TYPE);
			paa_log(pool, APACHE_MSGID, PAA_ERROR, errmsg);
			return APR_EINVAL;
		}
	}

	if (cache_type == NULL || strcmp(AUTO_TYPE, cache_type) == 0) {
		int max_servers;
		apr_status_t result;
		result = ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_servers);
		if (result == APR_SUCCESS) {
			server_config->configured_cache_type = max_servers > 1 && max_servers < MAX_SERVERS_FOR_ZMQ_CACHE ?
			   	PAA_CACHE_ZMQ : PAA_CACHE_STANDALONE;
		} else {
			server_config->configured_cache_type = PAA_CACHE_ZMQ;
			errmsg = apr_psprintf(pool, "unable to determine server limit, using ZMQ caching");
			paa_log(pool, APACHE_MSGID, PAA_WARN, errmsg);
		}
	} else if (strcmp(ZMQ_TYPE, cache_type) == 0) {
		server_config->configured_cache_type = PAA_CACHE_ZMQ;
	} else {
		server_config->configured_cache_type = PAA_CACHE_STANDALONE;
	}

	return APR_SUCCESS;
}

void paa_register_hooks(apr_pool_t *p)
{
    USE(p);

    paa_set_log_functions(apache_paa_log_msg, apache_paa_get_log_level);

    // Register filters
    ap_register_output_filter(SET_RESPONSE_HEADERS_FILTER, paa_set_response_headers_filter,
            NULL, AP_FTYPE_CONTENT_SET);

    // Register hooks
    //ap_hook_header_parser
    ap_hook_header_parser(paa_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(paa_insert_filters, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(paa_insert_error_filters, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(paa_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(paa_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static
void *paa_create_server_config(apr_pool_t *pool, server_rec *s)
{
    USE(s);

    paa_server_config *server_config =
		(paa_server_config *)apr_pcalloc(pool, sizeof(paa_server_config));
    server_config->cert_dir = NULL;
    server_config->config = NULL;
    server_config->properties_files = apr_array_make(pool, 3, sizeof(char *));
	server_config->paa_enabled_note_name = PAA_ENABLE_NOTE;

    return server_config;
}

static
void *paa_create_dir_config(apr_pool_t *pool, char *dir)
{
	USE(dir);

	paa_dir_config *dir_config = (paa_dir_config*) apr_pcalloc(pool, sizeof(paa_dir_config));
	dir_config->paa_enabled = -1;

	return dir_config;
}

static
void *paa_merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
	paa_dir_config *base_dir_config = (paa_dir_config *)base_conf;
    paa_dir_config *new_dir_config = (paa_dir_config *)new_conf;
    paa_dir_config *dir_config = (paa_dir_config *)paa_create_dir_config(p, "Merged configuration.");

	dir_config->paa_enabled = (new_dir_config->paa_enabled == -1) ?
		base_dir_config->paa_enabled : new_dir_config->paa_enabled;

	return dir_config;
}

static
const char *set_property_files(cmd_parms *parms, void *unused, const char *arg)
{
    USE(unused);

    // This directive is only valid in the global context (not within a virtual host)
    const char *errmsg = ap_check_cmd_context(parms, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    server_rec *s = parms->server;
    paa_server_config *server_config =
        (paa_server_config *)ap_get_module_config(s->module_config, &paa_module);

    void *prop_file_path = apr_array_push(server_config->properties_files);

    // The value of the property can be relative or absolute and this function will resolve the
    // file accordingly
    return ap_set_file_slot(parms, prop_file_path, arg);
}

static
const char *set_cert_dir(cmd_parms *parms, void *unused, const char *arg)
{
    USE(unused);

    // This directive is only valid in the global context (not within a virtual host)
    const char *errmsg = ap_check_cmd_context(parms, GLOBAL_ONLY);
    if (errmsg != NULL) {
        return errmsg;
    }

    server_rec *s = parms->server;
    paa_server_config *server_config = 
        (paa_server_config *)ap_get_module_config(s->module_config, &paa_module);

    // The value of the property can be relative or absolute and this function will resolve the
    // file accordingly
    return ap_set_file_slot(parms, &(server_config->cert_dir), arg);
}

static
const char *set_paa_enabled_note_name(cmd_parms *parms, void *unused, const char *arg)
{
	USE(unused);

	const char *errmsg = ap_check_cmd_context(parms, GLOBAL_ONLY);
	if (errmsg != NULL) {
		return errmsg;
	}

	server_rec *s = parms->server;
	paa_server_config *server_config =
		(paa_server_config *)ap_get_module_config(s->module_config, &paa_module);

	server_config->paa_enabled_note_name = arg;

	return NULL;
}

static
const char *set_paa_enabled(cmd_parms *parms, void *dir_conf, const char *arg)
{
	USE(parms);
	paa_dir_config *dir_config = (paa_dir_config *) dir_conf;

	if(dir_config)
	{
		if(strncmp(arg, "off", 3)==0)
		{
			dir_config->paa_enabled = 0;
		}
		else if(strncmp(arg, "on", 2)==0)
		{
			dir_config->paa_enabled = 1;
		}
		else
		{
			dir_config->paa_enabled = -1;
		}
	}

    return NULL;

}

static
const command_rec paa_cmds[] = {
    AP_INIT_ITERATE("PaaPropertyFiles", CMD_FUNC(set_property_files), NULL, RSRC_CONF,
            "A list of .properties files used to configure the module"),
    AP_INIT_TAKE1("PaaCertificateDir", CMD_FUNC(set_cert_dir), NULL, RSRC_CONF,
            "A directory for certificate files extracted from .properties files"),
    AP_INIT_TAKE1("PaaEnabled", CMD_FUNC(set_paa_enabled), NULL, RSRC_CONF | ACCESS_CONF,
            "An option whether or not to enable or disable the agent."),
    AP_INIT_TAKE1("PaaEnabledNoteName", CMD_FUNC(set_paa_enabled_note_name), NULL, RSRC_CONF,
            "The name of the note field used to enable or disable the agent dynamically."),
    { NULL, { NULL }, NULL, 0, (enum cmd_how)0, NULL },
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA paa_module = {
    STANDARD20_MODULE_STUFF,
    paa_create_dir_config,                      /* create per-dir    config structures */
    paa_merge_dir_config,                       /* merge  per-dir    config structures */
    paa_create_server_config,                   /* create per-server config structures */
    NULL,                                       /* merge  per-server config structures */
    paa_cmds,                                   /* table of config file commands       */
    paa_register_hooks                          /* register hooks                      */
}
;


void apache_paa_log_msg(const char *file,
        int line,
        apr_pool_t *pool,
        const char *msgid,
        paa_log_level level,
        apr_status_t error_code,
        const char * const format,
        va_list va_args)
{
    USE(msgid);

    if (level == PAA_MONITOR && paa_apache_monitoring_disabled) {
        // Drop the monitoring message since monitoring is not enabled
        return;
    }

    if (level == PAA_TRACE && !paa_trace_logging_enabled) {
        // Drop the trace message since trace logging is not enabled
        return;
    }

    int apache_level;
    switch (level) {
        case PAA_ERROR:
            apache_level = APLOG_CRIT; // an ERROR in the PAA module indicates incorrect operation
            break;
        case PAA_WARN:
            apache_level = APLOG_WARNING;
            break;
        case PAA_MONITOR:
            apache_level = APLOG_INFO;
            break;
        case PAA_INFO:
            apache_level = APLOG_INFO;
            break;
        case PAA_TRACE:
            apache_level = APLOG_DEBUG;
            break;
        case PAA_DEBUG:
            apache_level = APLOG_DEBUG;
            break;
        case PAA_OFF:
            return;
        default:
            // default to debug
            apache_level = APLOG_DEBUG;
            break;
    }

    if (pool != NULL) {
        const char * const msg_format = (level == PAA_MONITOR) ? MONITOR_MSG_FORMAT :
            NORMAL_MSG_FORMAT;
        const char *msg;

        msg = apr_pvsprintf(pool, format, va_args);

        if (thread_key != NULL) {
            request_rec *req = NULL;
            apr_threadkey_private_get((void **)&req, thread_key);

            if (req != NULL) {
                paa_ap_log_rerror(file, line, apache_level, error_code, req,
                        msg_format, msg);
                return;
            }
        }

        // No request context to log with -- use the global server handle
        paa_ap_log_error(file, line, apache_level, error_code, global_server_log_handle,
                msg_format, msg);
    }else{
        // This could occur when the server is out of memory -- make a best effort attempt to
        // add a log entry to the error log via stderr
        vfprintf(stderr, format, va_args);
        fflush(stderr);
    }
}

static
paa_log_level apache_level_to_paa_level(int level)
{
    switch(level) {
        case APLOG_EMERG:
        case APLOG_ERR:
        case APLOG_ALERT:
        case APLOG_CRIT:
            return PAA_ERROR;
        case APLOG_WARNING:
            return PAA_WARN;
        case APLOG_NOTICE:
        case APLOG_INFO:
            if (!paa_apache_monitoring_disabled) {
                // The SDK doesn't invoke the registered log function if the level of the entry is
                // greater than the configured level. Since Apache doesn't have a monitoring log level,
                // this is required to ensure that the SDK will pass log messages to the registered
                // log function when Apache's LogLevel is INFO
                return PAA_MONITOR;
            }
            return PAA_INFO;
        case APLOG_DEBUG:
            if (paa_trace_logging_enabled) {
                // Similar to PAA_MONITOR, this level does not map to Apache.
                return PAA_TRACE;
            }
            return PAA_DEBUG;
        default:
            break;
    }

    return PAA_DEBUG;
}

paa_log_level apache_paa_get_log_level()
{
    int loglevel = 0;
    if (thread_key != NULL) {
        request_rec *req = NULL;
        apr_threadkey_private_get((void **)&req, thread_key);
        if (req != NULL) {
            loglevel = paa_get_log_level_from_server_rec(req->server);
            return apache_level_to_paa_level(loglevel);
        }
    }

    if (global_server_log_handle != NULL) {
        loglevel = paa_get_log_level_from_server_rec(global_server_log_handle);
        return apache_level_to_paa_level(loglevel);
    }

    // default to debug -- this indicates something is likely wrong so might as well generate
    // more verbose logging at this point
    return PAA_DEBUG;
}

void paa_ap_log_error(
    const char *file,
    int	line,
    int	level,
    apr_status_t status,
    const server_rec *s,
    const char *fmt,
    const char *msg
					  ) { 

    #ifdef APACHE24
        ap_log_error(file, line, APLOG_MODULE_INDEX, level, status, s, fmt, msg);
    #else
        ap_log_error(file, line, level, status, s, fmt, msg);
    #endif
}

void paa_ap_log_rerror(
    const char *file,
    int	line,
    int	level,
    apr_status_t status,
    const request_rec *r,
    const char *fmt,
    const char *msg) 
{

    #ifdef APACHE24
        ap_log_rerror(file, line, APLOG_MODULE_INDEX, level, status, r, fmt, msg);
    #else
        ap_log_rerror(file, line, level, status, r, fmt, msg);
    #endif
}

int paa_get_log_level_from_server_rec(server_rec *srec) {
    int loglevel = 
    #if (defined(APACHE22))
        srec->loglevel;
    #elif (defined(APACHE24))
        ap_get_server_module_loglevel(srec, APLOG_MODULE_INDEX);
    #else
	  #error "ERROR. Unsupported version of Apache server."
    #endif

    return loglevel;
}
