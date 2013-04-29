
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_tcp_io.h>
#include <nginx.h>
#include <cjson.h>

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

static ngx_int_t ngx_http_stup_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_status_ex_commands[] = {

    { ngx_string("stub_status_ex"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_stub_status_ex_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_stup_init,                    /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_stub_status_ex_module = {
    NGX_MODULE_V1,
    &ngx_http_stub_status_ex_module_ctx,      /* module context */
    ngx_http_status_ex_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_status_ex_handler(ngx_http_request_t *r)
{
    size_t             size, index_size;
	u_char			   host[URL_LEN];
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_atomic_int_t   ap, hn, ac, rq, rd, wr;// cc;// rt;
	cJSON *root,*fmt;
	char *out_cjson;
	ngx_url_io_array *url_io_array;
	ngx_tcp_io		  ngx_io;
	ngx_tcp_io		 **url_io;
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

	ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;
	//cc = *ngx_connection_counter;
   // rt = *ngx_stat_requesttime;
	
	//ngx_tcp_io_get(&tcp_in, &tcp_out);
	ngx_tcp_io_get_ex(&ngx_io);
	root=cJSON_CreateObject();
	
	cJSON_AddStringToObject(root, "verison", DRAGON_VER); 
	cJSON_AddNumberToObject(root, "code", 0);
	cJSON_AddItemToObject(root, "result", fmt=cJSON_CreateObject());
	cJSON_AddNumberToObject(fmt,"active_connections", 			ac);
	cJSON_AddNumberToObject(fmt,"requests",			rq);
	cJSON_AddNumberToObject(fmt,"accepts",			ap);
	cJSON_AddNumberToObject (fmt,"handled", 			hn);
	
	cJSON_AddNumberToObject(fmt,"reading_request",		rd);
	cJSON_AddNumberToObject(fmt,"writing_request",		wr);
	cJSON_AddNumberToObject(fmt,"waitting_request",		ac - (rd + wr));
	//cJSON_AddNumberToObject(fmt,"connection_",		cc);
	//cJSON_AddNumberToObject(fmt,"respone_time",		rt);

	cJSON_AddItemToObject(root, "stream", fmt=cJSON_CreateObject());
	cJSON_AddNumberToObject (fmt,"in_http_stream", 			ngx_io.in);
	cJSON_AddNumberToObject (fmt,"out_http_stream", 		ngx_io.out);
	cJSON_AddNumberToObject(fmt,"http_1xx",		ngx_io.http_1xx);
	cJSON_AddNumberToObject(fmt,"http_2xx",		ngx_io.http_2xx);
	cJSON_AddNumberToObject(fmt,"http_3xx",		ngx_io.http_3xx);
	cJSON_AddNumberToObject(fmt,"http_4xx",		ngx_io.http_4xx);
	cJSON_AddNumberToObject(fmt,"http_5xx",		ngx_io.http_5xx);

	cJSON_AddNumberToObject(fmt,"http_400",		ngx_io.http_400);
	cJSON_AddNumberToObject(fmt,"http_401",		ngx_io.http_401);
	cJSON_AddNumberToObject(fmt,"http_403",		ngx_io.http_403);
	cJSON_AddNumberToObject(fmt,"http_404",		ngx_io.http_404);
	cJSON_AddNumberToObject(fmt,"http_408",		ngx_io.http_408);
	cJSON_AddNumberToObject(fmt,"http_500",		ngx_io.http_500);
	cJSON_AddNumberToObject(fmt,"http_502",		ngx_io.http_502);
	cJSON_AddNumberToObject(fmt,"http_503",		ngx_io.http_503);
	cJSON_AddNumberToObject(fmt,"http_504",		ngx_io.http_504);
	cJSON_AddNumberToObject(fmt,"http_505",		ngx_io.http_505);

	if (ngx_status_io_get(&url_io_array) == NGX_OK)
	{
		cJSON_AddNumberToObject(root,"number",		url_io_array->number);
		url_io = (ngx_tcp_io**)&url_io_array->ngx_tcp_io;
		for (index_size= 0; index_size<url_io_array->number; index_size++)
		{
			ngx_memzero(host, URL_LEN);
			ngx_memcpy(host, url_io[index_size]->host, url_io[index_size]->host_len);
			cJSON_AddItemToObject(root, (const char *)host, fmt=cJSON_CreateObject());
			cJSON_AddNumberToObject(fmt, "in", url_io[index_size]->in);
			cJSON_AddNumberToObject(fmt, "out", url_io[index_size]->out);
			cJSON_AddNumberToObject(fmt, "requests", url_io[index_size]->requests);
			cJSON_AddNumberToObject(fmt, "http_1xx", url_io[index_size]->http_1xx);
			cJSON_AddNumberToObject(fmt, "http_2xx", url_io[index_size]->http_2xx);
			cJSON_AddNumberToObject(fmt, "http_3xx", url_io[index_size]->http_3xx);
			cJSON_AddNumberToObject(fmt, "http_4xx", url_io[index_size]->http_4xx);
			cJSON_AddNumberToObject(fmt, "http_5xx", url_io[index_size]->http_5xx);

			cJSON_AddNumberToObject(fmt, "http_401", url_io[index_size]->http_401);
			cJSON_AddNumberToObject(fmt, "http_403", url_io[index_size]->http_403);
			cJSON_AddNumberToObject(fmt, "http_404", url_io[index_size]->http_404);
			cJSON_AddNumberToObject(fmt, "http_408", url_io[index_size]->http_408);
			cJSON_AddNumberToObject(fmt, "http_500", url_io[index_size]->http_500);
			cJSON_AddNumberToObject(fmt, "http_502", url_io[index_size]->http_502);
			cJSON_AddNumberToObject(fmt, "http_503", url_io[index_size]->http_503);
			cJSON_AddNumberToObject(fmt, "http_504", url_io[index_size]->http_504);
			cJSON_AddNumberToObject(fmt, "http_505", url_io[index_size]->http_505);
		}
	}
	out_cjson=cJSON_Print(root);  
	cJSON_Delete(root);
	
	size = ngx_strlen(out_cjson);
	b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	out.buf = b;
    out.next = NULL;
	b->last = ngx_cpymem(b->last, out_cjson,
                         size);
	if (out_cjson)
		ngx_free(out_cjson); 

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

ngx_int_t
ngx_http_statu_update_requesttime(ngx_http_request_t *r)
{
	ngx_time_t                *tp;
    ngx_msec_int_t             ms;
    
    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
         ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

    ms = ngx_max(ms, 0);
	
/*	(void) ngx_atomic_fetch_add(ngx_stat_requesttime, ms);
*/
    return NGX_OK;
}

ngx_int_t
ngx_http_statu_monitor_handler(ngx_http_request_t *r)
{
	if (ngx_tcp_io_getfirsttime() == 0)
		ngx_tcp_io_set_firsttime(ngx_current_msec);
    ngx_tcp_io_update(r);
	ngx_http_statu_update_requesttime(r);
	return NGX_OK;
}

static ngx_int_t ngx_http_stup_init(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t  *cmcf;
	ngx_http_handler_pt        *h;
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	if (ngx_tcp_io_init_rbtree(cf, &ngx_http_core_module) == NGX_ERROR)
		return NGX_ERROR;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_statu_monitor_handler;
	return NGX_OK;
}

static char *ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
	
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_ex_handler;
    return NGX_CONF_OK;
}

