/*
 * Copyright (C) 
 * Copyright (C) 
 * author:      	wu yangping
 * create time:		20120600
 * update time: 	20120727
 */

#ifndef _NGX_TCP_PORT_IO_
#define _NGX_TCP_PORT_IO_

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <ngx_config.h>
#include <ngx_core.h>

#define TCP_PORT_IO_SHM_NAME "statu_monitor_shm_name"
#define STATU_MONITOR_DOMAINS 1024
#define URL_LEN				  128

void *statu_monitor_shm_pool;

typedef struct NGX_TCP_IO{
	ngx_atomic_int_t		in;
	ngx_atomic_int_t		out;
	ngx_atomic_int_t		requests;
	ngx_atomic_int_t		http_1xx;
	ngx_atomic_int_t		http_2xx;
	ngx_atomic_int_t		http_3xx;
	ngx_atomic_int_t		http_4xx;
	ngx_atomic_int_t		http_5xx;
	ngx_atomic_int_t		http_400;
	ngx_atomic_int_t		http_401;
	ngx_atomic_int_t		http_403;
	ngx_atomic_int_t		http_404;
	ngx_atomic_int_t		http_408;
	ngx_atomic_int_t		http_500;
	ngx_atomic_int_t		http_502;
	ngx_atomic_int_t		http_503;
	ngx_atomic_int_t		http_504;
	ngx_atomic_int_t		http_505;
	ngx_atomic_int_t		http_other;
	ngx_msec_t 				http_stup_first_time;
	unsigned int			pid;
	unsigned int			host_len;
	u_char					host[1];
}ngx_tcp_io;

typedef struct NGX_URL_IO_ARRAY{
	size_t					number;
	ngx_tcp_io*				ngx_tcp_io[1];
}ngx_url_io_array;

typedef struct NGX_TCP_IO_ARRAY{
    int             number;
    void            *tcp_io_array;
}ngx_tcp_io_array;

typedef struct {
    ngx_rbtree_t       *rbtree;
} ngx_status_ex_host_ctx_t;

extern ngx_module_t  ngx_http_stub_status_ex_module;

int ngx_tcp_io_get(ngx_atomic_int_t *in, ngx_atomic_int_t *out);
int ngx_tcp_io_get_ex(ngx_tcp_io *ngx_io);
int ngx_tcp_io_init(ngx_conf_t *cf, void *tag);
int ngx_tcp_io_init_rbtree(ngx_conf_t *cf, void *tag);
int ngx_tcp_io_update(ngx_http_request_t *r);
ngx_msec_t ngx_tcp_io_getfirsttime();
int ngx_tcp_io_set_firsttime(ngx_msec_t msec_time);
int ngx_status_io_get(ngx_url_io_array **url_io_array);

#endif

