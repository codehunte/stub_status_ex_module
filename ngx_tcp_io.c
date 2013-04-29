/*
 * Copyright (C) 
 * Copyright (C) 
 * author:      	wu yangping
 * create time:		20120600
 * update time: 	20120727
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_tcp_io.h>
//#define _TEMP_LOG_
 
long int out_old, in_old;
ngx_tcp_io *statu_io_info=NULL;
ngx_url_io_array *statu_url_io_array=NULL;

ngx_shm_zone_t		*status_ex_shm_zone = NULL;

static ngx_rbtree_node_t *
ngx_host_list_lookup(ngx_rbtree_t *rbtree, ngx_str_t *vv,
    uint32_t hash)
{
    ngx_int_t                    rc;
	ngx_tcp_io					*lcn;
    ngx_rbtree_node_t           *node, *sentinel;
    
    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
		
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (ngx_tcp_io *) &node->data;
		rc = ngx_memn2cmp(lcn->host, vv->data, lcn->host_len, vv->len);
        if (rc == 0 ) {
        	return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static void
ngx_status_ex_host_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
	ngx_tcp_io       *lcn, *lcnt;
    ngx_rbtree_node_t           	  **p;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_tcp_io *) &node->data;
            lcnt = (ngx_tcp_io *) &temp->data;

            p = (ngx_memn2cmp(lcn->host, lcnt->host, lcn->host_len, lcnt->host_len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

void *ngx_status_get_momerybyhost_brtree(ngx_http_request_t *r)
{
	ssize_t						n,len;
	uint32_t					hash;
	ngx_tcp_io					*io_ret;
	ngx_slab_pool_t     		*shpool;
	ngx_rbtree_node_t			*node, *o_node;
	ngx_status_ex_host_ctx_t	ctx;
	
	if (r == NULL || r->headers_in.host == NULL)
		return NULL;

	if (status_ex_shm_zone == NULL || status_ex_shm_zone->data == NULL)
		return NULL;

	if (r->headers_in.host->value.len > URL_LEN)
		return NULL;
	
	ctx.rbtree = *(ngx_rbtree_t **)status_ex_shm_zone->data;
	
	hash = ngx_crc32_short(r->headers_in.host->value.data, r->headers_in.host->value.len);
	node = ngx_host_list_lookup(ctx.rbtree, &r->headers_in.host->value, hash);

	/*==NULL insert new node*/
	if (node == NULL)
	{
		len = r->headers_in.host->value.len;
		shpool = (ngx_slab_pool_t *)status_ex_shm_zone->shm.addr;
		n = offsetof(ngx_rbtree_node_t, color)
			+ offsetof(ngx_tcp_io, host)
			+ len;

		node = ngx_slab_alloc_locked(shpool, n);
		if (node == NULL) {
	   		return NULL;
	    }

	    io_ret = (ngx_tcp_io *) &node->data;

	    node->key = hash;
	    io_ret->host_len= len;
	    ngx_memcpy(io_ret->host, r->headers_in.host->value.data, r->headers_in.host->value.len);

		ngx_shmtx_lock(&shpool->mutex);
		/*secend find*/
		o_node = ngx_host_list_lookup(ctx.rbtree, &r->headers_in.host->value, hash);
		if (o_node == NULL)
		{
			ngx_rbtree_insert(ctx.rbtree, node);
			statu_url_io_array->ngx_tcp_io[statu_url_io_array->number] = io_ret;
			statu_url_io_array->number++;
		}
		
		ngx_shmtx_unlock(&shpool->mutex);
	}
	
	return (ngx_tcp_io *) &node->data;
}

int ngx_tcp_io_update_in(long int in, ngx_http_request_t *r)
{
    ngx_tcp_io *data = statu_io_info;
	ngx_tcp_io *tcp_io_data = NULL;

    if (r == NULL || data == NULL)
    {
        return NGX_ERROR;
    }

#ifdef _TEMP_LOG_
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_tcp_io_update_in %d#%d#%d#%s",
                getpid(), data->in, in, r->headers_in.host->value.data);
#endif

	ngx_atomic_fetch_add(&data->in, in);
	ngx_atomic_fetch_add(&data->requests, 1);

	tcp_io_data = ngx_status_get_momerybyhost_brtree(r);
	if (tcp_io_data)
	{
		ngx_atomic_fetch_add(&tcp_io_data->in, in);
		ngx_atomic_fetch_add(&tcp_io_data->requests, 1);
	}
	
	return data->in;
}

int ngx_tcp_http_status_update(ngx_http_request_t *r, ngx_tcp_io *data)
{
	ngx_atomic_int_t *p_int_t;
	if (r==NULL || data==NULL)
		return NGX_ERROR;
	
	switch (r->headers_out.status)
	{
		case 400:
			p_int_t = &data->http_400;
			break;
		case 401:
			p_int_t = &data->http_401;
			break;
		case 403:
			p_int_t = &data->http_403;
			break;
		case 404:
			p_int_t = &data->http_404;
			break;
		case 408:
			p_int_t = &data->http_408;
			break;
		case 500:
			p_int_t = &data->http_500;
			break;
		case 502:
			p_int_t = &data->http_502;
			break;
		case 503:
			p_int_t = &data->http_503;
			break;
		case 504:
			p_int_t = &data->http_504;
			break;
		case 505:
			p_int_t = &data->http_505;
			break;
		default:
			p_int_t = &data->http_other;
			break;	
	}
	
	ngx_atomic_fetch_add(p_int_t,1);

	switch(r->headers_out.status/100)
	{
		case 1:
			p_int_t = &data->http_1xx;			
			break;
		case 2:
			p_int_t = &data->http_2xx;
			break;
		case 3:
			p_int_t = &data->http_3xx;
			break;
		case 4:
			p_int_t = &data->http_4xx;
			break;
		case 5:
			p_int_t = &data->http_5xx;
			break;
		default:
			p_int_t = &data->http_other;
			break;	
	}
	ngx_atomic_fetch_add(p_int_t,1);

	return NGX_OK;
}


int ngx_tcp_http_status_update_ex(long int out, ngx_http_request_t *r)
{
	ngx_tcp_io *tcp_io_data = NULL;
	ngx_tcp_io *data = statu_io_info;
	if (r == NULL)
		return NGX_ERROR;
	
	ngx_tcp_http_status_update(r, data);

	tcp_io_data = ngx_status_get_momerybyhost_brtree(r);
	if (tcp_io_data)
	{
		ngx_tcp_http_status_update(r, tcp_io_data);
		ngx_atomic_fetch_add(&tcp_io_data->out, out);
	}
	return NGX_OK;
}

int ngx_tcp_io_update_out(long int out, ngx_http_request_t *r)
{
    ngx_tcp_io *data = statu_io_info;
	
    if (data == NULL || r==NULL)
    {
        return NGX_ERROR;
    }

#ifdef _TEMP_LOG_
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_tcp_io_update_out %d#%d#%d#%s",
                getpid(), data->out, out, r->headers_in.host->value.data);
#endif
	ngx_atomic_fetch_add(&data->out, out);
	ngx_tcp_http_status_update_ex(out, r);
	
	return data->out;
}

int ngx_tcp_io_get(ngx_atomic_int_t *in, ngx_atomic_int_t *out)
{
	if (!in || !out || !statu_io_info)
        return NGX_ERROR;
	
    *in = statu_io_info->in;
    *out = statu_io_info->out;

	return NGX_OK;
}

int ngx_tcp_io_get_ex(ngx_tcp_io *ngx_io)
{
	if (!statu_io_info || !ngx_io)
        return NGX_ERROR;
	ngx_memcpy((void *)ngx_io, (void *)statu_io_info, sizeof(ngx_tcp_io));

	return NGX_OK;
}

int ngx_status_io_get(ngx_url_io_array **url_io_array)
{
	if (url_io_array==NULL)
		return NGX_ERROR;
	*url_io_array = statu_url_io_array;
	return NGX_OK;
}

static ngx_int_t
ngx_status_ex_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_status_ex_host_ctx_t       *octx = data;

    size_t                      	 len;
    ngx_slab_pool_t                  *shpool;
    ngx_rbtree_node_t                *sentinel;
    ngx_status_ex_host_ctx_t  	 	 *ctx;

    ctx = shm_zone->data;
	
    if (octx) {
        ctx->rbtree = octx->rbtree;
		
		status_ex_shm_zone = shm_zone;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;
		
		status_ex_shm_zone = shm_zone;
        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

	statu_io_info = ngx_slab_alloc(shpool, sizeof(ngx_tcp_io));
	if (statu_io_info == NULL)
		return NGX_ERROR;

	statu_url_io_array = ngx_slab_alloc(shpool, sizeof(statu_url_io_array)+ sizeof(ngx_tcp_io*) * STATU_MONITOR_DOMAINS);
	if (statu_url_io_array == NULL)
			return NGX_ERROR;
	
	statu_url_io_array->number = 0;
	ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_status_ex_host_rbtree_insert_value);

    len = sizeof(" in status_ex zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in status_ex zone \"%V\"%Z",
                &shm_zone->shm.name);

	status_ex_shm_zone = shm_zone;
    return NGX_OK;
}


int ngx_tcp_io_init_rbtree(ngx_conf_t *cf, void *tag)
{
	size_t							size;
	ngx_str_t						name;
	ngx_shm_zone_t             		*shm_zone;
	ngx_status_ex_host_ctx_t 		*ctx;
	
	name.data = (u_char *)"status_ex_721";
	name.len = sizeof("status_ex_721")-1;
	
	size = sizeof(ngx_tcp_io) + STATU_MONITOR_DOMAINS * (sizeof(ngx_tcp_io)+URL_LEN)+URL_LEN;
	shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_stub_status_ex_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_status_ex_host_ctx_t));
	
	if (ctx == NULL) {
		return NGX_ERROR;
	}
	
    if (shm_zone->data) {
        ctx = shm_zone->data;
		
        return NGX_OK;
    }

    shm_zone->init = ngx_status_ex_init_zone;
    shm_zone->data = ctx;

	return NGX_OK;
}

int ngx_tcp_io_update(ngx_http_request_t *r)
{
	if (r == NULL)
		return NGX_ERROR;
	
	//if (r->connection->sent >0 )
	{
    	ngx_tcp_io_update_out(r->connection->sent, r);
	}
	
	//if (r->request_length > 0)
	{
   		ngx_tcp_io_update_in(r->request_length, r);
	}

    return NGX_OK;
}

ngx_msec_t ngx_tcp_io_getfirsttime()
{
	if (!statu_io_info)
	{
		return -1;
	}
	
	ngx_tcp_io *temp_tcp_io = statu_io_info;
	return (temp_tcp_io->http_stup_first_time);
}

int ngx_tcp_io_set_firsttime(ngx_msec_t msec_time)
{
	if (!statu_io_info)
	{
		return NGX_ERROR;
	}
	
	ngx_tcp_io *temp_tcp_io = statu_io_info;
	temp_tcp_io->http_stup_first_time = msec_time;
	
	return NGX_OK;
}

