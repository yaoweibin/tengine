

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_ESI_MAX_PARAMS  16
#define NGX_HTTP_ESI_COMMAND_LEN 32
#define NGX_HTTP_ESI_PARAM_LEN   32
#define NGX_HTTP_ESI_PARAMS_N    4

#define NGX_HTTP_ESI_ERROR       1


typedef struct {
    ngx_buf_t                *buf;

    u_char                   *pos;
    u_char                   *copy_start;
    u_char                   *copy_end;

    ngx_chain_t              *in;
    ngx_chain_t              *out;
    ngx_chain_t             **last_out;
    ngx_chain_t              *busy;
    ngx_chain_t              *free;

    ngx_uint_t                state;
    ngx_uint_t                saved_state;
    size_t                    saved;
    size_t                    looked;

    size_t                    value_len;

    ngx_uint_t                key;
    ngx_str_t                 command;
    ngx_array_t               params;
    ngx_table_elt_t          *param;
    ngx_table_elt_t           params_array[NGX_HTTP_ESI_PARAMS_N];

    void                     *value_buf;
    ngx_str_t                 errmsg;
    ngx_http_request_t       *wait;

    ngx_url_t                 u;

    unsigned                  wait_resolver;
} ngx_http_esi_ctx_t;


typedef struct {
    ngx_flag_t                enable;
    ngx_flag_t                silent_errors;
    ngx_flag_t                ignore_recycled_buffers;

    ngx_hash_t                types;

    size_t                    value_len;

    ngx_array_t              *types_keys;
} ngx_http_esi_loc_conf_t;


typedef enum {
    esi_start_state = 0,
    esi_tag_state,
    esi_tag_e_state,
    esi_tag_s_state,
    esi_tag_colon_state,
    esi_precommand_state,
    esi_command_state,
    esi_preparam_state,
    esi_param_state,
    esi_preequal_state,
    esi_prevalue_state,
    esi_double_quoted_value_state,
    esi_quoted_value_state,
    esi_quoted_symbol_state,
    esi_postparam_state,
    esi_tag_end_state,
    esi_error_state,
    esi_error_end_state,
} ngx_http_esi_state_e;


typedef ngx_int_t (*ngx_http_esi_command_pt) (ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx, ngx_str_t **);

typedef struct {
    ngx_str_t                 name;
    ngx_http_esi_command_pt   handler;
} ngx_http_esi_command_t;


static ngx_int_t ngx_http_esi_output(ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx);
static void ngx_http_esi_buffered(ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx);
static ngx_int_t ngx_http_esi_parse(ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx);

static ngx_http_esi_command_t *ngx_http_esi_find_command(
    ngx_http_esi_ctx_t *ctx);
static ngx_int_t ngx_http_esi_include(ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx, ngx_str_t **params);
static ngx_int_t ngx_http_esi_fetch_resource(ngx_http_request_t *r,
    ngx_http_esi_ctx_t *ctx);
static ngx_int_t ngx_http_esi_parse_url(ngx_url_t *u, ngx_str_t *url,
    ngx_pool_t *pool);
static ngx_int_t ngx_http_esi_resolve_host(ngx_http_request_t *r,
    ngx_str_t *host);
static void ngx_http_esi_resolve_callback(ngx_resolver_ctx_t *ctx);

static void *ngx_http_esi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_esi_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_esi_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_esi_filter_commands[] = {

    { ngx_string("esi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_esi_loc_conf_t, enable),
      NULL },

    { ngx_string("esi_silent_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_esi_loc_conf_t, silent_errors),
      NULL },

    { ngx_string("esi_ignore_recycled_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_esi_loc_conf_t, ignore_recycled_buffers),
      NULL },

    { ngx_string("esi_value_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_esi_loc_conf_t, value_len),
      NULL },

    { ngx_string("esi_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_esi_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_esi_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_esi_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_esi_create_loc_conf,          /* create location configuration */
    ngx_http_esi_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_esi_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_esi_filter_module_ctx,       /* module context */
    ngx_http_esi_filter_commands,          /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static u_char ngx_http_esi_string[] = "<esi";

static ngx_http_esi_command_t  ngx_http_esi_commands[] = {
    { ngx_string("include"), ngx_http_esi_include },
    { ngx_null_string, NULL }
};


static ngx_int_t
ngx_http_esi_header_filter(ngx_http_request_t *r)
{
    ngx_http_esi_ctx_t       *ctx;
    ngx_http_esi_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_esi_filter_module);

    if (!elcf->enable
        || r->headers_out.content_length_n == 0
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || ngx_http_test_content_type(r, &elcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_esi_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_esi_filter_module);

    ctx->value_len = elcf->value_len;
    ctx->last_out = &ctx->out;

    ctx->params.elts = ctx->params_array;
    ctx->params.size = sizeof(ngx_table_elt_t);
    ctx->params.nalloc = NGX_HTTP_ESI_PARAMS_N;
    ctx->params.pool = r->pool;

    ngx_str_set(&ctx->errmsg,
                "[an error occurred while processing the directive]");

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
        ngx_http_clear_accept_ranges(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_esi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_esi_ctx_t        *ctx;
    ngx_http_esi_command_t    *cmd;
    ngx_http_esi_loc_conf_t   *elcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_esi_filter_module);

    if (ctx == NULL
        || (in == NULL
            && ctx->buf == NULL
            && ctx->in == NULL
            && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http esi filter \"%V?%V\"", &r->uri, &r->args);

    if (ctx->wait_resolver) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http esi filter wait for the host \"%V\" resolving",
                       &ctx->u.host);
        return NGX_AGAIN;
    }

    if (ctx->wait) {

        if (r != r->connection->data) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http esi filter wait \"%V?%V\" non-active",
                           &ctx->wait->uri, &ctx->wait->args);

            return NGX_AGAIN;
        }

        if (ctx->wait->done) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http esi filter wait \"%V?%V\" done",
                           &ctx->wait->uri, &ctx->wait->args);

            ctx->wait = NULL;

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http esi filter wait \"%V?%V\"",
                           &ctx->wait->uri, &ctx->wait->args);

            return ngx_http_next_body_filter(r, NULL);
        }
    }

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_esi_filter_module);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == esi_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_esi_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, looked: %d %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d", ctx->saved);

                if (ctx->saved) {

                    if (ctx->free) {
                        cl = ctx->free;
                        ctx->free = ctx->free->next;
                        b = cl->buf;
                        ngx_memzero(b, sizeof(ngx_buf_t));

                    } else {
                        b = ngx_calloc_buf(r->pool);
                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                    }

                    b->memory = 1;
                    b->pos = ngx_http_esi_string;
                    b->last = ngx_http_esi_string + ctx->saved;

                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    ctx->saved = 0;
                }

                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;

                } else {
                    b = ngx_alloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->memory = 1;
                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->recycled = 0;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "out buf: %*s", ngx_buf_size(b), b->pos);

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (ctx->state == esi_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            b = NULL;

            if (rc == NGX_OK) {

                cmd = ngx_http_esi_find_command(ctx);
                if (cmd == NULL) {
                    goto esi_error;
                }

                if (ctx->params.nelts > NGX_HTTP_ESI_MAX_PARAMS) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too many ESI command parameters: \"%V\"",
                                  &ctx->command);
                    goto esi_error;
                }

                /* TODO: command verification */

                if (ctx->out) {

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "esi flush");

                    if (ngx_http_esi_output(r, ctx) == NGX_ERROR) {
                        return NGX_ERROR;
                    }
                }

                rc = ngx_http_esi_include(r, ctx, NULL);

                if (rc == NGX_OK) {
                    continue;
                }

                if (rc == NGX_DONE || rc == NGX_AGAIN || rc == NGX_ERROR) {
                    ngx_http_esi_buffered(r, ctx);
                    return rc;
                }
            }

            /* rc == NGX_HTTP_ESI_ERROR */

esi_error:

            if (elcf->silent_errors) {
                continue;
            }

            if (ctx->free) {
                cl = ctx->free;
                ctx->free = ctx->free->next;
                b = cl->buf;
                ngx_memzero(b, sizeof(ngx_buf_t));

            } else {
                b = ngx_calloc_buf(r->pool);
                if (b == NULL) {
                    return NGX_ERROR;
                }

                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                cl->buf = b;
            }

            b->memory = 1;
            b->pos = ctx->errmsg.data;
            b->last = ctx->errmsg.data + ctx->errmsg.len;

            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            continue;
        }

        if (ctx->buf->last_buf || ngx_buf_in_memory(ctx->buf)) {
            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    ngx_memzero(b, sizeof(ngx_buf_t));

                } else {
                    b = ngx_calloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            if (elcf->ignore_recycled_buffers == 0)  {
                b->recycled = ctx->buf->recycled;
            }
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_esi_output(r, ctx);
}


static ngx_int_t
ngx_http_esi_output(ngx_http_request_t *r, ngx_http_esi_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "esi out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in esi");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    ngx_http_esi_buffered(r, ctx);

    return rc;
}


static void
ngx_http_esi_buffered(ngx_http_request_t *r, ngx_http_esi_ctx_t *ctx)
{
    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SSI_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SSI_BUFFERED;
    }
}


static ngx_int_t
ngx_http_esi_parse(ngx_http_request_t *r, ngx_http_esi_ctx_t *ctx)
{
    u_char                *p, *value, *last, *copy_end, ch;
    size_t                 looked;
    ngx_http_esi_state_e   state;

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;

        if (state == esi_start_state) {

            /* the tight loop */

            for ( ;; ) {
                if (ch == '<') {
                    copy_end = p;
                    looked = 1;
                    state = esi_tag_state;

                    goto tag_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
            }

            ctx->state = state;
            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return NGX_AGAIN;

        tag_started:

            continue;
        }

        switch (state) {

        case esi_start_state:
            /* not reached */
            break;

        case esi_tag_state:
            switch (ch) {
            case 'e':
                looked = 2;
                state = esi_tag_e_state;
                break;

            case '<':
                copy_end = p;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = esi_start_state;
                break;
            }

            break;

        case esi_tag_e_state:
            switch (ch) {
            case 's':
                looked = 3;
                state = esi_tag_s_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = esi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = esi_start_state;
                break;
            }

            break;

        case esi_tag_s_state:
            switch (ch) {
            case 'i':
                looked = 4;
                state = esi_tag_colon_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = esi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = esi_start_state;
                break;
            }

            break;

        case esi_tag_colon_state:
            switch (ch) {
            case ':':
                if (p - ctx->pos < 4) {
                    ctx->saved = 0;
                }
                looked = 0;
                state = esi_precommand_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = esi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = esi_start_state;
                break;
            }

            break;

        case esi_precommand_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            default:
                ctx->command.len = 1;
                ctx->command.data = ngx_pnalloc(r->pool,
                                                NGX_HTTP_ESI_COMMAND_LEN);
                if (ctx->command.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->command.data[0] = ch;

                ctx->params.nelts = 0;

                state = esi_command_state;
                break;
            }

            break;

        case esi_command_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = esi_preparam_state;
                break;

            case '/':
                state = esi_tag_end_state;
                break;

            default:
                if (ctx->command.len == NGX_HTTP_ESI_COMMAND_LEN) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "the \"%V%c...\" ESI command is too long",
                                  &ctx->command, ch);

                    state = esi_error_state;
                    break;
                }

                ctx->command.data[ctx->command.len++] = ch;
            }

            break;

        case esi_preparam_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '/':
                state = esi_tag_end_state;
                break;

            default:
                ctx->param = ngx_array_push(&ctx->params);
                if (ctx->param == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.len = 1;
                ctx->param->key.data = ngx_pnalloc(r->pool,
                                                   NGX_HTTP_ESI_PARAM_LEN);
                if (ctx->param->key.data == NULL) {
                    return NGX_ERROR;
                }

                ctx->param->key.data[0] = ch;

                ctx->param->value.len = 0;

                if (ctx->value_buf == NULL) {
                    ctx->param->value.data = ngx_pnalloc(r->pool,
                                                         ctx->value_len + 1);
                    if (ctx->param->value.data == NULL) {
                        return NGX_ERROR;
                    }

                } else {
                    ctx->param->value.data = ctx->value_buf;
                }

                state = esi_param_state;
                break;
            }

            break;

        case esi_param_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = esi_preequal_state;
                break;

            case '=':
                state = esi_prevalue_state;
                break;

            case '/':
                state = esi_error_end_state;

                ctx->param->key.data[ctx->param->key.len++] = ch;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "invalid \"%V\" parameter in \"%V\" ESI command",
                              &ctx->param->key, &ctx->command);
                break;

            default:
                if (ctx->param->key.len == NGX_HTTP_ESI_PARAM_LEN) {
                    state = esi_error_state;
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" parameter in "
                                  "\"%V\" ESI command",
                                  &ctx->param->key, ch, &ctx->command);
                    break;
                }

                ctx->param->key.data[ctx->param->key.len++] = ch;
            }

            break;

        case esi_preequal_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '=':
                state = esi_prevalue_state;
                break;

            default:
                if (ch == '/') {
                    state = esi_error_end_state;
                } else {
                    state = esi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" "
                              "parameter in \"%V\" ESI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case esi_prevalue_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '"':
                state = esi_double_quoted_value_state;
                break;

            case '\'':
                state = esi_quoted_value_state;
                break;

            default:
                if (ch == '/') {
                    state = esi_error_end_state;
                } else {
                    state = esi_error_state;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol before value of "
                              "\"%V\" parameter in \"%V\" ESI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case esi_double_quoted_value_state:
            switch (ch) {
            case '"':
                state = esi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = esi_double_quoted_value_state;
                state = esi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" ESI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = esi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case esi_quoted_value_state:
            switch (ch) {
            case '\'':
                state = esi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = esi_quoted_value_state;
                state = esi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" ESI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = esi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case esi_quoted_symbol_state:
            state = ctx->saved_state;

            if (ctx->param->value.len == ctx->value_len) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "too long \"%V%c...\" value of \"%V\" "
                              "parameter in \"%V\" ESI command",
                              &ctx->param->value, ch, &ctx->param->key,
                              &ctx->command);
                state = esi_error_state;
                break;
            }

            ctx->param->value.data[ctx->param->value.len++] = ch;

            break;

        case esi_postparam_state:

            if (ctx->param->value.len + 1 < ctx->value_len / 2) {
                value = ngx_pnalloc(r->pool, ctx->param->value.len + 1);
                if (value == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(value, ctx->param->value.data,
                           ctx->param->value.len);

                ctx->value_buf = ctx->param->value.data;
                ctx->param->value.data = value;

            } else {
                ctx->value_buf = NULL;
            }

            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = esi_preparam_state;
                break;

            case '/':
                state = esi_tag_end_state;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" value "
                              "of \"%V\" parameter in \"%V\" ESI command",
                              ch, &ctx->param->value, &ctx->param->key,
                              &ctx->command);
                state = esi_error_state;
                break;
            }

            break;

        case esi_tag_end_state:
            switch (ch) {
            case '>':
                ctx->state = esi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_OK;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" ESI command",
                              ch, &ctx->command);
                state = esi_error_state;
                break;
            }

            break;

        case esi_error_state:
            switch (ch) {
            case '/':
                state = esi_error_end_state;
                break;

            default:
                break;
            }

            break;

        case esi_error_end_state:
            switch (ch) {
            case '>':
                ctx->state = esi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_HTTP_ESI_ERROR;

            default:
                state = esi_error_state;
                break;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == esi_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return NGX_AGAIN;
}


static ngx_http_esi_command_t *
ngx_http_esi_find_command(ngx_http_esi_ctx_t *ctx)
{
    ngx_http_esi_command_t *cmd;

    for (cmd = ngx_http_esi_commands; cmd->handler; cmd++) {
        if (cmd == NULL || cmd->name.data == NULL) {
            break;
        }

        if (ctx->command.len != cmd->name.len) {
            continue;
        }

        if (ngx_strncmp(ctx->command.data, cmd->name.data,
                        cmd->name.len) == 0) {
            return cmd;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_esi_include(ngx_http_request_t *r, ngx_http_esi_ctx_t *ctx,
    ngx_str_t **params)
{
    ngx_uint_t                   i;
    ngx_table_elt_t             *param;
 
    param = ctx->params.elts;
    for (i = 0; i < ctx->params.nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "esi include: praram[\"%V\"] = %V", &param[i].key, &param[i].value);
    }

    if (ngx_http_esi_parse_url(&ctx->u, &param[0].value, r->pool) == NGX_ERROR) {
        if (ctx->u.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                               "%s in with ESI url \"%V\"", ctx->u.err, &ctx->u.url);
        }

        return NGX_HTTP_ESI_ERROR;
    }

    if (ctx->u.one_addr) {
        return ngx_http_esi_fetch_resource(r, ctx);

    } else if (ctx->u.naddrs == 0) {

        ctx->wait_resolver = 1;

        if (ngx_http_esi_resolve_host(r, &ctx->u.host) == NGX_ERROR) {
            return NGX_HTTP_ESI_ERROR;
        }
    } else {
        return ngx_http_esi_fetch_resource(r, ctx);
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_esi_fetch_resource(ngx_http_request_t *r, ngx_http_esi_ctx_t *ctx)
{
    u_char                      *dst, *src;
    size_t                       len;
    ngx_str_t                   *uri, args;
    ngx_uint_t                   flags;
    ngx_http_request_t          *sr;

    uri = &ctx->u.uri;
    if (uri->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no uri in \"include\" ESI command");
        return NGX_HTTP_ESI_ERROR;
    }

    dst = uri->data;
    src = uri->data;

    ngx_unescape_uri(&dst, &src, uri->len, NGX_UNESCAPE_URI);

    len = (uri->data + uri->len) - src;
    if (len) {
        dst = ngx_movemem(dst, src, len);
    }

    uri->len = dst - uri->data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "esi include: \"%V\"", uri);

    ngx_str_null(&args);
    flags = NGX_HTTP_LOG_UNSAFE;

    if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
        return NGX_HTTP_ESI_ERROR;
    }

    flags = NGX_HTTP_SUBREQUEST_WAITED;

    if (ngx_http_subrequest(r, uri, &args, &sr, NULL, flags) != NGX_OK) {
        return NGX_HTTP_ESI_ERROR;
    }

    if (ctx->wait == NULL) {
        ctx->wait = sr;

        return NGX_AGAIN;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "can only wait for one subrequest at a time");
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_esi_parse_url(ngx_url_t *u, ngx_str_t *url, ngx_pool_t *pool)
{
    u_char              *p;
    size_t               add;
    in_port_t            port;
    in_addr_t            in_addr;
    struct sockaddr_in  *sin;

    add = 0;
    port = 80;

    ngx_memzero(u, sizeof(ngx_url_t));

    if (url->len == 0) {
        return NGX_OK;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

        add = 8;
        port = 443;
    } else if (url->data[0] == '/') {

        /* The local url */
        u->one_addr = 1;
    } else {
        return NGX_ERROR;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = port;
    u->uri_part = 1;
    u->no_resolve = 1;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        return NGX_ERROR;
    }

    in_addr = ngx_inet_addr(u->host.data, u->host.len);

    if (in_addr != INADDR_NONE) {
        u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
        if (u->addrs == NULL) {
            return NGX_ERROR;
        }

        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        u->naddrs = 1;

        sin->sin_family = AF_INET;
        sin->sin_port = port;
        sin->sin_addr.s_addr = in_addr;

        u->addrs[0].sockaddr = (struct sockaddr *) sin;
        u->addrs[0].socklen = sizeof(struct sockaddr_in);

        p = ngx_pnalloc(pool, u->host.len + sizeof(":65535") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        u->addrs[0].name.len = ngx_sprintf(p, "%V:%d",
                                           &u->host, ntohs(port)) - p;
        u->addrs[0].name.data = p;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_esi_resolve_host(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_resolver_ctx_t        *ctx, temp;
    ngx_http_core_loc_conf_t  *clcf;

    temp.name = *host;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ctx = ngx_resolve_start(clcf->resolver, &temp);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no resolver defined to resolve %V", host);
        return NGX_ERROR;
    }

    ctx->name = *host;
    ctx->type = NGX_RESOLVE_A;
    ctx->handler = ngx_http_esi_resolve_callback;
    ctx->data = r;
    ctx->timeout = clcf->resolver_timeout;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_esi_resolve_callback(ngx_resolver_ctx_t *ctx)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i;
    struct sockaddr_in  *sin;
    ngx_http_request_t  *r;
    ngx_http_esi_ctx_t  *ectx;

    r = ctx->data;

    ectx = ngx_http_get_module_ctx(r, ngx_http_esi_filter_module);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        /*TODO*/
    }

#if (NGX_DEBUG)
    {
    in_addr_t   addr;
    ngx_uint_t  i;

    for (i = 0; i < ctx->naddrs; i++) {
        addr = ntohl(ctx->addrs[i]);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %ud.%ud.%ud.%ud",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }
    }
#endif

    ectx->u.naddrs = ctx->naddrs;

    ectx->u.addrs = ngx_pcalloc(r->pool, ctx->naddrs * sizeof(ngx_addr_t));
    if (ectx->u.addrs == NULL) {
        /*TODO*/
    }

    for (i = 0; i < ctx->naddrs; i++) {

        sin = ngx_pcalloc(r->pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            /*TODO*/
        }

        *sin = *(struct sockaddr_in *) &ctx->addrs[i];

        ectx->u.addrs[i].sockaddr = (struct sockaddr *) sin;
        ectx->u.addrs[i].socklen = sizeof(struct sockaddr_in);

        len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            /*TODO*/
        }

        len = ngx_sock_ntop((struct sockaddr *) sin, p, len, 1);

        ectx->u.addrs[i].name.len = len;
        ectx->u.addrs[i].name.data = p;
    }

    ngx_resolve_name_done(ctx);

    ectx->wait_resolver = 0;

    ngx_http_esi_fetch_resource(r, ectx);
}


static void *
ngx_http_esi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_esi_loc_conf_t  *elcf;

    elcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_esi_loc_conf_t));
    if (elcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    elcf->enable = NGX_CONF_UNSET;
    elcf->silent_errors = NGX_CONF_UNSET;
    elcf->ignore_recycled_buffers = NGX_CONF_UNSET;

    elcf->value_len = NGX_CONF_UNSET_SIZE;

    return elcf;
}


static char *
ngx_http_esi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_esi_loc_conf_t *prev = parent;
    ngx_http_esi_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);
    ngx_conf_merge_value(conf->ignore_recycled_buffers,
                         prev->ignore_recycled_buffers, 0);

    ngx_conf_merge_size_value(conf->value_len, prev->value_len, 255);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_esi_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_esi_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_esi_body_filter;

    return NGX_OK;
}
