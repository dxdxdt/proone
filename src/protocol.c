#include "protocol.h"
#include "util_rt.h"
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

prne_htbt_ser_rc_t prne_enc_host_cred (uint8_t *data, const size_t len, size_t *actual, const uint8_t salt, const prne_host_cred_t *in) {
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
	prne_htbt_ser_rc_t ret = PRNE_HTBT_SER_RC_OK;
	char *id = NULL, *pw = NULL;

	if (!(2 <= len && len <= 2 + 255 + 255)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	id = prne_alloc_str(data[0]);
	pw = prne_alloc_str(data[1]);
	if (id == NULL || pw == NULL) {
		ret = PRNE_HTBT_SER_RC_ERRNO;
		goto END;
	}
	memcpy(id, data + 2, data[0]);
	id[data[0]] = 0;
	memcpy(pw, data + 2 + data[0], data[1]);
	pw[data[1]] = 0;

	out->id = id;
	out->pw = pw;
	id = pw = NULL;

END:
	prne_free(id);
	prne_free(pw);

	return ret;
}

void prne_htbt_init_host_info (prne_htbt_host_info_t *hi) {
	hi->parent_uptime = 0;
	hi->child_uptime = 0;
	hi->rerun_cnt = 0;
	hi->bne_cnt = 0;
	hi->infect_cnt = 0;
	hi->parent_pid = 0;
	hi->child_pid = 0;
	memzero(hi->prog_ver, 16);
	memzero(hi->boot_id, 16);
	memzero(hi->instance_id, 16);
	hi->cred = NULL;
	hi->cred_size = 0;
	hi->arch = PRNE_ARCH_NONE;
}

bool prne_htbt_alloc_host_info (prne_htbt_host_info_t *hi, const size_t cred_size) {
	void *ny_mem;

	if (!(3 < cred_size && cred_size <= 3 + 255 + 255)) {
		errno = EINVAL;
		return false;
	}

	ny_mem = prne_malloc(1, cred_size);
	if (ny_mem == NULL) {
		return false;
	}

	prne_free(hi->cred);
	hi->cred = (uint8_t*)ny_mem;
	hi->cred_size = cred_size;

	return true;
}

void prne_htbt_free_host_info (prne_htbt_host_info_t *hi) {
	RETIF_NULL(hi);

	prne_free(hi->cred);
	hi->cred = NULL;
	hi->cred_size = 0;
}

bool prne_htbt_eq_host_info (const prne_htbt_host_info_t *a, const prne_htbt_host_info_t *b) {
	return
		a->parent_uptime == b->parent_uptime &&
		a->child_uptime == b->child_uptime &&
		a->rerun_cnt == b->rerun_cnt &&
		a->bne_cnt == b->bne_cnt &&
		a->infect_cnt == b->infect_cnt &&
		a->parent_pid == b->parent_pid &&
		a->child_pid == b->child_pid &&
		a->cred_size == b->cred_size &&
		a->arch == b->arch &&
		memcmp(a->prog_ver, b->prog_ver, 16) == 0 &&
		memcmp(a->boot_id, b->boot_id, 16) == 0 &&
		memcmp(a->instance_id, b->instance_id, 16) == 0 &&
		memcmp(a->cred, b->cred, a->cred_size) == 0;
}

void prne_htbt_init_cmd (prne_htbt_cmd_t *cmd) {
	cmd->mem_len = 0;
	cmd->mem = NULL;
	cmd->args = NULL;
	cmd->argc = 0;
}

bool prne_htbt_alloc_cmd (prne_htbt_cmd_t *cmd, const uint16_t argc, const size_t *args_len) {
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
	return
		a->mem_len == b->mem_len &&
		a->argc == b->argc &&
		memcmp(a->mem, b->mem, a->mem_len) == 0;
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
	mem[0] = (uint8_t)((id & 0xFF00) >> 8);
	mem[1] = (uint8_t)((id & 0x00FF) >> 0);
	mem[2] = (uint8_t)in->op;

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_status (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_status_t *in) {
	*actual = 5;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	
	mem[0] = (uint8_t)in->code;
	mem[1] = (uint8_t)(((uint32_t)in->err & 0xFF000000) >> 24);
	mem[2] = (uint8_t)(((uint32_t)in->err & 0x00FF0000) >> 16);
	mem[3] = (uint8_t)(((uint32_t)in->err & 0x0000FF00) >> 8);
	mem[4] = (uint8_t)(((uint32_t)in->err & 0x000000FF) >> 0);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_host_info (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_host_info_t *in) {
	if (in->cred_size > 0 && !(3 <= in->cred_size && in->cred_size <= 3 + 255 * 2)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	*actual = 99 + in->cred_size;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = in->prog_ver[0];
	mem[1] = in->prog_ver[1];
	mem[2] = in->prog_ver[2];
	mem[3] = in->prog_ver[3];
	mem[4] = in->prog_ver[4];
	mem[5] = in->prog_ver[5];
	mem[6] = in->prog_ver[6];
	mem[7] = in->prog_ver[7];
	mem[8] = in->prog_ver[8];
	mem[9] = in->prog_ver[9];
	mem[10] = in->prog_ver[10];
	mem[11] = in->prog_ver[11];
	mem[12] = in->prog_ver[12];
	mem[13] = in->prog_ver[13];
	mem[14] = in->prog_ver[14];
	mem[15] = in->prog_ver[15];

	mem[16] = in->boot_id[0];
	mem[17] = in->boot_id[1];
	mem[18] = in->boot_id[2];
	mem[19] = in->boot_id[3];
	mem[20] = in->boot_id[4];
	mem[21] = in->boot_id[5];
	mem[22] = in->boot_id[6];
	mem[23] = in->boot_id[7];
	mem[24] = in->boot_id[8];
	mem[25] = in->boot_id[9];
	mem[26] = in->boot_id[10];
	mem[27] = in->boot_id[11];
	mem[28] = in->boot_id[12];
	mem[29] = in->boot_id[13];
	mem[30] = in->boot_id[14];
	mem[31] = in->boot_id[15];

	mem[32] = in->instance_id[0];
	mem[33] = in->instance_id[1];
	mem[34] = in->instance_id[2];
	mem[35] = in->instance_id[3];
	mem[36] = in->instance_id[4];
	mem[37] = in->instance_id[5];
	mem[38] = in->instance_id[6];
	mem[39] = in->instance_id[7];
	mem[40] = in->instance_id[8];
	mem[41] = in->instance_id[9];
	mem[42] = in->instance_id[10];
	mem[43] = in->instance_id[11];
	mem[44] = in->instance_id[12];
	mem[45] = in->instance_id[13];
	mem[46] = in->instance_id[14];
	mem[47] = in->instance_id[15];

	mem[48] = (uint8_t)((in->parent_uptime & 0xFF00000000000000) >> 56);
	mem[49] = (uint8_t)((in->parent_uptime & 0x00FF000000000000) >> 48);
	mem[50] = (uint8_t)((in->parent_uptime & 0x0000FF0000000000) >> 40);
	mem[51] = (uint8_t)((in->parent_uptime & 0x000000FF00000000) >> 32);
	mem[52] = (uint8_t)((in->parent_uptime & 0x00000000FF000000) >> 24);
	mem[53] = (uint8_t)((in->parent_uptime & 0x0000000000FF0000) >> 16);
	mem[54] = (uint8_t)((in->parent_uptime & 0x000000000000FF00) >> 8);
	mem[55] = (uint8_t)((in->parent_uptime & 0x00000000000000FF) >> 0);

	mem[56] = (uint8_t)((in->child_uptime & 0xFF00000000000000) >> 56);
	mem[57] = (uint8_t)((in->child_uptime & 0x00FF000000000000) >> 48);
	mem[58] = (uint8_t)((in->child_uptime & 0x0000FF0000000000) >> 40);
	mem[59] = (uint8_t)((in->child_uptime & 0x000000FF00000000) >> 32);
	mem[60] = (uint8_t)((in->child_uptime & 0x00000000FF000000) >> 24);
	mem[61] = (uint8_t)((in->child_uptime & 0x0000000000FF0000) >> 16);
	mem[62] = (uint8_t)((in->child_uptime & 0x000000000000FF00) >> 8);
	mem[63] = (uint8_t)((in->child_uptime & 0x00000000000000FF) >> 0);

	mem[64] = (uint8_t)((in->rerun_cnt & 0xFF00000000000000) >> 56);
	mem[65] = (uint8_t)((in->rerun_cnt & 0x00FF000000000000) >> 48);
	mem[66] = (uint8_t)((in->rerun_cnt & 0x0000FF0000000000) >> 40);
	mem[67] = (uint8_t)((in->rerun_cnt & 0x000000FF00000000) >> 32);
	mem[68] = (uint8_t)((in->rerun_cnt & 0x00000000FF000000) >> 24);
	mem[69] = (uint8_t)((in->rerun_cnt & 0x0000000000FF0000) >> 16);
	mem[70] = (uint8_t)((in->rerun_cnt & 0x000000000000FF00) >> 8);
	mem[71] = (uint8_t)((in->rerun_cnt & 0x00000000000000FF) >> 0);

	mem[72] = (uint8_t)((in->bne_cnt & 0xFF00000000000000) >> 56);
	mem[73] = (uint8_t)((in->bne_cnt & 0x00FF000000000000) >> 48);
	mem[74] = (uint8_t)((in->bne_cnt & 0x0000FF0000000000) >> 40);
	mem[75] = (uint8_t)((in->bne_cnt & 0x000000FF00000000) >> 32);
	mem[76] = (uint8_t)((in->bne_cnt & 0x00000000FF000000) >> 24);
	mem[77] = (uint8_t)((in->bne_cnt & 0x0000000000FF0000) >> 16);
	mem[78] = (uint8_t)((in->bne_cnt & 0x000000000000FF00) >> 8);
	mem[79] = (uint8_t)((in->bne_cnt & 0x00000000000000FF) >> 0);

	mem[80] = (uint8_t)((in->infect_cnt & 0xFF00000000000000) >> 56);
	mem[81] = (uint8_t)((in->infect_cnt & 0x00FF000000000000) >> 48);
	mem[82] = (uint8_t)((in->infect_cnt & 0x0000FF0000000000) >> 40);
	mem[83] = (uint8_t)((in->infect_cnt & 0x000000FF00000000) >> 32);
	mem[84] = (uint8_t)((in->infect_cnt & 0x00000000FF000000) >> 24);
	mem[85] = (uint8_t)((in->infect_cnt & 0x0000000000FF0000) >> 16);
	mem[86] = (uint8_t)((in->infect_cnt & 0x000000000000FF00) >> 8);
	mem[87] = (uint8_t)((in->infect_cnt & 0x00000000000000FF) >> 0);

	mem[88] = (uint8_t)((in->parent_pid & 0xFF000000) >> 24);
	mem[89] = (uint8_t)((in->parent_pid & 0x00FF0000) >> 16);
	mem[90] = (uint8_t)((in->parent_pid & 0x0000FF00) >> 8);
	mem[91] = (uint8_t)((in->parent_pid & 0x000000FF) >> 0);

	mem[92] = (uint8_t)((in->child_pid & 0xFF000000) >> 24);
	mem[93] = (uint8_t)((in->child_pid & 0x00FF0000) >> 16);
	mem[94] = (uint8_t)((in->child_pid & 0x0000FF00) >> 8);
	mem[95] = (uint8_t)((in->child_pid & 0x000000FF) >> 0);

	mem[96] = (uint8_t)((in->cred_size & 0xFF00) >> 8);
	mem[97] = (uint8_t)((in->cred_size & 0x00FF) >> 0);

	mem[98] = (uint8_t)in->arch;

	memcpy(mem + 99, in->cred, in->cred_size);

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

	mem[0] = (uint8_t)((in->mem_len & 0xFF00) >> 8);
	mem[1] = (uint8_t)((in->mem_len & 0x00FF) >> 0);
	memcpy(mem + 2, in->mem, in->mem_len);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_ser_bin_meta (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_bin_meta_t *in) {
	*actual = in->cmd.mem_len + 5;

	if (mem_len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	mem[0] = (uint8_t)((in->bin_size & 0xFF0000) >> 16);
	mem[1] = (uint8_t)((in->bin_size & 0x00FF00) >> 8);
	mem[2] = (uint8_t)((in->bin_size & 0x0000FF) >> 0);
	mem[3] = (uint8_t)((in->cmd.mem_len & 0xFF00) >> 8);
	mem[4] = (uint8_t)((in->cmd.mem_len & 0x00FF) >> 0);
	memcpy(mem + 5, in->cmd.mem, in->cmd.mem_len);

	return PRNE_HTBT_SER_RC_OK;
}


prne_htbt_ser_rc_t prne_htbt_dser_msg_head (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_msg_head_t *out) {
	*actual = 3;
	
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	out->id = (((uint_fast16_t)data[0] & 0x7F) << 8) | ((uint_fast16_t)data[1] << 0);
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
	out->err = (int32_t)
		(((uint_fast32_t)data[1] << 24) |
		((uint_fast32_t)data[2] << 16) |
		((uint_fast32_t)data[3] << 8) |
		((uint_fast32_t)data[4] << 0));

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_host_info (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_host_info_t *out) {
	uint_fast16_t cred_size;

	*actual = 99;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	cred_size = ((uint_fast16_t)data[96] << 8) | ((uint_fast16_t)data[97] << 0);
	*actual += cred_size;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}

	prne_htbt_free_host_info(out);
	if (!prne_htbt_alloc_host_info(out, cred_size)) {
		return PRNE_HTBT_SER_RC_ERRNO;
	}

	out->prog_ver[0] = data[0];
	out->prog_ver[1] = data[1];
	out->prog_ver[2] = data[2];
	out->prog_ver[3] = data[3];
	out->prog_ver[4] = data[4];
	out->prog_ver[5] = data[5];
	out->prog_ver[6] = data[6];
	out->prog_ver[7] = data[7];
	out->prog_ver[8] = data[8];
	out->prog_ver[9] = data[9];
	out->prog_ver[10] = data[10];
	out->prog_ver[11] = data[11];
	out->prog_ver[12] = data[12];
	out->prog_ver[13] = data[13];
	out->prog_ver[14] = data[14];
	out->prog_ver[15] = data[15];

	out->boot_id[0] = data[16];
	out->boot_id[1] = data[17];
	out->boot_id[2] = data[18];
	out->boot_id[3] = data[19];
	out->boot_id[4] = data[20];
	out->boot_id[5] = data[21];
	out->boot_id[6] = data[22];
	out->boot_id[7] = data[23];
	out->boot_id[8] = data[24];
	out->boot_id[9] = data[25];
	out->boot_id[10] = data[26];
	out->boot_id[11] = data[27];
	out->boot_id[12] = data[28];
	out->boot_id[13] = data[29];
	out->boot_id[14] = data[30];
	out->boot_id[15] = data[31];

	out->instance_id[0] = data[32];
	out->instance_id[1] = data[33];
	out->instance_id[2] = data[34];
	out->instance_id[3] = data[35];
	out->instance_id[4] = data[36];
	out->instance_id[5] = data[37];
	out->instance_id[6] = data[38];
	out->instance_id[7] = data[39];
	out->instance_id[8] = data[40];
	out->instance_id[9] = data[41];
	out->instance_id[10] = data[42];
	out->instance_id[11] = data[43];
	out->instance_id[12] = data[44];
	out->instance_id[13] = data[45];
	out->instance_id[14] = data[46];
	out->instance_id[15] = data[47];

	out->parent_uptime =
		((uint_fast64_t)data[48] << 56) |
		((uint_fast64_t)data[49] << 48) |
		((uint_fast64_t)data[50] << 40) |
		((uint_fast64_t)data[51] << 32) |
		((uint_fast64_t)data[52] << 24) |
		((uint_fast64_t)data[53] << 16) |
		((uint_fast64_t)data[54] << 8) |
		((uint_fast64_t)data[55] << 0);

	out->child_uptime =
		((uint_fast64_t)data[56] << 56) |
		((uint_fast64_t)data[57] << 48) |
		((uint_fast64_t)data[58] << 40) |
		((uint_fast64_t)data[59] << 32) |
		((uint_fast64_t)data[60] << 24) |
		((uint_fast64_t)data[61] << 16) |
		((uint_fast64_t)data[62] << 8) |
		((uint_fast64_t)data[63] << 0);

	out->rerun_cnt =
		((uint_fast64_t)data[64] << 56) |
		((uint_fast64_t)data[65] << 48) |
		((uint_fast64_t)data[66] << 40) |
		((uint_fast64_t)data[67] << 32) |
		((uint_fast64_t)data[68] << 24) |
		((uint_fast64_t)data[69] << 16) |
		((uint_fast64_t)data[70] << 8) |
		((uint_fast64_t)data[71] << 0);

	out->bne_cnt =
		((uint_fast64_t)data[72] << 56) |
		((uint_fast64_t)data[73] << 48) |
		((uint_fast64_t)data[74] << 40) |
		((uint_fast64_t)data[75] << 32) |
		((uint_fast64_t)data[76] << 24) |
		((uint_fast64_t)data[77] << 16) |
		((uint_fast64_t)data[78] << 8) |
		((uint_fast64_t)data[79] << 0);

	out->infect_cnt =
		((uint_fast64_t)data[80] << 56) |
		((uint_fast64_t)data[81] << 48) |
		((uint_fast64_t)data[82] << 40) |
		((uint_fast64_t)data[83] << 32) |
		((uint_fast64_t)data[84] << 24) |
		((uint_fast64_t)data[85] << 16) |
		((uint_fast64_t)data[86] << 8) |
		((uint_fast64_t)data[87] << 0);

	out->parent_pid =
		((uint_fast32_t)data[88] << 24) |
		((uint_fast32_t)data[89] << 16) |
		((uint_fast32_t)data[90] << 8) |
		((uint_fast32_t)data[91] << 0);

	out->child_pid =
		((uint_fast32_t)data[92] << 24) |
		((uint_fast32_t)data[93] << 16) |
		((uint_fast32_t)data[94] << 8) |
		((uint_fast32_t)data[95] << 0);

	out->cred_size =
		((uint_fast16_t)data[96] << 8) |
		((uint_fast16_t)data[97] << 0);

	out->arch = (prne_arch_t)data[98];

	memcpy(out->cred, data + 99, cred_size);

	return PRNE_HTBT_SER_RC_OK;
}

prne_htbt_ser_rc_t prne_htbt_dser_cmd (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_cmd_t *out) {
	uint_fast16_t args_len, argc = 0;
	char **args = NULL;
	char *mem = NULL;
	prne_htbt_ser_rc_t ret = PRNE_HTBT_SER_RC_OK;
	size_t i, str_len;
	char *ptr;

	*actual = 2;
	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	
	args_len = ((uint_fast16_t)data[0] << 8) | ((uint_fast16_t)data[1] << 0);
	*actual += args_len;

	if (len < *actual) {
		return PRNE_HTBT_SER_RC_MORE_BUF;
	}
	if (args_len > PRNE_HTBT_ARG_MEM_MAX || (args_len > 0 && data[args_len + 1] != 0)) {
		return PRNE_HTBT_SER_RC_FMT_ERR;
	}

	for (i = 0; i < args_len; i += 1) {
		if (data[2 + i] == 0) {
			argc += 1;
			if (argc > PRNE_HTBT_ARGS_MAX) {
				return PRNE_HTBT_SER_RC_FMT_ERR;
			}
		}
	}

	args = (char**)prne_malloc(sizeof(char*), argc + 1);
	mem = (char*)prne_malloc(1, args_len);
	if (args == NULL || mem == NULL) {
		ret = PRNE_HTBT_SER_RC_ERRNO;
		goto END;
	}

	memcpy(mem, data + 2, args_len);

	ptr = mem;
	for (i = 0; i < argc; i += 1) {
		str_len = strlen(ptr);
		args[i] = ptr;
		ptr += str_len + 1;
	}
	args[argc] = NULL;

	prne_htbt_free_cmd(out);
	out->mem = mem;
	out->mem_len = args_len;
	out->args = args;
	out->argc = argc;
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
	out->bin_size =
		((uint_fast32_t)data[0] << 16) |
		((uint_fast32_t)data[1] << 8) |
		((uint_fast32_t)data[2] << 0);

	return PRNE_HTBT_SER_RC_OK;
}
