#pragma once
#include "protocol.h"
#include "util_ct.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


typedef struct prne_htbt_host_info prne_htbt_host_info_t;

typedef enum {
	PRNE_HTBT_OP_HOST_INFO,
	PRNE_HTBT_OP_CMD,
	PRNE_HTBT_OP_NY_BIN,
	PRNE_HTBT_OP_RSP,

	NB_PRNE_HTBT_OP
} prne_htbt_op_t;
PRNE_LIMIT_ENUM(prne_htbt_op_t, NB_PRNE_HTBT_OP, 0xFF);

typedef enum {
	PRNE_HTBT_RSP_OK,
	PRNE_HTBT_RSP_ERRNO,

	NB_PRNE_HTBT_RSP
} prne_htbt_rsp_t;
PRNE_LIMIT_ENUM(prne_htbt_rsp_t, NB_PRNE_HTBT_RSP, 0xFF);

struct prne_htbt_host_info {
	char prog_ver[36];
	uint64_t uptime;
	uint64_t rerun_cnt;
	uint64_t bne_cnt;
	uint64_t infect_cnt;
	uint32_t god_pid;
	uint32_t proone_pid;
	const char *cred_str;
	uint8_t cred_id_len;
	uint8_t cred_pw_len;
	prne_arch_t arch;
};
