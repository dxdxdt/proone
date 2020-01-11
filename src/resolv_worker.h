#pragma once
#include "protocol.h"
#include "worker.h"

#include <mbedtls/ctr_drbg.h>


struct prne_resolv_wkr_ctx;
typedef struct prne_resolv_wkr_ctx* prne_resolv_wkr_ctx_t;

struct prne_resolv_prm;
struct prne_resolv_fut;
struct prne_resolv_rr;
typedef struct prne_resolv_prm prne_resolv_prm_t;
typedef struct prne_resolv_fut prne_resolv_fut_t;
typedef struct prne_resolv_rr prne_resolv_rr_t;
typedef uint16_t prne_resolv_rcode_t;

typedef enum {
	PRNE_RESOLV_QR_NONE = -1,
	
	PRNE_RESOLV_QR_OK,
	PRNE_RESOLV_QR_ERR,
	PRNE_RESOLV_QR_PRO_ERR,
	PRNE_RESOLV_QR_FIN,
	PRNE_RESOLV_QR_IMPL,
	PRNE_RESOLV_QR_TIMEOUT,
	PRNE_RESOLV_QR_STATUS,

	NB_PRNE_RESOLV
} prne_resolv_qr_t;

typedef enum {
	PRNE_RESOLV_QT_NONE = -1,

	PRNE_RESOLV_QT_A,
	PRNE_RESOLV_QT_AAAA,
	PRNE_RESOLV_QT_TXT,

	NB_PRNE_RESOLV_QT
} prne_resolv_query_type_t;

struct prne_resolv_prm {
	void *ctx;
	prne_resolv_fut_t *fut;
	int evtfd;
};

struct prne_resolv_fut {
	size_t rr_cnt;
	prne_resolv_rr_t *rr;
	int err;
	prne_resolv_qr_t qr;
	prne_resolv_rcode_t status;
};

struct prne_resolv_rr {
	char *name;
	uint16_t rr_class, rr_type;
	uint32_t rr_ttl;
	uint8_t *rd_data;
	uint16_t rd_len;
};

// honor bind-utils' choice of words
#define PRNE_RESOLV_RCODE_NOERROR	0
#define PRNE_RESOLV_RCODE_FORMERR	1
#define PRNE_RESOLV_RCODE_SERVFAIL	2
#define PRNE_RESOLV_RCODE_NXDOMAIN	3
#define PRNE_RESOLV_RCODE_NOTIMP	4
#define PRNE_RESOLV_RCODE_REFUSED	5

#define PRNE_RESOLV_RTYPE_A		1
#define PRNE_RESOLV_RTYPE_NS	2
#define PRNE_RESOLV_RTYPE_CNAME	5
#define PRNE_RESOLV_RTYPE_SOA	6
#define PRNE_RESOLV_RTYPE_PTR	12
#define PRNE_RESOLV_RTYPE_MX	15
#define PRNE_RESOLV_RTYPE_TXT	16
#define PRNE_RESOLV_RTYPE_AAAA	28


prne_resolv_wkr_ctx_t prne_alloc_resolv_worker (prne_worker_t *w, prne_wkr_sched_req_t *wsr, mbedtls_ctr_drbg_context *ctr_drbg);
bool prne_resolv_prm_gethostbyname (prne_resolv_wkr_ctx_t wkr, const char *name, const prne_ipv_t ipv, prne_resolv_prm_t *out, const struct timespec *timeout);
bool prne_resolv_prm_gettxtrec (prne_resolv_wkr_ctx_t wkr, const char *name, prne_resolv_prm_t *out, const struct timespec *timeout);

void prne_resolv_init_prm (prne_resolv_prm_t *prm);
void prne_resolv_free_prm (prne_resolv_prm_t *prm);
void prne_init_resolv_fut (prne_resolv_fut_t *fut);
void prne_free_resolv_fut (prne_resolv_fut_t *fut);
void prne_init_resolv_rr (prne_resolv_rr_t *rr);
void prne_free_resolv_rr (prne_resolv_rr_t *rr);
const char *prne_resolv_qr_tostr (const prne_resolv_qr_t qr);
const char *prne_resolv_rcode_tostr (const prne_resolv_rcode_t rc);
const char *prne_resolv_rrtype_tostr (const uint16_t rrt);
