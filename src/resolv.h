#pragma once
#include "protocol.h"
#include "pth.h"

#include <mbedtls/ctr_drbg.h>


struct prne_resolv;
typedef struct prne_resolv prne_resolv_t;
typedef struct prne_resolv_ns_pool prne_resolv_ns_pool_t;

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

struct prne_resolv_ns_pool {
	prne_net_endpoint_t *arr;
	size_t cnt;
	bool ownership;
};

struct prne_resolv_prm {
	void *ctx;
	prne_resolv_fut_t *fut;
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

#define PRNE_RESOLV_NS_IPV4_GOOGLE_A \
	0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_GOOGLE_B \
	0x08, 0x08, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLOUDFLARE_A \
	0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLOUDFLARE_B \
	0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_QUAD9_A \
	0x09, 0x09, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_QUAD9_B \
	0x95, 0x70, 0x70, 0x0a, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLEANBROWSING_A \
	0xb9, 0xe4, 0xa8, 0x09, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLEANBROWSING_B \
	0xb9, 0xe4, 0xa9, 0x09, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_POOL_IPV4 {\
	PRNE_RESOLV_NS_IPV4_GOOGLE_A,\
	PRNE_RESOLV_NS_IPV4_GOOGLE_B,\
	PRNE_RESOLV_NS_IPV4_CLOUDFLARE_A,\
	PRNE_RESOLV_NS_IPV4_CLOUDFLARE_B,\
	PRNE_RESOLV_NS_IPV4_QUAD9_A,\
	PRNE_RESOLV_NS_IPV4_QUAD9_B,\
	PRNE_RESOLV_NS_IPV4_CLEANBROWSING_A,\
	PRNE_RESOLV_NS_IPV4_CLEANBROWSING_B\
}

#define PRNE_RESOLV_NS_IPV6_GOOGLE_A \
	0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88
#define PRNE_RESOLV_NS_IPV6_GOOGLE_B \
	0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44
#define PRNE_RESOLV_NS_IPV6_CLOUDFLARE_A \
	0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
#define PRNE_RESOLV_NS_IPV6_CLOUDFLARE_B \
	0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01
#define PRNE_RESOLV_NS_IPV6_QUAD9_A \
	0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe
#define PRNE_RESOLV_NS_IPV6_QUAD9_B \
	0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09
#define PRNE_RESOLV_NS_IPV6_CLEANBROWSING_A \
	0x2a, 0x0d, 0x2a, 0x00, 0x00, 0x01, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
#define PRNE_RESOLV_NS_IPV6_CLEANBROWSING_B \
	0x2a, 0x0d, 0x2a, 0x00, 0x00, 0x02, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
#define PRNE_RESOLV_NS_POOL_IPV6 {\
	PRNE_RESOLV_NS_IPV6_GOOGLE_A,\
	PRNE_RESOLV_NS_IPV6_GOOGLE_B,\
	PRNE_RESOLV_NS_IPV6_CLOUDFLARE_A,\
	PRNE_RESOLV_NS_IPV6_CLOUDFLARE_B,\
	PRNE_RESOLV_NS_IPV6_QUAD9_A,\
	PRNE_RESOLV_NS_IPV6_QUAD9_B,\
	PRNE_RESOLV_NS_IPV6_CLEANBROWSING_A,\
	PRNE_RESOLV_NS_IPV6_CLEANBROWSING_B\
}

/* Default Nameserver Pools
*
* For testing only. Referencing these will increase the size of the binary.
*/
extern const prne_resolv_ns_pool_t PRNE_RESOLV_DEF_IPV4_POOL;
extern const prne_resolv_ns_pool_t PRNE_RESOLV_DEF_IPV6_POOL;

// honor bind-utils' choice of words
#define PRNE_RESOLV_RCODE_NOERROR		0
#define PRNE_RESOLV_RCODE_FORMERR		1
#define PRNE_RESOLV_RCODE_SERVFAIL		2
#define PRNE_RESOLV_RCODE_NXDOMAIN		3
#define PRNE_RESOLV_RCODE_NOTIMP		4
#define PRNE_RESOLV_RCODE_REFUSED		5

#define PRNE_RESOLV_RTYPE_A				1
#define PRNE_RESOLV_RTYPE_NS			2
#define PRNE_RESOLV_RTYPE_CNAME			5
#define PRNE_RESOLV_RTYPE_SOA			6
#define PRNE_RESOLV_RTYPE_PTR			12
#define PRNE_RESOLV_RTYPE_MX			15
#define PRNE_RESOLV_RTYPE_TXT			16
#define PRNE_RESOLV_RTYPE_AAAA			28


prne_resolv_t *prne_alloc_resolv (
	prne_worker_t *wkr,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_resolv_ns_pool_t pool_v4,
	const prne_resolv_ns_pool_t pool_v6);
bool prne_resolv_prm_gethostbyname (
	prne_resolv_t *ctx,
	const char *name,
	const prne_ipv_t ipv,
	prne_pth_cv_t *cv,
	prne_resolv_prm_t *out);
bool prne_resolv_prm_gettxtrec (
	prne_resolv_t *ctx,
	const char *name,
	prne_pth_cv_t *cv,
	prne_resolv_prm_t *out);

void prne_resolv_init_ns_pool (prne_resolv_ns_pool_t *pool);
void prne_resolv_free_ns_pool (prne_resolv_ns_pool_t *pool);
bool prne_resolv_alloc_ns_pool (prne_resolv_ns_pool_t *pool, const size_t cnt);
prne_resolv_ns_pool_t prne_resolv_own_ns_pool(
	const prne_resolv_ns_pool_t *pool,
	const bool ownership);
void prne_resolv_init_prm (prne_resolv_prm_t *prm);
void prne_resolv_free_prm (prne_resolv_prm_t *prm);
void prne_init_resolv_fut (prne_resolv_fut_t *fut);
void prne_free_resolv_fut (prne_resolv_fut_t *fut);
void prne_init_resolv_rr (prne_resolv_rr_t *rr);
void prne_free_resolv_rr (prne_resolv_rr_t *rr);
const char *prne_resolv_qr_tostr (const prne_resolv_qr_t qr);
const char *prne_resolv_rcode_tostr (const prne_resolv_rcode_t rc);
const char *prne_resolv_rrtype_tostr (const uint16_t rrt);
