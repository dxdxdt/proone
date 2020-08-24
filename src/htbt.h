#pragma once
#include "pth.h"
#include "resolv.h"


typedef struct prne_htbt prne_htbt_t;
struct prne_htbt;


prne_htbt_t *prne_alloc_htbt_worker (
	prne_worker_t *w,
	pth_t sigterm_pth,
	prne_resolv_t *resolv, // optional
	mbedtls_ctr_drbg_context *ctr_drbg);
