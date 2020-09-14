#pragma once
#include "pth.h"
#include "protocol.h"

#include <mbedtls/ctr_drbg.h>


typedef struct prne_recon prne_recon_t;
typedef struct prne_recon_param prne_recon_param_t;
typedef struct prne_recon_network prne_recon_network_t;
typedef void(*prne_recon_evt_ft)(const prne_net_endpoint_t *ep);

struct prne_recon_network {
	prne_ip_addr_t addr;
	uint8_t mask[16];
};

struct prne_recon_param {
	struct {
		prne_recon_network_t *arr;
		size_t cnt;
	} blist;
	struct {
		prne_recon_network_t *arr;
		size_t cnt;
	} target;
	struct {
		uint16_t *arr;
		size_t cnt;
	} ports;
	prne_recon_evt_ft evt_cb;
	bool ownership;
};

prne_recon_t *prne_alloc_recon (
	prne_worker_t *wkr,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_recon_param_t param);
void prne_init_recon_param (prne_recon_param_t *p);
void prne_free_recon_param (prne_recon_param_t *p);
bool prne_alloc_recon_param (
	prne_recon_param_t *p,
	const size_t blist,
	const size_t target,
	const size_t ports);
prne_recon_param_t prne_own_recon_param (
	const prne_recon_param_t *p,
	const bool ownership);
