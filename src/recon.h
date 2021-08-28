/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#pragma once
#include "pth.h"
#include "protocol.h"

#include <mbedtls/ctr_drbg.h>


typedef struct prne_recon prne_recon_t;
typedef struct prne_recon_param prne_recon_param_t;
typedef struct prne_recon_network prne_recon_network_t;
typedef void(*prne_recon_evt_ft)(void *ctx, const prne_net_endpoint_t *ep);

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
	void *cb_ctx;
	bool ownership;
};

prne_recon_t *prne_alloc_recon (
	prne_worker_t *wkr,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_recon_param_t *param);
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
