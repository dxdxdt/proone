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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include <regex.h>
#include <arpa/inet.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "recon.h"
#include "util_ct.h"
#include "util_rt.h"
#include "inet.h"


static regex_t re_entry, re_comment, re_empty;

static void print_help (FILE *o, const char *prog) {
	fprintf(
		o,
		"Usage: %s <conf> <port 1> [port 2] ... [port n]\n"
		"Options:\n"
		"\t<conf>: path to config file. \"-\" to read stdin\n"
		"Config Format: <ENTRY SPEC> <NET SPEC>\n"
		"\t<ENTRY SPEC>: \"T\" for target or \"BL\" for blacklist\n"
		"\t<NET SPEC>: <IPv4 or IPv6 Address>/<CIDR>\n"
		"\tNote:\n"
		"\t\t- Parsed case-insensitively\n"
		"\t\t- Lines start with \"#\" are ignored\n"
		"Config Example:\n"
		"\t# Test pool A\n"
		"\tT\t192.18.0.0/24\n"
		"\t# Test pool B\n"
		"\tT\t192.18.1.0/24\n"
		"\t# Test pool C\n"
		"\tT\tfc00:A::/96\n"
		"\t# Test pool D\n"
		"\tT\tfc00:B::/96\n"
		"\t# My Private Net (IPv4)\n"
		"\tBL\t192.168.0.1/24\n"
		"\t# My Private Net (IPv6)\n"
		"\tBL\tfd00:ABBA::/64\n",
		prog);
}

static int do_parse_conf (FILE *file, prne_recon_param_t *param) {
	static const size_t RM_SIZE = 8;
	regmatch_t rm[RM_SIZE];
	char line[2][1024];
	size_t nr_line = 0;
	char *ent_spec, *ent_addr, *ent_cidr;
	uint8_t cidr;
	prne_recon_network_t net;

	while (true) {
		if (fgets(line[0], sizeof(line[0]), file) == NULL) {
			break;
		}
		nr_line += 1;

		if (regexec(&re_empty, line[0], RM_SIZE, rm, 0) == 0 ||
			regexec(&re_comment, line[0], RM_SIZE, rm, 0) == 0)
		{
			continue;
		}
		if (regexec(&re_entry, line[0], RM_SIZE, rm, 0) != 0) {
			goto INV_LINE;
		}

		strcpy(line[1], line[0]);
		prne_memzero(&net, sizeof(prne_recon_network_t));

		line[1][rm[2].rm_eo] = 0; // terminate ENTRY SPEC
		line[1][rm[4].rm_eo] = 0; // terminate address
		line[1][rm[5].rm_eo] = 0; // terminate CIDR
		ent_spec = line[1] + rm[2].rm_so;
		ent_addr = line[1] + rm[4].rm_so;
		ent_cidr = line[1] + rm[5].rm_so;
		prne_transcstr(ent_spec, prne_ctoupper);
		prne_transcstr(ent_addr, prne_ctolower);

		if (inet_pton(AF_INET6, ent_addr, net.addr.addr)) {
			net.addr.ver = PRNE_IPV_6;
		}
		else if (inet_pton(AF_INET, ent_addr, net.addr.addr)) {
			net.addr.ver = PRNE_IPV_4;
		}
		else {
			goto INV_LINE;
		}

		if (sscanf(ent_cidr, "%"SCNu8, &cidr) != 1 ||
			(net.addr.ver == PRNE_IPV_6 && cidr > 128) ||
			(net.addr.ver == PRNE_IPV_4 && cidr > 32))
		{
			goto INV_LINE;
		}
		prne_netmask_from_cidr(net.mask, cidr);

		if (strcmp(ent_spec, "T") == 0) {
			prne_assert(prne_alloc_recon_param(
				param,
				param->blist.cnt,
				param->target.cnt + 1,
				param->ports.cnt));
			param->target.arr[param->target.cnt - 1] = net;
		}
		else if (strcmp(ent_spec, "BL") == 0) {
			prne_assert(prne_alloc_recon_param(
				param,
				param->blist.cnt + 1,
				param->target.cnt,
				param->ports.cnt));
			param->blist.arr[param->blist.cnt - 1] = net;
		}
		else {
			abort();
		}
	}

	return 0;
INV_LINE:
	fprintf(
		stderr,
		"*** Invalid entry at line %zu: %s\n",
		nr_line,
		line[0]);
	return 2;
}

static void evt_cb (void *ctx, const prne_net_endpoint_t *ep) {
	char addr_str[prne_op_max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	switch (ep->addr.ver) {
	case PRNE_IPV_4:
		inet_ntop(AF_INET, ep->addr.addr, addr_str, sizeof(addr_str));
		printf("%s:%"PRIu16"\n", addr_str, ep->port);
		break;
	case PRNE_IPV_6:
		inet_ntop(AF_INET6, ep->addr.addr, addr_str, sizeof(addr_str));
		printf(
			"[%s%%%"PRIu32"]:%"PRIu16"\n",
			addr_str,
			ep->addr.scope_id,
			ep->port);
		break;
	default: abort();
	}
}

int main (const int argc, const char **args) {
	int ret = 0;
	prne_recon_param_t param;
	FILE *conf_f = NULL;
	bool own_conf_f = false;
	prne_worker_t wkr;
	prne_recon_t *recon;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	sigset_t ss_term;
	int caught_sig;

	prne_assert(regcomp(
		&re_entry,
		// ^(\s+)?(T|BL)(\s+)([0-9a-f:.]+)\/([0-9]{1,3})(\s+)?(#.*)?$
		// number of captures: 7
		// significant groups: 2, 4, 5
		"^(\\s+)?(T|BL)(\\s+)([0-9a-f:.]+)\\/([0-9]{1,3})(\\s+)?(#.*)?$",
		REG_EXTENDED | REG_ICASE) == 0);
	prne_assert(regcomp(
		&re_comment,
		// ^(\s+)?#.*$
		"^(\\s+)?#.*$",
		REG_EXTENDED | REG_ICASE) == 0);
	prne_assert(regcomp(
		&re_empty,
		// ^(\s+)?$
		"^(\\s+)?$",
		REG_EXTENDED | REG_ICASE) == 0);

	prne_init_recon_param(&param);
	param.evt_cb = evt_cb;
	prne_init_worker(&wkr);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	sigemptyset(&ss_term);
	sigaddset(&ss_term, SIGTERM);
	sigaddset(&ss_term, SIGINT);

	// parse args
	if (argc < 3) {
		print_help(stderr, args[0]);
		ret = 2;
		goto END;
	}

	if (prne_nstreq(args[1], "-")) {
		conf_f = stdin;
	}
	else {
		own_conf_f = true;
		conf_f = fopen(args[1], "r");

		if (conf_f == NULL) {
			perror(args[1]);
			ret = 1;
			goto END;
		}
	}

	for (int i = 2; i < argc; i += 1) {
		uint16_t port;

		if (sscanf(args[i], "%"SCNu16, &port) != 1 || port == 0) {
			fprintf(stderr, "*** %s: invalid port value\n", args[i]);
			ret = 2;
			goto END;
		}
		prne_assert(prne_alloc_recon_param(
			&param,
			param.blist.cnt,
			param.target.cnt,
			param.ports.cnt + 1));
		param.ports.arr[param.ports.cnt - 1] = port;
	}

	prne_assert(pth_init());

	// try-catch init
	prne_assert(mbedtls_ctr_drbg_seed(
		&ctr_drbg,
		mbedtls_entropy_func,
		&entropy,
		NULL,
		0) == 0);

	// parse conf
	ret = do_parse_conf(conf_f, &param);
	if (ret != 0) {
		goto END;
	}
	if (param.target.cnt == 0) {
		fprintf(stderr, "*** No target network configured\n");
		ret = 2;
		goto END;
	}

	// alloc recon
	param.ownership = false;
	recon = prne_alloc_recon(
		&wkr,
		&ctr_drbg,
		&param);
	param.ownership = true;
	if (recon == NULL) {
		perror("prne_alloc_recon()");
		ret = 2;
		goto END;
	}
	wkr.pth = pth_spawn(PTH_ATTR_DEFAULT, wkr.entry, wkr.ctx);
	prne_assert(wkr.pth != NULL);

	// wait for termination
	prne_assert(sigprocmask(SIG_BLOCK, &ss_term, NULL) == 0);
	pth_sigwait(&ss_term, &caught_sig);
	sigprocmask(SIG_UNBLOCK, &ss_term, NULL);

	// fin worker
	wkr.fin(wkr.ctx);
	pth_join(wkr.pth, NULL);
	wkr.pth = NULL;
	prne_free_worker(&wkr);

END:
	// clean up
	regfree(&re_entry);
	regfree(&re_comment);
	regfree(&re_empty);
	prne_free_recon_param(&param);
	if (own_conf_f && conf_f != NULL) {
		fclose(conf_f);
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	pth_kill();

	return ret;
}
