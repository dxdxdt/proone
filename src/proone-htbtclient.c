/*
* No pipelining assumed.
* Don't handle SIGPIPE.
*/
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
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>

#include <sys/mman.h>
#include <getopt.h>
#include <regex.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>
#include <yaml.h>

#include "protocol.h"
#include "util_rt.h"
#include "mbedtls.h"
#include "config.h"
#include "iobuf.h"
#include "bitfield.h"

#define STRINGIFY(x) #x
#define STRINGIFY_X(x) STRINGIFY(x)

#define ROOT_TAG_NAME "htbtclient_run"
#define PREEMBLE_TAG_NAME "preemble"
#define PREEMBLE_OPT_TAG_NAME "options"
#define BODY_TAG_NAME "body"

#define MAIN_HELP_STR \
"Proone Heartbeat Subsystem Client\n"\
"Usage: %s [common options] <COMMAND> ...\n"\
"\n"\
"COMMAND:\n"\
"  hostinfo  query host info\n"\
"  hover     send handover request\n"\
"  runcmd    run command on host\n"\
"  runbin    upload and run arbitrary binary on host\n"\
"  upbin     perform binary update\n"\
"  rcb       download binary from instance\n"\
"\n"\
"Common options:\n"\
"  -h, --help           print help for specified command and exit. Print this\n"\
"                       help and exit if no command is specified\n"\
"  -V, --version        print version and exit\n"\
"  -x                   do not use stdio for user interaction(\"script mode\")\n"\
"  -v, --verbose        increase verbose level. Can be used more than once\n"\
"  -m <MODE>            mode selection. 'tls'(default) or 'txtrec'\n"\
"  --tls-ca <FILE>      path to tls CA certificate\n"\
"  --tls-cert <FILE>    path to tls client certificate\n"\
"  --tls-key <FILE>     path to tls private key\n"\
"  --tls-key-pw <PW>    password for tls private key\n"\
"  -t, --host <REMOTE>  remote host to connect to\n"\
"  -p, --port <PORT>    specify port (default: " STRINGIFY_X(PRNE_HTBT_PROTO_PORT) ")\n"\
"\n"\
"The server will not be verified if --tls-ca is not used. Rolled out htbt hosts \n"\
"will verify clients by design/default so both --tls-cert and --tls-key should \n"\
"be used.\n"\
"\n"\
"Use \"%s -h COMMAND\" to get help on each command.\n"\
"\n"
#define HOSTINFO_HELP_STR \
"Get host info from Proone instance and ouput in YAML format.\n"\
"Usage: %s [common options] hostinfo\n"\
"\n"
#define HOVER_HELP_STR \
"Send Handover request to Proone instance.\n"\
"Usage: %s [common options] hover [options]\n"\
"\n"\
"Options:\n"\
"  --v4-addr <ADDR>  IPv4 address\n"\
"  --v6-addr <ADDR>  IPv6 address\n"\
"  --port <PORT>     specify both v4 and v6 port (default: " STRINGIFY_X(PRNE_HTBT_PROTO_PORT) ")\n"\
"  --v4-port <PORT>  specify v4 port\n"\
"  --v6-port <PORT>  specify v6 port\n"\
"\n"\
"If only one of the IP addresses is specified, the other will be zero-filled,\n"\
"disabling the use of that IP version(as per RFC1122 abnd RFC4291).\n"\
"\n"
#define RUNCMD_HELP_STR \
"Run command on host running Proone instance.\n"\
"Usage: %s [common options] runcmd [options] [--] <arg0> [arg1 ...]\n"\
"\n"\
"Options:\n"\
"  -d, --detach  run detached(i.e., run as daemon)\n"\
"\n"
#define RUNBIN_HELP_STR \
"Upload and run binary on host running Proone instance.\n"\
"Usage: %s [common options] runbin [options] <FILE> [arg0] [arg1 ...]\n"\
"\n"\
"Options:\n"\
"  -d, --detach  run detached(i.e., run as daemon)\n"\
"\n"
#define UPBIN_HELP_STR \
"Perform binary update.\n"\
"Usage: %s [common options] upbin [options] <FILE> [arg0] [arg1 ...]\n"\
"\n"\
"Options:\n"\
"  --nybin      do binary recombination. <FILE> must be nybin format binary\n"\
"  --exec       upload <FILE> as is\n"\
"  --no-compat  do not retry recombination with compatible arch\n"\
"\n"\
"Note that an instance will continue to run with original binary if it fails to\n"\
"exec() to the new binary.\n"\
"\n"
#define RCB_HELP_STR \
"Order instance to do binary recombination and download the binary.\n"\
"Usage: %s [common options] rcb [options] [OUTFILE]\n"\
"\n"\
"Options:\n"\
"  --arch <ARCH>  target CPU ARCH\n"\
"  --no-compat    do not allow recombination of compatible arch\n"\
"  -f             overwrite OUTFILE\n"\
"\n"\
"The program will write to stdout if OUTFILE is \"-\"(default).\n"\
"If --arch option is not used, binary recombination will not take place and the\n"\
"running executable will be copied(i.e., \"self copy\").\n"\
"OS codes are reserved in the protocol but not exposed on programs.\n"\
"Run proone-list-arch for possible values for --arch option.\n"\
"\n"

enum prog_mode {
	PM_NONE,

	PM_TLS,
	PM_TXTREC,

	NB_PM
};
typedef enum prog_mode prog_mode_t;

enum sub_command {
	SC_NONE,

	SC_HOSTINFO,
	SC_HOVER,
	SC_RUNCMD,
	SC_RUNBIN,
	SC_UPBIN,
	SC_RCB,

	NB_SC
};
typedef enum sub_command sub_command_t;

enum bin_type {
	BT_NONE,

	BT_NYBIN,
	BT_EXEC,

	NB_BT
};
typedef enum bin_type bin_type_t;

struct {
	char *tls_ca;
	char *tls_cert;
	char *tls_key;
	char tls_key_pw[256]; // scrub after use
	char *remote_host;
	char *remote_port;
	prog_mode_t mode;
	sub_command_t cmd;
	int prne_vl;
	bool help; // -h or --help used
	bool version; // -V or --version used
	bool tls_key_pw_arg; // true if tls_key_pw is passed via option
	bool no_term; // true if terminal interaction is not permitted
	union {
		struct {
			prne_htbt_hover_t f;
		} hover;
		struct {
			char *bin_path;
			size_t bin_len;
			bin_type_t bin_type;
			prne_htbt_bin_meta_t bm;
			bool compat;
		} run;
		struct {
			char *out_path;
			bool f;
			prne_htbt_rcb_t rcb;
		} rcb;
	} cmd_param;
	void (*free_cmdparam_f)(void);
} prog_conf;

struct {
	struct {
		mbedtls_ssl_config conf;
		mbedtls_x509_crt ca;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
		mbedtls_ctr_drbg_context rnd;
		mbedtls_entropy_context ent;
		mbedtls_ssl_context ctx;
	} ssl;
	struct {
		mbedtls_net_context ctx;
		prne_iobuf_t ib;
	} net;
	struct {
		bool (*do_connect)(void);
		void (*do_disconnect)(void);
		ssize_t (*do_read)(void *buf, size_t l);
		ssize_t (*do_write)(const void *buf, size_t l);
	} io;
	struct {
		yaml_emitter_t *emitter;
		int fd;
		bool our_fd;
	} yaml;
	union {
		struct {
			int fd;
			prne_bin_host_t target;
			prne_bin_host_t actual;
			bool has_status;
			prne_iobuf_t ib;
			prne_htbt_status_t st;
		} run;
		struct {
			int fd;
			bool our_file;
			prne_iobuf_t ib;
		} rcb;
	} cmd_st;
	void (*free_cmdst_f)(void);
} prog_g;

static void print_help (const char *prog, const sub_command_t sc, FILE *out_f) {
	switch (sc) {
	case SC_HOSTINFO:
		fprintf(out_f, HOSTINFO_HELP_STR, prog);
		break;
	case SC_HOVER:
		fprintf(out_f, HOVER_HELP_STR, prog);
		break;
	case SC_RUNCMD:
		fprintf(out_f, RUNCMD_HELP_STR, prog);
		break;
	case SC_RUNBIN:
		fprintf(out_f, RUNBIN_HELP_STR, prog);
		break;
	case SC_UPBIN:
		fprintf(out_f, UPBIN_HELP_STR, prog);
		break;
	case SC_RCB:
		fprintf(out_f, RCB_HELP_STR, prog);
		break;
	default: fprintf(out_f, MAIN_HELP_STR, prog, prog);
	}
}

static void init_prog_g (void) {
	int f_ret;

	prne_memzero(&prog_g, sizeof(prog_g)); // so main() is recallable

	mbedtls_ssl_config_init(&prog_g.ssl.conf);
	mbedtls_x509_crt_init(&prog_g.ssl.ca);
	mbedtls_x509_crt_init(&prog_g.ssl.crt);
	mbedtls_pk_init(&prog_g.ssl.pk);
	mbedtls_ctr_drbg_init(&prog_g.ssl.rnd);
	mbedtls_entropy_init(&prog_g.ssl.ent);
	mbedtls_ssl_init(&prog_g.ssl.ctx);

	mbedtls_net_init(&prog_g.net.ctx);
	prne_init_iobuf(&prog_g.net.ib);
	if (!prne_alloc_iobuf(
			&prog_g.net.ib,
			prne_op_max(PRNE_HTBT_PROTO_MIN_BUF, prne_getpagesize())))
	{
		perror("prne_alloc_iobuf()");
		abort();
	}

	f_ret = mbedtls_ctr_drbg_seed(
		&prog_g.ssl.rnd,
		mbedtls_entropy_func,
		&prog_g.ssl.ent,
		NULL,
		0);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ctr_drbg_seed()");
		abort();
	}

	prog_g.yaml.fd = -1;
}

static void free_run_g (void) {
	prne_close(prog_g.cmd_st.run.fd);
	prog_g.cmd_st.run.fd = -1;
	prne_free_iobuf(&prog_g.cmd_st.run.ib);
	prne_htbt_free_status(&prog_g.cmd_st.run.st);
}

static void init_run_g (void) {
	assert(prog_g.free_cmdst_f == NULL);

	prog_g.cmd_st.run.fd = -1;
	prne_init_iobuf(&prog_g.cmd_st.run.ib);
	prne_htbt_init_status(&prog_g.cmd_st.run.st);
	assert(prne_alloc_iobuf(&prog_g.cmd_st.run.ib, prne_getpagesize()));
	prog_g.free_cmdst_f = free_run_g;
}

static void free_rcb_g (void) {
	prne_close(prog_g.cmd_st.rcb.fd);
	prog_g.cmd_st.rcb.fd = -1;
	prne_free_iobuf(&prog_g.cmd_st.rcb.ib);
}

static void init_rcb_g (void) {
	assert(prog_g.free_cmdst_f == NULL);

	prog_g.cmd_st.rcb.fd = -1;
	prne_init_iobuf(&prog_g.cmd_st.rcb.ib);
	if (!prne_alloc_iobuf(&prog_g.cmd_st.rcb.ib, PRNE_HTBT_STDIO_LEN_MAX)) {
		perror("prne_alloc_iobuf()");
		abort();
	}
	prog_g.free_cmdst_f = free_rcb_g;
}

static void deinit_prog_g (void) {
	if (prog_g.free_cmdst_f != NULL) {
		prog_g.free_cmdst_f();
	}

	mbedtls_ssl_config_free(&prog_g.ssl.conf);
	mbedtls_x509_crt_free(&prog_g.ssl.ca);
	mbedtls_x509_crt_free(&prog_g.ssl.crt);
	mbedtls_pk_free(&prog_g.ssl.pk);
	mbedtls_ctr_drbg_free(&prog_g.ssl.rnd);
	mbedtls_entropy_free(&prog_g.ssl.ent);
	mbedtls_ssl_free(&prog_g.ssl.ctx);

	mbedtls_net_free(&prog_g.net.ctx);
	prne_free_iobuf(&prog_g.net.ib);
}

static void init_prog_conf (void) {
	mlock(prog_conf.tls_key_pw, sizeof(prog_conf.tls_key_pw));
	prne_memzero(&prog_conf, sizeof(prog_conf)); // so main() is recallable
	prog_conf.remote_port = prne_dup_str(STRINGIFY_X(PRNE_HTBT_PROTO_PORT));
	prog_conf.prne_vl = PRNE_VL_INFO;
	prog_conf.mode = PM_TLS;
}

static void free_hover_conf (void) {
	prne_htbt_free_hover(&prog_conf.cmd_param.hover.f);
}

static void init_hover_conf (void) {
	assert(prog_conf.free_cmdparam_f == NULL);
	prne_htbt_init_hover(&prog_conf.cmd_param.hover.f);
	prog_conf.cmd_param.hover.f.v4.port =
		prog_conf.cmd_param.hover.f.v6.port =
		PRNE_HTBT_PROTO_PORT;

	prog_conf.free_cmdparam_f = free_hover_conf;
}

static void free_run_conf (void) {
	prne_htbt_free_bin_meta(&prog_conf.cmd_param.run.bm);
	prne_free(prog_conf.cmd_param.run.bin_path);
	prog_conf.cmd_param.run.bin_path = NULL;
}

static void init_run_conf (void) {
	assert(prog_conf.free_cmdparam_f == NULL);
	prne_htbt_init_bin_meta(&prog_conf.cmd_param.run.bm);
	prog_conf.cmd_param.run.compat = true;

	prog_conf.free_cmdparam_f = free_run_conf;
}

static void free_rcb_conf (void) {
	prne_free(prog_conf.cmd_param.rcb.out_path);
	prog_conf.cmd_param.rcb.out_path = NULL;
	prne_htbt_free_rcb(&prog_conf.cmd_param.rcb.rcb);
}

static void init_rcb_conf (void) {
	assert(prog_conf.free_cmdparam_f == NULL);
	prne_htbt_init_rcb(&prog_conf.cmd_param.rcb.rcb);
	prog_conf.cmd_param.rcb.out_path = prne_dup_str("-");
	prog_conf.cmd_param.rcb.rcb.compat = true;
	prog_conf.cmd_param.rcb.rcb.self = true;
	prog_conf.cmd_param.rcb.rcb.os = PRNE_OS_LINUX;

	prog_conf.free_cmdparam_f = free_rcb_conf;
}

static void deinit_prog_conf (void) {
	if (prog_conf.free_cmdparam_f != NULL) {
		prog_conf.free_cmdparam_f();
	}
	prne_free(prog_conf.tls_ca);
	prne_free(prog_conf.tls_cert);
	prne_free(prog_conf.tls_key);
	// Security first!
	prne_memzero(prog_conf.tls_key_pw, sizeof(prog_conf.tls_key_pw));
	prne_free(prog_conf.remote_host);
	prne_free(prog_conf.remote_port);
}

static bool is_info_run (void) {
	return prog_conf.help || prog_conf.version;
}

static void print_version (FILE *f) {
	static const uint8_t ver_uuid[] = PRNE_PROG_VER;
	static char ver_str[37];

	if (ver_str[0] == 0) {
		prne_uuid_tostr(ver_uuid, ver_str);
	}

	fprintf(
		f,
		"PRNE_PROG_VER: %s\n"
		"__DATE__: %s\n",
		ver_str,
		__DATE__);
}

static void load_optarg (char **out) {
	const size_t l = strlen(optarg);

	prne_free(*out);
	*out = prne_alloc_str(l);
	strncpy(*out, optarg, l + 1);
}

static bool assert_host_arg (void) {
	if (prog_conf.mode == PM_TXTREC) {
		return true;
	}
	if (prog_conf.remote_host == NULL) {
		fprintf(stderr, "Use -t or --host option to specify host.\n");
		return false;
	}
	return true;
}

static int parse_args_hostinfo (const int argc, char *const *args) {
	if (assert_host_arg()) {
		return 0;
	}
	return 2;
}

static bool parse_port (const char *str, uint16_t *out) {
	return sscanf(str, "%"SCNu16, out) == 1;
}

static void ipton_perror (const char *s) {
	if (errno != 0) {
		perror(s);
	}
	else {
		fprintf(stderr, "%s: invalid argument\n", s);
	}
}

static void p_invarg (const char *s) {
	fprintf(stderr, "%s: invalid argument\n", s);
}

static int parse_args_hover (const int argc, char *const *args) {
	static const struct option lopts[] = {
		{ "v4-addr", required_argument, 0, 0 },
		{ "v6-addr", required_argument, 0, 0 },
		{ "port", required_argument, 0, 0 },
		{ "v4-port", required_argument, 0, 0 },
		{ "v6-port", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	int f_ret, li;
	const struct option *cur_lo;
	bool addr_passed = false;

	if (!assert_host_arg()) {
		return 2;
	}
	init_hover_conf();

	while (true) {
		f_ret = getopt_long(argc, args, "", lopts, &li);
		if (f_ret == 0) {
			cur_lo = lopts + li;

			if (strcmp("v4-addr", cur_lo->name) == 0) {
				errno = 0;
				if (inet_pton(AF_INET,
						optarg,
						prog_conf.cmd_param.hover.f.v4.addr) == 0)
				{
					ipton_perror("--v4-addr");
					return 2;
				}
				addr_passed = true;
			}
			else if (strcmp("v6-addr", cur_lo->name) == 0) {
				errno = 0;
				if (inet_pton(AF_INET6,
						optarg,
						prog_conf.cmd_param.hover.f.v6.addr) == 0)
				{
					ipton_perror("--v6-addr");
					return 2;
				}
				addr_passed = true;
			}
			else if (strcmp("port", cur_lo->name) == 0) {
				uint16_t port;

				if (!parse_port(optarg, &port)) {
					p_invarg("--port");
					return 2;
				}
				prog_conf.cmd_param.hover.f.v4.port =
					prog_conf.cmd_param.hover.f.v6.port =
					port;
			}
			else if (strcmp("v4-port", cur_lo->name) == 0) {
				if (!parse_port(optarg, &prog_conf.cmd_param.hover.f.v4.port)) {
					p_invarg("--v4-port");
					return 2;
				}
			}
			else if (strcmp("v6-port", cur_lo->name) == 0) {
				if (!parse_port(optarg, &prog_conf.cmd_param.hover.f.v6.port)) {
					p_invarg("--v6-port");
					return 2;
				}
			}
			else {
				abort();
			}
		}
		else {
			return 2;
		}
	}

	if (!addr_passed) {
		fprintf(stderr, "No address given.\n");
		return 2;
	}

	return 0;
}

static int parse_args_run (const int argc, char *const *args, const bool bin) {
	static const struct option lopts[] = {
		{ "detach", no_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	int li, f_ret;
	const struct option *co;

	if (!assert_host_arg()) {
		return 2;
	}
	init_run_conf();
	init_run_g();

	while (true) {
		f_ret = getopt_long(argc, args, "+d", lopts, &li);
		switch (f_ret) {
		case 0:
			co = (const struct option*)lopts + li;
			if (strcmp("detach", co->name) == 0) {
				prog_conf.cmd_param.run.bm.cmd.detach = true;
			}
			else {
				abort();
			}
			break;
		case 'd':
			prog_conf.cmd_param.run.bm.cmd.detach = true;
			break;
		default:
			goto LOOP_END;
		}
	}
LOOP_END:
	if (bin) {
		if (argc <= optind) {
			fprintf(stderr, "FILE not specified.\n");
			return 2;
		}

		prne_free(prog_conf.cmd_param.run.bin_path);
		prog_conf.cmd_param.run.bin_path = prne_dup_str(args[optind]);
		if (prog_conf.cmd_param.run.bin_path == NULL) {
			perror("prne_dup_str()");
			abort();
		}
		optind += 1;
	}

	if (!bin && argc - optind <= 0) {
		fprintf(stderr, "No argument specified.\n");
		return 2;
	}
	if (!prne_htbt_set_cmd(
			&prog_conf.cmd_param.run.bm.cmd,
			(const char**)args + optind))
	{
		perror("prne_htbt_set_cmd()");
		abort();
	}

	return 0;
}

static int parse_args_upbin (const int argc, char *const *args) {
	static const struct option lopts[] = {
		{ "nybin", no_argument, 0, 0 },
		{ "exec", no_argument, 0, 0 },
		{ "no-compat", no_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	int li, f_ret;
	const struct option *co;

	if (!assert_host_arg()) {
		return 2;
	}
	init_run_conf();
	init_run_g();

	while (true) {
		f_ret = getopt_long(argc, args, "", lopts, &li);
		if (f_ret != 0) {
			break;
		}

		co = (const struct option*)lopts + li;
		if (strcmp("nybin", co->name) == 0) {
			prog_conf.cmd_param.run.bin_type = BT_NYBIN;
		}
		else if (strcmp("exec", co->name) == 0) {
			prog_conf.cmd_param.run.bin_type = BT_EXEC;
		}
		else if (strcmp("no-compat", co->name) == 0) {
			prog_conf.cmd_param.run.compat = false;
		}
		else {
			abort();
		}
	}

	if (prog_conf.cmd_param.run.bin_type == BT_NONE) {
		fprintf(stderr, "Use --nybin or --exec to specify binary type.\n");
		return 2;
	}
	if (prog_conf.cmd_param.run.bin_type == BT_NYBIN &&
		prog_conf.mode == PM_TXTREC)
	{
		fprintf(stderr, "--nybin is not supported in txtrec mode.\n");
		return 2;
	}

	if (argc <= optind) {
		fprintf(stderr, "FILE not specified.\n");
		return 2;
	}

	prne_free(prog_conf.cmd_param.run.bin_path);
	prog_conf.cmd_param.run.bin_path = prne_dup_str(args[optind]);
	if (prog_conf.cmd_param.run.bin_path == NULL) {
		perror("prne_dup_str()");
		abort();
	}
	optind += 1;

	if (!prne_htbt_set_cmd(
			&prog_conf.cmd_param.run.bm.cmd,
			(const char**)args + optind))
	{
		perror("prne_htbt_set_cmd()");
		abort();
	}

	return 0;
}

static int parse_args_rcb (const int argc, char *const *args) {
	static const struct option lopts[] = {
		{ "arch", required_argument, 0, 0 },
		{ "no-compat", no_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	int li, f_ret;
	const struct option *co;

	if (!assert_host_arg()) {
		return 2;
	}
	init_rcb_conf();
	init_rcb_g();

	while (true) {
		f_ret = getopt_long(argc, args, "f", lopts, &li);
		if (f_ret == 'f') {
			prog_conf.cmd_param.rcb.f = true;
			continue;
		}
		else if (f_ret != 0) {
			break;
		}

		co = (const struct option*)lopts + li;
		if (strcmp("arch", co->name) == 0) {
			prog_conf.cmd_param.rcb.rcb.arch = prne_arch_fstr(optarg);
			prog_conf.cmd_param.rcb.rcb.self = false;
			if (prog_conf.cmd_param.rcb.rcb.arch == PRNE_ARCH_NONE) {
				perror(optarg);
				return 2;
			}
		}
		else if (strcmp("no-compat", co->name) == 0) {
			prog_conf.cmd_param.rcb.rcb.compat = false;
		}
		else {
			abort();
		}
	}

	if (argc > optind) {
		prne_free(prog_conf.cmd_param.rcb.out_path);
		prog_conf.cmd_param.rcb.out_path = prne_dup_str(args[optind]);
		if (prog_conf.cmd_param.rcb.out_path == NULL) {
			perror("prne_dup_str()");
			abort();
		}
		optind += 1;
	}

	return 0;
}

static int parse_args (const int argc, char *const *args) {
	int fr, li, ret = 0;
	static const struct option lopts[] = {
		{ "help", no_argument, 0, 0 },
		{ "version", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 0 },
		{ "tls-ca", required_argument, 0, 0 },
		{ "tls-cert", required_argument, 0, 0 },
		{ "tls-key", required_argument, 0, 0 },
		{ "tls-key-pw", required_argument, 0, 0 },
		{ "host", required_argument, 0, 0 },
		{ "port", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	const struct option *cur_lo;

	while (true) {
		fr = getopt_long(argc, args, "+hVvxt:p:m:", lopts, &li);

		switch (fr) {
		case 0:
			cur_lo = lopts + li;

			if (strcmp("help", cur_lo->name) == 0) {
				prog_conf.help = true;
			}
			else if (strcmp("verbose", cur_lo->name) == 0) {
				prog_conf.prne_vl += 1;
			}
			else if (strcmp("version", cur_lo->name) == 0) {
				prog_conf.version = true;
			}
			else if (strcmp("tls-ca", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_ca);
			}
			else if (strcmp("tls-cert", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_cert);
			}
			else if (strcmp("tls-key", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_key);
			}
			else if (strcmp("tls-key-pw", cur_lo->name) == 0) {
				strncpy(
					prog_conf.tls_key_pw,
					optarg,
					sizeof(prog_conf.tls_key_pw));
				prog_conf.tls_key_pw_arg = true;
			}
			else if (strcmp("host", cur_lo->name) == 0) {
				load_optarg(&prog_conf.remote_host);
			}
			else if (strcmp("port", cur_lo->name) == 0) {
				load_optarg(&prog_conf.remote_port);
			}
			else {
				abort();
			}
			break;
		case 'V':
			prog_conf.version = true;
			break;
		case 'v':
			prog_conf.prne_vl += 1;
			break;
		case 'h':
			prog_conf.help = true;
			break;
		case 'x':
			prog_conf.no_term = true;
			break;
		case 't':
			load_optarg(&prog_conf.remote_host);
			break;
		case 'p':
			load_optarg(&prog_conf.remote_port);
			break;
		case 'm':
			if (strcmp(optarg, "tls") == 0) {
				prog_conf.mode = PM_TLS;
			}
			else if (strcmp(optarg, "txtrec") == 0) {
				prog_conf.mode = PM_TXTREC;
			}
			else {
				fprintf(stderr, "%s: invalid mode\n", optarg);
				return 2;
			}
			break;
		default:
			goto END_LOOP;
		}
	}
END_LOOP:

	if (!is_info_run()) {
		if ((prog_conf.tls_cert == NULL) ^ (prog_conf.tls_key == NULL)) {
			fprintf(stderr, "--tls-cert and --tls-key must be used in pair.\n");
			return 2;
		}
	}

	if (optind < argc) {
		const char *cmd_str = args[optind];

		optind += 1;
		if (strcmp("hostinfo", cmd_str) == 0) {
			prog_conf.cmd = SC_HOSTINFO;
		}
		else if (strcmp("hover", cmd_str) == 0) {
			prog_conf.cmd = SC_HOVER;
		}
		else if (strcmp("runcmd", cmd_str) == 0) {
			prog_conf.cmd = SC_RUNCMD;
		}
		else if (strcmp("runbin", cmd_str) == 0) {
			prog_conf.cmd = SC_RUNBIN;
		}
		else if (strcmp("upbin", cmd_str) == 0) {
			prog_conf.cmd = SC_UPBIN;
		}
		else if (strcmp("rcb", cmd_str) == 0) {
			prog_conf.cmd = SC_RCB;
		}
		else {
			fprintf(stderr, "Invalid COMMAND \"%s\".\n", cmd_str);
			return 2;
		}
	}

	if (is_info_run()) {
		return 0;
	}
	switch (prog_conf.cmd) {
	case SC_HOSTINFO: ret = parse_args_hostinfo(argc, args); break;
	case SC_HOVER: ret = parse_args_hover(argc, args); break;
	case SC_RUNCMD: ret = parse_args_run(argc, args, false); break;
	case SC_RUNBIN: ret = parse_args_run(argc, args, true); break;
	case SC_UPBIN: ret = parse_args_upbin(argc, args); break;
	case SC_RCB: ret = parse_args_rcb(argc, args); break;
	default:
		ret = 2;
		fprintf(stderr, "COMMAND not specified.\n");
	}

	return ret;
}

static bool interact_tls_key_pw (void) {
	int f_ret;
	char *s_ret;
	struct termios t;
	tcflag_t saved_flags;
	bool ret = true, flags_saved = false;

// TRY
	if (prog_conf.tls_key_pw_arg) {
		ret = false;
		goto END;
	}
	if (isatty(STDIN_FILENO) == 0 || prog_conf.no_term) {
		fprintf(
			stderr,
			"TLS PK is encrypted but terminal interaction is not possible.\n");
		ret = false;
		goto END;
	}

	fprintf(stderr, "TLS PK password: ");
	fflush(stderr);

	// turn off echo
	f_ret = tcgetattr(STDIN_FILENO, &t);
	if (f_ret != 0) {
		perror("tcgetattr()");
		ret = false;
		goto END;
	}
	saved_flags = t.c_lflag;
	flags_saved = true;
	t.c_lflag &= ~ECHO;
	t.c_lflag |= ECHONL;
	f_ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
	if (f_ret != 0) {
		perror("tcsetattr()");
		ret = false;
		goto END;
	}

	s_ret = fgets(
		prog_conf.tls_key_pw,
		sizeof(prog_conf.tls_key_pw),
		stdin);
	if (s_ret == NULL) {
		ret = false;
		goto END;
	}
	prog_conf.tls_key_pw[strcspn(prog_conf.tls_key_pw, "\r\n")] = 0;

END: // CATCH
	if (flags_saved) {
		t.c_lflag = saved_flags;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
	}
	return ret;
}

static void pstatus (const prne_htbt_status_t *st, const char *s) {
	fprintf(stderr, "%s: code=%d, err=%"PRId32"\n", s, st->code, st->err);
}

static void pprc (const prne_pack_rc_t prc, const char *s, int *err) {
	switch (prc) {
	case PRNE_PACK_RC_Z_ERR:
		if (err != NULL) {
			fprintf(stderr, "%s: %s(%d)\n", s, prne_pack_rc_tostr(prc), *err);
			break;
		}
		/* fall-through */
	case PRNE_PACK_RC_OK:
	case PRNE_PACK_RC_EOF:
	case PRNE_PACK_RC_INVAL:
	case PRNE_PACK_RC_FMT_ERR:
	case PRNE_PACK_RC_NO_ARCH:
		fprintf(stderr, "%s: %s\n", s, prne_pack_rc_tostr(prc));
		break;
	case PRNE_PACK_RC_ERRNO:
		perror(s);
		break;
	default: abort();
	}
}

static int yaml_output_handler(void *data, unsigned char *buffer, size_t size) {
	ssize_t io_ret;

	while (size > 0) {
		io_ret = write(prog_g.yaml.fd, buffer, size);
		if (io_ret <= 0) {
			if (io_ret < 0) {
				perror("write()");
			}
			return false;
		}
		size -= io_ret;
		buffer += io_ret;
	}
	return true;
}

static void yaml_perror (const char *s) {
	fprintf(stderr, "%s: %s\n", s, prog_g.yaml.emitter->problem);
}

static void emit_mapping_start (void) {
	yaml_event_t e;

	if (yaml_mapping_start_event_initialize(
			&e,
			NULL,
			(yaml_char_t*)YAML_MAP_TAG,
			true,
			YAML_ANY_MAPPING_STYLE) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_start_event_initialize()");
		abort();
	}
}

static void emit_mapping_end (void) {
	yaml_event_t e;

	if (yaml_mapping_end_event_initialize(&e) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_end_event_initialize()");
		abort();
	}
}

static void emit_seq_start (void) {
	yaml_event_t e;

	if (yaml_sequence_start_event_initialize(
			&e,
			NULL,
			(yaml_char_t*)YAML_SEQ_TAG,
			true,
			YAML_ANY_SEQUENCE_STYLE) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_sequence_start_event_initialize()");
		abort();
	}
}

static void emit_seq_end (void) {
	yaml_event_t e;

	if (yaml_sequence_end_event_initialize(&e) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_sequence_end_event_initialize()");
		abort();
	}
}

static void emit_scalar (const char *type, const char *val) {
	yaml_event_t e;

	if (yaml_scalar_event_initialize(
			&e,
			NULL,
			(yaml_char_t*)type,
			(yaml_char_t*)val,
			strlen(val),
			true,
			false,
			YAML_ANY_SCALAR_STYLE) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_end_event_initialize()");
		abort();
	}
}

static void emit_bool_scalar (const bool val) {
	emit_scalar(YAML_BOOL_TAG, val ? "true" : "false");
}

static void emit_scalar_fmt (const char *type, const char *fmt, ...) {
	char *str;
	int f_ret;
	va_list va;

	va_start(va, fmt);
	f_ret = vsnprintf(NULL, 0, fmt, va);
	va_end(va);
	if (f_ret < 0) {
		perror("vsnprintf()");
		abort();
	}

	str = prne_alloc_str(f_ret);
	va_start(va, fmt);
	f_ret = vsnprintf(str, (size_t)f_ret + 1, fmt, va);
	va_end(va);

	emit_scalar(type, str);
	prne_free(str);
}

static void start_yaml (const int fd, const bool ours) {
	yaml_event_t e;

	assert(prog_g.yaml.emitter == NULL);

	prog_g.yaml.fd = fd;
	prog_g.yaml.our_fd = ours;
	prog_g.yaml.emitter = prne_malloc(sizeof(yaml_emitter_t), 1);
	if (yaml_emitter_initialize(prog_g.yaml.emitter) == 0) {
		yaml_perror("yaml_emitter_initialize()");
		abort();
	}
	yaml_emitter_set_output(prog_g.yaml.emitter, yaml_output_handler, NULL);

	if (yaml_stream_start_event_initialize(&e, YAML_UTF8_ENCODING) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_stream_start_event_initialize()");
		abort();
	}
	if (yaml_document_start_event_initialize(&e, NULL, NULL, NULL, true) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_document_start_event_initialize()");
		abort();
	}
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, ROOT_TAG_NAME);
	emit_mapping_start();
}

static void end_yaml (void) {
	yaml_event_t e;

	if (prog_g.yaml.emitter == NULL) {
		return;
	}

	emit_mapping_end();
	emit_mapping_end();
	if (yaml_document_end_event_initialize(&e, true) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_document_end_event_initialize()");
		abort();
	}
	if (yaml_stream_end_event_initialize(&e) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_stream_end_event_initialize()");
		abort();
	}

	yaml_emitter_delete(prog_g.yaml.emitter);
	prne_free(prog_g.yaml.emitter);
	prog_g.yaml.emitter = NULL;
	if (prog_g.yaml.our_fd) {
		prne_close(prog_g.yaml.fd);
		prog_g.yaml.fd = -1;
	}
}

static ssize_t do_read_null (void *buf, size_t l) {
	return 0;
}

static bool do_connect_tls (void) {
	int f_ret;

	if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
		fprintf(stderr, "do_connect_tls()\n");
	}

	f_ret = mbedtls_net_connect(
		&prog_g.net.ctx,
		prog_conf.remote_host,
		prog_conf.remote_port,
		MBEDTLS_NET_PROTO_TCP);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_net_connect()");
		return false;
	}

	f_ret = mbedtls_ssl_setup(&prog_g.ssl.ctx, &prog_g.ssl.conf);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_setup()");
		return false;
	}
	mbedtls_ssl_set_bio(
		&prog_g.ssl.ctx,
		&prog_g.net.ctx,
		mbedtls_net_send,
		mbedtls_net_recv,
		mbedtls_net_recv_timeout);

	f_ret = mbedtls_ssl_handshake(&prog_g.ssl.ctx);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_handshake()");
		return false;
	}
	if (!prne_mbedtls_verify_alp(
			&prog_g.ssl.conf,
			&prog_g.ssl.ctx,
			PRNE_HTBT_TLS_ALP))
	{
		fprintf(stderr, "ALPN not negotiated.\n");
		return false;
	}

	return true;
}

static void do_disconnect_tls (void) {
	if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
		fprintf(stderr, "do_disconnect_tls()\n");
	}
	mbedtls_ssl_close_notify(&prog_g.ssl.ctx);
	mbedtls_ssl_free(&prog_g.ssl.ctx);

	mbedtls_net_free(&prog_g.net.ctx);
	prne_iobuf_reset(&prog_g.net.ib);
}

static ssize_t do_read_tls (void *buf, size_t l) {
	return mbedtls_ssl_read(&prog_g.ssl.ctx, (unsigned char *)buf, l);
}

static ssize_t do_write_tls (const void *buf, size_t l) {
	return mbedtls_ssl_write(&prog_g.ssl.ctx, (const unsigned char *)buf, l);
}

static bool do_connect_stdio (void) {
	if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
		fprintf(stderr, "do_connect_stdio()\n");
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Cannot write binary data to terminal.\n");
		return false;
	}
	return true;
}

static void do_disconnect_stdio (void) {
	if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
		fprintf(stderr, "do_disconnect_stdio()\n");
	}
}

#if 0
static ssize_t do_read_stdio (void *buf, size_t l) {
	return read(STDIN_FILENO, buf, l);
}
#endif

static ssize_t do_write_stdio (const void *buf, size_t l) {
	return write(STDOUT_FILENO, buf, l);
}

static int init_tls_io (void) {
	int f_ret;
	static const char *ALPN_ARR[] = {
		PRNE_HTBT_TLS_ALP,
		NULL
	};

	f_ret = mbedtls_ssl_config_defaults(
		&prog_g.ssl.conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_config_defaults()");
		abort();
	}

	f_ret = mbedtls_ssl_conf_alpn_protocols(&prog_g.ssl.conf, ALPN_ARR);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_conf_alpn_protocols()");
		abort();
	}

	mbedtls_ssl_conf_rng(
		&prog_g.ssl.conf,
		mbedtls_ctr_drbg_random,
		&prog_g.ssl.rnd);

	if (prog_conf.tls_ca != NULL) {
		f_ret = mbedtls_x509_crt_parse_file(&prog_g.ssl.ca, prog_conf.tls_ca);
		if (f_ret != 0) {
			prne_mbedtls_perror(f_ret, prog_conf.tls_ca);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&prog_g.ssl.conf, &prog_g.ssl.ca, NULL);
		mbedtls_ssl_conf_authmode(
			&prog_g.ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
	}
	else {
		mbedtls_ssl_conf_authmode(
			&prog_g.ssl.conf,
			MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	if (prog_conf.tls_cert != NULL) {
		f_ret = mbedtls_x509_crt_parse_file(&prog_g.ssl.crt, prog_conf.tls_cert);
		if (f_ret != 0) {
			prne_mbedtls_perror(f_ret, prog_conf.tls_cert);
			return 1;
		}
	}
	if (prog_conf.tls_key != NULL) {
		do {
			f_ret = mbedtls_pk_parse_keyfile(
				&prog_g.ssl.pk,
				prog_conf.tls_key,
				prog_conf.tls_key_pw);
			switch (f_ret) {
			case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
			case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
				prne_mbedtls_perror(f_ret, "mbedtls_pk_parse_keyfile()");
				if (!interact_tls_key_pw()) {
					return 1;
				}
				break;
			case 0: break;
			default:
				prne_mbedtls_perror(f_ret, prog_conf.tls_key);
				return 1;
			}
		} while (f_ret != 0);
	}
	prne_memzero(prog_conf.tls_key_pw, sizeof(prog_conf.tls_key_pw));

	f_ret = mbedtls_ssl_conf_own_cert(
		&prog_g.ssl.conf,
		&prog_g.ssl.crt,
		&prog_g.ssl.pk);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_conf_own_cert()");
		return 1;
	}

	prog_g.io.do_connect = do_connect_tls;
	prog_g.io.do_disconnect = do_disconnect_tls;
	prog_g.io.do_read = do_read_tls;
	prog_g.io.do_write = do_write_tls;

	return 0;
}

static int init_txtrec_io () {
	prog_g.io.do_connect = do_connect_stdio;
	prog_g.io.do_disconnect = do_disconnect_stdio;
	prog_g.io.do_read = do_read_null;
	prog_g.io.do_write = do_write_stdio;

	return 0;
}

static int init_io (void) {
	switch (prog_conf.mode) {
	case PM_TLS: return init_tls_io();
	case PM_TXTREC: return init_txtrec_io();
	default: abort();
	}
}

static uint16_t htbt_msgid_rnd_f (void *ctx) {
	int f_ret;
	uint16_t ret;

	f_ret = mbedtls_ctr_drbg_random(
		&prog_g.ssl.rnd,
		(unsigned char*)&ret,
		sizeof(ret));
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ctr_drbg_random()");
		abort();
	}
	return ret;
}

static void raise_proto_err (const char *fmt, ...) {
	va_list vl;

	fprintf(stderr, "Protocol error: ");
	va_start(vl, fmt);
	vfprintf(stderr, fmt, vl);
	va_end(vl);
	fprintf(stderr, "\n");
}

static void raise_invalid_op (const prne_htbt_op_t op) {
	raise_proto_err("invalid response op %"PRIx8"", op);
}

static void raise_invalid_status (const prne_htbt_status_t *st) {
	raise_proto_err(
		"Invalid status response: code=%"PRIx8", err=%"PRId32,
		st->code,
		st->err);
}

static bool send_frame (const void *frame, prne_htbt_ser_ft ser_f) {
	int f_ret;
	size_t actual;
	prne_htbt_ser_rc_t rc;

	prne_iobuf_reset(&prog_g.net.ib);
	rc = ser_f(
		prog_g.net.ib.m,
		prog_g.net.ib.avail,
		&actual,
		frame);
	switch (rc) {
	case PRNE_HTBT_SER_RC_OK: break;
	case PRNE_HTBT_SER_RC_ERRNO:
		perror("prne_htbt_ser_ft()");
		return false;
	default:
		fprintf(stderr, "prne_htbt_ser_ft(): %s\n", prne_htbt_serrc_tostr(rc));
		return false;
	}
	prne_iobuf_shift(&prog_g.net.ib, actual);

	while (prog_g.net.ib.len > 0) {
		f_ret = prog_g.io.do_write(prog_g.net.ib.m, prog_g.net.ib.len);
		if (f_ret == 0) {
			raise_proto_err("remote end shutdown read");
			return false;
		}
		if (f_ret < 0) {
			prne_mbedtls_perror(f_ret, "prog_g.io.do_write()");
			return false;
		}
		prne_iobuf_shift(&prog_g.net.ib, -f_ret);
	}

	return true;
}

static bool send_mh (const prne_htbt_msg_head_t *mh) {
	return send_frame(mh, (prne_htbt_ser_ft)prne_htbt_ser_msg_head);
}

static bool recv_frame (void *frame, prne_htbt_dser_ft dser_f) {
	size_t actual;
	prne_htbt_ser_rc_t rc;
	int f_ret;

	while (true) {
		rc = dser_f(prog_g.net.ib.m, prog_g.net.ib.len, &actual, frame);

		switch (rc) {
		case PRNE_HTBT_SER_RC_OK:
			prne_iobuf_shift(&prog_g.net.ib, -actual);
			return true;
		case PRNE_HTBT_SER_RC_MORE_BUF:
			assert(actual <= prog_g.net.ib.size);
			break;
		case PRNE_HTBT_SER_RC_ERRNO:
			perror("dser_f()");
			abort();
		default:
			raise_proto_err(
				"failed to deserialise frame (%s)",
				prne_htbt_serrc_tostr(rc));
			return false;
		}

		f_ret = prog_g.io.do_read(prog_g.net.ib.m + prog_g.net.ib.len, actual);
		if (f_ret == 0) {
			raise_proto_err("remote end shutdown write");
			return false;
		}
		if (f_ret < 0) {
			prne_mbedtls_perror(f_ret, "prog_g.io.do_read()");
			return false;
		}
		prne_iobuf_shift(&prog_g.net.ib, f_ret);
	}
}

static bool recv_mh (prne_htbt_msg_head_t *mh, const uint16_t *cor_id) {
	if (!recv_frame(mh, (prne_htbt_dser_ft)prne_htbt_dser_msg_head)) {
		return false;
	}

	if (!mh->is_rsp) {
		raise_proto_err("received request frame for a response");
		return false;
	}
	if (cor_id != NULL && *cor_id != mh->id) {
		raise_proto_err("Uninitiated msg_id %"PRIx8, mh->id);
		return false;
	}

	return true;
}

static bool do_ayt (void) {
	prne_htbt_msg_head_t mh;
	bool ret = false;

	if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
		fprintf(stderr, "do_ayt()\n");
	}

	prne_htbt_init_msg_head(&mh);
	do {
		if (!send_frame(&mh, (prne_htbt_ser_ft)prne_htbt_ser_msg_head) ||
			!recv_frame(&mh, (prne_htbt_dser_ft)prne_htbt_dser_msg_head))
		{
			break;
		}
		ret = mh.op == PRNE_HTBT_OP_NOOP && mh.is_rsp;
	} while (false);

	prne_htbt_free_msg_head(&mh);
	return ret;
}

static bool recv_status (prne_htbt_status_t *st) {
	return recv_frame(st, (prne_htbt_dser_ft)prne_htbt_dser_status);
}

static void emit_status_frame (const prne_htbt_status_t *st) {
	emit_scalar(YAML_STR_TAG, BODY_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_INT_TAG, "code");
	emit_scalar_fmt(YAML_INT_TAG, "%d", st->code);
	emit_scalar(YAML_STR_TAG, "err");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRId32, st->err);
	if (st->code == PRNE_HTBT_STATUS_ERRNO) {
		emit_scalar(YAML_STR_TAG, "err_str");
		emit_scalar(YAML_STR_TAG, strerror(st->err));
	}
	emit_mapping_end();
}

static void emit_preemble (
	const char *cmd,
	const char *result,
	void (*opt_f)(void))
{
	int f_ret;
	uint8_t sa_storage[
		prne_op_max(sizeof(struct sockaddr_in6), sizeof(struct sockaddr_in))];
	socklen_t sl = sizeof(sa_storage);
	const struct sockaddr *sa = (const struct sockaddr*)sa_storage;

	f_ret = getpeername(prog_g.net.ctx.fd, (struct sockaddr*)sa_storage, &sl);
	if (f_ret != 0) {
		perror("getpeername()");
		abort();
	}
	assert(sizeof(sa_storage) >= sl);

	emit_scalar(YAML_STR_TAG, PREEMBLE_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "remote");
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "host");
	emit_scalar(YAML_STR_TAG, prog_conf.remote_host);
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sa = (const struct sockaddr_in*)sa_storage;
		char addr_str[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, &sa->sin_addr, addr_str, sizeof(addr_str)) ==
			NULL)
		{
			perror("inet_ntop()");
			abort();
		}
		emit_scalar(YAML_STR_TAG, "af");
		emit_scalar(YAML_STR_TAG, "INET");
		emit_scalar(YAML_STR_TAG, "addr");
		emit_scalar(YAML_STR_TAG, addr_str);
		emit_scalar(YAML_STR_TAG, "port");
		emit_scalar_fmt(YAML_INT_TAG, "%u", ntohs(sa->sin_port));
	}
	else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sa = (const struct sockaddr_in6*)sa_storage;
		char addr_str[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, &sa->sin6_addr, addr_str, sizeof(addr_str)) ==
			NULL)
		{
			perror("inet_ntop()");
			abort();
		}
		emit_scalar(YAML_STR_TAG, "af");
		emit_scalar(YAML_STR_TAG, "INET6");
		emit_scalar(YAML_STR_TAG, "addr");
		emit_scalar(YAML_STR_TAG, addr_str);
		emit_scalar(YAML_STR_TAG, "port");
		emit_scalar_fmt(YAML_INT_TAG, "%u", ntohs(sa->sin6_port));
	}
	else {
		abort();
	}
	emit_mapping_end();
	emit_scalar(YAML_STR_TAG, "command");
	emit_scalar(YAML_STR_TAG, cmd);
	emit_scalar(YAML_STR_TAG, "result");
	emit_scalar(YAML_STR_TAG, result);
	if (opt_f != NULL) {
		opt_f();
	}
	emit_mapping_end();
}

static void emit_hostinfo_iflags (
	void *ctx,
	const unsigned int bit,
	const bool v)
{
	const char *enumstr;

	if (!v) {
		return;
	}

	enumstr = prne_iflag_tostr(bit);
	if (enumstr) {
		emit_scalar(YAML_STR_TAG, enumstr);
	}
	else {
		emit_scalar_fmt(YAML_STR_TAG, "#%u", bit);
	}
}

static void emit_uuid (const uint8_t *uuid) {
	emit_scalar_fmt(
		YAML_STR_TAG,
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uuid[0],
		uuid[1],
		uuid[2],
		uuid[3],
		uuid[4],
		uuid[5],
		uuid[6],
		uuid[7],
		uuid[8],
		uuid[9],
		uuid[10],
		uuid[11],
		uuid[12],
		uuid[13],
		uuid[14],
		uuid[15]);
}

static void emit_hostinfo_frame (const prne_htbt_host_info_t *hi) {
	prne_host_cred_t hc;
	prne_htbt_ser_rc_t rc;
	const char *enumstr;

	prne_init_host_cred(&hc);
	emit_scalar(YAML_STR_TAG, BODY_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "parent_uptime");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->parent_uptime);
	emit_scalar(YAML_STR_TAG, "child_uptime");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->child_uptime);
	emit_scalar(YAML_STR_TAG, "bne_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->bne_cnt);
	emit_scalar(YAML_STR_TAG, "infect_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->infect_cnt);
	emit_scalar(YAML_STR_TAG, "parent_pid");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->parent_pid);
	emit_scalar(YAML_STR_TAG, "child_pid");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->child_pid);
	emit_scalar(YAML_STR_TAG, "prog_ver");
	emit_uuid(hi->prog_ver);
	emit_scalar(YAML_STR_TAG, "boot_id");
	emit_uuid(hi->boot_id);
	emit_scalar(YAML_STR_TAG, "instance_id");
	emit_uuid(hi->instance_id);
	emit_scalar(YAML_STR_TAG, "org_id");
	emit_uuid(hi->org_id);

	if (hi->host_cred_len > 0) {
		rc = prne_dec_host_cred(hi->host_cred, hi->host_cred_len, &hc);
		emit_scalar(YAML_STR_TAG, "host_cred");

		emit_mapping_start();
		if (rc == PRNE_HTBT_SER_RC_ERRNO) {
			perror("prne_dec_host_cred()");
			abort();
		}
		else if (rc == PRNE_HTBT_SER_RC_OK &&
			prne_chkcstr(hc.id, prne_cisprint) &&
			prne_chkcstr(hc.pw, prne_cisprint))
		{
			emit_scalar(YAML_STR_TAG, "fmt");
			emit_scalar(YAML_STR_TAG, "plain");
			emit_scalar(YAML_STR_TAG, "id");
			emit_scalar(YAML_STR_TAG, hc.id);
			emit_scalar(YAML_STR_TAG, "pw");
			emit_scalar(YAML_STR_TAG, hc.pw);
		}
		else {
			char *b64str;

			b64str = prne_enc_base64_mem(hi->host_cred, hi->host_cred_len);
			if (b64str == NULL) {
				perror("prne_enc_base64_mem()");
				abort();
			}

			emit_scalar(YAML_STR_TAG, "fmt");
			emit_scalar(YAML_STR_TAG, "raw");
			emit_scalar(YAML_STR_TAG, "raw");
			emit_scalar(YAML_STR_TAG, b64str);

			prne_free(b64str);
		}
		emit_mapping_end();
	}

	emit_scalar(YAML_STR_TAG, "crash_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->crash_cnt);
	emit_scalar(YAML_STR_TAG, "os");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->os);
	enumstr = prne_os_tostr(hi->os);
	if (enumstr != NULL) {
		emit_scalar(YAML_STR_TAG, "osstr");
		emit_scalar(YAML_STR_TAG, enumstr);
	}
	emit_scalar(YAML_STR_TAG, "arch");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->arch);
	enumstr = prne_arch_tostr(hi->arch);
	if (enumstr != NULL) {
		emit_scalar(YAML_STR_TAG, "archstr");
		emit_scalar(YAML_STR_TAG, enumstr);
	}

	emit_scalar(YAML_STR_TAG, "flags");
	emit_seq_start();
	prne_bf_foreach(NULL, hi->bf, hi->bf_len, emit_hostinfo_iflags);
	emit_seq_end();

	emit_mapping_end();

	prne_free_host_cred(&hc);
}

static bool do_hostinfo (
	prne_htbt_host_info_t *hi,
	prne_htbt_status_t *st,
	bool *status)
{
	bool ret = false;
	const uint16_t msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);
	prne_htbt_msg_head_t mh;

	prne_htbt_init_msg_head(&mh);
	mh.id = msgid;
	mh.is_rsp = false;
	mh.op = PRNE_HTBT_OP_HOST_INFO;

	if (!send_mh(&mh)) {
		goto END;
	}
	if (prog_conf.mode == PM_TXTREC) {
		goto END;
	}
	if (!recv_mh(&mh, &msgid)) {
		goto END;
	}
	switch (mh.op) {
	case PRNE_HTBT_OP_HOST_INFO:
		if (!recv_frame(hi, (prne_htbt_dser_ft)prne_htbt_dser_host_info)) {
			goto END;
		}
		*status = false;
		break;
	case PRNE_HTBT_OP_STATUS:
		if (!recv_status(st)) {
			goto END;
		}
		*status = true;
		break;
	default:
		raise_invalid_op(mh.op);
		goto END;
	}
	ret = true;

END:
	prne_htbt_free_msg_head(&mh);
	return ret;
}

static int cmdmain_hostinfo (void) {
	int ret = 0;
	bool status;
	prne_htbt_host_info_t hi;
	prne_htbt_status_t st;

	prne_htbt_init_host_info(&hi);
	prne_htbt_init_status(&st);

	if (!prog_g.io.do_connect()) {
		ret = 1;
		goto END;
	}
	if (!do_hostinfo(&hi, &st, &status)) {
		ret = 1;
		goto END;
	}

	start_yaml(STDOUT_FILENO, false);
	if (status) {
		emit_preemble("hostinfo", "status", NULL);
		emit_status_frame(&st);
	}
	else {
		emit_preemble("hostinfo", "ok", NULL);
		emit_hostinfo_frame(&hi);
	}
	ret = 0;

END:
	prne_htbt_free_host_info(&hi);
	prne_htbt_free_status(&st);
	return ret;
}

static void emit_hover_opts (void) {
	char addr_str[prne_op_max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	emit_scalar(YAML_STR_TAG, PREEMBLE_OPT_TAG_NAME);
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "v4_addr");
	if (inet_ntop(
			AF_INET,
			prog_conf.cmd_param.hover.f.v4.addr,
			addr_str,
			sizeof(addr_str)) == NULL)
	{
		perror("inet_ntop()");
		abort();
	}
	emit_scalar(YAML_STR_TAG, addr_str);
	emit_scalar(YAML_STR_TAG, "v4_port");
	emit_scalar_fmt(
		YAML_INT_TAG,
		"%"PRIu16,
		prog_conf.cmd_param.hover.f.v4.port);
	emit_scalar(YAML_STR_TAG, "v6_addr");
	if (inet_ntop(
			AF_INET6,
			prog_conf.cmd_param.hover.f.v6.addr,
			addr_str,
			sizeof(addr_str)) == NULL)
	{
		perror("inet_ntop()");
		abort();
	}
	emit_scalar(YAML_STR_TAG, addr_str);
	emit_scalar(YAML_STR_TAG, "v6_port");
	emit_scalar_fmt(
		YAML_INT_TAG,
		"%"PRIu16,
		prog_conf.cmd_param.hover.f.v6.port);
	emit_mapping_end();
}

static bool upload_bin (
	prne_htbt_msg_head_t *mh,
	prne_htbt_stdio_t *sh,
	size_t l)
{
	ssize_t io_ret;

	mh->op = PRNE_HTBT_OP_STDIO;
	prne_iobuf_reset(&prog_g.cmd_st.run.ib);

	while (l > 0) {
		io_ret = read(
			prog_g.cmd_st.run.fd,
			prog_g.cmd_st.run.ib.m,
			prne_op_min(
				prne_op_min(l, prog_g.cmd_st.run.ib.avail),
				PRNE_HTBT_STDIO_LEN_MAX));
		if (io_ret == 0) {
			fprintf(stderr, "Unexpected EOF whilst reading binary!\n");
			return false;
		}
		if (io_ret < 0) {
			perror("read()");
			return false;
		}
		prne_iobuf_shift(&prog_g.cmd_st.run.ib, io_ret);
		l -= io_ret;

		sh->len = io_ret;
		if (!(send_mh(mh) &&
			send_frame(sh, (prne_htbt_ser_ft)prne_htbt_ser_stdio)))
		{
			return false;
		}

		while (prog_g.cmd_st.run.ib.len > 0) {
			io_ret = prog_g.io.do_write(
				prog_g.cmd_st.run.ib.m,
				prog_g.cmd_st.run.ib.len);
			if (io_ret == 0) {
				raise_proto_err("remote end shutdown read");
				return false;
			}
			if (io_ret < 0) {
				prne_mbedtls_perror((int)io_ret, "prog_g.io.do_write()");
				return false;
			}
			if (prog_conf.prne_vl >= PRNE_VL_DBG0) {
				fprintf(stderr, "bin ul %zd bytes.\n", io_ret);
			}
			prne_iobuf_shift(&prog_g.cmd_st.run.ib, -io_ret);
		}
	}

	sh->len = 0;
	sh->fin = true;
	return
		send_mh(mh) &&
		send_frame(sh, (prne_htbt_ser_ft)prne_htbt_ser_stdio);
}

static bool run_setup (const uint16_t msgid) {
	bool ret = true;
	struct stat fs;
	void *f;
	prne_htbt_ser_ft ser_f;
	prne_htbt_msg_head_t mh;
	prne_htbt_stdio_t sh;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_stdio(&sh);
	mh.id = msgid;
	mh.is_rsp = false;

	switch (prog_conf.cmd) {
	case SC_RUNCMD: mh.op = PRNE_HTBT_OP_RUN_CMD; break;
	case SC_RUNBIN: mh.op = PRNE_HTBT_OP_RUN_BIN; break;
	case SC_UPBIN: mh.op = PRNE_HTBT_OP_UP_BIN; break;
	default: abort();
	}

	switch (prog_conf.cmd) {
	case SC_RUNCMD:
		f = &prog_conf.cmd_param.run.bm.cmd;
		ser_f = (prne_htbt_ser_ft)prne_htbt_ser_cmd;
		fs.st_size = 0;
		break;
	case SC_RUNBIN:
	case SC_UPBIN:
		if (fstat(prog_g.cmd_st.run.fd, &fs) != 0) {
			ret = false;
			perror("fstat()");
			goto END;
		}

		prog_conf.cmd_param.run.bm.alloc_len = prne_op_min(
			fs.st_size,
			PRNE_HTBT_BIN_ALLOC_LEN_MAX);
		f = &prog_conf.cmd_param.run.bm;
		ser_f = (prne_htbt_ser_ft)prne_htbt_ser_bin_meta;
		break;
	}

	ret = send_mh(&mh) && send_frame(f, ser_f);
	if (!ret) {
		goto END;
	}

	if (fs.st_size > 0) {
		prog_conf.cmd_param.run.bin_len = (size_t)fs.st_size;
		ret = upload_bin(&mh, &sh, fs.st_size);
	}

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_stdio(&sh);
	return ret;
}

static bool run_sendstd (const uint16_t msgid, int *fd) {
	bool ret = true;
	prne_htbt_msg_head_t mh;
	prne_htbt_stdio_t f;
	ssize_t io_ret;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_stdio(&f);
	mh.id = msgid;
	mh.is_rsp = false;
	mh.op = PRNE_HTBT_OP_STDIO;

	prne_iobuf_reset(&prog_g.cmd_st.run.ib);
	io_ret = read(
		*fd,
		prog_g.cmd_st.run.ib.m,
		prog_g.cmd_st.run.ib.avail);
	if (io_ret < 0) {
		ret = false;
		perror("read()");
		goto END;
	}
	if (io_ret == 0) {
		*fd = -1;
		f.fin = true;
		ret =
			send_mh(&mh) &&
			send_frame(&f, (prne_htbt_ser_ft)prne_htbt_ser_stdio);
		goto END;
	}
	prne_iobuf_shift(&prog_g.cmd_st.run.ib, io_ret);

	f.len = io_ret;
	ret =
		send_mh(&mh) &&
		send_frame(&f, (prne_htbt_ser_ft)prne_htbt_ser_stdio);
	if (!ret) {
		goto END;
	}
	while (prog_g.cmd_st.run.ib.len > 0) {
		io_ret = prog_g.io.do_write(
			prog_g.cmd_st.run.ib.m,
			prog_g.cmd_st.run.ib.len);
		if (io_ret == 0) {
			ret = false;
			raise_proto_err("remote end shutdown read");
			goto END;
		}
		if (io_ret < 0) {
			prne_mbedtls_perror((int)io_ret, "prog_g.io.do_write()");
			goto END;
		}

		prne_iobuf_shift(&prog_g.cmd_st.run.ib, -io_ret);
	}

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_stdio(&f);
	return ret;
}

static bool run_relay_stdout (prne_htbt_stdio_t *f) {
	ssize_t io_ret;

	prne_iobuf_reset(&prog_g.cmd_st.run.ib);
	while (f->len > 0 || prog_g.cmd_st.run.ib.len > 0) {
		if (f->len > 0 && prog_g.cmd_st.run.ib.avail > 0) {
			io_ret = prog_g.io.do_read(
				prog_g.cmd_st.run.ib.m + prog_g.cmd_st.run.ib.len,
				prne_op_min(f->len, prog_g.cmd_st.run.ib.avail));
			if (io_ret == 0) {
				raise_proto_err("remote end shutdown write");
				return false;
			}
			if (io_ret < 0) {
				prne_mbedtls_perror(io_ret, "prog_g.io.do_read()");
			}

			f->len -= io_ret;
			prne_iobuf_shift(&prog_g.cmd_st.run.ib, io_ret);
		}
		if (prog_g.cmd_st.run.ib.len > 0) {
			io_ret = write( // This is where the process will be killed on EPIPE
				f->err ? STDERR_FILENO : STDOUT_FILENO,
				prog_g.cmd_st.run.ib.m,
				prog_g.cmd_st.run.ib.len);
			assert(io_ret != 0);
			if (io_ret < 0) {
				perror("write()");
				return false;
			}

			prne_iobuf_shift(&prog_g.cmd_st.run.ib, -io_ret);
		}
	}

	return true;
}

static bool run_recvstd (const uint16_t msgid, int *fd) {
	bool ret = true;
	prne_htbt_msg_head_t mh;
	prne_htbt_stdio_t f;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_stdio(&f);

	ret = recv_mh(&mh, &msgid);
	if (!ret) {
		goto END;
	}
	switch (mh.op) {
	case PRNE_HTBT_OP_STATUS:
		prog_g.cmd_st.run.has_status = ret = recv_status(&prog_g.cmd_st.run.st);
		if (!ret) {
			goto END;
		}
		break;
	case PRNE_HTBT_OP_STDIO:
		ret =
			recv_frame(&f, (prne_htbt_dser_ft)prne_htbt_dser_stdio) &&
			run_relay_stdout(&f);
		if (!ret) {
			goto END;
		}
		break;
	default:
		ret = false;
		raise_invalid_op(mh.op);
		goto END;
	}

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_stdio(&f);
	return ret;
}

static bool run_relay (const uint16_t msgid) {
	bool ret = true;
	int f_ret;
	struct pollfd pfd[2];

	pfd[0].fd = STDIN_FILENO;
	pfd[1].fd = prog_g.net.ctx.fd;
	pfd[0].events = pfd[1].events = POLLIN;

	while (pfd[0].fd >= 0 || pfd[1].fd >= 0) {
		pfd[0].revents = pfd[1].revents = 0;

		if (mbedtls_ssl_check_pending(&prog_g.ssl.ctx)) {
			pfd[1].revents = POLLIN;
		}
		else {
			f_ret = poll(pfd, 2, -1);
			if (f_ret < 0) {
				ret = false;
				perror("poll()");
				break;
			}
			assert(f_ret != 0);
		}

		if (pfd[0].revents != 0 && !run_sendstd(msgid, &pfd[0].fd)) {
			ret = false;
			break;
		}
		if (pfd[1].revents != 0 && !run_recvstd(msgid, &pfd[1].fd)) {
			ret = false;
			break;
		}
		if (prog_g.cmd_st.run.has_status) {
			break;
		}
	}

	return ret;
}

static bool run_recv_status (const uint16_t msgid) {
	prne_htbt_msg_head_t mh;

	prne_htbt_init_msg_head(&mh);

	prog_g.cmd_st.run.has_status =
		recv_mh(&mh, &msgid) &&
		recv_status(&prog_g.cmd_st.run.st);

	prne_htbt_free_msg_head(&mh);
	return prog_g.cmd_st.run.has_status;
}

static bool do_open_bin (void) {
	prne_assert(prog_g.cmd_st.run.fd < 0);
	prog_g.cmd_st.run.fd = open(prog_conf.cmd_param.run.bin_path, O_RDONLY);
	if (prog_g.cmd_st.run.fd < 0) {
		perror(prog_conf.cmd_param.run.bin_path);
		return false;
	}
	return true;
}

static int cmdmain_run (void) {
	uint16_t msgid;

	msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);

	do { // fake
		if (!prog_g.io.do_connect()) {
			break;
		}
		if (prog_conf.cmd == SC_RUNBIN && !do_open_bin()) {
			break;
		}
		if (!run_setup(msgid)) {
			break;
		}
		if (prog_conf.mode == PM_TXTREC) {
			break;
		}
		if (!prog_conf.cmd_param.run.bm.cmd.detach && !run_relay(msgid)) {
			break;
		}

		if (!prog_g.cmd_st.run.has_status && !run_recv_status(msgid)) {
			break;
		}

		switch (prog_g.cmd_st.run.st.code) {
		case PRNE_HTBT_STATUS_OK:
			return prog_g.cmd_st.run.st.err;
		case PRNE_HTBT_STATUS_ERRNO:
			errno = prog_g.cmd_st.run.st.err;
			perror("Error status");
			return 1;
		default:
			raise_invalid_status(&prog_g.cmd_st.run.st);
			return 1;
		}
	} while (false);

	return 1;
}

static void emit_bin_host (const prne_bin_host_t *bh) {
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "os");
	emit_scalar(YAML_STR_TAG, prne_os_tostr(bh->os));
	emit_scalar(YAML_STR_TAG, "arch");
	emit_scalar(YAML_STR_TAG, prne_arch_tostr(bh->arch));
	emit_mapping_end();
}

static void emit_upbin_opts (void) {
	emit_scalar(YAML_STR_TAG, PREEMBLE_OPT_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "bin_type");
	if (prog_conf.cmd_param.run.bin_type == BT_NYBIN) {
		emit_scalar(YAML_STR_TAG, "nybin");
		emit_scalar(YAML_STR_TAG, "compat");
		emit_bool_scalar(prog_conf.cmd_param.run.compat);
		emit_scalar(YAML_STR_TAG, "target");
		emit_bin_host(&prog_g.cmd_st.run.target);
		emit_scalar(YAML_STR_TAG, "actual");
		emit_bin_host(&prog_g.cmd_st.run.actual);
	}
	else {
		emit_scalar(YAML_STR_TAG, "exec");
	}

	emit_scalar(YAML_STR_TAG, "alloc_len");
	emit_scalar_fmt(
		YAML_INT_TAG,
		"%"PRIu32,
		prog_conf.cmd_param.run.bm.alloc_len);
	emit_scalar(YAML_STR_TAG, "bin_len");
	emit_scalar_fmt(
		YAML_INT_TAG,
		"%"PRIu32,
		prog_conf.cmd_param.run.bin_len);
	emit_scalar(YAML_STR_TAG, "args");
	emit_seq_start();
	for (size_t i = 0; i < prog_conf.cmd_param.run.bm.cmd.argc; i += 1) {
		emit_scalar(YAML_STR_TAG, prog_conf.cmd_param.run.bm.cmd.args[i]);
	}
	emit_seq_end();
	emit_mapping_end();
}

static bool do_mktmpfile (void) {
	static const char *FMT_STR = "/tmp/proone-htbtclient.%"PRIdMAX;
	bool ret = false;
	int f_ret;
	char *tmpf = NULL;
	const pid_t pid = getpid();

	f_ret = snprintf(NULL, 0, FMT_STR, (intmax_t)pid);
	if (f_ret < 0) {
		perror("snprintf()");
		goto END;
	}
	tmpf = prne_alloc_str((size_t)f_ret);
	tmpf[0] = 0;
	snprintf(tmpf, (size_t)f_ret + 1, FMT_STR, (intmax_t)pid);

	prog_g.cmd_st.run.fd = open(tmpf, O_CREAT | O_RDWR | O_TRUNC | O_EXCL);
	if (prog_g.cmd_st.run.fd < 0) {
		goto END;
	}
	unlink(tmpf);
	ret = true;

END:
	prne_free(tmpf);
	return ret;
}

static bool upbin_do_rcb (void) {
	bool ret = false;
	prne_bin_archive_t ba;
	prne_bin_rcb_ctx_t rcb;
	const uint8_t *m_nybin = MAP_FAILED, *m_dv, *m_ba;
	size_t dv_len, ba_len;
	struct stat st;
	int fd = -1, err;
	prne_pack_rc_t prc;
	ssize_t io_ret;

	prne_init_bin_archive(&ba);
	prne_init_bin_rcb_ctx(&rcb);

	fd = open(prog_conf.cmd_param.run.bin_path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		perror(prog_conf.cmd_param.run.bin_path);
		goto END;
	}
	m_nybin = (const uint8_t*)mmap(
		NULL,
		st.st_size,
		PROT_READ,
		MAP_PRIVATE,
		fd,
		0);
	if (m_nybin == MAP_FAILED) {
		perror("mmap()");
		goto END;
	}

	if (!prne_index_nybin(
		m_nybin,
		st.st_size,
		&m_dv,
		&dv_len,
		&m_ba,
		&ba_len))
	{
		perror("prne_index_nybin");
		goto END;
	}
	prc = prne_index_bin_archive(m_ba, ba_len, &ba);
	if (prc != PRNE_PACK_RC_OK) {
		pprc(prc, "prne_index_bin_archive()", NULL);
		goto END;
	}
	prc = prne_start_bin_rcb_compat(
		&rcb,
		prog_g.cmd_st.run.target,
		NULL,
		NULL,
		0,
		0,
		m_dv,
		dv_len,
		&ba,
		&prog_g.cmd_st.run.actual);
	if (prc != PRNE_PACK_RC_OK) {
		pprc(prc, "prne_start_bin_rcb()", NULL);
		goto END;
	}
	if (!prne_eq_bin_host(
			&prog_g.cmd_st.run.target,
			&prog_g.cmd_st.run.actual))
	{
		if (!prog_conf.cmd_param.run.compat) {
			fprintf(
				stderr,
				"Compatible arch %s for target %s: not allowed\n",
				prne_arch_tostr(prog_g.cmd_st.run.actual.arch),
				prne_arch_tostr(prog_g.cmd_st.run.target.arch));
			goto END;
		}
		if (prog_conf.prne_vl >= PRNE_VL_WARN) {
			fprintf(
				stderr,
				"Using compatible arch %s for target %s.\n",
				prne_arch_tostr(prog_g.cmd_st.run.actual.arch),
				prne_arch_tostr(prog_g.cmd_st.run.target.arch));
		}
	}

	if (!do_mktmpfile()) {
		goto END;
	}

	prne_iobuf_reset(&prog_g.cmd_st.run.ib);
	while (true) {
		if (prog_g.cmd_st.run.ib.avail > 0 && prc != PRNE_PACK_RC_EOF) {
			io_ret = prne_bin_rcb_read(
				&rcb,
				prog_g.cmd_st.run.ib.m + prog_g.cmd_st.run.ib.len,
				prog_g.cmd_st.run.ib.avail,
				&prc,
				&err);
			if (io_ret < 0) {
				pprc(prc, "prne_bin_rcb_read()", &err);
				goto END;
			}
			prne_iobuf_shift(&prog_g.cmd_st.run.ib, io_ret);
		}

		if (prog_g.cmd_st.run.ib.len > 0) {
			io_ret = write(
				prog_g.cmd_st.run.fd,
				prog_g.cmd_st.run.ib.m,
				prog_g.cmd_st.run.ib.len);
			if (io_ret < 0) {
				perror("write()");
				goto END;
			}
			if (io_ret == 0) {
				abort();
			}

			prne_iobuf_shift(&prog_g.cmd_st.run.ib, -io_ret);
		}
		else if (prc == PRNE_PACK_RC_EOF) {
			break;
		}
	}

	if (lseek(prog_g.cmd_st.run.fd, 0, SEEK_SET) < 0) {
		perror("lseek()");
		goto END;
	}
	ret = true;

END:
	prne_close(fd);
	prne_free_bin_archive(&ba);
	prne_free_bin_rcb_ctx(&rcb);
	if (m_nybin != MAP_FAILED) {
		munmap((void*)m_nybin, st.st_size);
	}
	return ret;
}

static bool query_arch (void) {
	bool ret = false, status;
	prne_htbt_host_info_t hi;

	prne_htbt_init_host_info(&hi);

	if (!do_hostinfo(&hi, &prog_g.cmd_st.run.st, &status)) {
		goto END;
	}
	if (status) {
		prog_g.cmd_st.run.has_status = true;
		pstatus(&prog_g.cmd_st.run.st, "Querying hostinfo");
		goto END;
	}
	prog_g.cmd_st.run.target.os = hi.os;
	prog_g.cmd_st.run.target.arch = hi.arch;
	if (!prne_bin_host_inrange(&prog_g.cmd_st.run.target)) {
		fprintf(stderr, "Out of range: os=%d arch=%d\n", hi.os, hi.arch);
		goto END;
	}
	ret = true;

END:
	prne_htbt_free_host_info(&hi);
	return ret;
}

static int cmdmain_upbin (void) {
	uint16_t msgid;

	msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);

	if (!prog_g.io.do_connect()) {
		return 1;
	}
	switch (prog_conf.cmd_param.run.bin_type) {
	case BT_NYBIN:
		if (!query_arch() || !upbin_do_rcb()) {
			return 1;
		}
		break;
	case BT_EXEC:
		if (!do_open_bin()) {
			return 1;
		}
		break;
	default: abort();
	}
	if (prog_conf.mode != PM_TXTREC && !do_ayt()) {
		if (prog_conf.prne_vl >= PRNE_VL_WARN) {
			fprintf(stderr, "Reconnecting ...\n");
		}
		prog_g.io.do_disconnect();
		if (!prog_g.io.do_connect()) {
			return 1;
		}
	}
	if (!run_setup(msgid)) {
		return 1;
	}
	if (prog_conf.mode == PM_TXTREC) {
		return 0;
	}
	if (!prog_g.cmd_st.run.has_status && !run_recv_status(msgid)) {
		return 1;
	}

	start_yaml(STDOUT_FILENO, false);
	emit_preemble("upbin", "ok", emit_upbin_opts);
	emit_status_frame(&prog_g.cmd_st.run.st);

	return 0;
}

static int cmdmain_hover (void) {
	int ret = 0;
	uint16_t msgid;
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t st;

	msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);
	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&st);
	mh.id = msgid;
	mh.is_rsp = false;
	mh.op = PRNE_HTBT_OP_HOVER;

	if (!prog_g.io.do_connect()) {
		ret = 1;
		goto END;
	}

	if (!send_frame(&mh, (prne_htbt_ser_ft)prne_htbt_ser_msg_head) ||
		!send_frame(
			&prog_conf.cmd_param.hover.f,
			(prne_htbt_ser_ft)prne_htbt_ser_hover))
	{
		ret = 1;
		goto END;
	}
	if (prog_conf.mode == PM_TXTREC) {
		ret = 0;
		goto END;
	}
	if (!recv_mh(&mh, &msgid)) {
		ret = 1;
		goto END;
	}
	if (mh.op != PRNE_HTBT_OP_STATUS) {
		raise_invalid_op(mh.op);
		ret = 1;
		goto END;
	}

	if (!recv_status(&st)) {
		ret = 1;
		goto END;
	}
	start_yaml(STDOUT_FILENO, false);
	emit_preemble("hover", "ok", emit_hover_opts);
	emit_status_frame(&st);

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&st);
	return ret;
}

static void emit_rcb_opts (void) {
	emit_scalar(YAML_STR_TAG, PREEMBLE_OPT_TAG_NAME);
	emit_mapping_start();
	if (prog_conf.cmd_param.rcb.rcb.arch != PRNE_ARCH_NONE) {
		emit_scalar(YAML_STR_TAG, "arch");
		emit_scalar(
			YAML_STR_TAG,
			prne_arch_tostr(prog_conf.cmd_param.rcb.rcb.arch));
	}
	emit_scalar(YAML_STR_TAG, "compat");
	emit_bool_scalar(prog_conf.cmd_param.rcb.rcb.compat);
	emit_mapping_end();
}

static bool rcb_open_outfile (void) {
	assert(prog_g.cmd_st.rcb.fd < 0);
	assert(prog_conf.cmd_param.rcb.out_path != NULL);
	if (strcmp(prog_conf.cmd_param.rcb.out_path, "-") == 0) {
		prog_g.cmd_st.rcb.fd = STDOUT_FILENO;
		prog_g.cmd_st.rcb.our_file = false;
	}
	else {
		if (!prog_conf.cmd_param.rcb.f) {
			if (access(prog_conf.cmd_param.rcb.out_path, F_OK) == 0) {
				errno = EEXIST;
				perror(prog_conf.cmd_param.rcb.out_path);
				return false;
			}
		}

		prog_g.cmd_st.rcb.fd = open(
			prog_conf.cmd_param.rcb.out_path,
			O_CREAT | O_TRUNC | O_WRONLY | O_EXCL,
			0755);
		if (prog_g.cmd_st.rcb.fd < 0) {
			perror(prog_conf.cmd_param.rcb.out_path);
			return false;
		}
		prog_g.cmd_st.rcb.our_file = true;
	}

	return true;
}

static int cmdmain_rcb (void) {
	int ret = 0;
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t st;
	prne_htbt_stdio_t df;
	uint16_t msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);
	ssize_t io_ret;
	size_t sum = 0;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&st);
	prne_htbt_init_stdio(&df);

	if (prog_conf.mode != PM_TXTREC) {
		if (!rcb_open_outfile()) {
			ret = 1;
			goto END;
		}
		if (isatty(prog_g.cmd_st.rcb.fd)) {
			ret = 1;
			fprintf(stderr, "Cannot write binary data to terminal.\n");
			goto END;
		}
	}
	if (!prog_g.io.do_connect()) {
		ret = 1;
		goto END;
	}

	mh.id = msgid;
	mh.op = PRNE_HTBT_OP_RCB;
	if (!(send_mh(&mh) &&
		send_frame(
			&prog_conf.cmd_param.rcb.rcb,
			(prne_htbt_ser_ft)prne_htbt_ser_rcb)))
	{
		ret = 1;
		goto END;
	}

	if (prog_conf.mode == PM_TXTREC) {
		ret = 0;
		goto END;
	}

	do {
		if (!recv_mh(&mh, &msgid)) {
			ret = 1;
			goto END;
		}
		switch (mh.op) {
		case PRNE_HTBT_OP_STDIO: break;
		case PRNE_HTBT_OP_STATUS:
			if (!recv_status(&st)) {
				ret = 1;
				goto END;
			}
			start_yaml(STDERR_FILENO, false);
			emit_preemble("rcb", "status", emit_rcb_opts);
			emit_status_frame(&st);
			goto END;
		default:
			ret = 1;
			raise_invalid_op(mh.op);
			goto END;
		}

		if (!recv_frame(&df, (prne_htbt_dser_ft)prne_htbt_dser_stdio)) {
			ret = 1;
			goto END;
		}
		while (df.len > 0) {
			io_ret = prog_g.io.do_read(prog_g.cmd_st.rcb.ib.m, df.len);
			if (io_ret == 0) {
				ret = 1;
				raise_proto_err("remote end shutdown write");
				goto END;
			}
			if (io_ret < 0) {
				ret = 1;
				prne_mbedtls_perror(io_ret, "prog_g.io.do_read()");
				goto END;
			}
			prne_iobuf_shift(&prog_g.cmd_st.rcb.ib, io_ret);
			df.len -= io_ret;
			sum += io_ret;

			while (prog_g.cmd_st.rcb.ib.len > 0) {
				io_ret = write(
					prog_g.cmd_st.rcb.fd,
					prog_g.cmd_st.rcb.ib.m,
					prog_g.cmd_st.rcb.ib.len);
				if (io_ret < 0) {
					ret = 1;
					perror("write()");
					goto END;
				}
				if (io_ret == 0) {
					ret = 1;
					fprintf(stderr, "write() EOF\n");
					goto END;
				}
				prne_iobuf_shift(&prog_g.cmd_st.rcb.ib, -io_ret);
			}
		}
	} while (!df.fin);
	start_yaml(STDERR_FILENO, false);
	emit_preemble("rcb", "ok", emit_rcb_opts);
	emit_scalar(YAML_STR_TAG, BODY_TAG_NAME);
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "size");
	emit_scalar_fmt(YAML_INT_TAG, "%zu", sum);
	emit_mapping_end();

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&st);
	prne_htbt_free_stdio(&df);
	if (ret != 0 && prog_g.cmd_st.rcb.our_file) {
		unlink(prog_conf.cmd_param.rcb.out_path);
	}
	return ret;
}

int main (const int argc, char *const *args) {
	int ec = 0;

	init_prog_g();
	init_prog_conf();

	if (argc <= 1) {
		print_help(args[0], SC_NONE, stderr);
		ec = 2;
		goto END;
	}

	ec = parse_args(argc, args);
	if (prog_conf.help) {
		print_help(args[0], prog_conf.cmd, stdout);
	}
	if (prog_conf.version) {
		print_version(stdout);
	}
	if (ec != 0 || is_info_run()) {
		goto END;
	}

	ec = init_io();
	if (ec != 0) {
		goto END;
	}

	do {
		switch (prog_conf.mode) {
		case PM_TLS:
			switch (prog_conf.cmd) {
			case SC_HOSTINFO: ec = cmdmain_hostinfo(); continue;
			case SC_HOVER: ec = cmdmain_hover(); continue;
			case SC_RUNCMD:
			case SC_RUNBIN: ec = cmdmain_run(); continue;
			case SC_UPBIN: ec = cmdmain_upbin(); continue;
			case SC_RCB: ec = cmdmain_rcb(); continue;
			}
			break;
		case PM_TXTREC:
			switch (prog_conf.cmd) {
			case SC_HOSTINFO: cmdmain_hostinfo(); continue;
			case SC_HOVER: cmdmain_hover(); continue;
			case SC_RUNCMD:
			case SC_RUNBIN: cmdmain_run(); continue;
			case SC_UPBIN: cmdmain_upbin(); continue;
			case SC_RCB: cmdmain_rcb(); continue;
			}
			break;
		default: abort();
		}
		ec = 1;
		fprintf(stderr, "COMMAND not implemented.\n");
	} while (false);

END:
	end_yaml();
	deinit_prog_conf();
	deinit_prog_g();
	return ec;
}
