#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <regex.h>
#include <arpa/inet.h>

#include "util_rt.h"
#include "util_ct.h"

#define HELP_STR \
	"Usage: %s <op> [op args ...]\n"\
	"Args:\n"\
	"\t<op>: Heartbeart OP code. One of hover, run-cmd, ny-bin or run-bin\n"\
	"OP Usages:\n"\
	"\tHOVER: <IPv4 EP SPEC> <IPv6 EP SPEC>\n"\
	"\tRUN-CMD: <arg0> [arg1] [arg2] ...\n"\
	"\tNY-BIN: <PATH SPEC> [arg1] [arg2] ...\n"\
	"SPECS:\n"\
	"\tEP SPEC: \"192.0.2.1:64420\" or \"[2001:db8::1]:66420\"\n"\
	"\tPATH SPEC: path to file or \"-\" to read stdin\n"


static const char *PROG_NAME;

static void print_helpstr (void) {
	fprintf(stderr, HELP_STR, PROG_NAME);
}

static int do_hover (const int argc, char **args) {
	int ret = 0;
	regex_t re_ipv4, re_ipv6;
	regmatch_t rm[3];
	prne_htbt_hover_t hover;

	prne_htbt_init_hover(&hover);
	assert(regcomp(
		&re_ipv4,
		"^([0-9\\.]+):([0-9]{1,5})$",
		REG_ICASE | REG_EXTENDED) == 0);
	assert(regcomp(
		&re_ipv6,
		"^\\[([0-9a-f:]+)\\]:([0-9]{1,5})$",
		REG_ICASE | REG_EXTENDED) == 0);

	if (argc <= 1) {
		print_helpstr();
		ret = 2;
		goto END;
	}

	do {
		if (regexec(&re_ipv4, args[1], 3, &rm, 0) != 0) {
			goto CATCH;
		}
		args[1][rm[1].rm_eo] = 0;
		if (!inet_pton(AF_INET, args[1] + rm[1].rm_so, hover.v4.addr)) {
			goto CATCH;
		}
		if (sscanf(args[1] + rm[2].rm_so, "%"SCNu16, &hover.v4.port) != 0) {
			goto CATCH;
		}

		break;
CATCH:
		args[1][rm[1].rm_eo] = ':';
		fprintf(stderr, "Unreconised IP SPEC \"%s\"\n", args[1]);
		ret = 2;
		goto END;
	} while (false);

	do {
		if (regexec(&re_ipv6, args[2], 3, &rm, 0) != 0) {
			goto CATCH;
		}
		args[2][rm[1].rm_eo] = 0;
		if (!inet_pton(AF_INET6, args[2] + rm[1].rm_so, hover.v6.addr)) {
			goto CATCH;
		}
		if (sscanf(args[2] + rm[2].rm_so, "%"SCNu16, &hover.v6.port) != 0) {
			goto CATCH;
		}

		break;
CATCH:
		args[2][rm[1].rm_eo] = ':';
		fprintf(stderr, "Unreconised IP SPEC \"%s\"\n", args[2]);
		ret = 2;
		goto END;
	} while (false);


END:
	prne_htbt_free_hover(&hover);
	regfree(&re_ipv4);
	regfree(&re_ipv6);

	return ret;
}

static int do_runcmd (const int argc, char **args) {
	return 0;
}

static int do_nybin (const int argc, char **args) {
	return 0;
}

int main (const int argc, char **args) {
	PROG_NAME = argc > 0 ? args[0] : "proone-mkcnc";

	if (argc <= 1) {
		print_helpstr();
		return 2;
	}

	prne_transstr(args[1], tolower);

	if (strcmp(args[1], "hover") == 0) {
		return do_hover(argc - 1, args + 1);
	}
	else if (strcmp(args[1], "run-cmd") == 0) {
		return do_runcmd(argc - 1, args + 1);
	}
	else if (strcmp(args[1], "ny-bin") == 0) {
		return do_nybin(argc - 1, args + 1);
	}

	fprintf(stderr, "Unknown OP \"%s\"\n", args[1]);
	return 2;
}
