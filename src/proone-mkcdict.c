#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include <regex.h>
#include <unistd.h>
#include <fcntl.h>

#include "config.h"
#include "cred_dict.h"
#include "util_rt.h"
#include "llist.h"


static regex_t re_entry, re_comment, re_empty;

static void print_help (FILE *o, const char *prog) {
	fprintf(
		o,
		"Usage: %s <cred file> <out file>\n"
		"Options:\n"
		"\t<cred file>: path to file listing credentials. \"-\" to read stdin\n"
		"\t<out file>: path to output file. \"-\" for stdout\n"
		"Cred File Format: <WEIGHT> <ID> [PW]\n"
		"\t<WEIGHT>: uint8_t weight value\n"
		"\t<ID>: c_str username\n"
		"\t[PW]: c_str password (optional)\n"
		"\tNote:\n"
		"\t\t- <ID> and <PW> are case-sensitive\n"
		"\t\t- Lines start with \"#\" are ignored\n"
		"Cred File Example:\n"
		"\t# TP-Link\n"
		"\t16\tadmin\tadmin\n"
		"\t# Linux machine with empty root password\n"
		"\t128\troot\n"
		"\t# Another typical default cred\n"
		"\t32\troot\t1234\n",
		prog);
}

static int do_parse (
	FILE *file,
	prne_cred_dict_raw_entry_t **arr,
	size_t *cnt)
{
	static const size_t RM_SIZE = 8;
	regmatch_t rm[RM_SIZE];
	char line[2][1024];
	size_t nr_line = 0;
	char *ent_weight, *ent_id, *ent_pw;
	size_t sl_id, sl_pw;
	prne_cred_dict_raw_entry_t ent;

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
		prne_memzero(&ent, sizeof(prne_cred_dict_raw_entry_t));

		line[1][rm[2].rm_eo] = 0; // terminate WEIGHT
		line[1][rm[3].rm_eo] = 0; // terminate ID
		ent_weight = line[1] + rm[2].rm_so;
		ent_id = line[1] + rm[3].rm_so;
		sl_id = rm[3].rm_eo - rm[3].rm_so;
		if (rm[5].rm_so >= 0) { // PW
			line[1][rm[5].rm_eo] = 0;
			ent_pw = line[1] + rm[5].rm_so;
			sl_pw = rm[5].rm_eo - rm[5].rm_so;
		}
		else {
			ent_pw = "";
			sl_pw = 0;
		}

		if (sscanf(ent_weight, "%"SCNu8, &ent.weight) != 1) {
			goto INV_LINE;
		}

		ent.id = prne_alloc_str(sl_id);
		ent.pw = prne_alloc_str(sl_pw);
		prne_assert(ent.id != NULL && ent.pw != NULL);
		memcpy(ent.id, ent_id, sl_id + 1);
		memcpy(ent.pw, ent_pw, sl_pw + 1);

		*arr = prne_realloc(*arr, sizeof(prne_cred_dict_raw_entry_t), *cnt + 1);
		prne_assert(*arr != NULL);
		(*arr)[*cnt] = ent;
		*cnt += 1;
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

int main (const int argc, const char **args) {
	int ret = 0;
	prne_cred_dict_t dict;
	prne_cred_dict_raw_entry_t *arr = NULL;
	uint8_t *m = NULL;
	size_t m_len = 0;
	size_t cnt = 0;
	FILE *in_f = NULL;
	bool own_in_f = false;
	int out_fd = -1;

	prne_assert(regcomp(
		&re_entry,
		// ^(\s+)?([0-9]{1,3})\s+(\S+)(\s+(\S+))?(\s+)?(#.*)?$
		// number of captures: 7
		// significant groups: <2>, <3>, [5]
		"^(\\s+)?([0-9]{1,3})\\s+(\\S+)(\\s+(\\S+))?(\\s+)?(#.*)?$",
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

	prne_init_cred_dict(&dict);

// TRY
	// parse args
	if (argc < 3) {
		print_help(stderr, args[0]);
		ret = 2;
		goto END;
	}

	if (prne_nstreq(args[1], "-")) {
		in_f = stdin;
	}
	else {
		own_in_f = true;
		in_f = fopen(args[1], "r");

		if (in_f == NULL) {
			perror(args[1]);
			ret = 1;
			goto END;
		}
	}

	if (prne_nstreq(args[2], "-")) {
		out_fd = STDOUT_FILENO;
	}
	else {
		out_fd = open(args[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (out_fd < 0) {
			perror(args[2]);
			ret = 1;
			goto END;
		}
	}
	if (isatty(out_fd)) {
		fprintf(stderr, "Refusing to write on terminal.\n");
		ret = 1;
		goto END;
	}

	ret = do_parse(in_f, &arr, &cnt);
	if (ret != 0) {
		goto END;
	}
	if (!prne_build_cred_dict(arr, cnt, &m, &m_len)) {
		ret = 1;
		perror("prne_build_cred_dict()");
		goto END;
	}
	// test
	if (!prne_dser_cred_dict(&dict, m, m_len)) {
		ret = 1;
		perror("prne_dser_cred_dict()");
		goto END;
	}
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		for (size_t i = 0; i < dict.cnt; i += 1) {
			fprintf(
				stderr,
				"%"PRIu8"\t%s\t%s\n",
				dict.arr[i].weight,
				dict.m + dict.arr[i].id,
				dict.m + dict.arr[i].pw);
		}
	}

	if (write(out_fd, m, m_len) != (ssize_t)m_len) {
		ret = 1;
		perror("write()");
		goto END;
	}

END:
	// clean up
	prne_close(out_fd);
	if (own_in_f && in_f != NULL) {
		fclose(in_f);
	}

	regfree(&re_entry);
	regfree(&re_comment);
	regfree(&re_empty);

	prne_free_cred_dict(&dict);
	for (size_t i = 0; i < cnt; i += 1) {
		prne_free(arr[i].id);
		prne_free(arr[i].pw);
	}
	prne_free(arr);
	prne_free(m);

	return ret;
}
