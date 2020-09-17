#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


typedef struct prne_cred_dict_entry prne_cred_dict_entry_t;
typedef struct prne_cred_dict_raw_entry prne_cred_dict_raw_entry_t;
typedef struct prne_cred_dict prne_cred_dict_t;

struct prne_cred_dict_entry {
	uint16_t id;
	uint16_t pw;
	uint8_t weight;
};

struct prne_cred_dict_raw_entry {
	char *id;
	char *pw;
	uint8_t weight;
};

struct prne_cred_dict {
	const char *m;
	prne_cred_dict_entry_t *arr;
	size_t cnt;
};

void prne_init_cred_dict (prne_cred_dict_t *p);
void prne_free_cred_dict (prne_cred_dict_t *p);

bool prne_build_cred_dict (
	const prne_cred_dict_raw_entry_t *arr,
	const size_t cnt,
	uint8_t **out_m,
	size_t *out_l);
bool prne_dser_cred_dict (
	prne_cred_dict_t *dict,
	const uint8_t *buf,
	const size_t len);
