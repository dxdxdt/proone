#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


typedef struct prne_strmap prne_strmap_t;
typedef struct prne_strmap_tuple prne_strmap_tuple_t;

struct prne_strmap {
	prne_strmap_tuple_t *tbl;
	size_t size;
};

struct prne_strmap_tuple {
	const char *key;
	void *val;
};

void prne_init_strmap (prne_strmap_t *map);
void prne_free_strmap (prne_strmap_t *map);

void prne_strmap_clear (prne_strmap_t *map);
const prne_strmap_tuple_t *prne_strmap_insert (
	prne_strmap_t *map,
	const char* key,
	void *val);
void prne_strmap_erase (prne_strmap_t *map, const char* key);
const prne_strmap_tuple_t *prne_strmap_lookup (
	prne_strmap_t *map,
	const char* key);
