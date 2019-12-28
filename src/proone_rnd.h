#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>


struct proone_rnd_engine;
typedef struct proone_rnd_engine proone_rnd_engine_t;

typedef enum {
	PROONE_RND_ENGINE_ALLOC_OK,
	PROONE_RND_ENGINE_ALLOC_INVALID_SEED,
	PROONE_RND_ENGINE_ALLOC_MEM_ERR
} proone_rnd_engine_alloc_result_code_t;

typedef struct {
	proone_rnd_engine_alloc_result_code_t result;
	proone_rnd_engine_t *engine;
} proone_rnd_engnie_alloc_result_t;


void proone_init_alloc_rnd_engine_result (proone_rnd_engnie_alloc_result_t *r);
proone_rnd_engnie_alloc_result_t proone_alloc_rnd_engine (const uint32_t *seed);
void proone_free_rnd_engine (proone_rnd_engine_t *engine);
uint32_t proone_rnd_gen_int (proone_rnd_engine_t *engine);
double proone_rnd_gen_double (proone_rnd_engine_t *engine);
