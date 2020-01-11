#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>


struct prne_rnd_engine;
typedef struct prne_rnd_engine prne_rnd_engine_t;
typedef struct prne_rnd_engnie_alloc_result prne_rnd_engnie_alloc_result_t;

typedef enum {
	PRNE_RND_ENGINE_ALLOC_OK,
	PRNE_RND_ENGINE_ALLOC_INVALID_SEED,
	PRNE_RND_ENGINE_ALLOC_MEM_ERR
} prne_rnd_engine_alloc_result_code_t;

struct prne_rnd_engnie_alloc_result {
	prne_rnd_engine_alloc_result_code_t result;
	prne_rnd_engine_t *engine;
};


void prne_init_alloc_rnd_engine_result (prne_rnd_engnie_alloc_result_t *r);
prne_rnd_engnie_alloc_result_t prne_alloc_rnd_engine (const uint32_t *seed);
void prne_free_rnd_engine (prne_rnd_engine_t *engine);
uint32_t prne_rnd_gen_int (prne_rnd_engine_t *engine);
double prne_rnd_gen_double (prne_rnd_engine_t *engine);

prne_rnd_engine_t *prne_mk_rnd_engine (void);
