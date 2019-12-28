#include "proone_rnd.h"

#include <stdlib.h>

#define N ((size_t)624)


struct proone_rnd_engine {
	size_t mti;
	uint32_t mt[N];
};


void proone_init_alloc_rnd_engine_result (proone_rnd_engnie_alloc_result_t *r) {
	r->engine = NULL;
	r->result = PROONE_RND_ENGINE_ALLOC_OK;
}

proone_rnd_engnie_alloc_result_t proone_alloc_rnd_engine (const uint32_t *s) {
	proone_rnd_engnie_alloc_result_t ret;
	uint32_t seed;

	proone_init_alloc_rnd_engine_result(&ret);
	
	if (s == NULL) {
		seed = 4357;
	}
	else {
		if (*s == 0) {
			ret.result = PROONE_RND_ENGINE_ALLOC_INVALID_SEED;
			return ret;
		}
		seed = *s;
	}
	
	ret.engine = (proone_rnd_engine_t*)malloc(sizeof(proone_rnd_engine_t));
	if (ret.engine == NULL) {
		ret.result = PROONE_RND_ENGINE_ALLOC_MEM_ERR;
		return ret;
	}

	ret.engine->mt[0] = seed;
	for (ret.engine->mti = 1; ret.engine->mti < N; ret.engine->mti += 1) {
		ret.engine->mt[ret.engine->mti] = 69069 * ret.engine->mt[ret.engine->mti - 1];
	}

	return ret;
}

void proone_free_rnd_engine (proone_rnd_engine_t *engine) {
	free(engine);
}

uint32_t proone_rnd_gen_int (proone_rnd_engine_t *engine) {
	static const size_t M = 397;
	static const uint32_t
		MATRIX_A = 0x9908b0df,
		UPPER_MASK = 0x80000000,
		LOWER_MASK = 0x7fffffff,
		TEMPERING_MASK_B = 0x9d2c5680,
		TEMPERING_MASK_C = 0xefc60000;
	uint32_t y;
	static const uint32_t mag01[2] = {0, MATRIX_A};
	
	if (engine->mti >= N) {
		size_t kk;

		for (kk = 0; kk < N - M; kk += 1) {
			y = (engine->mt[kk] & UPPER_MASK) | (engine->mt[kk + 1] & LOWER_MASK);
			engine->mt[kk] = engine->mt[kk + M] ^ (y >> 1) ^ mag01[y & 1];
		}
		for (; kk < N - 1; kk += 1) {
			y = (engine->mt[kk] & UPPER_MASK) | (engine->mt[kk + 1] & LOWER_MASK);
			engine->mt[kk] = engine->mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 1];
		}
		y = (engine->mt[N - 1] & UPPER_MASK) | (engine->mt[0] & LOWER_MASK);
		engine->mt[N - 1] = engine->mt[M - 1] ^ (y >> 1) ^ mag01[y & 1];

		engine->mti = 0;
	}

	y = engine->mt[engine->mti];
	engine->mti += 1;
	y ^= y >> 11;
	y ^= (y << 7) & TEMPERING_MASK_B;
	y ^= (y << 15) & TEMPERING_MASK_C;
	y ^= y >> 18;

	return y;
}

double proone_rnd_gen_double (proone_rnd_engine_t *engine) {
	return (double)proone_rnd_gen_int(engine) * 2.3283064370807974e-10;
}
