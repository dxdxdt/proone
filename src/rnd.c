#include "rnd.h"
#include "util_rt.h"

#include <stdlib.h>
#include <time.h>

#include <unistd.h>
#include <sys/random.h>

#define N ((size_t)624)


struct prne_rnd_engine {
	size_t mti;
	uint32_t mt[N];
};


void prne_init_alloc_rnd_engine_result (prne_rnd_engnie_alloc_result_t *r) {
	r->engine = NULL;
	r->result = PRNE_RND_ENGINE_ALLOC_OK;
}

prne_rnd_engnie_alloc_result_t prne_alloc_rnd_engine (const uint32_t *s) {
	prne_rnd_engnie_alloc_result_t ret;
	uint32_t seed;

	prne_init_alloc_rnd_engine_result(&ret);
	
	if (s == NULL) {
		seed = 4357;
	}
	else {
		if (*s == 0) {
			ret.result = PRNE_RND_ENGINE_ALLOC_INVALID_SEED;
			return ret;
		}
		seed = *s;
	}
	
	ret.engine = (prne_rnd_engine_t*)prne_malloc(sizeof(prne_rnd_engine_t), 1);
	if (ret.engine == NULL) {
		ret.result = PRNE_RND_ENGINE_ALLOC_MEM_ERR;
		return ret;
	}

	ret.engine->mt[0] = seed;
	for (ret.engine->mti = 1; ret.engine->mti < N; ret.engine->mti += 1) {
		ret.engine->mt[ret.engine->mti] = 69069 * ret.engine->mt[ret.engine->mti - 1];
	}

	return ret;
}

void prne_free_rnd_engine (prne_rnd_engine_t *engine) {
	prne_free(engine);
}

uint32_t prne_rnd_gen_int (prne_rnd_engine_t *engine) {
	static const size_t M = 397;
	static const uint32_t
		UPPER_MASK = 0x80000000,
		LOWER_MASK = 0x7fffffff,
		TEMPERING_MASK_B = 0x9d2c5680,
		TEMPERING_MASK_C = 0xefc60000;
	static const uint32_t mag01[2] = {0, 0x9908b0df};
	uint32_t y;
	
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

double prne_rnd_gen_double (prne_rnd_engine_t *engine) {
	return (double)prne_rnd_gen_int(engine) * 2.3283064370807974e-10;
}

prne_rnd_engine_t *prne_mk_rnd_engine (void) {
	uint32_t seed = 0;
    prne_rnd_engnie_alloc_result_t ret;

    getrandom(&seed, sizeof(uint32_t), 0);

    if (seed == 0) {
        // fall back to seeding with what's available.
        seed =
            (uint32_t)(time(NULL) % 0xFFFFFFFF) ^
            (uint32_t)(getpid() % 0xFFFFFFFF) ^
            (uint32_t)(getppid() % 0xFFFFFFFF) ^
            (uint32_t)(clock() % 0xFFFFFFFF);
    }
    
    ret = prne_alloc_rnd_engine(seed == 0 ? NULL : &seed);
    if (ret.result != PRNE_RND_ENGINE_ALLOC_OK) {
        return NULL;
    }

    return ret.engine;
}
