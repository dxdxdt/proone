/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
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
#include <inttypes.h>

#include "rnd.h"
#include "util_rt.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>


int main (const int argc, const char **args) {
	int ret = 0;
	uint32_t max, cnt, n, empty_cnt;
	uint32_t *arr = NULL;
	size_t graph[20], g_max, sn;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	prne_rnd_t rnd;

	prne_memzero(graph, sizeof(graph));
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	prne_init_rnd(&rnd);

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <max> <count>\n", args[0]);
		ret = 2;
		goto END;
	}
	if (sscanf(args[1], "%"SCNu32, &max) != 1 || max == 0) {
		fprintf(stderr, "Invalid <max>\n");
		ret = 2;
		goto END;
	}
	if (sscanf(args[2], "%"SCNu32, &cnt) != 1) {
		fprintf(stderr, "Invalid <count>\n");
		ret = 2;
		goto END;
	}

	prne_assert(mbedtls_ctr_drbg_seed(
		&ctr_drbg,
		mbedtls_entropy_func,
		&entropy,
		NULL,
		0) == 0);
	{
		uint8_t is[PRNE_RND_WELL512_SEEDLEN];

		prne_assert(mbedtls_ctr_drbg_random(&ctr_drbg, is, sizeof(is)) == 0);
		prne_assert(prne_rnd_alloc_well512(&rnd, is));
	}

	arr = prne_calloc(sizeof(uint32_t), max);
	for (uint32_t i = 0; i < cnt; i += 1) {
#if 1
		prne_assert(prne_rnd(&rnd, (uint8_t*)&n, sizeof(n)));
#else
		prne_assert(mbedtls_ctr_drbg_random(
			&ctr_drbg,
			(uint8_t*)&n,
			sizeof(n)) == 0);
#endif
		n = n % max;
		arr[n] += 1;
		graph[n * 20 / max] += 1;
	}

	empty_cnt = 0;
	for (size_t i = 0; i < max; i += 1) {
		if (arr[i] == 0) {
			empty_cnt += 1;
		}
	}

	g_max = 0;
	for (size_t i = 0; i < 20; i += 1) {
		if (graph[i] > g_max) {
			g_max = graph[i];
		}
	}

	for (size_t y = 0; y < 20; y += 1) {
		sn = graph[y] * 75 / g_max;
		printf("%2zu: ", y + 1);
		for (size_t x = 0; x < sn; x += 1) {
			printf("=");
		}
		printf("\n");
	}
	printf("Empty: %"PRIu32"\n", empty_cnt);

END:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	prne_free_rnd(&rnd);
	prne_free(arr);

	return ret;
}
