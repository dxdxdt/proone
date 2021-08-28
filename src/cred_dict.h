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
