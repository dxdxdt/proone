#pragma once
#include "rnd.h"

#include <stddef.h>
#include <time.h>


#if 0
bool prne_strendsw (const char *str, const char *w) {
    const size_t len_str = strlen(str);
    const size_t len_w = strlen(w);

    if (len_str < len_w) {
        return false;
    }
    return strcmp(str + (len_str - len_w), w) == 0;
}
#endif

void prne_succeed_or_die (const int ret);
void prne_empty_func ();

void *prne_malloc (const size_t se, const size_t cnt);
void *prne_realloc (void *ptr, const size_t se, const size_t cnt);
void *prne_calloc (const size_t se, const size_t cnt);
void prne_free (void *ptr);

void prne_rnd_anum_str (prne_rnd_engine_t *rnd_engine, char *str, const size_t len);
size_t prne_str_shift_spaces (char *str, const size_t len);

struct timespec prne_sub_timespec (const struct timespec *a, const struct timespec *b);
double prne_real_timespec (const struct timespec *ts);
int prne_cmp_timespec (const struct timespec *a, const struct timespec *b);

char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size);
