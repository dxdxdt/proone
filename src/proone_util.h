#pragma once
#include "proone_rnd.h"

#include <stddef.h>
#include <time.h>


#define proone_op_spaceship(a,b) (a==b?0:a<b?-1:1)


#if 0
bool proone_strendsw (const char *str, const char *w) {
    const size_t len_str = strlen(str);
    const size_t len_w = strlen(w);

    if (len_str < len_w) {
        return false;
    }
    return strcmp(str + (len_str - len_w), w) == 0;
}
#endif

void proone_succeed_or_die (const int ret);
void proone_empty_func ();

void proone_rnd_alphanumeric_str (proone_rnd_engine_t *rnd_engine, char *str, const size_t len);
size_t proone_str_shift_spaces (char *str, const size_t len);

struct timespec proone_sub_timespec (const struct timespec *a, const struct timespec *b);
double proone_real_timespec (const struct timespec *ts);
int proone_cmp_timespec (const struct timespec *a, const struct timespec *b);

char *proone_enc_base64_mem (const uint8_t *data, const size_t size);
bool proone_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size);
