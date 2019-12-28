#pragma once
#include "proone_rnd.h"

#include <stddef.h>


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

void proone_rnd_alphanumeric_str (proone_rnd_engine_t *rnd_engine, char *str, const size_t len);
