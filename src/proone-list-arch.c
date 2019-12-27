#include <stdio.h>

#include "proone_protocol.h"


int main (void) {
    proone_arch_t i;

    for (i = PROONE_ARCH_NONE + 1; i < NB_PROONE_ARCH; i += 1) {
        printf("%s\n", proone_arch2str(i));
    }

    return 0;
}
