#include <stdio.h>

#include "protocol.h"


int main (void) {
	prne_arch_t i;

	for (i = PRNE_ARCH_NONE + 1; i < NB_PRNE_ARCH; i += 1) {
		printf("%s\n", prne_arch_tostr(i));
	}

	return 0;
}
