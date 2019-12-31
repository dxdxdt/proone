#include <stdio.h>
#include <stdlib.h>

#include "dvault.h"


int main (void) {
	prne_data_key_t i = PRNE_DATA_KEY_NONE + 1;
	prne_data_type_t type;

	prne_init_dvault();

	for (i = PRNE_DATA_KEY_NONE + 1; i < NB_PRNE_DATA_KEY; i += 1) {
		type = (prne_data_type_t)PRNE_DATA_DICT[i][0];

		switch (type) {
		case PRNE_DATA_TYPE_CSTR:
			printf("%10lld: %s\n", (long long)i, prne_dvault_unmask_entry_cstr(i, NULL));
			break;
		default:
			fprintf(stderr, "Error: unhandled data type (%d)'%s'\n", (int)type, prne_data_type2str(type));
			abort();
		}
	}

	prne_deinit_dvault();
	return 0;
}
