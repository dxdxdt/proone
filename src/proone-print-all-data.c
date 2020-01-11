#include <stdio.h>
#include <stdlib.h>

#include "dvault.h"

#define TYPE_STR_PADDING "4"


int main (void) {
	prne_data_key_t i = PRNE_DATA_KEY_NONE + 1;
	prne_data_type_t type;

	prne_init_dvault();

	for (i = PRNE_DATA_KEY_NONE + 1; i < NB_PRNE_DATA_KEY; i += 1) {
		type = (prne_data_type_t)PRNE_DATA_DICT[i][0];

		printf("%10lld(%" TYPE_STR_PADDING "s): ", (long long)i, prne_data_type_tostr(type));
		switch (type) {
		case PRNE_DATA_TYPE_CSTR:
			printf("%s", prne_dvault_unmask_entry_cstr(i, NULL));
			break;
		case PRNE_DATA_TYPE_BIN: {
			const uint8_t *p;
			size_t size, it;

			prne_dvault_unmask_entry_bin(i, &p, &size);

			for (it = 0; it < size; it += 1) {
				printf("%02X ", p[it]);
			}
			break;	
		}
		default:
			fprintf(stderr, "Error: unknown data type (%d)'%s'\n", (int)type, prne_data_type_tostr(type));
			abort();
		}

		printf("\n");
	}

	prne_deinit_dvault();
	return 0;
}
