#include <stdio.h>
#include <stdlib.h>

#include "proone_dvault.h"


int main (void) {
	proone_data_key_t i = PROONE_DATA_KEY_NONE + 1;
	proone_data_type_t type;

	proone_init_dvault();

	for (i = PROONE_DATA_KEY_NONE + 1; i < NB_PROONE_DATA_KEY; i += 1) {
		type = (proone_data_type_t)PROONE_DATA_DICT[i][0];

		switch (type) {
		case PROONE_DATA_TYPE_CSTR:
			printf("%10lld: %s\n", (long long)i, proone_dvault_unmask_entry_cstr(i));
			break;
		default:
			fprintf(stderr, "Error: unhandled data type (%d)'%s'\n", (int)type, proone_data_type2str(type));
			abort();
		}
	}

	proone_deinit_dvault();
	return 0;
}
