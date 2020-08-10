#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>

#include "dvault.h"
#include "util_rt.h"


int main (const int argc, char **args) {
	int exit_code = 0;
	ssize_t fd_read_size;
	size_t read_size = 0;
	uint8_t salt;
	prne_dvault_mask_result_t mask_result;
	prne_data_type_t type;

	prne_init_dvault_mask_result(&mask_result);

	if (argc <= 1) {
		fprintf(stderr,
			"Usage: %s <type> [salt]\n"
			"<type>: 'cstr', 'bin'\n"
			"[salt]: salt hex value\n",
			args[0]);
		exit_code = 2;
		goto END;
	}

	if (argc >= 3) {
		for (char *p = args[2]; *p != 0; p += 1) {
			*p = (char)tolower(*p);
		}

		if (sscanf(args[2], "%hhx", &salt) != 1) {
			perror("parsing salt: ");
			exit_code = 1;
			goto END;
		}
	}
	else {
		prne_geturandom(&salt, sizeof(salt));
	}

	type = prne_data_type_fstr(args[1]);
	switch (type) {
	case PRNE_DATA_TYPE_BIN:
	case PRNE_DATA_TYPE_CSTR: {
		static const size_t buf_size = 0x0000FFFF + 1;
		uint8_t buf[buf_size];

		do {
			fd_read_size = read(STDIN_FILENO, buf + read_size, buf_size - read_size);
			if (fd_read_size < 0) {
				perror("Error reading stdin");
				exit_code = 1;
				goto END;
			}
			if (fd_read_size > 0) {
				read_size += fd_read_size;
				if (read_size >= buf_size) {
					fprintf(stderr, "Error: data too large\n");
					exit_code = 1;
					goto END;
				}
			}
		} while (fd_read_size > 0);

		if (read_size == 0) {
			fprintf(stderr, "Error: no data read\n");
			exit_code = 1;
			goto END;
		}

		mask_result = prne_dvault_mask(type, salt, read_size, buf);
		if (mask_result.result == PRNE_DVAULT_MASK_OK) {
			printf("(uint8_t*)\"%s\",\n", mask_result.str);
		}
		else {
			fprintf(stderr, "Error: prne_dvault_mask() returned %d\n", (int)mask_result.result);
			exit_code = 1;
			goto END;
		}
		break;
	}
	default:
		fprintf(stderr, "Error: unknown data type '%s'\n", args[1]);
		exit_code = 2;
		goto END;
	}	 

END:
	prne_free_dvault_mask_result(&mask_result);

	return exit_code;
}
