#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>
#include <regex.h>


int main (const int argc, const char **args) {
	static const int AF[2] = { AF_INET, AF_INET6 };
	char buf[512];
	uint8_t addr[16];
	size_t i;
	regex_t re_trim;
	regmatch_t rm[2];

	assert(regcomp(&re_trim, "(\\S+)", REG_EXTENDED) == 0);

	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		if (regexec(&re_trim, buf, 2, rm, 0) != 0) {
			goto CYCLE;
		}
		assert(rm[1].rm_so >= 0 && rm[1].rm_eo >= 0);
		buf[rm[1].rm_eo] = 0;

		for (i = 0; i < 2; i += 1) {
			memset(addr, 0, sizeof(addr));

			if (inet_pton(AF[i], buf + rm[1].rm_so, addr) != 0) {
				printf("{ 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x }",
					addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
				break;
			}
		}

CYCLE:
		printf("\n");
	}

	regfree(&re_trim);

	return 0;
}
