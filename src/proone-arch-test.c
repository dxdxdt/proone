#include <stdio.h>
#include <math.h>

#include "protocol.h"
#include "config.h"


int main (void) {
	int exit_code;
	volatile double mat[9] = {
		1, 0, 0,
		0, 1, 0,
		0, 0, 1
	};
	volatile double arr[3] = {
		1, 2, 3
	};
	volatile double d;

	arr[0] = arr[0] * mat[0] + arr[1] * mat[1] + arr[2] * mat[2];
	arr[1] = arr[0] * mat[3] + arr[1] * mat[4] + arr[2] * mat[5];
	arr[2] = arr[0] * mat[6] + arr[1] * mat[7] + arr[2] * mat[8];
	d = arr[0] + arr[1] + arr[2];

	exit_code = isnan(d) ? 1 : 0;

	printf("%s\n", prne_arch_tostr(prne_host_arch));

	return exit_code;
}
