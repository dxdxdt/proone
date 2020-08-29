#pragma once
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef PRNE_DEBUG
#include <stdio.h>
#include <errno.h>
#endif

#define PRNE_LIMIT_ENUM(t,x,l) _Static_assert((x) <= (l),"enum overflow: "#t)

#define prne_op_min(a, b) ((a) < (b) ? (a) : (b))
#define prne_op_max(a, b) ((a) > (b) ? (a) : (b))
#define prne_op_spaceship(a, b) ((a) == (b) ? 0 : (a) < (b) ? -1 : 1)

#define prne_salign_next(x, align) (((x) % (align) == 0) ? (x) : ((x) / (align) + 1) * (align))
#define prne_salign_at(x, align) (((x) % (align) == 0) ? (x) : ((x) / (align)) * (align))

#ifdef PRNE_DEBUG
#define prne_dbgpf(...) fprintf(stderr, __VA_ARGS__)
#define prne_dbgperr(str) perror(str)
#define prne_assert(expr) assert(expr)
#define prne_massert(expr, ...)\
	if (!(expr)) {\
		fprintf(stderr, "*** ");\
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
		abort();\
	}
#define prne_dbgast(expr) prne_assert(expr)
#define prne_dbgmast(expr, ...) prne_massert(expr, __VA_ARGS__)
#define prne_dbgtrap(expr) prne_assert(expr)
#else
#define prne_dbgpf(...)
#define prne_dbgperr(str)
#define prne_assert(expr)\
	if (!(expr)) {\
		abort();\
	}
#define prne_massert(expr, ...) prne_assert(expr)
#define prne_dbgast(expr)
#define prne_dbgmast(expr, ...)
#define prne_dbgtrap(expr) (expr)
#endif
