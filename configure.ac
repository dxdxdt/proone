AC_INIT([proone], [0.0.0], [])

: ${CFLAGS=""}
: ${CXXFLAGS=""}
: ${PRNE_VERBOSE=2}
: ${BIN_ALIGNMENT=8}

AC_CONFIG_HEADERS([src/config_gen.h])
AM_INIT_AUTOMAKE([1.0 subdir-objects])
AC_CANONICAL_HOST
AC_LANG([C])
AC_PROG_CC
AC_PROG_RANLIB

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
			   [build with debug flags. Default: no]),
[case "${enableval}" in
			 yes) debug=1 ;;
			 no)  debug=0 ;;
			 *)	  AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=0])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"1")
AH_TEMPLATE([PRNE_DEBUG], [non-zero for debug build])
AC_DEFINE_UNQUOTED([PRNE_DEBUG], [$debug])

AC_ARG_ENABLE(static,
AS_HELP_STRING([--enable-static],
			   [build statically linked executables. Default: no]),
[case "${enableval}" in
			 yes) static=true ;;
			 no)  static=false ;;
			 *)	  AC_MSG_ERROR([bad value ${enableval} for --enable-static]) ;;
esac],
[static=false])
AM_CONDITIONAL(STATIC_RT, test x"$static" = x"true")

AC_ARG_ENABLE(mttools,
AS_HELP_STRING([--enable-mttools],
			   [build maintenance tools. Default: no]),
[case "${enableval}" in
			 yes) mttools=true ;;
			 no)  mttools=false ;;
			 *)	  AC_MSG_ERROR([bad value ${enableval} for --enable-mttools]) ;;
esac],
[mttools=false])
AM_CONDITIONAL(BUILD_MTTOOLS, test x"$mttools" = x"true")

AC_ARG_ENABLE(minmem,
	AS_HELP_STRING(
		[--enable-minmem],
		[use only minimum amount of memory required to function. Default: no]),
	[case "${enableval}" in
		yes) minmem=1 ;;
		no)  minmem=0 ;;
		*)   AC_MSG_ERROR([bad value ${enableval} for --enable-minmem]) ;;
	esac],
	[minmem=0])
AH_TEMPLATE(
	[PRNE_USE_MIN_MEM],
	[use only minimum amount of memory required to function])
AC_DEFINE_UNQUOTED([PRNE_USE_MIN_MEM], [$minmem])

AH_TEMPLATE([PRNE_VERBOSE], [Hardcoded compile-time verbose level])
AC_ARG_VAR(
	[PRNE_VERBOSE],
	[Debug verbose level. Must be used with --enable-debug. Defaults to 2])
AC_DEFINE_UNQUOTED([PRNE_VERBOSE], [$PRNE_VERBOSE])
AH_TEMPLATE([PRNE_BIN_ALIGNMENT], [Binary alignment size])
AC_DEFINE_UNQUOTED([PRNE_BIN_ALIGNMENT], [$BIN_ALIGNMENT])
AC_SUBST([BIN_ALIGNMENT])
AH_TEMPLATE([PRNE_BUILD_ENTROPY], [Generated build entropy on configuration])
AC_DEFINE_UNQUOTED(
	[PRNE_BUILD_ENTROPY],
	[{ $(xxd -l16 -ps /dev/urandom |\
		sed -E s/\(\\S{2}\)/0x\&,\ /g | sed -E s/,\ \$//) }])

AC_CHECK_LIB(
	[pthread],
	[pthread_create],
	[],
	[AC_MSG_ERROR([pthread not found])])
AC_CHECK_LIB(
	[rt],
	[shm_open],
	[],
	[AC_MSG_ERROR([rt not found])])
AC_CHECK_LIB(
	[z],
	[zlibVersion],
	[],
	[AC_MSG_ERROR([zlib not found])])
AC_CHECK_LIB(
	[mbedcrypto],
	[mbedtls_cipher_setup],
	[],
	[AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB(
	[mbedx509],
	[mbedtls_x509_crt_parse],
	[],
	[AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB(
	[mbedtls],
	[mbedtls_ssl_init],
	[],
	[AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB(
	[ssh2],
	[libssh2_init],
	[],
	[AC_MSG_ERROR([ssh2 not found])])
AC_CHECK_LIB(
	[pthsem],
	[pth_init],
	[],
	[AC_MSG_ERROR([pthsem not found])])
AS_IF([test x"$mttools" = x"true"], [
	AC_CHECK_LIB([yaml],
		[yaml_parser_initialize],
		[],
		[AC_MSG_ERROR([yaml not found])])
	AC_CHECK_LIB([mariadb],
		[mysql_init],
		[],
		[AC_MSG_ERROR([mariadb not found])])

	AC_MSG_CHECKING([mbedtls threading support])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
		#include <mbedtls/config.h>
		#if !defined(MBEDTLS_THREADING_C)
		#error "mbedtls must be compiled with threading support"
		#endif
	]])],
	[ AC_MSG_RESULT([yes]) ],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([mbedtls not compiled with threading support])])
])

AC_CHECK_PROG(TOOL_XXD, [xxd], [yes])
AS_IF([test x"$TOOL_XXD" != x"yes"], [AC_MSG_ERROR([xxd not found])])
AC_CHECK_PROG(TOOL_SED, [sed], [yes])
AS_IF([test x"$TOOL_SED" != x"yes"], [AC_MSG_ERROR([sed not found])])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
