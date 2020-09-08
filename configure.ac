AC_INIT([proone], [0.0.0], [])

: ${CFLAGS=""}
: ${CXXFLAGS=""}

AM_INIT_AUTOMAKE([1.0 subdir-objects])
AC_CANONICAL_HOST
AC_LANG([C])
AC_PROG_CC
AC_PROG_RANLIB

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
			   [build with debug flags, default: no]),
[case "${enableval}" in
			 yes) debug=true ;;
			 no)  debug=false ;;
			 *)	  AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([pthread not found])])
AC_CHECK_LIB([rt], [shm_open], [], [AC_MSG_ERROR([rt not found])])
AC_CHECK_LIB([z], [zlibVersion], [], [AC_MSG_ERROR([zlib not found])])
AC_CHECK_LIB([mbedcrypto], [mbedtls_cipher_setup], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([mbedtls], [mbedtls_ssl_init], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([mbedx509], [mbedtls_x509_crt_parse], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([pthsem], [pth_init], [], [AC_MSG_ERROR([pthsem not found])])

AC_CHECK_PROG(TOOL_XXD, [xxd], [yes])
AS_IF([test x"$TOOL_XXD" != x"yes"], [AC_MSG_ERROR([xxd not found])])
AC_CHECK_PROG(TOOL_SED, [sed], [yes])
AS_IF([test x"$TOOL_SED" != x"yes"], [AC_MSG_ERROR([sed not found])])


AC_DEFINE_UNQUOTED(
	[PRNE_BUILD_ENTROPY],
	[{ $(xxd -l16 -ps /dev/urandom | sed -E s/\(\\S{2}\)/0x\&,\ /g | sed -E s/,\ \$//) }])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
