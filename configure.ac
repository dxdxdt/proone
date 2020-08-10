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

AC_ARG_ENABLE(tests,
AS_HELP_STRING([--enable-tests],
			   [build tests, default: no]),
[case "${enableval}" in
			 yes) tests=true ;;
			 no)  tests=false ;;
			 *)	  AC_MSG_ERROR([bad value ${enableval} for --enable-tests]) ;;
esac],
[tests=false])
AM_CONDITIONAL(TESTS, test x"$tests" = x"true")
# AM_COND_IF([TESTS], [
# 	AC_CHECK_HEADERS([gtest/gtest.h],
# 	[],
# 	[AC_MSG_ERROR([gtest/gtest.h not found.])])
# ])

PKG_CHECK_MODULES_STATIC([DEP_PKGCFG], [zlib])
AC_CHECK_LIB([mbedcrypto], [mbedtls_cipher_setup], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([mbedtls], [mbedtls_ssl_init], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([mbedx509], [mbedtls_x509_crt_parse], [], [AC_MSG_ERROR([mbedtls not found])])
AC_CHECK_LIB([pthsem], [pth_init], [], [AC_MSG_ERROR([pthsem not found])])

AC_DEFINE_UNQUOTED([PRNE_BUILD_ENTROPY], ["`uuidgen -r`"])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
