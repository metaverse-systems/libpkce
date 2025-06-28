AC_PREREQ([2.72])
AC_INIT([libpkce], [0.1], [tim@metaverse.systems])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX
AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT

PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.0])
PKG_CHECK_MODULES([HTTPLIB], [cpp-httplib])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_CONFIG_FILES([libpkce.pc])
AC_OUTPUT
