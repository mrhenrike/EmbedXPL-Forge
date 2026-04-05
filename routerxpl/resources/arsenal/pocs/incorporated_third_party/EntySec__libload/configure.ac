AC_INIT([libload], [1.0.0], [https://github.com/EntySec/libload])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])

AC_PROG_CC
AM_PROG_AR
AM_PROG_AS
LT_INIT

AC_CANONICAL_HOST

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug logging to stderr])],
    [enable_debug=$enableval],
    [enable_debug=no])

AS_IF([test "x$enable_debug" = "xyes"],
    [AC_DEFINE([LIBLOAD_DEBUG], [1], [Enable debug logging])])

# Platform detection
case $host_os in
    darwin*)
        platform=macos
        ;;
    linux*)
        platform=linux
        ;;
    *)
        AC_MSG_ERROR([Unsupported platform: $host_os])
        ;;
esac

AM_CONDITIONAL([PLATFORM_MACOS], [test "x$platform" = "xmacos"])
AM_CONDITIONAL([PLATFORM_LINUX], [test "x$platform" = "xlinux"])

# Check for dlsym on Linux
AS_IF([test "x$platform" = "xlinux"],
    [AC_SEARCH_LIBS([dlsym], [dl], [], [AC_MSG_ERROR([dlsym not found])])])

AM_CFLAGS="-Wall -Wextra -Werror -O2"
AC_SUBST([AM_CFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
