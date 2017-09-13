#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([hashword], [0.1], [ian@geekprojects.com])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])


# Checks for programs.
AM_PROG_AR
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lsqlite3':
AC_CHECK_LIB([sqlite3], [sqlite3_initialize])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/time.h sys/timeb.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset mkdir munmap strchr getentropy])

case $target_os in
     *linux*)   arch=linux;;
     *darwin*)  arch=darwin;;
     *)         arch=unknown;;
esac

AM_CONDITIONAL([LINUX], [ test x"$arch" = x"linux" ])
AM_CONDITIONAL([DARWIN], [ test x"$arch" = x"darwin" ])

AC_ARG_ENABLE(
    [memdump],
    [AS_HELP_STRING([--enable-memdump], [Dump memory image after each invocation [default=no]])],
    [
        memdump_build="$enableval"
        if test "$enableval" = "yes"
        then
            AC_DEFINE(ENABLE_MEMDUMP, 1, [Define to 1 if you want to dump memory after each invocation.])
        fi
    ],
    [memdump_build=no])
AM_CONDITIONAL([BUILD_MEMDUMP], [test  x"$memdump_build" = x"yes"])

CPPFLAGS="$CPPFLAGS -std=c++11 -Wall -Werror"

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/openaes/Makefile
                 src/scrypt/Makefile
                 src/sha/Makefile
                 src/zxcvbn/Makefile])
AC_OUTPUT
