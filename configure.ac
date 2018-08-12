#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([diba], [1.0.0], [no-reports-yet])
AM_INIT_AUTOMAKE()
#AM_INIT_AUTOMAKE([subdir-objects])
AC_OUTPUT(Makefile transport/Makefile keygen/Makefile tools/Makefile)

#AC_CONFIG_SRCDIR([hello.c])
#AC_CONFIG_HEADERS([config.h])
#AC_CONFIG_FILES([Makefile])
 
# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h locale.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit dup2 getcwd gethostbyname getpass inet_ntoa memset mkdir setlocale socket strchr strdup strerror strpbrk strrchr strstr strtol])

AC_OUTPUT

