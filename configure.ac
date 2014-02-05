#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(dnsforwarder, 0.0, https://github.com/holmium/dnsforwarder/issues)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([dnscache.h])
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# Checks for math libraries.
AC_CHECK_LIB(m, log, , 
	AC_MSG_ERROR(No libmath found.)
	)
AC_CHECK_LIB(m, sqrt, , 
	AC_MSG_ERROR(No libmath found.)
	)
	


# Checks for pthread.
AC_CHECK_LIB(pthread, pthread_create, , 
	AC_MSG_ERROR(No pthread found.)
	)
AC_CHECK_LIB(pthread, pthread_exit, , 
	AC_MSG_ERROR(No pthread found.)
	)
AC_CHECK_LIB(pthread, pthread_detach, , 
	AC_MSG_ERROR(No pthread found.)
	)
AC_CHECK_LIB(pthread, pthread_mutex_init, , 
	AC_MSG_ERROR(No pthread found.)
	)
AC_CHECK_LIB(pthread, pthread_spin_init, , 
	AC_MSG_ERROR(No pthread found.)
	)
AC_CHECK_LIB(pthread, pthread_rwlock_init, , 
	AC_MSG_ERROR(No pthread found.)
	)

# Checks for curl.
AC_CHECK_LIB(curl, curl_global_init, ,
	AC_MSG_ERROR(No libcurl found.)
	)
AC_CHECK_LIB(curl, curl_easy_init, ,
	AC_MSG_ERROR(No libcurl found.)
	)
AC_CHECK_LIB(curl, curl_easy_setopt, ,
	AC_MSG_ERROR(No libcurl found.)
	)
AC_CHECK_LIB(curl, curl_easy_perform, ,
	AC_MSG_ERROR(No libcurl found.)
	)
AC_CHECK_LIB(curl, curl_easy_cleanup, ,
	AC_MSG_ERROR(No libcurl found.)
	)

# Checks for openssl.
AC_CHECK_LIB(crypto, BIO_new, ,
	AC_MSG_ERROR(No openssl found.)
	)
AC_CHECK_LIB(crypto, BIO_new_mem_buf, ,
	AC_MSG_ERROR(No openssl found.)
	)
AC_CHECK_LIB(crypto, BIO_free_all, ,
	AC_MSG_ERROR(No openssl found.)
	)
AC_CHECK_LIB(crypto, BIO_push, ,
	AC_MSG_ERROR(No openssl found.)
	)
AC_CHECK_LIB(crypto, BIO_read, ,
	AC_MSG_ERROR(No openssl found.)
	)


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h memory.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h math.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memmove memset pow select socket sqrt strchr strerror strpbrk strrchr strstr mkdir])

AC_ARG_WITH([ccflags],
    [AS_HELP_STRING([--with-ccflags],
        [clear $CFLAGS (default=yes)]
    )],
	[   case "${withval}" in
	    yes) [[CFLAGS=""]] ;;
	    no)  [] ;;
	    *)   AC_MSG_ERROR(bad value ${withval} for --with-ccflags) ;;
	    esac
	],
    [CFLAGS=""]
    )

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
	    [enable DEBUG mode (default=no)]
	)],
	[   case "${enableval}" in
	    yes) [CFLAGS="${CFLAGS} -DDEBUG -g -Wall"] ;;
	    no)  [CFLAGS="${CFLAGS} -O2"] ;;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-server) ;;
	    esac
	],
	[CFLAGS="${CFLAGS} -O2"]
	)

AC_CONFIG_FILES([makefile])
AC_OUTPUT
