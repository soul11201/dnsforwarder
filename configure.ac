#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(dnsforwarder, 0.0, https://github.com/holmium/dnsforwarder/issues)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([dnscache.h])
AC_CONFIG_HEADERS(config.h)

AC_ARG_WITH([ccflags],
    [AS_HELP_STRING([--with-ccflags],
        [clear $CFLAGS (default=yes)]
    )],
	[   case "${withval}" in
	    yes) [CFLAGS=""] ;;
	    no)  [] ;;
	    *)   AC_MSG_ERROR(bad value ${withval} for --with-ccflags) ;;
	    esac
	],
    [CFLAGS=""]
    )

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
AC_CHECK_LIB(pthread, pthread_mutex_init, , 
	AC_MSG_ERROR(No pthread found.)
	)

AC_ARG_ENABLE([downloader],
	[AS_HELP_STRING([--enable-downloader],
	    [enable downloader (default=yes)]
	)],
	[   case "${enableval}" in
	    yes)  DOWNLOADER=yes;;
	    no)   DOWNLOADER=no;;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-downloader) ;;
	    esac
	],
	[DOWNLOADER=yes]
	)

if test "$DOWNLOADER" == "yes" 
then 

# Checks for curl.
AC_CHECK_LIB(curl, curl_global_init, ,
	AC_MSG_ERROR(No libcurl found.)
	)

# Checks for openssl.
AC_CHECK_LIB(crypto, BIO_new, ,
	AC_MSG_ERROR(No openssl found.)
	)

else
CFLAGS="${CFLAGS} -DNODOWNLOAD "
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h memory.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h math.h stdint.h curl/curl.h openssl/bio.h openssl/evp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memmove memset pow select socket sqrt strchr strerror strpbrk strrchr strstr mkdir pthread_spin_init pthread_rwlock_init])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
	    [enable DEBUG mode (default=no)]
	)],
	[   case "${enableval}" in
	    yes) [CFLAGS="${CFLAGS} -DDEBUG -g -Wall "] ;;
	    no)  [CFLAGS="${CFLAGS} -O2 "] ;;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
	    esac
	],
	[CFLAGS="${CFLAGS} -O2 "]
	)
	
AC_ARG_ENABLE([android],
	[AS_HELP_STRING([--enable-android],
	    [compile for android (default=no)]
	)],
	[   case "${enableval}" in
	    yes)  [CFLAGS="${CFLAGS} -DANDROID "];;
	    no)   [];;
	    *)   AC_MSG_ERROR(bad value ${enableval} for --enable-android) ;;
	    esac
	],
	[]
	)

AC_CONFIG_FILES([makefile])
AC_OUTPUT
