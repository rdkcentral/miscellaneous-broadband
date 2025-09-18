AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -fPIC
AM_CFLAGS += -D_GNU_SOURCE
AM_CFLAGS += -DSC_POSIX_SEM
AM_CFLAGS += -I$(top_srcdir)/hal/include

AM_CPPFLAGS = -Wall -Werror -fPIC -shared
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libdocsis_stats.la

libdocsis_stats_la_LDFLAGS = -lsyscfg -lz -lsecure_wrapper -lcm_mgnt

libdocsis_stats_la_CPPFLAGS = -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp \
						      -I$(top_srcdir)/ \
						      $(CPPFLAGS)

libdocsis_stats_la_SOURCES =  docsis_stats.c
