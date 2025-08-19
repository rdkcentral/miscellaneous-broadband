AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -fPIC
AM_CFLAGS += -D_GNU_SOURCE
AM_CFLAGS += -DSC_POSIX_SEM
AM_LDFLAGS = -lpthread
AM_LDFLAGS += -lz
AM_LDFLAGS += -lsecure_wrapper

AM_CPPFLAGS = -Wall -Werror -fPIC
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libgw_stats.la

libgw_stats_la_LDFLAGS = -lsyscfg -lz -lsecure_wrapper -lpcap

libgw_stats_la_CPPFLAGS = -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp \
						  -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
						  -I$(top_srcdir)/ \
						  $(CPPFLAGS)

libgw_stats_la_SOURCES =  system_stats.c wan_stats.c lan_stats.c tcp_stats.c ipv6_monitoring.c helper.c
