# SPDX-License-Identifier: Apache-2.0

AM_CFLAGS =

lib_LTLIBRARIES = libfw_download_chk.la

libfw_download_chk_la_SOURCES = fw_download_check.c

# syscfg for syscfg_get, ccsp_common for logging headers
libfw_download_chk_la_LDFLAGS = -lsyscfg -lccsp_common -ltelemetry_msgsender
