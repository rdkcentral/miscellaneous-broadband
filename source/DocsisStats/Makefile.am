# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS = -D_GNU_SOURCE
AM_CFLAGS += -Wall -Wextra

bin_PROGRAMS = DocsisStats

DocsisStats_CPPFLAGS = -I$(top_srcdir)/source/docsis_stats_collection \
                        -I$(top_srcdir)/source/DocsisStats/include \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp

DocsisStats_SOURCES = docsis_collect_data.c docsis_stats.pb-c.c docsis_stats_encoder.c docsis_stats_publisher.c main.c

DocsisStats_LDADD = ../docsis_stats_collection/libdocsis_stats.la
DocsisStats_DEPENDENCIES = $(DocsisStats_LDADD)

DocsisStats_LDFLAGS = -lccsp_common -lcm_mgnt -lsecure_wrapper \
                       -lpthread -lprotobuf-c -lev -lmosquitto