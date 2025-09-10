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

bin_PROGRAMS = GatewayStats

GatewayStats_CPPFLAGS = -I$(top_srcdir)/source/gw_stats_collection \
                        -I$(top_srcdir)/source/mosqev/inc \
                        -I$(top_srcdir)/source/GatewayStats/include \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/ccsp \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

GatewayStats_SOURCES = source/gateway_stats.pb-c.c source/gw_collect_data.c source/gw_stats_encoder.c \
                       source/gw_collect_restart_counts.c source/gw_stats_publisher.c source/main.c

GatewayStats_LDADD = ../gw_stats_collection/libgw_stats.la
GatewayStats_DEPENDENCIES = $(GatewayStats_LDADD)

GatewayStats_LDFLAGS = -L${PKG_CONFIG_SYSROOT_DIR}/usr/lib \
                       -lccsp_common -lsysevent -lsecure_wrapper \
                       -lpthread -lrbus -lpcap -lprotobuf-c -lev -lmosquitto
