##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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

bin_PROGRAMS = AnomalyEngine

AnomalyEngine_SOURCES = \
    core/ae_rule_engine.c     \
    core/ae_module_registry.c \
    core/ae_engine.c          \
    core/ae_log_collector.c   \
    core/ae_action_engine.c   \
    core/ae_report.c          \
    modules/ae_cpu_module.c   \
    modules/ae_mem_module.c   \
    core/ae_main.c

AnomalyEngine_CFLAGS = \
    -I$(top_srcdir)/source/AnomalyEngine        \
    -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

AnomalyEngine_LDFLAGS = \
    -lrbus      \
    -lpthread

# Install engine config to /etc
sysconf_DATA = config/anomaly_engine_config.json
