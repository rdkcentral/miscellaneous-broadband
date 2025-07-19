/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include "syscfg/syscfg.h"
#include <sys/stat.h>
#include "platform_hal.h"
#include "rdk_debug.h"

#define TRUE_STR               "true"
#define TRUE                   1
#define FALSE                  0
#define SUCCESS                0
#define FAILURE                1
#define BUFLEN_4               4           //!< buffer length 4
#define BUFLEN_8               8           //!< buffer length 8
#define BUFLEN_16              16          //!< buffer length 16
#define BUFLEN_18              18          //!< buffer length 18
#define BUFLEN_24              24          //!< buffer length 24
#define BUFLEN_32              32          //!< buffer length 32
#define BUFLEN_40              40          //!< buffer length 40
#define BUFLEN_48              48          //!< buffer length 48
#define BUFLEN_64              64          //!< buffer length 64
#define BUFLEN_80              80          //!< buffer length 80
#define BUFLEN_128             128         //!< buffer length 128
#define BUFLEN_256             256         //!< buffer length 256
#define BUFLEN_264             264         //!< buffer length 264
#define BUFLEN_512             512         //!< buffer length 512
#define BUFLEN_1024            1024        //!< buffer length 1024
#define COLLECT_WAIT_INTERVAL_MS          4
#define USECS_IN_MSEC                     1000
#define MSECS_IN_SEC                      1000
#define RETURN_PID_TIMEOUT_IN_MSEC        (5 * MSECS_IN_SEC)    // 5 sec
#define RETURN_PID_INTERVAL_IN_MSEC       (0.5 * MSECS_IN_SEC)  // 0.5 sec - half a second
#define INTF_V6LL_TIMEOUT_IN_MSEC        (5 * MSECS_IN_SEC)    // 5 sec
#define INTF_V6LL_INTERVAL_IN_MSEC       (0.5 * MSECS_IN_SEC)  // 0.5 sec - half a second

#define DBG_PRINT(fmt, arg...) \
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.WANMANAGER", fmt, ##arg);

#define UNUSED_VARIABLE(x) (void)(x)

typedef enum {
    WAN_LOCAL_IFACE = 1,
    WAN_REMOTE_IFACE,
} IfaceType;

typedef struct dhcp_opt {
    char * ifname;      // VLAN interface name
    char * baseIface;   // Base interface name
    IfaceType ifType;
    bool is_release_required;
} dhcp_params;

pid_t start_dhcpv4_client (dhcp_params * params);
int stop_udhcpc (dhcp_params * params);
pid_t start_dhcpv6_client (dhcp_params * params);
int stop_dhcpv6_client (dhcp_params * params);
pid_t start_exe(char * exe, char * args);
pid_t get_process_pid (char * name, char * args, bool waitForProcEntry);
int collect_waiting_process(int pid, int timeout);
void free_opt_list_data (dhcp_opt_list * opt_list);
int signal_process (pid_t pid, int signal);
int add_dhcp_opt_to_list (dhcp_opt_list ** opt_list, int opt, char * opt_val);
void create_dir_path(const char *dirpath);
