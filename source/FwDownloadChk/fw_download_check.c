/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

#include <syscfg/syscfg.h>
#include <telemetry_busmessage_sender.h>
#include "fw_download_check.h"

#define XCONF_LOG_PATH "/rdklogs/logs/xconf.txt.0"
#define XCONF_LOG_INFO(...)  xconf_log_write("INFO", __VA_ARGS__)
#define XCONF_LOG_ERROR(...) xconf_log_write("ERROR", __VA_ARGS__)


/**
 * @brief Append a timestamped log line to the XCONF log file.
 *
 * Writes logs to XCONF_LOG_PATH in append mode. If the log file cannot be opened,
 * logs are written to stderr instead.
 *
 * Log format:
 *     YYYY-MM-DD HH:MM:SS [LEVEL] <formatted message>
 *
 * @param level Log level string (e.g., "INFO", "ERROR").
 * @param fmt   printf-style format string.
 * @param ...   Arguments corresponding to @p fmt.
 */
static void xconf_log_write(const char *level, const char *fmt, ...)
{
    FILE *fp = fopen(XCONF_LOG_PATH, "a");
    if (!fp) {
        fp = stderr;
    }

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(fp, "%s [%s] ", ts, level);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);

    if (fp != stderr) {
        fflush(fp);
        fclose(fp);
    } else {
        fflush(stderr);
    }
}

/**
 * @brief Check whether the device has enough available RAM to proceed with firmware download.
 *
 * This function determines if firmware download should be allowed based on:
 *   1) The firmware image size retrieved from the HTTP "Content-Length" header of the
 *      URL composed using syscfg keys `xconf_url` and `fw_to_upgrade`.
 *   2) The currently available memory read from `/proc/meminfo` (MemAvailable in kB).
 *   3) A reserved memory threshold (in MB) from syscfg key `FwDwld_AvlMem_RsrvThreshold`.
 *   4) Additional image processing overhead computed as a percentage of firmware size
 *      from syscfg key `FwDwld_ImageProcMemPercent`.
 *
 * The required memory is computed as:
 *     required_kB = firmware_kB + (reserve_threshold_MB * 1024) + (firmware_kB * image_proc_percent / 100)
 *
 * If MemAvailable is greater than or equal to required_kB, the function returns success
 * and the caller may proceed with the firmware download.
 *
 * @note Side effects:
 *   - Appends INFO/ERROR logs to XCONF_LOG_PATH (falls back to stderr on failure).
 *   - Sends a telemetry event "XCONF_Dwld_Ignored_Not_EnoughMem" when memory is insufficient.
 *
 * @return FW_DWNLD_MEMCHK_SUCCEED (1)
 *         Enough available memory; firmware download can proceed.
 *
 * @return FW_DWNLD_MEMCHK_NOT_ENOUGH_MEM (0)
 *         Memory is insufficient; firmware download should be blocked.
 *
 * @return FW_DWNLD_MEMCHK_FAILED (-1)
 *         An error occurred (e.g., syscfg read failure, curl/popen failure,
 *         missing/invalid Content-Length, or inability to parse MemAvailable).
 */
int can_proceed_fw_download(void)
{
    char url[1024] = {0};
    char fname[256] = {0};
    char buf[64] = {0};
    char line[256] = {0};

    uint64_t fw_kb = 0;
    uint64_t avail_kb = 0;
    uint64_t rsrv_mb = 0, rsrv_kb = 0;
    int imgp_pct = 0;

    if(syscfg_get(NULL,"xconf_url",url, sizeof(url)) != 0){
        XCONF_LOG_ERROR("[FWCHK] Failed to get xconf_url\n");
        return FW_DWNLD_MEMCHK_FAILED;
    }
    XCONF_LOG_INFO("[FWCHK] xconf_url: %s\n", url);

    if(syscfg_get(NULL,"fw_to_upgrade",fname,sizeof(fname)) != 0){
        XCONF_LOG_ERROR("[FWCHK] Failed to get fw_to_upgrade\n");
        return FW_DWNLD_MEMCHK_FAILED;
    }
    XCONF_LOG_INFO("[FWCHK] fw_to_upgrade: %s\n", fname);

    {
        char cmd[1500];
        snprintf(cmd, sizeof(cmd),
                 "curl -sI '%s%s%s' | grep -i Content-Length | awk '{print $2}'",
                 url, (url[strlen(url)-1] == '/') ? "" : "/", fname);

        FILE *fp = popen(cmd, "r");
        if (!fp) {
            XCONF_LOG_ERROR("[FWCHK] popen() failed for curl\n");
            return FW_DWNLD_MEMCHK_FAILED;
        }

        if (fgets(line, sizeof(line), fp) == NULL) {
            XCONF_LOG_ERROR("[FWCHK] Content-Length not found\n");
            pclose(fp);
            return FW_DWNLD_MEMCHK_FAILED;
        }
        pclose(fp);

        uint64_t bytes = strtoull(line, NULL, 10);
        if (bytes == 0) {
            XCONF_LOG_ERROR("[FWCHK] Invalid Content-Length\n");
            return FW_DWNLD_MEMCHK_FAILED;
        }

        fw_kb = (bytes + 1023ULL) / 1024ULL;
        XCONF_LOG_INFO("[FWCHK] Firmware size: %" PRIu64 " kB\n", fw_kb);
    }

    {
        FILE *fp = fopen("/proc/meminfo", "r");
        if (!fp) {
            XCONF_LOG_ERROR("[FWCHK] Cannot read /proc/meminfo\n");
            return FW_DWNLD_MEMCHK_FAILED;
        }

        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemAvailable:", 13) == 0) {
                char *p = line + 13;
                while (*p && !isdigit((unsigned char)*p)) ++p;
                avail_kb = strtoull(p, NULL, 10);
                break;
            }
        }
        fclose(fp);

        if (avail_kb == 0) {
            XCONF_LOG_ERROR("[FWCHK] MemAvailable not found\n");
            return FW_DWNLD_MEMCHK_FAILED;
        }
        XCONF_LOG_INFO("[FWCHK] MemAvailable: %" PRIu64 " kB\n", avail_kb);
    }

    if(syscfg_get(NULL, "FwDwld_AvlMem_RsrvThreshold", buf, sizeof(buf)) != 0){
        XCONF_LOG_ERROR("[FWCHK] Failed to get FwDwld_AvlMem_RsrvThreshold\n");
        return FW_DWNLD_MEMCHK_FAILED;
    }
    rsrv_mb = (uint64_t)atoi(buf);
    rsrv_kb = rsrv_mb * 1024ULL;
    XCONF_LOG_INFO("[FWCHK] ReserveThreshold: %llu MB\n", (unsigned long long)rsrv_mb);

    if(syscfg_get(NULL, "FwDwld_ImageProcMemPercent", buf, sizeof(buf)) != 0){
        XCONF_LOG_ERROR("[FWCHK] Failed to get FwDwld_ImageProcMemPercent\n");
        return FW_DWNLD_MEMCHK_FAILED;
    }
    imgp_pct = atoi(buf);
    if (imgp_pct < 0) imgp_pct = 0;
    XCONF_LOG_INFO("[FWCHK] ImageProcPercent: %d %%\n", imgp_pct);

    uint64_t img_proc_kb = (fw_kb * (uint64_t)imgp_pct + 99ULL) / 100ULL;
    uint64_t required_kb = fw_kb + rsrv_kb + img_proc_kb;

    XCONF_LOG_INFO("[FWCHK] Required Memory: %" PRIu64 " kB\n", required_kb);

    if (avail_kb >= required_kb) {
        XCONF_LOG_INFO("[FWCHK] Verdict: PROCEED\n");
        return FW_DWNLD_MEMCHK_SUCCEED;
    }

    XCONF_LOG_INFO("[FWCHK] Verdict: BLOCK\n");
    t2_event_d("XCONF_Dwld_Ignored_Not_EnoughMem", 1);
    return FW_DWNLD_MEMCHK_NOT_ENOUGH_MEM;
}
