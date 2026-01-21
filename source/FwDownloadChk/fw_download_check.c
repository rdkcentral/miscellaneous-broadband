#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <syscfg/syscfg.h>
#include "ccsp_trace.h"

#include "fw_download_check.h"

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

    /* 1) Fetch URL and filename */
    if(syscfg_get(NULL,"xconf_url",url, sizeof(url)) != 0){
        CcspTraceError(("[FWCHK] Failed to get xconf_url\n"));
        return 0;
    }
    if(syscfg_get(NULL,"fw_to_upgrade",fname,sizeof(fname)) != 0){
        CcspTraceError(("[FWCHK] Failed to get fw_to_upgrade\n"));
        return 0;
    }
    CcspTraceInfo(("[FWCHK] URL: %s\n", url));

    /* 2) Fetch Content-Length using curl CLI via popen (NO libcurl needed) */
    {
        char cmd[1500];
        snprintf(cmd, sizeof(cmd),
                 "curl -sI '%s%s%s' | grep -i Content-Length | awk '{print $2}'",
                 url, (url[strlen(url)-1] == '/') ? "" : "/", fname);

        FILE *fp = popen(cmd, "r");
        if (!fp) {
            CcspTraceError(("[FWCHK] popen() failed for curl\n"));
            return 0;
        }

        if (fgets(line, sizeof(line), fp) == NULL) {
            CcspTraceError(("[FWCHK] Content-Length not found\n"));
            pclose(fp);
            return 0;
        }
        pclose(fp);

        uint64_t bytes = strtoull(line, NULL, 10);
        if (bytes == 0) {
            CcspTraceError(("[FWCHK] Invalid Content-Length\n"));
            return 0;
        }

        fw_kb = (bytes + 1023ULL) / 1024ULL;
        CcspTraceInfo(("[FWCHK] Firmware size: %" PRIu64 " kB\n", fw_kb));
    }

    /* 3) Read MemAvailable (kB) */
    {
        FILE *fp = fopen("/proc/meminfo", "r");
        if (!fp) {
            CcspTraceError(("[FWCHK] Cannot read /proc/meminfo\n"));
            return 0;
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
            CcspTraceError(("[FWCHK] MemAvailable not found\n"));
            return 0;
        }
        CcspTraceInfo(("[FWCHK] MemAvailable: %" PRIu64 " kB\n", avail_kb));
    }

    /* 4) syscfg variables EXACTLY as you wanted */
    syscfg_get(NULL, "FwDwld_AvlMem_RsrvThreshold", buf, sizeof(buf));
    rsrv_mb = (uint64_t)atoi(buf);
    rsrv_kb = rsrv_mb * 1024ULL;
    CcspTraceInfo(("[FWCHK] ReserveThreshold: %llu MB\n", (unsigned long long)rsrv_mb));

    syscfg_get(NULL, "FwDwld_ImageProcMemPercent", buf, sizeof(buf));
    imgp_pct = atoi(buf);
    if (imgp_pct < 0) imgp_pct = 0;
    CcspTraceInfo(("[FWCHK] ImageProcPercent: %d %%\n", imgp_pct));

    /* 5) Required Memory calculation */
    uint64_t img_proc_kb = (fw_kb * (uint64_t)imgp_pct + 99ULL) / 100ULL;
    uint64_t required_kb = fw_kb + rsrv_kb + img_proc_kb;

    CcspTraceInfo(("[FWCHK] Required Memory: %" PRIu64 " kB\n", required_kb));

    /* 6) Verdict */
    if (avail_kb >= required_kb) {
        CcspTraceInfo(("[FWCHK] Verdict: PROCEED\n"));
        return 1;
    }

    CcspTraceInfo(("[FWCHK] Verdict: BLOCK\n"));
    return 0;
}
