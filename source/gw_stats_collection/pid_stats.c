#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

void initialize_pid_stats(PidStats *stats) {
    memset(stats, 0, sizeof(PidStats));
    stats->timestamp_ms = 0;
    stats->count = 0;
    stats->pid_details = NULL;
    stats->next = NULL;
}

// API to collect PidStats for all running processes
int get_pid_stats(PidStats *stats) {
    const char *proc_dirname = "/proc";
    DIR *proc_dir = NULL;
    struct dirent *dire;
    int num_allocated = 128;
    int num = 0;
    pidDetails *details = malloc(num_allocated * sizeof(pidDetails));
    if (!details) return -1;

    proc_dir = opendir(proc_dirname);
    if (!proc_dir) {
        free(details);
        return -1;
    }

    while ((dire = readdir(proc_dir)) != NULL) {
        char c = dire->d_name[0];
        if (!(c >= '0' && c <= '9')) continue;
        uint32_t pid = (uint32_t)atoi(dire->d_name);

        char status_path[64], smaps_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%u/status", pid);
        snprintf(smaps_path, sizeof(smaps_path), "/proc/%u/smaps", pid);

        FILE *status_file = fopen(status_path, "r");
        if (!status_file) continue;
        char line[512];
        details[num].pName[0] = '\0';
        details[num].rss = 0;
        while (fgets(line, sizeof(line), status_file)) {
            if (strncmp(line, "Name:", 5) == 0) {
                char *name = line + 5;
                while (*name == ' ' || *name == '\t') name++;
                size_t name_len = strcspn(name, "\n");
                if (name_len > sizeof(details[num].pName) - 1)
                    name_len = sizeof(details[num].pName) - 1;
                strncpy(details[num].pName, name, name_len);
                details[num].pName[name_len] = '\0';
            } else if (strncmp(line, "VmRSS:", 6) == 0) {
                char *rss_str = line + 6;
                while (*rss_str == ' ' || *rss_str == '\t') rss_str++;
                unsigned int rss = 0;
                sscanf(rss_str, "%u", &rss);
                details[num].rss = rss; // VmRSS is already in kB
            }
        }
        fclose(status_file);

        // Get PSS from smaps
        FILE *smaps_file = fopen(smaps_path, "r");
        uint32_t pss_total = 0;
        if (smaps_file) {
            char buf[256];
            while (fgets(buf, sizeof(buf), smaps_file)) {
                if (strncmp(buf, "Pss:", 4) == 0) {
                    unsigned int pss = 0;
                    sscanf(buf, "Pss: %u", &pss);
                    pss_total += pss;
                }
            }
            fclose(smaps_file);
        }
        details[num].pss = pss_total;

        // mem_util: use pss if available, else rss
        details[num].mem_util = (pss_total > 0) ? pss_total : details[num].rss;

        // cpu_util: not available here, set to 0
        details[num].cpu_util = 0;

        details[num].pid = pid;

        num++;
        if (num == num_allocated) {
            num_allocated *= 2;
            pidDetails *tmp = realloc(details, num_allocated * sizeof(pidDetails));
            if (!tmp) {
                free(details);
                closedir(proc_dir);
                return -1;
            }
            details = tmp;
        }
    }
    closedir(proc_dir);

    stats->count = num;
    stats->pid_details = details;

    return 0;
}

void collect_pid_stats(PidStats *stats) {
    stats->timestamp_ms = get_timestamp_ms();
    get_pid_stats(stats);
}