#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#define LINUX_PROC_UPTIME_FILE   "/proc/uptime"

/* Defaults. Values will be acquired at runtime */
static uint32_t CLOCK_TCK = 100;

/* Structure to store CPU timing data for processes */
typedef struct {
    uint32_t   pid;
    char       cmd[18];
    uint32_t   utime;       // [clock ticks]
    uint32_t   stime;       // [clock ticks]
    uint64_t   starttime;   // [clock ticks]
    uint32_t   cpu_util;    // CPU utilization [%] [0..100]
} pid_cpu_data_t;

/* Structure to store previous measurements for CPU calculation */
typedef struct {
    uint64_t        timestamp;   // [clock ticks]
    pid_cpu_data_t *pid_cpu_data;
    unsigned        count;
} prev_cpu_data_t;

/* Global variable to store previous measurements */
static prev_cpu_data_t g_prev_cpu_data = {0};

/* Find and return a pointer to the 'n'-th [0..] token in a string 'str'
 * where tokens are delimited by 'delim' characters. */
static const char* str_ntok(const char *str, char delim, unsigned n)
{
    unsigned i = 0;
    const char *s = str;

    if (i == n) return str;

    while (i < n)
    {
        s = strchr(s, delim);
        if (s == NULL) return NULL;

        while (*s == delim) s++;

        if (*s == '\0') return NULL;

        i++;
        if (i == n) return s;
    }
    return NULL;
}

/* Get system uptime [clock ticks]. */
static int proc_parse_uptime(uint64_t *uptime)
{
    const char *filename = LINUX_PROC_UPTIME_FILE;
    FILE *proc_file = NULL;
    char buf[256];
    double sys_time;

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        return -1;
    }

    if (fgets(buf, sizeof(buf), proc_file) == NULL)
    {
        fclose(proc_file);
        return -1;
    }

    if (sscanf(buf, "%lf", &sys_time) != 1)
    {
        fclose(proc_file);
        return -1;
    }

    *uptime = (uint64_t) (sys_time * CLOCK_TCK);

    fclose(proc_file);
    return 0;
}

/* For pid get its CPU timing stats from /proc/[pid]/stat */
static int proc_parse_pid_stat_cpu(uint32_t pid, pid_cpu_data_t *cpu_data)
{
    char filename[64];
    FILE *proc_file = NULL;
    char line[512];
    const char *tok;
    const char *end;
    int rc = 0;

    snprintf(filename, sizeof(filename), "/proc/%u/stat", pid);
    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        return -1; /* Process probably already exited */
    }

    if (fgets(line, sizeof(line), proc_file) == NULL)
    {
        fclose(proc_file);
        return -1;
    }

    /* Parse command name between parentheses */
    if (!(tok = strchr(line, '(')))
    {
        fclose(proc_file);
        return -1;
    }
    tok++;
    if (!(end = strchr(tok, ')')))
    {
        fclose(proc_file);
        return -1;
    }

    /* Copy the command name */
    size_t name_len = end - tok;
    if (name_len > sizeof(cpu_data->cmd) - 1)
        name_len = sizeof(cpu_data->cmd) - 1;
    strncpy(cpu_data->cmd, tok, name_len);
    cpu_data->cmd[name_len] = '\0';

    tok = end + 2; /* Skip ') ' */

    /* Skip to utime field (field 14) */
    if (!(tok = str_ntok(tok, ' ', 11)))
    {
        fclose(proc_file);
        return -1;
    }
    rc = sscanf(tok, "%u", &cpu_data->utime);
    if (rc != 1)
    {
        fclose(proc_file);
        return -1;
    }

    /* Get stime field (field 15) */
    if (!(tok = str_ntok(tok, ' ', 1)))
    {
        fclose(proc_file);
        return -1;
    }
    rc = sscanf(tok, "%u", &cpu_data->stime);
    if (rc != 1)
    {
        fclose(proc_file);
        return -1;
    }

    /* Skip to starttime field (field 22) */
    if (!(tok = str_ntok(tok, ' ', 7)))
    {
        fclose(proc_file);
        return -1;
    }
    rc = sscanf(tok, "%"PRIu64, &cpu_data->starttime);
    if (rc != 1)
    {
        fclose(proc_file);
        return -1;
    }

    cpu_data->pid = pid;
    cpu_data->cpu_util = 0; /* Will be calculated later */

    fclose(proc_file);
    return 0;
}

/* Find previous CPU data for a specific PID */
static const pid_cpu_data_t* find_prev_cpu_data(uint32_t pid)
{
    unsigned i;

    if (g_prev_cpu_data.pid_cpu_data == NULL) return NULL;

    for (i = 0; i < g_prev_cpu_data.count; i++)
    {
        const pid_cpu_data_t *iter = &g_prev_cpu_data.pid_cpu_data[i];
        if (iter->pid == pid) return iter;
    }
    return NULL;
}

/* Calculate CPU utilization for all processes
 * Formula: CPU% = (ΔCPUtime / Δsystem_time) × 100
 * Where: ΔCPUtime = change in process CPU time between measurements
 *        Δsystem_time = change in system uptime between measurements
 * Requires previous measurements stored in global state for comparison
 */

/*
    Example of CPU utilization calculation for a process:

    First Call:
    - Process 1234: utime=1000, stime=500, system_time=10000
    - No previous data → cpu_util = 0

    Second Call (5 seconds later):
    - Process 1234: utime=1200, stime=600, system_time=15000
    - CPU time change: (1200+600) - (1000+500) = 300 ticks
    - System time change: 15000 - 10000 = 5000 ticks
    - CPU utilization: (300/5000) × 100 = 6%
*/
static int calculate_cpu_utilization(pid_details_t *details, int count)
{
    uint64_t current_timestamp;
    pid_cpu_data_t *current_cpu_data;
    int i;
    long rc;

    /* Get actual values at runtime for USER_HZ */
    if ((rc = sysconf(_SC_CLK_TCK)) != -1)
    {
        CLOCK_TCK = (uint32_t)rc;
    }

    /* Get current system uptime */
    if (proc_parse_uptime(&current_timestamp) != 0)
    {
        return -1;
    }

    /* Allocate memory for current CPU data */
    current_cpu_data = malloc(count * sizeof(pid_cpu_data_t));
    if (!current_cpu_data) return -1;

    /* Collect current CPU data for all processes */
    int valid_count = 0;
    for (i = 0; i < count; i++)
    {
        if (proc_parse_pid_stat_cpu(details[i].pid, &current_cpu_data[valid_count]) == 0)
        {
            valid_count++;
        }
    }

    /* Calculate CPU utilization for each process */
    for (i = 0; i < valid_count; i++)
    {
        pid_cpu_data_t *curr = &current_cpu_data[i];
        const pid_cpu_data_t *prev = find_prev_cpu_data(curr->pid);

        if (prev != NULL &&
            prev->starttime == curr->starttime &&
            strcmp(prev->cmd, curr->cmd) == 0)
        {
            uint32_t cpu_time_curr = curr->utime + curr->stime;
            uint32_t cpu_time_prev = prev->utime + prev->stime;
            uint64_t timestamp_diff = current_timestamp - g_prev_cpu_data.timestamp;

            if (timestamp_diff > 0)
            {
                /* Calculate percentage and round */
                double util = 100.0 * (double)(cpu_time_curr - cpu_time_prev)
                             / (double)timestamp_diff;
                curr->cpu_util = (uint32_t)(util + 0.5);

                /* Update the corresponding pid_details entry */
                int j;
                for (j = 0; j < count; j++)
                {
                    if (details[j].pid == curr->pid)
                    {
                        details[j].cpu_util = curr->cpu_util;
                        break;
                    }
                }
            }
        }
    }

    /* Store current data as previous for next iteration */
    if (g_prev_cpu_data.pid_cpu_data != NULL)
    {
        free(g_prev_cpu_data.pid_cpu_data);
    }
    g_prev_cpu_data.pid_cpu_data = current_cpu_data;
    g_prev_cpu_data.count = valid_count;
    g_prev_cpu_data.timestamp = current_timestamp;

    return 0;
}

void initialize_pid_stats(pid_stats_t *stats) {
    memset(stats, 0, sizeof(pid_stats_t));
    stats->timestamp_ms = 0;
    stats->count = 0;
    stats->pid_details = NULL;
    stats->next = NULL;
}

// API to collect pid_stats_t for all running processes
int get_pid_stats(pid_stats_t *stats) {
    const char *proc_dirname = "/proc";
    DIR *proc_dir = NULL;
    struct dirent *dire;
    int num_allocated = 128;
    int num = 0;
    pid_details_t *details = malloc(num_allocated * sizeof(pid_details_t));
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

        // cpu_util: will be calculated separately
        details[num].cpu_util = 0;

        details[num].pid = pid;

        num++;
        if (num == num_allocated) {
            num_allocated *= 2;
            pid_details_t *tmp = realloc(details, num_allocated * sizeof(pid_details_t));
            if (!tmp) {
                free(details);
                closedir(proc_dir);
                return -1;
            }
            details = tmp;
        }
    }
    closedir(proc_dir);

    /* Calculate CPU utilization for all processes before setting final data */
    if (calculate_cpu_utilization(details, num) != 0) {
        /* CPU calculation failed, but we still have other stats */
        /* Continue with cpu_util set to 0 for all processes */
        log_message("Warning: CPU utilization calculation failed, cpu_util will be 0\n");
    }

    /* Now set the final data structure with CPU utilization populated */
    stats->count = num;
    stats->pid_details = details;

    return 0;
}

void collect_pid_stats(pid_stats_t *stats) {
    stats->timestamp_ms = get_timestamp_ms();
    get_pid_stats(stats);
}