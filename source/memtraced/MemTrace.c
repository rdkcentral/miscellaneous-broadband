#include "MemTrace.h"
#include "MemTrace_log.h"
#include "MemTrace_rbus.h"

ProcessThresholdConfig threshold_configs[MAX_PROC_THRESHOLD_CONFIG_COUNT];
unsigned int threshold_config_count = 0;

// Global runtime config values
unsigned int interval = 0;
unsigned long rss_threshold = 0;
unsigned int initial_snapshot_uptime = 0;

int read_config_values(void) {
    char interval_str[16] = {0};
    char rss_threshold_str[16] = {0};
    char initial_snapshot_uptime_str[16] = {0};

    if (syscfg_get(NULL, "MemTrace_Interval", interval_str, sizeof(interval_str)) != 0 ||
        syscfg_get(NULL, "MemTrace_RSSThreshold", rss_threshold_str, sizeof(rss_threshold_str)) != 0 ||
        syscfg_get(NULL, "MemTrace_InitialSnapshotUptime", initial_snapshot_uptime_str, sizeof(initial_snapshot_uptime_str)) != 0) {
        return -1; // Config not found
    }

    interval = (unsigned int)strtoul(interval_str, NULL, 10);
    rss_threshold = strtoul(rss_threshold_str, NULL, 10);
    initial_snapshot_uptime = (unsigned int)strtoul(initial_snapshot_uptime_str, NULL, 10);
    return 0;
}

// Load per-process thresholds from syscfg
int load_process_thresholds() {
    char count_str[16] = {0};
    int configured_count = 0;
    threshold_config_count = 0;

    if (syscfg_get(NULL, "MemTrace_RSSThreshold_count", count_str, sizeof(count_str)) != 0) {
        unsigned long fallback_threshold_kb = (rss_threshold > 0) ? rss_threshold : DEFAULT_THRESHOLD_KB;
        MemTraceInfo((
            "Per-process threshold syscfg not found (MemTrace_RSSThreshold_count). Using fallback %lu KB for all processes.\n",
            fallback_threshold_kb));
        return -1;
    }

    configured_count = (int)strtol(count_str, NULL, 10);
    if (configured_count <= 0) {
        unsigned long fallback_threshold_kb = (rss_threshold > 0) ? rss_threshold : DEFAULT_THRESHOLD_KB;
        MemTraceInfo((
            "Per-process threshold count is %d. Using fallback %lu KB for all processes.\n",
            configured_count, fallback_threshold_kb));
        return -1;
    }

    for (int i = 1; i <= configured_count; i++) {
        char key_enabled[64] = {0};
        char key_procname[64] = {0};
        char key_kb[64] = {0};
        char enabled_str[16] = {0};
        char proc_name[NAME_LEN] = {0};
        char threshold_kb_str[32] = {0};
        long threshold_kb = 0;

        if (threshold_config_count >= MAX_PROC_THRESHOLD_CONFIG_COUNT) {
            MemTraceError((
                "Too many threshold configs (max %d). Ignoring newer threshold configs\n",
                MAX_PROC_THRESHOLD_CONFIG_COUNT));
            break;
        }

        snprintf(key_enabled, sizeof(key_enabled), "MemTrace_RSSThreshold_enabled_%d", i);
        snprintf(key_procname, sizeof(key_procname), "MemTrace_RSSThreshold_procname_%d", i);
        snprintf(key_kb, sizeof(key_kb), "MemTrace_RSSThreshold_kB_%d", i);

        if (syscfg_get(NULL, key_enabled, enabled_str, sizeof(enabled_str)) != 0 ||
            syscfg_get(NULL, key_procname, proc_name, sizeof(proc_name)) != 0 ||
            syscfg_get(NULL, key_kb, threshold_kb_str, sizeof(threshold_kb_str)) != 0) {
            MemTraceError((
                "Skipping invalid per-process threshold entry %d (missing one or more syscfg keys)\n",
                i));
            continue;
        }

        threshold_kb = strtol(threshold_kb_str, NULL, 10);
        if (threshold_kb < 0) {
            MemTraceError((
                "Skipping invalid per-process threshold entry %d (negative threshold: %ld)\n",
                i, threshold_kb));
            continue;
        }

        strncpy(threshold_configs[threshold_config_count].process_name, proc_name, NAME_LEN - 1);
        threshold_configs[threshold_config_count].process_name[NAME_LEN - 1] = '\0';
        threshold_configs[threshold_config_count].threshold_kb = (unsigned long)threshold_kb;
        threshold_configs[threshold_config_count].enabled =
            (strcmp(enabled_str, "1") == 0 ||
             strcmp(enabled_str, "yes") == 0 ||
             strcmp(enabled_str, "true") == 0);

        MemTraceInfo((
            "Loaded threshold config from syscfg: %s -> %lu KB [%s]\n",
            threshold_configs[threshold_config_count].process_name,
            threshold_configs[threshold_config_count].threshold_kb,
            threshold_configs[threshold_config_count].enabled ? "enabled" : "disabled"));

        threshold_config_count++;
    }

    MemTraceInfo((
        "Loaded %u per-process threshold configs from syscfg\n",
        threshold_config_count));
    return 0;
}

// Get threshold for a specific process
unsigned long get_threshold_for_process(const char *process_name) {
    // First, check for exact match
    for (unsigned int i = 0; i < threshold_config_count; i++) {
        if (strcmp(threshold_configs[i].process_name, process_name) == 0) {
            if (!threshold_configs[i].enabled) {
                return 0;  // Monitoring disabled
            }
            return threshold_configs[i].threshold_kb;
        }
    }

    // Check for wildcard (*) default
    for (unsigned int i = 0; i < threshold_config_count; i++) {
        if (strcmp(threshold_configs[i].process_name, "*") == 0) {
            return threshold_configs[i].threshold_kb;
        }
    }

    // Fallback to global RSS threshold; use hardcoded default only when config is zero.
    if (rss_threshold > 0) {
        return rss_threshold;
    }
    return DEFAULT_THRESHOLD_KB;
}

ProcessInfo processes[MAX_PROCESS_COUNT];
int process_count = 0;

// *** Shared Memory globals ***
long initial_shmem = 0;
long prev_shmem = 0;
long curr_shmem = 0;
Bucket shmem_bucket = GREEN;

static void enable_mtrace(const char *proc_name, pid_t pid) {
    // Create marker file to indicate mtrace should be enabled for this PID.
    char marker_file[256];
    snprintf(marker_file, sizeof(marker_file), "/tmp/mtrace_%d", (int)pid);
    FILE *marker = fopen(marker_file, "w");
    if (marker) {
        fclose(marker);
    } else {
        MemTraceError((
            "Failed to create marker file %s for %s(%d): errno=%d\n",
            marker_file, proc_name, pid, errno));
    }
}

static void disable_mtrace(const char *proc_name, pid_t pid) {
    // Remove marker file when process recovers to GREEN.
    char marker_file[256];
    snprintf(marker_file, sizeof(marker_file), "/tmp/mtrace_%d", (int)pid);
    if (unlink(marker_file) != 0 && errno != ENOENT) {
        MemTraceError((
            "Failed to remove marker file %s for %s(%d): errno=%d\n",
            marker_file, proc_name, pid, errno));
    }
}

// Log bucket transitions to a persistent log file for debugging
void log_bucket_markers(ProcessInfo *processes, int process_count) {
    // Log YELLOW processes with telemetry marker format
    for (int i = 0; i < process_count; ++i) {
        if (processes[i].curr_bucket == YELLOW && processes[i].active) {
            MemTraceInfo(("mem_incr_dtctedbkt_yellow_split:\"%s:%d:%ld\" ",
                    processes[i].name, processes[i].pid, processes[i].curr_rss));
        }
    }

    // Log RED processes with telemetry marker format
    for (int i = 0; i < process_count; ++i) {
        if (processes[i].curr_bucket == RED && processes[i].active) {
            MemTraceInfo(("mem_incr_dtctedbkt_red_split:\"%s:%d:%ld\" ",
                    processes[i].name, processes[i].pid, processes[i].curr_rss));
        }
    }
}

long get_uptime_seconds() {
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return -1;
    double uptime = 0.0;
    fscanf(f, "%lf", &uptime);
    fclose(f);
    return (long)uptime;
}

// Shared memory read from /proc/meminfo
long read_shared_memory_kb() {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        MemTraceError(("Failed to open /proc/meminfo to read shared memory.\n"));
        return -1;
    }
    char line[256];
    long shmem_kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Shmem:", 6) == 0) {
            sscanf(line + 6, "%ld", &shmem_kb);
            break;
        }
    }
    fclose(f);
    return shmem_kb;
}

void take_initial_snapshot() {
    process_count = 0;
    scan_processes();
    for (int i = 0; i < process_count; ++i) {
        processes[i].initial_rss = processes[i].curr_rss;
        processes[i].prev_rss = processes[i].curr_rss;
        processes[i].prev_bucket = GREEN;
        processes[i].curr_bucket = GREEN;
        processes[i].active = 1;
    }
    // Initial shared memory baseline
    initial_shmem = read_shared_memory_kb();
    prev_shmem = initial_shmem;
    shmem_bucket = GREEN;

    MemTraceInfo((
            "Initial snapshot taken (shmem=%ld KB).\n",
            initial_shmem));
}

long get_rss(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
    FILE *f = fopen(path, "r");

    char line[256];
    long rss = -1;

    // Prefer smaps_rollup RSS for more accurate accounting.
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Rss:", 4) == 0) {
                sscanf(line + 4, "%ld", &rss);
                break;
            }
        }
        fclose(f);
        return rss;
    }

    // Fallback to /proc/<pid>/status when smaps_rollup is unavailable.
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

int get_process_name(pid_t pid, char *name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (fgets(name, NAME_LEN, f)) {
        size_t len = strlen(name);
        if (len > 0 && name[len-1] == '\n') name[len-1] = '\0';
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

const char* ignore_names[] = {
    "sleep", "dropbear", "sh", "bash"
};

const int ignore_count = sizeof(ignore_names) / sizeof(ignore_names[0]);

int is_ignored_process(const char* name) {
    for (int i = 0; i < ignore_count; ++i) {
        if (strcmp(name, ignore_names[i]) == 0)
            return 1;
    }
    return 0;
}

void scan_processes() {
    DIR *dir = opendir("/proc");
    if (!dir) {
        MemTraceError(("Failed to open /proc directory.\n"));
        return;
    }
    struct dirent *entry;
    int idx = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        pid_t pid = atoi(entry->d_name);
        char name[NAME_LEN] = "";
        if (!get_process_name(pid, name)) continue;
        if (is_ignored_process(name)) continue;
        long rss = get_rss(pid);
        if (rss < 0) continue;

        int found = 0;
        for (int i = 0; i < process_count; ++i) {
            if (processes[i].pid == pid && strcmp(processes[i].name, name) == 0) {
                processes[i].prev_rss = processes[i].curr_rss;
                processes[i].curr_rss = rss;
                processes[i].active = 1;
                found = 1;
                break;
            }
        }
        if (!found) {
            for (int i = 0; i < process_count; ++i) {
                if (strcmp(processes[i].name, name) == 0 && processes[i].active == 0) {
                    processes[i].pid = pid;
                    processes[i].initial_rss = rss;
                    processes[i].prev_rss = rss;
                    processes[i].curr_rss = rss;
                    processes[i].peak_rss = rss;
                    processes[i].yellow_entry_rss = 0;
                    processes[i].stable_count = 0;
                    processes[i].prev_bucket = GREEN;
                    processes[i].curr_bucket = GREEN;
                    processes[i].active = 1;
                    found = 1;
                    break;
                }
            }
        }
        if (!found && process_count < MAX_PROCESS_COUNT) {
            processes[process_count].pid = pid;
            strncpy(processes[process_count].name, name, NAME_LEN);
            processes[process_count].initial_rss = rss;
            processes[process_count].prev_rss = rss;
            processes[process_count].curr_rss = rss;
            processes[process_count].peak_rss = rss;
            processes[process_count].yellow_entry_rss = 0;
            processes[process_count].stable_count = 0;
            processes[process_count].prev_bucket = GREEN;
            processes[process_count].curr_bucket = GREEN;
            processes[process_count].active = 1;
            process_count++;
        }
        if (++idx >= MAX_PROCESS_COUNT) break;
    }
    closedir(dir);
}

void update_buckets() {
    for (int i = 0; i < process_count; ++i) {
        if (!processes[i].active) continue;

        // Get per-process threshold
        long process_threshold = get_threshold_for_process(processes[i].name);
        long diff = processes[i].curr_rss - processes[i].prev_rss;
        long total_diff = processes[i].curr_rss - processes[i].initial_rss;

        processes[i].prev_bucket = processes[i].curr_bucket;
        // Skip if monitoring disabled for this process
        if (process_threshold == 0) {
            processes[i].curr_bucket = GREEN;
            processes[i].stable_count = 0;
        } else {
            switch (processes[i].curr_bucket) {
                case GREEN:
                    if (total_diff >= process_threshold) {
                        processes[i].curr_bucket = YELLOW;
                        processes[i].yellow_entry_rss = processes[i].curr_rss;  // Store RSS at YELLOW entry
                        processes[i].stable_count = 0;
                        MemTraceInfo((
                            "%s(%d) moved to YELLOW (threshold: %ld KB, growth: %ld KB)\n",
                            processes[i].name, processes[i].pid, process_threshold, total_diff));
                    }
                    break;
                case YELLOW:
                    if (diff >= process_threshold) {
                        processes[i].curr_bucket = RED;
                        processes[i].peak_rss = processes[i].curr_rss;  // Track peak when entering RED
                        processes[i].stable_count = 0;
                        MemTraceInfo((
                            "%s(%d) moved to RED (threshold: %ld KB, rapid growth: %ld KB)\n",
                            processes[i].name, processes[i].pid, process_threshold, diff));
                    } else if (total_diff < process_threshold) {
                        // Back to baseline - move to GREEN
                        processes[i].curr_bucket = GREEN;
                        processes[i].initial_rss = processes[i].curr_rss; // Reset baseline
                        processes[i].stable_count = 0;
                        MemTraceInfo((
                            "%s(%d) recovered to GREEN (below threshold: %ld KB)\n",
                            processes[i].name, processes[i].pid, process_threshold));
                    } else if (diff <= 0) {
                        // RSS stable or decreasing in YELLOW - count stable periods
                        processes[i].stable_count++;
                        if (processes[i].stable_count >= YELLOW_STABLE_COUNT) {
                            // Stable for required periods - move to GREEN
                            MemTraceInfo((
                                "%s(%d) stabilized at %ld KB after %d interval. Moving YELLOW→GREEN\n",
                                processes[i].name, processes[i].pid, processes[i].curr_rss, processes[i].stable_count));
                            processes[i].curr_bucket = GREEN;
                            processes[i].initial_rss = processes[i].curr_rss;
                            processes[i].stable_count = 0;
                        }
                    } else {
                        // RSS still growing - reset stable counter
                        processes[i].stable_count = 0;
                    }
                    break;
                case RED:
                    // Update peak RSS if still growing
                    if (processes[i].curr_rss > processes[i].peak_rss) {
                        processes[i].peak_rss = processes[i].curr_rss;
                    }

                    if (total_diff < process_threshold) {
                        // Major recovery - back to baseline
                        processes[i].curr_bucket = GREEN;
                        processes[i].initial_rss = processes[i].curr_rss;
                        processes[i].stable_count = 0;
                        MemTraceInfo((
                            "%s(%d) major recovery to GREEN (below threshold: %ld KB)\n",
                            processes[i].name, processes[i].pid, process_threshold));
                    } else if (diff <= 0) {
                        // RSS stopped growing or decreasing - check if enough drop to move to YELLOW
                        long drop_from_peak = processes[i].peak_rss - processes[i].curr_rss;
                        long drop_percent = (drop_from_peak * 100) / processes[i].peak_rss;

                        if (drop_percent >= RED_TO_YELLOW_DROP_PERCENT) {
                            // Dropped enough from peak - move to YELLOW
                            MemTraceInfo((
                                "%s(%d) dropped %ld%% from peak (%ld→%ld KB). Moving RED→YELLOW\n",
                                processes[i].name, processes[i].pid, drop_percent,
                                processes[i].peak_rss, processes[i].curr_rss));
                            processes[i].curr_bucket = YELLOW;
                            processes[i].yellow_entry_rss = processes[i].curr_rss;
                            processes[i].stable_count = 0;
                        } else {
                            // Not enough drop yet - stay in RED
                            MemTraceDebug((
                                "%s(%d) only dropped %ld%% from peak (need %d%%). Staying in RED\n",
                                processes[i].name, processes[i].pid, drop_percent, RED_TO_YELLOW_DROP_PERCENT));
                        }
                    }
                    break;
            }
        }
        if (processes[i].prev_bucket != processes[i].curr_bucket) {
            MemTraceDebug((
                "%s(%d): PID=%d Name=%s Bucket=%d->%d RSS=%ld Diff=%ld\n",
                __func__, __LINE__, processes[i].pid, processes[i].name,
                processes[i].prev_bucket, processes[i].curr_bucket, processes[i].curr_rss, diff));
            if (processes[i].curr_bucket == GREEN) {
                disable_mtrace(processes[i].name, processes[i].pid);
            } else if (processes[i].prev_bucket == GREEN) {
                enable_mtrace(processes[i].name, processes[i].pid);
            }
        }
    }
}

//*** New: Update shared memory bucket ***
void update_shared_mem_bucket() {
    curr_shmem = read_shared_memory_kb();
    if (curr_shmem < 0) return; // Error reading shared mem
    long diff = curr_shmem - prev_shmem;

    Bucket prev_bucket = shmem_bucket;
    switch (shmem_bucket) {
        case GREEN:
            if (diff >= SHMEM_THRESHOLD_YELLOW_KB || curr_shmem >= SHMEM_THRESHOLD_YELLOW_KB) {
                shmem_bucket = YELLOW;
            }
            break;

        case YELLOW:
            if (diff > 0) {
                if (curr_shmem >= SHMEM_THRESHOLD_RED_KB) {
                    shmem_bucket = RED;
                }
            } else if (curr_shmem < SHMEM_THRESHOLD_YELLOW_KB) {
                shmem_bucket = GREEN;
            }
            break;

        case RED:
            if (curr_shmem < SHMEM_THRESHOLD_YELLOW_KB) {
                shmem_bucket = GREEN;
            } else if (diff <= 0) {
                shmem_bucket = YELLOW;
            }
            break;
    }

    if (prev_bucket != shmem_bucket) {
        MemTraceInfo((
                "Shared Memory Bucket %d->%d Current Shmem: %ld KB Diff: %ld KB\n",
                prev_bucket, shmem_bucket, curr_shmem, diff));
    }

    prev_shmem = curr_shmem;
}

// Print telemetry markers
void print_bucket_telemetry() {
    for (int i = 0; i < process_count; ++i) {
        if (!processes[i].active) continue;
        long curr_rss = processes[i].curr_rss;

        if (processes[i].prev_bucket == GREEN && processes[i].curr_bucket == YELLOW) {
            MemTraceInfo((
                "mem_bucket_transition_split:\"%s:%d:GREEN->YELLOW:%ld\"\n",
                processes[i].name, processes[i].pid, curr_rss));
        } else if (processes[i].prev_bucket == YELLOW && processes[i].curr_bucket == RED) {
            MemTraceInfo((
                "mem_bucket_transition_split:\"%s:%d:YELLOW->RED:%ld\"\n",
                processes[i].name, processes[i].pid, curr_rss));
        } else if (processes[i].prev_bucket == RED && processes[i].curr_bucket == YELLOW) {
            MemTraceInfo((
                "mem_bucket_transition_split:\"%s:%d:RED->YELLOW:%ld\"\n",
                processes[i].name, processes[i].pid, curr_rss));
        } else if (processes[i].prev_bucket == YELLOW && processes[i].curr_bucket == GREEN) {
            MemTraceInfo((
                "mem_bucket_transition_split:\"%s:%d:YELLOW->GREEN:%ld\"\n",
                processes[i].name, processes[i].pid, curr_rss));
        }

        switch (processes[i].curr_bucket) {
            case GREEN:
                MemTraceInfo(("mem_incr_dtctedbkt_%s_split:\"%s:%d:%ld\"\n",
                              "green", processes[i].name, processes[i].pid, curr_rss));
                break;
            case YELLOW:
                MemTraceInfo(("mem_incr_dtctedbkt_%s_split:\"%s:%d:%ld\"\n",
                              "yellow", processes[i].name, processes[i].pid, curr_rss));
                break;
            case RED:
                MemTraceInfo(("mem_incr_dtctedbkt_%s_split:\"%s:%d:%ld\"\n",
                              "red", processes[i].name, processes[i].pid, curr_rss));
                break;
        }
    }
    // Print shared memory telemetry
    switch (shmem_bucket) {
        case GREEN:
            MemTraceInfo(("mem_sharedmem_dtctedbkt_%s_split:\"%ld\"\n", "green", curr_shmem));
            break;
        case YELLOW:
            MemTraceInfo(("mem_sharedmem_dtctedbkt_%s_split:\"%ld\"\n", "yellow", curr_shmem));
            break;
        case RED:
            MemTraceInfo(("mem_sharedmem_dtctedbkt_%s_split:\"%ld\"\n", "red", curr_shmem));
            break;
    }
}

void reset_active_flags() {
    for (int i = 0; i < process_count; ++i) {
        processes[i].active = 0;
    }
}

void print_buckets() {
    MemTraceInfo(("\n--- Bucket Status ---\n"));
    MemTraceInfo(("GREEN:\n"));
    for (int i = 0; i < process_count; ++i) {
        if (processes[i].curr_bucket == GREEN && processes[i].active)
            MemTraceInfo(("%s (PID %d) RSS: %ld KB\n", processes[i].name, processes[i].pid, processes[i].curr_rss));
    }
    MemTraceInfo(("YELLOW:\n"));
    for (int i = 0; i < process_count; ++i) {
        if (processes[i].curr_bucket == YELLOW && processes[i].active)
            MemTraceInfo(("%s (PID %d) RSS: %ld KB\n", processes[i].name, processes[i].pid, processes[i].curr_rss));
    }
    MemTraceInfo(("RED:\n"));
    for (int i = 0; i < process_count; ++i) {
        if (processes[i].curr_bucket == RED && processes[i].active)
            MemTraceInfo(("%s (PID %d) RSS: %ld KB\n", processes[i].name, processes[i].pid, processes[i].curr_rss));
    }
    MemTraceInfo(("\nShared Memory Bucket: "));
    switch (shmem_bucket) {
        case GREEN:
            MemTraceInfo(("GREEN\n"));
            break;
        case YELLOW:
            MemTraceInfo(("YELLOW\n"));
            break;
        case RED:
            MemTraceInfo(("RED\n"));
            break;
    }
}

static void daemonize(void) {
    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            MemTraceError(("memtraced: Error daemonizing (fork)! %d - %s\n", errno, strerror(errno)));
            exit(0);
            break;
        default:
            _exit(0);
    }

    if (setsid() < 0) {
        MemTraceError(("memtraced: Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef  _DEBUG
    int fd;
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

int main() {
    MemTrace_Log_Init();
    if (read_config_values() == 0) {
        MemTraceInfo((
            "Config: Interval=%u, RSSThreshold=%lu, InitialSnapshotUptime=%u\n",
            interval, rss_threshold, initial_snapshot_uptime));
    } else {
        MemTraceInfo(("Config file not found!\n"));
    }

    // Load per-process thresholds
    load_process_thresholds();
    daemonize();
    MemTraceRbusInit();
    MemTraceInfo(("RSS memory monitor started.\n"));
    long uptime = get_uptime_seconds();
    long target = (initial_snapshot_uptime == 0) ? DEFAULT_INITIAL_SNAPSHOT_UPTIME_SEC : initial_snapshot_uptime;
    if (uptime < target) {
        long wait_time = target - uptime;
        MemTraceInfo((
            "Waiting %ld seconds until %ld seconds after boot to take initial snapshot...\n",
            wait_time, target));
        sleep(wait_time);
    } else {
        MemTraceInfo((
            "System has already passed %ld seconds after boot. Taking initial snapshot now.\n", target));
    }
    take_initial_snapshot();
    while (1) {
        reset_active_flags();
        scan_processes();
        update_buckets();
        update_shared_mem_bucket();  // *** Track shared memory ***
        print_bucket_telemetry();
        print_buckets();
        log_bucket_markers(processes, process_count);  // Log YELLOW/RED to file
        sleep((interval == 0) ? DEFAULT_INTERVAL_SEC : (unsigned int)interval);
    }
    return 0;
}
