#include "system_stats.h"

// API to initialize system statistics
void initialize_system_stats(SystemStats *stats) {
    memset(stats, 0, sizeof(SystemStats));
    strncpy(stats->cmac, "UNKNOWN", sizeof(stats->cmac));
    stats->cpu_usage = -1.0;
    stats->used_memory_kb = -1.0;
    stats->loadavg_15min = -1.0;
    stats->avail_memory_kb = -1.0;
    stats->free_memory_kb = -1.0;
    stats->slab_memory_kb = -1.0;
    stats->client_count_2g = -1;
    stats->client_count_5g = -1;
    stats->client_count_6g = -1;
}

// API to collect CMAC address
void get_cmac_address(char *cmac, size_t size) {
    FILE *fp = v_secure_popen("r", "deviceinfo.sh -cmac");
    if (fp) {
        if (fgets(cmac, size, fp)) {
            cmac[strcspn(cmac, "\n")] = '\0'; // Remove newline character
        } else {
            strncpy(cmac, "UNKNOWN", size);
        }
        v_secure_pclose(fp);
    } else {
        strncpy(cmac, "UNKNOWN", size);
    }
}

// API to collect CPU usage
void get_cpu_usage(double *cpu_usage) {
    char buffer[256];
    FILE *fp = v_secure_popen("r", "dmcli eRT retv Device.DeviceInfo.ProcessStatus.CPUUsage");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            *cpu_usage = atof(buffer);
        } else {
            *cpu_usage = -1.0; // Default value if reading fails
        }
        v_secure_pclose(fp);
    } else {
        *cpu_usage = -1.0; // Default value if command fails
    }
}

// API to collect memory information
// Values are stored in kB (raw values from /proc/meminfo).
// used_memory_kb = MemTotal - MemFree.
void get_memory_info(double *used_memory_kb, double *free_memory_kb, double *avail_memory_kb, double *slab_memory_kb) {
    char buffer[256];
    double val;
    double total_kb = -1.0;
    FILE *fp = fopen("/proc/meminfo", "r");
    *used_memory_kb = *free_memory_kb = *avail_memory_kb = *slab_memory_kb = -1.0;
    if (!fp) return;
    while (fgets(buffer, sizeof(buffer), fp)) {
        if      (sscanf(buffer, "MemTotal: %lf",    &val) == 1) total_kb        = val;
        else if (sscanf(buffer, "MemFree: %lf",     &val) == 1) *free_memory_kb = val;
        else if (sscanf(buffer, "MemAvailable: %lf",&val) == 1) *avail_memory_kb= val;
        else if (sscanf(buffer, "Slab: %lf",        &val) == 1) *slab_memory_kb = val;
    }
    fclose(fp);
    if (total_kb >= 0.0 && *free_memory_kb >= 0.0)
        *used_memory_kb = total_kb - *free_memory_kb;
}

// API to collect 15-minute load average
void get_load_average(double *load15) {
    double load1, load5;
    FILE *fp = fopen("/proc/loadavg", "r");
    if (fp) {
        if (fscanf(fp, "%lf %lf %lf", &load1, &load5, load15) != 3) {
            *load15 = -1.0;
        }
        fclose(fp);
    } else {
        *load15 = -1.0;
    }
}

// API to collect WiFi client counts for 2.4GHz, 5GHz, and 6GHz bands
static int get_dmcli_int(const char *param) {
    char buffer[64];
    FILE *fp = v_secure_popen("r", "dmcli eRT retv %s", param);
    if (fp) {
        int val = -1;
        if (fgets(buffer, sizeof(buffer), fp))
            val = atoi(buffer);
        v_secure_pclose(fp);
        return val;
    }
    return -1;
}

void get_wifi_client_counts(int *count_2g, int *count_5g, int *count_6g) {
    *count_2g = get_dmcli_int("Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries");
    *count_5g = get_dmcli_int("Device.WiFi.AccessPoint.2.AssociatedDeviceNumberOfEntries");
    *count_6g = get_dmcli_int("Device.WiFi.AccessPoint.3.AssociatedDeviceNumberOfEntries");
}

// API to collect system statistics using the individual APIs
void collect_system_stats(SystemStats *stats) {
    get_cmac_address(stats->cmac, sizeof(stats->cmac));
    get_cpu_usage(&stats->cpu_usage);
    get_memory_info(&stats->used_memory_kb, &stats->free_memory_kb, &stats->avail_memory_kb, &stats->slab_memory_kb);
    get_load_average(&stats->loadavg_15min);
    get_wifi_client_counts(&stats->client_count_2g, &stats->client_count_5g, &stats->client_count_6g);
}
