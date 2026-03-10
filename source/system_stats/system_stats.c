#include "system_stats.h"
#include "helper.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// API to initialize system statistics
void initialize_system_stats(SystemStats *stats) {
    memset(stats, 0, sizeof(SystemStats));
    strncpy(stats->model, "UNKNOWN", sizeof(stats->model));
    strncpy(stats->firmware, "UNKNOWN", sizeof(stats->firmware));
    strncpy(stats->cmac, "UNKNOWN", sizeof(stats->cmac));
    strncpy(stats->uptime, "UNKNOWN", sizeof(stats->uptime));
    stats->cpu_usage = -1.0;
    stats->cpu_user = -1.0;
    stats->cpu_system = -1.0;
    stats->cpu_idle = -1.0;
    stats->cpu_iowait = -1.0;
    stats->total_memory = -1.0;
    stats->free_memory = -1.0;
    stats->avail_memory = -1.0;
    stats->cached_mem = -1.0;
    stats->buffers_mem = -1.0;
    stats->slab_memory = -1.0;
    stats->slab_unreclaim = -1.0;
    stats->active_memory = -1.0;
    stats->inactive_memory = -1.0;
    stats->loadavg_1min = -1.0;
    stats->loadavg_5min = -1.0;
    stats->loadavg_15min = -1.0;
    stats->hour_of_day = -1;
    strncpy(stats->day_of_week, "UNKNOWN", sizeof(stats->day_of_week));
}

// API to collect device model
void get_device_model(char *model, size_t size) {
    FILE *fp = v_secure_popen("r", "deviceinfo.sh -mo");
    if (fp) {
        if (fgets(model, size, fp)) {
            model[strcspn(model, "\n")] = '\0'; // Remove newline character
        } else {
            strncpy(model, "UNKNOWN", size);
        }
        v_secure_pclose(fp);
    } else {
        strncpy(model, "UNKNOWN", size);
    }
}

// API to collect firmware version
void get_firmware_version(char *firmware, size_t size) {
    FILE *fp = v_secure_popen("r", "deviceinfo.sh -fw");
    if (fp) {
        if (fgets(firmware, size, fp)) {
            firmware[strcspn(firmware, "\n")] = '\0'; // Remove newline character
        } else {
            strncpy(firmware, "UNKNOWN", size);
        }
        v_secure_pclose(fp);
    } else {
        strncpy(firmware, "UNKNOWN", size);
    }
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

// API to collect CPU stats (user, system, idle, iowait) as percentages
// Reads /proc/stat twice with a 200ms interval and computes deltas
void get_cpu_stats(double *cpu_user, double *cpu_system, double *cpu_idle, double *cpu_iowait) {
    unsigned long long user1, nice1, system1, idle1, iowait1, irq1, softirq1, steal1;
    unsigned long long user2, nice2, system2, idle2, iowait2, irq2, softirq2, steal2;
    *cpu_user = *cpu_system = *cpu_idle = *cpu_iowait = -1.0;

    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return;
    if (fscanf(fp, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
               &user1, &nice1, &system1, &idle1, &iowait1, &irq1, &softirq1, &steal1) != 8) {
        fclose(fp);
        return;
    }
    fclose(fp);

    usleep(200000); // 200ms sample interval

    fp = fopen("/proc/stat", "r");
    if (!fp) return;
    if (fscanf(fp, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
               &user2, &nice2, &system2, &idle2, &iowait2, &irq2, &softirq2, &steal2) != 8) {
        fclose(fp);
        return;
    }
    fclose(fp);

    unsigned long long d_user    = (user2 + nice2)   - (user1 + nice1);
    unsigned long long d_system  = system2            - system1;
    unsigned long long d_idle    = idle2              - idle1;
    unsigned long long d_iowait  = iowait2            - iowait1;
    unsigned long long d_total   = d_user + d_system + d_idle + d_iowait
                                 + (irq2 - irq1) + (softirq2 - softirq1) + (steal2 - steal1);

    if (d_total == 0) return;

    *cpu_user   = (double)d_user   / d_total * 100.0;
    *cpu_system = (double)d_system / d_total * 100.0;
    *cpu_idle   = (double)d_idle   / d_total * 100.0;
    *cpu_iowait = (double)d_iowait / d_total * 100.0;
}

// API to collect memory information
void get_memory_info(double *total_memory, double *free_memory, double *avail_memory, double *cached_mem, double *buffers_mem, double *slab_memory, double *slab_unreclaim, double *active_memory, double *inactive_memory) {
    char buffer[256];
    FILE *fp = fopen("/proc/meminfo", "r");
    *total_memory = *free_memory = *avail_memory = *cached_mem = *buffers_mem = -1.0;
    *slab_memory = *slab_unreclaim = *active_memory = *inactive_memory = -1.0;
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strncmp(buffer, "MemTotal:", 9) == 0) {
                sscanf(buffer, "MemTotal: %lf", total_memory);
                *total_memory /= 1024.0;
                *total_memory = (int)(*total_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "MemFree:", 8) == 0) {
                sscanf(buffer, "MemFree: %lf", free_memory);
                *free_memory /= 1024.0;
                *free_memory = (int)(*free_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "MemAvailable:", 13) == 0) {
                sscanf(buffer, "MemAvailable: %lf", avail_memory);
                *avail_memory /= 1024.0;
                *avail_memory = (int)(*avail_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Cached:", 7) == 0) {
                sscanf(buffer, "Cached: %lf", cached_mem);
                *cached_mem /= 1024.0;
                *cached_mem = (int)(*cached_mem * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Buffers:", 8) == 0) {
                sscanf(buffer, "Buffers: %lf", buffers_mem);
                *buffers_mem /= 1024.0;
                *buffers_mem = (int)(*buffers_mem * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Slab:", 5) == 0) {
                sscanf(buffer, "Slab: %lf", slab_memory);
                *slab_memory /= 1024.0;
                *slab_memory = (int)(*slab_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "SUnreclaim:", 11) == 0) {
                sscanf(buffer, "SUnreclaim: %lf", slab_unreclaim);
                *slab_unreclaim /= 1024.0;
                *slab_unreclaim = (int)(*slab_unreclaim * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Active:", 7) == 0) {
                sscanf(buffer, "Active: %lf", active_memory);
                *active_memory /= 1024.0;
                *active_memory = (int)(*active_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Inactive:", 9) == 0) {
                sscanf(buffer, "Inactive: %lf", inactive_memory);
                *inactive_memory /= 1024.0;
                *inactive_memory = (int)(*inactive_memory * 1000.0 + 0.5) / 1000.0;
            }
        }
        fclose(fp);
    }
}

// API to collect load average
void get_load_average(double *load1, double *load5, double *load15) {
    FILE *fp = fopen("/proc/loadavg", "r");
    if (fp) {
        if (fscanf(fp, "%lf %lf %lf", load1, load5, load15) != 3) {
            *load1 = *load5 = *load15 = -1.0;
        }
        fclose(fp);
    } else {
        *load1 = *load5 = *load15 = -1.0;
    }
}

// API to collect device uptime
void get_device_uptime(char *uptime, size_t size) {
    FILE *fp = fopen("/proc/uptime", "r");
    if (fp) {
        double seconds;
        if (fscanf(fp, "%lf", &seconds) == 1) {
            snprintf(uptime, size, "%.0f", seconds);

            // int days = seconds / 86400;
            // int hours = ((int)seconds % 86400) / 3600;
            // int minutes = ((int)seconds % 3600) / 60;
            // snprintf(uptime, size, "%d days, %d hours, %d minutes", days, hours, minutes);
        } else {
            strncpy(uptime, "UNKNOWN", size);
        }
        fclose(fp);
    } else {
        strncpy(uptime, "UNKNOWN", size);
    }
}

// API to collect hour of day (0-23)
void get_hour_of_day(int *hour) {
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    *hour = tm_info.tm_hour;
}

// API to collect day of week (e.g. "Tue")
void get_day_of_week(char *day, size_t size) {
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    strftime(day, size, "%a", &tm_info);
}

// API to collect system statistics using the individual APIs
void collect_system_stats(SystemStats *stats) {
    get_device_model(stats->model, sizeof(stats->model));
    get_firmware_version(stats->firmware, sizeof(stats->firmware));
    get_cmac_address(stats->cmac, sizeof(stats->cmac));
    get_cpu_usage(&stats->cpu_usage);
    get_cpu_stats(&stats->cpu_user, &stats->cpu_system, &stats->cpu_idle, &stats->cpu_iowait);
    get_memory_info(&stats->total_memory, &stats->free_memory, &stats->avail_memory, &stats->cached_mem, &stats->buffers_mem, &stats->slab_memory, &stats->slab_unreclaim, &stats->active_memory, &stats->inactive_memory);
    get_load_average(&stats->loadavg_1min, &stats->loadavg_5min, &stats->loadavg_15min);
    get_device_uptime(stats->uptime, sizeof(stats->uptime));
    get_hour_of_day(&stats->hour_of_day);
    get_day_of_week(stats->day_of_week, sizeof(stats->day_of_week));
}
