#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>


#define ROOTFS_PATH "/"
#define TMPFS_PATH "/tmp"

// API to initialize system statistics
void initialize_system_stats(SystemStats *stats) {
    memset(stats, 0, sizeof(SystemStats));
    stats->timestamp_ms = 0;
    strncpy(stats->model, "UNKNOWN", sizeof(stats->model));
    strncpy(stats->firmware, "UNKNOWN", sizeof(stats->firmware));
    strncpy(stats->cmac, "UNKNOWN", sizeof(stats->cmac));
    strncpy(stats->uptime, "UNKNOWN", sizeof(stats->uptime));
    stats->cpu_usage = -1.0;
    stats->free_memory = -1.0;
    stats->slab_memory = -1.0;
    stats->avail_memory = -1.0;
    stats->cached_mem = -1.0;
    stats->slab_unreclaim = -1.0;
    stats->loadavg_1min = -1.0;
    stats->loadavg_5min = -1.0;
    stats->loadavg_15min = -1.0;
    stats->rootfs_used_kb = 0;
    stats->rootfs_total_kb = 0;
    stats->tmpfs_used_kb = 0;
    stats->tmpfs_total_kb = 0;
    stats->pid_stats_count = 0;
    stats->pid_stats = NULL;
    stats->next = NULL;
}

void initialize_restart_count_stats(RestartCountStats *stats) {
    if (!stats) return;
    memset(stats, 0, sizeof(RestartCountStats));
    stats->fw_restart_time = NULL;
    stats->wan_restart_time = NULL;
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

// API to collect memory information (free memory and slab memory)
void get_memory_info(double *free_memory, double *slab_memory, double *avail_memory, double *cached_mem, double *slab_unreclaim) {
    char buffer[256];
    FILE *fp = fopen("/proc/meminfo", "r");
    *free_memory = *slab_memory = *avail_memory = *cached_mem = *slab_unreclaim = -1.0;
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strncmp(buffer, "MemFree:", 8) == 0) {
                sscanf(buffer, "MemFree: %lf", free_memory);
                *free_memory /= 1024.0; // Convert to MB
                *free_memory = (int)(*free_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Slab:", 5) == 0) {
                sscanf(buffer, "Slab: %lf", slab_memory);
                *slab_memory /= 1024.0;
                *slab_memory = (int)(*slab_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "MemAvailable:", 13) == 0) {
                sscanf(buffer, "MemAvailable: %lf", avail_memory);
                *avail_memory /= 1024.0;
                *avail_memory = (int)(*avail_memory * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "Cached:", 7) == 0) {
                sscanf(buffer, "Cached: %lf", cached_mem);
                *cached_mem /= 1024.0;
                *cached_mem = (int)(*cached_mem * 1000.0 + 0.5) / 1000.0;
            } else if (strncmp(buffer, "SUnreclaim:", 11) == 0) {
                sscanf(buffer, "SUnreclaim: %lf", slab_unreclaim);
                *slab_unreclaim /= 1024.0;
                *slab_unreclaim = (int)(*slab_unreclaim * 1000.0 + 0.5) / 1000.0;
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
            int days = seconds / 86400;
            int hours = ((int)seconds % 86400) / 3600;
            int minutes = ((int)seconds % 3600) / 60;
            snprintf(uptime, size, "%d days, %d hours, %d minutes", days, hours, minutes);
        } else {
            strncpy(uptime, "UNKNOWN", size);
        }
        fclose(fp);
    } else {
        strncpy(uptime, "UNKNOWN", size);
    }
}

// API to collect rootfs and tmpfs memory
void get_fs_data(char* path, uint32_t* used_kb, uint32_t* total_kb) {
    int res;
    struct statfs fs_info;


    res = statfs(path, &fs_info);
    if (res != 0)
    {
        log_message("Error getting filesystem status info: %s", path);
        return;
    }
    *total_kb = (fs_info.f_blocks * fs_info.f_bsize) / 1024;
    *used_kb  = ((*total_kb) - (fs_info.f_bfree * fs_info.f_bsize) / 1024);
}

// API to collect system statistics using the individual APIs
void collect_system_stats(SystemStats *stats) {
    stats->timestamp_ms = get_timestamp_ms();
    get_device_model(stats->model, sizeof(stats->model));
    get_firmware_version(stats->firmware, sizeof(stats->firmware));
    get_cmac_address(stats->cmac, sizeof(stats->cmac));
    get_cpu_usage(&stats->cpu_usage);
    get_memory_info(&stats->free_memory, &stats->slab_memory, &stats->avail_memory, &stats->cached_mem, &stats->slab_unreclaim);
    get_load_average(&stats->loadavg_1min, &stats->loadavg_5min, &stats->loadavg_15min);
    get_device_uptime(stats->uptime, sizeof(stats->uptime));
    get_fs_data(ROOTFS_PATH, &stats->rootfs_used_kb, &stats->rootfs_total_kb);
    get_fs_data(TMPFS_PATH, &stats->tmpfs_used_kb, &stats->tmpfs_total_kb);
}