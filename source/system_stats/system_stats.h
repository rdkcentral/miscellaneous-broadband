#ifndef SYSTEM_STATS_H
#define SYSTEM_STATS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysevent/sysevent.h>
#include "secure_wrapper.h"

// Structure to store system statistics
typedef struct {
    double cpu_usage;
    double cpu_user;
    double cpu_system;
    double cpu_idle;
    double cpu_iowait;
    double total_memory;
    double free_memory;
    double avail_memory;
    double cached_mem;
    double buffers_mem;
    double slab_memory;
    double slab_unreclaim;
    double active_memory;
    double inactive_memory;
    double loadavg_1min;
    double loadavg_5min;
    double loadavg_15min;
    int hour_of_day;
    char model[64];
    char firmware[128];
    char cmac[32];
    char uptime[64];
    char day_of_week[16];
} SystemStats;

// Function declarations
void initialize_system_stats(SystemStats *stats);
void collect_system_stats(SystemStats *stats);
void get_cpu_usage(double *cpu_usage);
void get_cpu_stats(double *cpu_user, double *cpu_system, double *cpu_idle, double *cpu_iowait);
void get_memory_info(double *total_memory, double *free_memory, double *avail_memory, double *cached_mem, double *buffers_mem, double *slab_memory, double *slab_unreclaim, double *active_memory, double *inactive_memory);
void get_load_average(double *load1, double *load5, double *load15);
void get_device_model(char *model, size_t size);
void get_firmware_version(char *firmware, size_t size);
void get_cmac_address(char *cmac, size_t size);
void get_device_uptime(char *uptime, size_t size);
void get_hour_of_day(int *hour);
void get_day_of_week(char *day, size_t size);

#endif // SYSTEM_STATS_H
