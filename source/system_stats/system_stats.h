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
    char model[64];
    char firmware[128];
    char cmac[32];
    char uptime[64];
    double cpu_usage;
    double free_memory;
    double slab_memory;
    double avail_memory;
    double cached_mem;
    double slab_unreclaim;
    double loadavg_1min;
    double loadavg_5min;
    double loadavg_15min;
} SystemStats;

// Function declarations
void initialize_system_stats(SystemStats *stats);
void collect_system_stats(SystemStats *stats);
void get_cpu_usage(double *cpu_usage);
void get_memory_info(double *free_memory, double *slab_memory, double *avail_memory, double *cached_mem, double *slab_unreclaim);
void get_load_average(double *load1, double *load5, double *load15);
void get_device_model(char *model, size_t size);
void get_firmware_version(char *firmware, size_t size);
void get_cmac_address(char *cmac, size_t size);
void get_device_uptime(char *uptime, size_t size);

#endif // SYSTEM_STATS_H
