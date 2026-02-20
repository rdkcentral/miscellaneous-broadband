#ifndef SYSTEMSTATS_APIS_H
#define SYSTEMSTATS_APIS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include "ansc_platform.h"

#define LOG_FILE "/rdklogs/logs/system_stats_logs.txt"
#define DEFAULT_INTERVAL 900 // 15 minutes in seconds

// Declare the mutex for lan_stats
extern pthread_mutex_t lan_stats_mutex;

// Function declarations
void log_message(const char *format, ...);
void execute_command(const char *command, char *output, size_t size);
int SystemStats_Init();
int SystemStats_Collect();
int SystemStats_Save();
int SystemStats_DeInit();
int SystemStats_StartThread();
void SystemStats_StopThread();

#endif // SYSTEMSTATS_APIS_H