#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <syscfg/syscfg.h>

#define MAX_PROCESS_COUNT 1024
#define NAME_LEN 256
#define DEFAULT_THRESHOLD_KB 2048  // Default threshold for processes not in config
#define RED_TO_YELLOW_DROP_PERCENT 30  // Must drop 30% from peak to move RED → YELLOW
#define YELLOW_STABLE_COUNT 3  // Must be stable for 3 interval (6 min) to move YELLOW → GREEN
#define MAX_PROC_THRESHOLD_CONFIG_COUNT 50
#define BUCKET_FILE "/tmp/bucket_status.txt"
#define DEFAULT_INTERVAL_SEC 120    // Snapshot interval in seconds 2 minutes
#define DEFAULT_INITIAL_SNAPSHOT_UPTIME_SEC 120 // Initial snapshot timer in seconds (2 minutes)

//*** Shared Mem Extension ***
#define SHMEM_THRESHOLD_YELLOW_KB   71680   // 70 MB
#define SHMEM_THRESHOLD_RED_KB     122880   // 120 MB

//#define SHMEM_THRESHOLD_YELLOW_KB 10240  // 10 MB
//#define SHMEM_THRESHOLD_RED_KB    20480  // 20 MB

// Per-process threshold configuration
typedef struct {
    char process_name[256];
    unsigned long threshold_kb;
    bool enabled;
} ProcessThresholdConfig;

// Enum for bucket
typedef enum { GREEN, YELLOW, RED } Bucket;

// Process info struct
typedef struct {
    pid_t pid;
    char name[NAME_LEN];
    long initial_rss;
    long prev_rss;
    long curr_rss;
    long peak_rss;              // Track highest RSS seen (for RED → YELLOW logic)
    long yellow_entry_rss;      // RSS value when entered YELLOW (for file logging)
    int stable_count;           // Count stable/decreasing interval
    Bucket prev_bucket;
    Bucket curr_bucket;
    int active;
} ProcessInfo;

void scan_processes();
int load_process_thresholds();
