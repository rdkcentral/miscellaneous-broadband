#include "gateway_stats.h"

static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_cond = PTHREAD_COND_INITIALIZER;
static bool stop_thread = false;
static pthread_t fw_restart_thread;
static bool stop_fw_restart_thread = false;
static pthread_t wan_restart_thread;
static bool stop_wan_restart_thread = false;


static int sysevent_fd;
static token_t sysevent_token;

extern gw_stats_report g_report;

static void* fw_restart_time_thread_func(void *arg) {
    UNREFERENCED_PARAMETER(arg);
    async_id_t firewall_restart_event_asyncid;

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "GatewayStats", &sysevent_token);
    if (!sysevent_fd) {
        log_message("Failed to open sysevent_fd\n");
        return NULL;
    }
    sysevent_set_options(sysevent_fd, sysevent_token, "firewall-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, "firewall-restart", &firewall_restart_event_asyncid);

    while (!stop_fw_restart_thread) {
        char name[20] = {0};
        char val[20] = {0};
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        async_id_t getnotification_asyncid;
        int err = 0;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_asyncid);
        if(err)
        {
            log_message("sysevent_getnotification failed with error: %d\n", err);
            sleep(2);
        }
        else
        {
            log_message("Received sysevent notification: %s = %s\n", name, val);
            if (strcmp(name, "firewall-restart") == 0) {
                log_message("Firewall restart event received.\n");
                // Add timestamp to fw_restart_time in g_report.restart_count_stats
                char timestamp[64];
                get_current_timestamp(timestamp, sizeof(timestamp));
                restart_count_stats_t *stats = g_report.restart_count_stats;

                // Ensure fw_restart_time is initialized
                if (stats->fw_restart_time == NULL) {
                    stats->fw_restart_time = calloc(1, sizeof(char *));
                    if (stats->fw_restart_time == NULL) {
                        log_message("Failed to allocate initial memory for fw_restart_time\n");
                        continue;
                    }
                    stats->fw_restart_count = 0;
                }

                char **new_times = realloc(stats->fw_restart_time, (stats->fw_restart_count + 1) * sizeof(char *));
                if (new_times) {
                    stats->fw_restart_time = new_times;
                    stats->fw_restart_time[stats->fw_restart_count] = strdup(timestamp);
                    if (stats->fw_restart_time[stats->fw_restart_count]) {
                        stats->fw_restart_count++;
                        log_message("Added fw_restart_time: %s, count: %d\n", timestamp, stats->fw_restart_count);
                    } else {
                        log_message("Failed to allocate memory for fw_restart_time string\n");
                    }
                } else {
                    log_message("Failed to allocate memory for fw_restart_time\n");
                }
            }
        }
    }
    log_message("fw_restart_time_thread_func: Exiting thread.\n");
    return NULL;
}

static void* wan_restart_time_thread_func(void *arg) {
    UNREFERENCED_PARAMETER(arg);
    async_id_t wan_restart_event_asyncid;

    int sysevent_fd_local;
    token_t sysevent_token_local;
    sysevent_fd_local = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "GatewayStatsWAN", &sysevent_token_local);
    if (!sysevent_fd_local) {
        log_message("Failed to open sysevent_fd for WAN restart\n");
        return NULL;
    }
    sysevent_set_options(sysevent_fd_local, sysevent_token_local, "wan-restart", TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd_local, sysevent_token_local, "wan-restart", &wan_restart_event_asyncid);

    while (!stop_wan_restart_thread) {
        char name[32] = {0};
        char val[32] = {0};
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        async_id_t getnotification_asyncid;
        int err = 0;

        err = sysevent_getnotification(sysevent_fd_local, sysevent_token_local, name, &namelen,  val, &vallen, &getnotification_asyncid);
        if(err) {
            log_message("WAN sysevent_getnotification failed with error: %d\n", err);
            sleep(2);
        } else {
            log_message("Received WAN sysevent notification: %s = %s\n", name, val);
            if (strcmp(name, "wan-restart") == 0) {
                log_message("WAN restart event received.\n");
                // Add timestamp to wan_restart_time in g_report.restart_count_stats
                char timestamp[64];
                get_current_timestamp(timestamp, sizeof(timestamp));
                restart_count_stats_t *stats = g_report.restart_count_stats;

                // Ensure wan_restart_time is initialized
                if (stats->wan_restart_time == NULL) {
                    stats->wan_restart_time = calloc(1, sizeof(char *));
                    if (stats->wan_restart_time == NULL) {
                        log_message("Failed to allocate initial memory for wan_restart_time\n");
                        continue;
                    }
                    stats->wan_restart_count = 0;
                }

                char **new_times = realloc(stats->wan_restart_time, (stats->wan_restart_count + 1) * sizeof(char *));
                if (new_times) {
                    stats->wan_restart_time = new_times;
                    stats->wan_restart_time[stats->wan_restart_count] = strdup(timestamp);
                    if (stats->wan_restart_time[stats->wan_restart_count]) {
                        stats->wan_restart_count++;
                        log_message("Added wan_restart_time: %s, count: %d\n", timestamp, stats->wan_restart_count);
                    } else {
                        log_message("Failed to allocate memory for wan_restart_time string\n");
                    }
                } else {
                    log_message("Failed to allocate memory for wan_restart_time\n");
                }
            }
        }
    }
    log_message("wan_restart_time_thread_func: Exiting thread.\n");
    return NULL;
}

int RestartCountStats_StartThread() {
    // Create the fw_restart_time collection thread
    stop_fw_restart_thread = false;
    if (pthread_create(&fw_restart_thread, NULL, fw_restart_time_thread_func, NULL) != 0) {
        log_message("Failed to create fw_restart_time thread.\n");
        return -1;
    } else {
        pthread_detach(fw_restart_thread);
    }

    // Create the wan_restart_time collection thread
    stop_wan_restart_thread = false;
    if (pthread_create(&wan_restart_thread, NULL, wan_restart_time_thread_func, NULL) != 0) {
        log_message("Failed to create wan_restart_time thread.\n");
        return -1;
    } else {
        pthread_detach(wan_restart_thread);
    }

    return 0;
}

int RestartCountStats_StopThread() {
    pthread_mutex_lock(&stats_mutex);
    stop_thread = true;
    pthread_cond_signal(&stats_cond); // Wake up the thread to exit
    pthread_mutex_unlock(&stats_mutex);

    // Signal fw_restart_time thread to stop
    stop_fw_restart_thread = true;

    // Signal wan_restart_time thread to stop
    stop_wan_restart_thread = true;
    // No join needed since thread is detached and just prints/logs for now

    return 0;
}
