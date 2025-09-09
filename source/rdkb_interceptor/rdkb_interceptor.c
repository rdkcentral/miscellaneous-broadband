#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ev.h>
#include <rbus/rbus.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <cjson/cJSON.h>
#include "rdkb_interceptor.h"

// Separate whitelists for get/set for each API
static char syscfg_get_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int syscfg_get_whitelist_count = 0;
static char syscfg_set_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int syscfg_set_whitelist_count = 0;

static char sysevent_get_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int sysevent_get_whitelist_count = 0;
static char sysevent_set_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int sysevent_set_whitelist_count = 0;

static char rbus_get_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int rbus_get_whitelist_count = 0;
static char rbus_set_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int rbus_set_whitelist_count = 0;

static char whitelist_filename[512] = {0};

static struct ev_loop *loop = NULL;
static ev_stat whitelist_watcher;
static pthread_t watcher_thread;

// Logging file pointer and logic for log redirection
static FILE *interceptor_log_fp = NULL;
static pthread_once_t log_fp_once_control = PTHREAD_ONCE_INIT;

static void init_log_fp() {
    const char *logfile = getenv("RDKB_INTERCEPTOR_LOGFILE");
    if (logfile && *logfile) {
        interceptor_log_fp = fopen(logfile, "a");
        if (!interceptor_log_fp) {
            interceptor_log_fp = stderr;
        }
    } else {
        interceptor_log_fp = stderr;
    }
}

static FILE *get_log_fp() {
    pthread_once(&log_fp_once_control, init_log_fp);
    return interceptor_log_fp;
}

// Macro for logging
#define INTERCEPTOR_LOG(fmt, ...) \
    do { \
        FILE *fp = get_log_fp(); \
        if ((fmt)[strlen(fmt) - 1] == '\n') { \
            fprintf(fp, fmt, ##__VA_ARGS__); \
        } else { \
            fprintf(fp, fmt "\n", ##__VA_ARGS__); \
        } \
        fflush(fp); \
    } while(0)

// Load whitelist from JSON file using cJSON
// Now expects JSON like:
// {
//   "syscfg": { "get": ["foo"], "set": ["bar"] },
//   "sysevent": { "get": ["foo"], "set": ["bar"] },
//   "rbus": { "get": ["foo"], "set": ["bar"] }
// }

static void reload_whitelist() {
    if (whitelist_filename[0] == '\0') {
        fprintf(stderr, "Whitelist filename is empty, cannot open file.\n");
        return;
    }
    FILE *fp = fopen(whitelist_filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open whitelist file: %s\n", whitelist_filename);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) {
        fclose(fp);
        return;
    }
    char *json_data = malloc(fsize + 1);
    if (!json_data) {
        fclose(fp);
        return;
    }
    size_t bytes_read = fread(json_data, 1, fsize, fp);
    if (bytes_read != (size_t)fsize) {
        free(json_data);
        fclose(fp);
        return;
    }
    json_data[fsize] = 0;
    fclose(fp);

    cJSON *parsed_json = cJSON_Parse(json_data);
    free(json_data);
    if (!parsed_json) return;

    // Reset all whitelists
    syscfg_get_whitelist_count = 0;
    syscfg_set_whitelist_count = 0;
    sysevent_get_whitelist_count = 0;
    sysevent_set_whitelist_count = 0;
    rbus_get_whitelist_count = 0;
    rbus_set_whitelist_count = 0;

    cJSON *api_obj, *arr;
    int i, arrlen;
    // syscfg
    api_obj = cJSON_GetObjectItem(parsed_json, "syscfg");
    if (api_obj && cJSON_IsObject(api_obj)) {
        // get
        arr = cJSON_GetObjectItem(api_obj, "get");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && syscfg_get_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(syscfg_get_whitelisted_names[syscfg_get_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    syscfg_get_whitelisted_names[syscfg_get_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    syscfg_get_whitelist_count++;
                }
            }
        }
        // set
        arr = cJSON_GetObjectItem(api_obj, "set");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && syscfg_set_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(syscfg_set_whitelisted_names[syscfg_set_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    syscfg_set_whitelisted_names[syscfg_set_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    syscfg_set_whitelist_count++;
                }
            }
        }
    }
    // sysevent
    api_obj = cJSON_GetObjectItem(parsed_json, "sysevent");
    if (api_obj && cJSON_IsObject(api_obj)) {
        // get
        arr = cJSON_GetObjectItem(api_obj, "get");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && sysevent_get_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(sysevent_get_whitelisted_names[sysevent_get_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    sysevent_get_whitelisted_names[sysevent_get_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    sysevent_get_whitelist_count++;
                }
            }
        }
        // set
        arr = cJSON_GetObjectItem(api_obj, "set");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && sysevent_set_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(sysevent_set_whitelisted_names[sysevent_set_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    sysevent_set_whitelisted_names[sysevent_set_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    sysevent_set_whitelist_count++;
                }
            }
        }
    }
    // rbus
    api_obj = cJSON_GetObjectItem(parsed_json, "rbus");
    if (api_obj && cJSON_IsObject(api_obj)) {
        // get
        arr = cJSON_GetObjectItem(api_obj, "get");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && rbus_get_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(rbus_get_whitelisted_names[rbus_get_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    rbus_get_whitelisted_names[rbus_get_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    rbus_get_whitelist_count++;
                }
            }
        }
        // set
        arr = cJSON_GetObjectItem(api_obj, "set");
        if (arr && cJSON_IsArray(arr)) {
            arrlen = cJSON_GetArraySize(arr);
            for (i = 0; i < arrlen && rbus_set_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(rbus_set_whitelisted_names[rbus_set_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                    rbus_set_whitelisted_names[rbus_set_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                    rbus_set_whitelist_count++;
                }
            }
        }
    }
    cJSON_Delete(parsed_json);
}

// libev callback for file changes
static void whitelist_cb(EV_P_ ev_stat *w, int revents) {
    UNUSED_PARAMETER(w);
    UNUSED_PARAMETER(revents);
    reload_whitelist();
    INTERCEPTOR_LOG(
        "[Whitelist] Reloaded (syscfg: %d, sysevent: %d, rbus: %d names)\n",
        syscfg_get_whitelist_count + syscfg_set_whitelist_count,
        sysevent_get_whitelist_count + sysevent_set_whitelist_count,
        rbus_get_whitelist_count + rbus_set_whitelist_count
    );
}

// Check if name is allowed for syscfg get
static int is_syscfg_get_api_allowed(const char *name) {
    for (int i = 0; i < syscfg_get_whitelist_count; ++i) {
        if (strcmp(name, syscfg_get_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}
// Check if name is allowed for syscfg set
static int is_syscfg_set_api_allowed(const char *name) {
    for (int i = 0; i < syscfg_set_whitelist_count; ++i) {
        if (strcmp(name, syscfg_set_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}
// Check if name is allowed for sysevent get
static int is_sysevent_get_api_allowed(const char *name) {
    for (int i = 0; i < sysevent_get_whitelist_count; ++i) {
        if (strcmp(name, sysevent_get_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}
// Check if name is allowed for sysevent set
static int is_sysevent_set_api_allowed(const char *name) {
    for (int i = 0; i < sysevent_set_whitelist_count; ++i) {
        if (strcmp(name, sysevent_set_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}
// Check if name is allowed for rbus get
static int is_rbus_get_api_allowed(const char *name) {
    for (int i = 0; i < rbus_get_whitelist_count; ++i) {
        if (strcmp(name, rbus_get_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}
// Check if name is allowed for rbus set
static int is_rbus_set_api_allowed(const char *name) {
    for (int i = 0; i < rbus_set_whitelist_count; ++i) {
        if (strcmp(name, rbus_set_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}

// Thread function to run the libev event loop
static void *whitelist_watcher_thread(void *arg) {
    (void)arg;
    ev_run(loop, 0);
    return NULL;
}

static pthread_once_t whitelist_monitor_once = PTHREAD_ONCE_INIT;

// Initializes the whitelist monitoring system, sets up the event loop, and starts the watcher thread if the WHITELIST_FILE environment variable is set.
static void init_whitelist_monitor_once(void) {
    if (loop) return;
    const char *env = getenv("WHITELIST_FILE");
    if (!env || !*env) {
        fprintf(stderr, "WHITELIST_FILE env variable not set\n");
        return;
    }
    if (strlen(env) >= sizeof(whitelist_filename) - 1) {
        INTERCEPTOR_LOG("Error: WHITELIST_FILE path too long (%zu bytes). Maximum allowed length is %zu bytes. Initialization aborted.\n", strlen(env), sizeof(whitelist_filename)-1);
        return;
    }
    strncpy(whitelist_filename, env, sizeof(whitelist_filename)-1);
    whitelist_filename[sizeof(whitelist_filename)-1] = '\0';
    loop = ev_default_loop(0);
    if (!loop) {
        fprintf(stderr, "Failed to initialize libev default loop\n");
        return;
    }

    // Initialize and start the ev_stat watcher for the whitelist file
    ev_stat_init(&whitelist_watcher, whitelist_cb, whitelist_filename, 0.);
    ev_stat_start(loop, &whitelist_watcher);

    // Initial load of the whitelist
    reload_whitelist();

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&watcher_thread, &attr, whitelist_watcher_thread, NULL);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        INTERCEPTOR_LOG("Failed to create whitelist watcher thread: %s\n", strerror(rc));
        if (loop) {
            ev_stat_stop(loop, &whitelist_watcher);
            ev_loop_destroy(loop);
            loop = NULL; // Reset loop so that init can be retried safely
        }
    }
}

// Initializes the whitelist monitor exactly once using pthread_once.
// This ensures the whitelist file watcher is set up only a single time per process.
static void init_whitelist_monitor() {
    pthread_once(&whitelist_monitor_once, init_whitelist_monitor_once);
}

__attribute__((constructor))
void init_library() {
    INTERCEPTOR_LOG("RDK-B Interceptor shared library loaded\n");
    init_whitelist_monitor();
}

rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value)
{
    static rbus_get_func_t real_rbus_get = NULL;
    if (!is_rbus_get_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] rbus_get denied for name: %s (not in rbus get whitelist). Exiting.\n", name);
        return RBUS_ERROR_BUS_ERROR;
    }
    if (!real_rbus_get) {
        real_rbus_get = DLSYM_FN(rbus_get_func_t, "rbus_get");
        if (!real_rbus_get) {
            fprintf(stderr, "Error resolving original rbus_get\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] rbus_get called with name: %s\n", name);
    rbusError_t result = real_rbus_get(handle, name, value);
    return result;
}

rbusError_t rbus_set(rbusHandle_t handle, const char* name, rbusValue_t value, rbusSetOptions_t* opts)
{
    static rbus_set_func_t real_rbus_set = NULL;
    if (!is_rbus_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] rbus_set denied for name: %s (not in rbus set whitelist). Exiting.\n", name);
        return RBUS_ERROR_BUS_ERROR;
    }
    if (!real_rbus_set) {
        real_rbus_set = DLSYM_FN(rbus_set_func_t, "rbus_set");
        if (!real_rbus_set) {
            fprintf(stderr, "Error resolving original rbus_set\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] rbus_set called with name: %s\n", name);
    rbusError_t result = real_rbus_set(handle, name, value, opts);
    return result;
}

int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes)
{
    static sysevent_get_func_t real_sysevent_get = NULL;
    if (!is_sysevent_get_api_allowed(inbuf)) {
        INTERCEPTOR_LOG("[Denied] sysevent_get denied for name: %s (not in sysevent get whitelist). Exiting.\n", inbuf);
        return -1;
    }
    if (!real_sysevent_get) {
        real_sysevent_get = DLSYM_FN(sysevent_get_func_t, "sysevent_get");
        if (!real_sysevent_get) {
            fprintf(stderr, "Error resolving original sysevent_get\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] sysevent_get called with fd: %d, token: %d, name: %s\n", fd, token, inbuf);
    int result = real_sysevent_get(fd, token, inbuf, outbuf, outbytes);
    return result;
}

int sysevent_set(const int fd, const token_t token, const char *name, const char *value,  int conf_req)
{
    static sysevent_set_func_t real_sysevent_set = NULL;
    if (!is_sysevent_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] sysevent_set denied for name: %s (not in sysevent set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_sysevent_set) {
        real_sysevent_set = DLSYM_FN(sysevent_set_func_t, "sysevent_set");
        if (!real_sysevent_set) {
            fprintf(stderr, "Error resolving original sysevent_set\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] sysevent_set called with fd: %d, token: %d, name: %s, value: %s, conf_req: %d\n", fd, token, name, value, conf_req);
    int result = real_sysevent_set(fd, token, name, value, conf_req);
    return result;
}

int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz)
{
    static syscfg_get_func_t real_syscfg_get = NULL;
    if (!is_syscfg_get_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_get denied in function syscfg_get for name: %s (not in syscfg get whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_get) {
        real_syscfg_get = DLSYM_FN(syscfg_get_func_t, "syscfg_get");
        if (!real_syscfg_get) {
            fprintf(stderr, "Error resolving original syscfg_get\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_get called with ns: %s, name: %s\n", ns, name);
    int result = real_syscfg_get(ns, name, out_val, outbufsz);
    return result;
}

int syscfg_set_ns(const char *ns, const char *name, const char *value)
{
    static syscfg_set_ns_func_t real_syscfg_set_ns = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_ns denied for name: %s (function: syscfg_set_ns, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns) {
        real_syscfg_set_ns = DLSYM_FN(syscfg_set_ns_func_t, "syscfg_set_ns");
        if (!real_syscfg_set_ns) {
            fprintf(stderr, "Error resolving original syscfg_set_ns\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns(ns, name, value);
    return result;
}

int syscfg_set_nns(const char *name, const char *value)
{
    static syscfg_set_nns_func_t real_syscfg_set_nns = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_nns denied in function syscfg_set_nns for name: %s (not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns) {
        real_syscfg_set_nns = DLSYM_FN(syscfg_set_nns_func_t, "syscfg_set_nns");
        if (!real_syscfg_set_nns) {
            fprintf(stderr, "Error resolving original syscfg_set_nns\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns(name, value);
    return result;
}

int syscfg_set_ns_commit(const char *ns, const char *name, const char *value)
{
    static syscfg_set_ns_func_t real_syscfg_set_ns_commit = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_ns_commit denied for name: %s (function: syscfg_set_ns_commit, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_commit) {
        real_syscfg_set_ns_commit = DLSYM_FN(syscfg_set_ns_func_t, "syscfg_set_ns_commit");
        if (!real_syscfg_set_ns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_commit called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns_commit(ns, name, value);
    return result;
}

int syscfg_set_nns_commit(const char *name, const char *value)
{
    static syscfg_set_nns_func_t real_syscfg_set_nns_commit = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_nns_commit denied for name: %s (function: syscfg_set_nns_commit, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_commit) {
        real_syscfg_set_nns_commit = DLSYM_FN(syscfg_set_nns_func_t, "syscfg_set_nns_commit");
        if (!real_syscfg_set_nns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_commit called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns_commit(name, value);
    return result;
}

int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value)
{
    static syscfg_set_ns_u_func_t real_syscfg_set_ns_u = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_ns_u denied for name: %s (function: syscfg_set_ns_u, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_u) {
        real_syscfg_set_ns_u = DLSYM_FN(syscfg_set_ns_u_func_t, "syscfg_set_ns_u");
        if (!real_syscfg_set_ns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u(ns, name, value);
    return result;
}

int syscfg_set_nns_u(const char *name, unsigned long value)
{
    static syscfg_set_nns_u_func_t real_syscfg_set_nns_u = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_nns_u denied for name: %s (function: syscfg_set_nns_u, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_u) {
        real_syscfg_set_nns_u = DLSYM_FN(syscfg_set_nns_u_func_t, "syscfg_set_nns_u");
        if (!real_syscfg_set_nns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u(name, value);
    return result;
}

int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value)
{
    static syscfg_set_ns_u_func_t real_syscfg_set_ns_u_commit = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_ns_u_commit denied for name: %s (function: syscfg_set_ns_u_commit, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_u_commit) {
        real_syscfg_set_ns_u_commit = DLSYM_FN(syscfg_set_ns_u_func_t, "syscfg_set_ns_u_commit");
        if (!real_syscfg_set_ns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u_commit called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u_commit(ns, name, value);
    return result;
}

int syscfg_set_nns_u_commit(const char *name, unsigned long value)
{
    static syscfg_set_nns_u_func_t real_syscfg_set_nns_u_commit = NULL;
    if (!is_syscfg_set_api_allowed(name)) {
        INTERCEPTOR_LOG("[Denied] syscfg_set_nns_u_commit denied for name: %s (function: syscfg_set_nns_u_commit, not in syscfg set whitelist). Exiting.\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_u_commit) {
        real_syscfg_set_nns_u_commit = DLSYM_FN(syscfg_set_nns_u_func_t, "syscfg_set_nns_u_commit");
        if (!real_syscfg_set_nns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u_commit called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u_commit(name, value);
    return result;
}

int syscfg_commit(void)
{
    static syscfg_commit_func_t real_syscfg_commit = NULL;
    if (!real_syscfg_commit) {
        real_syscfg_commit = DLSYM_FN(syscfg_commit_func_t, "syscfg_commit");
        if (!real_syscfg_commit) {
            fprintf(stderr, "Error resolving original syscfg_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_commit called\n");
    int result = real_syscfg_commit();
    return result;
}