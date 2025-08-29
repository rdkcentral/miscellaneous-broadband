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

#define UNUSED_PARAMETER(x) (void)(x)


#define MAX_WHITELISTED_NAMES 256
#define MAX_API_NAME_LEN 128

static char syscfg_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int syscfg_whitelist_count = 0;
static char sysevent_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int sysevent_whitelist_count = 0;
static char rbus_whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int rbus_whitelist_count = 0;
static char whitelist_filename[512] = {0};

static struct ev_loop *loop = NULL;
static ev_stat whitelist_watcher;
static pthread_t watcher_thread;

// Debug logging macro
static bool is_debug_enabled() {
    static int checked = 0;
    static int enabled = 0;
    if (!checked) {
        const char *env = getenv("RDKB_INTERCEPTOR_DEBUG");
        enabled = (env && strcmp(env, "1") == 0);
        checked = 1;
    }
    return enabled;
}
#define INTERCEPTOR_LOG(fmt, ...) \
    do { if (is_debug_enabled()) fprintf(stderr, fmt, ##__VA_ARGS__); } while(0)

// Load whitelist from JSON file using cJSON
static void reload_whitelist() {
    FILE *fp = fopen(whitelist_filename, "r");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_data = malloc(fsize + 1);
    if (!json_data) {
        fclose(fp);
        return;
    }
    fread(json_data, 1, fsize, fp);
    json_data[fsize] = 0;
    fclose(fp);

    cJSON *parsed_json = cJSON_Parse(json_data);
    free(json_data);
    if (!parsed_json) return;

    // Reset all whitelists
    syscfg_whitelist_count = 0;
    sysevent_whitelist_count = 0;
    rbus_whitelist_count = 0;

    cJSON *arr;
    int i, arrlen;
    // syscfg
    arr = cJSON_GetObjectItem(parsed_json, "syscfg");
    if (arr && cJSON_IsArray(arr)) {
        arrlen = cJSON_GetArraySize(arr);
        for (i = 0; i < arrlen && syscfg_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
            cJSON *item = cJSON_GetArrayItem(arr, i);
            if (cJSON_IsString(item)) {
                strncpy(syscfg_whitelisted_names[syscfg_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                syscfg_whitelisted_names[syscfg_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                syscfg_whitelist_count++;
            }
        }
    }
    // sysevent
    arr = cJSON_GetObjectItem(parsed_json, "sysevent");
    if (arr && cJSON_IsArray(arr)) {
        arrlen = cJSON_GetArraySize(arr);
        for (i = 0; i < arrlen && sysevent_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
            cJSON *item = cJSON_GetArrayItem(arr, i);
            if (cJSON_IsString(item)) {
                strncpy(sysevent_whitelisted_names[sysevent_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                sysevent_whitelisted_names[sysevent_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                sysevent_whitelist_count++;
            }
        }
    }
    // rbus
    arr = cJSON_GetObjectItem(parsed_json, "rbus");
    if (arr && cJSON_IsArray(arr)) {
        arrlen = cJSON_GetArraySize(arr);
        for (i = 0; i < arrlen && rbus_whitelist_count < MAX_WHITELISTED_NAMES; ++i) {
            cJSON *item = cJSON_GetArrayItem(arr, i);
            if (cJSON_IsString(item)) {
                strncpy(rbus_whitelisted_names[rbus_whitelist_count], item->valuestring, MAX_API_NAME_LEN-1);
                rbus_whitelisted_names[rbus_whitelist_count][MAX_API_NAME_LEN-1] = 0;
                rbus_whitelist_count++;
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
    INTERCEPTOR_LOG("[Whitelist] Reloaded (syscfg: %d, sysevent: %d, rbus: %d names)\n", syscfg_whitelist_count, sysevent_whitelist_count, rbus_whitelist_count);
}


// Check if name is allowed for syscfg
static int is_syscfg_api_allowed(const char *name) {
    for (int i = 0; i < syscfg_whitelist_count; ++i) {
        if (strcmp(name, syscfg_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}

// Check if name is allowed for sysevent
static int is_sysevent_api_allowed(const char *name) {
    for (int i = 0; i < sysevent_whitelist_count; ++i) {
        if (strcmp(name, sysevent_whitelisted_names[i]) == 0)
            return 1;
    }
    return 0;
}

// Check if name is allowed for rbus
static int is_rbus_api_allowed(const char *name) {
    for (int i = 0; i < rbus_whitelist_count; ++i) {
        if (strcmp(name, rbus_whitelisted_names[i]) == 0)
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

// Initialize whitelist watcher (call once)
static void init_whitelist_monitor() {
    if (loop) return;
    const char *env = getenv("WHITELIST_FILE");
    if (!env || !*env) {
        fprintf(stderr, "WHITELIST_FILE env variable not set\n");
        return;
    }
    strncpy(whitelist_filename, env, sizeof(whitelist_filename)-1);
    whitelist_filename[sizeof(whitelist_filename)-1] = 0;
    loop = ev_default_loop(0);
    reload_whitelist();
    ev_stat_init(&whitelist_watcher, whitelist_cb, whitelist_filename, 0.);
    ev_stat_start(loop, &whitelist_watcher);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&watcher_thread, &attr, whitelist_watcher_thread, NULL);
    pthread_attr_destroy(&attr);
}

__attribute__((constructor))
void init_library() {
    INTERCEPTOR_LOG("Shared library loaded (C)\n");
    init_whitelist_monitor();
}

__attribute__((destructor))
void cleanup_library() {
    INTERCEPTOR_LOG("Shared library unloaded (C)\n");
}


// ---- RBUS ----
rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value) {
    if (!is_rbus_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] rbus_get denied for name: %s (not in rbus whitelist). Exiting.\n", name);
        exit(1);
    }
    static rbusError_t (*real_rbus_get)(rbusHandle_t, const char*, rbusValue_t*) = NULL;
    if (!real_rbus_get) {
        real_rbus_get = dlsym(RTLD_NEXT, "rbus_get");
        if (!real_rbus_get) {
            fprintf(stderr, "Error resolving original rbus_get\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] rbus_get called with name: %s\n", name);
    rbusError_t result = real_rbus_get(handle, name, value);
    if (result == RBUS_ERROR_SUCCESS && value) {
        const char* valStr = rbusValue_ToString(*value, NULL, 0);
    INTERCEPTOR_LOG("[Intercepted] rbus_get returned value: %s\n", valStr);
    }
    return result;
}

rbusError_t rbus_set(rbusHandle_t handle, char const* name, rbusValue_t value, rbusSetOptions_t* opts) {
    if (!is_rbus_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] rbus_set denied for name: %s (not in rbus whitelist). Exiting.\n", name);
        exit(1);
    }
    static rbusError_t (*real_rbus_set)(rbusHandle_t, char const*, rbusValue_t, rbusSetOptions_t*) = NULL;
    if (!real_rbus_set) {
        real_rbus_set = dlsym(RTLD_NEXT, "rbus_set");
        if (!real_rbus_set) {
            fprintf(stderr, "Error resolving original rbus_set\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] rbus_set called with name: %s\n", name);
    rbusError_t result = real_rbus_set(handle, name, value, opts);
    if (result == RBUS_ERROR_SUCCESS) {
        const char* valStr = rbusValue_ToString(value, NULL, 0);
    INTERCEPTOR_LOG("[Intercepted] rbus_set set value: %s\n", valStr);
    }
    return result;
}

// ---- SYSEVENT ----
int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
    if (!is_sysevent_api_allowed(inbuf)) {
    INTERCEPTOR_LOG("[Denied] sysevent_get denied for name: %s (not in sysevent whitelist). Exiting.\n", inbuf);
        exit(1);
    }
    static int (*real_sysevent_get)(const int, const token_t, const char *, char *, int) = NULL;
    if (!real_sysevent_get) {
        real_sysevent_get = dlsym(RTLD_NEXT, "sysevent_get");
        if (!real_sysevent_get) {
            fprintf(stderr, "Error resolving original sysevent_get\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] sysevent_get called with fd: %d, token: %d, name: %s\n", fd, token, inbuf);
    int result = real_sysevent_get(fd, token, inbuf, outbuf, outbytes);
    INTERCEPTOR_LOG("[Intercepted] sysevent_get returned: %d\n", result);
    return result;
}

int sysevent_set(const int fd, const token_t token, const char *name, const char *value, int conf_req) {
    if (!is_sysevent_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] sysevent_set denied for name: %s (not in sysevent whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_sysevent_set)(const int, const token_t, const char *, const char *, int) = NULL;
    if (!real_sysevent_set) {
        real_sysevent_set = dlsym(RTLD_NEXT, "sysevent_set");
        if (!real_sysevent_set) {
            fprintf(stderr, "Error resolving original sysevent_set\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] sysevent_set called with fd: %d, token: %d, name: %s, value: %s, conf_req: %d\n", fd, token, name, value, conf_req);
    int result = real_sysevent_set(fd, token, name, value, conf_req);
    INTERCEPTOR_LOG("[Intercepted] sysevent_set returned: %d\n", result);
    return result;
}

// ---- SYSCFG ----
int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_get denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_get)(const char *, const char *, char *, int) = NULL;
    if (!real_syscfg_get) {
        real_syscfg_get = dlsym(RTLD_NEXT, "syscfg_get");
        if (!real_syscfg_get) {
            fprintf(stderr, "Error resolving original syscfg_get\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_get called with ns: %s, name: %s\n", ns, name);
    int result = real_syscfg_get(ns, name, out_val, outbufsz);
    INTERCEPTOR_LOG("[Intercepted] syscfg_get returned: %d, value: %s\n", result, out_val);
    return result;
}

int syscfg_set_ns(const char *ns, const char *name, const char *value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_ns denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_ns)(const char *, const char *, const char *) = NULL;
    if (!real_syscfg_set_ns) {
        real_syscfg_set_ns = dlsym(RTLD_NEXT, "syscfg_set_ns");
        if (!real_syscfg_set_ns) {
            fprintf(stderr, "Error resolving original syscfg_set_ns\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns(ns, name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns returned: %d\n", result);
    return result;
}

int syscfg_set_nns(const char *name, const char *value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_nns denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_nns)(const char *, const char *) = NULL;
    if (!real_syscfg_set_nns) {
        real_syscfg_set_nns = dlsym(RTLD_NEXT, "syscfg_set_nns");
        if (!real_syscfg_set_nns) {
            fprintf(stderr, "Error resolving original syscfg_set_nns\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns(name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns returned: %d\n", result);
    return result;
}

int syscfg_set_ns_commit(const char *ns, const char *name, const char *value)
{
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_ns_commit denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_ns_commit)(const char *, const char *, const char *) = NULL;
    if (!real_syscfg_set_ns_commit) {
        real_syscfg_set_ns_commit = dlsym(RTLD_NEXT, "syscfg_set_ns_commit");
        if (!real_syscfg_set_ns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_commit called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns_commit(ns, name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_commit returned: %d\n", result);
    return result;
}

int syscfg_set_nns_commit(const char *name, const char *value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_nns_commit denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_nns_commit)(const char *, const char *) = NULL;
    if (!real_syscfg_set_nns_commit) {
        real_syscfg_set_nns_commit = dlsym(RTLD_NEXT, "syscfg_set_nns_commit");
        if (!real_syscfg_set_nns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_commit called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns_commit(name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_commit returned: %d\n", result);
    return result;
}

int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_ns_u denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_ns_u)(const char *, const char *, unsigned long) = NULL;
    if (!real_syscfg_set_ns_u) {
        real_syscfg_set_ns_u = dlsym(RTLD_NEXT, "syscfg_set_ns_u");
        if (!real_syscfg_set_ns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u(ns, name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u returned: %d\n", result);
    return result;
}

int syscfg_set_nns_u(const char *name, unsigned long value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_nns_u denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_nns_u)(const char *, unsigned long) = NULL;
    if (!real_syscfg_set_nns_u) {
        real_syscfg_set_nns_u = dlsym(RTLD_NEXT, "syscfg_set_nns_u");
        if (!real_syscfg_set_nns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u(name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u returned: %d\n", result);
    return result;
}

int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_ns_u_commit denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_ns_u_commit)(const char *, const char *, unsigned long) = NULL;
    if (!real_syscfg_set_ns_u_commit) {
        real_syscfg_set_ns_u_commit = dlsym(RTLD_NEXT, "syscfg_set_ns_u_commit");
        if (!real_syscfg_set_ns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u_commit called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u_commit(ns, name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_ns_u_commit returned: %d\n", result);
    return result;
}

int syscfg_set_nns_u_commit(const char *name, unsigned long value) {
    if (!is_syscfg_api_allowed(name)) {
    INTERCEPTOR_LOG("[Denied] syscfg_set_nns_u_commit denied for name: %s (not in syscfg whitelist). Exiting.\n", name);
        exit(1);
    }
    static int (*real_syscfg_set_nns_u_commit)(const char *, unsigned long) = NULL;
    if (!real_syscfg_set_nns_u_commit) {
        real_syscfg_set_nns_u_commit = dlsym(RTLD_NEXT, "syscfg_set_nns_u_commit");
        if (!real_syscfg_set_nns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u_commit called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u_commit(name, value);
    INTERCEPTOR_LOG("[Intercepted] syscfg_set_nns_u_commit returned: %d\n", result);
    return result;
}

int syscfg_commit(void) {
    // No name parameter, allow by default
    static int (*real_syscfg_commit)(void) = NULL;
    if (!real_syscfg_commit) {
        real_syscfg_commit = dlsym(RTLD_NEXT, "syscfg_commit");
        if (!real_syscfg_commit) {
            fprintf(stderr, "Error resolving original syscfg_commit\n");
            return -1;
        }
    }
    INTERCEPTOR_LOG("[Intercepted] syscfg_commit called\n");
    int result = real_syscfg_commit();
    INTERCEPTOR_LOG("[Intercepted] syscfg_commit returned: %d\n", result);
    return result;
}
