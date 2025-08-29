#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ev.h>
#include <rbus/rbus.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>

#define UNUSED_PARAMETER(x) (void)(x)

#define MAX_WHITELISTED_NAMES 256
#define MAX_API_NAME_LEN 128

static char whitelisted_names[MAX_WHITELISTED_NAMES][MAX_API_NAME_LEN];
static int whitelist_count = 0;
static char whitelist_filename[512] = {0};

static struct ev_loop *loop = NULL;
static ev_stat whitelist_watcher;
static pthread_t watcher_thread;

// Load whitelist from file
static void reload_whitelist() {
    FILE *fp = fopen(whitelist_filename, "r");
    whitelist_count = 0;
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len && line[len-1] == '\n') line[len-1] = 0;
        if (whitelist_count < MAX_WHITELISTED_NAMES) {
            strncpy(whitelisted_names[whitelist_count], line, MAX_API_NAME_LEN-1);
            whitelisted_names[whitelist_count][MAX_API_NAME_LEN-1] = 0;
            whitelist_count++;
        }
    }
    fclose(fp);
}

// libev callback for file changes
static void whitelist_cb(EV_P_ ev_stat *w, int revents) {
    UNUSED_PARAMETER(w);
    UNUSED_PARAMETER(revents);
    reload_whitelist();
    printf("[Whitelist] Reloaded (%d names)\n", whitelist_count);
}

// Check if name is allowed
static int is_api_allowed(const char *name) {
    for (int i = 0; i < whitelist_count; ++i) {
        if (strcmp(name, whitelisted_names[i]) == 0)
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
    printf("Shared library loaded (C)\n");
    init_whitelist_monitor();
}

__attribute__((destructor))
void cleanup_library() {
    printf("Shared library unloaded (C)\n");
}

// ---- RBUS ----
rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] rbus_get denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] rbus_get called with name: %s\n", name);
    rbusError_t result = real_rbus_get(handle, name, value);
    if (result == RBUS_ERROR_SUCCESS && value) {
        const char* valStr = rbusValue_ToString(*value, NULL, 0);
        printf("[Intercepted] rbus_get returned value: %s\n", valStr);
    }
    return result;
}

rbusError_t rbus_set(rbusHandle_t handle, char const* name, rbusValue_t value, rbusSetOptions_t* opts) {
    if (!is_api_allowed(name)) {
        printf("[Denied] rbus_set denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] rbus_set called with name: %s\n", name);
    rbusError_t result = real_rbus_set(handle, name, value, opts);
    if (result == RBUS_ERROR_SUCCESS) {
        const char* valStr = rbusValue_ToString(value, NULL, 0);
        printf("[Intercepted] rbus_set set value: %s\n", valStr);
    }
    return result;
}

// ---- SYSEVENT ----
int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes) {
    if (!is_api_allowed(inbuf)) {
        printf("[Denied] sysevent_get denied for name: %s (not in whitelist). Exiting.\n", inbuf);
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
    printf("[Intercepted] sysevent_get called with fd: %d, token: %d, name: %s\n", fd, token, inbuf);
    int result = real_sysevent_get(fd, token, inbuf, outbuf, outbytes);
    printf("[Intercepted] sysevent_get returned: %d\n", result);
    return result;
}

int sysevent_set(const int fd, const token_t token, const char *name, const char *value, int conf_req) {
    if (!is_api_allowed(name)) {
        printf("[Denied] sysevent_set denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] sysevent_set called with fd: %d, token: %d, name: %s, value: %s, conf_req: %d\n", fd, token, name, value, conf_req);
    int result = real_sysevent_set(fd, token, name, value, conf_req);
    printf("[Intercepted] sysevent_set returned: %d\n", result);
    return result;
}

// ---- SYSCFG ----
int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_get denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_get called with ns: %s, name: %s\n", ns, name);
    int result = real_syscfg_get(ns, name, out_val, outbufsz);
    printf("[Intercepted] syscfg_get returned: %d, value: %s\n", result, out_val);
    return result;
}

int syscfg_set_ns(const char *ns, const char *name, const char *value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_ns denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_ns called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns(ns, name, value);
    printf("[Intercepted] syscfg_set_ns returned: %d\n", result);
    return result;
}

int syscfg_set_nns(const char *name, const char *value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_nns denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_nns called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns(name, value);
    printf("[Intercepted] syscfg_set_nns returned: %d\n", result);
    return result;
}

int syscfg_set_ns_commit(const char *ns, const char *name, const char *value)
{
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_ns_commit denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_ns_commit called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns_commit(ns, name, value);
    printf("[Intercepted] syscfg_set_ns_commit returned: %d\n", result);
    return result;
}

int syscfg_set_nns_commit(const char *name, const char *value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_nns_commit denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_nns_commit called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns_commit(name, value);
    printf("[Intercepted] syscfg_set_nns_commit returned: %d\n", result);
    return result;
}

int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_ns_u denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_ns_u called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u(ns, name, value);
    printf("[Intercepted] syscfg_set_ns_u returned: %d\n", result);
    return result;
}

int syscfg_set_nns_u(const char *name, unsigned long value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_nns_u denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_nns_u called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u(name, value);
    printf("[Intercepted] syscfg_set_nns_u returned: %d\n", result);
    return result;
}

int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_ns_u_commit denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_ns_u_commit called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u_commit(ns, name, value);
    printf("[Intercepted] syscfg_set_ns_u_commit returned: %d\n", result);
    return result;
}

int syscfg_set_nns_u_commit(const char *name, unsigned long value) {
    if (!is_api_allowed(name)) {
        printf("[Denied] syscfg_set_nns_u_commit denied for name: %s (not in whitelist). Exiting.\n", name);
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
    printf("[Intercepted] syscfg_set_nns_u_commit called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u_commit(name, value);
    printf("[Intercepted] syscfg_set_nns_u_commit returned: %d\n", result);
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
    printf("[Intercepted] syscfg_commit called\n");
    int result = real_syscfg_commit();
    printf("[Intercepted] syscfg_commit returned: %d\n", result);
    return result;
}
