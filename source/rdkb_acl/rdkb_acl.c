#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <ev.h>
#include <rbus/rbus.h>
#include <rbus/rbuscore_message.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <cjson/cJSON.h>
#include "rdkb_acl.h"

static rbusError_t CCSPError_to_rbusError(rtError e)
{
  rbusError_t err;
  switch (e)
  {
    case RBUS_LEGACY_ERR_SUCCESS:
      err = RBUS_ERROR_SUCCESS;
      break;
    case RBUS_LEGACY_ERR_MEMORY_ALLOC_FAIL:
      err = RBUS_ERROR_OUT_OF_RESOURCES;
      break;
    case RBUS_LEGACY_ERR_FAILURE:
      err = RBUS_ERROR_BUS_ERROR;
      break;
    case RBUS_LEGACY_ERR_NOT_CONNECT:
      err = RBUS_ERROR_OUT_OF_RESOURCES;
      break;
    case RBUS_LEGACY_ERR_TIMEOUT:
      err = RBUS_ERROR_TIMEOUT;
      break;
    case RBUS_LEGACY_ERR_NOT_EXIST:
      err = RBUS_ERROR_DESTINATION_NOT_FOUND;
      break;
    case RBUS_LEGACY_ERR_NOT_SUPPORT:
      err = RBUS_ERROR_BUS_ERROR;
      break;
    case RBUS_LEGACY_ERR_RESOURCE_EXCEEDED:
      err = RBUS_ERROR_OUT_OF_RESOURCES;
      break;
    case RBUS_LEGACY_ERR_INVALID_PARAMETER_NAME:
      err = RBUS_ERROR_INVALID_NAMESPACE;
      break;
    case RBUS_LEGACY_ERR_INVALID_PARAMETER_TYPE:
      err = RBUS_ERROR_INVALID_PARAMETER_TYPE;
      break;
    case RBUS_LEGACY_ERR_INVALID_PARAMETER_VALUE:
     err = RBUS_ERROR_INVALID_PARAMETER_VALUE;
     break;
    case RBUS_LEGACY_ERR_NOT_WRITABLE:
     err = RBUS_ERROR_NOT_WRITABLE;
     break;
    default:
      err = RBUS_ERROR_BUS_ERROR;
      break;
  }
  return err;
}

static acl_mode_t acl_mode = MODE_DENY_ALL;

static char syscfg_get_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int syscfg_get_count = 0;
static char syscfg_set_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int syscfg_set_count = 0;

static char sysevent_get_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int sysevent_get_count = 0;
static char sysevent_set_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int sysevent_set_count = 0;

static char rbus_get_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int rbus_get_count = 0;
static char rbus_set_list[MAX_ACL_NAMES][MAX_API_NAME_LEN] = {0};
static int rbus_set_count = 0;

static char acl_json_filename[512] = {0};
static pthread_mutex_t reload_acllist_mutex = PTHREAD_MUTEX_INITIALIZER;

static rbus_get_func_t real_rbus_get = NULL;
static rbus_set_func_t real_rbus_set = NULL;
static sysevent_get_func_t real_sysevent_get = NULL;
static sysevent_set_func_t real_sysevent_set = NULL;
static syscfg_get_func_t real_syscfg_get = NULL;
static syscfg_set_ns_func_t real_syscfg_set_ns = NULL;
static syscfg_set_nns_func_t real_syscfg_set_nns = NULL;
static syscfg_set_ns_func_t real_syscfg_set_ns_commit = NULL;
static syscfg_set_nns_func_t real_syscfg_set_nns_commit = NULL;
static syscfg_set_ns_u_func_t real_syscfg_set_ns_u = NULL;
static syscfg_set_nns_u_func_t real_syscfg_set_nns_u = NULL;
static syscfg_set_ns_u_func_t real_syscfg_set_ns_u_commit = NULL;
static syscfg_set_nns_u_func_t real_syscfg_set_nns_u_commit = NULL;
static rbus_getExt_func_t real_rbus_getExt = NULL;

static FILE *acl_log_fp = NULL;

// Macro for logging
#define ACL_LOG(fmt, ...) \
    do { \
        if (acl_log_fp) { \
            fprintf(acl_log_fp, fmt, ##__VA_ARGS__); \
            fflush(acl_log_fp); \
        } \
    } while(0)

// Load acllist from JSON file using cJSON
// Now expects JSON like:
// {
//   "mode": "deny_all",
//   "syscfg": { "get": ["foo", "bar"], "set": ["baz"] },
//   "sysevent": { "get": ["foo", "bar"], "set": ["baz"] },
//   "rbus": { "get": ["foo", "bar"], "set": ["baz"] }
// }

static acl_mode_t parse_acl_mode(const char *mode_str) {
    if (!mode_str) return MODE_DENY_ALL;
    if (strcmp(mode_str, "allow_all") == 0) return MODE_ALLOW_ALL;
    if (strcmp(mode_str, "deny_all") == 0) return MODE_DENY_ALL;
    if (strcmp(mode_str, "allow_with_selective_blocklist") == 0) return MODE_ALLOW_WITH_SELECTIVE_BLOCKLIST;
    if (strcmp(mode_str, "deny_with_selective_whitelist") == 0) return MODE_DENY_WITH_SELECTIVE_WHITELIST;
    return MODE_DENY_ALL;
}

const char* acl_mode_to_string(acl_mode_t mode) {
    switch (mode) {
        case MODE_ALLOW_ALL:
            return "allow_all";
        case MODE_DENY_ALL:
            return "deny_all";
        case MODE_ALLOW_WITH_SELECTIVE_BLOCKLIST:
            return "allow_with_selective_blocklist";
        case MODE_DENY_WITH_SELECTIVE_WHITELIST:
            return "deny_with_selective_whitelist";
        default:
            return "unknown_mode";
    }
}

static void reload_acllist() {
    ACL_LOG("Inside %s\n", __FUNCTION__);
    if (acl_json_filename[0] == '\0') {
        fprintf(stderr, "acllist filename is empty, cannot open file.\n");
        return;
    }
    FILE *fp = fopen(acl_json_filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open acllist file: %s\n", acl_json_filename);
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
    if (!parsed_json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        ACL_LOG("Failed to parse acllist JSON file: %s. Error at: %s\n", acl_json_filename, error_ptr ? error_ptr : "unknown location");
        free(json_data);
        return;
    }
    ACL_LOG("Successfully parsed acllist JSON file: %s\n", acl_json_filename);
    free(json_data);

    // Reset all
    syscfg_get_count = syscfg_set_count = 0;
    sysevent_get_count = sysevent_set_count = 0;
    rbus_get_count = rbus_set_count = 0;
    acl_mode = MODE_DENY_ALL;
    memset(syscfg_get_list, 0, sizeof(syscfg_get_list));
    memset(syscfg_set_list, 0, sizeof(syscfg_set_list));
    memset(sysevent_get_list, 0, sizeof(sysevent_get_list));
    memset(sysevent_set_list, 0, sizeof(sysevent_set_list));
    memset(rbus_get_list, 0, sizeof(rbus_get_list));
    memset(rbus_set_list, 0, sizeof(rbus_set_list));

    cJSON *mode_item = cJSON_GetObjectItem(parsed_json, "mode");
    acl_mode = parse_acl_mode(cJSON_IsString(mode_item) ? mode_item->valuestring : NULL);

    // Early exit for allow_all or deny_all
    if (acl_mode == MODE_ALLOW_ALL || acl_mode == MODE_DENY_ALL) {
        cJSON_Delete(parsed_json);
        return;
    }

    cJSON *api_obj, *get_arr, *set_arr;
    int i, arrlen;

    // syscfg
    api_obj = cJSON_GetObjectItem(parsed_json, "syscfg");
    if (api_obj && cJSON_IsObject(api_obj)) {
        get_arr = cJSON_GetObjectItem(api_obj, "get");
        if (get_arr && cJSON_IsArray(get_arr)) {
            arrlen = cJSON_GetArraySize(get_arr);
            for (i = 0; i < arrlen && syscfg_get_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(get_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(syscfg_get_list[syscfg_get_count], item->valuestring, MAX_API_NAME_LEN-1);
                    syscfg_get_list[syscfg_get_count][MAX_API_NAME_LEN-1] = 0;
                    syscfg_get_count++;
                }
            }
        }
        set_arr = cJSON_GetObjectItem(api_obj, "set");
        if (set_arr && cJSON_IsArray(set_arr)) {
            arrlen = cJSON_GetArraySize(set_arr);
            for (i = 0; i < arrlen && syscfg_set_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(set_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(syscfg_set_list[syscfg_set_count], item->valuestring, MAX_API_NAME_LEN-1);
                    syscfg_set_list[syscfg_set_count][MAX_API_NAME_LEN-1] = 0;
                    syscfg_set_count++;
                }
            }
        }
    }
    // sysevent
    api_obj = cJSON_GetObjectItem(parsed_json, "sysevent");
    if (api_obj && cJSON_IsObject(api_obj)) {
        get_arr = cJSON_GetObjectItem(api_obj, "get");
        if (get_arr && cJSON_IsArray(get_arr)) {
            arrlen = cJSON_GetArraySize(get_arr);
            for (i = 0; i < arrlen && sysevent_get_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(get_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(sysevent_get_list[sysevent_get_count], item->valuestring, MAX_API_NAME_LEN-1);
                    sysevent_get_list[sysevent_get_count][MAX_API_NAME_LEN-1] = 0;
                    sysevent_get_count++;
                }
            }
        }
        set_arr = cJSON_GetObjectItem(api_obj, "set");
        if (set_arr && cJSON_IsArray(set_arr)) {
            arrlen = cJSON_GetArraySize(set_arr);
            for (i = 0; i < arrlen && sysevent_set_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(set_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(sysevent_set_list[sysevent_set_count], item->valuestring, MAX_API_NAME_LEN-1);
                    sysevent_set_list[sysevent_set_count][MAX_API_NAME_LEN-1] = 0;
                    sysevent_set_count++;
                }
            }
        }
    }
    // rbus
    api_obj = cJSON_GetObjectItem(parsed_json, "rbus");
    if (api_obj && cJSON_IsObject(api_obj)) {
        get_arr = cJSON_GetObjectItem(api_obj, "get");
        if (get_arr && cJSON_IsArray(get_arr)) {
            arrlen = cJSON_GetArraySize(get_arr);
            for (i = 0; i < arrlen && rbus_get_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(get_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(rbus_get_list[rbus_get_count], item->valuestring, MAX_API_NAME_LEN-1);
                    rbus_get_list[rbus_get_count][MAX_API_NAME_LEN-1] = 0;
                    rbus_get_count++;
                }
            }
        }
        set_arr = cJSON_GetObjectItem(api_obj, "set");
        if (set_arr && cJSON_IsArray(set_arr)) {
            arrlen = cJSON_GetArraySize(set_arr);
            for (i = 0; i < arrlen && rbus_set_count < MAX_ACL_NAMES; ++i) {
                cJSON *item = cJSON_GetArrayItem(set_arr, i);
                if (cJSON_IsString(item)) {
                    strncpy(rbus_set_list[rbus_set_count], item->valuestring, MAX_API_NAME_LEN-1);
                    rbus_set_list[rbus_set_count][MAX_API_NAME_LEN-1] = 0;
                    rbus_set_count++;
                }
            }
        }
    }
    cJSON_Delete(parsed_json);
    ACL_LOG("mode: %s\n", acl_mode_to_string(acl_mode));
    if (acl_mode == MODE_ALLOW_WITH_SELECTIVE_BLOCKLIST || acl_mode == MODE_DENY_WITH_SELECTIVE_WHITELIST) {
        ACL_LOG(
            "[ACLList] Reloaded (syscfg: %d, sysevent: %d, rbus: %d names)\n",
            syscfg_get_count + syscfg_set_count,
            sysevent_get_count + sysevent_set_count,
            rbus_get_count + rbus_set_count
        );
    }
}

// libev callback for file changes
static void acllist_cb(EV_P_ ev_stat *w, int revents) {
    ACL_LOG("Inside %s\n", __FUNCTION__);
    UNUSED_PARAMETER(w);
    UNUSED_PARAMETER(revents);
    pthread_mutex_lock(&reload_acllist_mutex);
    reload_acllist();
    pthread_mutex_unlock(&reload_acllist_mutex);
}

// Thread function to run the libev event loop
static void* acllist_watcher_thread(void* arg) {
    UNUSED_PARAMETER(arg);
    pthread_detach(pthread_self());
    ACL_LOG("Inside %s\n", __FUNCTION__);
    struct ev_loop *loop = ev_loop_new(0);
    if (!loop) {
        ACL_LOG("Failed to create event loop\n");
        return NULL;
    }
    ev_stat acllist_watcher;

    // Initialize and start the ev_stat watcher for the acllist file
    ev_stat_init(&acllist_watcher, acllist_cb, acl_json_filename, 0.);
    ev_stat_start(loop, &acllist_watcher);

    ev_run(loop, 0);
    return NULL;
}

static pthread_t watcher_thread;
void acllist_watcher_once(void) {
    ACL_LOG("Inside %s\n", __FUNCTION__);
    int rc = pthread_create(&watcher_thread, NULL, acllist_watcher_thread, NULL);
    if (rc == 0) {
        pthread_setname_np(watcher_thread, "acllist_watcher");
    } else {
        ACL_LOG("Error: pthread_create failed in acllist_watcher_once (rc=%d)\n", rc);
    }
}

static pthread_once_t acllist_once = PTHREAD_ONCE_INIT;
static bool log_fp_initialized = false;
__attribute__((constructor))
void init_library() {
    if (!log_fp_initialized) {
        const char *logfile = getenv("RDKB_ACL_LOGFILE");
        if (logfile) {
            acl_log_fp = fopen(logfile, "a");
            if (!acl_log_fp) {
                acl_log_fp = stderr;
            }
        } else {
            acl_log_fp = stderr;
        }
        log_fp_initialized = true;
    }
    ACL_LOG("Inside %s\n", __FUNCTION__);
    ACL_LOG("PID %d\n", getpid());
    // Use RDKB_ACL_JSON environment variable for ACL list file path
    const char *env = getenv("RDKB_ACL_JSON");
    if (!env) {
        fprintf(stderr, "RDKB_ACL_JSON env variable not set\n");
        return;
    }
    if (strlen(env) >= sizeof(acl_json_filename) - 1) {
        ACL_LOG("Error: RDKB_ACL_JSON path too long (%zu bytes). Maximum allowed length is %zu bytes. Initialization aborted.\n", strlen(env), sizeof(acl_json_filename)-1);
        return;
    }
    strncpy(acl_json_filename, env, sizeof(acl_json_filename)-1);
    acl_json_filename[sizeof(acl_json_filename)-1] = '\0';

    // Initial load of the acllist
    pthread_mutex_lock(&reload_acllist_mutex);
    reload_acllist();
    pthread_mutex_unlock(&reload_acllist_mutex);

    pthread_once(&acllist_once, acllist_watcher_once);
    pthread_atfork(NULL, NULL, acllist_watcher_once);
}

static bool is_api_allowed(const char *name, char list[][MAX_API_NAME_LEN], int count, bool is_rbus) {
    // Block access while reloading the ACL list
    switch (acl_mode) {
        case MODE_ALLOW_ALL:
            return true;
        case MODE_DENY_ALL:
            return false;
        case MODE_ALLOW_WITH_SELECTIVE_BLOCKLIST:
            pthread_mutex_lock(&reload_acllist_mutex);
            for (int i = 0; i < count; ++i) {
                if (is_rbus) {
                    if (strstr(name, list[i]) != NULL) {
                        pthread_mutex_unlock(&reload_acllist_mutex);
                        return false;
                    }
                } else {
                    if (strcmp(name, list[i]) == 0) {
                        pthread_mutex_unlock(&reload_acllist_mutex);
                        return false;
                    }
                }
            }
            pthread_mutex_unlock(&reload_acllist_mutex);
            return true;
        case MODE_DENY_WITH_SELECTIVE_WHITELIST:
            pthread_mutex_lock(&reload_acllist_mutex);
            for (int i = 0; i < count; ++i) {
                if (is_rbus) {
                    if (strstr(name, list[i]) != NULL) {
                        pthread_mutex_unlock(&reload_acllist_mutex);
                        return true;
                    }
                } else {
                    if (strcmp(name, list[i]) == 0) {
                        pthread_mutex_unlock(&reload_acllist_mutex);
                        return true;
                    }
                }
            }
            pthread_mutex_unlock(&reload_acllist_mutex);
            return false;
        default:
            return false;
    }
}

#define IS_SYSCFG_GET_ALLOWED(name) is_api_allowed(name, syscfg_get_list, syscfg_get_count, false)
#define IS_SYSCFG_SET_ALLOWED(name) is_api_allowed(name, syscfg_set_list, syscfg_set_count, false)
#define IS_SYSEVENT_GET_ALLOWED(name) is_api_allowed(name, sysevent_get_list, sysevent_get_count, false)
#define IS_SYSEVENT_SET_ALLOWED(name) is_api_allowed(name, sysevent_set_list, sysevent_set_count, false)
#define IS_RBUS_GET_ALLOWED(name) is_api_allowed(name, rbus_get_list, rbus_get_count, true)
#define IS_RBUS_SET_ALLOWED(name) is_api_allowed(name, rbus_set_list, rbus_set_count, true)

rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value)
{
    if (!IS_RBUS_GET_ALLOWED(name)) {
        ACL_LOG("[Denied] rbus_get denied for name: %s (not allowed by mode).\n", name);
        return RBUS_ERROR_ACCESS_NOT_ALLOWED;
    }
    if (!real_rbus_get) {
        real_rbus_get = DLSYM_FN(rbus_get_func_t, "rbus_get");
        if (!real_rbus_get) {
            fprintf(stderr, "Error resolving original rbus_get\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    ACL_LOG("[Intercepted] rbus_get called with name: %s\n", name);
    rbusError_t result = real_rbus_get(handle, name, value);
    return result;
}

rbusError_t rbus_set(rbusHandle_t handle, const char* name, rbusValue_t value, rbusSetOptions_t* opts)
{
    if (!IS_RBUS_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] rbus_set denied for name: %s (not allowed by mode).\n", name);
        return RBUS_ERROR_ACCESS_NOT_ALLOWED;
    }
    if (!real_rbus_set) {
        real_rbus_set = DLSYM_FN(rbus_set_func_t, "rbus_set");
        if (!real_rbus_set) {
            fprintf(stderr, "Error resolving original rbus_set\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    ACL_LOG("[Intercepted] rbus_set called with name: %s\n", name);
    rbusError_t result = real_rbus_set(handle, name, value, opts);
    return result;
}

rbusError_t rbus_getExt(rbusHandle_t handle, int numParams, const char** params, int* resCount, rbusProperty_t* props)
{
    // Check ACL for each param
    for (int i = 0; i < numParams; ++i) {
        if (!IS_RBUS_GET_ALLOWED(params[i])) {
            ACL_LOG("[Denied] rbus_getExt denied for param: %s (not allowed by mode).\n", params[i]);
            return RBUS_ERROR_ACCESS_NOT_ALLOWED;
        }
    }
    if (!real_rbus_getExt) {
        real_rbus_getExt = DLSYM_FN(rbus_getExt_func_t, "rbus_getExt");
        if (!real_rbus_getExt) {
            fprintf(stderr, "Error resolving original rbus_getExt\n");
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    ACL_LOG("[Intercepted] rbus_getExt called with numParams: %d\n", numParams);
    return real_rbus_getExt(handle, numParams, params, resCount, props);
}

rbusError_t rbusProperty_initFromMessage(rbusProperty_t* property, rbusMessage msg)
{
    char const* name;
    rbusValue_t value;
    rbusError_t err = RBUS_ERROR_SUCCESS;

    rbusMessage_GetString(msg, (char const**) &name);
    if (!IS_RBUS_GET_ALLOWED(name)) {
        ACL_LOG("[Denied] rbusProperty_initFromMessage denied for name: %s (not allowed by mode).\n", name);
        rbusProperty_Init(property, name, NULL);
        rbusValue_initFromMessage(&value, msg);
        rbusProperty_SetValue(*property, NULL);
        rbusValue_Release(value);
        return RBUS_ERROR_ACCESS_NOT_ALLOWED;
    }
    else {
        ACL_LOG("[Intercepted] rbusProperty_initFromMessage for name: %s\n", name);
    }

    if (!property)
    {
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_Init(property, name, NULL);
    err= rbusValue_initFromMessage(&value, msg);
    rbusProperty_SetValue(*property, value);
    rbusValue_Release(value);
    return err;
}

rbusError_t _getExt_response_parser(rbusMessage response, int *numValues, rbusProperty_t* retProperties)
{
    rbusError_t errorcode = RBUS_ERROR_SUCCESS;
    rbusLegacyReturn_t legacyRetCode = RBUS_LEGACY_ERR_FAILURE;
    int numOfVals = 0;
    int ret = -1;
    int i = 0;
    int j = 0;

    rbusMessage_GetInt32(response, &ret);

    errorcode = (rbusError_t) ret;
    legacyRetCode = (rbusLegacyReturn_t) ret;

    *numValues = 0;
    if((errorcode == RBUS_ERROR_SUCCESS) || (legacyRetCode == RBUS_LEGACY_ERR_SUCCESS))
    {
        errorcode = RBUS_ERROR_SUCCESS;
        rbusMessage_GetInt32(response, &numOfVals);

        if(numOfVals)
        {
            rbusProperty_t last;
            for(i = 0; i < numOfVals; i++)
            {
                /* For the first instance, lets use the given pointer */
                if (0 == j)
                {
                    errorcode = rbusProperty_initFromMessage(retProperties, response);
                    if (errorcode == RBUS_ERROR_SUCCESS)
                    {
                        j++;
                        last = *retProperties;
                    }
                }
                else
                {
                    rbusProperty_t tmpProperties;
                    errorcode = rbusProperty_initFromMessage(&tmpProperties, response);
                    if (errorcode == RBUS_ERROR_SUCCESS)
                    {
                        j++;
                        rbusProperty_SetNext(last, tmpProperties);
                        rbusProperty_Release(tmpProperties);
                        last = tmpProperties;
                    }
                    else
                    {
                        rbusProperty_Release(tmpProperties);
                    }
                }
            }
        }
        *numValues = j;
    }
    else
    {
        if(legacyRetCode > RBUS_LEGACY_ERR_SUCCESS)
        {
            errorcode = CCSPError_to_rbusError(legacyRetCode);
        }
    }
    rbusMessage_Release(response);

    return errorcode;
}

int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes)
{
    if (!IS_SYSEVENT_GET_ALLOWED(inbuf)) {
        ACL_LOG("[Denied] sysevent_get denied for name: %s (not allowed by mode).\n", inbuf);
        return -1;
    }
    if (!real_sysevent_get) {
        real_sysevent_get = DLSYM_FN(sysevent_get_func_t, "sysevent_get");
        if (!real_sysevent_get) {
            fprintf(stderr, "Error resolving original sysevent_get\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] sysevent_get called with fd: %d, token: %d, name: %s\n", fd, token, inbuf);
    int result = real_sysevent_get(fd, token, inbuf, outbuf, outbytes);
    return result;
}

int sysevent_set(const int fd, const token_t token, const char *name, const char *value,  int conf_req)
{
    if (!IS_SYSEVENT_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] sysevent_set denied for name: %s (not allowed by mode).\n", name);
        return -1;
    }
    if (!real_sysevent_set) {
        real_sysevent_set = DLSYM_FN(sysevent_set_func_t, "sysevent_set");
        if (!real_sysevent_set) {
            fprintf(stderr, "Error resolving original sysevent_set\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] sysevent_set called with fd: %d, token: %d, name: %s, value: %s, conf_req: %d\n", fd, token, name, value, conf_req);
    int result = real_sysevent_set(fd, token, name, value, conf_req);
    return result;
}

int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz)
{
    if (!IS_SYSCFG_GET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_get denied in function syscfg_get for name: %s (not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_get) {
        real_syscfg_get = DLSYM_FN(syscfg_get_func_t, "syscfg_get");
        if (!real_syscfg_get) {
            fprintf(stderr, "Error resolving original syscfg_get\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_get called with ns: %s, name: %s\n", ns, name);
    int result = real_syscfg_get(ns, name, out_val, outbufsz);
    return result;
}

int syscfg_set_ns(const char *ns, const char *name, const char *value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_ns denied for name: %s (function: syscfg_set_ns, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns) {
        real_syscfg_set_ns = DLSYM_FN(syscfg_set_ns_func_t, "syscfg_set_ns");
        if (!real_syscfg_set_ns) {
            fprintf(stderr, "Error resolving original syscfg_set_ns\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_ns called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns(ns, name, value);
    return result;
}

int syscfg_set_nns(const char *name, const char *value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_nns denied in function syscfg_set_nns for name: %s (not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns) {
        real_syscfg_set_nns = DLSYM_FN(syscfg_set_nns_func_t, "syscfg_set_nns");
        if (!real_syscfg_set_nns) {
            fprintf(stderr, "Error resolving original syscfg_set_nns\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_nns called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns(name, value);
    return result;
}

int syscfg_set_ns_commit(const char *ns, const char *name, const char *value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_ns_commit denied for name: %s (function: syscfg_set_ns_commit, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_commit) {
        real_syscfg_set_ns_commit = DLSYM_FN(syscfg_set_ns_func_t, "syscfg_set_ns_commit");
        if (!real_syscfg_set_ns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_commit\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_ns_commit called with ns: %s, name: %s, value: %s\n", ns, name, value);
    int result = real_syscfg_set_ns_commit(ns, name, value);
    return result;
}

int syscfg_set_nns_commit(const char *name, const char *value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_nns_commit denied for name: %s (function: syscfg_set_nns_commit, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_commit) {
        real_syscfg_set_nns_commit = DLSYM_FN(syscfg_set_nns_func_t, "syscfg_set_nns_commit");
        if (!real_syscfg_set_nns_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_commit\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_nns_commit called with name: %s, value: %s\n", name, value);
    int result = real_syscfg_set_nns_commit(name, value);
    return result;
}

int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_ns_u denied for name: %s (function: syscfg_set_ns_u, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_u) {
        real_syscfg_set_ns_u = DLSYM_FN(syscfg_set_ns_u_func_t, "syscfg_set_ns_u");
        if (!real_syscfg_set_ns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_ns_u called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u(ns, name, value);
    return result;
}

int syscfg_set_nns_u(const char *name, unsigned long value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_nns_u denied for name: %s (function: syscfg_set_nns_u, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_u) {
        real_syscfg_set_nns_u = DLSYM_FN(syscfg_set_nns_u_func_t, "syscfg_set_nns_u");
        if (!real_syscfg_set_nns_u) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_nns_u called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u(name, value);
    return result;
}

int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_ns_u_commit denied for name: %s (function: syscfg_set_ns_u_commit, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_ns_u_commit) {
        real_syscfg_set_ns_u_commit = DLSYM_FN(syscfg_set_ns_u_func_t, "syscfg_set_ns_u_commit");
        if (!real_syscfg_set_ns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_ns_u_commit\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_ns_u_commit called with ns: %s, name: %s, value: %lu\n", ns, name, value);
    int result = real_syscfg_set_ns_u_commit(ns, name, value);
    return result;
}

int syscfg_set_nns_u_commit(const char *name, unsigned long value)
{
    if (!IS_SYSCFG_SET_ALLOWED(name)) {
        ACL_LOG("[Denied] syscfg_set_nns_u_commit denied for name: %s (function: syscfg_set_nns_u_commit, not allowed by mode).\n", name);
        return -1;
    }
    if (!real_syscfg_set_nns_u_commit) {
        real_syscfg_set_nns_u_commit = DLSYM_FN(syscfg_set_nns_u_func_t, "syscfg_set_nns_u_commit");
        if (!real_syscfg_set_nns_u_commit) {
            fprintf(stderr, "Error resolving original syscfg_set_nns_u_commit\n");
            return -1;
        }
    }
    ACL_LOG("[Intercepted] syscfg_set_nns_u_commit called with name: %s, value: %lu\n", name, value);
    int result = real_syscfg_set_nns_u_commit(name, value);
    return result;
}
