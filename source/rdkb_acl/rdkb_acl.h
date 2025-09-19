#define UNUSED_PARAMETER(x) (void)(x)

// Typedefs for function pointers
typedef rbusError_t (*rbus_get_func_t)(rbusHandle_t, const char*, rbusValue_t*);
typedef rbusError_t (*rbus_set_func_t)(rbusHandle_t, const char*, rbusValue_t, rbusSetOptions_t*);
typedef rbusError_t (*rbus_getExt_func_t)(rbusHandle_t, int, const char**, int*, rbusProperty_t*);

typedef int (*sysevent_get_func_t)(const int, const token_t, const char *, char *, int);
typedef int (*sysevent_set_func_t)(const int, const token_t, const char *, const char *, int);

typedef int (*syscfg_get_func_t)(const char *, const char *, char *, int);
typedef int (*syscfg_set_ns_func_t)(const char *, const char *, const char *);
typedef int (*syscfg_set_nns_func_t)(const char *, const char *);
typedef int (*syscfg_set_ns_u_func_t)(const char *, const char *, unsigned long);
typedef int (*syscfg_set_nns_u_func_t)(const char *, unsigned long);

typedef enum {
    MODE_ALLOW_ALL,
    MODE_DENY_ALL,
    MODE_ALLOW_WITH_SELECTIVE_BLOCKLIST,
    MODE_DENY_WITH_SELECTIVE_WHITELIST
} acl_mode_t;

// Macro for dlsym casting
#define DLSYM_FN(type, sym) ((type)dlsym(RTLD_NEXT, sym))

#define MAX_ACL_NAMES 256
#define MAX_API_NAME_LEN 128

rbusError_t rbusValue_initFromMessage(rbusValue_t* value, rbusMessage msg);

typedef enum _rbus_legacy_returns {
    RBUS_LEGACY_ERR_SUCCESS = 100,
    RBUS_LEGACY_ERR_MEMORY_ALLOC_FAIL = 101,
    RBUS_LEGACY_ERR_FAILURE = 102,
    RBUS_LEGACY_ERR_NOT_CONNECT = 190,
    RBUS_LEGACY_ERR_TIMEOUT = 191,
    RBUS_LEGACY_ERR_NOT_EXIST = 192,
    RBUS_LEGACY_ERR_NOT_SUPPORT = 193,
    RBUS_LEGACY_ERR_RESOURCE_EXCEEDED = 9004,
    RBUS_LEGACY_ERR_INVALID_PARAMETER_NAME = 9005,
    RBUS_LEGACY_ERR_INVALID_PARAMETER_TYPE = 9006,
    RBUS_LEGACY_ERR_INVALID_PARAMETER_VALUE = 9007,
    RBUS_LEGACY_ERR_NOT_WRITABLE = 9008,
} rbusLegacyReturn_t;
