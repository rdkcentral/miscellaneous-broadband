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

rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value);
rbusError_t rbus_set(rbusHandle_t handle, const char* name, rbusValue_t value, rbusSetOptions_t* opts);
rbusError_t rbus_getExt(rbusHandle_t handle, int numParams, const char** params, int* resCount, rbusProperty_t* props);

int sysevent_get(const int fd, const token_t token, const char *inbuf, char *outbuf, int outbytes);
int sysevent_set(const int fd, const token_t token, const char *name, const char *value,  int conf_req);

int syscfg_get(const char *ns, const char *name, char *out_val, int outbufsz);
int syscfg_set_ns(const char *ns, const char *name, const char *value);
int syscfg_set_nns (const char *name, const char *value);
int syscfg_set_ns_commit(const char *ns, const char *name, const char *value);
int syscfg_set_nns_commit(const char *name, const char *value);
int syscfg_set_ns_u(const char *ns, const char *name, unsigned long value);
int syscfg_set_nns_u(const char *name, unsigned long value);
int syscfg_set_ns_u_commit(const char *ns, const char *name, unsigned long value);
int syscfg_set_nns_u_commit(const char *name, unsigned long value);
