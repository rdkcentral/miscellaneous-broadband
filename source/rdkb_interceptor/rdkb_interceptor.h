#define UNUSED_PARAMETER(x) (void)(x)

// Typedefs for function pointers
typedef rbusError_t (*rbus_get_func_t)(rbusHandle_t, const char*, rbusValue_t*);
typedef rbusError_t (*rbus_set_func_t)(rbusHandle_t, const char*, rbusValue_t, rbusSetOptions_t*);

typedef int (*sysevent_get_func_t)(const int, const token_t, const char *, char *, int);
typedef int (*sysevent_set_func_t)(const int, const token_t, const char *, const char *, int);

typedef int (*syscfg_get_func_t)(const char *, const char *, char *, int);
typedef int (*syscfg_set_ns_func_t)(const char *, const char *, const char *);
typedef int (*syscfg_set_nns_func_t)(const char *, const char *);
typedef int (*syscfg_set_ns_u_func_t)(const char *, const char *, unsigned long);
typedef int (*syscfg_set_nns_u_func_t)(const char *, unsigned long);
typedef int (*syscfg_commit_func_t)(void);

// Macro for dlsym casting
#define DLSYM_FN(type, sym) ((type)dlsym(RTLD_NEXT, sym))

#define MAX_WHITELISTED_NAMES 256
#define MAX_API_NAME_LEN 128

rbusError_t rbus_get(rbusHandle_t handle, const char* name, rbusValue_t* value);
rbusError_t rbus_set(rbusHandle_t handle, const char* name, rbusValue_t value, rbusSetOptions_t* opts);

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
int syscfg_commit(void);