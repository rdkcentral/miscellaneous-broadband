#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rbus/rbus.h>

#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)

rbusHandle_t handle = NULL;
char rbus_component_name[128] = { '\0' };
void syscfg_rbus_lib_init(void)
{
    if (handle == NULL)
    {
        snprintf(rbus_component_name, sizeof(rbus_component_name), "syscfg_rbus_lib_%d", getpid());
        rbus_open(&handle, rbus_component_name);
    }
}

int syscfg_create(const char *file, long int max_file_sz)
{
    UNREFERENCED_PARAMETER(file);
    UNREFERENCED_PARAMETER(max_file_sz);
    return 0;
}

void syscfg_destroy()
{
    return;
}

int syscfg_get (const char *ns, const char *name, char *out_val, int outbufsz)
{
    size_t len;
    int rc;
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;

    if (NULL == name || NULL == out_val) {
        if (out_val != NULL) {
            out_val[0] = 0;
        }
        return -1;
    }
    syscfg_rbus_lib_init();
    //val = _syscfg_get(ns, name);

    //syscfg_get(NULL, cmd[1], val, sizeof(val));
    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    rbusValue_SetString(value, cmd[1]);
    rbusObject_SetValue(inParams, "syscfg_key", value);
    rbusValue_Release(value);
    rbus_response = rbusMethod_Invoke(handle, "syscfg_get()", inParams, &outParams);
    rbusObject_Release(inParams);
    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusProperty_t outProps = rbusObject_GetProperties(outParams);
        if (outProps)
        {
            value = rbusProperty_GetValue(outProps);
            if (value && rbusValue_GetType(value) == RBUS_STRING)
            {
                const char* val = rbusValue_GetString(value,NULL);
                len = strlen(val);

                if (len >= outbufsz) {
                    memcpy(out_val, val, outbufsz - 1);
                    out_val[outbufsz - 1] = 0;
#if defined (VERBOSE_DEBUG)
                    fprintf(stderr, "syscfg_get: %s outbufsz too small (%d < %d) (%s: lr %p)\n", name, outbufsz, (int) len + 1, program_invocation_short_name, __builtin_extract_return_addr (__builtin_return_address (0)));
#endif
                }
                else {
                    memcpy(out_val, val, len + 1);
                }
                rc = 0;
            }
            else
            {
                fprintf(stderr, "[%s] Expected syscfg_val string but got type %d \n", __FUNCTION__, rbusValue_GetType(value));
                rc = -1;
            }
        }
        else
        {
            fprintf(stderr, "[%s] Failed to retrieve properties \n", __FUNCTION__);
        }
        rbusObject_Release(outParams);
    }

    if (val == NULL) {
        out_val[0] = 0;
        rc = -1;
    }

    return rc;
}

int syscfg_set (const char *ns, const char *name, const char *val)
{
    int rc;
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    syscfg_rbus_lib_init();
    //rc = syscfg_set(NULL, cmd[1], cmd[2]);
    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    rbusValue_SetString(value, name);
    rbusObject_SetValue(inParams, "syscfg_key", value);
    rbusValue_Release(value);
    rbusValue_Init(&value);
    rbusValue_SetString(value, val);
    rbusObject_SetValue(inParams, "syscfg_value", value);
    rbusValue_Release(value);
    rbus_response = rbusMethod_Invoke(handle, "syscfg_set()", inParams, &outParams);
    rbusObject_Release(inParams);
    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusObject_Release(outParams);
        rc = 0;
    }
    else
    {
        rc = -1;
    }
    return rc;
}

int syscfg_unset(const char *ns, const char *name)
{
    int rc;
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    syscfg_rbus_lib_init();
    //rc = syscfg_unset(NULL, cmd[1]);
    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    rbusValue_SetString(value, cmd[1]);
    rbusObject_SetValue(inParams, "syscfg_key", value);
    rbusValue_Release(value);
    rbus_response = rbusMethod_Invoke(handle, "syscfg_unset()", inParams, &outParams);
    rbusObject_Release(inParams);
    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusObject_Release(outParams);
        rc = 0;
    }
    else
    {
        rc = -1;
    }
    return rc;
}

int syscfg_commit (void)
{
    int rc = 0;
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;
    syscfg_rbus_lib_init();
    //rc = syscfg_commit();
    rbusObject_Init(&inParams, NULL);
    rbus_response = rbusMethod_Invoke(handle, "syscfg_commit()", inParams, &outParams);
    rbusObject_Release(inParams);
    if (RBUS_ERROR_SUCCESS == rbus_response)
    {
        rbusObject_Release(outParams);
        rc = 0;
    }
    else
    {
        rc = 1;
    }
    if (rc != 0) {
        fprintf(stderr, "Error: internal error handling tmp file\n");
    }
    return rc;
}

int syscfg_getall2(char *buf, size_t bufsz, size_t *outsz)
{
    UNREFERENCED_PARAMETER(buf);
    UNREFERENCED_PARAMETER(bufsz);
    UNREFERENCED_PARAMETER(outsz);
    return 0;
}

int syscfg_getsz (long int *used_sz, long int *max_sz)
{
    UNREFERENCED_PARAMETER(used_sz);
    UNREFERENCED_PARAMETER(max_sz);
    return 0;
}