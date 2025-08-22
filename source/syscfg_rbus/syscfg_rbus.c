#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rbus/rbus.h>
#include <syscfg/syscfg.h>

rbusHandle_t handle;
int rbus_response = RBUS_ERROR_SUCCESS;

bool syscfg_rbus_init(void)
{
    rbus_response = rbus_open(&handle, "syscfg_rbus_bin");
    return (RBUS_ERROR_SUCCESS == rbus_response)?true:false;
}

static inline void syscfg_usage (void)
{
    printf("Usage: syscfg [set name value | get name | commit]\n");
}

int main (int argc, char **argv)
{
    int rc = 0;
    char **cmd;

    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t value;

    if (argc < 2) {
        syscfg_usage();
        return 1;
    }

    argc -= 1;
    cmd = argv + 1;

    if (!syscfg_rbus_init()) {
        printf("Error: rbus init failed\n");
        return 1;
    }
    rbusObject_Init(&inParams, NULL);
    if (strcmp(cmd[0], "get") == 0)
    {
        if (argc == 2) {
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
                //fprintf(stderr, "[%s] Successfully invoked syscfg_get()  \n", __FUNCTION__ );
                if (outProps)
                {
                    value = rbusProperty_GetValue(outProps);
                    if (value && rbusValue_GetType(value) == RBUS_STRING)
                    {
                        const char* str = rbusValue_GetString(value,NULL);
                        puts(str);
                        rc = 0;
                    }
                    else
                    {
                        fprintf(stderr, "[%s] Expected syscfg_val string but got type %d \n", __FUNCTION__, rbusValue_GetType(value));
                        rc = 1;
                    }
                }
                else
                {
                    fprintf(stderr, "[%s] Failed to retrieve properties \n", __FUNCTION__);
                }
                rbusObject_Release(outParams);
            }
        }
        else {
            syscfg_usage();
            rc = 1;
        }
    }
    else if (strcmp(cmd[0], "set") == 0)
    {
        if (argc == 3) {
            //rc = syscfg_set(NULL, cmd[1], cmd[2]);
            rbusObject_Init(&inParams, NULL);
            rbusValue_Init(&value);
            rbusValue_SetString(value, cmd[1]);
            rbusObject_SetValue(inParams, "syscfg_key", value);
            rbusValue_Release(value);
            rbusValue_Init(&value);
            rbusValue_SetString(value, cmd[2]);
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
                rc = 1;
            }

            if (rc != 0) {
                printf("Error. code=%d\n", rc);
            }
        }
        else {
            syscfg_usage();
            rc = 1;
        }
    }
    else if (strcmp(cmd[0], "commit") == 0)
    {
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
    }
    else {
        syscfg_usage();
        rc = 1;
    }
    rbus_close(handle);
    return rc;
}