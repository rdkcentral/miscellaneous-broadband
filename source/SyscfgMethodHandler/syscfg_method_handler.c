#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rbus/rbus.h>
#include <syscfg/syscfg.h>
#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
#define UNUSED_PARAMETER(x) (void)(x)
#define ANSC_STATUS_SUCCESS 0
#define ANSC_STATUS unsigned long

rbusHandle_t rbus_handle = NULL;

rbusError_t syscfg_get_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                                        rbusMethodAsyncHandle_t asyncHandle);
rbusError_t syscfg_set_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                                        rbusMethodAsyncHandle_t asyncHandle);
rbusError_t syscfg_commit_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                                        rbusMethodAsyncHandle_t asyncHandle);
rbusDataElement_t syscfg_RbusElements[] =
{
    { "syscfg_get()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, syscfg_get_rbus} },
    { "syscfg_set()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, syscfg_set_rbus} },
    { "syscfg_commit()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, syscfg_commit_rbus} }
};

rbusError_t syscfg_RbusInit(void)
{
    int rc = RBUS_ERROR_SUCCESS;

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        printf("RBUS enabled, Proceed with syscfg method handler\n");
    }
    else
    {
        printf("RBUS is NOT ENABLED, Can't Proceed with syscfg method handler\n");
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&rbus_handle, "syscfgMethodHandler");
    if (rc != RBUS_ERROR_SUCCESS)
    {
        printf("rbus initialization failed\n");
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }
    return rc;
}

rbusError_t syscfg_reg_elements(void)
{
    int rc = RBUS_ERROR_SUCCESS;
    rc = rbus_regDataElements(rbus_handle, ARRAY_SZ(syscfg_RbusElements), syscfg_RbusElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        printf("rbus register data elements failed\n");
        return rc;
    }
    return rc;
}

rbusError_t syscfg_unreg_elements(void)
{
    int rc = RBUS_ERROR_SUCCESS;
    rc = rbus_unregDataElements(rbus_handle, ARRAY_SZ(syscfg_RbusElements), syscfg_RbusElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        printf("rbus unregister data elements failed\n");
        return rc;
    }
    rbus_close(rbus_handle);
    return rc;
}

rbusError_t syscfg_get_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    UNUSED_PARAMETER(handle);
    UNUSED_PARAMETER(methodName);
    UNUSED_PARAMETER(asyncHandle);
    rbusValue_t rbus_value;
    char *syscfg_key = NULL;
    int len = 0;
    char buf[128]={'\0'};

    rbus_value = rbusObject_GetValue(inParams, "syscfg_key");
    syscfg_key = (char*)rbusValue_GetString(rbus_value, &len);
    if(syscfg_key == NULL)
    {
        printf("%s: syscfg_key is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }
    //printf("%s: syscfg_key: %s\n", __FUNCTION__, syscfg_key);

    syscfg_get( NULL, syscfg_key, buf, sizeof(buf));

    /*set syscfg value */
    rbusValue_Init(&rbus_value);
    rbusValue_SetString(rbus_value, buf);
    rbusObject_SetValue(outParams, "syscfg_value", rbus_value);
    rbusValue_Release(rbus_value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t syscfg_set_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    UNUSED_PARAMETER(handle);
    UNUSED_PARAMETER(methodName);
    UNUSED_PARAMETER(outParams);
    UNUSED_PARAMETER(asyncHandle);
    rbusValue_t rbus_value;
    char *syscfg_key = NULL;
    char *syscfg_val = NULL;
    int len = 0;

    rbus_value = rbusObject_GetValue(inParams, "syscfg_key");
    syscfg_key = (char*)rbusValue_GetString(rbus_value, &len);

    if (syscfg_key == NULL) {
        printf("%s: syscfg_key is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbus_value = rbusObject_GetValue(inParams, "syscfg_value");
    syscfg_val = (char*)rbusValue_GetString(rbus_value, &len);

    if (syscfg_val == NULL) {
        printf("%s: syscfg_value is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    //printf("%s: syscfg_key: %s, syscfg_value: %s\n", __FUNCTION__, syscfg_key, syscfg_val);

    if (syscfg_set(NULL, syscfg_key, syscfg_val) != 0)
    {
        printf("syscfg_set failed for syscfg_key: %s\n", syscfg_key);
        return RBUS_ERROR_BUS_ERROR;
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t syscfg_commit_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    UNUSED_PARAMETER(handle);
    UNUSED_PARAMETER(methodName);
    UNUSED_PARAMETER(inParams);
    UNUSED_PARAMETER(outParams);
    UNUSED_PARAMETER(asyncHandle);

    if (syscfg_commit() != 0)
    {
        printf("syscfg_commit failed.\n");
        return RBUS_ERROR_BUS_ERROR;
    }

    return RBUS_ERROR_SUCCESS;
}

int main()
{
    syscfg_init();
    rbusError_t rc = syscfg_RbusInit();
    if (rc != RBUS_ERROR_SUCCESS)
    {
        printf("Failed to initialize rbus: %d\n", rc);
        return rc;
    }

    rc = syscfg_reg_elements();
    if (rc != RBUS_ERROR_SUCCESS)
    {
        printf("Failed to register rbus elements: %d\n", rc);
        return rc;
    }
    while(1)
    {
        sleep(30);
    }
    syscfg_unreg_elements(); // Optionally unregister elements on exit
    return 0;
}