#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rbus/rbus.h>
#include <syscfg/syscfg.h>
#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

rbusHandle_t rbus_handle = NULL;

rbusDataElement_t syscfg_RbusElements[] =
{
    { "syscfg_get()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, syscfg_get_rbus} },
    { "syscfg_set()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, syscfg_set_rbus} }
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
        printf("rbus unregister data elements failed for type %d\n",type);
        return rc;
    }
    rbus_close(rbus_handle);
    return rc;
}

rbusError_t syscfg_get_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    rbusValue_t value;
    char *key = NULL;
    uint32_t len = 0;
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    char buf[128]={'\0'};

    value = rbusObject_GetValue(inParams, "key");
    key = (char*)rbusValue_GetString(value, &len);
    if(key == NULL)
    {
        printf("%s: Key is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }
    printf("%s: Key: %s\n", __FUNCTION__, key);

    syscfg_get( NULL, key, buf, sizeof(buf));

    /*set syscfg value */
    rbusValue_Init(&value);
    rbusValue_SetString(value, buf);
    rbusObject_SetValue(outParams, "value", value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t syscfg_set_rbus(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    rbusValue_t value;
    char *key = NULL;
    char *val = NULL;
    uint32_t len = 0;

    value = rbusObject_GetValue(inParams, "key");
    key = (char*)rbusValue_GetString(value, &len);

    if (key == NULL) {
        printf("%s: key is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }
    
    value = rbusObject_GetValue(inParams, "value");
    val = (char*)rbusValue_GetString(value, &len);

    if (val == NULL) {
        printf("%s: value is NULL\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    printf("%s: Key: %s, Value: %s\n", __FUNCTION__, key, val);

    if (syscfg_set(NULL, key, val) != 0)
    {
        printf("syscfg_set failed for key: %s\n", key);
        return RBUS_ERROR_INVALID_INPUT;
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
