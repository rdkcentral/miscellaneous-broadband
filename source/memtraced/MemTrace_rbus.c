#include "MemTrace.h"
#include "MemTrace_rbus.h"
#include "MemTrace_log.h"

extern unsigned int interval;
extern unsigned long rss_threshold;
extern unsigned int initial_snapshot_uptime;

extern ProcessInfo processes[MAX_PROCESS_COUNT];
extern int process_count;

rbusHandle_t g_rbusHandle;

static bool MemTrace_ParseThresholdRowProperty(char const* name, unsigned int* index, char* field, size_t fieldSize)
{
    const char* prefix = "Device.Diagnostics.MemTrace.PerProcessThreshold.";
    size_t prefixLen = strlen(prefix);
    char* end = NULL;
    unsigned long inst = 0;

    if (!name || !index || !field || fieldSize == 0)
        return false;

    if (strncmp(name, prefix, prefixLen) != 0)
        return false;

    inst = strtoul(name + prefixLen, &end, 10);
    if (end == (name + prefixLen) || inst == 0 || *end != '.')
        return false;

    if (*(end + 1) == '\0')
        return false;

    *index = (unsigned int)inst;
    strncpy(field, end + 1, fieldSize - 1);
    field[fieldSize - 1] = '\0';
    return true;
}

static bool MemTrace_ParseThresholdRowName(char const* rowName, unsigned int* index)
{
    const char* prefix = "Device.Diagnostics.MemTrace.PerProcessThreshold.";
    size_t prefixLen = strlen(prefix);
    char* end = NULL;
    unsigned long inst = 0;

    if (!rowName || !index)
        return false;

    if (strncmp(rowName, prefix, prefixLen) != 0)
        return false;

    inst = strtoul(rowName + prefixLen, &end, 10);
    if (end == (rowName + prefixLen) || inst == 0)
        return false;

    if (*end != '\0' && strcmp(end, ".") != 0)
        return false;

    *index = (unsigned int)inst;
    return true;
}

static void MemTrace_BuildThresholdKey(char* key, size_t size, const char* field, unsigned int index)
{
    snprintf(key, size, "MemTrace_RSSThreshold_%s_%u", field, index);
}

static int MemTrace_GetThresholdCount(unsigned int* count)
{
    char countStr[16] = {0};
    long value = 0;

    if (!count)
        return -1;

    if (syscfg_get(NULL, "MemTrace_RSSThreshold_count", countStr, sizeof(countStr)) != 0)
    {
        *count = 0;
        return -1;
    }

    value = strtol(countStr, NULL, 10);
    if (value < 0)
        value = 0;
    if (value > MAX_PROC_THRESHOLD_CONFIG_COUNT)
        value = MAX_PROC_THRESHOLD_CONFIG_COUNT;

    *count = (unsigned int)value;
    return 0;
}

static rbusError_t MemTrace_SetSyscfgValue(const char* key, const char* value)
{
    if (syscfg_set_commit(NULL, key, value) != 0)
    {
        MemTraceError(("%s: syscfg_set_commit failed for %s=%s\n", __FUNCTION__, key, value));
        return RBUS_ERROR_BUS_ERROR;
    }
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_TableGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    char const* name = rbusProperty_GetName(property);
    unsigned int index = 0;
    char field[32] = {0};
    char key[64] = {0};
    char valueStr[256] = {0};
    rbusValue_t value;

    if (!MemTrace_ParseThresholdRowProperty(name, &index, field, sizeof(field)))
        return RBUS_ERROR_INVALID_INPUT;

    if (strcmp(field, "Enabled") == 0)
        MemTrace_BuildThresholdKey(key, sizeof(key), "enabled", index);
    else if (strcmp(field, "ProcName") == 0)
        MemTrace_BuildThresholdKey(key, sizeof(key), "procname", index);
    else if (strcmp(field, "kB") == 0)
        MemTrace_BuildThresholdKey(key, sizeof(key), "kB", index);
    else
        return RBUS_ERROR_INVALID_INPUT;

    if (syscfg_get(NULL, key, valueStr, sizeof(valueStr)) != 0)
        return RBUS_ERROR_BUS_ERROR;

    rbusValue_Init(&value);
    if (strcmp(field, "ProcName") == 0)
        rbusValue_SetString(value, valueStr);
    else
        rbusValue_SetUInt32(value, (uint32_t)strtoul(valueStr, NULL, 10));

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_TableSetHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    unsigned int index = 0;
    char field[32] = {0};
    char key[64] = {0};
    char valueStr[256] = {0};
    rbusValueType_t valueType;

    if (!value || !MemTrace_ParseThresholdRowProperty(name, &index, field, sizeof(field)))
        return RBUS_ERROR_INVALID_INPUT;

    if (strcmp(field, "Enabled") == 0)
    {
        MemTrace_BuildThresholdKey(key, sizeof(key), "enabled", index);
        valueType = rbusValue_GetType(value);
        if (valueType == RBUS_BOOLEAN)
            snprintf(valueStr, sizeof(valueStr), "%u", rbusValue_GetBoolean(value) ? 1U : 0U);
        else
            return RBUS_ERROR_INVALID_INPUT;
    }
    else if (strcmp(field, "ProcName") == 0)
    {
        char const* strVal = rbusValue_GetString(value, NULL);
        if (!strVal)
            return RBUS_ERROR_INVALID_INPUT;
        MemTrace_BuildThresholdKey(key, sizeof(key), "procname", index);
        snprintf(valueStr, sizeof(valueStr), "%s", strVal);
    }
    else if (strcmp(field, "kB") == 0)
    {
        MemTrace_BuildThresholdKey(key, sizeof(key), "kB", index);
        valueType = rbusValue_GetType(value);
        if (valueType == RBUS_UINT32)
            snprintf(valueStr, sizeof(valueStr), "%u", (unsigned int)rbusValue_GetUInt32(value));
        else
            return RBUS_ERROR_INVALID_INPUT;
    }
    else
    {
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (MemTrace_SetSyscfgValue(key, valueStr) != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    (void)load_process_thresholds();
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_TableAddRowHandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    (void)handle;
    (void)tableName;
    (void)aliasName;
    unsigned int count = 0;
    unsigned int next = 0;
    unsigned long defaultThresholdKb = (rss_threshold > 0) ? rss_threshold : DEFAULT_THRESHOLD_KB;
    char key[64] = {0};
    char valueStr[32] = {0};

    if (!instNum)
        return RBUS_ERROR_INVALID_INPUT;

    (void)MemTrace_GetThresholdCount(&count);
    if (count >= MAX_PROC_THRESHOLD_CONFIG_COUNT)
        return RBUS_ERROR_BUS_ERROR;

    next = count + 1;
    *instNum = next;

    MemTrace_BuildThresholdKey(key, sizeof(key), "enabled", next);
    if (MemTrace_SetSyscfgValue(key, "1") != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    MemTrace_BuildThresholdKey(key, sizeof(key), "procname", next);
    if (MemTrace_SetSyscfgValue(key, "*") != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    MemTrace_BuildThresholdKey(key, sizeof(key), "kB", next);
    snprintf(valueStr, sizeof(valueStr), "%lu", defaultThresholdKb);
    if (MemTrace_SetSyscfgValue(key, valueStr) != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    snprintf(valueStr, sizeof(valueStr), "%u", next);
    if (MemTrace_SetSyscfgValue("MemTrace_RSSThreshold_count", valueStr) != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    (void)load_process_thresholds();
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_TableRemoveRowHandler(rbusHandle_t handle, char const* rowName)
{
    (void)handle;
    unsigned int removeIndex = 0;
    unsigned int count = 0;
    char srcKey[64] = {0};
    char dstKey[64] = {0};
    char valueStr[256] = {0};

    if (!MemTrace_ParseThresholdRowName(rowName, &removeIndex))
        return RBUS_ERROR_INVALID_INPUT;

    if (MemTrace_GetThresholdCount(&count) != 0 || removeIndex == 0 || removeIndex > count)
        return RBUS_ERROR_INVALID_INPUT;

    for (unsigned int i = removeIndex; i < count; i++)
    {
        MemTrace_BuildThresholdKey(srcKey, sizeof(srcKey), "enabled", i + 1);
        MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "enabled", i);
        if (syscfg_get(NULL, srcKey, valueStr, sizeof(valueStr)) != 0)
            snprintf(valueStr, sizeof(valueStr), "1");
        if (MemTrace_SetSyscfgValue(dstKey, valueStr) != RBUS_ERROR_SUCCESS)
            return RBUS_ERROR_BUS_ERROR;

        MemTrace_BuildThresholdKey(srcKey, sizeof(srcKey), "procname", i + 1);
        MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "procname", i);
        if (syscfg_get(NULL, srcKey, valueStr, sizeof(valueStr)) != 0)
            valueStr[0] = '\0';
        if (MemTrace_SetSyscfgValue(dstKey, valueStr) != RBUS_ERROR_SUCCESS)
            return RBUS_ERROR_BUS_ERROR;

        MemTrace_BuildThresholdKey(srcKey, sizeof(srcKey), "kB", i + 1);
        MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "kB", i);
        if (syscfg_get(NULL, srcKey, valueStr, sizeof(valueStr)) != 0)
            snprintf(valueStr, sizeof(valueStr), "0");
        if (MemTrace_SetSyscfgValue(dstKey, valueStr) != RBUS_ERROR_SUCCESS)
            return RBUS_ERROR_BUS_ERROR;
    }

    MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "enabled", count);
    if (MemTrace_SetSyscfgValue(dstKey, "0") != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;
    MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "procname", count);
    if (MemTrace_SetSyscfgValue(dstKey, "") != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;
    MemTrace_BuildThresholdKey(dstKey, sizeof(dstKey), "kB", count);
    if (MemTrace_SetSyscfgValue(dstKey, "0") != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    snprintf(valueStr, sizeof(valueStr), "%u", count - 1);
    if (MemTrace_SetSyscfgValue("MemTrace_RSSThreshold_count", valueStr) != RBUS_ERROR_SUCCESS)
        return RBUS_ERROR_BUS_ERROR;

    (void)load_process_thresholds();
    return RBUS_ERROR_SUCCESS;
}

char const* GetParamName(char const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

rbusDataElement_t memtrace_RbusDataElements[] = {
    {"Device.Diagnostics.MemTrace.Interval", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.RSSThreshold", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.InitialSnapshotUptime", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeGreen", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeYellow", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeRed", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.PerProcessThreshold.", RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, MemTrace_TableAddRowHandler, MemTrace_TableRemoveRowHandler, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.PerProcessThreshold.{i}.Enabled", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_TableGetHandler, MemTrace_TableSetHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.PerProcessThreshold.{i}.ProcName", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_TableGetHandler, MemTrace_TableSetHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.PerProcessThreshold.{i}.kB", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_TableGetHandler, MemTrace_TableSetHandler, NULL, NULL, NULL, NULL}},
};

#define MT_NUM_OF_RBUS_PARAMS sizeof(memtrace_RbusDataElements)/sizeof(memtrace_RbusDataElements[0])

rbusError_t MemTraceRbusInit()
{
    int rc = RBUS_ERROR_SUCCESS;
    MemTraceDebug(("In %s\n", __FUNCTION__));
    if(RBUS_ENABLED == rbus_checkStatus())
    {
        MemTraceInfo(("RBUS enabled, Proceed with MemTrace\n"));
    }
    else
    {
        MemTraceError(("RBUS is NOT ENABLED, Can't Proceed with MemTrace\n"));
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&g_rbusHandle, MT_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        MemTraceError(("MemTrace RBUS Initialization failed\n"));
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }

    // Register data elements
    rc = rbus_regDataElements(g_rbusHandle, MT_NUM_OF_RBUS_PARAMS, memtrace_RbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        MemTraceError(("MemTrace rbus register data elements failed\n"));
        rc = rbus_close(g_rbusHandle);
        return rc;
    }

    {
        unsigned int count = 0;
        unsigned int i = 0;
        if (MemTrace_GetThresholdCount(&count) == 0 && count > 0)
        {
            for (i = 1; i <= count; i++)
            {
                rbusError_t rowRc = rbusTable_registerRow(g_rbusHandle,
                    "Device.Diagnostics.MemTrace.PerProcessThreshold.",
                    i, NULL);
                if (rowRc != RBUS_ERROR_SUCCESS)
                {
                    MemTraceError(("MemTrace rbusTable_registerRow failed for index %u (rc=%d)\n", i, rowRc));
                }
                else
                {
                    MemTraceDebug(("MemTrace rbusTable_registerRow succeeded for index %u\n", i));
                }
            }
        }
    }

    MemTraceDebug(("Out %s\n", __FUNCTION__));
    return rc;
}

bool ReadProcessListFromBucketStatus(Bucket color,
                                     char *outBuf,
                                     size_t outBufSize)
{
    size_t used = 0;
    bool wrote_anything = false;

    if (!outBuf || outBufSize == 0) {
        return false;
    }

    outBuf[0] = '\0';

    for (int i = 0; i < process_count; i++) {
        if (processes[i].curr_bucket == color &&
            processes[i].active) {

            int written = snprintf(
                outBuf + used,
                outBufSize - used,
                "%s%s",
                (used == 0) ? "" : ",",
                processes[i].name
            );

            /* Buffer full or error */
            if (written < 0 ||
                (size_t)written >= (outBufSize - used)) {
                break;  /* Truncation is acceptable */
            }

            used += (size_t)written;
            wrote_anything = true;
        }
    }

    return wrote_anything;
}

/**********************************************************************
    caller:     owner of this object
    prototype
        BOOL
        MemTrace_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );
    description:
        This function is called to retrieve ULONG parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG*                      puLong
                The buffer of returned ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
MemTrace_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    (void) hInsContext;
    if( (strcmp(ParamName, "Interval") == 0) ||
        (strcmp(ParamName, "RSSThreshold") == 0) ||
        (strcmp(ParamName, "InitialSnapshotUptime") == 0)
      )
    {
        if (strcmp(ParamName, "Interval") == 0) {
            *puLong = (unsigned long) interval;
        }
        else if (strcmp(ParamName, "RSSThreshold") == 0) {
            *puLong = rss_threshold;
        }
        else if (strcmp(ParamName, "InitialSnapshotUptime") == 0) {
            *puLong = (unsigned long) initial_snapshot_uptime;
        }
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        MemTrace_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );
    description:
        This function is called to set ULONG parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                ULONG                       uValue
                The updated ULONG value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
MemTrace_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    if( (strcmp(ParamName, "Interval") == 0) ||
        (strcmp(ParamName, "RSSThreshold") == 0) ||
        (strcmp(ParamName, "InitialSnapshotUptime") == 0)
      )
    {
        char res[24] = {0};
        snprintf(res, sizeof(res), "%lu", uValue);
        if (strcmp(ParamName, "Interval") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_Interval", res) != 0) {
                MemTraceWarning(("%s: Failed to set MemTrace_Interval in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            MemTraceInfo(("%s - setting Interval of %s seconds\n", __FUNCTION__, res));
            interval = (unsigned int) uValue;
        }
        else if (strcmp(ParamName, "RSSThreshold") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_RSSThreshold", res) != 0) {
                MemTraceWarning(("%s: Failed to set MemTrace_RSSThreshold in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            MemTraceInfo(("%s - setting RSSThreshold of %s kB\n", __FUNCTION__, res));
            rss_threshold = uValue;
        }
        else if (strcmp(ParamName, "InitialSnapshotUptime") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_InitialSnapshotUptime", res) != 0) {
                MemTraceWarning(("%s: Failed to set MemTrace_InitialSnapshotUptime in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            MemTraceInfo(("%s - setting InitialSnapshotUptime of %s seconds\n", __FUNCTION__, res));
            initial_snapshot_uptime = (unsigned int) uValue;
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        MemTrace_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to get string value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The parameter value;
                ULONG                       pUlSize
                The string length;
    return:     ULONG Size of the returned string.
**********************************************************************/
ULONG
MemTrace_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    (void) hInsContext;

    // Feature is enabled, read from bucket status file
    if (strcmp(ParamName, "ProcessesInCodeYellow") == 0) {
        if (ReadProcessListFromBucketStatus(YELLOW, pValue, *pUlSize)) {
            return 0;
        }
    } else if (strcmp(ParamName, "ProcessesInCodeGreen") == 0) {
        if (ReadProcessListFromBucketStatus(GREEN, pValue, *pUlSize)) {
            return 0;
        }
    } else if (strcmp(ParamName, "ProcessesInCodeRed") == 0) {
        if (ReadProcessListFromBucketStatus(RED, pValue, *pUlSize)) {
            return 0;
        }
    } else {
        MemTraceWarning(("%s - MemTrace has no bucket list\n", __FUNCTION__));
        return 1;
    }
    return 1;
}

rbusError_t MemTrace_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    MemTraceDebug(("In %s\n", __FUNCTION__));
    errno_t rc = 0;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    char value[4096] = {0};
    unsigned long ulSize = sizeof(value);

    MemTraceInfo(("Called %s for [%s]\n", __FUNCTION__, propName));

    rbusValue_Init(&val);

    rc = MemTrace_GetParamStringValue(NULL, param, value, &ulSize);
    free(param);
    if(rc != 0)
    {
        MemTraceError(("[%s]: MemTrace_GetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetString(val, value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    MemTraceDebug(("Out %s\n", __FUNCTION__));
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_GetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    ULONG value = 0;
    rbusValue_t val;

    if (!param)
    {
        MemTraceError(("[%s]: failed to allocate param name\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&val);
    rc = MemTrace_GetParamUlongValue(NULL, param, &value);
    free(param);
    if(rc != TRUE)
    {
        rbusValue_Release(val);
        MemTraceError(("[%s]: MemTrace_GetParamUlongValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetUInt32(val, (uint32_t)value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_SetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);
    ULONG value = 0;

    if (!param || !val)
    {
        free(param);
        MemTraceError(("[%s]: invalid input for ulong set\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    value = (ULONG)rbusValue_GetUInt32(val);
    rc = MemTrace_SetParamUlongValue(NULL, param, value);
    free(param);
    if(rc != TRUE)
    {
        MemTraceError(("[%s]: MemTrace_SetParamUlongValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    return RBUS_ERROR_SUCCESS;
}
