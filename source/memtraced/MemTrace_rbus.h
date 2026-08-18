#include <rbus/rbus.h>
#include <stdint.h>
#include "safec_lib_common.h"
#include "ccsp_trace.h"
#include "ansc_platform.h"
#include <secure_wrapper.h>
#include <syscfg/syscfg.h>

#define BUF_64 64

bool ReadProcessListFromBucketStatus(Bucket color, char* outBuf, size_t outBufSize);

BOOL
MemTrace_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );
BOOL
MemTrace_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );
ULONG
MemTrace_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

rbusError_t MemTrace_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_GetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_SetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);
rbusError_t MemTrace_TableAddRowHandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum);
rbusError_t MemTrace_TableRemoveRowHandler(rbusHandle_t handle, char const* rowName);
rbusError_t MemTrace_TableGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_TableSetHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

#define MT_COMPONENT_NAME "MemTraceRbus"

rbusError_t MemTraceRbusInit(void);
