#include <stdbool.h>
#include <stdarg.h>
#include "rdk_debug.h"

/******************************************************************
 * @brief Enables or disables logs of different severity levels.
 *****************************************************************/

#define DEBUG_INI_NAME  "/etc/debug.ini"
#define ARGS_EXTRACT(msg ...) msg

#define MEMTRACE_LOG(level, msg)  \
    RDK_LOG(level, "LOG.RDK.MEMTRACE", ARGS_EXTRACT msg);

#define MemTraceError(msg)       MEMTRACE_LOG(RDK_LOG_ERROR, msg)
#define MemTraceInfo(msg)        MEMTRACE_LOG(RDK_LOG_INFO, msg)
#define MemTraceWarning(msg)     MEMTRACE_LOG(RDK_LOG_WARN, msg)
#define MemTraceDebug(msg)       MEMTRACE_LOG(RDK_LOG_DEBUG, msg)

bool MemTrace_Log_Init();
bool MemTrace_Log_Deinit();