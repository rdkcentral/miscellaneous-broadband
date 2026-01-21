#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "onestack.h"
#include "onestack_log.h"
#include "syscfg/syscfg.h"
#include "platform_hal.h"

#if defined(_ONESTACK_PRODUCT_REQ_)
#define BUFLEN_32 32
#define BUFLEN_256 256
#define MAX_RETRY 3
#define RETRY_DELAY_SEC 1
#define PARTNER_ID_FILE "/nvram/.partner_ID"

/**
 * @brief Trim trailing newline from string
 * @param str String to trim
 */
static inline void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0';
    }
}

/**
 * @brief Get partner ID with fallback mechanism
 * @param pValue Buffer to store the partner ID
 * @param size Size of the buffer
 * @return 0 on success, -1 on failure
 */
int getpartnerid(char *pValue, int size)
{
    FILE *fp = NULL;
    char buffer[BUFLEN_256] = {0};
    int retry;

    if (!pValue || size <= 0)
    {
        ONESTACK_ERROR("%s: Invalid parameters (pValue=%p, size=%d)\n", __FUNCTION__, pValue, size);
        return -1;
    }

    ONESTACK_DEBUG("%s: Starting partner ID retrieval\n", __FUNCTION__);

    // 1. Try HAL API with retries
    for (retry = 0; retry < MAX_RETRY; retry++)
    {
        ONESTACK_DEBUG("%s: Attempting HAL API call (attempt %d/%d)\n", __FUNCTION__, retry + 1, MAX_RETRY);
        if (platform_hal_getFactoryPartnerId(pValue) == 0 && pValue[0] != '\0')
        {
            ONESTACK_INFO("%s: Partner ID retrieved from HAL API: %s (attempt %d)\n", __FUNCTION__, pValue, retry + 1);
            return 0;
        }
        if (retry < MAX_RETRY - 1)
        {
            sleep(RETRY_DELAY_SEC);
        }
    }
    ONESTACK_WARN("%s: HAL API failed after %d retries, trying file method\n", __FUNCTION__, MAX_RETRY);

    // 2. Try reading from file
    if (access(PARTNER_ID_FILE, R_OK) == 0)
    {
        ONESTACK_DEBUG("%s: Attempting to read from file: %s\n", __FUNCTION__, PARTNER_ID_FILE);
        fp = fopen(PARTNER_ID_FILE, "r");
        if (fp)
        {
            if (fgets(buffer, sizeof(buffer), fp))
            {
                trim_newline(buffer);
                
                if (buffer[0] != '\0')
                {
                    strncpy(pValue, buffer, size - 1);
                    pValue[size - 1] = '\0';
                    fclose(fp);
                    ONESTACK_INFO("%s: Partner ID retrieved from file: %s\n", __FUNCTION__, pValue);
                    return 0;
                }
            }
            fclose(fp);
        }
        else
        {
            ONESTACK_WARN("%s: Failed to open file: %s\n", __FUNCTION__, PARTNER_ID_FILE);
        }
    }
    else
    {
        ONESTACK_DEBUG("%s: File not accessible: %s, trying syscfg\n", __FUNCTION__, PARTNER_ID_FILE);
    }

    // 3. Fallback to syscfg
    ONESTACK_DEBUG("%s: Attempting syscfg_get for PartnerID\n", __FUNCTION__);
    if (syscfg_get(NULL, "PartnerID", pValue, size) == 0 && pValue[0] != '\0')
    {
        ONESTACK_INFO("%s: Partner ID retrieved from syscfg: %s\n", __FUNCTION__, pValue);
        return 0;
    }

    ONESTACK_ERROR("%s: Failed to retrieve partner ID from all sources (HAL/File/Syscfg)\n", __FUNCTION__);
    return -1;
}

int main(int argc, char *argv[])
{
    char partnerId[BUFLEN_256] = {0};
    bool isBci = false;

    // Initialize RDK logger
    if (!onestack_log_init())
    {
        printf("Warning: Logging initialization failed, continuing with console output\n");
    }

    ONESTACK_INFO("OneStack Partner ID Utility started\n");
    printf("OneStack Partner ID Utility\n");
    printf("===========================\n\n");

    if (getpartnerid(partnerId, sizeof(partnerId)) == 0)
    {
        isBci = (strcmp(partnerId, "comcast-business") == 0);
        
        ONESTACK_INFO("Partner ID: %s | Is BCI: %s\n", partnerId, isBci ? "Yes" : "No");
        printf("\n[SUCCESS] Partner ID: %s\n", partnerId);
        printf("[INFO] Partner is %sComcast Business (BCI)\n", isBci ? "" : "NOT ");
        
        onestack_log_deinit();
        return 0;
    }

    ONESTACK_ERROR("Failed to retrieve Partner ID\n");
    fprintf(stderr, "\n[FAILED] Unable to retrieve Partner ID\n");
    
    onestack_log_deinit();
    return 1;
}

#else

int main(int argc, char *argv[])
{
    fprintf(stderr, "ERROR: OneStack utility is not enabled (_ONESTACK_PRODUCT_REQ_ not defined)\n");
    return 1;
}

#endif
