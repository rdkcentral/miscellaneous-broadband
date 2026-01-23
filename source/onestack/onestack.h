#ifndef _COMMON_ONESTACK_H_
#define _COMMON_ONESTACK_H_

#include <stdbool.h>

#ifdef _ONESTACK_PRODUCT_REQ_

/**
 * @brief Get partner ID with fallback mechanism
 * 
 * This function attempts to retrieve the partner ID using the following priority:
 * 1. HAL API (platform_hal_getFactoryPartnerId) with 3 retries
 * 2. Read from /nvram/.partner_ID file
 * 3. Read from syscfg (PartnerID)
 * 
 * @param pValue Buffer to store the partner ID
 * @param size Size of the buffer
 * @return 0 on success, -1 on failure
 */
int getpartnerid(char *pValue, int size);

#endif

#endif /* _COMMON_ONESTACK_H_ */
