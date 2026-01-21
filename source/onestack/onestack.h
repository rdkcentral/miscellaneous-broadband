#ifndef _COMMON_ONESTACK_H_
#define _COMMON_ONESTACK_H_

#include <stdbool.h>

#ifdef _ONESTACK_PRODUCT_REQ_

/**
 * @brief Check if the current partner is BCI (Comcast Business)
 * @return true if partner is comcast-business, false otherwise
 */
bool is_bci_partner(void);

#endif

#endif /* _COMMON_ONESTACK_H_ */
