#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "onestack.h"

#if defined(_ONESTACK_PRODUCT_REQ_)
#define BUFLEN_32 32
static char partnerID[BUFLEN_32] = {0};

bool is_bci_partner(void)
{
    if (partnerID[0] == '\0')
    {
        if (syscfg_get(NULL, "PartnerID", partnerID, sizeof(partnerID)) != 0)
        {
            return false;
        }
    }
    return strcmp(partnerID, "comcast-business") == 0;
}
#endif
