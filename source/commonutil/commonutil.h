/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2017 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef  _COMMONUTIL_H
#define  _COMMONUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "ccsp_base_api.h"
#include "syscfg/syscfg.h"
#include "ccsp_psm_helper.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"

#define CCSP_SUBSYS "eRT."

typedef enum
{
        SYSCFG_DB = 0,
        PSM_DB
} paramDbName_t;

typedef enum
{
        PARAM_BOOLEAN  = 0,      /**< bool true or false */
        PARAM_INT,               /**< integer */
        PARAM_UINT,              /**< unsigned integer */
        PARAM_STRING,            /**< string */
        PARAM_CHAR,              /**< char of size 1 byte*/
        PARAM_BYTE,              /**< unsigned char */
        PARAM_INT8,              /**< 8 bit int */
        PARAM_UINT8,             /**< 8 bit unsigned int */
        PARAM_INT16,             /**< 16 bit int */
        PARAM_UINT16,            /**< 16 bit unsigned int */
        PARAM_INT32,             /**< 32 bit int */
        PARAM_UINT32,            /**< 32 bit unsigned int */
        PARAM_INT64,             /**< 64 bit int */
        PARAM_UINT64,            /**< 64 bit unsigned int */
        PARAM_SINGLE,            /**< 32 bit float */
        PARAM_DOUBLE,            /**< 64 bit float */
        PARAM_NONE
} paramValueType_t;

bool GetValueFromDb(char *ParamName, void *pValue, paramValueType_t ValueType, paramDbName_t DbName);
bool SetValueToDb(char *ParamName, char *pValue, paramDbName_t DbName);

#endif /* _COMMONUTIL_H */
