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

#include "commonutil.h"

extern ANSC_HANDLE rbus_handle;

extern char *pComponentName;

static bool CastValueFromString(char* fromValue, void* toValue, paramValueType_t ValueType)
{
        if (!fromValue || !toValue) {
                CcspTraceError(("CastValueFromString: NULL pointer (fromValue=%p, toValue=%p)\n", fromValue, toValue));
                return false;
        }
        if (fromValue[0] == '\0') {
                CcspTraceError(("CastValueFromString: Empty fromValue string\n"));
                return false;
        }
        int ind = -1;

        switch(ValueType)
        {
        case PARAM_BOOLEAN:
                if((strcmp_s("true",strlen("true"),fromValue, &ind) == EOK) && (!ind))
                {
                        *((bool*) toValue) = true;
                        break;
                }
                else if((strcmp_s("false",strlen("false"),fromValue, &ind) == EOK) && (!ind))
                {
                        *((bool*) toValue) = false;
                        break;
                }
                else
                {
                        CcspTraceError(("%s failed for the parameter %s in %d\n", __FUNCTION__, fromValue, __LINE__));
                        return false;
                }

        case PARAM_INT:
                *((int*) toValue) = atoi(fromValue);
                break;

        case PARAM_UINT:
                *((unsigned int*) toValue) = atoi(fromValue);
                break;

        case PARAM_UINT16:
                *((uint16_t*) toValue) = atoi(fromValue);
                break;

        case PARAM_INT32:
                *((int32_t*) toValue) = atoi(fromValue);
                break;

        case PARAM_STRING:
                strcpy(toValue, fromValue);
                break;

        default:
                strcpy(toValue, fromValue);
                break;
        }
        return true;
}

/** PSM RBUS util apis */
static int 
execute_method_cmd
	(
		char *method, 
		rbusObject_t inParams, 
		char** pOutValue
	)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rbusValue_t value = NULL;
    rbusObject_t outParams = NULL;
    rbusProperty_t prop = NULL;
    char *str_value = NULL;

    rc = rbusMethod_Invoke(rbus_handle, method, inParams, &outParams);
	if(inParams) {
        rbusObject_Release(inParams);
	}

    if(RBUS_ERROR_SUCCESS != rc)
    {
        CcspTraceInfo(("%s failed for %s with err: '%s'\n\r",__FUNCTION__, method,rbusError_ToString(rc)));
        return -1;
    }

    prop = rbusObject_GetProperties(outParams);
    while(prop)
    {
        value = rbusProperty_GetValue(prop);
        if(value)
        {
            str_value = rbusValue_ToString(value,NULL,0);

            if(str_value)
            {
				if (0 == strcmp("GetPSMRecordValue()", method)) {
					*pOutValue = (char*) malloc(strlen(str_value) + 1);
					strncpy(*pOutValue, str_value, strlen(str_value) + 1);
					CcspTraceInfo(("PSM_Get_Record_Value_Rbus: Name  : %s   Value : %s\n", rbusProperty_GetName(prop), *pOutValue));
				}
				else if (0 == strcmp("SetPSMRecordValue()", method)) {
					CcspTraceInfo(("PSM_Set_Record_Value_Rbus for parameter '%s' success\n", rbusProperty_GetName(prop)));
				}
				else if (0 == strcmp("DeletePSMRecord()", method)) {
					CcspTraceInfo(("PSM_Del_Record_Value_Rbus for parameter '%s' success\n", rbusProperty_GetName(prop)));
				}
				free(str_value);
            }
			else {
				rbusObject_Release(outParams);
				return 1;
			}
        }
		else {
			rbusObject_Release(outParams);
			return 1;
		}
        prop = rbusProperty_GetNext(prop);
    }

    rbusObject_Release(outParams);
	return 0;
}

bool
PSM_Get_Record_Value_Rbus
	(
		char*	PsmParamName,
		char**	pOutValue
	)
{
	int ret;
	rbusProperty_t prop = NULL;
	rbusObject_t inParams = NULL;

	rbusObject_Init(&inParams, NULL);
	rbusProperty_Init(&prop, PsmParamName, NULL) ;
	rbusObject_SetProperty(inParams,prop);
	rbusProperty_Release(prop);
	ret = execute_method_cmd("GetPSMRecordValue()", inParams, pOutValue);
	if (ret != 0){
		return false;
	}
	return true;
}

bool
PSM_Set_Record_Value_Rbus
	(
		char*	PsmParamName,
		char*	pInValue
	)
{
	int ret;
	rbusValue_t value = NULL;
	rbusProperty_t prop = NULL;
	rbusObject_t inParams = NULL;

	rbusObject_Init(&inParams, NULL);
	rbusValue_Init(&value);
	if(false == rbusValue_SetFromString(value, RBUS_STRING, pInValue))
	{
		CcspTraceError(("%s:Invalid value '%s' for the parameter %s\n\r", __FUNCTION__, pInValue, PsmParamName));
		return false;
	}
	rbusProperty_Init(&prop, PsmParamName, value);
	rbusObject_SetProperty(inParams,prop);
	rbusValue_Release(value);
	rbusProperty_Release(prop);
	ret = execute_method_cmd("SetPSMRecordValue()", inParams, NULL);
	if (ret != 0){
		return false;
	}
	return true;
}

bool GetValueFromDb(char *ParamName, void *pValue, paramValueType_t ValueType, paramDbName_t DbName)
{
        if (!ParamName || ParamName[0] == '\0') {
                CcspTraceError(("GetValueFromDb: NULL or empty ParamName!\n"));
                return false;
        }
        if (!pValue) {
                CcspTraceError(("GetValueFromDb: NULL pValue for ParamName=%s!\n", ParamName));
                return false;
        }
        if (DbName == SYSCFG_DB) {
                char out_value[256] = {0};
                memset(out_value, 0, sizeof(out_value));

                if(!syscfg_get(NULL, ParamName, out_value, sizeof(out_value))) {
                        if(!CastValueFromString(out_value, pValue, ValueType)){
                                CcspTraceError(("syscfg_get failed for the parameter %s in %d\n", ParamName, __LINE__));
                                return false;
                        }
                        CcspTraceInfo(("syscfg_get success for the parameter %s and has value : %s\n", ParamName, out_value));
                        return true;
                }
                else {
                        CcspTraceError(("syscfg_get failed for the parameter %s\n", ParamName));
                        return false;
                }
                return false;
        }

        if (DbName == PSM_DB) {
                char* strValue = NULL;
                if (!PSM_Get_Record_Value_Rbus(ParamName, &strValue)) {
                        CcspTraceError(("%s: psm get failed for the parameter %s\n", __FUNCTION__, ParamName));
                        return false;
                }
                if (strValue != NULL)
                {
                        if(!CastValueFromString(strValue, pValue, ValueType)){
                                CcspTraceError(("psm_get failed for the parameter %s in %d\n", ParamName, __LINE__));
                                return false;
                        }
                        CcspTraceInfo(("psm_get success for the parameter %s and has value : %s\n", ParamName, strValue));
                        free(strValue);
                        return true;
                }
                else
                {
                        CcspTraceError(("psm_get failed for the parameter %s\n", ParamName));
                        return false;
                }
                return false;
        }
        return false;
}

bool SetValueToDb(char *ParamName, char *pValue, paramDbName_t DbName)
{
        if (DbName == SYSCFG_DB){

                if( syscfg_set( NULL, ParamName, pValue ) != 0 )
                {
                        CcspTraceError(("syscfg_set failed for the parameter %s\n", ParamName));
                        return false;
                }
                else
                {
                        if ( 0 != syscfg_commit( ) )
                        {
                                CcspTraceError(("syscfg_set commit failed for the parameter %s\n", ParamName));
                                return false;
                        }
                }
                return true;
        }

        if (DbName == PSM_DB){
                if(!PSM_Set_Record_Value_Rbus(ParamName, pValue)) {
                        CcspTraceError(("psm_set failed for the parameter %s\n", ParamName));
                        return false;
                }
                return true;
        }
        return false;
}
