/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2020 RDK Management
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

#ifndef MOCK_OVS_H
#define MOCK_OVS_H


#include <gtest/gtest.h>
#include <gmock/gmock.h>
extern "C"
{
#include "OvsAgentApi.h"
}

class OvsInterface {
public:
	virtual ~OvsInterface() {}
	virtual bool ovs_agent_api_get_config(OVS_TABLE , void ** ) = 0;
	virtual bool ovs_agent_api_interact(ovs_interact_request * , ovs_interact_cb ) = 0;
        virtual bool ovs_agent_api_deinit(void) = 0;
	virtual bool ovs_agent_api_init(OVS_COMPONENT_ID) = 0;
};

class OvsMock: public OvsInterface {
public:
	virtual ~OvsMock() {}
	MOCK_METHOD2(ovs_agent_api_get_config, bool(OVS_TABLE , void ** ));
	MOCK_METHOD2(ovs_agent_api_interact, bool(ovs_interact_request * , ovs_interact_cb ));
        MOCK_METHOD0(ovs_agent_api_deinit, bool(void));
        MOCK_METHOD1(ovs_agent_api_init, bool(OVS_COMPONENT_ID));
};

#endif




