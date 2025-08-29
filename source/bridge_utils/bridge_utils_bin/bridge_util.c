/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

#include "bridge_util.h"
#include "bridge_util_generic.h"
#include "bridge_creation.h"
#include <unistd.h>
#include <stdint.h>
#include "cap.h"
#include "secure_wrapper.h"
#include <sys/stat.h>
#include <arpa/inet.h>
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#ifdef CORE_NET_LIB
#include <libnet.h>
#else
#include "linux/if.h"
#endif
#define ONEWIFI_ENABLED "/etc/onewifi_enabled"
#define OPENVSWITCH_LOADED "/sys/module/openvswitch"
#define WFO_ENABLED        "/etc/WFO_enabled"
#define DEFAULT_NETMASK_ADDR "255.255.255.0"
#define BRCTL_INTERACT_ENABLE_FILE "/var/tmp/brctl_interact_enable.txt"
#define isValidSubnetByte(byte) (((byte == 255) || (byte == 254) || (byte == 252) || \
                                  (byte == 248) || (byte == 240) || (byte == 224) || \
                                  (byte == 192) || (byte == 128)) ? 1 : 0)
static char *component_id = "ccsp.bridgeUtils";
static char *pCfg 	= CCSP_MSG_BUS_CFG;
static void  *bus_handle  = NULL;
static cap_user   appcaps;

int InstanceNumber = 0; 
int DeviceMode = 0,ovsEnable = 0 , bridgeUtilEnable = 0 , skipWiFi=0 , ethWanEnabled =0 , PORT2ENABLE = 0, eb_enable = 0; // router = 0, bridge = 2
#if !defined (NO_MOCA_FEATURE_SUPPORT)
int skipMoCA = 0;
#endif
int wan_mode = 0;
#ifdef RDKB_EXTENDER_ENABLED
int DeviceNetworkingMode = DEVICE_NETWORKINGMODE_ROUTER; // 0 is router, 1 is extender.
#endif
char Cmd_Opr[32] = {0};
char primaryBridgeName[64] = {0} , ethWanIfaceName[64] ={0} ;
// It confirms whether the opeartion is to create the bridge or to remove the bridge
int BridgeOprInPropgress = -1;
int syseventfd_vlan = 0 ;
token_t sysevent_token_vlan;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
int MocaIsolation_Enabled =0 ;
#endif

int syncMembers = 0 ;

int need_wifi_gw_refresh = 0, need_switch_gw_refresh = 0 ;

FILE *logFp = NULL;
char log_buff[MAX_LOG_BUFF_SIZE] = {0} ;
char log_msg_wtime[MAX_LOG_BUFF_SIZE+TIMESTAMP];

struct tm *timeinfo;
time_t utc_time;

static char *l2netBridgeName = "dmsb.l2net.%d.Name";
static char *l2netVlanID = "dmsb.l2net.%d.Vid";
static char *l2netEthMembers = "dmsb.l2net.%d.Members.Eth";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
static char *l2netMocaMembers = "dmsb.l2net.%d.Members.Moca";
#endif
static char *l2netGreMembers = "dmsb.l2net.%d.Members.Gre";
#ifdef RDK_ONEWIFI
static char *l2netWiFiMembers = "dmsb.l2net.%d.Members.OneWiFi";
#else
static char *l2netWiFiMembers = "dmsb.l2net.%d.Members.WiFi";
#endif
static char *l2netLinkMembers = "dmsb.l2net.%d.Members.Link";
static char *l2netVirualParentIfname = "dmsb.l2net.%d.Members.VirtualParentIfname";

static char *l2netEthWanInterface = "dmsb.l2net.EthWanInterface";
#if !defined (NO_MOCA_FEATURE_SUPPORT)
static char *mocaIsolation = "dmsb.l2net.HomeNetworkIsolation";

static char *mocaIsolationL3Net = "dmsb.MultiLAN.MoCAIsoLation_l3net";
#endif
static char *LnFL3Net = "dmsb.MultiLAN.LnF_l3net";
static char *MeshBhaulL3Net = "dmsb.MultiLAN.MeshBhaul_l3net";
static char *MeshOnboardL3Net = "dmsb.MultiLAN.MeshOnboard_l3net";
static char *MeshWiFiBhaulL3Net_2G = "dmsb.MultiLAN.MeshWiFiBhaul_2G_l3net";
static char *MeshWiFiBhaulL3Net_5G = "dmsb.MultiLAN.MeshWiFiBhaul_5G_l3net";
static char *MeshWiFiOnboardL3Net_2G = "dmsb.MultiLAN.MeshWiFiOnboard_2G_l3net";
static char *EthBhaulL3Net = "dmsb.MultiLAN.EthBhaul_l3net";
#if defined (WIFI_MANAGE_SUPPORTED)
static char *ManageWiFiData = "dmsb.MultiLAN.ManageWiFi_l3net";
#endif /*WIFI_MANAGE_SUPPORTED*/

static char *l2netLinuxBridgeEnabled= "dmsb.l2net.%d.LinuxBridgeEnabled";
static char *l3netIPaddr = "dmsb.l3net.%d.V4Addr";

static char *l3netSubnetMask = "dmsb.l3net.%d.V4SubnetMask";

static char *g_Subsystem = "eRT." ;

static char *hotspot_enable = "dmsb.hotspot.enable" ;

#define InterfaceMap_TOTAL (sizeof(InterfaceMap)/sizeof(InterfaceMap[0]))

typedef struct InterfaceMap_s 
{
    char   *iface;
    int    inst;
} InterfaceMap_t;
static InterfaceMap_t InterfaceMap[] = 
{
	{"wlan0.3", LOST_N_FOUND},
	{"wlan0.5", LOST_N_FOUND},
	{"wlan2.3", LOST_N_FOUND},
	{"wlan2.5", LOST_N_FOUND},
	{"wlan0.0", PRIVATE_LAN},
	{"wlan2.0", PRIVATE_LAN},
	{"wlan0.1", HOME_SECURITY},
	{"wlan2.1", HOME_SECURITY},
	{"wlan0.6", MESH_WIFI_BACKHAUL_2G},
	{"wlan2.6", MESH_WIFI_BACKHAUL_5G},
	{"wlan0.2", HOTSPOT_2G},
	{"wlan2.2", HOTSPOT_5G},
	{"wlan0.4", HOTSPOT_SECURE_2G},
	{"wlan2.4", HOTSPOT_SECURE_5G}
};

br_shm_mutex brmutex;

#if !defined(USE_LINUX_BRIDGE)
int mapOvsCmdToBrCmd(int ifCmd)
{
    int brCmdType = -1;
    switch (ifCmd)
    {
        case IF_UP_CMD:
            brCmdType = OVS_IF_UP_CMD;
            break;
        case IF_DELETE_CMD:
            brCmdType = OVS_IF_DELETE_CMD;
            break;
        case BR_REMOVE_CMD:
            brCmdType = OVS_BR_REMOVE_CMD;
            break;
        case IF_DOWN_CMD:
            brCmdType = OVS_IF_DOWN_CMD;
            break;
        default:
            break;
    }
    return brCmdType;
}
#endif

void subnet(char *ipv4Addr, char *ipv4Subnet, char *subnet)
{
    int l_iFirstByte, l_iSecondByte, l_iThirdByte, l_iFourthByte;
    int l_iFirstByteSub, l_iSecondByteSub, l_iThirdByteSub, l_iFourthByteSub;

    sscanf(ipv4Addr, "%d.%d.%d.%d", &l_iFirstByte, &l_iSecondByte, 
           &l_iThirdByte, &l_iFourthByte);

    sscanf(ipv4Subnet, "%d.%d.%d.%d", &l_iFirstByteSub, &l_iSecondByteSub, 
           &l_iThirdByteSub, &l_iFourthByteSub);

    l_iFirstByte = l_iFirstByte & l_iFirstByteSub;
    l_iSecondByte = l_iSecondByte & l_iSecondByteSub;
    l_iThirdByte = l_iThirdByte & l_iThirdByteSub;
    l_iFourthByte = l_iFourthByte & l_iFourthByteSub;

    snprintf(subnet, 16, "%d.%d.%d.%d", l_iFirstByte, 
             l_iSecondByte, l_iThirdByte, l_iFourthByte);
}
unsigned int countSetBits(int byte)
{
    unsigned int l_iCount = 0;
    if (isValidSubnetByte(byte) || 0 == byte)
    {
        while (byte)
        {
            byte &= (byte-1);
            l_iCount++;
        }
        return l_iCount;
    }
    else
    {
        bridge_util_log("Invalid subnet byte:%d\n", byte);
        return 0;
    }
}

unsigned int mask2cidr(char *subnetMask)
{
    int l_iFirstByte, l_iSecondByte, l_iThirdByte, l_iFourthByte;
    int l_iCIDR = 0;

    sscanf(subnetMask, "%d.%d.%d.%d", &l_iFirstByte, &l_iSecondByte,
            &l_iThirdByte, &l_iFourthByte);

    l_iCIDR += countSetBits(l_iFirstByte);
    l_iCIDR += countSetBits(l_iSecondByte);
    l_iCIDR += countSetBits(l_iThirdByte);
    l_iCIDR += countSetBits(l_iFourthByte);
    return l_iCIDR;
}

#if defined (AMENITIES_NETWORK_ENABLED)
#define SYS_CLASS_PATH_OF_BRIDGES         "/sys/class/net/%s/bridge/nf_call_iptables"
void setNfCallIptables(char * pBridgeName, BOOL bValue)
{
    if (NULL == pBridgeName)
        return;

    char cPath [128] = {0};
    char cVal [8] = {0};
    snprintf(cPath,sizeof(cPath),SYS_CLASS_PATH_OF_BRIDGES,pBridgeName);
    int iFd = open(cPath,O_WRONLY);
    if (iFd >= 0)
    {
        snprintf(cVal, sizeof(cVal),"%d",bValue);
        write(iFd,cVal, 1);
        close(iFd);
    }
    else
    {
        bridge_util_log ("%s:%d,Failed to open:%s\n",__FUNCTION__,__LINE__,cPath);
        perror("open");
    }
}
#endif /*AMENITIES_NETWORK_ENABLED*/
/***********************************************************************
 * broad cast address set API
***********************************************************************/
#ifdef CORE_NET_LIB
void Set_Broadcast_address(char IfName[],char subnetmask[],char IpAddr[])
{
	int l_iCIDR;
	char l_cSubnet[16] = {0};
	char bcast[INET_ADDRSTRLEN];
	char Cmd[255] = {0};

	l_iCIDR = mask2cidr(subnetmask);
	subnet(IpAddr, subnetmask, l_cSubnet);
    bridge_util_log("%s Adding IP routes\n",__FUNCTION__);
	addr_derive_broadcast(IpAddr, l_iCIDR, bcast, INET_ADDRSTRLEN);
	snprintf(Cmd, sizeof(Cmd),"%s/%d broadcast %s dev %s",IpAddr, l_iCIDR, bcast, IfName);
    addr_add(Cmd);
    bridge_util_log("%s cmd: %s\n",__func__,Cmd);
}
#endif
/*********************************************************************************************

    caller:  main
    prototype:

        br_shm_mutex
        br_shm_mutex_init
            (
              char *mutexName,
            );
    	description :
			This function initilizes shared memory mutex, so that 2 instance of same process 
			will not run together.    
    	argument:   
              		char *mutexName    --> mutex name
    
***********************************************************************************************/


br_shm_mutex br_shm_mutex_init(char *mutexName) {
	errno = 0;
	br_shm_mutex bridgeMutex;
	memset(&bridgeMutex,0,sizeof bridgeMutex);
	/* CID :175705 Buffer not null terminated (BUFFER_SIZE) */
	strncpy(bridgeMutex.br_mutex, mutexName,sizeof(bridgeMutex.br_mutex)-1);	
	bridgeMutex.br_shm_fd= shm_open(mutexName, O_RDWR, 0660);
	if (errno == ENOENT) 
	{
		bridge_util_log("shm open in create mode\n");
		bridgeMutex.br_shm_fd = shm_open(mutexName, O_RDWR|O_CREAT, 0660);
		bridgeMutex.br_shm_create = 1;
	}
	if (bridgeMutex.br_shm_fd == -1) 
	{
		bridge_util_log("shm_open call failed\n");
		return bridgeMutex;
	}
	if (ftruncate(bridgeMutex.br_shm_fd, sizeof(pthread_mutex_t)) != 0) {
		bridge_util_log("ftruncate call failed\n");
		return bridgeMutex;
	}
	  // Using mmap to map the pthread mutex into the shared memory.
	 void *address = mmap(
		    NULL,
		    sizeof(pthread_mutex_t),
		    PROT_READ|PROT_WRITE,
		    MAP_SHARED,
		    bridgeMutex.br_shm_fd,
		    0
	  );
	if (address == MAP_FAILED)
	{
		bridge_util_log("mmap failed\n");
		return bridgeMutex;
	}
	bridgeMutex.ptr  = (pthread_mutex_t *)address;
	if (bridgeMutex.br_shm_create) 
	{
		pthread_mutexattr_t attr;
		if (pthread_mutexattr_init(&attr)) 
		{
			bridge_util_log("pthread_mutexattr_init failed\n");
			return bridgeMutex;
		}
		int error = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		if (error) 
		{
			bridge_util_log("pthread_mutexattr_setpshared error %d: %s\n",error,strerror(error));
			return bridgeMutex;
		}		
		error = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
		if (error) 
		{
			bridge_util_log("pthread_mutexattr_setprotocol error %d: %s\n", error , strerror(error));
		}	
		error = pthread_mutexattr_setrobust_np(&attr, PTHREAD_MUTEX_ROBUST_NP);
		if (error) 
		{
			bridge_util_log("pthread_mutexattr_setrobust_np error %d: %s\n" ,error,strerror(error));
		}	
		if (pthread_mutex_init(bridgeMutex.ptr, &attr)) 
		{
			bridge_util_log("pthread_mutex_init failed\n");
			return bridgeMutex;
		}
	}
	return bridgeMutex;
}

/*********************************************************************************************

    caller:  ExitFunc
    prototype:

        int
        br_shm_mutex_close
            (
              br_shm_mutex brmutex,
            );
    	description :
			This function unmap the memory allocated for shm mutex and closes shm mutex.    
    	argument:   
              		br_shm_mutex brmutex    --> pointer to mutex
    
***********************************************************************************************/

int br_shm_mutex_close(br_shm_mutex brmutex) 
{
	if (munmap((void *)brmutex.ptr, sizeof(pthread_mutex_t))) 
	{
		bridge_util_log("munmap failed\n");
		return -1;
	}
	brmutex.ptr = NULL;
	if (close(brmutex.br_shm_fd)) 
	{
		bridge_util_log("closing file handler");
		return -1;
	}
	brmutex.br_shm_fd = 0;
return 0;
}

// Function to check if interface is created
int checkIfExists(char* iface_name)
{
	struct ifreq ifr;
	int fd;
	if (strlen(iface_name) >= sizeof(ifr.ifr_name)) {
		bridge_util_log("%s Interface doesn't exists \n",iface_name);
		return INTERFACE_NOT_EXIST;
	}
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		bridge_util_log("%s Interface doesn't exists \n",iface_name);
		return INTERFACE_NOT_EXIST;
	}

        /*CID 180986 Calling risky function */
        strncpy(ifr.ifr_name, iface_name, (sizeof(ifr.ifr_name)-1));
        ifr.ifr_name[(sizeof(ifr.ifr_name)-1)] = '\0';

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		if (errno == ENODEV) {
			bridge_util_log("%s Interface doesn't exists \n",iface_name);
			close(fd);
			return INTERFACE_NOT_EXIST;
		}
	}

    close(fd);
    return INTERFACE_EXIST;
}
// Function to check if interface is attached to bridge
int checkIfExistsInBridge(char* iface_name, char *bridge_name)
{
	FILE *fp = NULL;
	int ret =0;
	char *token = NULL;
	char if_list[IFLIST_SIZE] = {'\0'};
#if !defined(USE_LINUX_BRIDGE)
	if ( 1 == ovsEnable )
	{
		fp = v_secure_popen("r","ovs-vsctl list-ifaces %s | grep %s | tr '\n' ' ' ",bridge_name, iface_name);
	}
	else
	{
		fp = v_secure_popen("r","brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ",bridge_name, iface_name);
	}
#else
	fp = v_secure_popen("r","brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ",bridge_name, iface_name);
#endif
	if ( fp != NULL )
	{
		fgets(if_list,IFLIST_SIZE-1,fp);
		if_list[strlen(if_list)-1] = '\0';
		ret = v_secure_pclose(fp);
		if(ret !=0)
		{
	            bridge_util_log("Error in closing pipe ret val [%d] \n",ret);
		}
	}
	if(strlen(if_list) > 1)
	{
		token = strtok(if_list, " ");
		while(token != NULL)
		{
			if(strcmp(token, iface_name) == 0)
			{
				bridge_util_log("%s is attached to %s\n",iface_name, bridge_name);
				return INTERFACE_EXIST;
			}
		}
	}
	bridge_util_log("%s is not attached to %s\n",iface_name, bridge_name);
	return INTERFACE_NOT_EXIST;
}

void removeIfaceFromList(char *IfList, const char *ifname) 
{
	size_t len = strlen(ifname);
	if (len > 0) {
		char *token = IfList;
		while ((token = strstr(token, ifname)) != NULL) {
			memmove(token, token + len, strlen(token + len) + 1);
		}
	}
}

/*********************************************************************************************

    caller:  CreateBrInterface, addIfaceToBridge
    prototype:

        int
        getMTU
            (
              int InstanceNumber,
            );
    	description :
			This function  returns the MTU value based on the instance number   
    	argument:   
              		int InstanceNumber    --> Instance number
    
***********************************************************************************************/
int getMTU(int InstanceNumber)
{
	int mtu = 0 ;

	switch(InstanceNumber)
	{
		case MESH:			

		case MESH_BACKHAUL:

        case MESH_ONBOARD:

		case MESH_WIFI_BACKHAUL_2G:

		case MESH_WIFI_BACKHAUL_5G:

        case MESH_WIFI_ONBOARD_2G:
					mtu = 1600 ;
					break;	
		case ETH_BACKHAUL:
					break;	
		case PRIVATE_LAN:
					break;

		case HOME_SECURITY:
					break;	
				
		case HOTSPOT_2G:
					break;

		case HOTSPOT_5G:
					break;	
				
		case LOST_N_FOUND:
					break;

		case HOTSPOT_SECURE_2G:
					break;	

		case HOTSPOT_SECURE_5G:
					break;

#if !defined (NO_MOCA_FEATURE_SUPPORT)
		case MOCA_ISOLATION:
					break;	
#endif

		default :
					bridge_util_log("Default case\n");

	}
	return mtu;	
}

#if !defined (NO_MOCA_FEATURE_SUPPORT)
/*********************************************************************************************

    caller:  CreateBrInterface
    prototype:

        void
        enableMoCaIsolationSettings
            (
              bridgeDetails *bridgeDetails,
            );
    	description :
			This function enables all the settings needed for MoCA Home Isolation when feature 
			is enabled 
    	argument:   
              		bridgeDetails *bridgeDetails    --> Parameter has complete bridge info including
              									  vlan, vlanid and all the interfaces attached
              									  to bridge
    
***********************************************************************************************/
void enableMoCaIsolationSettings (bridgeDetails *bridgeInfo)
{
	char paramName[256]={0};
	int retPsmGet = CCSP_SUCCESS;
	char *paramValue = NULL;
        int ret = 0;
	char ipaddr[32] = {0} ;
	int  mocaIsolationL3NetIdx = 0;  
	char subNetMask[64] = {0};
	snprintf(paramName,sizeof(paramName), mocaIsolationL3Net);
	retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
	if (retPsmGet == CCSP_SUCCESS) 
	{
		bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
		mocaIsolationL3NetIdx = atoi(paramValue);
		if(bus_handle != NULL)
		{
			((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			paramValue = NULL;
		}

	}
    	else
   	{
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    	}
	memset(paramName,0,sizeof(paramName)); 

	snprintf(paramName,sizeof(paramName), l3netIPaddr,mocaIsolationL3NetIdx);
	retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
	if (retPsmGet == CCSP_SUCCESS) 
	{
		bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
		strncpy(ipaddr,paramValue,sizeof(ipaddr)-1);
		if(bus_handle != NULL)
		{
			((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			paramValue = NULL;
		}

	}
	else
    	{
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    	}


	memset(paramName,0,sizeof(paramName)); 

	snprintf(paramName,sizeof(paramName), l2netBridgeName,PRIVATE_LAN);
	retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
	if (retPsmGet == CCSP_SUCCESS) 
	{
		bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
		strncpy(primaryBridgeName,paramValue,sizeof(primaryBridgeName)-1);
		if(bus_handle != NULL)
		{
			((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			paramValue = NULL;
		}

	}
    else
    {
    	bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    }
	memset(paramName,0,sizeof(paramName));
    snprintf(paramName,sizeof(paramName), l3netSubnetMask,mocaIsolationL3NetIdx);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS)
    {
        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	if(paramValue[0]!='\0')
	{
           strncpy(subNetMask,paramValue,sizeof(subNetMask)-1);
	}
	else
	{
           strncpy(subNetMask,DEFAULT_NETMASK_ADDR,sizeof(subNetMask)-1);
	}
		if(bus_handle != NULL)
		{
        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
        	paramValue = NULL;
		}
    }
    else
    {
        bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);
    }

	#ifdef CORE_NET_LIB
		libnet_status status;
		bridge_util_log("%s bridge name :%s ipaddr:%s subNetMask:%s using core net lib\n",__func__,bridgeInfo->bridgeName,ipaddr,subNetMask);
		Set_Broadcast_address(bridgeInfo->bridgeName,subNetMask,ipaddr);
		interface_set_allmulticast(bridgeInfo->bridgeName);
		interface_set_ip(bridgeInfo->bridgeName,ipaddr);
		//interface_get_netmask(bridgeInfo->bridgeName,subNetMask);
		status=interface_up(bridgeInfo->bridgeName);
		if(status==CNL_STATUS_FAILURE)
		{
			bridge_util_log("Failure to set interface_up:%s\n",bridgeInfo->bridgeName);
		}

		ret=v_secure_system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ;\
				sysctl -w net.ipv4.conf.all.arp_announce=3 ;");
		if(ret !=0)
		{
			bridge_util_log("Failed in exceuting the command via v_secure_system() ret %d\n",ret);
		}
		char buf[128];
		snprintf(buf,sizeof(buf),"from all iif %s lookup all_lans",bridgeInfo->bridgeName);
		rule_add(buf);
		ret= v_secure_system("echo 0 > /proc/sys/net/ipv4/conf/'%s'/rp_filter ;\
				touch %s ",
				bridgeInfo->bridgeName,
				LOCAL_MOCABR_UP_FILE);
		if(ret !=0)
		{
			bridge_util_log("Failed in exceuting the command via v_secure_system() ret %d\n",ret);
		}
	#else
		bridge_util_log("%s bridge name :%s ipaddr:%s \n",__func__,bridgeInfo->bridgeName,ipaddr);
		ret = v_secure_system("ip link set %s allmulticast on ;\
	    	ifconfig %s %s ; \
	    	ip link set %s up ; \
	    	echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ; \
	    	sysctl -w net.ipv4.conf.all.arp_announce=3 ; \
	    	ip rule add from all iif %s lookup all_lans ; \
	    	echo 0 > /proc/sys/net/ipv4/conf/'%s'/rp_filter ;\
	    	touch %s ",
	    	bridgeInfo->bridgeName,
	    	bridgeInfo->bridgeName,
	    	ipaddr,
	    	bridgeInfo->bridgeName,
	    	bridgeInfo->bridgeName,
	    	bridgeInfo->bridgeName,
	    	LOCAL_MOCABR_UP_FILE);

        if(ret !=0)
        {
                bridge_util_log("Failed in exceuting the command via v_secure_system() ret %d\n",ret);
        }

	#endif
	return;
}


/*********************************************************************************************

    caller:  CreateBrInterface
    prototype:

        void
        disableMoCaIsolationSettings
            (
              bridgeDetails *bridgeDetails,
            );
    	description :
			This function disables all the settings from HomeIsolation feature when feature  
			is disabled 
    	argument:   
              		bridgeDetails *bridgeDetails    --> Parameter has complete bridge info including
              									  vlan, vlanid and all the interfaces attached
              									  to bridge
    
***********************************************************************************************/

void disableMoCaIsolationSettings (bridgeDetails *bridgeInfo)
{
	
#ifdef CORE_NET_LIB
	libnet_status status;
	bridge_util_log("%s interface down using core net lib api: %s \n",__FUNCTION__,bridgeInfo->bridgeName);
	status=interface_down(bridgeInfo->bridgeName);
	if(status==CNL_STATUS_FAILURE)
	{
		 bridge_util_log("Failed to set interface %s down\n",bridgeInfo->bridgeName);
	}
#else
	int ret =0;
  	bridge_util_log("%s interface down : %s \n",__FUNCTION__,bridgeInfo->bridgeName);
   ret = v_secure_system("ip link set %s down",bridgeInfo->bridgeName);
    if(ret != 0)
    {
        bridge_util_log("Failed in executing the command via v_secure_system ret val: %d \n",ret);
    }
	
#endif
}
#endif

/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

        bool
        create_bridge_api
            (
              ovs_interact_request *request,
              ovs_interact_request_cb callback
            );
    	description :
			This function creates bridge , and add/delete/update interfaces to it.
			When OVS is enabled ovs api's are called otherwise linux bridge commands are called.
    	argument:   
              		ovs_interact_request *request    --> request contains mode of operation(insert/delete/update)
              								  and bridge,vlan/iface details which needs to created/deleted
              								  /updated
              		ovs_interact_request_cb callback --> callback function 
    	return value : returns true when execution succesed otherwise it returns false
***********************************************************************************************/
#if !defined(USE_LINUX_BRIDGE)
bool create_ovs_bridge_api(interact_request *request, ovs_interact_cb callback) 
{
    if ( 1 == ovsEnable )
    {
        bridge_util_log("%s ovs is enabled, calling ovs api \n", __FUNCTION__ );
        return (ovs_agent_api_interact(&request->ovs_request,callback));
    }
    else
    {
        if ( 1 == bridgeUtilEnable )
        {
            bridge_util_log("%s ovs is disabled, and bridgeUtilEnable is enabled calling brctl api's create bridge \n", __FUNCTION__ );
            return (brctl_interact(request->gw_config) );	
        }
    }
    return false;
}
#endif
/*********************************************************************************************
prototype:
        bool
        create_linux_bridge_api
            (
              ovs_interact_request *request,
            );
        description :
            This function creates bridge , and add/delete/update interfaces to it.
            when linux bridge commands are called.
        argument:   
            ovs_interact_request *request    --> request contains mode of operation(insert/delete/update)
              								  and bridge,vlan/iface details which needs to created/deleted
              								  /updated
        return value : returns true when execution succesed otherwise it returns false
***********************************************************************************************/
#if defined(USE_LINUX_BRIDGE)
bool create_linux_bridge_api(interact_request *request)
{
    if ( 1 == bridgeUtilEnable )
    {
        bridge_util_log("%s ovs is disabled, and bridgeUtilEnable is enabled calling brctl api's create bridge \n", __FUNCTION__ );
        return (brctl_interact(request->gw_config) );	
    }
    return false;
} 
#endif
/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

        int
        getIfList
            (
		bridgeDetails *bridgeInfo
            );
   	description :
			This function get bridge information from PSM database based on Instance Number
    	argument:   
              		bridgeDetails *bridgeInfo   --> bridgeDetails struct contains bridge , 
              								vlan,vlan_id and all interfaces need to be available in bridge
    	return value : returns 0 in case of success
***********************************************************************************************/

int getIfList(bridgeDetails *bridgeInfo)
{
	/* Call PSM to get interface names for given InstanceNumberance */
	/* check Mode if router or Bridge based on that return interface list */
	/* Check if XHS port enable or not for InstanceNumberance belongs to private and XHS*/

    char paramName[256]={0};
    int retPsmGet = CCSP_SUCCESS;
    char *paramValue = NULL;

    snprintf(paramName,sizeof(paramName), l2netBridgeName, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	        
	        strncpy(bridgeInfo->bridgeName,paramValue,sizeof(bridgeInfo->bridgeName)-1);
			if(bus_handle != NULL)
			{
	        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        	paramValue = NULL;
			}

    }
    else
    {
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    }

    memset(paramName,0,sizeof(paramName)); 

    snprintf(paramName,sizeof(paramName), l2netVlanID, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	    bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
		bridgeInfo->vlanID = atoi(paramValue);
		if(bus_handle != NULL)
		{	        
	        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        paramValue = NULL;
		}

    }
    else
    {
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    }
    memset(paramName,0,sizeof(paramName)); 

// TODO : need to decide if we need this call , can VlanLinkMembers be replaced with it or vice versa can be used
    snprintf(paramName,sizeof(paramName), l2netLinkMembers, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	        
	        strncpy(bridgeInfo->vlan_name,paramValue,sizeof(bridgeInfo->vlan_name)-1);
			if(bus_handle != NULL)
			{
	        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        	paramValue = NULL;
			}

    }
    else
    {
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    }

    memset(paramName,0,sizeof(paramName)); 
    snprintf(paramName,sizeof(paramName), l2netVirualParentIfname, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	        
	        strncpy(bridgeInfo->VirtualParentIfname,paramValue,sizeof(bridgeInfo->vlan_name)-1);
			if(bus_handle != NULL)
			{
	        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        	paramValue = NULL;
			}

    }

    memset(paramName,0,sizeof(paramName)); 

    snprintf(paramName,sizeof(paramName), l2netEthMembers, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	        
	        strncpy(bridgeInfo->ethIfList,paramValue,sizeof(bridgeInfo->ethIfList)-1);
			if(bus_handle != NULL)
			{
	        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        	paramValue = NULL;
			}
    }
    else
    {
		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    }

#if !defined (NO_MOCA_FEATURE_SUPPORT)
    if ( skipMoCA != 1 )
    {
		    memset(paramName,0,sizeof(paramName)); 

		    snprintf(paramName,sizeof(paramName), l2netMocaMembers, InstanceNumber);
		    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
		    if (retPsmGet == CCSP_SUCCESS) 
		    {
			        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
			        
			        strncpy(bridgeInfo->MoCAIfList,paramValue,sizeof(bridgeInfo->MoCAIfList)-1);
					if(bus_handle != NULL)
					{
			        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			        	paramValue = NULL;
					}

		    }
		    else
		    {
				    bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

		    }
    }
#endif
    if ( skipWiFi != 1 )
    {
    		    memset(paramName,0,sizeof(paramName)); 

  		    snprintf(paramName,sizeof(paramName), l2netWiFiMembers, InstanceNumber);
		    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
		    if (retPsmGet == CCSP_SUCCESS) 
		    {
			        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
			        
			        strncpy(bridgeInfo->WiFiIfList,paramValue,sizeof(bridgeInfo->WiFiIfList)-1);
					if(bus_handle != NULL)
					{
			        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			        	paramValue = NULL;
					}

		     }
		     else
		     {
		     		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

		     }
    }

	
    memset(paramName,0,sizeof(paramName));   	

    snprintf(paramName,sizeof(paramName), l2netGreMembers, InstanceNumber);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS) 
    {
	        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
	        
	        strncpy(bridgeInfo->GreIfList,paramValue,sizeof(bridgeInfo->GreIfList)-1);
			if(bus_handle != NULL)
			{
	        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
	        	paramValue = NULL;
			}

     }
    else
    {
		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);
    }

     return 0;
}


/*********************************************************************************************

    caller:  HandlePreConfigGeneric
    prototype:

        int
        getXfinityEnableStatus
            (

	    );
    	description :
			This function returns whether hotspot is enabled or not.

	return : Returns xfinity enable status
***********************************************************************************************/

int getXfinityEnableStatus()
{
	    int xfinityEnable = 0 ;
	    char paramName[256]={0};
	    int retPsmGet = CCSP_SUCCESS;
	    char *paramValue = NULL;

	    snprintf(paramName,sizeof(paramName), hotspot_enable);
	    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
	    if (retPsmGet == CCSP_SUCCESS) 
	    {
            bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);

            xfinityEnable= atoi(paramValue);
            if(bus_handle != NULL)
            {
            (   (CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
            }
            paramValue = NULL;

	    }
	    else
	    {
			bridge_util_log("%s: psm call failed for %s, ret code %d\n", __FUNCTION__, paramName, retPsmGet);

	    }

	return xfinityEnable;
}

/*********************************************************************************************

    caller:  HandlePreConfigGeneric
    prototype:

        int
        wait_for_gre_ready
            (
		char* GreIf
	    );
    	description :
			This function waits for gre interface to be ready.

	char* GreIf : Gre interface name

	return : return 0 if gre status is ready , otherwise return any other value
***********************************************************************************************/

int wait_for_gre_ready(char* GreIf)
{
	    char GreState[64] = {0} , greSysName[128] = {0};

	    char IfList_Copy[IFLIST_SIZE] = {0} ;
	    char* token = NULL; 

	    char* rest = NULL; 
	    int ret = -1, numOfIter=0;
		
	    if ( GreIf[0] != '\0')
	    {
	    		strncpy(IfList_Copy,GreIf,sizeof(IfList_Copy)-1);

			rest = IfList_Copy ;
			while ((token = strtok_r(rest, " ", &rest))) 
			{
				snprintf(greSysName,sizeof(greSysName),"if_%s-status",token);
				while( numOfIter <= MAX_GRE_STATE_WAIT_TIME )
				{

					if ( ( 0 == sysevent_get(syseventfd_vlan, sysevent_token_vlan, greSysName, GreState, sizeof(GreState)) ) && ( strncmp(GreState,"ready",sizeof(GreState)-1)  == 0 ) )
					{
						bridge_util_log("%s:%s status is ready, returning...\n",__FUNCTION__,greSysName);
						ret = 0;
						return ret;
					}	
					else
					{
						bridge_util_log("%s:Waiting for gre to be ready...\n",__FUNCTION__);
						memset(GreState,0,sizeof(GreState));
						sleep(1);

					}
						numOfIter++;

				}
										
			}    				
		}

	return ret;
}

/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

        int
        HandlePreConfigGeneric
            (
		bridgeDetails *bridgeInfo,
		int InstanceNumber 
	    );
    	description :
			This function has generic changes which needs to be configured before 
			creating/updating/deleting bridge. 

	Argument : 
			bridgeDetails *bridgeInfo,   -- Bridge info
			int InstanceNumber 			-- Instance number
	return : When success returns 0 
***********************************************************************************************/


int HandlePreConfigGeneric(bridgeDetails *bridgeInfo,int InstanceNumber)
{
		
		char IfList_Copy[IFLIST_SIZE] = {0} ;
    	char* token = NULL; 
        int ret = 0;
    	char* rest = NULL; 
	bridge_util_log("enter %s\n",__func__);
		/* This is platform specific code to handle platform specific operation for given config pre bridge creation*/
	switch(InstanceNumber)
	{

		case HOTSPOT_2G:

		case HOTSPOT_5G:
				
		case HOTSPOT_SECURE_2G:

		case HOTSPOT_SECURE_5G:

					if ( BridgeOprInPropgress == CREATE_BRIDGE && 1 == getXfinityEnableStatus() )
					{
						if ( bridgeInfo->GreIfList[0] != '\0')
						{
							strncpy(IfList_Copy,bridgeInfo->GreIfList,sizeof(IfList_Copy)-1);

							rest = IfList_Copy ;
							while ((token = strtok_r(rest, " ", &rest))) 
							{
						                ret = v_secure_system(GRE_HANDLER_SCRIPT " create %d %s",InstanceNumber,token);
                                                                if(ret != 0)
                                                                {
                                                                     bridge_util_log("Failed in executing the command via v_secure_system ret val: %d \n", ret);
                                                                }
							}    				
						}

					}
            if ( 0 ==  wait_for_gre_ready(bridgeInfo->GreIfList) )
            {
                bridge_util_log("%s:%d, Gre status is ready\n",__FUNCTION__,__LINE__);
            }
            else
            {
                bridge_util_log("%s:%d, Gre status is NOT ready\n",__FUNCTION__,__LINE__);
            }
					break ;
		case PRIVATE_LAN:
                    {
#ifdef AUTOWAN_ENABLE
                        int isEthWanInterfaceRemove = 0;
                        if (ethWanEnabled)
                        {
                            isEthWanInterfaceRemove = 1;
                        }
                        if (!wan_mode)
                        {
                            if ((0 != access( "/tmp/autowan_iface_finalized" , F_OK ))) 
                            {
                                isEthWanInterfaceRemove = 1;
                            }
                        }

                        if((isEthWanInterfaceRemove) && (strlen(ethWanIfaceName) > 1))
                        {
                            removeIfaceFromList(bridgeInfo->ethIfList,ethWanIfaceName);
                        }
#endif
                    }
					break;

		case HOME_SECURITY:
					break;	
		case LOST_N_FOUND:
					if ( BridgeOprInPropgress == DELETE_BRIDGE )
					{
#if !defined (NO_MOCA_FEATURE_SUPPORT)
						bridge_util_log("%s : operation is to delete bridge, calling disableMoCaIsolationSettings\n",__FUNCTION__); 

						disableMoCaIsolationSettings (bridgeInfo);
#endif
					}			
					break;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		case MOCA_ISOLATION:
					break;	
#endif

		case MESH:
					break;

		case ETH_BACKHAUL:
					break;

		case MESH_WIFI_BACKHAUL_2G:
					break;

		case MESH_WIFI_BACKHAUL_5G:
					break;

		default :
					bridge_util_log("%s : Default case\n",__FUNCTION__); 

	}
	return 0;
}

/*********************************************************************************************

    caller:  HandlePostConfigGeneric
    prototype:

        void
        assignIpToBridge
            (
		char *bridgeName,
		char*  ipAddr 
	    );
    	description :
			This function assign ip address to the bridge name provided

	Argument : 
				char *bridgeName --> Bridge name 
				char*  ipAddr 	 --> IP address to the bridge
***********************************************************************************************/


void assignIpToBridge(char* bridgeName, char* l3netName)
{
    char paramName[256]={0};
    int retPsmGet = CCSP_SUCCESS;
    char *paramValue = NULL;
    //int ret = 0;
    char ipaddr[64] = {0} ;
    char subNetMask[64] = {0};
    int L3NetIdx = 0;
    snprintf(paramName,sizeof(paramName), l3netName);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS)
    {
        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
        L3NetIdx = atoi(paramValue);
		if(bus_handle != NULL)
		{
        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
        	paramValue = NULL;
		}
    }
    else
    {
        bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);
        return;
    }
    memset(paramName,0,sizeof(paramName));

    snprintf(paramName,sizeof(paramName), l3netIPaddr,L3NetIdx);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS)
    {
        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
        strncpy(ipaddr,paramValue,sizeof(ipaddr)-1);
		if(bus_handle != NULL)
		{
        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
        	paramValue = NULL;
		}
    }
    else
    {
      bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);
      return;
    }
    memset(paramName,0,sizeof(paramName));

    snprintf(paramName,sizeof(paramName), l3netSubnetMask,L3NetIdx);
    retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS)
    {
        bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
        strncpy(subNetMask,paramValue,sizeof(subNetMask)-1);
		if(bus_handle != NULL)
		{
        	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
        	paramValue = NULL;
		}
    }
    else
    {
        bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);
    }

    if(subNetMask[0] != '\0')
    {
#ifdef CORE_NET_LIB
		libnet_status status;
		bridge_util_log("%s : Assigning Ip [%s] with default subnetmask [%s] to bridge [%s] using core net lib api \n",__FUNCTION__,ipaddr,subNetMask, bridgeName);
		interface_set_ip(bridgeName,ipaddr);
		Set_Broadcast_address(bridgeName,subNetMask,ipaddr);
		status=interface_set_netmask(bridgeName,subNetMask);
		if(status==CNL_STATUS_FAILURE)
		{
			bridge_util_log("Failure to set subNetMask:%s to bridge:%s\n",subNetMask,bridgeName);
		}
		status=interface_up(bridgeName);
		if(status==CNL_STATUS_FAILURE)
		{
			bridge_util_log("Failure to set interface_up:%s\n",bridgeName);
		}
#else
		int ret = 0;
        bridge_util_log("%s : Assigning Ip [%s] with default subnetmask [%s] to bridge [%s] \n",__FUNCTION__,ipaddr,subNetMask, bridgeName);
       ret = v_secure_system("ifconfig %s %s netmask %s up",bridgeName,ipaddr, subNetMask);
        if(ret != 0)
        {
            bridge_util_log("Failure in executing command via v_secure_system. ret val: %d \n", ret);
        }
#endif

    }
    else
    {
        bridge_util_log("%s : Assigning Ip [%s] to bridge [%s] \n",__FUNCTION__,ipaddr,bridgeName);
        #ifdef CORE_NET_LIB
		bridge_util_log("interface_set_ip using core net lib\n");
		Set_Broadcast_address(bridgeName,DEFAULT_NETMASK_ADDR,ipaddr);
		interface_set_ip(bridgeName,ipaddr);
		#else
		int ret = 0;
		ret = v_secure_system("ifconfig %s %s",bridgeName,ipaddr);
        if(ret != 0)
        {
            bridge_util_log("Failure in executing command via v_secure_system. ret val: %d \n", ret);
        }
		#endif
    }
    return;
}

/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

        int
        HandlePostConfigGeneric
            (
		bridgeDetails *bridgeInfo,
		int InstanceNumber 
	    );
    	description :
			This function has generic changes which needs to be configured after 
			creating/updating/deleting bridge

	Argument : 
			bridgeDetails *bridgeInfo,   -- Bridge info
			int InstanceNumber 	     -- Instance number
	return : When success returns 0 
***********************************************************************************************/

int HandlePostConfigGeneric(bridgeDetails *bridgeInfo,int InstanceNumber)
{

	/* This is platform specific code to handle platform specific operation for given config post bridge creation */
		switch(InstanceNumber)
		{

			case LOST_N_FOUND:
					if ( BridgeOprInPropgress == CREATE_BRIDGE )
					{
                        bool isIpNeedToAssign = true;
#ifdef RDKB_EXTENDER_ENABLED
                        if (DeviceNetworkingMode == DEVICE_NETWORKINGMODE_EXTENDER)
                        {
                            isIpNeedToAssign = false;
                        }
#endif                        

                        if (isIpNeedToAssign == true)
                        {
                            assignIpToBridge(bridgeInfo->bridgeName,LnFL3Net);
                        }
					}
					break;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
			case MOCA_ISOLATION:

					if ( MocaIsolation_Enabled && BridgeOprInPropgress == CREATE_BRIDGE)
					{
						bridge_util_log("%s : MocaIsolation is enabled and operation is to create/sync bridge, calling enableMoCaIsolationSettings\n",__FUNCTION__); 

						enableMoCaIsolationSettings(bridgeInfo);
					}

					break;	
#endif
			case HOTSPOT_2G:
					break;

			case HOTSPOT_5G:
					break;	

			case HOTSPOT_SECURE_2G:
					break;	

			case HOTSPOT_SECURE_5G:
					break;

			case PRIVATE_LAN:
					break;
			case HOME_SECURITY:

					break;	

			case MESH_BACKHAUL :
                    			if ( BridgeOprInPropgress == CREATE_BRIDGE )
                    			{
                            			assignIpToBridge(bridgeInfo->bridgeName,MeshBhaulL3Net);
                    			}
					break;

            case MESH_ONBOARD :
                    if ( BridgeOprInPropgress == CREATE_BRIDGE )
                    {
                        assignIpToBridge(bridgeInfo->bridgeName,MeshOnboardL3Net);
                    }
                    break;

            case ETH_BACKHAUL:
                if ( BridgeOprInPropgress == CREATE_BRIDGE )
                {
                    assignIpToBridge(bridgeInfo->bridgeName,EthBhaulL3Net);
                }
                break;	

            case MESH:
                    break;

			case MESH_WIFI_BACKHAUL_2G:
				if ( BridgeOprInPropgress == CREATE_BRIDGE )
				{
					assignIpToBridge(bridgeInfo->bridgeName,MeshWiFiBhaulL3Net_2G);
				}
				break;

			case MESH_WIFI_BACKHAUL_5G:
				if ( BridgeOprInPropgress == CREATE_BRIDGE )
				{
					assignIpToBridge(bridgeInfo->bridgeName,MeshWiFiBhaulL3Net_5G);
				}
				break;

            case MESH_WIFI_ONBOARD_2G:
                if ( BridgeOprInPropgress == CREATE_BRIDGE )
                {
                    assignIpToBridge(bridgeInfo->bridgeName,MeshWiFiOnboardL3Net_2G);
#if !defined(USE_LINUX_BRIDGE)
                    v_secure_system("ovs-vsctl set int %s mtu_request=1600",bridgeInfo->bridgeName);
#else
                    v_secure_system("ifconfig %s mtu 1600",bridgeInfo->bridgeName);
#endif
                }
                break;

#if defined (WIFI_MANAGE_SUPPORTED)
            case MANAGE_WIFI_BRIDGE:
            {
                if (BridgeOprInPropgress == CREATE_BRIDGE )
                {
                    assignIpToBridge(bridgeInfo->bridgeName,ManageWiFiData);
                }
                break;
            }
#endif /*WIFI_MANAGE_SUPPORTED*/
#if defined (AMENITIES_NETWORK_ENABLED)
            case AMENITY_BRIDGE_2G:
            case AMENITY_BRIDGE_5G:
            case AMENITY_BRIDGE_6G:
            {
                bridge_util_log("%s:%d, bridgeName:%s\n",__FUNCTION__,__LINE__,bridgeInfo->bridgeName);
                setNfCallIptables(bridgeInfo->bridgeName, TRUE);
                break;
            }
#endif /*AMENITIES_NETWORK_ENABLED*/
			default :
					bridge_util_log("%s : Default case\n",__FUNCTION__); 

		}
		return 0;

}
/************************************************************
 * Allocate mempry to the gateway config
************************************************************/
Gateway_Config_t *Allocate_mem_for_Gateway_Config()
{
	Gateway_Config_t *pGwConfig = NULL;
	if ( 1 == bridgeUtilEnable )
	{
		if ((pGwConfig = (Gateway_Config_t *)malloc(sizeof(Gateway_Config_t))) != NULL)
		{
			memset(pGwConfig, 0, sizeof(Gateway_Config_t));
                        pGwConfig->if_cmd = IF_UP_CMD_TYPE;
			return pGwConfig;
		}
		else
		{
			bridge_util_log("%s :bridgeUtilEnabled, malloc to Gateway_Config failed\n",__FUNCTION__); 
			return NULL;
		}
	}
	else
	{
		bridge_util_log("%s : OVS or bridgeUtil not enabled\n",__FUNCTION__); 
		return NULL;
	}		

}


/*********************************************************************************************

    caller:  CreateBrInterface,DeleteBrInterface,SyncBrInterfaces
    prototype:

	int updateBridgeInfo
	(
		bridgeDetails *bridgeInfo, 
		char* ifNameToBeUpdated, 
		int Opr , 
		int type
	);

    description :
		This function has generic changes which needs to be configured after 
		creating/updating/deleting bridge

    Argument : 
		bridgeDetails *bridgeInfo --> Bridge Information
		char* ifNameToBeUpdated   -->Interface to be deleted and updated , applicable only during sync
		int Opr 		  --> This parameter has the info whether the request INSERT/DELET/UPDATE 
		int type   		  --> Interface type, in case of sync delete value is set to unknown/other
   return : 	When success returns 0 
***********************************************************************************************/
int updateBridgeInfo(bridgeDetails *bridgeInfo, char* ifNameToBeUpdated, int Opr , int type)
{

	char IfList_Copy[IFLIST_SIZE] = {0} ;
    	char tmp_buff[32] = {0} ;
	int if_type = OTHER_IF_TYPE_VALUE;
	int vlanId = -1 ;
	interact_request request = {0};
	//ovs_interact_request ovs_request = {0};
        Gateway_Config_t *pGwConfig = NULL;
	bool retValue = false ;
    	char* token = NULL; 
    	char* rest = NULL; 
    	bool bridgeCreated = false;
    	bool interfaceExist=true;
        int OprType = 0;
#if !defined(USE_LINUX_BRIDGE)
        OprType = mapOvsCmdToBrCmd(Opr);
	request.ovs_request.block_mode = OVS_ENABLE_BLOCK_MODE ;

	request.ovs_request.table_config.table.id = OVS_GW_CONFIG_TABLE;
#else
        OprType = Opr;
#endif
	switch(type)
	{
		case IF_BRIDGE_BRIDGEUTIL:
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->bridgeName[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->bridgeName,sizeof(IfList_Copy)-1);
			}
			if_type = BRIDGE_IF_TYPE_VALUE;
			break;
		case IF_VLAN_BRIDGEUTIL:
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->vlan_name[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->vlan_name,sizeof(IfList_Copy)-1);
			}
			if_type = VLAN_IF_TYPE_VALUE ;

			vlanId = bridgeInfo->vlanID ;
			break;
		case IF_WIFI_BRIDGEUTIL:
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->WiFiIfList[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->WiFiIfList,sizeof(IfList_Copy)-1);
			}

			break;
		case IF_ETH_BRIDGEUTIL: 
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->ethIfList[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->ethIfList,sizeof(IfList_Copy)-1);
			}
			if_type = ETH_IF_TYPE_VALUE;
			break;
		case IF_GRE_BRIDGEUTIL: 
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->GreIfList[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->GreIfList,sizeof(IfList_Copy)-1);
			}
			// setting as VLAN type since vconfig is used to create the gretap.* interface

			if_type = VLAN_IF_TYPE_VALUE;

			vlanId = bridgeInfo->vlanID ;
			break;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
		case IF_MOCA_BRIDGEUTIL: 
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			else if ( bridgeInfo->MoCAIfList[0] != '\0' )
			{
				strncpy(IfList_Copy,bridgeInfo->MoCAIfList,sizeof(IfList_Copy)-1);
			}
			break;
#endif
		case IF_OTHER_BRIDGEUTIL: 
			if( ifNameToBeUpdated[0] != '\0' )
			{
				strncpy(IfList_Copy, ifNameToBeUpdated, sizeof(IfList_Copy)-1);
			}
			break;

		default  :	
			bridge_util_log("%s : Invalid Interface Type passed, returning failure.\n",__FUNCTION__); 
			return FAILED;
	}

		rest = IfList_Copy;
        int retryCounter=0;

#if !defined(USE_LINUX_BRIDGE)
		if(ovsEnable != 1)
		{
			if(pGwConfig==NULL)
			{
				pGwConfig=Allocate_mem_for_Gateway_Config();
				if(pGwConfig==NULL)
				{
					return FAILED;
				}
            }
		}	
#else
		if(pGwConfig==NULL)
		{
			pGwConfig=Allocate_mem_for_Gateway_Config();
			if(pGwConfig==NULL)
			{
				return FAILED;
			}
        }
#endif

		while ((token = strtok_r(rest, " ", &rest))) 
		{
			    interfaceExist=true;
            	retryCounter = 0;
            		/* 
            		Checking if VAP/wifi interface is created before attaching to bridge in OneWifi enabled build.
            		Either BCM driver/Onewifi will attach the vaps once it is created. 
			*/
			
			#ifdef RDK_ONEWIFI
            		// OVSAgent considers WiFi interfaces as OVS_OTHER_IF_TYPE
       			if ( IF_UP_CMD_TYPE == OprType && IF_WIFI_BRIDGEUTIL == type && INTERFACE_NOT_EXIST == checkIfExists(token))

       			{
       				interfaceExist=false;
       				if(bridgeCreated)
       					continue;
       			} 
			#endif
            	        if ( (ethWanEnabled) && ((if_type == ETH_IF_TYPE_VALUE) || (if_type == VLAN_IF_TYPE_VALUE) ) && ( strncmp(ethWanIfaceName,token,sizeof(ethWanIfaceName)-1) == 0 ))
            		    continue;
OVSACTION:
#if !defined(USE_LINUX_BRIDGE)
			if ( 1 == ovsEnable )
			{
				if (!ovs_agent_api_get_config(OVS_GW_CONFIG_TABLE, (void **)&pGwConfig))
				{
					bridge_util_log("%s failed to allocate and initialize config\n", __FUNCTION__);
				    return FAILED;
				}
			}
			else 
			{
				if(pGwConfig!=NULL)
				{
					memset(pGwConfig,0,sizeof(Gateway_Config));
                }
			}	
#else
			if(pGwConfig != NULL)
			{
				memset(pGwConfig,0,sizeof(Gateway_Config_t));
        	}
#endif

			strncpy(pGwConfig->parent_bridge,bridgeInfo->bridgeName,sizeof(pGwConfig->parent_bridge)-1); ;
		    	pGwConfig->if_type = if_type ;
	                if ( IF_UP_CMD_TYPE != OprType ) 
                            pGwConfig->if_cmd = OprType;

				if ( ( if_type == GRE_IF_TYPE_VALUE ) || ( if_type == VLAN_IF_TYPE_VALUE )  )
				{
	    				pGwConfig->vlan_id = vlanId ;
					if ( bridgeInfo->VirtualParentIfname[0] != '\0' )
					{

						if (strlen(bridgeInfo->VirtualParentIfname) < MAX_IF_NAME_SIZE )
						{
						    strncpy(pGwConfig->parent_ifname,bridgeInfo->VirtualParentIfname,sizeof(pGwConfig->parent_ifname)-1);
							/* CID 339902: String not null terminated */
							pGwConfig->parent_ifname[sizeof(pGwConfig->parent_ifname) - 1] = '\0'; 
						}
						else
						{
						    printf("%s failed to copy VirtualParentIfname %s !\n", __func__,bridgeInfo->VirtualParentIfname);
						}
						strncpy(pGwConfig->if_name,token,sizeof(pGwConfig->if_name)-1);
					}
					else
					{
						strncpy(pGwConfig->parent_ifname,token,sizeof(pGwConfig->parent_ifname)-1);
		                		snprintf(tmp_buff,sizeof(tmp_buff),"%s.%d",pGwConfig->parent_ifname,pGwConfig->vlan_id);
                				strncpy(pGwConfig->if_name,tmp_buff,sizeof(pGwConfig->if_name)-1);	
					}			
				}
				else
				{
					//if interface doesn't exist creating only bridge interface
					if(interfaceExist)
						strncpy(pGwConfig->if_name,token,sizeof(pGwConfig->if_name)-1);
				}

				#if !defined(USE_LINUX_BRIDGE)
				request.ovs_request.table_config.config = (void *) pGwConfig;
				bridge_util_log("%s : method is : %d  Mode is : %d , if_cmd is %d \n",__FUNCTION__,request.ovs_request.method,request.ovs_request.block_mode,pGwConfig->if_cmd);
				#endif
				if( ( ovsEnable  == 0)&&(bridgeUtilEnable == 1 ))
				{
					request.gw_config=pGwConfig;
					bridge_util_log("%s : parent_ifname is %s : if_name is %s : bridge %s : vlan id is %d , if_type is %d: \n", __FUNCTION__,pGwConfig->parent_ifname,pGwConfig->if_name,pGwConfig->parent_bridge,pGwConfig->vlan_id,pGwConfig->if_type); 
				}
				#if !defined(USE_LINUX_BRIDGE)
				retValue = create_ovs_bridge_api(&request,NULL);
				#else
				retValue = create_linux_bridge_api(&request);
				#endif

				if ( retValue != true )
				{
					bridge_util_log("create bridge call failed\n");
                   			 if ( retryCounter == 0 )
                    			{
                        			retryCounter++;
                        			bridge_util_log("retrying last call\n");
                        			goto OVSACTION;
                    			}
				}
				else
				{
					if(!bridgeCreated)
						bridgeCreated=true;	
				}
		}
  #if !defined(USE_LINUX_BRIDGE)
  	if ( ovsEnable != 1 )
    {
		if(pGwConfig!=NULL)
		{
			free(pGwConfig);
			pGwConfig=NULL;
			request.gw_config=NULL;
			request.ovs_request.table_config.config=NULL;
		}
    }
  #else
  	if(pGwConfig!=NULL)
	{
		free(pGwConfig);
		pGwConfig=NULL;
		request.gw_config=NULL;
		#if !defined(USE_LINUX_BRIDGE)
		request.ovs_request.table_config.config=NULL;
		#endif
	}
  #endif
    return 0;
}

/*********************************************************************************************

    caller:  Main
    prototype:

        int
        CreateBrInterface
            (
            );
    	description :
			This function creates the bridge and attaches interfaces to it
			multinet-up,multinet-start cases
    	return value : returns 0 in case of success
***********************************************************************************************/

int CreateBrInterface()
{
	char event_name[64] = {0};
	snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "partial", 0);
	char val[16] = {0} ;
        int bridgeCreated=0;
	bridgeDetails *bridgeInfo = NULL;
	bridge_util_log("enter %s\n",__func__);
	bridgeInfo = (bridgeDetails*) malloc (sizeof(bridgeDetails));
	if ( bridgeInfo == NULL )
	{
		bridge_util_log("%s : Memory allocation failed to allocate for bridgeDetails, exiting\n",__FUNCTION__);
		return -1;
	}

	memset(bridgeInfo, 0, sizeof(bridgeDetails));

	getIfList(bridgeInfo);

	HandlePreConfigGeneric(bridgeInfo,InstanceNumber);
	HandlePreConfigVendorGeneric(bridgeInfo,InstanceNumber);

	if ( bridgeInfo->bridgeName[0] != '\0' )
	{
		snprintf(event_name,sizeof(event_name),"multinet_%d-name",InstanceNumber);
		sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, bridgeInfo->bridgeName, 0);
	}

	snprintf(event_name,sizeof(event_name),"multinet_%d-vid",InstanceNumber);
	snprintf(val,sizeof(val),"%d",bridgeInfo->vlanID);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, val, 0);

	if ( bridgeInfo->vlan_name[0] != '\0' )
        {
                bridgeCreated = 1 ;
		
		updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_VLAN_BRIDGEUTIL);		
        }

    	if ( bridgeInfo->GreIfList[0] != '\0')
    	{
            if( 1== getXfinityEnableStatus() )
            {
                bridgeCreated = 1 ;
                updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_GRE_BRIDGEUTIL);
            }
    	}

    	if ( bridgeInfo->ethIfList[0] != '\0')
    	{
    		need_switch_gw_refresh = 1;
                bridgeCreated = 1 ;
		updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_ETH_BRIDGEUTIL);		
    	}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    	if ( bridgeInfo->MoCAIfList[0] != '\0')
    	{
        	bridgeCreated = 1 ;
		updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_MOCA_BRIDGEUTIL); 				
	}	
#endif

	if ( bridgeInfo->WiFiIfList[0] != '\0')
	{		     						 
    		need_wifi_gw_refresh = 1;
                bridgeCreated = 1 ;
		updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_WIFI_BRIDGEUTIL); 				
	}
		
        if ( bridgeCreated == 0 )
        {
                updateBridgeInfo(bridgeInfo,"",IF_UP_CMD,IF_BRIDGE_BRIDGEUTIL);                 
        }
	HandlePostConfigGeneric(bridgeInfo,InstanceNumber);
	HandlePostConfigVendorGeneric(bridgeInfo,InstanceNumber);

	if ( bridgeInfo != NULL )
	{
		free(bridgeInfo);
		bridgeInfo = NULL ;
	}

    	snprintf(event_name,sizeof(event_name),"multinet_%d-localready",InstanceNumber);
    	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "1", 0);
	
    	snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "ready", 0);

	sysevent_set(syseventfd_vlan, sysevent_token_vlan, "firewall-restart", NULL, 0);

	return 0;
}

/*********************************************************************************************

    caller:  Main
    prototype:

        int
        DeleteBrInterface
            (
            );
    	description :
			This function delete the bridge and and removes all the interfaced to it.
			multinet-down,mulinet-stop cases 

    	return value : returns 0 in case of success
***********************************************************************************************/

int DeleteBrInterface()
{
	char event_name[64] = {0};
	snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "stopping", 0);

	bridgeDetails *bridgeInfo = NULL;
	bridgeInfo = (bridgeDetails*) malloc (sizeof(bridgeDetails));
	if ( bridgeInfo == NULL )
	{
		bridge_util_log("%s : Memory allocation failed to allocate for bridgeDetails, exiting\n",__FUNCTION__);
		return -1;
	}

	memset(bridgeInfo, 0, sizeof(bridgeDetails));

	getIfList(bridgeInfo);

	HandlePreConfigGeneric(bridgeInfo,InstanceNumber);
	HandlePreConfigVendorGeneric(bridgeInfo,InstanceNumber);
       	if ( bridgeInfo->vlan_name[0] != '\0' )
        {
                updateBridgeInfo(bridgeInfo,"",IF_DELETE_CMD,IF_VLAN_BRIDGEUTIL);               
                
        }

        if ( bridgeInfo->GreIfList[0] != '\0')
        {
        	updateBridgeInfo(bridgeInfo,"",IF_DELETE_CMD,IF_GRE_BRIDGEUTIL);               
        } 
		
	updateBridgeInfo(bridgeInfo,"",IF_DELETE_CMD,IF_BRIDGE_BRIDGEUTIL); 				
    	if ( bridgeInfo->WiFiIfList[0] != '\0' )
    	{
		need_wifi_gw_refresh = 1;
	}

	if ( bridgeInfo->ethIfList[0] != '\0' )
    	{
		need_switch_gw_refresh = 1;
	}

	HandlePostConfigGeneric(bridgeInfo,InstanceNumber);
	HandlePostConfigVendorGeneric(bridgeInfo,InstanceNumber);


	if ( bridgeInfo != NULL )
	{
		free(bridgeInfo);
		bridgeInfo = NULL ;
	}

    	snprintf(event_name,sizeof(event_name),"multinet_%d-localready",InstanceNumber);
    	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "0", 0);
    
    	snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "stopped", 0);

	sysevent_set(syseventfd_vlan, sysevent_token_vlan, "firewall-restart", NULL, 0);

	return 0;
}


/*********************************************************************************************

    caller:  SyncBrInterfaces
    prototype:

        void
        getCurrentIfList
            (
            	char *bridge, 
            	char *current_if_list
            );

    	description :
			This function returns the list of interfaces currently attached to bridge
	
	Argument:
         	char *bridge  --> bridge name 
            	char *current_if_list  --> returns the list of interfaces currently attached to the 
            							bridge name passed
***********************************************************************************************/

void getCurrentIfList(char *bridge, char *current_if_list)
{
        FILE *fp = NULL;
        int ret = 0;
#if !defined(USE_LINUX_BRIDGE)
	if( 1 == ovsEnable )
	{
		fp = v_secure_popen("r","ovs-vsctl list-ifaces %s | tr '\n' ' ' ",bridge);
	}
	else if ( 1 == bridgeUtilEnable ) {
	    fp = v_secure_popen("r","brctl show %s | sed '1d' | awk '{print $NF}' | tr '\n' ' ' ",bridge);
	}
	else 
	{    
	    return;
	}
#else
	if ( 1 == bridgeUtilEnable ) {
	    fp = v_secure_popen("r","brctl show %s | sed '1d' | awk '{print $NF}' | tr '\n' ' ' ",bridge);
	}
	else{
		return;
	}
#endif
	 if ( fp != NULL )
	 {
	 	fgets(current_if_list,TOTAL_IFLIST_SIZE-1,fp);
	 	ret = v_secure_pclose(fp);
                if(ret !=0) {
		    bridge_util_log("%s: Error in closing pipe! [%d]\n",__func__,ret);
		}
	 }
	 return;
}

void removePgdInterfacesFromCurrentIfList(char *current_if_list)
{
	char currentIfListCopy[TOTAL_IFLIST_SIZE] = {0} ;
	char *rest_curlist = NULL;
	char *token = NULL;
	char tempList[TOTAL_IFLIST_SIZE] = {0}, temp[512] = {0};
	
    // check if space-separated interface list contains either "pgd" or "ethpod"
	if(strstr(current_if_list, "pgd") != NULL || strstr(current_if_list, "ethpod") != NULL)
	{
          	bridge_util_log("%s: current_if_list: %s\n",__FUNCTION__, current_if_list);
		strncpy(currentIfListCopy,current_if_list,sizeof(currentIfListCopy)-1);

		rest_curlist = currentIfListCopy ;

		while ((token = strtok_r(rest_curlist, " ", &rest_curlist))) 
		{
            // skip if it is "pgd" or "ethpod"
			if(strstr(token, "pgd") == NULL && strstr(token, "ethpod") == NULL)
			{
				if(strlen(tempList) > 0)
				{
					snprintf(tempList, sizeof(tempList), "%s %s", temp, token);
				}
				else
				{
					strncpy(tempList, token, sizeof(tempList)-1);
				}
				strncpy(temp, tempList, sizeof(temp)-1);
			}
		}
		strncpy(current_if_list, tempList, TOTAL_IFLIST_SIZE);
		bridge_util_log("%s: Updated current_if_list: %s\n",__FUNCTION__,current_if_list);
	}
}
/*********************************************************************************************

    caller:  SyncBrInterfaces
    prototype:

        void
        removeIfaceFromBridge
            (
            	bridgeDetails *bridgeInfo,
            	char *current_if_list
            );
    	description :
			This function comapares current interfaces in bridge with new list of 
			interface after sync 
			and removes the iface which doesn't exists in new list

	Arguments : 
			bridgeDetails *bridgeInfo  --> bridge details (new list ) 
            		char *current_if_list  --> list of interfaces currently attached to bridge(current list)

***********************************************************************************************/

void removeIfaceFromBridge(bridgeDetails *bridgeInfo,char *current_if_list) 
{
	bridge_util_log("Entering function removeIfaceFromBridge\n");
	char* token_curlist = NULL ;
	char* token_newlist = NULL;
	char* rest_curlist = NULL ;
	char* rest_newlist = NULL;
	char* vendorIfaces = NULL;
	int removeIface = 1 ;
	char lIfName[IFACE_NAME_SIZE] = {0} ;
	char IfList_Copy[IFLIST_SIZE] = {0} ;
	char currentIfListCopy[TOTAL_IFLIST_SIZE] = {0} ;
	vendorIfaces = getVendorIfaces();
	strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);
	removePgdInterfacesFromCurrentIfList(currentIfListCopy);

	rest_curlist = currentIfListCopy ;

	while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
	{
		removeIface = 1 ;

		if ( bridgeInfo->vlan_name[0] != '\0' )
    		{
    			strncpy(IfList_Copy,bridgeInfo->vlan_name,sizeof(IfList_Copy)-1);

		    	//rest_newlist = bridgeInfo->vlan_name; 
			rest_newlist = IfList_Copy;

			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{
				memset(lIfName,0,sizeof(lIfName));
				snprintf(lIfName,sizeof(lIfName),"%s.%d",token_newlist,bridgeInfo->vlanID);

				if ( strcmp(lIfName,token_curlist) == 0)
				{
					removeIface = 0; 
					goto IF_REMOVE;
				}
			}  			
    		}

		if ( bridgeInfo->GreIfList[0] != '\0' )
    		{

    			strncpy(IfList_Copy,bridgeInfo->GreIfList,sizeof(IfList_Copy)-1);

		    	//rest_newlist = bridgeInfo->GreIfList; 
			rest_newlist = IfList_Copy;

			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{

				memset(lIfName,0,sizeof(lIfName));
				snprintf(lIfName,sizeof(lIfName),"%s.%d",token_newlist,bridgeInfo->vlanID);

				if ( strcmp(lIfName,token_curlist) == 0)
				{
					removeIface = 0; 
					goto IF_REMOVE;
				}
			}  			
    		}


		if ( bridgeInfo->ethIfList[0] != '\0' )
    		{

		    	strncpy(IfList_Copy,bridgeInfo->ethIfList,sizeof(IfList_Copy)-1);

		    	//rest_newlist = bridgeInfo->ethIfList; 
		    	rest_newlist = IfList_Copy;
    					
			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{    							
				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					removeIface = 0; 
					goto IF_REMOVE;
				}
			}  			
    		}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    		if ( bridgeInfo->MoCAIfList[0] != '\0' )
    		{
		    	strncpy(IfList_Copy,bridgeInfo->MoCAIfList,sizeof(IfList_Copy)-1);

		    	//rest_newlist = bridgeInfo->MoCAIfList; 
		    	rest_newlist = IfList_Copy;

			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{
				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					removeIface = 0; 
					goto IF_REMOVE;
				}

			}  
			
    		}
#endif
    		if ( bridgeInfo->WiFiIfList[0] != '\0' )
    		{
    			strncpy(IfList_Copy,bridgeInfo->WiFiIfList,sizeof(IfList_Copy)-1);
		    	//rest_newlist = bridgeInfo->WiFiIfList; 
		    	rest_newlist = IfList_Copy;

			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{

				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					removeIface = 0; 
					goto IF_REMOVE;
				}

			}  
			
    		}
			if ( (DeviceMode !=0) && (vendorIfaces != NULL) )
			{
				bridge_util_log("%s: vendorIfaces are %s\n",__FUNCTION__, vendorIfaces);
				strncpy(IfList_Copy,vendorIfaces,sizeof(IfList_Copy)-1);
				rest_newlist = IfList_Copy;
				while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist)))
				{
					if ( strcmp(token_newlist,token_curlist) == 0)
					{
						removeIface = 0;
						goto IF_REMOVE;
					}
				}
			}

IF_REMOVE:
		if ( removeIface == 1 )
		{
			//  set parameter to gw_lan_refresh both switch and wifi
			need_wifi_gw_refresh = 1;
			need_switch_gw_refresh = 1 ;
			bridge_util_log("In  function removeIfaceFromBridge removing  %s\n", token_curlist);
			updateBridgeInfo(bridgeInfo,token_curlist,BR_REMOVE_CMD,IF_OTHER_BRIDGEUTIL); 				
				
		}


	}
	bridge_util_log("Leaving function removeIfaceFromBridge\n");

}


/*********************************************************************************************

    caller:  SyncBrInterfaces
    prototype:

        void
        addIfaceToBridge
            (
            	bridgeDetails *bridgeInfo,
            	char *current_if_list
            );
    	description :
			This function comapares current interfaces in bridge with new list of 
			interface after sync 
			and adds the iface which is not in bridge attached list

	Arguments : 
			bridgeDetails *bridgeInfo  --> bridge details (new list ) 
            		char *current_if_list  --> list of interfaces currently attached to bridge(current list)

***********************************************************************************************/

void addIfaceToBridge(bridgeDetails *bridgeInfo,char *current_if_list)
{

  	char* token_curlist = NULL ;
  	char* token_newlist = NULL;  

    	char* rest_curlist = NULL ;
    	char* rest_newlist = NULL; 

    	int addIface = 1 ;
	char lIfName[IFACE_NAME_SIZE] = {0} ;

	char IfList_Copy[IFLIST_SIZE] = {0} ;
	char currentIfListCopy[TOTAL_IFLIST_SIZE] = {0} ;


	if ( bridgeInfo->vlan_name[0] != '\0' )
    	{

    		strncpy(IfList_Copy,bridgeInfo->vlan_name,sizeof(IfList_Copy)-1);

		// rest_newlist = bridgeInfo->vlan_name; 
    		rest_newlist = IfList_Copy ;
		while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
		{
			addIface = 1 ;
			memset(lIfName,0,sizeof(lIfName));
			snprintf(lIfName,sizeof(lIfName),"%s.%d",token_newlist,bridgeInfo->vlanID);

			strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);

			rest_curlist = currentIfListCopy ;
			while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
			{
				if ( strcmp(lIfName,token_curlist) == 0)
				{
					addIface = 0; 
					break;
				}

			}

			if (addIface == 1)
			{
				updateBridgeInfo(bridgeInfo,token_newlist,IF_UP_CMD,IF_VLAN_BRIDGEUTIL); 				
			}
		}  
		
    	}

	if (( bridgeInfo->GreIfList[0] != '\0' ) && ( 1 == getXfinityEnableStatus()))
    	{
    		if ( 0 ==  wait_for_gre_ready(bridgeInfo->GreIfList) )
    		{
		    			
		    	strncpy(IfList_Copy,bridgeInfo->GreIfList,sizeof(IfList_Copy)-1);

			//rest_newlist = bridgeInfo->GreIfList; 
		    	rest_newlist = IfList_Copy;
			while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
			{
				addIface = 1 ;
				memset(lIfName,0,sizeof(lIfName));
				snprintf(lIfName,sizeof(lIfName),"%s.%d",token_newlist,bridgeInfo->vlanID);

				strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);

				rest_curlist = currentIfListCopy ;
				while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
				{
					if ( strcmp(lIfName,token_curlist) == 0)
					{
						addIface = 0; 
						break;
					}

				}

				if (addIface == 1)
				{
					updateBridgeInfo(bridgeInfo,token_newlist,IF_UP_CMD,IF_GRE_BRIDGEUTIL); 				
				}
			}

		}  
		
    	}

	if ( bridgeInfo->ethIfList[0] != '\0' )
    	{
    		need_switch_gw_refresh = 1 ;
    			
    		strncpy(IfList_Copy,bridgeInfo->ethIfList,sizeof(IfList_Copy)-1);

		//rest_newlist = bridgeInfo->ethIfList; 
    		rest_newlist = IfList_Copy ;
		while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
		{
			addIface = 1 ;

			strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);

			rest_curlist = currentIfListCopy ;
			while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
			{
				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					addIface = 0; 
					break;
				}

			}

			if (addIface == 1)
			{
				updateBridgeInfo(bridgeInfo,token_newlist,IF_UP_CMD,IF_ETH_BRIDGEUTIL); 				
 
			}
		}  
    	}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    	if ( bridgeInfo->MoCAIfList[0] != '\0' )
    	{
    		strncpy(IfList_Copy,bridgeInfo->MoCAIfList,sizeof(IfList_Copy)-1);

		//rest_newlist = bridgeInfo->MoCAIfList; 
    		rest_newlist = IfList_Copy ;

		while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
		{
			addIface = 1 ;

    			strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);

			rest_curlist = currentIfListCopy ;
			while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
			{
				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					addIface = 0; 
					break;
				}

			}

			if (addIface == 1)
			{
				updateBridgeInfo(bridgeInfo,token_newlist,IF_UP_CMD,IF_MOCA_BRIDGEUTIL); 				
			}
		}  
		
    	}
#endif

    	if ( bridgeInfo->WiFiIfList[0] != '\0' )
    	{
    		need_wifi_gw_refresh = 1 ;
    		strncpy(IfList_Copy,bridgeInfo->WiFiIfList,sizeof(IfList_Copy)-1);

    		rest_newlist = IfList_Copy ;

		while ((token_newlist = strtok_r(rest_newlist, " ", &rest_newlist))) 
		{
			addIface = 1 ;

			strncpy(currentIfListCopy,current_if_list,sizeof(IfList_Copy)-1);

			rest_curlist = currentIfListCopy ;
			while ((token_curlist = strtok_r(rest_curlist, " ", &rest_curlist))) 
			{
				if ( strcmp(token_newlist,token_curlist) == 0)
				{
					addIface = 0; 
					break;
				}

			}

			if (addIface == 1)
			{
				updateBridgeInfo(bridgeInfo,token_newlist,IF_UP_CMD,IF_WIFI_BRIDGEUTIL); 				
			}
		}  
		
    	}
    	return;
}

/*********************************************************************************************

    caller:  main
    prototype:

        int
        SyncBrInterfaces
            (

            );
    	description :
			This function sync(remove/add) the ifaces in bridge. 

	return : When success returns 0 
***********************************************************************************************/

int SyncBrInterfaces()
{
	syncMembers = 1 ;


	char event_name[64] = {0};
    	char val[16] = {0} ;
	// setting for mode switch , sleeping for 2 secs so that async events are removed
  	sleep(2);
	snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "partial", 0);

	bridgeDetails *bridgeInfo = NULL;
	bridgeInfo = (bridgeDetails*) malloc (sizeof(bridgeDetails));
		
	if ( bridgeInfo == NULL )
	{
		bridge_util_log("%s : Memory allocation failed to allocate for bridgeDetails, exiting\n",__FUNCTION__);
		return -1;
	}
        /* CID :161059 Out-of-bounds access (OVERRUN) */
	char current_if_list[TOTAL_IFLIST_SIZE] = {0} ;
	memset(bridgeInfo, 0, sizeof(bridgeDetails));
	getIfList(bridgeInfo);
	

    	if ( bridgeInfo->bridgeName[0] != '\0' )
    	{
        	snprintf(event_name,sizeof(event_name),"multinet_%d-name",InstanceNumber);
        	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, bridgeInfo->bridgeName, 0);
    	}

    	snprintf(event_name,sizeof(event_name),"multinet_%d-vid",InstanceNumber);
    	snprintf(val,sizeof(val),"%d",bridgeInfo->vlanID);
    	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, val, 0);

	HandlePreConfigGeneric(bridgeInfo,InstanceNumber);

	HandlePreConfigVendorGeneric(bridgeInfo,InstanceNumber);

	getCurrentIfList(bridgeInfo->bridgeName,current_if_list);

	removeIfaceFromBridge(bridgeInfo,current_if_list);

	addIfaceToBridge(bridgeInfo,current_if_list);
		
	HandlePostConfigGeneric(bridgeInfo,InstanceNumber);

	HandlePostConfigVendorGeneric(bridgeInfo,InstanceNumber);

    snprintf(event_name,sizeof(event_name),"multinet_%d-localready",InstanceNumber);
    sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "1", 0);

    snprintf(event_name,sizeof(event_name),"multinet_%d-status",InstanceNumber);
	sysevent_set(syseventfd_vlan, sysevent_token_vlan, event_name, "ready", 0);

	sysevent_set(syseventfd_vlan, sysevent_token_vlan, "firewall-restart", NULL, 0);

	if ( bridgeInfo != NULL )
	{
		free(bridgeInfo);
		bridgeInfo = NULL ;
	}

	return 0;
}


/*********************************************************************************************

    caller:  main
    prototype:

        void
        AddOrDeletePort
            (
                char* bridge_name, 
                char* iface_name,
                int operation
            );
        description :
            This function add/deletes port/iface from bridge.
***********************************************************************************************/

void AddOrDeletePort(char* bridge_name, char* iface_name,int operation)
{

    syncMembers = 1;
    bridge_util_log("Entering %s \n",__FUNCTION__); 

    if( ( strlen(bridge_name) == 0 ) || (strlen(iface_name) == 0 ) )
    {
        bridge_util_log("%s : Either bridge name or iface name is missing, returning\n",__FUNCTION__);
        return;
    }

    bridgeDetails  bridgeInfo ;
    memset(&bridgeInfo, 0, sizeof(bridgeDetails));

    strncpy(bridgeInfo.bridgeName,bridge_name,sizeof(bridgeInfo.bridgeName)-1);

    if ( operation == IF_UP_CMD_TYPE )
    {
        updateBridgeInfo(&bridgeInfo,iface_name,IF_UP_CMD,IF_OTHER_BRIDGEUTIL);                
    }
    else if ( operation == BR_REMOVE_CMD_TYPE )
    {
        updateBridgeInfo(&bridgeInfo,iface_name,BR_REMOVE_CMD,IF_OTHER_BRIDGEUTIL);
    }

    return ;
}

// Drop root privilages from component
void drop_root()
{
	appcaps.caps = NULL;
    	appcaps.user_name = NULL;
    	init_capability();
    	drop_root_caps(&appcaps);
    	update_process_caps(&appcaps);
    	read_capability(&appcaps);
}
/*********************************************************************************************

    caller:  main
    prototype:

        int
        Initialize
            (

            );
    	description :
			This function initialzes bus , syscfg ,sysevent. 

	return : When success returns 0 
***********************************************************************************************/

int Initialize()
{
	// Initializing bus communication
	/* CID :257718 Resource leak (RESOURCE_LEAK) */
	int fd;
    	if ((fd = creat(BRIDGE_UTIL_RUNNING,S_IRUSR |S_IWUSR | S_IRGRP | S_IROTH)) >= 0)
	{
	    close(fd);
	}
	int ret;
	ret = CCSP_Message_Bus_Init(component_id, pCfg, &bus_handle,(CCSP_MESSAGE_BUS_MALLOC) Ansc_AllocateMemory_Callback, Ansc_FreeMemory_Callback);
	if (ret == -1)
	{
		bridge_util_log("%s : Message bus init failed\n",__FUNCTION__);
		return FAILED;
				
	}

	//Initialize sysevent

	syseventfd_vlan = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION,
	                                            "bridge_utils", &sysevent_token_vlan);

	if (syseventfd_vlan < 0)       
	{    
	        bridge_util_log("%s : sysevent_open failed\n",__FUNCTION__);
		return FAILED;
	}  

	return 0;

}

/*********************************************************************************************

    caller:  main
    prototype:

        int
        ExitFunc
            (

            );
    	description :
			This function during exit from the program gracefully closes bus , sysevent,
			unlocks shm mutex

	return : When success returns 0 
***********************************************************************************************/

int ExitFunc()
{

	if( bus_handle != NULL )
		CCSP_Message_Bus_Exit(bus_handle);

	/* CID 249136 Waiting while holding a lock fix */
	pthread_mutex_unlock(brmutex.ptr);

	if ( syseventfd_vlan > 0 )
		sysevent_close(syseventfd_vlan, sysevent_token_vlan);

	if ( logFp != NULL)
	{
		fclose(logFp);
	    	logFp= NULL;
	}

	    
#if !defined(USE_LINUX_BRIDGE) 
	if ( ovsEnable == 1 )
	{
    	ovs_agent_api_deinit();
	}
#endif
	 	
	if (br_shm_mutex_close(brmutex)) {
            unlink(BRIDGE_UTIL_RUNNING);
	    	return -1;
	}
    
    unlink(BRIDGE_UTIL_RUNNING);
	return 0;

}

/*********************************************************************************************

    caller:  main
    prototype:

        void
        getSettings
            (

            );
    	description :
			This function queries all the system settings (device mode, ovs is enabled )
			needed by the program to configure bridge.

***********************************************************************************************/

void getSettings()
{
        char buf[ 8 ] = { 0 };
        if( 0 == syscfg_get( NULL, "selected_wan_mode", buf, sizeof( buf ) ) )
        {
        	wan_mode = atoi(buf);
        }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve wan selected mode\n");

        }

#ifdef RDKB_EXTENDER_ENABLED
        if( 0 == syscfg_get( NULL, "Device_Mode", buf, sizeof( buf ) ) )
        {
            DeviceNetworkingMode = atoi(buf);
        }
        else
        {
            bridge_util_log("syscfg_get failed to retrieve  device networking mode\n");

        }
#endif
        if( 0 == syscfg_get( NULL, "bridge_mode", buf, sizeof( buf ) ) )
        {
        	DeviceMode = atoi(buf);
        }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve bridge_mode\n");

        }

        memset(buf,0,sizeof(buf));

        if( 0 == syscfg_get( NULL, "HomeSecurityEthernet4Flag", buf, sizeof( buf ) ) )
        {
            PORT2ENABLE = atoi(buf);
      
        }

        memset(buf,0,sizeof(buf));

       if( 0 == syscfg_get( NULL, "mesh_ovs_enable", buf, sizeof( buf ) ) )
        {
	          if ( strcmp (buf,"true") == 0 )
	            	ovsEnable = 1;
	          else 
	            	ovsEnable = 0;        
	    }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve ovs_enable\n");

        }
        if( 0 == access( OPENVSWITCH_LOADED, F_OK ) )
        {
            ovsEnable = 1;
            bridge_util_log("setting ovsEnable to true for OVS build\n");
        }

        memset(buf,0,sizeof(buf));

        if( 0 == syscfg_get( NULL, "bridge_util_enable", buf, sizeof( buf ) ) )
        {
        	  	if ( strcmp (buf,"true") == 0 )
	            	bridgeUtilEnable = 1;
	         	else 
	            	bridgeUtilEnable = 0;   
        }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve bridge_util_enable\n");

        }
        
        memset(buf,0,sizeof(buf));

        memset(ethWanIfaceName,0,sizeof(ethWanIfaceName));
        if( 0 == syscfg_get( NULL, "eth_wan_enabled", buf, sizeof( buf ) ) )
        {
                if ( strcmp (buf,"true") == 0 )
                {
                    ethWanEnabled = 1;
                    if( 0 == syscfg_get( NULL, "eth_wan_iface_name", ethWanIfaceName, sizeof( ethWanIfaceName ) ) )
                    {
                        bridge_util_log("ethWanIfaceName is %s\n",ethWanIfaceName);
                    }
                    else
                    {
                        bridge_util_log("syscfg_get failed to retrieve ethWanIfaceName\n");
                    }
                }
                else
                {
                    ethWanEnabled = 0;   
                }
        }
        else
        {
            bridge_util_log("syscfg_get failed to retrieve eth_wan_enabled\n");

        }
        memset(buf,0,sizeof(buf));
        if( 0 == syscfg_get( NULL, "NonRootSupport", buf, sizeof( buf ) ) )
        {
        	  	if ( strcmp (buf,"true") == 0 )
				drop_root();	
        }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve NonRootSupport\n");
        }

        memset(buf,0,sizeof(buf));
        if( 0 == syscfg_get( NULL, "eb_enable", buf, sizeof( buf ) ) )
        {
        	if ( strcmp (buf,"true") == 0 )
                    eb_enable = 1;
                else
                    eb_enable = 0;
        }
        else
        {
        	bridge_util_log("syscfg_get failed to retrieve eb_enable\n");
        }
        char paramName[256]={0};
	int retPsmGet = CCSP_SUCCESS;
	char *paramValue = NULL;

    //read from psm if not available in syscfg db.
    if(ethWanIfaceName[0] == '\0')
    {
        memset(paramName,0,sizeof(paramName));

        snprintf(paramName,sizeof(paramName), l2netEthWanInterface);
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
        if (retPsmGet == CCSP_SUCCESS)
        {
            bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);

            strncpy(ethWanIfaceName,paramValue,sizeof(ethWanIfaceName)-1);
			if(bus_handle != NULL)
			{
            	((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
            	paramValue = NULL;
			}
        }
        else
        {
            bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

        }
    }
#if !defined (NO_MOCA_FEATURE_SUPPORT)
	snprintf(paramName,sizeof(paramName), mocaIsolation);
	retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, paramName, NULL, &paramValue);
	if (retPsmGet == CCSP_SUCCESS) 
	{
		bridge_util_log("%s: %s returned %s\n", __func__, paramName, paramValue);
		MocaIsolation_Enabled = atoi(paramValue);

		if(bus_handle != NULL)
		{
			((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
			paramValue = NULL;
		}

	}
    	else
    	{
    		bridge_util_log("%s: psm call failed for %s, ret code %d\n", __func__, paramName, retPsmGet);

    	}
#endif
	// In bridge mode and bridge is private lan don't need add WiFi interfaces
    	if ( ( DeviceMode != 0 ) && ( InstanceNumber == PRIVATE_LAN ) )
    	{
    		skipWiFi = 1 ;
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    		skipMoCA = 1 ;
#endif
    	}
#if !defined (NO_MOCA_FEATURE_SUPPORT)
    	if ( ( MocaIsolation_Enabled ==  1 ) && ( InstanceNumber == PRIVATE_LAN ) )
    	{
    		skipMoCA = 1 ;
    	}
  
  	if ( ( MocaIsolation_Enabled ==  0 ) && ( InstanceNumber == MOCA_ISOLATION ) )
        {
        	skipMoCA = 1 ;
        }
#endif
    char cParamName[128] = {0};
    char *pParamVal = NULL;
    int iRetPsmGet = CCSP_SUCCESS;
    snprintf(cParamName,sizeof(cParamName),l2netLinuxBridgeEnabled,InstanceNumber);
    iRetPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, cParamName, NULL, &pParamVal);
    if (iRetPsmGet == CCSP_SUCCESS)
    {
        bridge_util_log("%s: %s returned %s\n", __func__, cParamName, pParamVal);
        if (!strncmp(pParamVal, "TRUE", 4))
        {
            bridge_util_log("Linux Bridge is enabled\n");
            ovsEnable = 0;
            bridgeUtilEnable = 1;
        }
        else
        {
            bridge_util_log("Linux Bridge is not enabled\n");
        }
        if(bus_handle != NULL)
        {
            ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(pParamVal);
            pParamVal = NULL;
        }
    }
}
int HandleWifiInterface(char *Cmd_Opr)
{
	unsigned int m;
	for(m=0; m< InterfaceMap_TOTAL; m++ )
	{
		if( strstr(  Cmd_Opr , InterfaceMap[m].iface) )
		{
			return InterfaceMap[m].inst;
		}
	}
	return -1;
}

int bridgeUtils_main(int argc, char *argv[])
{
		
	logFp = fopen(BRIDGE_UTIL_LOG_FNAME,"a+") ;
    
    	#ifdef INCLUDE_BREAKPAD
    	breakpad_ExceptionHandler();
    	#endif

	if ( argc < 3 )
	{
		bridge_util_log(" ERROR : Missing arguments, please pass valid number of arguments\n");
		return -1;
	}

	int i = 1, rc = 0 ;
	bridgeDetails *bridgeInfo = NULL;
	for (i = 1; i < argc; ++i)
	{
		/* code */
		bridge_util_log("argv[%d] = %s\n",i,argv[i]);
		if(i == 1)
		{
			strncpy(Cmd_Opr,argv[i],sizeof(Cmd_Opr)-1);
			bridge_util_log("Cmd_Opr = %s\n",Cmd_Opr);
        		if( (strcmp(Cmd_Opr,"add-port") == 0 ) || (strcmp(Cmd_Opr,"del-port") == 0 ) )
                		break;
		}
		else if(i == 2)
		{
			InstanceNumber = atoi(argv[i]);
			bridge_util_log("InstanceNumber = %d\n",InstanceNumber);
			break;
		}
	}

	pid_t process_id;
	   
	process_id = getpid();

	brmutex = br_shm_mutex_init(BR_SHM_MUTEX);
	if (brmutex.ptr == NULL) {
		rc = -1;
		return rc;
	}

	if (brmutex.br_shm_create) {
		bridge_util_log("Created shm mutex\n");
	}

	int error;
	// Use pthread calls for locking and unlocking.
	bridge_util_log("Process %d is waiting for lock\n",process_id);
	error = pthread_mutex_lock(brmutex.ptr);

	bridge_util_log("Process %d acquired the lock\n",process_id);
	if (error == EOWNERDEAD) 
	{
		bridge_util_log("Owner dead, acquring the lock\n");
		error = pthread_mutex_consistent_np(brmutex.ptr);
	}

	if ( Initialize() == FAILED )
	{
		rc = -1;
		goto EXIT;

	}
	
	getSettings();

#if defined(USE_LINUX_BRIDGE)
	if(bridgeUtilEnable == 0)
	{
		bridge_util_log(" OVS and Bridge utils are not enabled, exiting\n");
		rc = -1;
		goto EXIT;

	}
#endif
#if !defined(USE_LINUX_BRIDGE)
	if ( 1 == ovsEnable )
	{
		if (!ovs_agent_api_init(OVS_BRIDGE_UTILS_COMPONENT_ID))
		{
			printf("%s failed to initialize API!\n", __func__);
			goto EXIT;
		}
	}
	else if( ( ovsEnable  == 0)&&(bridgeUtilEnable == 0 ))
	{
		bridge_util_log(" OVS and Bridge utils are not enabled, exiting\n");
		rc = -1;
		goto EXIT;

	}
#endif
	if ( (strcmp(Cmd_Opr,"multinet-down") == 0 ) || (strcmp(Cmd_Opr,"multinet-stop") == 0 ) )
	{
		BridgeOprInPropgress = DELETE_BRIDGE;
		DeleteBrInterface();
	}
	else if ( (strcmp(Cmd_Opr,"multinet-up") == 0 ) || (strcmp(Cmd_Opr,"multinet-start") == 0 ) )
	{
		BridgeOprInPropgress = CREATE_BRIDGE;
		CreateBrInterface();

	}
	else if (strcmp(Cmd_Opr,"multinet-syncMembers") == 0 )
	{
		BridgeOprInPropgress = CREATE_BRIDGE;

		SyncBrInterfaces();
	}
	else if ( (strcmp(Cmd_Opr,"multinet-restart") == 0 ) ) 
	{
		BridgeOprInPropgress = DELETE_BRIDGE;

		DeleteBrInterface();
		BridgeOprInPropgress = CREATE_BRIDGE;

		CreateBrInterface();
	}
	// hard coding instance number to not break the exisiting flow
	else if ( (strcmp(Cmd_Opr,"lnf-setup") == 0 ) ) 
	{
		BridgeOprInPropgress = CREATE_BRIDGE;

		InstanceNumber = LOST_N_FOUND;
		CreateBrInterface();
	}
	else if ( (strcmp(Cmd_Opr,"lnf-down") == 0 ) ) 
	{
		BridgeOprInPropgress = DELETE_BRIDGE;

		InstanceNumber = LOST_N_FOUND;
		DeleteBrInterface();
	}
    else if ( (strcmp(Cmd_Opr,"meshbhaul-setup") == 0 ) ) 
    {
        BridgeOprInPropgress = CREATE_BRIDGE;
        InstanceNumber = MESH_BACKHAUL;
        CreateBrInterface();
    }
    else if ( (strcmp(Cmd_Opr,"meshonboard-setup") == 0 ) )
    {
        BridgeOprInPropgress = CREATE_BRIDGE;
        InstanceNumber = MESH_ONBOARD;
        CreateBrInterface();
    }
    else if ( (strcmp(Cmd_Opr, "meshethbhaul-up") == 0 ) )
    {
        if(eb_enable != 0)
        {
            BridgeOprInPropgress = CREATE_BRIDGE;
            InstanceNumber = ETH_BACKHAUL;
            CreateBrInterface();
        }
        else
        {
            bridge_util_log("Meshethbhaul not started as eb_enable is false\n");
        }
    }
    else if ( (strcmp(Cmd_Opr, "meshethbhaul-down") == 0 ) )
    {
        BridgeOprInPropgress = DELETE_BRIDGE;
        InstanceNumber = ETH_BACKHAUL;
        DeleteBrInterface();
    }
    else if ( (strcmp(Cmd_Opr,"add-port") == 0 ) ) 
    {
        AddOrDeletePort(argv[2],argv[3],IF_UP_CMD_TYPE);
    }
    else if ( (strcmp(Cmd_Opr,"del-port") == 0 ) ) 
    {
        AddOrDeletePort(argv[2],argv[3],BR_REMOVE_CMD_TYPE);
    }
    else if ( (strstr(Cmd_Opr,"if_wlan") != 0 ) ) 
    {
        int instance = -1;
        char *wlan_ifname = NULL;
        char if_wlan_cmd[32] = {0};

        memcpy(if_wlan_cmd, Cmd_Opr, 32);
        wlan_ifname = strtok (if_wlan_cmd, "_");
        wlan_ifname = strtok (NULL, "-");
        if (wlan_ifname == NULL)
        {
            bridge_util_log("%s : wlan_ifname is NULL, exiting\n", __FUNCTION__);
            rc = -1;
            goto EXIT;
        }
        bridge_util_log("wlan_ifname %s\n", wlan_ifname);

        bridgeInfo = (bridgeDetails*)malloc(sizeof(bridgeDetails));
        if (bridgeInfo == NULL)
        {
            bridge_util_log("%s : Memory allocation failed to allocate for bridgeDetails, exiting\n", __FUNCTION__);
            rc = -1;
            goto EXIT;
        }

        memset(bridgeInfo, 0, sizeof(bridgeDetails));
        instance = HandleWifiInterface(Cmd_Opr);
        InstanceNumber = instance;
        getIfList(bridgeInfo);

        if ((bridgeInfo->bridgeName[0] == '\0') || (bridgeInfo->WiFiIfList[0] == '\0'))
        {
            bridge_util_log("bridgeName / WiFiIfList is empty, exiting\n");
            rc = -1;
            goto EXIT;
        }
        if( -1 != instance && HOTSPOT_2G != instance && HOTSPOT_5G != instance && HOTSPOT_SECURE_2G != instance && HOTSPOT_SECURE_5G != instance)
        {
            bridge_util_log(" In wlan instance %d \n", instance );
            bridge_util_log("In wlan ifname %s\n", wlan_ifname);
            if ((INTERFACE_EXIST == checkIfExists(wlan_ifname)))
            {
                if (strstr(bridgeInfo->WiFiIfList, wlan_ifname) != 0 )
                {
                    if (INTERFACE_NOT_EXIST == checkIfExistsInBridge(wlan_ifname, bridgeInfo->bridgeName))
                    {
                        AddOrDeletePort(bridgeInfo->bridgeName, wlan_ifname, IF_UP_CMD_TYPE);
                    }
                }
            }
        }
        else if(HOTSPOT_2G == instance || HOTSPOT_5G == instance || HOTSPOT_SECURE_2G == instance || HOTSPOT_SECURE_5G == instance)
        {
            bridge_util_log(" In wlan instance %d. This will be handled as part of hotspot blob unpack and gre tunnel creation \n", instance );
        }
    }
    else
    {
        bridge_util_log("%s is invalid operation\n",Cmd_Opr);
    }

EXIT:
    if (bridgeInfo != NULL)
    {
        free(bridgeInfo);
        bridgeInfo = NULL;
    }
	ExitFunc();


	return rc;
}
