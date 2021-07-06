#ifndef __SRVCC_STRUCTS_H_
#define __SRVCC_STRUCTS_H_

#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <nas_structs.h>
#include "../../src/gtpV2Codec/ieClasses/gtpV2DataTypes.h"

#define S11_MSGBUF_SIZE 2048
#define DED_BEARER_COUNT 1

typedef struct AdditionalMmContextForSrvcc
{
    Mobile_Station_Classmark_2 msclassmark2;
}AdditionalMmContextForSrvcc;

typedef struct MmContextForEutranSrvcc
{
    uint8_t eKSI;
    uint8_t CKSRVCC[NAS_INT_KEY_SIZE];    
    uint8_t IKSRVCC[NAS_SEC_KEY_SIZE];
    Mobile_Station_Classmark_2 mobileStationClassmark2;
    uint8_t lengthOfTheMobileStationClassmark3;    
    uint8_t mobileStationClassmark3;    
    uint8_t lengthOfTheSupportedCodecList;    
    uint8_t supportedCodecList;    

}MmContextForEutranSrvcc;

typedef struct MmContext_t
{
    uint8_t securityMode;    
    bool nhiPresent;    
    bool drxiPresent;    
    uint8_t ksiAsme;    
    uint8_t numberOfQuintuplets;    
    uint8_t numberOfQuadruplet;    
    bool uambriPresent;    
    bool osciPresent;    
    bool sambriPresent;    
    uint8_t usedNasIntegrity;    
    uint8_t usedNasCipher;    
    uint32_t nasDownlinkCount;    
    uint32_t nasUplinkCount;    
    struct KASME kAsme;    
    AuthenticationQuadrupletArray5 authenticationQuadruplet;    
    AuthenticationQuintupletArray5 authenticationQuintuplet;    
    uint8_t drxParameter;    
    uint8_t nh[KENB_SIZE];    
    uint8_t ncc;    
    uint8_t uplinkSubscribedUeAmbr;    
    uint8_t downlinkSubscribedUeAmbr;    
    uint8_t uplinkUsedUeAmbr;    
    uint8_t downlinkUsedUeAmbr;    
    UE_net_capab ueNwCap;    
    uint8_t lengthOfMsNetworkCapability;    
    uint8_t msNetworkCapability;    
    uint8_t lengthOfMobileEquipmentIdentity;    
    uint8_t mobileEquipmentIdentity;    
    bool ecna;    
    bool nbna;    
    bool hnna;    
    bool ena;    
    bool ina;    
    bool gana;    
    bool gena;    
    bool una;    
    bool nhiOIdPresent;    
    uint8_t oldKsiAsme;    
    uint8_t oldNcc;    
    uint8_t oldKasme;    
    uint8_t oldNh;    
    uint8_t lengthOfVoiceDomainPreferenceAndUesUsageSetting;    
    Voice_Domain_Preference voiceDomainPreferenceAndUesUsageSetting;    
    uint8_t lengthOfUeRadioCapabilityForPagingInformation;    
    uint8_t ueRadioCapabilityForPagingInformation;    
    uint8_t lengthOfExtendedAccessRestrictionData;    
    bool ussrna;    
    bool nrsrna;    
    uint8_t lengthOfUeAdditionalSecurityCapability;    
    uint8_t ueAdditionalSecurityCapability;    
    uint8_t lengthOfUeNrSecurityCapability;    
    uint8_t ueNrSecurityCapability;    

}MmContext_t;

#endif
