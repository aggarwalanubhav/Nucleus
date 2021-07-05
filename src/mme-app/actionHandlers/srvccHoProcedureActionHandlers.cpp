/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
/******************************************************************************
 *
 * This file has both generated and manual code.
 * 
 * File template used for code generation:
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/actionHandlers.cpp.tt>
 *
 ******************************************************************************/
#include "actionHandlers/actionHandlers.h"
#include "controlBlock.h" 
#include "msgType.h"
#include "structs.h"

#include "controlBlock.h" 
#include "msgType.h"
#include "controlBlock.h"
#include "msgType.h"
#include "mme_app.h"
#include "procedureStats.h"
#include "log.h"
#include "secUtils.h"
#include "state.h"
#include <string.h>
#include <sstream>
#include <mmeSmDefs.h>
#include "common_proc_info.h"
#include <ipcTypes.h>
#include <tipcTypes.h>
#include <msgBuffer.h>
#include <interfaces/mmeIpcInterface.h>
#include <event.h>
#include <stateMachineEngine.h>
#include <utils/mmeCommonUtils.h>
#include <utils/mmeS1MsgUtils.h>
#include <utils/mmeGtpMsgUtils.h>
#include <utils/mmeCauseUtils.h>
#include <contextManager/dataBlocks.h>
#include <utils/mmeContextManagerUtils.h>
#include "mmeStatsPromClient.h"
#include "gtpCauseTypes.h"
#include "nas_structs.h"



using namespace mme;
using namespace SM;

/***************************************
* Action handler : split_bearer
***************************************/
ActStatus ActionHandlers::split_bearer(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_ps_to_cs_req_to_msc
***************************************/
ActStatus ActionHandlers::send_ps_to_cs_req_to_msc(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_fwd_rel_req_to_sgsn
***************************************/
ActStatus ActionHandlers::send_fwd_rel_req_to_sgsn(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside send_fwd_rel_req_to_sgsn ");

    UEContext *ue_ctxt = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_fwd_rel_req_to_sgsn: ue context or procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());

    if (srvcc_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_fwd_rel_req_to_sgsn: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }
    S1HandoverProcedureContext *s1procctxt =
            dynamic_cast<S1HandoverProcedureContext*>(cb.getTempDataBlock());
    if (s1procctxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_fwd_rel_req_to_sgsn: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    MmeProcedureCtxt* prcdCtxt_p = 
		dynamic_cast<MmeProcedureCtxt*>(cb.getTempDataBlock());

    if (prcdCtxt_p == NULL)
    {
        log_msg(LOG_DEBUG, "send_fwd_rel_req_to_sgsn: MME procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    SessionContext* sessioncntxt = 
		dynamic_cast<SessionContext*>(cb.getTempDataBlock());

    if (sessioncntxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_fwd_rel_req_to_sgsn: Session ctxt is NULL ");
        return ActStatus::HALT;
    }





    struct FORWARD_REL_REQ_msg fwd_rel_req;
    memset(&fwd_rel_req, 0, sizeof(struct FORWARD_REL_REQ_msg));

    fwd_rel_req.msg_type = forward_relocation_request;
    fwd_rel_req.ue_idx = ueCtxt->getContextID();



    
    fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV4Address.ipValue = sessioncntxt->getS11SgwCtrlFteid().fteid_m.ip.ipv4;
    fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.count = INET6_ADDRSTRLEN;
    memcpy(fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.values,sessioncntxt->getS11SgwCtrlFteid().fteid_m.ip.ipv6.__in6_u.__u6_addr16,sizeof(fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.values))
    
    const DigitRegister15& ueImsi = ueCtxt->getImsi();
    ueImsi.convertToBcdArray( fwd_rel_req.IMSI );

    fwd_rel_req.mmeSgsnAmfUeMmContext.securityMode = EPSsecurityContext;
    fwd_rel_req.mmeSgsnAmfUeMmContext.nhiPresent = 1;
    
    E_UTRAN_sec_vector* secVect =
            const_cast<E_UTRAN_sec_vector*>(ue_ctxt->getAiaSecInfo().AiaSecInfo_mp);
    secinfo& secInfo = const_cast<secinfo&>(ue_ctxt->getUeSecInfo().secinfo_m);

    fwd_rel_req.mmeSgsnAmfUeMmContext.nasDownlinkCount = ueCtxt->getUeSecInfo().getDownlinkCount();
    fwd_rel_req.mmeSgsnAmfUeMmContext.nasUplinkCount = ueCtxt->getUeSecInfo().getUplinkCount();
    fwd_rel_req.mmeSgsnAmfUeMmContext.uambriPresent = true;
    fwd_rel_req.mmeSgsnAmfUeMmContext.usedNasIntegrity = ueCtxt->getUeSecInfo().getSelectSecAlg();
    fwd_rel_req.mmeSgsnAmfUeMmContext.usedNasCipher = ueCtxt->getUeSecInfo().getSelectIntAlg();

    fwd_rel_req.mmeSgsnAmfUeMmContext.kAsme = secInfo.kasme.val;
    fwd_rel_req.mmeSgsnAmfUeMmContext.drxParameter = PAGINX_DRX256;
    
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.authenticationQuadruplet.values, secVect,sizeof(AuthenticationQuadruplet));
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.authenticationQuintuplet.values, secVect,sizeof(AuthenticationQuintuplet));
    
    /// Next hop count and next chaining count need to check
    unsigned char nh[SECURITY_KEY_SIZE] = { 0 };
    secInfo.next_hop_chaining_count = 1;
    SecUtils::create_nh_key(secVect->kasme.val, nh, secInfo.kenb_key);
    memcpy(secInfo.next_hop_nh , nh, KENB_SIZE);
    
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.nh  , nh, KENB_SIZE);
    fwd_rel_req.mmeSgsnAmfUeMmContext.ncc = ueCtxt->getUeSecInfo().secinfo_m.next_hop_chaining_count;

    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfUeNetworkCapability = ueCtxt->getUeNetCapab().ue_net_capab_m.len;
    fwd_rel_req.mmeSgsnAmfUeMmContext.ueNetworkCapability = ueCtxt->getUeNetCapab().ue_net_capab_m.u;
    //need clarification in ms network capability
    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfMsNetworkCapability = ueCtxt->getUeNetCapab().ue_net_capab_m.capab[1];
    fwd_rel_req.mmeSgsnAmfUeMmContext.msNetworkCapability = ueCtxt->getMsNetCapab().ms_net_capab_m.len;
    fwd_rel_req.mmeSgsnAmfUeMmContext.voiceDomainPreferenceAndUesUsageSetting = ueCtxt->getVoiceDomainPref().voiceDomainPref_m.voice_dom_pref;
    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfVoiceDomainPreferenceAndUesUsageSetting = sizeof(Voice_Domain_Preference);

    memcpy(fwd_rel_req.selectedPlmnId , &(ue_ctxt->getTai().tai_m.plmn_id), 3);

    memcpy(&(fwd_rel_req.eUtranTransparentContainer),
            &(s1procctxt.getSrcToTargetTransContainer()),
            sizeof(struct src_target_transparent_container));

    memcpy(&(fwd_rel_req.utranTransparentContainer),
            &(s1procctxt.getSrcToTargetTransContainer()),
            sizeof(struct src_target_transparent_container));

    fwd_rel_req.s1ApCause.fCauseField = prcdCtxt_p->getS1HoCause().s1apCause_m.choice.protocol;
    fwd_rel_req.ranapCause.fCauseField = prcdCtxt_p->getS1HoCause().s1apCause_m.choice.radioNetwork;
    memcpy(fwd_rel_req.servingNetwork , &(ue_ctxt->getTai().tai_m.plmn_id), 3);


    memcpy(&(fwd_rel_req.AdditionalMmContextForSrvcc.msclassmark2),
                &(ueCtxt->getMsClassmark2()),
                sizeof(Mobile_Station_Classmark_2));

    memset(fwd_rel_req.MSISDN, 0, BINARY_IMSI_LEN);
	
	const DigitRegister15& ueMSISDN = ue_ctxt->getMsisdn();
	ueMSISDN.convertToBcdArray(fwd_rel_req.MSISDN);

    memset(fwd_rel_req.cMsisdn, 0, BINARY_IMSI_LEN);
	
	const DigitRegister15& uecMSISDN = ue_ctxt->getMsisdn();
	uecMSISDN.convertToBcdArray(fwd_rel_req.cMSISDN);

    /*Send message to S10-APP*/
    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_S3_FORWARD_RELOCATION_REQUEST);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::s3AppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &fwd_rel_req, sizeof(fwd_rel_req), destAddr);
    log_msg(LOG_DEBUG, "Leaving send_fr_request_to_target_mme ");
    ProcedureStats::num_of_fwd_relocation_req_sent++;
    


    return ActStatus::PROCEED;
}

/***************************************
* Action handler : handle_fwd_rel_res_from_sgsn
***************************************/
ActStatus ActionHandlers::handle_fwd_rel_res_from_sgsn(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside forward_relocation_reponse ");

	UEContext *ue_ctxt = dynamic_cast<UEContext*>(cb.getPermDataBlock());
	VERIFY_UE(cb, ue_ctxt, "Invalid UE");
    ProcedureStats::num_of_processed_attach_cmp_from_ue ++;
	log_msg(LOG_DEBUG, "Leaving handle_attach_cmp_from_ue ");

    
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_ERROR, "forward_relocation_reponse: ue context is NULL",
                cb.getCBIndex());
        return ActStatus::HALT;
    }
    MsgBuffer *msgBuf = static_cast<MsgBuffer*>(cb.getMsgData());
    if (msgBuf == NULL)
    {
        log_msg(LOG_ERROR, "Failed to retrieve message buffer ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());

    if (srvcc_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "forward_relocation_reponse: SRVCC procedure ctxt is NULL ");
        return ActStatus::HALT;
    }
    S1HandoverProcedureContext* s1HoPrCtxt = dynamic_cast<S1HandoverProcedureContext*>(cb.getTempDataBlock());
    if(s1HoPrCtxt==NULL)
    {  
        log_msg(LOG_DEBUG,"forward_relocation_reponse: S1HandoverProcedureContext is NULL");
        return ActStatus::HALT;

    }

    MmeProcedureCtxt *procCtxt = dynamic_cast<MmeProcedureCtxt*>(cb.getTempDataBlock());
    if(procCtxt==NULL)
    {  
        log_msg(LOG_DEBUG,"forward_relocation_reponse: MMEProcedureContext is NULL");
        return ActStatus::HALT;

    }
	SessionContext* sessionCtxt = sessionCtxtContainer.front();
    if(sessionCtxt==NULL)
    {  
        log_msg(LOG_DEBUG,"forward_relocation_reponse: SessionContext is NULL");
        return ActStatus::HALT;

    }
    
    MmeProcedureCtxt *MmeSvcReqProcedureCtxt = dynamic_cast<MmeProcedureCtxt*>(cb.getMmeSvcReqProcedureCtxt());
    if(MmeSvcReqProcedureCtxt==NULL)
    {  
        log_msg(LOG_DEBUG,"forward_relocation_reponse: MmeSvcReqProcedureCtxt is NULL");
        return ActStatus::HALT;

    }

    const forward_rel_response_msg *forward_rel_response_msg = static_cast<const forward_rel_response_msg*>(msgBuf->getDataPointer());
    
    
    sessionCtxt->setS11SgwCtrlFteid(forward_rel_response_msg->senderFTeidForControlPlane);
    procCtxt->setMmeErrorCause(forward_rel_response_msg->cause.causeValue);
    MmeSvcReqProcedureCtxt->setEpsBearerId(forward_rel_response_msg->listOfSetUpBearers[0].epsBearerId);
    s1HoPrCtxt->setTargetToSrcTransContainer(forward_rel_response_msg->utranTranparentContainer);

    ProcedureStats::num_of_fwd_relocation_resp_received++;
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : handle_ps_to_cs_res
***************************************/
ActStatus ActionHandlers::handle_ps_to_cs_res(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : process_ps_to_cs_comp
***************************************/
ActStatus ActionHandlers::process_ps_to_cs_comp(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_del_bearer_command
***************************************/
ActStatus ActionHandlers::send_del_bearer_command(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : process_fwd_rel_comp
***************************************/
ActStatus ActionHandlers::process_fwd_rel_comp(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_srvcc_ho_command
***************************************/
ActStatus ActionHandlers::send_srvcc_ho_command(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}
