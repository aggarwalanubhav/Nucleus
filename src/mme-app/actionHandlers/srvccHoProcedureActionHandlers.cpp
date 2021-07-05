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
#include "structs.h"

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



using namespace cmn;
using namespace cmn::utils;
using namespace mme;
using namespace SM;

/***************************************
* Action handler : split_bearer
***************************************/
ActStatus ActionHandlers::split_bearer(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside split_bearer");

    UEContext *ueCtxt = static_cast<UEContext*>(cb.getPermDataBlock());

    if (ueCtxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "split_bearer: ue context is NULL");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvccProc_p =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (srvccProc_p == NULL)
    {
        log_msg(LOG_DEBUG,
                "split_bearer: SrvccProcedureContext is NULL");
        return ActStatus::HALT;
    }

    auto& sessionCtxtContainer = ue_ctxt->getSessionContextContainer();
    if(sessionCtxtContainer.size() < 1)
    {
	log_msg(LOG_DEBUG, "split_bearer:Session context list empty");
	return ActStatus::HALT;
    }

    SessionContext* sessionCtxt = sessionCtxtContainer.front();
    if (sessionCtxt) {
        auto &bearerCtxtContainer = sessionCtxt->getBearerContextContainer();
        if (bearerCtxtContainer.size() < 1)
        {
            log_msg(LOG_ERROR, "Bearer context list is empty for UE IDX %d",
                    cb.getCBIndex());
            return;
        }

        auto it = bearerCtxtContainer.begin();
        BearerContext *bearer_p = NULL;
        while (it != bearerCtxtContainer.end())
        {
            bearer_p = *it;
            it++;
            if (bearer_p->getBearerQos().qci == 1)
                srvccProc_p->setVoiceBearer(bearer_p);
            else
                srvccProc_p->addPsBearers(bearer_p);
        }
    }

    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_ps_to_cs_req_to_msc
***************************************/
ActStatus ActionHandlers::send_ps_to_cs_req_to_msc(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside send_ps_to_cs_req_to_msc");

    UEContext *ueCtxt = static_cast<UEContext*>(cb.getPermDataBlock());

    if (ueCtxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_ps_to_cs_req_to_msc: ue context is NULL");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvccProc_p =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (srvccProc_p == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_ps_to_cs_req_to_msc: SrvccProcedureContext is NULL");
        return ActStatus::HALT;
    }

    struct PS_to_CS_REQ_msg psToCsReq;
    memset(&psToCsReq, 0, sizeof(struct PS_to_CS_REQ_msg));

    MmeGtpMsgUtils::populatePsToCsRequest(
            cb, *ue_ctxt, *srvccProc_p, psToCsReq);

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_SV_PS_TO_CS_REQUEST);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::svAppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &psToCsReq, sizeof(psToCsReq), destAddr);

    ProcedureStats::num_of_fwd_relocation_req_sent++;
    log_msg(LOG_DEBUG, "Leaving send_ps_to_cs_req_to_msc ");
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
    log_msg(LOG_DEBUG, "Inside handle_ps_to_cs_res ");

	UEContext *ue_ctxt = dynamic_cast<UEContext*>(cb.getPermDataBlock());
	VERIFY_UE(cb, ue_ctxt, "Invalid UE");

    MsgBuffer *msgBuf = static_cast<MsgBuffer*>(cb.getMsgData());
    if (msgBuf == NULL)
    {
        log_msg(LOG_ERROR, "Failed to retrieve message buffer ");
        return ActStatus::HALT;
    }

    S1HandoverProcedureContext* s1HoPrCtxt = dynamic_cast<S1HandoverProcedureContext*>(cb.getTempDataBlock());
    if(s1HoPrCtxt==NULL)
    {  
        log_msg(LOG_DEBUG,"forward_relocation_reponse: S1HandoverProcedureContext is NULL");
        return ActStatus::HALT;

    }

    const ps_to_cs_res_Q_msg *psToCsRes = static_cast<const ps_to_cs_res_Q_msg*>(msgBuf->getDataPointer());
    s1HoPrCtxt->setTargetToSrcTransContainer(psToCsRes->target_to_source_transparent_container);
    ProcedureStats::num_of_fwd_relocation_resp_processed++;

    return ActStatus::PROCEED;
}

/***************************************
* Action handler : process_ps_to_cs_comp
***************************************/
ActStatus ActionHandlers::process_ps_to_cs_comp(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside process_ps_to_cs_comp ");

    UEContext *ue_ctxt = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "process_ps_to_cs_comp: ue context or procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (srvcc_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "process_ps_to_cs_comp: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    struct PS_to_CS_COMP_ACK_msg ps_to_cs_ack_msg;
    ps_to_cs_ack_msg.msg_type = ps_to_cs_complete_acknowledge;
	ps_to_cs_ack_msg.ue_idx = ueCtxt.getContextID();
    ps_to_cs_ack_msg.cause.causeValue = 16;

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_SV_PS_TO_CS_COMPLETE_ACK);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::svAppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &ps_to_cs_ack_msg, sizeof(ps_to_cs_ack_msg), destAddr);

    ProcedureStats::num_of_ps_to_cs_comp_processed++;
    ProcedureStats::num_of_ps_to_cs_comp_ack_sent++;
    log_msg(LOG_DEBUG, "Leaving process_ps_to_cs_comp ");
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_del_bearer_command
***************************************/
ActStatus ActionHandlers::send_del_bearer_command(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside send_del_bearer_command ");

    UEContext *ue_ctxt = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_del_bearer_command: ue context or procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (srvcc_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_del_bearer_command: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    auto& sessionCtxtContainer = ue_ctxt->getSessionContextContainer();
    if(sessionCtxtContainer.size() < 1)
    {
	log_msg(LOG_DEBUG, "send_del_bearer_command:Session context list empty");
	return ActStatus::HALT;
    }

    SessionContext* sessionCtxt = sessionCtxtContainer.front();

    struct DELETE_BEARER_COMMAND_msg db_command_msg;
    memset(&db_command_msg, 0, sizeof(struct DELETE_BEARER_COMMAND_msg));
    MmeGtpMsgUtils::populateDeleteBearerCommand(
            cb, *ue_ctxt, *sessionCtxt, *srvcc_ctxt, db_command_msg);

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_S3_FORWARD_RELOCATION_COMPLETE_ACK);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::s3AppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &fwd_rel_comp_ack_msg, sizeof(fwd_rel_comp_ack_msg), destAddr);

    mmeStats::Instance()->increment(mmeStatsCounter::MME_PROCEDURES_DELETE_BEARER_PROC);
    srvcc_ctxt->setCtxtType(ProcedureType::dedBrDeActivation_c);
    srvcc_ctxt->setNextState(SrvccDelDedBearer::Instance());
    srvcc_ctxt->setHoType(lteToUtran);
    cb.addTempDataBlock(srvcc_ctxt);

    ProcedureStats::num_of_fwd_rel_comp_processed++;
    ProcedureStats::num_of_fwd_rel_comp_ack_sent++;
    log_msg(LOG_DEBUG, "Leaving send_del_bearer_command ");
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : process_fwd_rel_comp
***************************************/
ActStatus ActionHandlers::process_fwd_rel_comp(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside process_fwd_rel_comp ");

    UEContext *ue_ctxt = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "process_fwd_rel_comp: ue context or procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (srvcc_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "process_fwd_rel_comp: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    struct fwd_rel_comp_ack fwd_rel_comp_ack_msg;
    fwd_rel_comp_ack_msg.msg_type = fwd_rel_comp_ack;
	fwd_rel_comp_ack_msg.ue_idx = ueCtxt.getContextID();
    fwd_rel_comp_ack_msg.cause.causeValue = 16;

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_S3_FORWARD_RELOCATION_COMPLETE_ACK);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::s3AppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &fwd_rel_comp_ack_msg, sizeof(fwd_rel_comp_ack_msg), destAddr);

    ProcedureStats::num_of_fwd_rel_comp_processed++;
    ProcedureStats::num_of_fwd_rel_comp_ack_sent++;
    log_msg(LOG_DEBUG, "Leaving process_fwd_rel_comp ");
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_srvcc_ho_command
***************************************/
ActStatus ActionHandlers::send_srvcc_ho_command(ControlBlock& cb)
{
    log_msg(LOG_DEBUG, "Inside send_srvcc_ho_command");

    UEContext *ue_ctxt = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ue_ctxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_srvcc_ho_command: ue ctxt is NULL ");
        return ActStatus::HALT;
    }

    SrvccProcedureContext *srvcc_ctxt =
            dynamic_cast<SrvccProcedureContext*>(cb.getTempDataBlock());
    if (ho_ctxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_srvcc_ho_command: procedure ctxt is NULL ");
        return ActStatus::HALT;
    }

    struct handover_command_Q_msg ho_command;
    memset(&ho_command, 0, sizeof(struct handover_command_Q_msg));

    MmeS1MsgUtils::populateHoCommand(cb, *ue_ctxt, *srvcc_ctxt, ho_command);

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_S1AP_HANDOVER_COMMAND);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::s1apAppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &ho_command, sizeof(ho_command), destAddr);

    ProcedureStats::num_of_ho_command_to_src_enb_sent++;
    log_msg(LOG_DEBUG, "Leaving send_srvcc_ho_command");
    return ActStatus::PROCEED;
}
