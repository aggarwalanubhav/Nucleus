/*
* Copyright 2020-present, Infosys Ltd.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <utils/mmeGtpMsgUtils.h>
#include "msgType.h"
#include "secUtils.h"
#include <controlBlock.h>
#include <contextManager/dataBlocks.h>
#include <utils/mmeCauseUtils.h>
#include <utils/mmeContextManagerUtils.h>
#include "gtpCauseTypes.h"
#include <log.h>
#include <mme_app.h>

using namespace mme;

void MmeGtpMsgUtils::populateModifyBearerRequestHo(SM::ControlBlock& cb,
        UEContext& ueCtxt,
        SessionContext& sessionCtxt,
		S1HandoverProcedureContext& procCtxt,
		struct MB_Q_msg& mbMsg)
{
	mbMsg.msg_type = modify_bearer_request;
	mbMsg.ue_idx = ueCtxt.getContextID();
    memset(mbMsg.indication, 0, S11_MB_INDICATION_FLAG_SIZE);

    BearerContext *bearerCtxt = sessionCtxt.findBearerContextByBearerId(sessionCtxt.getLinkedBearerId());
    if (bearerCtxt == NULL)
    {
        log_msg(LOG_DEBUG, "send_mb_req_to_sgw_for_ho: bearer ctxt is NULL ");
        return;
    }

    mbMsg.bearer_ctx_list.bearers_count = 1;

    mbMsg.bearer_ctx_list.bearer_ctxt[0].eps_bearer_id = bearerCtxt->getBearerId();
    memcpy(&(mbMsg.s11_sgw_c_fteid),
            &(sessionCtxt.getS11SgwCtrlFteid().fteid_m), sizeof(struct fteid));

    mbMsg.bearer_ctx_list.bearer_ctxt[0].s1u_enb_fteid.header.iface_type = 0;
    mbMsg.bearer_ctx_list.bearer_ctxt[0].s1u_enb_fteid.header.v4 = 1;
    mbMsg.bearer_ctx_list.bearer_ctxt[0].s1u_enb_fteid.header.teid_gre = procCtxt.getErabAdmittedItem().gtp_teid;
    mbMsg.bearer_ctx_list.bearer_ctxt[0].s1u_enb_fteid.ip.ipv4.s_addr =
            procCtxt.getErabAdmittedItem().transportLayerAddress;

    bearerCtxt->setS1uEnbUserFteid(Fteid(mbMsg.bearer_ctx_list.bearer_ctxt[0].s1u_enb_fteid));

    mbMsg.userLocationInformationIePresent = true;
    memcpy(&(mbMsg.tai), &(procCtxt.getTargetTai().tai_m), sizeof(struct TAI));
    memcpy(&(mbMsg.utran_cgi), &(procCtxt.getTargetCgi().cgi_m), sizeof(struct CGI));

    mbMsg.servingNetworkIePresent = true;

}

bool MmeGtpMsgUtils::populateCreateBearerResponse(SM::ControlBlock &cb,
        MmeSmCreateBearerProcCtxt &createBearerProc, struct CB_RESP_Q_msg &cb_resp)
{
    bool status = false;

    cb_resp.msg_type = create_bearer_response;

    UEContext *ueCtxt_p = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ueCtxt_p != NULL)
    {
        SessionContext *sessionCtxt_p =
                ueCtxt_p->findSessionContextByLinkedBearerId(
                        createBearerProc.getBearerId());

        if (sessionCtxt_p != NULL)
        {
            uint8_t index = 0;
            uint8_t successCount = 0;

            memcpy(&(cb_resp.s11_sgw_c_fteid),
                    &(sessionCtxt_p->getS11SgwCtrlFteid().fteid_m), sizeof(struct fteid));

            auto &bearerStatusContainer = createBearerProc.getBearerStatusContainer();
            cb_resp.bearer_ctxt_cb_resp_list.bearers_count = bearerStatusContainer.size();

            for (auto &it : bearerStatusContainer)
            {
                BearerContext *bearerCtxt_p =
                        MmeContextManagerUtils::findBearerContext(
                                it.bearer_ctxt_cb_resp_m.eps_bearer_id,
                                ueCtxt_p);

                memcpy(&cb_resp.bearer_ctxt_cb_resp_list.bearer_ctxt[index],
                        &it.bearer_ctxt_cb_resp_m,
                        sizeof(bearer_ctxt_cb_resp_t));
                if (bearerCtxt_p != NULL)
                {
                    memcpy(
                            &(cb_resp.bearer_ctxt_cb_resp_list.bearer_ctxt[index].s1u_enb_fteid),
                            &(bearerCtxt_p->getS1uEnbUserFteid().fteid_m),
                            sizeof(struct fteid));
                }

                index++;

                if (it.bearer_ctxt_cb_resp_m.cause.cause
                        == GTPV2C_CAUSE_REQUEST_ACCEPTED
                        || it.bearer_ctxt_cb_resp_m.cause.cause
                                == GTPV2C_CAUSE_REQUEST_ACCEPTED_PARTIALLY)
                {
                    successCount++;
                }
            }

            if (successCount == 0)
                cb_resp.cause = GTPV2C_CAUSE_REQUEST_REJECTED;
            else
                cb_resp.cause = GTPV2C_CAUSE_REQUEST_ACCEPTED;
        }
        else
        {
            log_msg(LOG_INFO,
                    "populateCreateBearerResponse : SessionContext is NULL ");
            cb_resp.cause = GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
        }
    }
    else
    {
        log_msg(LOG_INFO,
                "populateCreateBearerResponse : UEContext is NULL ");
        cb_resp.cause = GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
    }

    cmn::IpcEventMessage *ipcMsg =
            dynamic_cast<cmn::IpcEventMessage*>(createBearerProc.getCreateBearerReqEMsgRaw());

    if (ipcMsg != NULL)
    {
        cmn::utils::MsgBuffer *msgBuf =
                static_cast<cmn::utils::MsgBuffer*>(ipcMsg->getMsgBuffer());
        if (msgBuf != NULL)
        {
            cb_req_Q_msg *cb_req =
                    static_cast<cb_req_Q_msg*>(msgBuf->getDataPointer());

            if (cb_req != NULL)
            {
                // In case of unavailability of session/UE Contexts,
                // s11_sgw_cp_teid will be set as 0
                if (cb_resp.cause == GTPV2C_CAUSE_CONTEXT_NOT_FOUND)
                {
                    cb_resp.s11_sgw_c_fteid.header.teid_gre = 0;
                }
                cb_resp.s11_sgw_c_fteid.ip.ipv4.s_addr = cb_req->sgw_ip;
                cb_resp.destination_port = cb_req->source_port;
		cb_resp.seq_no = cb_req->seq_no;
		if(createBearerProc.getMmeErrorCause())
		{
                    cb_resp.cause = MmeCauseUtils::convertToGtpCause(
                        createBearerProc.getMmeErrorCause());
		}

                status = true;

                log_msg(LOG_INFO, "populateCreateBearerResponse : CB Response Cause: %d ", cb_resp.cause);
            }
        }
    }
    return status;
}

bool MmeGtpMsgUtils::populateDeleteBearerResponse(SM::ControlBlock &cb,
        MmeSmDeleteBearerProcCtxt &deleteBearerProc,
        struct DB_RESP_Q_msg &db_resp)
{
    bool status = false;
    cmn::utils::MsgBuffer *msgBuf = NULL;
    db_req_Q_msg *db_req = NULL;
    /*
     * Even in cases of abort, we are deleting the bearers implicitly.
     * Hence, initializing the cause value as REQUEST_ACCEPTED
     */
    uint8_t gtpCause = GTPV2C_CAUSE_REQUEST_ACCEPTED;

    cmn::IpcEventMessage *ipcMsg =
            dynamic_cast<cmn::IpcEventMessage*>(deleteBearerProc.getDeleteBearerReqEMsgRaw());

    if (ipcMsg != NULL)
    {
        msgBuf = static_cast<cmn::utils::MsgBuffer*>(ipcMsg->getMsgBuffer());
        if (msgBuf != NULL)
        {
            db_req = static_cast<db_req_Q_msg*>(msgBuf->getDataPointer());
        }
    }

    if (db_req == NULL)
    {
        log_msg(LOG_INFO,
                "populateDeleteBearerResponse : db_Req is NULL ");
        return status;
    }

    db_resp.msg_type = delete_bearer_response;

    UEContext *ueCtxt_p = static_cast<UEContext*>(cb.getPermDataBlock());
    if (ueCtxt_p != NULL)
    {
        SessionContext *sessionCtxt_p = ueCtxt_p->findSessionContextByLinkedBearerId(
                deleteBearerProc.getBearerId());

        if (sessionCtxt_p != NULL)
        {
            uint8_t index = 0;
            uint8_t successCount = 0;

            memcpy(&(db_resp.s11_sgw_c_fteid),
                    &(sessionCtxt_p->getS11SgwCtrlFteid().fteid_m),
                    sizeof(struct fteid));

            if (db_req->linked_bearer_id == 0)
            {
                auto &bearerStatusContainer =
                        deleteBearerProc.getBearerStatusContainer();
                db_resp.bearer_ctxt_db_resp_list.bearers_count =
                        bearerStatusContainer.size();

                for (auto &it : bearerStatusContainer)
                {
                    db_resp.bearer_ctxt_db_resp_list.bearer_ctxt[index].eps_bearer_id =
                           		it.eps_bearer_id;

                    db_resp.bearer_ctxt_db_resp_list.bearer_ctxt[index].cause.cause =
                            it.cause.cause;

                    if (it.pco_from_ue_opt.pco_length)
                    {
                        memcpy(
                                &db_resp.bearer_ctxt_db_resp_list.bearer_ctxt[index].pco_from_ue_opt.pco_options,
                                &it.pco_from_ue_opt.pco_options,
                                it.pco_from_ue_opt.pco_length);
                    }

                    index++;
                }
            }
            else
            {
                db_resp.linked_bearer_id = deleteBearerProc.getBearerId();
            }
        }
        else
        {
            log_msg(LOG_INFO,
                    "populateDeleteBearerResponse : SessionContext is NULL ");
            gtpCause = GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
        }
    }
    else
    {
        log_msg(LOG_INFO,
                "populateDeleteBearerResponse : UEContext is NULL ");
        gtpCause = GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
    }

    db_resp.s11_sgw_c_fteid.ip.ipv4.s_addr = db_req->sgw_ip;
    db_resp.destination_port = db_req->source_port;
    db_resp.seq_no = db_req->seq_no;

    if (deleteBearerProc.getMmeErrorCause())
    {
        gtpCause = MmeCauseUtils::convertToGtpCause(
                deleteBearerProc.getMmeErrorCause());
        /*
         * Rewriting the cause as GTPV2C_CAUSE_REQUEST_ACCEPTED,
         * since bearers are deleted even in cases of timeout &
         * abort except few cases such as CONTEXT_NOT_FOUND
         */
        if(gtpCause == GTPV2C_CAUSE_NETWORK_FAILURE)
            gtpCause = GTPV2C_CAUSE_REQUEST_ACCEPTED;
    }

    db_resp.cause = gtpCause;

    status = true;

    log_msg(LOG_INFO, "populateDeleteBearerResponse : DB Response Cause: %d ",
            db_resp.cause);

    return status;
}

void MmeGtpMsgUtils::populatePsToCsRequest(SM::ControlBlock& cb,
        UEContext& ueCtxt,
		SrvccProcedureContext& procCtxt,
		struct PS_to_CS_REQ_msg& psToCsReq)
{
        psToCsReq.msg_type = ps_to_cs_request;
    psToCsReq.ue_idx = ueCtxt.getContextID();

    //IMSI
    psToCsReq.imsiIePresent = true;

    const DigitRegister15& ueImsi = ueCtxt.getImsi();
	ueImsi.convertToBcdArray( psToCsReq.IMSI );

    //MSISDN
    psToCsReq.cMsisdnIePresent = true;
    memset(psToCsReq.MSISDN, 0, BINARY_IMSI_LEN);
	
	const DigitRegister15& ueMSISDN = ueCtxt.getMsisdn();
	ueMSISDN.convertToBcdArray(psToCsReq.MSISDN);

    //SRC to Target Trans Container
    memcpy(&(psToCsReq.sourceToTargetTransparentContainer),
        &(procCtxt.getSrcToTargetTransContainer()),
        sizeof(struct src_target_transparent_container));

    // Target RNC Id
    psToCsReq.targetRncIdIePresent = true;
    psToCsReq.targetRncId.RncID = (Uint8)procCtxt.getTargetRncId();

    // sv flags
    psToCsReq.svFlagsIePresent = false;

	// STN-SR
    psToCsReq.stnSrIePresent = true;

    const DigitRegister15& uestnsr = ueCtxt.getStnsr();
	uestnsr.convertToBcdArray( psToCsReq.STNSR );
    
    //mm context
    psToCsReq.mmContextForEutranSrvccIePresent = true;
    E_UTRAN_sec_vector *secVect = const_cast<E_UTRAN_sec_vector*>(ueCtxt.getAiaSecInfo().AiaSecInfo_mp);
    SecUtils::create_integrity_key(ueCtxt.getUeSecInfo().getSelectIntAlg(), 
                                   secVect->kasme.val, (unsigned char*)psToCsReq.mmContextForEutranSrvcc.CKSRVCC);

    SecUtils::create_ciphering_key(ueCtxt.getUeSecInfo().getSelectSecAlg(),
                                    secVect->kasme.val, (unsigned char*)psToCsReq.mmContextForEutranSrvcc.IKSRVCC);

    memcpy(&(psToCsReq.mmContextForEutranSrvcc.mobileStationClassmark2),
                &(ueCtxt.getMsClassmark2()),
                sizeof(Mobile_Station_Classmark_2));
}

void MmeGtpMsgUtils::populateDeleteBearerCommand(SM::ControlBlock& cb,
        UEContext& ueCtxt,
        SessionContext& sessionCtxt,
		SrvccProcedureContext& procCtxt,
		struct DELETE_BEARER_COMMAND_msg& db_command_msg)
{
        db_command_msg.msg_type = delete_bearer_cmd;
        db_command_msg.ue_idx = ueCtxt.getContextID();

    db_command_msg.bearerContext.epsBearerId.epsBearerId = procCtxt.getVoiceBearer().getBearerId();

    db_command_msg.secondaryRatUsageDataReportIePresent = false;
    db_command_msg.senderFTeidForControlPlaneIePresent = false;
    db_command_msg.ueTimeZoneIePresent = false;
    db_command_msg.uliTimestampIePresent = false;
    db_command_msg.userLocationInformationIePresent = false;
    db_command_msg.sgwsOverloadControlInformationIePresent = false;
    db_command_msg.mmeS4SgsnsOverloadControlInformationIePresent = false;
    db_command_msg.bearerContext.bearerFlagsIePresent = false;
    db_command_msg.bearerContext.ranNasReleaseCauseIePresent = false;
}

void MmeGtpMsgUtils::populateForwardRelocationRequest(SM::ControlBlock& cb,
        UEContext& ueCtxt,
        SessionContext& sessionCtxt,
		SrvccProcedureContext& procCtxt,
		struct FORWARD_REL_REQ_msg& fwd_rel_req) {
    fwd_rel_req.msg_type = forward_relocation_request;
    fwd_rel_req.ue_idx = ueCtxt.getContextID();

    fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV4Address.ipValue = sessionCtxt.getS11SgwCtrlFteid().fteid_m.ip.ipv4;
    fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.count = INET6_ADDRSTRLEN;
    memcpy(fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.values,sessionCtxt.getS11SgwCtrlFteid().fteid_m.ip.ipv6.__in6_u.__u6_addr16,
        sizeof(fwd_rel_req.sgwS11S4IpAddressAndTeidForControlPlane.ipV6Address.ipValue.values));
    
    const DigitRegister15& ueImsi = ueCtxt.getImsi();
    ueImsi.convertToBcdArray( fwd_rel_req.IMSI );

    fwd_rel_req.mmeSgsnAmfUeMmContext.securityMode = EPSsecurityContext;
    fwd_rel_req.mmeSgsnAmfUeMmContext.nhiPresent = 1;
    
    E_UTRAN_sec_vector* secVect =
            const_cast<E_UTRAN_sec_vector*>(ueCtxt.getAiaSecInfo().AiaSecInfo_mp);
    secinfo& secInfo = const_cast<secinfo&>(ueCtxt.getUeSecInfo().secinfo_m);

    fwd_rel_req.mmeSgsnAmfUeMmContext.nasDownlinkCount = ueCtxt.getUeSecInfo().getDownlinkCount();
    fwd_rel_req.mmeSgsnAmfUeMmContext.nasUplinkCount = ueCtxt.getUeSecInfo().getUplinkCount();
    fwd_rel_req.mmeSgsnAmfUeMmContext.uambriPresent = true;
    fwd_rel_req.mmeSgsnAmfUeMmContext.usedNasIntegrity = ueCtxt.getUeSecInfo().getSelectSecAlg();
    fwd_rel_req.mmeSgsnAmfUeMmContext.usedNasCipher = ueCtxt.getUeSecInfo().getSelectIntAlg();

    fwd_rel_req.mmeSgsnAmfUeMmContext.kAsme = secInfo.kasme.val;
    fwd_rel_req.mmeSgsnAmfUeMmContext.drxParameter = PAGINX_DRX256;
    
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.authenticationQuadruplet.values, secVect,sizeof(AuthenticationQuadruplet));
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.authenticationQuintuplet.values, secVect,sizeof(AuthenticationQuintuplet));
    
    /// Next hop count and next chaining count need to check
    unsigned char nh[SECURITY_KEY_SIZE] = { 0 };
    secInfo.next_hop_chaining_count = 1;
    SecUtils::create_nh_key(secVect->kasme.val, nh, secInfo.kenb_key);
    memcpy(secInfo.next_hop_nh , nh, KENB_SIZE);
    
    memcpy(fwd_rel_req.mmeSgsnAmfUeMmContext.nh, nh, KENB_SIZE);
    fwd_rel_req.mmeSgsnAmfUeMmContext.ncc = ueCtxt.getUeSecInfo().secinfo_m.next_hop_chaining_count;

    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfUeNetworkCapability = ueCtxt.getUeNetCapab().ue_net_capab_m.len;
    fwd_rel_req.mmeSgsnAmfUeMmContext.ueNetworkCapability = ueCtxt.getUeNetCapab().ue_net_capab_m.u;
    //need clarification in ms network capability
    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfMsNetworkCapability = ueCtxt.getUeNetCapab().ue_net_capab_m.len;
    fwd_rel_req.mmeSgsnAmfUeMmContext.msNetworkCapability = ueCtxt.getMsNetCapab().ms_net_capab_m.len;
    fwd_rel_req.mmeSgsnAmfUeMmContext.voiceDomainPreferenceAndUesUsageSetting = ueCtxt.getVoiceDomainPref().voiceDomainPref_m.voice_dom_pref;
    fwd_rel_req.mmeSgsnAmfUeMmContext.lengthOfVoiceDomainPreferenceAndUesUsageSetting = sizeof(Voice_Domain_Preference);

    memcpy(&(fwd_rel_req.selectedPlmnId), &(ueCtxt.getTai().tai_m.plmn_id), 3);

    memcpy(&(fwd_rel_req.eUtranTransparentContainer),
            &(procCtxt.getSrcToTargetTransContainer()),
            sizeof(struct src_target_transparent_container));

    memcpy(&(fwd_rel_req.utranTransparentContainer),
            &(procCtxt.getSrcToTargetTransContainer()),
            sizeof(struct src_target_transparent_container));

    fwd_rel_req.s1ApCause.fCauseField = procCtxt.getS1HoCause().s1apCause_m.choice.protocol;
    fwd_rel_req.ranapCause.fCauseField = procCtxt.getS1HoCause().s1apCause_m.choice.radioNetwork;
    memcpy(&(fwd_rel_req.servingNetwork), &(ueCtxt.getTai().tai_m.plmn_id), 3);


    memcpy(&(fwd_rel_req.additionalMmContextForSrvcc.msclassmark2),
                &(ueCtxt.getMsClassmark2()),
                sizeof(Mobile_Station_Classmark_2));

	const DigitRegister15& ueMSISDN = ueCtxt.getMsisdn();

    memset(&(fwd_rel_req.msisdn), 0, BINARY_IMSI_LEN);
	ueMSISDN.convertToBcdArray(fwd_rel_req.msisdn);

    memset(&(fwd_rel_req.cMsisdn), 0, BINARY_IMSI_LEN);
	ueMSISDN.convertToBcdArray(fwd_rel_req.cMsisdn);
        
}
