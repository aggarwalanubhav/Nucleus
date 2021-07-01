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
#include "contextManager/dataBlocks.h"
#include "controlBlock.h" 
#include <structs.h>
#include "secUtils.h"
#include "contextManager/srvccProcedureContextManager.h"
#include <utils/mmeContextManagerUtils.h>
#include "mmeStatsPromClient.h"
#include <ipcTypes.h>
#include <tipcTypes.h>
#include <interfaces/mmeIpcInterface.h>
#include "mmeStatsPromClient.h"

using namespace cmn;
using namespace cmn::utils;
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
    log_msg(LOG_DEBUG, "Inside send_ps_to_cs_req_to_msc");

    UEContext *ueCtxt = static_cast<UEContext*>(cb.getPermDataBlock());

    if (ueCtxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_ps_to_cs_req_to_msc: ue context is NULL");
        return ActStatus::HALT;
    }

    S1HandoverProcedureContext *hoProcCtxt =
            dynamic_cast<S1HandoverProcedureContext*>(cb.getTempDataBlock());
    if (hoProcCtxt == NULL)
    {
        log_msg(LOG_DEBUG,
                "send_ps_to_cs_req_to_msc: MmeS1HandoverProcedureCtxt is NULL");
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
    
    psToCsReq.msg_type = ps_to_cs_request;
    psToCsReq.ue_idx = ueCtxt->getContextID();

    //IMSI
    psToCsReq.imsiIePresent = true;

    const DigitRegister15& ueImsi = ueCtxt->getImsi();
	ueImsi.convertToBcdArray( psToCsReq.IMSI );

    //MSISDN
    psToCsReq.cMsisdnIePresent = true;
    memset(psToCsReq.MSISDN, 0, BINARY_IMSI_LEN);
	
	const DigitRegister15& ueMSISDN = ueCtxt->getMsisdn();
	ueMSISDN.convertToBcdArray(psToCsReq.MSISDN);

    //SRC to Target Trans Container
    memcpy(&(psToCsReq.sourceToTargetTransparentContainer),
        &(hoProcCtxt->getSrcToTargetTransContainer()),
        sizeof(struct src_target_transparent_container));

    // Target RNC Id
    psToCsReq.targetRncIdIePresent = true;
    psToCsReq.targetRncId.RncID = (Uint8)srvccProc_p->getTargetRncId();

    // sv flags
    psToCsReq.svFlagsIePresent = false;

	// STN-SR
    psToCsReq.stnSrIePresent = true;

    const DigitRegister15& uestnsr = ueCtxt->getStnsr();
	uestnsr.convertToBcdArray( psToCsReq.STNSR );
    
    //mm context
    psToCsReq.mmContextForEutranSrvccIePresent = true;
    E_UTRAN_sec_vector *secVect = const_cast<E_UTRAN_sec_vector*>(ueCtxt->getAiaSecInfo().AiaSecInfo_mp);
    SecUtils::create_integrity_key(ueCtxt->getUeSecInfo().getSelectIntAlg(), 
                                   secVect->kasme.val, (unsigned char*)psToCsReq.mmContextForEutranSrvcc.CKSRVCC);

    SecUtils::create_ciphering_key(ueCtxt->getUeSecInfo().getSelectSecAlg(),
                                    secVect->kasme.val, (unsigned char*)psToCsReq.mmContextForEutranSrvcc.IKSRVCC);

    memcpy(&(psToCsReq.mmContextForEutranSrvcc.mobileStationClassmark2),
                &(ueCtxt->getMsClassmark2()),
                sizeof(Mobile_Station_Classmark_2));

    mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_TX_SV_PS_TO_CS_REQUEST);
    cmn::ipc::IpcAddress destAddr = {TipcServiceInstance::svAppInstanceNum_c};
    MmeIpcInterface &mmeIpcIf = static_cast<MmeIpcInterface&>(compDb.getComponent(MmeIpcInterfaceCompId));
    mmeIpcIf.dispatchIpcMsg((char *) &psToCsReq, sizeof(psToCsReq), destAddr);
    log_msg(LOG_DEBUG, "Leaving send_ps_to_cs_req_to_msc ");
    //ProcedureStats::num_of_fwd_relocation_req_sent++;

    return ActStatus::PROCEED;
}

/***************************************
* Action handler : send_fwd_rel_req_to_sgsn
***************************************/
ActStatus ActionHandlers::send_fwd_rel_req_to_sgsn(ControlBlock& cb)
{
    return ActStatus::PROCEED;
}

/***************************************
* Action handler : handle_fwd_rel_res_from_sgsn
***************************************/
ActStatus ActionHandlers::handle_fwd_rel_res_from_sgsn(ControlBlock& cb)
{
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
    //ProcedureStats::num_of_fwd_relocation_resp_received++;

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
