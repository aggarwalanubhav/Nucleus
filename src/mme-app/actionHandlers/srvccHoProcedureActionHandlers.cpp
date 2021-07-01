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
