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
    return ActStatus::PROCEED;
}
