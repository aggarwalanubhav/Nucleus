/*
 * Copyright (c) 2019, Infosys Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <msgHandlers/gtpMsgHandler.h>

#include <contextManager/subsDataGroupManager.h>
#include <event.h>
#include <eventMessage.h>
#include <ipcTypes.h>
#include <log.h>
#include <mmeSmDefs.h>
#include <utils/mmeCommonUtils.h>
#include "mmeStatsPromClient.h"

using namespace SM;
using namespace mme;
using namespace cmn;

GtpMsgHandler::~GtpMsgHandler() {

}

GtpMsgHandler::GtpMsgHandler()
{

}

GtpMsgHandler* GtpMsgHandler::Instance()
{
	static GtpMsgHandler msgHandler;
	return &msgHandler;
}

void GtpMsgHandler::handleGtpMessage_v(IpcEMsgUnqPtr eMsg)
{
    if (eMsg.get() == NULL)
        return;

    utils::MsgBuffer *msgBuf = eMsg->getMsgBuffer();
    if (msgBuf == NULL)
    {
        log_msg(LOG_INFO, "GTP Message Buffer is empty ");
        return;
    }
    if (msgBuf->getLength() < sizeof(gtp_incoming_msg_data_t))
    {
        log_msg(LOG_INFO, "Not enough bytes in gtp message ");
        return;
    }

    const gtp_incoming_msg_data_t *msgData_p =
            (gtp_incoming_msg_data_t*) (msgBuf->getDataPointer());

	switch (msgData_p->msg_type)
	{
		case msg_type_t::ps_to_cs_response:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_CREATE_SESSION_RESPONSE);
			const struct ps_to_cs_res_Q_msg* pstocsres_info= (const struct ps_to_cs_res_Q_msg*) (msgBuf->getDataPointer());
			handlePstoCsResponse_v(std::move(eMsg), pstocsres_info->s11_mme_cp_teid);
		}
		break;

		case msg_type_t::ps_to_cs_cancel_acknowledge:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_MODIFY_BEARER_RESPONSE);
			const struct ps_to_cs_cancel_ack_Q_msg* pstocscanack_info= (const struct ps_to_cs_cancel_ack_Q_msg*) (msgBuf->getDataPointer());
			handlePstoCsCancelAcknowlege_v(std::move(eMsg), pstocscanack_info->s11_mme_cp_teid);
		}
		break;

		case msg_type_t::ps_to_cs_complete_notification:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_DELETE_SESSION_RESPONSE);
			const struct ps_to_cs_comp_noti_Q_msg* pstocscmpnot_info= (const struct ps_to_cs_comp_noti_Q_msg*) (msgBuf->getDataPointer());
			handlePstoCsCompleteNotification_v(std::move(eMsg), pstocscmpnot_info->s11_mme_cp_teid);
		}
		break;

		default:
			log_msg(LOG_INFO, "Unhandled Gtp Message %d ", msgData_p->msg_type);
	}

}

void GtpMsgHandler::handlePstoCsResponse_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handlePstoCsResponse_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handlePstoCsResponse_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	// Fire CS resp from SGW event, insert cb to procedure queue
	SM::Event evt(CS_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

void GtpMsgHandler::handlePstoCsCancelAcknowlege_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handlePstoCsCancelAcknowlege_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handlePstoCsCancelAcknowlege_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	// Fire MB rep from SGW event, insert cb to procedure queue
	SM::Event evt(MB_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

void GtpMsgHandler::handlePstoCsCompleteNotification_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handlePstoCsCompleteNotification_v");
	
	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handlePstoCsCompleteNotification_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	SM::Event evt(DEL_SESSION_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

