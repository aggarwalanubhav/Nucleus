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
		case msg_type_t::forward_access_context_acknowledge:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_CREATE_SESSION_RESPONSE);
			const struct FWD_ACCESS_CONTEXT_ACK_msg* fwd_acc_context_ack_info= (const struct FWD_ACCESS_CONTEXT_ACK_msg*) (msgBuf->getDataPointer());
			handleForwardAccessContextAcknowledge_v(std::move(eMsg), fwd_acc_context_ack_info->s11_mme_cp_teid);
		}
		break;
		case msg_type_t::forward_relocation_response:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_CREATE_SESSION_RESPONSE);
			const struct forward_rel_response_msg* fwd_rel_resp_info= (const struct forward_rel_response_msg*) (msgBuf->getDataPointer());
			handleForwardRelocationResponse_v(std::move(eMsg), fwd_rel_resp_info->s11_mme_cp_teid);
		}
		break;

		case msg_type_t::relocation_cancel_response:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_DELETE_SESSION_RESPONSE);
			const struct REL_CAN_RES_msg* relcanres_info= (const struct REL_CAN_RES_msg*) (msgBuf->getDataPointer());
			handleRelocationCancelResponse_v(std::move(eMsg), relcanres_info->s11_mme_cp_teid);
		}
		break;
			
		case msg_type_t::identification_request:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_RELEASE_BEARER_RESPONSE);
			const struct IDENTIFICATION_REQ_msg* identreq_info= (const struct IDENTIFICATION_REQ_msg*) (msgBuf->getDataPointer());
			handleIdentificationReq_v(std::move(eMsg), identreq_info->s11_mme_cp_teid);
		}
		break;

		case msg_type_t::context_request:
		{
			mmeStats::Instance()->increment(mmeStatsCounter::MME_MSG_RX_S11_RELEASE_BEARER_RESPONSE);
			const struct CONTEXT_REQ_msg* contextreq_info= (const struct CONTEXT_REQ_msg*) (msgBuf->getDataPointer());
			handleContextReq_v(std::move(eMsg), contextreq_info->s11_mme_cp_teid);
		}
		break;
		
		

		default:
			log_msg(LOG_INFO, "Unhandled Gtp Message %d ", msgData_p->msg_type);
	}

}

void GtpMsgHandler::handleForwardAccessContextAcknowledge_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handleForwardAccessContextAcknowledge_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleForwardAccessContextAcknowledge_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	// Fire CS resp from SGW event, insert cb to procedure queue
	SM::Event evt(CS_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

void GtpMsgHandler::handleForwardRelocationResponse_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handleForwardRelocationResponse_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleForwardRelocationResponse_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	// Fire CS resp from SGW event, insert cb to procedure queue
	SM::Event evt(CS_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}


void GtpMsgHandler::handleRelocationCancelResponse_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handleRelocationCancelResponse_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleRelocationCancelResponse_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	// Fire MB rep from SGW event, insert cb to procedure queue
	SM::Event evt(MB_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

void GtpMsgHandler::handleIdentificationReq_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handleIdentificationReq_v");
	
	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleIdentificationReq_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}

	SM::Event evt(DEL_SESSION_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}

void GtpMsgHandler::handleContextReq_v(IpcEMsgUnqPtr eMsg, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "handleContextReq_v");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleContextReq_v: "
							"Failed to find UE context using idx %d",
							ueIdx);
		return;
	}
	
	// Fire rel bearer response from sgw event, insert cb to procedure queue
	SM::Event evt(REL_AB_RESP_FROM_SGW, cmn::IpcEMsgShPtr(std::move(eMsg)));
	controlBlk_p->addEventToProcQ(evt);
}