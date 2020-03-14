/*
 * Copyright (c) 2019, Infosys Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <msgHandlers/s6MsgHandler.h>

#include <contextManager/subsDataGroupManager.h>
#include <event.h>
#include <ipcTypes.h>
#include <log.h>

using namespace SM;
using namespace mme;


S6MsgHandler::~S6MsgHandler() {

}
S6MsgHandler::S6MsgHandler() {

}

S6MsgHandler* S6MsgHandler::Instance()
{
	static S6MsgHandler msgHandler;
	return &msgHandler;
}

void S6MsgHandler::handleS6Message_v(cmn::utils::MsgBuffer* msgBuf)
{
	if (msgBuf == NULL)
		return;

	const s6_incoming_msg_data_t* msgData_p = (s6_incoming_msg_data_t*)(msgBuf->getDataPointer());
	switch (msgData_p->msg_type)
	{
		case msg_type_t::auth_info_answer:
			handleAuthInfoAnswer_v(msgBuf, msgData_p->ue_idx);
			break;

		case msg_type_t::update_loc_answer:
			handleUpdateLocationAnswer_v(msgBuf,  msgData_p->ue_idx);
			break;

		case msg_type_t::purge_answser:
			handlePurgeAnswer_v(msgBuf,  msgData_p->ue_idx);
			break;
		
		case msg_type_t::cancel_location_request:
			handleCancelLocationRequest_v(msgBuf);
			break;

		default:
			log_msg(LOG_INFO, "Unhandled S6 Message %d \n", msgData_p->msg_type);
	}

}

void S6MsgHandler::handleAuthInfoAnswer_v(cmn::utils::MsgBuffer* msgData_p, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "Inside handleAuthInfoAnswer_v \n");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleAuthInfoAnswer_v: "
							"Failed to find UE context using idx %d\n",
							ueIdx);
		return;
	}

	// Fire Auth Info Answer event, insert cb to procedure queue
	SM::Event evt(Event_e::AIA_FROM_HSS, (void *)msgData_p);
	controlBlk_p->addEventToProcQ(evt);
}

void S6MsgHandler::handleUpdateLocationAnswer_v(cmn::utils::MsgBuffer* msgData_p, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "Inside handleUpdateLocationAnswer_v \n");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleUpdateLocationAnswer_v: "
							"Failed to find UE context using idx %d\n",
							ueIdx);
		return;
	}
	// Fire Update Loc Answer event, insert cb to procedure queue
	SM::Event evt(Event_e::ULA_FROM_HSS, (void *)msgData_p);
	controlBlk_p->addEventToProcQ(evt);
}

void S6MsgHandler::handlePurgeAnswer_v(cmn::utils::MsgBuffer* msgData_p, uint32_t ueIdx)
{
	log_msg(LOG_INFO, "Inside handlePurgeAnswer_v \n");

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ueIdx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handlePurgeAnswer_v: "
							"Failed to find UE context using idx %d\n",
							ueIdx);
		return;
	}
	// Fire attach-start event, insert cb to procedure queue
	//SM::Event evt(Event_e::DETACH_PUR_RESP_FROM_HSS);
	//controlBlk_p->addEventToProcQ(evt);
	//
}

void S6MsgHandler::handleCancelLocationRequest_v(cmn::utils::MsgBuffer* msgData_p)
{
	log_msg(LOG_INFO, "Inside handleCancelLocationRequest \n");
        
	const char *buf = static_cast<const char*>(msgData_p->getDataPointer());
	const s6_incoming_msg_data_t* msgInfo_p = (s6_incoming_msg_data_t*)(buf);

	DigitRegister15 IMSI;
	IMSI.setImsiDigits(const_cast<uint8_t*> (msgInfo_p->msg_data.clr_Q_msg_m.imsi));
      
	int ue_idx =  SubsDataGroupManager::Instance()->findCBWithimsi(IMSI);
	log_msg(LOG_INFO, "UE_IDX found from map : %d \n", ue_idx);

	if (ue_idx < 1)
	{
		log_msg(LOG_ERROR, "Failed to find ue index using IMSI : %d\n", ue_idx);
		return;
	}

	SM::ControlBlock* controlBlk_p = SubsDataGroupManager::Instance()->findControlBlock(ue_idx);
	if(controlBlk_p == NULL)
	{
		log_msg(LOG_ERROR, "handleCancelLocationRequest_v: "
				   "Failed to find UE Context using IMSI in CLR\n");
		return;
	}
	//Fire CLR event, insert CB to Procedure Queue
	SM::Event evt(Event_e::CLR_FROM_HSS, (void *)msgData_p);
	controlBlk_p->addEventToProcQ(evt);
}
