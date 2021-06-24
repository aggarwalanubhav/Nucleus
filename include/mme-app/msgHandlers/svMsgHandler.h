/*
 * Copyright 2019-present Infosys Limited  
 *   
 * SPDX-License-Identifier: Apache-2.0    
 */

#ifndef INCLUDE_MME_APP_MSGHANDLERS_SVMSGHANDLER_H_
#define INCLUDE_MME_APP_MSGHANDLERS_SVMSGHANDLER_H_

#include <stdint.h>
#include <eventMessage.h>

class SvMsgHandler {
public:
	static SvMsgHandler* Instance();
	virtual ~SvMsgHandler();

	void handleSvMessage_v(cmn::IpcEMsgUnqPtr eMsg);

private:
	SvMsgHandler();

	void handlePstoCsResponse_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handlePstoCsCancelAcknowlege_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handlePstoCsCompleteNotification_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);

};

#endif /* INCLUDE_MME_APP_MSGHANDLERS_SVMSGHANDLER_H_ */
