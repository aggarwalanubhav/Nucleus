/*
 * Copyright 2019-present Infosys Limited  
 *   
 * SPDX-License-Identifier: Apache-2.0    
 */

#ifndef INCLUDE_MME_APP_MSGHANDLERS_S3MSGHANDLER_H_
#define INCLUDE_MME_APP_MSGHANDLERS_S3MSGHANDLER_H_

#include <stdint.h>
#include <eventMessage.h>

class S3MsgHandler {
public:
	static S3MsgHandler* Instance();
	virtual ~S3MsgHandler();

	void handleS3Message_v(cmn::IpcEMsgUnqPtr eMsg);

private:
	S3MsgHandler();

	void handleForwardAccessContextAcknowledge_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handleForwardRelocationResponse_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handleRelocationCancelResponse_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handleIdentificationReq_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handleContextReq_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);
	void handleForwardRelocationCompleteNoti_v(cmn::IpcEMsgUnqPtr eMsg, uint32_t ueIdx);

};

#endif /* INCLUDE_MME_APP_MSGHANDLERS_S3MSGHANDLER_H_ */
