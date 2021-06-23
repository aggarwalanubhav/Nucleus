/*
 * Copyright 2019-present, Infosys Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ 
/******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/stacktemplate.h.tt>
 ******************************************************************************/
#ifndef GTPV2STACK_H_
#define GTPV2STACK_H_

#include <sstream>
#include <basicTypes.h>
#include <msgBuffer.h>
#include "msgClasses/gtpV2MsgDataTypes.h"

class GtpV2Stack {
public:
    GtpV2Stack();
    virtual ~GtpV2Stack();

    // Public datastructures that hold decoded data or data to be encoded
    CreateSessionRequestMsgData createSessionRequestStackData;
    CreateSessionResponseMsgData createSessionResponseStackData;
    ModifyBearerRequestMsgData modifyBearerRequestStackData;
    ModifyBearerResponseMsgData modifyBearerResponseStackData;
    DeleteSessionRequestMsgData deleteSessionRequestStackData;
    DeleteSessionResponseMsgData deleteSessionResponseStackData;
    ReleaseAccessBearersRequestMsgData releaseAccessBearersRequestStackData;
    ReleaseAccessBearersResponseMsgData releaseAccessBearersResponseStackData;
    CreateBearerRequestMsgData createBearerRequestStackData;
    CreateBearerResponseMsgData createBearerResponseStackData;
    DeleteBearerRequestMsgData deleteBearerRequestStackData;
    DeleteBearerResponseMsgData deleteBearerResponseStackData;
    DownlinkDataNotificationMsgData downlinkDataNotificationStackData;
    DownlinkDataNotificationAcknowledgeMsgData downlinkDataNotificationAcknowledgeStackData;
    DownlinkDataNotificationFailureIndicationMsgData downlinkDataNotificationFailureIndicationStackData;
    EchoRequestMsgData echoRequestStackData;
    EchoResponseMsgData echoResponseStackData;
    ForwardRelocationCompleteNotificationMsgData forwardRelocationCompleteNotificationStackData;
    ForwardRelocationCompleteAcknowledgeMsgData forwardRelocationCompleteAcknowledgeStackData;
    ForwardAccessContextNotificationMsgData forwardAccessContextNotificationStackData;
    ForwardAccessContextAcknowledgeMsgData forwardAccessContextAcknowledgeStackData;
    RelocationCancelRequestMsgData relocationCancelRequestStackData;
    RelocationCancelResponseMsgData relocationCancelResponseStackData;
    ConfigurationTransferTunnelMsgData configurationTransferTunnelStackData;
    IdentificationRequestMsgData identificationRequestStackData;
    IdentificationResponseMsgData identificationResponseStackData;
    SrvccPsToCsCompleteNotificationMsgData srvccPsToCsCompleteNotificationStackData;
    PstoCsCompleteAcknowledgeMsgData pstoCsCompleteAcknowledgeStackData;
    SrvccPsToCsRequestMsgData srvccPsToCsRequestStackData;
    SrvccPsToCsResponseMsgData srvccPsToCsResponseStackData;
    PstoCsCancelNotificationMsgData pstoCsCancelNotificationStackData;
    DetachNotificationMsgData detachNotificationStackData;
    ContextRequestMsgData contextRequestStackData;
    ContextResponseMsgData contextResponseStackData;
    ForwardRelocationResponseMsgData forwardRelocationResponseStackData;
    ForwardRelocationRequestMsgData forwardRelocationRequestStackData;
    SrvccPsToCsCancelAcknowledgeMsgData srvccPsToCsCancelAcknowledgeStackData;
    DeleteBearerCommandMsgData deleteBearerCommandStackData;

    bool encodeMessage(GtpV2MessageHeader& msgHeader, MsgBuffer& buffer,
                 void* data_p = NULL);
	bool decodeGtpMessageHeader(GtpV2MessageHeader& msgHeader, MsgBuffer& buffer);
    bool decodeMessage(GtpV2MessageHeader& msgHeader, MsgBuffer& buffer,
                 void* data_p = NULL);
    void display_v(Uint8 msgType, Debug& stream, void* data_p = NULL);
};

#endif /* GTPV2STACK_H_ */
