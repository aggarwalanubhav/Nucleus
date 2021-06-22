/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/msgtemplate.cpp.tt>
 ******************************************************************************/ 

#include "pstoCsCancelNotificationMsg.h"
#include "../ieClasses/manual/gtpV2Ie.h"
#include "../ieClasses/gtpV2IeFactory.h"
#include "../ieClasses/imsiIe.h"
#include "../ieClasses/srvccCauseIe.h"
#include "../ieClasses/meiIe.h"

PstoCsCancelNotificationMsg::PstoCsCancelNotificationMsg()
{
    msgType = PstoCsCancelNotificationMsgType;
    Uint16 mandIe;
    mandIe = SrvccCauseIeType;
    mandIe = (mandIe << 8) | 0; // cancelCause
    mandatoryIeSet.insert(mandIe);
}

PstoCsCancelNotificationMsg::~PstoCsCancelNotificationMsg()
{

}

bool PstoCsCancelNotificationMsg::encodePstoCsCancelNotificationMsg(MsgBuffer &buffer,
                        PstoCsCancelNotificationMsgData
							const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    if (data.imsiIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = ImsiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        ImsiIe imsi=
        dynamic_cast<
        ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));
        rc = imsi.encodeImsiIe(buffer, data.imsi);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: imsi\n");
            return false;
        }
    }

    
    // Encode the Ie Header
    header.ieType = SrvccCauseIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    SrvccCauseIe cancelCause=
    dynamic_cast<
    SrvccCauseIe&>(GtpV2IeFactory::getInstance().getIeObject(SrvccCauseIeType));
    rc = cancelCause.encodeSrvccCauseIe(buffer, data.cancelCause);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);

    if (!(rc))
    { 
        errorStream.add((char *)"Failed to encode IE: cancelCause\n");
        return false;
    }

    if (data.meIdentityIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = MeiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        MeiIe meIdentity=
        dynamic_cast<
        MeiIe&>(GtpV2IeFactory::getInstance().getIeObject(MeiIeType));
        rc = meIdentity.encodeMeiIe(buffer, data.meIdentity);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: meIdentity\n");
            return false;
        }
    }
    return rc;

}

bool PstoCsCancelNotificationMsg::decodePstoCsCancelNotificationMsg(MsgBuffer &buffer,
 PstoCsCancelNotificationMsgData 
 &data, Uint16 length)
{

    bool rc = false;
    GtpV2IeHeader ieHeader;
  
    set<Uint16> mandatoryIeLocalList = mandatoryIeSet;
    while (buffer.lengthLeft() > IE_HEADER_SIZE)
    {
        GtpV2Ie::decodeGtpV2IeHeader(buffer, ieHeader);
        if (ieHeader.length > buffer.lengthLeft())
        {
            // We do not have enough bytes left in the message for this IE
            errorStream.add((char *)"IE Length exceeds beyond message boundary\n");
            errorStream.add((char *)"  Offending IE Type: ");
            errorStream.add(ieHeader.ieType);
            errorStream.add((char *)"\n  Ie Length in Header: ");
            errorStream.add(ieHeader.length);
            errorStream.add((char *)"\n  Bytes left in message: ");
            errorStream.add(buffer.lengthLeft());
            errorStream.endOfLine();
            return false;
        }

        switch (ieHeader.ieType){
     
            case ImsiIeType:
            {
                ImsiIe ieObject =
                dynamic_cast<
                ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeImsiIe(buffer, data.imsi, ieHeader.length);

                    data.imsiIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: imsi\n");
                        return false;
                    }
                }

                else
                {
                    // Unknown IE instance print error
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
     
            case SrvccCauseIeType:
            {
                SrvccCauseIe ieObject =
                dynamic_cast<
                SrvccCauseIe&>(GtpV2IeFactory::getInstance().getIeObject(SrvccCauseIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeSrvccCauseIe(buffer, data.cancelCause, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: cancelCause\n");
                        return false;
                    }
                }

                else
                {
                    // Unknown IE instance print error
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
     
            case MeiIeType:
            {
                MeiIe ieObject =
                dynamic_cast<
                MeiIe&>(GtpV2IeFactory::getInstance().getIeObject(MeiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeMeiIe(buffer, data.meIdentity, ieHeader.length);

                    data.meIdentityIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: meIdentity\n");
                        return false;
                    }
                }

                else
                {
                    // Unknown IE instance print error
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }

            default:
            {
                // Unknown IE print error
                errorStream.add((char *)"Unknown IE Type: ");
                errorStream.add(ieHeader.ieType);
                errorStream.endOfLine();
                buffer.skipBytes(ieHeader.length);
            }
        }
    }
    return rc; // TODO validations
}

void PstoCsCancelNotificationMsg::
displayPstoCsCancelNotificationMsgData_v(PstoCsCancelNotificationMsgData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"PstoCsCancelNotificationMsg:");
    stream.endOfLine();
    stream.incrIndent();
        
    
    if (data.imsiIePresent)
    {


        stream.add((char *)"IE - imsi:");
        stream.endOfLine();
        ImsiIe imsi=
        dynamic_cast<
        ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));
        imsi.displayImsiIe_v(data.imsi, stream);

    }
    stream.add((char *)"IE - cancelCause:");
    stream.endOfLine();
    SrvccCauseIe cancelCause=
    dynamic_cast<
    SrvccCauseIe&>(GtpV2IeFactory::getInstance().getIeObject(SrvccCauseIeType));
    cancelCause.displaySrvccCauseIe_v(data.cancelCause, stream);

    if (data.meIdentityIePresent)
    {


        stream.add((char *)"IE - meIdentity:");
        stream.endOfLine();
        MeiIe meIdentity=
        dynamic_cast<
        MeiIe&>(GtpV2IeFactory::getInstance().getIeObject(MeiIeType));
        meIdentity.displayMeiIe_v(data.meIdentity, stream);

    }

    stream.decrIndent();
    stream.decrIndent();
}

