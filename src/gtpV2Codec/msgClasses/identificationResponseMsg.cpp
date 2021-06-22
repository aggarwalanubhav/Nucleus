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

#include "identificationResponseMsg.h"
#include "../ieClasses/manual/gtpV2Ie.h"
#include "../ieClasses/gtpV2IeFactory.h"
#include "../ieClasses/causeIe.h"
#include "../ieClasses/imsiIe.h"
#include "../ieClasses/mmContextIe.h"
#include "../ieClasses/traceInformationIe.h"
#include "../ieClasses/integerNumberIe.h"
#include "../ieClasses/monitoringEventInformationIe.h"

IdentificationResponseMsg::IdentificationResponseMsg()
{
    msgType = IdentificationResponseMsgType;
    Uint16 mandIe;
    mandIe = CauseIeType;
    mandIe = (mandIe << 8) | 0; // cause
    mandatoryIeSet.insert(mandIe);
}

IdentificationResponseMsg::~IdentificationResponseMsg()
{

}

bool IdentificationResponseMsg::encodeIdentificationResponseMsg(MsgBuffer &buffer,
                        IdentificationResponseMsgData
							const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    
    // Encode the Ie Header
    header.ieType = CauseIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    CauseIe cause=
    dynamic_cast<
    CauseIe&>(GtpV2IeFactory::getInstance().getIeObject(CauseIeType));
    rc = cause.encodeCauseIe(buffer, data.cause);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);

    if (!(rc))
    { 
        errorStream.add((char *)"Failed to encode IE: cause\n");
        return false;
    }

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

    if (data.mmeSgsnUeMmContextIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = MmContextIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        MmContextIe mmeSgsnUeMmContext=
        dynamic_cast<
        MmContextIe&>(GtpV2IeFactory::getInstance().getIeObject(MmContextIeType));
        rc = mmeSgsnUeMmContext.encodeMmContextIe(buffer, data.mmeSgsnUeMmContext);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: mmeSgsnUeMmContext\n");
            return false;
        }
    }

    if (data.traceInformationIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = TraceInformationIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        TraceInformationIe traceInformation=
        dynamic_cast<
        TraceInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(TraceInformationIeType));
        rc = traceInformation.encodeTraceInformationIe(buffer, data.traceInformation);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: traceInformation\n");
            return false;
        }
    }

    if (data.ueUsageTypeIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = IntegerNumberIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        IntegerNumberIe ueUsageType=
        dynamic_cast<
        IntegerNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(IntegerNumberIeType));
        rc = ueUsageType.encodeIntegerNumberIe(buffer, data.ueUsageType);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: ueUsageType\n");
            return false;
        }
    }

    if (data.monitoringEventInformationIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = MonitoringEventInformationIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        MonitoringEventInformationIe monitoringEventInformation=
        dynamic_cast<
        MonitoringEventInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(MonitoringEventInformationIeType));
        rc = monitoringEventInformation.encodeMonitoringEventInformationIe(buffer, data.monitoringEventInformation);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: monitoringEventInformation\n");
            return false;
        }
    }
    return rc;

}

bool IdentificationResponseMsg::decodeIdentificationResponseMsg(MsgBuffer &buffer,
 IdentificationResponseMsgData 
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
     
            case CauseIeType:
            {
                CauseIe ieObject =
                dynamic_cast<
                CauseIe&>(GtpV2IeFactory::getInstance().getIeObject(CauseIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeCauseIe(buffer, data.cause, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: cause\n");
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
     
            case MmContextIeType:
            {
                MmContextIe ieObject =
                dynamic_cast<
                MmContextIe&>(GtpV2IeFactory::getInstance().getIeObject(MmContextIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeMmContextIe(buffer, data.mmeSgsnUeMmContext, ieHeader.length);

                    data.mmeSgsnUeMmContextIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: mmeSgsnUeMmContext\n");
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
     
            case TraceInformationIeType:
            {
                TraceInformationIe ieObject =
                dynamic_cast<
                TraceInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(TraceInformationIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeTraceInformationIe(buffer, data.traceInformation, ieHeader.length);

                    data.traceInformationIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: traceInformation\n");
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
     
            case IntegerNumberIeType:
            {
                IntegerNumberIe ieObject =
                dynamic_cast<
                IntegerNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(IntegerNumberIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeIntegerNumberIe(buffer, data.ueUsageType, ieHeader.length);

                    data.ueUsageTypeIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: ueUsageType\n");
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
     
            case MonitoringEventInformationIeType:
            {
                MonitoringEventInformationIe ieObject =
                dynamic_cast<
                MonitoringEventInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(MonitoringEventInformationIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeMonitoringEventInformationIe(buffer, data.monitoringEventInformation, ieHeader.length);

                    data.monitoringEventInformationIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: monitoringEventInformation\n");
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

void IdentificationResponseMsg::
displayIdentificationResponseMsgData_v(IdentificationResponseMsgData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"IdentificationResponseMsg:");
    stream.endOfLine();
    stream.incrIndent();
        
    
    stream.add((char *)"IE - cause:");
    stream.endOfLine();
    CauseIe cause=
    dynamic_cast<
    CauseIe&>(GtpV2IeFactory::getInstance().getIeObject(CauseIeType));
    cause.displayCauseIe_v(data.cause, stream);

    if (data.imsiIePresent)
    {


        stream.add((char *)"IE - imsi:");
        stream.endOfLine();
        ImsiIe imsi=
        dynamic_cast<
        ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));
        imsi.displayImsiIe_v(data.imsi, stream);

    }
    if (data.mmeSgsnUeMmContextIePresent)
    {


        stream.add((char *)"IE - mmeSgsnUeMmContext:");
        stream.endOfLine();
        MmContextIe mmeSgsnUeMmContext=
        dynamic_cast<
        MmContextIe&>(GtpV2IeFactory::getInstance().getIeObject(MmContextIeType));
        mmeSgsnUeMmContext.displayMmContextIe_v(data.mmeSgsnUeMmContext, stream);

    }
    if (data.traceInformationIePresent)
    {


        stream.add((char *)"IE - traceInformation:");
        stream.endOfLine();
        TraceInformationIe traceInformation=
        dynamic_cast<
        TraceInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(TraceInformationIeType));
        traceInformation.displayTraceInformationIe_v(data.traceInformation, stream);

    }
    if (data.ueUsageTypeIePresent)
    {


        stream.add((char *)"IE - ueUsageType:");
        stream.endOfLine();
        IntegerNumberIe ueUsageType=
        dynamic_cast<
        IntegerNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(IntegerNumberIeType));
        ueUsageType.displayIntegerNumberIe_v(data.ueUsageType, stream);

    }
    if (data.monitoringEventInformationIePresent)
    {


        stream.add((char *)"IE - monitoringEventInformation:");
        stream.endOfLine();
        MonitoringEventInformationIe monitoringEventInformation=
        dynamic_cast<
        MonitoringEventInformationIe&>(GtpV2IeFactory::getInstance().getIeObject(MonitoringEventInformationIeType));
        monitoringEventInformation.displayMonitoringEventInformationIe_v(data.monitoringEventInformation, stream);

    }

    stream.decrIndent();
    stream.decrIndent();
}

