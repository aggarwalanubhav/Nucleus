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

#include "identificationRequestMsg.h"
#include "../ieClasses/manual/gtpV2Ie.h"
#include "../ieClasses/gtpV2IeFactory.h"
#include "../ieClasses/gutiIe.h"
#include "../ieClasses/completeRequestMessageIe.h"
#include "../ieClasses/pTmsiIe.h"
#include "../ieClasses/pTmsiSignatureIe.h"
#include "../ieClasses/ipAddressIe.h"
#include "../ieClasses/portNumberIe.h"
#include "../ieClasses/hopCounterIe.h"
#include "../ieClasses/servingNetworkIe.h"

IdentificationRequestMsg::IdentificationRequestMsg()
{
    msgType = IdentificationRequestMsgType;

}

IdentificationRequestMsg::~IdentificationRequestMsg()
{

}

bool IdentificationRequestMsg::encodeIdentificationRequestMsg(MsgBuffer &buffer,
                        IdentificationRequestMsgData
							const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    if (data.gutiIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = GutiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        GutiIe guti=
        dynamic_cast<
        GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));
        rc = guti.encodeGutiIe(buffer, data.guti);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: guti\n");
            return false;
        }
    }

    if (data.completeAttachRequestMessageIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = CompleteRequestMessageIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        CompleteRequestMessageIe completeAttachRequestMessage=
        dynamic_cast<
        CompleteRequestMessageIe&>(GtpV2IeFactory::getInstance().getIeObject(CompleteRequestMessageIeType));
        rc = completeAttachRequestMessage.encodeCompleteRequestMessageIe(buffer, data.completeAttachRequestMessage);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: completeAttachRequestMessage\n");
            return false;
        }
    }

    if (data.pTmsiIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = PTmsiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        PTmsiIe pTmsi=
        dynamic_cast<
        PTmsiIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiIeType));
        rc = pTmsi.encodePTmsiIe(buffer, data.pTmsi);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: pTmsi\n");
            return false;
        }
    }

    if (data.pTmsiSignatureIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = PTmsiSignatureIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        PTmsiSignatureIe pTmsiSignature=
        dynamic_cast<
        PTmsiSignatureIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiSignatureIeType));
        rc = pTmsiSignature.encodePTmsiSignatureIe(buffer, data.pTmsiSignature);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: pTmsiSignature\n");
            return false;
        }
    }

    if (data.addressForControlPlaneIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = IpAddressIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        IpAddressIe addressForControlPlane=
        dynamic_cast<
        IpAddressIe&>(GtpV2IeFactory::getInstance().getIeObject(IpAddressIeType));
        rc = addressForControlPlane.encodeIpAddressIe(buffer, data.addressForControlPlane);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: addressForControlPlane\n");
            return false;
        }
    }

    if (data.udpSourcePortNumberIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = PortNumberIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        PortNumberIe udpSourcePortNumber=
        dynamic_cast<
        PortNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(PortNumberIeType));
        rc = udpSourcePortNumber.encodePortNumberIe(buffer, data.udpSourcePortNumber);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: udpSourcePortNumber\n");
            return false;
        }
    }

    if (data.hopCounterIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = HopCounterIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        HopCounterIe hopCounter=
        dynamic_cast<
        HopCounterIe&>(GtpV2IeFactory::getInstance().getIeObject(HopCounterIeType));
        rc = hopCounter.encodeHopCounterIe(buffer, data.hopCounter);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: hopCounter\n");
            return false;
        }
    }

    if (data.targetPlmnIdIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = ServingNetworkIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        ServingNetworkIe targetPlmnId=
        dynamic_cast<
        ServingNetworkIe&>(GtpV2IeFactory::getInstance().getIeObject(ServingNetworkIeType));
        rc = targetPlmnId.encodeServingNetworkIe(buffer, data.targetPlmnId);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: targetPlmnId\n");
            return false;
        }
    }
    return rc;

}

bool IdentificationRequestMsg::decodeIdentificationRequestMsg(MsgBuffer &buffer,
 IdentificationRequestMsgData 
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
     
            case GutiIeType:
            {
                GutiIe ieObject =
                dynamic_cast<
                GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeGutiIe(buffer, data.guti, ieHeader.length);

                    data.gutiIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: guti\n");
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
     
            case CompleteRequestMessageIeType:
            {
                CompleteRequestMessageIe ieObject =
                dynamic_cast<
                CompleteRequestMessageIe&>(GtpV2IeFactory::getInstance().getIeObject(CompleteRequestMessageIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeCompleteRequestMessageIe(buffer, data.completeAttachRequestMessage, ieHeader.length);

                    data.completeAttachRequestMessageIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: completeAttachRequestMessage\n");
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
     
            case PTmsiIeType:
            {
                PTmsiIe ieObject =
                dynamic_cast<
                PTmsiIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodePTmsiIe(buffer, data.pTmsi, ieHeader.length);

                    data.pTmsiIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: pTmsi\n");
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
     
            case PTmsiSignatureIeType:
            {
                PTmsiSignatureIe ieObject =
                dynamic_cast<
                PTmsiSignatureIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiSignatureIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodePTmsiSignatureIe(buffer, data.pTmsiSignature, ieHeader.length);

                    data.pTmsiSignatureIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: pTmsiSignature\n");
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
     
            case IpAddressIeType:
            {
                IpAddressIe ieObject =
                dynamic_cast<
                IpAddressIe&>(GtpV2IeFactory::getInstance().getIeObject(IpAddressIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeIpAddressIe(buffer, data.addressForControlPlane, ieHeader.length);

                    data.addressForControlPlaneIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: addressForControlPlane\n");
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
     
            case PortNumberIeType:
            {
                PortNumberIe ieObject =
                dynamic_cast<
                PortNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(PortNumberIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodePortNumberIe(buffer, data.udpSourcePortNumber, ieHeader.length);

                    data.udpSourcePortNumberIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: udpSourcePortNumber\n");
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
     
            case HopCounterIeType:
            {
                HopCounterIe ieObject =
                dynamic_cast<
                HopCounterIe&>(GtpV2IeFactory::getInstance().getIeObject(HopCounterIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeHopCounterIe(buffer, data.hopCounter, ieHeader.length);

                    data.hopCounterIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: hopCounter\n");
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
     
            case ServingNetworkIeType:
            {
                ServingNetworkIe ieObject =
                dynamic_cast<
                ServingNetworkIe&>(GtpV2IeFactory::getInstance().getIeObject(ServingNetworkIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeServingNetworkIe(buffer, data.targetPlmnId, ieHeader.length);

                    data.targetPlmnIdIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: targetPlmnId\n");
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

void IdentificationRequestMsg::
displayIdentificationRequestMsgData_v(IdentificationRequestMsgData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"IdentificationRequestMsg:");
    stream.endOfLine();
    stream.incrIndent();
        
    
    if (data.gutiIePresent)
    {


        stream.add((char *)"IE - guti:");
        stream.endOfLine();
        GutiIe guti=
        dynamic_cast<
        GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));
        guti.displayGutiIe_v(data.guti, stream);

    }
    if (data.completeAttachRequestMessageIePresent)
    {


        stream.add((char *)"IE - completeAttachRequestMessage:");
        stream.endOfLine();
        CompleteRequestMessageIe completeAttachRequestMessage=
        dynamic_cast<
        CompleteRequestMessageIe&>(GtpV2IeFactory::getInstance().getIeObject(CompleteRequestMessageIeType));
        completeAttachRequestMessage.displayCompleteRequestMessageIe_v(data.completeAttachRequestMessage, stream);

    }
    if (data.pTmsiIePresent)
    {


        stream.add((char *)"IE - pTmsi:");
        stream.endOfLine();
        PTmsiIe pTmsi=
        dynamic_cast<
        PTmsiIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiIeType));
        pTmsi.displayPTmsiIe_v(data.pTmsi, stream);

    }
    if (data.pTmsiSignatureIePresent)
    {


        stream.add((char *)"IE - pTmsiSignature:");
        stream.endOfLine();
        PTmsiSignatureIe pTmsiSignature=
        dynamic_cast<
        PTmsiSignatureIe&>(GtpV2IeFactory::getInstance().getIeObject(PTmsiSignatureIeType));
        pTmsiSignature.displayPTmsiSignatureIe_v(data.pTmsiSignature, stream);

    }
    if (data.addressForControlPlaneIePresent)
    {


        stream.add((char *)"IE - addressForControlPlane:");
        stream.endOfLine();
        IpAddressIe addressForControlPlane=
        dynamic_cast<
        IpAddressIe&>(GtpV2IeFactory::getInstance().getIeObject(IpAddressIeType));
        addressForControlPlane.displayIpAddressIe_v(data.addressForControlPlane, stream);

    }
    if (data.udpSourcePortNumberIePresent)
    {


        stream.add((char *)"IE - udpSourcePortNumber:");
        stream.endOfLine();
        PortNumberIe udpSourcePortNumber=
        dynamic_cast<
        PortNumberIe&>(GtpV2IeFactory::getInstance().getIeObject(PortNumberIeType));
        udpSourcePortNumber.displayPortNumberIe_v(data.udpSourcePortNumber, stream);

    }
    if (data.hopCounterIePresent)
    {


        stream.add((char *)"IE - hopCounter:");
        stream.endOfLine();
        HopCounterIe hopCounter=
        dynamic_cast<
        HopCounterIe&>(GtpV2IeFactory::getInstance().getIeObject(HopCounterIeType));
        hopCounter.displayHopCounterIe_v(data.hopCounter, stream);

    }
    if (data.targetPlmnIdIePresent)
    {


        stream.add((char *)"IE - targetPlmnId:");
        stream.endOfLine();
        ServingNetworkIe targetPlmnId=
        dynamic_cast<
        ServingNetworkIe&>(GtpV2IeFactory::getInstance().getIeObject(ServingNetworkIeType));
        targetPlmnId.displayServingNetworkIe_v(data.targetPlmnId, stream);

    }

    stream.decrIndent();
    stream.decrIndent();
}

