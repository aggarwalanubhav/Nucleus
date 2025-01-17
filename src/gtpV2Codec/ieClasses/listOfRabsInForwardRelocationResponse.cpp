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
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/grpieinsttemplate.cpp.tt>
 ******************************************************************************/
 
#include "listOfRabsInForwardRelocationResponse.h"
#include "manual/gtpV2Ie.h"
#include "gtpV2IeFactory.h"
#include "ebiIe.h"
#include "packetFlowIdIe.h"
#include "fTeidIe.h"
#include "fTeidIe.h"
#include "fTeidIe.h"
#include "fTeidIe.h"
#include "fTeidIe.h"
#include "fTeidIe.h"

ListOfRabsInForwardRelocationResponse::
ListOfRabsInForwardRelocationResponse()
{

}

ListOfRabsInForwardRelocationResponse::
~ListOfRabsInForwardRelocationResponse()
{

}
bool ListOfRabsInForwardRelocationResponse::
encodeListOfRabsInForwardRelocationResponse(MsgBuffer &buffer,
                         ListOfRabsInForwardRelocationResponseData
                          const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    if (data.epsBearerIdIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = EbiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        EbiIe epsBearerId=
        dynamic_cast<
        EbiIe&>(GtpV2IeFactory::getInstance().getIeObject(EbiIeType));
        rc = epsBearerId.encodeEbiIe(buffer, data.epsBearerId);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: epsBearerId\n");
          return false;
        }
    }
    if (data.packetFlowIdIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = PacketFlowIdIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        PacketFlowIdIe packetFlowId=
        dynamic_cast<
        PacketFlowIdIe&>(GtpV2IeFactory::getInstance().getIeObject(PacketFlowIdIeType));
        rc = packetFlowId.encodePacketFlowIdIe(buffer, data.packetFlowId);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: packetFlowId\n");
          return false;
        }
    }
    if (data.enodebFTeidForDlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe enodebFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = enodebFTeidForDlDataForwarding.encodeFTeidIe(buffer, data.enodebFTeidForDlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: enodebFTeidForDlDataForwarding\n");
          return false;
        }
    }
    if (data.enodebFTeidForUlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 1;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe enodebFTeidForUlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = enodebFTeidForUlDataForwarding.encodeFTeidIe(buffer, data.enodebFTeidForUlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: enodebFTeidForUlDataForwarding\n");
          return false;
        }
    }
    if (data.sgwUpfFTeidForDlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 2;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe sgwUpfFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = sgwUpfFTeidForDlDataForwarding.encodeFTeidIe(buffer, data.sgwUpfFTeidForDlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: sgwUpfFTeidForDlDataForwarding\n");
          return false;
        }
    }
    if (data.rncFTeidForDlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 3;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe rncFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = rncFTeidForDlDataForwarding.encodeFTeidIe(buffer, data.rncFTeidForDlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: rncFTeidForDlDataForwarding\n");
          return false;
        }
    }
    if (data.sgsnFTeidForDlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 4;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe sgsnFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = sgsnFTeidForDlDataForwarding.encodeFTeidIe(buffer, data.sgsnFTeidForDlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: sgsnFTeidForDlDataForwarding\n");
          return false;
        }
    }
    if (data.sgwFTeidForUlDataForwardingIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 5;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe sgwFTeidForUlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = sgwFTeidForUlDataForwarding.encodeFTeidIe(buffer, data.sgwFTeidForUlDataForwarding);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: sgwFTeidForUlDataForwarding\n");
          return false;
        }
    }
    return rc;
}

bool ListOfRabsInForwardRelocationResponse::
decodeListOfRabsInForwardRelocationResponse(MsgBuffer &buffer,
                         ListOfRabsInForwardRelocationResponseData 
                         &data, Uint16 length)
{
    Uint16 groupedIeBoundary = length + buffer.getCurrentIndex();
    bool rc = false;
    GtpV2IeHeader ieHeader;
    set<Uint16> mandatoryIeLocalList = mandatoryIeSet;
    while ((buffer.lengthLeft() > IE_HEADER_SIZE) &&
                   (buffer.getCurrentIndex() < groupedIeBoundary))
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
            case EbiIeType:
            {
                EbiIe ieObject =
                dynamic_cast<
                EbiIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(EbiIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodeEbiIe(buffer, data.epsBearerId, ieHeader.length);

                    data.epsBearerIdIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: epsBearerId\n");
                        return false;
                    }
                }
                else
                {
                    // Unknown IE instance print error TODO
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
            case PacketFlowIdIeType:
            {
                PacketFlowIdIe ieObject =
                dynamic_cast<
                PacketFlowIdIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(PacketFlowIdIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodePacketFlowIdIe(buffer, data.packetFlowId, ieHeader.length);

                    data.packetFlowIdIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: packetFlowId\n");
                        return false;
                    }
                }
                else
                {
                    // Unknown IE instance print error TODO
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
            case FTeidIeType:
            {
                FTeidIe ieObject =
                dynamic_cast<
                FTeidIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(FTeidIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.enodebFTeidForDlDataForwarding, ieHeader.length);

                    data.enodebFTeidForDlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: enodebFTeidForDlDataForwarding\n");
                        return false;
                    }
                }
                else if(ieHeader.instance == 1)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.enodebFTeidForUlDataForwarding, ieHeader.length);

                    data.enodebFTeidForUlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: enodebFTeidForUlDataForwarding\n");
                        return false;
                    }
                }
                else if(ieHeader.instance == 2)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.sgwUpfFTeidForDlDataForwarding, ieHeader.length);

                    data.sgwUpfFTeidForDlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: sgwUpfFTeidForDlDataForwarding\n");
                        return false;
                    }
                }
                else if(ieHeader.instance == 3)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.rncFTeidForDlDataForwarding, ieHeader.length);

                    data.rncFTeidForDlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: rncFTeidForDlDataForwarding\n");
                        return false;
                    }
                }
                else if(ieHeader.instance == 4)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.sgsnFTeidForDlDataForwarding, ieHeader.length);

                    data.sgsnFTeidForDlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: sgsnFTeidForDlDataForwarding\n");
                        return false;
                    }
                }
                else if(ieHeader.instance == 5)
                {

                    rc = ieObject.decodeFTeidIe(buffer, data.sgwFTeidForUlDataForwarding, ieHeader.length);

                    data.sgwFTeidForUlDataForwardingIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: sgwFTeidForUlDataForwarding\n");
                        return false;
                    }
                }
                else
                {
                    // Unknown IE instance print error TODO
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
    if (!mandatoryIeLocalList.empty())
    {
        // some mandatory IEs are missing
        errorStream.add((char *)"Missing Mandatory IEs:");
        errorStream.endOfLine();
        while (!mandatoryIeLocalList.empty())
        {
            Uint16 missingMandIe = *mandatoryIeLocalList.begin ();
            mandatoryIeLocalList.erase (mandatoryIeLocalList.begin ());
            Uint16 missingInstance = missingMandIe & 0x00FF;
            Uint16 missingIeType = (missingMandIe >> 8);
            errorStream.add ((char *)"Missing Ie type: ");
            errorStream.add (missingIeType);
            errorStream.add ((char *)"  Instance: ");
            errorStream.add (missingInstance);
            errorStream.endOfLine();
        }
        rc = false;
    
    }
    return rc; 
}

void ListOfRabsInForwardRelocationResponse::
displayListOfRabsInForwardRelocationResponseData_v
(ListOfRabsInForwardRelocationResponseData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"ListOfRabsInForwardRelocationResponse:");
    stream.endOfLine();
    stream.incrIndent();

    if (data.epsBearerIdIePresent)
    {
        stream.add((char *)"epsBearerId:");
        stream.endOfLine();
        EbiIe epsBearerId=
        dynamic_cast<
        EbiIe&>(GtpV2IeFactory::getInstance().getIeObject(EbiIeType));
        epsBearerId.displayEbiIe_v(data.epsBearerId, stream);

	}
     if (data.packetFlowIdIePresent)
    {
        stream.add((char *)"packetFlowId:");
        stream.endOfLine();
        PacketFlowIdIe packetFlowId=
        dynamic_cast<
        PacketFlowIdIe&>(GtpV2IeFactory::getInstance().getIeObject(PacketFlowIdIeType));
        packetFlowId.displayPacketFlowIdIe_v(data.packetFlowId, stream);

	}
     if (data.enodebFTeidForDlDataForwardingIePresent)
    {
        stream.add((char *)"enodebFTeidForDlDataForwarding:");
        stream.endOfLine();
        FTeidIe enodebFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        enodebFTeidForDlDataForwarding.displayFTeidIe_v(data.enodebFTeidForDlDataForwarding, stream);

	}
     if (data.enodebFTeidForUlDataForwardingIePresent)
    {
        stream.add((char *)"enodebFTeidForUlDataForwarding:");
        stream.endOfLine();
        FTeidIe enodebFTeidForUlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        enodebFTeidForUlDataForwarding.displayFTeidIe_v(data.enodebFTeidForUlDataForwarding, stream);

	}
     if (data.sgwUpfFTeidForDlDataForwardingIePresent)
    {
        stream.add((char *)"sgwUpfFTeidForDlDataForwarding:");
        stream.endOfLine();
        FTeidIe sgwUpfFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        sgwUpfFTeidForDlDataForwarding.displayFTeidIe_v(data.sgwUpfFTeidForDlDataForwarding, stream);

	}
     if (data.rncFTeidForDlDataForwardingIePresent)
    {
        stream.add((char *)"rncFTeidForDlDataForwarding:");
        stream.endOfLine();
        FTeidIe rncFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rncFTeidForDlDataForwarding.displayFTeidIe_v(data.rncFTeidForDlDataForwarding, stream);

	}
     if (data.sgsnFTeidForDlDataForwardingIePresent)
    {
        stream.add((char *)"sgsnFTeidForDlDataForwarding:");
        stream.endOfLine();
        FTeidIe sgsnFTeidForDlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        sgsnFTeidForDlDataForwarding.displayFTeidIe_v(data.sgsnFTeidForDlDataForwarding, stream);

	}
     if (data.sgwFTeidForUlDataForwardingIePresent)
    {
        stream.add((char *)"sgwFTeidForUlDataForwarding:");
        stream.endOfLine();
        FTeidIe sgwFTeidForUlDataForwarding=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        sgwFTeidForUlDataForwarding.displayFTeidIe_v(data.sgwFTeidForUlDataForwarding, stream);

	}
 
    stream.decrIndent();
    stream.decrIndent();
}



