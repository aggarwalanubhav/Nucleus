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
 
#include "bearerContextsToBeRemovedInCreateSessionRequest.h"
#include "manual/gtpV2Ie.h"
#include "gtpV2IeFactory.h"
#include "ebiIe.h"
#include "fTeidIe.h"

BearerContextsToBeRemovedInCreateSessionRequest::
BearerContextsToBeRemovedInCreateSessionRequest()
{
    Uint16 mandIe;
    mandIe = EbiIeType;
    mandIe = (mandIe << 8) | 0; // epsBearerId
    mandatoryIeSet.insert(mandIe);

}

BearerContextsToBeRemovedInCreateSessionRequest::
~BearerContextsToBeRemovedInCreateSessionRequest()
{

}
bool BearerContextsToBeRemovedInCreateSessionRequest::
encodeBearerContextsToBeRemovedInCreateSessionRequest(MsgBuffer &buffer,
                         BearerContextsToBeRemovedInCreateSessionRequestData
                          const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;


    
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
    if (data.s4USgsnFTeidIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe s4USgsnFTeid=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = s4USgsnFTeid.encodeFTeidIe(buffer, data.s4USgsnFTeid);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        {
          errorStream.add((char *)"Failed to encode IE: s4USgsnFTeid\n");
          return false;
        }
    }
    return rc;
}

bool BearerContextsToBeRemovedInCreateSessionRequest::
decodeBearerContextsToBeRemovedInCreateSessionRequest(MsgBuffer &buffer,
                         BearerContextsToBeRemovedInCreateSessionRequestData 
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

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: epsBearerId\n");
                        return false;
                    }
                    Uint16 mandIe = EbiIeType;
                    mandIe = (mandIe << 8) | 0;
                    mandatoryIeLocalList.erase(mandIe);
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

                    rc = ieObject.decodeFTeidIe(buffer, data.s4USgsnFTeid, ieHeader.length);

                    data.s4USgsnFTeidIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: s4USgsnFTeid\n");
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

void BearerContextsToBeRemovedInCreateSessionRequest::
displayBearerContextsToBeRemovedInCreateSessionRequestData_v
(BearerContextsToBeRemovedInCreateSessionRequestData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"BearerContextsToBeRemovedInCreateSessionRequest:");
    stream.endOfLine();
    stream.incrIndent();

    stream.add((char *)"epsBearerId:");
    stream.endOfLine();
    EbiIe epsBearerId=
    dynamic_cast<
    EbiIe&>(GtpV2IeFactory::getInstance().getIeObject(EbiIeType));
    epsBearerId.displayEbiIe_v(data.epsBearerId, stream);

    if (data.s4USgsnFTeidIePresent)
    {
        stream.add((char *)"s4USgsnFTeid:");
        stream.endOfLine();
        FTeidIe s4USgsnFTeid=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        s4USgsnFTeid.displayFTeidIe_v(data.s4USgsnFTeid, stream);

	}
 
    stream.decrIndent();
    stream.decrIndent();
}


