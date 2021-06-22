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
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/ietemplate.cpp.tt>
 ******************************************************************************/

#include "changeToReportFlagsIe.h"
#include "dataTypeCodecUtils.h"

ChangeToReportFlagsIe::ChangeToReportFlagsIe() 
{
    ieType = 167;
    // TODO

}

ChangeToReportFlagsIe::~ChangeToReportFlagsIe() {
    // TODO Auto-generated destructor stub
}

bool ChangeToReportFlagsIe::encodeChangeToReportFlagsIe(MsgBuffer &buffer, ChangeToReportFlagsIeData const &data)
{
    buffer.skipBits(6);

    if(!(buffer.writeBits(data.tzcr, 1)))
    {
        errorStream.add((char *)"Encoding of tzcr failed\n");
        return false;
    }
    if(!(buffer.writeBits(data.sncr, 1)))
    {
        errorStream.add((char *)"Encoding of sncr failed\n");
        return false;
    }

    return true;
}

bool ChangeToReportFlagsIe::decodeChangeToReportFlagsIe(MsgBuffer &buffer, ChangeToReportFlagsIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;
    buffer.skipBits(6);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: \n");
        return false;
    }

    data.tzcr = buffer.readBits(1);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: tzcr\n");
        return false;
    }
    data.sncr = buffer.readBits(1);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: sncr\n");
        return false;
    }

    // The IE is decoded now. The buffer index should be pointing to the 
    // IE Boundary. If not, we have some more data left for the IE which we don't know
    // how to decode
    if (ieBoundary == buffer.getCurrentIndex())
    {
        return true;
    }
    else
    {
        errorStream.add((char *)"Unable to decode IE ChangeToReportFlagsIe\n");
        return false;
    }
}
void ChangeToReportFlagsIe::displayChangeToReportFlagsIe_v(ChangeToReportFlagsIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"ChangeToReportFlagsIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add( (char *)"tzcr: "); 
    stream.add((Uint8)data.tzcr);
    stream.endOfLine();
  
    stream.add( (char *)"sncr: "); 
    stream.add((Uint8)data.sncr);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}