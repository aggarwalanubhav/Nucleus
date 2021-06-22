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

#include "fCauseIe.h"
#include "dataTypeCodecUtils.h"

FCauseIe::FCauseIe() 
{
    ieType = 119;
    // TODO

}

FCauseIe::~FCauseIe() {
    // TODO Auto-generated destructor stub
}

bool FCauseIe::encodeFCauseIe(MsgBuffer &buffer, FCauseIeData const &data)
{
    buffer.skipBits(4);

    if(!(buffer.writeBits(data.causeType, 4)))
    {
        errorStream.add((char *)"Encoding of causeType failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.fCauseField)))
    {
        errorStream.add((char *)"Encoding of fCauseField failed\n");
        return false;
    }

    return true;
}

bool FCauseIe::decodeFCauseIe(MsgBuffer &buffer, FCauseIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;
    buffer.skipBits(4);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: \n");
        return false;
    }

    data.causeType = buffer.readBits(4);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: causeType\n");
        return false;
    }

    buffer.readUint8(data.fCauseField);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: fCauseField\n");
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
        errorStream.add((char *)"Unable to decode IE FCauseIe\n");
        return false;
    }
}
void FCauseIe::displayFCauseIe_v(FCauseIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"FCauseIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add( (char *)"causeType: "); 
    stream.add((Uint8)data.causeType);
    stream.endOfLine();
  
    stream.add((char *)"fCauseField: ");
    stream.add(data.fCauseField);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}