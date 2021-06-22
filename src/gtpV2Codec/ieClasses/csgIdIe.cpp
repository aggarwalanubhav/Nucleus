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

#include "csgIdIe.h"
#include "dataTypeCodecUtils.h"

CsgIdIe::CsgIdIe() 
{
    ieType = 147;
    // TODO

}

CsgIdIe::~CsgIdIe() {
    // TODO Auto-generated destructor stub
}

bool CsgIdIe::encodeCsgIdIe(MsgBuffer &buffer, CsgIdIeData const &data)
{
    buffer.skipBits(4);

    if(!(buffer.writeBits(data.csgId, 3)))
    {
        errorStream.add((char *)"Encoding of csgId failed\n");
        return false;
    }
    if(!(buffer.writeBits(data.csgId, 3)))
    {
        errorStream.add((char *)"Encoding of csgId failed\n");
        return false;
    }

    return true;
}

bool CsgIdIe::decodeCsgIdIe(MsgBuffer &buffer, CsgIdIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;
    buffer.skipBits(4);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: \n");
        return false;
    }

    data.csgId = buffer.readBits(3);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: csgId\n");
        return false;
    }
    data.csgId = buffer.readBits(3);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: csgId\n");
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
        errorStream.add((char *)"Unable to decode IE CsgIdIe\n");
        return false;
    }
}
void CsgIdIe::displayCsgIdIe_v(CsgIdIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"CsgIdIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add( (char *)"csgId: "); 
    stream.add((Uint8)data.csgId);
    stream.endOfLine();
  
    stream.add( (char *)"csgId: "); 
    stream.add((Uint8)data.csgId);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
