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

#include "teidCIe.h"
#include "dataTypeCodecUtils.h"

TeidCIe::TeidCIe() 
{
    ieType = 59;
    // TODO

}

TeidCIe::~TeidCIe() {
    // TODO Auto-generated destructor stub
}

bool TeidCIe::encodeTeidCIe(MsgBuffer &buffer, TeidCIeData const &data)
{
    if (!(buffer.writeUint32(data.tunnelEndpointIdentifierforControlPlane)))
    {
        errorStream.add((char *)"Encoding of tunnelEndpointIdentifierforControlPlane failed\n");
        return false;
    }

    return true;
}

bool TeidCIe::decodeTeidCIe(MsgBuffer &buffer, TeidCIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;

    buffer.readUint32(data.tunnelEndpointIdentifierforControlPlane);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: tunnelEndpointIdentifierforControlPlane\n");
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
        errorStream.add((char *)"Unable to decode IE TeidCIe\n");
        return false;
    }
}
void TeidCIe::displayTeidCIe_v(TeidCIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"TeidCIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add((char *)"tunnelEndpointIdentifierforControlPlane: ");
    stream.add(data.tunnelEndpointIdentifierforControlPlane);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
