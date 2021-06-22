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

#include "tiIe.h"
#include "dataTypeCodecUtils.h"

TiIe::TiIe() 
{
    ieType = 137;
    // TODO

}

TiIe::~TiIe() {
    // TODO Auto-generated destructor stub
}

bool TiIe::encodeTiIe(MsgBuffer &buffer, TiIeData const &data)
{
    if (!(buffer.writeUint8(data.transactionIdentifier)))
    {
        errorStream.add((char *)"Encoding of transactionIdentifier failed\n");
        return false;
    }

    return true;
}

bool TiIe::decodeTiIe(MsgBuffer &buffer, TiIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;

    buffer.readUint8(data.transactionIdentifier);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: transactionIdentifier\n");
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
        errorStream.add((char *)"Unable to decode IE TiIe\n");
        return false;
    }
}
void TiIe::displayTiIe_v(TiIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"TiIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add((char *)"transactionIdentifier: ");
    stream.add(data.transactionIdentifier);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
