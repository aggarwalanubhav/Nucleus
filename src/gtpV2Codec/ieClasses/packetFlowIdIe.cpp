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

#include "packetFlowIdIe.h"
#include "dataTypeCodecUtils.h"

PacketFlowIdIe::PacketFlowIdIe() 
{
    ieType = 123;
    // TODO

}

PacketFlowIdIe::~PacketFlowIdIe() {
    // TODO Auto-generated destructor stub
}

bool PacketFlowIdIe::encodePacketFlowIdIe(MsgBuffer &buffer, PacketFlowIdIeData const &data)
{
    buffer.skipBits(4);

    if(!(buffer.writeBits(data.EBI, 4)))
    {
        errorStream.add((char *)"Encoding of EBI failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.packetFlowId)))
    {
        errorStream.add((char *)"Encoding of packetFlowId failed\n");
        return false;
    }

    return true;
}

bool PacketFlowIdIe::decodePacketFlowIdIe(MsgBuffer &buffer, PacketFlowIdIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;
    buffer.skipBits(4);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: \n");
        return false;
    }

    data.EBI = buffer.readBits(4);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: EBI\n");
        return false;
    }

    buffer.readUint8(data.packetFlowId);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: packetFlowId\n");
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
        errorStream.add((char *)"Unable to decode IE PacketFlowIdIe\n");
        return false;
    }
}
void PacketFlowIdIe::displayPacketFlowIdIe_v(PacketFlowIdIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"PacketFlowIdIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add( (char *)"EBI: "); 
    stream.add((Uint8)data.EBI);
    stream.endOfLine();
  
    stream.add((char *)"packetFlowId: ");
    stream.add(data.packetFlowId);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
