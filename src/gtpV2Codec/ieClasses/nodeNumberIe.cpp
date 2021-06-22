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

#include "nodeNumberIe.h"
#include "dataTypeCodecUtils.h"

NodeNumberIe::NodeNumberIe() 
{
    ieType = 175;
    // TODO

}

NodeNumberIe::~NodeNumberIe() {
    // TODO Auto-generated destructor stub
}

bool NodeNumberIe::encodeNodeNumberIe(MsgBuffer &buffer, NodeNumberIeData const &data)
{
    if (!(data.lengthOfNodeName!=0))
    {
        errorStream.add((char *)"Data validation failure: lengthOfNodeName\n");
        return false; 
    }
    if (!(buffer.writeUint8(data.lengthOfNodeName)))
    {
        errorStream.add((char *)"Encoding of lengthOfNodeName failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.nodeName)))
    {
        errorStream.add((char *)"Encoding of nodeName failed\n");
        return false;
    }
    if (!(buffer.writeUint32(data.NodeNumber)))
    {
        errorStream.add((char *)"Encoding of NodeNumber failed\n");
        return false;
    }

    return true;
}

bool NodeNumberIe::decodeNodeNumberIe(MsgBuffer &buffer, NodeNumberIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;

    buffer.readUint8(data.lengthOfNodeName);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: lengthOfNodeName\n");
        return false;
    }
    if (!(data.lengthOfNodeName!=0))
    {
        errorStream.add((char *)"Data validation failure : lengthOfNodeName\n");
        return false; //TODO need to add validations
    }

    buffer.readUint8(data.nodeName);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: nodeName\n");
        return false;
    }

    buffer.readUint32(data.NodeNumber);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: NodeNumber\n");
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
        errorStream.add((char *)"Unable to decode IE NodeNumberIe\n");
        return false;
    }
}
void NodeNumberIe::displayNodeNumberIe_v(NodeNumberIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"NodeNumberIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add((char *)"lengthOfNodeName: ");
    stream.add(data.lengthOfNodeName);
    stream.endOfLine();
  
    stream.add((char *)"nodeName: ");
    stream.add(data.nodeName);
    stream.endOfLine();
  
    stream.add((char *)"NodeNumber: ");
    stream.add(data.NodeNumber);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
