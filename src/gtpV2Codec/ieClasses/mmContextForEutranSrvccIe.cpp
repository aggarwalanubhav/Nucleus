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

#include "mmContextForEutranSrvccIe.h"
#include "dataTypeCodecUtils.h"

MmContextForEutranSrvccIe::MmContextForEutranSrvccIe() 
{
    ieType = 54;
    // TODO

}

MmContextForEutranSrvccIe::~MmContextForEutranSrvccIe() {
    // TODO Auto-generated destructor stub
}

bool MmContextForEutranSrvccIe::encodeMmContextForEutranSrvccIe(MsgBuffer &buffer, MmContextForEutranSrvccIeData const &data)
{
    buffer.skipBits(4);

    if(!(buffer.writeBits(data.eKSI, 4)))
    {
        errorStream.add((char *)"Encoding of eKSI failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.CKSRVCC)))
    {
        errorStream.add((char *)"Encoding of CKSRVCC failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.IKSRVCC)))
    {
        errorStream.add((char *)"Encoding of IKSRVCC failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.lengthOfTheMobileStationClassmark2)))
    {
        errorStream.add((char *)"Encoding of lengthOfTheMobileStationClassmark2 failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.mobileStationClassmark2)))
    {
        errorStream.add((char *)"Encoding of mobileStationClassmark2 failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.lengthOfTheMobileStationClassmark3)))
    {
        errorStream.add((char *)"Encoding of lengthOfTheMobileStationClassmark3 failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.mobileStationClassmark3)))
    {
        errorStream.add((char *)"Encoding of mobileStationClassmark3 failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.lengthOfTheSupportedCodecList)))
    {
        errorStream.add((char *)"Encoding of lengthOfTheSupportedCodecList failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.supportedCodecList)))
    {
        errorStream.add((char *)"Encoding of supportedCodecList failed\n");
        return false;
    }

    return true;
}

bool MmContextForEutranSrvccIe::decodeMmContextForEutranSrvccIe(MsgBuffer &buffer, MmContextForEutranSrvccIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;
    buffer.skipBits(4);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: \n");
        return false;
    }

    data.eKSI = buffer.readBits(4);
    // confirm that we are not reading beyond the IE boundary
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: eKSI\n");
        return false;
    }

    buffer.readUint8(data.CKSRVCC);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: CKSRVCC\n");
        return false;
    }

    buffer.readUint8(data.IKSRVCC);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: IKSRVCC\n");
        return false;
    }

    buffer.readUint8(data.lengthOfTheMobileStationClassmark2);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: lengthOfTheMobileStationClassmark2\n");
        return false;
    }

    buffer.readUint8(data.mobileStationClassmark2);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: mobileStationClassmark2\n");
        return false;
    }

    buffer.readUint8(data.lengthOfTheMobileStationClassmark3);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: lengthOfTheMobileStationClassmark3\n");
        return false;
    }

    buffer.readUint8(data.mobileStationClassmark3);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: mobileStationClassmark3\n");
        return false;
    }

    buffer.readUint8(data.lengthOfTheSupportedCodecList);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: lengthOfTheSupportedCodecList\n");
        return false;
    }

    buffer.readUint8(data.supportedCodecList);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: supportedCodecList\n");
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
        errorStream.add((char *)"Unable to decode IE MmContextForEutranSrvccIe\n");
        return false;
    }
}
void MmContextForEutranSrvccIe::displayMmContextForEutranSrvccIe_v(MmContextForEutranSrvccIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"MmContextForEutranSrvccIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add( (char *)"eKSI: "); 
    stream.add((Uint8)data.eKSI);
    stream.endOfLine();
  
    stream.add((char *)"CKSRVCC: ");
    stream.add(data.CKSRVCC);
    stream.endOfLine();
  
    stream.add((char *)"IKSRVCC: ");
    stream.add(data.IKSRVCC);
    stream.endOfLine();
  
    stream.add((char *)"lengthOfTheMobileStationClassmark2: ");
    stream.add(data.lengthOfTheMobileStationClassmark2);
    stream.endOfLine();
  
    stream.add((char *)"mobileStationClassmark2: ");
    stream.add(data.mobileStationClassmark2);
    stream.endOfLine();
  
    stream.add((char *)"lengthOfTheMobileStationClassmark3: ");
    stream.add(data.lengthOfTheMobileStationClassmark3);
    stream.endOfLine();
  
    stream.add((char *)"mobileStationClassmark3: ");
    stream.add(data.mobileStationClassmark3);
    stream.endOfLine();
  
    stream.add((char *)"lengthOfTheSupportedCodecList: ");
    stream.add(data.lengthOfTheSupportedCodecList);
    stream.endOfLine();
  
    stream.add((char *)"supportedCodecList: ");
    stream.add(data.supportedCodecList);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
