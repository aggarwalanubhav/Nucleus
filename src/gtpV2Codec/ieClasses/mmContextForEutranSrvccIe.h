/*
 * Copyright (c) 2020, Infosys Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 /******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/ietemplate.h.tt>
 ******************************************************************************/
#ifndef MMCONTEXTFOREUTRANSRVCCIE_H_
#define MMCONTEXTFOREUTRANSRVCCIE_H_

#include "manual/gtpV2Ie.h"



class MmContextForEutranSrvccIe: public GtpV2Ie {
public:
    MmContextForEutranSrvccIe();
    virtual ~MmContextForEutranSrvccIe();

    bool encodeMmContextForEutranSrvccIe(MsgBuffer &buffer,
                 MmContextForEutranSrvccIeData const &data);
    bool decodeMmContextForEutranSrvccIe(MsgBuffer &buffer,
                 MmContextForEutranSrvccIeData &data, Uint16 length);
    void displayMmContextForEutranSrvccIe_v(MmContextForEutranSrvccIeData const &data,
                 Debug &stream);
};

#endif /* MMCONTEXTFOREUTRANSRVCCIE_H_ */
