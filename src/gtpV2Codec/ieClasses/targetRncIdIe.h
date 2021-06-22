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
#ifndef TARGETRNCIDIE_H_
#define TARGETRNCIDIE_H_

#include "manual/gtpV2Ie.h"



class TargetRncIdIe: public GtpV2Ie {
public:
    TargetRncIdIe();
    virtual ~TargetRncIdIe();

    bool encodeTargetRncIdIe(MsgBuffer &buffer,
                 TargetRncIdIeData const &data);
    bool decodeTargetRncIdIe(MsgBuffer &buffer,
                 TargetRncIdIeData &data, Uint16 length);
    void displayTargetRncIdIe_v(TargetRncIdIeData const &data,
                 Debug &stream);
};

#endif /* TARGETRNCIDIE_H_ */
