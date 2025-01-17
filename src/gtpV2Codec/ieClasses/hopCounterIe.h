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
#ifndef HOPCOUNTERIE_H_
#define HOPCOUNTERIE_H_

#include "manual/gtpV2Ie.h"



class HopCounterIe: public GtpV2Ie {
public:
    HopCounterIe();
    virtual ~HopCounterIe();

    bool encodeHopCounterIe(MsgBuffer &buffer,
                 HopCounterIeData const &data);
    bool decodeHopCounterIe(MsgBuffer &buffer,
                 HopCounterIeData &data, Uint16 length);
    void displayHopCounterIe_v(HopCounterIeData const &data,
                 Debug &stream);
};

#endif /* HOPCOUNTERIE_H_ */
