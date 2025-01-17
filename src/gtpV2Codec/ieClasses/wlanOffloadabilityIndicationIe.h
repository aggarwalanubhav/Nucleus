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
#ifndef WLANOFFLOADABILITYINDICATIONIE_H_
#define WLANOFFLOADABILITYINDICATIONIE_H_

#include "manual/gtpV2Ie.h"



class WlanOffloadabilityIndicationIe: public GtpV2Ie {
public:
    WlanOffloadabilityIndicationIe();
    virtual ~WlanOffloadabilityIndicationIe();

    bool encodeWlanOffloadabilityIndicationIe(MsgBuffer &buffer,
                 WlanOffloadabilityIndicationIeData const &data);
    bool decodeWlanOffloadabilityIndicationIe(MsgBuffer &buffer,
                 WlanOffloadabilityIndicationIeData &data, Uint16 length);
    void displayWlanOffloadabilityIndicationIe_v(WlanOffloadabilityIndicationIeData const &data,
                 Debug &stream);
};

#endif /* WLANOFFLOADABILITYINDICATIONIE_H_ */
